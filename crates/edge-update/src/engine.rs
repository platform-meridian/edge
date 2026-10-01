//! The update as a record on the state volume. Each step observes the unit,
//! acts idempotently, then records the next phase durably, so a restart, a
//! reboot or a power cut at any point resumes from what the unit shows.
//!
//! Order: verify, import the images, copy the store off, stage the config,
//! install the OS on trial and reboot, wait for the unit to commit it, update
//! the judge, then move the stack and wait for the judge's verdict. The stack
//! never moves before the OS is committed, so a cut leaves the old system or
//! the new OS under the old stack.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::bundle::{self, Manifest, Verifier, machineconfig};
use crate::unit::{Cluster, Registry, Settings, Talos};
use crate::upload::Uploads;

const LOADER: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
const SECURE_BOOT: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const SAVED_CONFIG: &str = "config-before.yaml";

const INSTALL: i64 = 30 * 60;
const SETTLE: i64 = 20 * 60;
const ROLLOUT: i64 = 10 * 60;
const GOOD: i64 = 20 * 60;
const HISTORY: usize = 50;
const SNAPSHOTS: usize = 2;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    Idle,
    Verifying { sha256: String },
    Starting,
    Importing,
    Snapshotting,
    Staging,
    Installing,
    Rebooting { boot_id: String },
    Trial,
    Settling,
    Seeding,
    AwaitingGood,
    Repointing { rolled_back: String },
    Judging { rolled_back: String },
    Collecting,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Release {
    pub sha256: String,
    pub manifest: Manifest,
    pub refs: BTreeSet<String>,
    #[serde(default)]
    pub os_done: bool,
}

impl Release {
    pub fn get(&self, k: &str) -> &str {
        self.manifest.get(k).map(String::as_str).unwrap_or_default()
    }
    pub fn tag(&self) -> &str {
        self.get("STACK_TAG")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Before {
    pub talos: String,
    pub url: String,
    pub tag: String,
    pub default_entry: String,
    pub started: i64,
    pub snapshot: Option<String>,
    /// An operator powered the unit down on the OS trial.
    #[serde(default)]
    pub backed_out: bool,
    /// The installer the unit's config names.
    #[serde(default)]
    pub installer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Committed,
    Failed,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub release: Option<Release>,
    pub outcome: Outcome,
    pub detail: String,
    pub started: i64,
    pub finished: i64,
    pub snapshot: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub phase: Phase,
    pub release: Option<Release>,
    pub before: Option<Before>,
    pub history: Vec<Entry>,
    pub error: String,
    /// When the current phase began.
    pub since: i64,
}

impl Record {
    /// Why the unit must not be powered down now: an update is under way. Its
    /// OS trial is the exception, since a reboot then backs the update out.
    pub fn power_refusal(&self) -> Option<String> {
        match self.phase {
            Phase::Idle | Phase::Verifying { .. } | Phase::Trial => None,
            _ => Some(format!(
                "the update to {} is under way: wait until it commits or fails",
                self.release.as_ref().map_or("", |r| r.tag())
            )),
        }
    }
}

impl Default for Record {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            release: None,
            before: None,
            history: Vec::new(),
            error: String::new(),
            since: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Tick {
    Moved,
    Wait(Duration),
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Power {
    Reboot,
    Shutdown,
}

/// The unit as it runs, whatever the engine is doing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Unit {
    pub talos_version: String,
    pub stack_tag: String,
    pub good: String,
    pub previous: String,
    pub trial: String,
    pub rolled_back: String,
    pub os_trial: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct Boot {
    pub selected: String,
    pub default: String,
    pub one_shot: String,
}

impl Boot {
    /// As boot-commit judges it: sd-boot chose an entry other than the default.
    fn uncommitted(&self) -> bool {
        !(self.one_shot == "kexec reboot" || self.selected.is_empty())
            && !self.selected.eq_ignore_ascii_case(&self.default)
    }

    /// Uncommitted with a default to go back to. Fresh media has none until
    /// boot-commit's first commit, and nothing to revert to.
    pub fn trial(&self) -> bool {
        self.uncommitted() && !self.default.is_empty()
    }
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct Engine {
    dir: PathBuf,
    settings: Settings,
    verifier: Verifier,
    talos: Arc<dyn Talos>,
    cluster: Arc<dyn Cluster>,
    registry: Arc<dyn Registry>,
    now: Clock,
    pub record: Record,
    /// What the current phase is waiting for, for a person.
    pub detail: String,
    pub unit: Unit,
}

enum Next {
    Go(Phase),
    Wait(Duration, String),
    Fail(String),
    Refuse(String),
    Done,
}

use Next::{Done, Fail, Go, Refuse, Wait};

fn poll(secs: u64, why: impl Into<String>) -> anyhow::Result<Next> {
    Ok(Wait(Duration::from_secs(secs), why.into()))
}

impl Engine {
    pub fn open(
        dir: &Path,
        settings: Settings,
        talos: Arc<dyn Talos>,
        cluster: Arc<dyn Cluster>,
        registry: Arc<dyn Registry>,
        now: Clock,
    ) -> anyhow::Result<Self> {
        let verifier = Verifier::new(&settings.signing_key, &settings.signature_namespace)?;
        let path = dir.join("state.json");
        let record = match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(r) => r,
                Err(e) => {
                    // A record that cannot be read is set aside, not trusted: the
                    // unit's boot and stack judges still finish what was started.
                    tracing::error!(error = %e, "the update record is unreadable; starting afresh");
                    edge_common::set_aside(&path);
                    Record::default()
                }
            },
            Err(_) => Record::default(),
        };
        Ok(Self {
            dir: dir.into(),
            settings,
            verifier,
            talos,
            cluster,
            registry,
            now,
            record,
            detail: String::new(),
            unit: Unit::default(),
        })
    }

    pub fn uploads(&self) -> Uploads {
        Uploads::new(&self.dir.join("upload"))
    }

    fn release_dir(&self, sha: &str) -> PathBuf {
        self.dir.join("releases").join(sha)
    }

    fn save(&self) -> anyhow::Result<()> {
        edge_common::durable_write(
            &self.dir.join("state.json"),
            &serde_json::to_vec_pretty(&self.record)?,
        )
        .context("record the update")
    }

    pub fn idle(&self) -> bool {
        self.record.phase == Phase::Idle
    }

    pub fn request_verify(&mut self, sha256: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.idle(), "an update is in progress");
        let up = self.uploads().current();
        anyhow::ensure!(
            up.is_some_and(|u| u.complete && u.sha256 == sha256),
            "no complete upload of that bundle"
        );
        self.go(Phase::Verifying {
            sha256: sha256.into(),
        })
    }

    pub async fn request_apply(&mut self, tag: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.idle(), "an update is in progress");
        let rel = self
            .record
            .release
            .as_ref()
            .context("no verified bundle to apply")?;
        anyhow::ensure!(
            rel.tag() == tag,
            "the verified bundle is {}, not {tag}",
            rel.tag()
        );
        // An update's own trial needs the unit's boot committed to fall back to.
        let boot = self.boot().await?;
        anyhow::ensure!(
            !boot.trial(),
            "the unit is on trial of {}: wait for it to commit or revert",
            boot.selected
        );
        anyhow::ensure!(
            !boot.uncommitted(),
            "the unit has not committed its first boot, {}, yet: wait for it to",
            boot.selected
        );
        self.record.error.clear();
        self.go(Phase::Starting)
    }

    /// Rereads the unit, a part that cannot be read keeping its last reading;
    /// true if anything changed.
    pub async fn refresh_unit(&mut self) -> bool {
        let was = self.unit.clone();
        match async { anyhow::Ok((self.talos.version().await?, self.boot().await?)) }.await {
            Ok((v, b)) => (self.unit.talos_version, self.unit.os_trial) = (v, b.trial()),
            Err(e) => tracing::debug!(error = format!("{e:#}"), "could not read the unit's OS"),
        }
        let st = &self.settings.stack;
        match async {
            let (_, tag) = self.cluster.sync(&st.flux_instance).await?;
            anyhow::Ok((tag, self.cluster.config_map(&st.judge).await?))
        }
        .await
        {
            Ok((tag, judge)) => {
                let judge = judge.unwrap_or_default();
                let get = |k: &str| judge.get(k).cloned().unwrap_or_default();
                let u = &mut self.unit;
                u.stack_tag = tag;
                (u.good, u.previous, u.trial, u.rolled_back) = (
                    get("good"),
                    get("previous"),
                    get("trial"),
                    get("rolled_back"),
                );
            }
            Err(e) => tracing::debug!(error = format!("{e:#}"), "could not read the unit's stack"),
        }
        self.unit != was
    }

    /// Reboots or shuts the unit down; says what it boots next.
    pub async fn power(&mut self, p: Power) -> anyhow::Result<String> {
        if let Some(why) = self.record.power_refusal() {
            anyhow::bail!(why);
        }
        let b = self.boot().await?;
        match p {
            Power::Reboot => self.talos.reboot().await?,
            Power::Shutdown => self.talos.shutdown().await?,
        }
        let action = match p {
            Power::Reboot => "rebooting",
            Power::Shutdown => "shutting down",
        };
        if !b.trial() {
            return Ok(action.into());
        }
        if self.record.phase == Phase::Trial
            && let Some(before) = self.record.before.as_mut()
        {
            before.backed_out = true;
            self.save()?;
        }
        Ok(format!(
            "{action}: the OS on trial, {}, is backed out and the unit boots {} again",
            b.selected, b.default
        ))
    }

    fn go(&mut self, p: Phase) -> anyhow::Result<()> {
        self.record.phase = p;
        self.record.since = (self.now)();
        self.detail.clear();
        self.save()
    }

    /// Advances by at most one phase.
    pub async fn step(&mut self) -> anyhow::Result<Tick> {
        let next = match self.record.phase.clone() {
            Phase::Idle => {
                self.tidy();
                return Ok(Tick::Idle);
            }
            Phase::Verifying { sha256 } => return self.verifying(&sha256).await,
            Phase::Starting => self.starting().await?,
            Phase::Importing => self.importing().await?,
            Phase::Snapshotting => self.snapshotting().await?,
            Phase::Staging => self.staging().await?,
            Phase::Installing => self.installing().await?,
            Phase::Rebooting { boot_id } => self.rebooting(&boot_id).await?,
            Phase::Trial => self.trial().await?,
            Phase::Settling => self.settling().await?,
            Phase::Seeding => self.seeding().await?,
            Phase::AwaitingGood => self.awaiting_good().await?,
            Phase::Repointing { rolled_back } => self.repointing(rolled_back).await?,
            Phase::Judging { rolled_back } => self.judging(&rolled_back).await?,
            Phase::Collecting => self.collecting().await?,
        };
        match next {
            Go(p) => {
                self.go(p)?;
                Ok(Tick::Moved)
            }
            Wait(d, why) => {
                self.detail = why;
                Ok(Tick::Wait(d))
            }
            Fail(why) => {
                self.finish(Outcome::Failed, why)?;
                Ok(Tick::Moved)
            }
            Refuse(why) => {
                self.finish(Outcome::Refused, why)?;
                Ok(Tick::Moved)
            }
            Done => {
                let tag = self.release()?.tag().to_string();
                self.finish(Outcome::Committed, format!("{tag} committed"))?;
                Ok(Tick::Moved)
            }
        }
    }

    fn release(&self) -> anyhow::Result<&Release> {
        self.record
            .release
            .as_ref()
            .context("the record lost its release")
    }

    fn before(&self) -> anyhow::Result<&Before> {
        self.record
            .before
            .as_ref()
            .context("the record lost the unit's state before the update")
    }

    fn finish(&mut self, outcome: Outcome, detail: String) -> anyhow::Result<()> {
        let now = (self.now)();
        let b = self.record.before.take();
        let release = self.record.release.clone();
        self.record.history.insert(
            0,
            Entry {
                release: release.clone(),
                outcome,
                started: b.as_ref().map(|b| b.started).unwrap_or(now),
                finished: now,
                snapshot: b.and_then(|b| b.snapshot),
                detail: detail.clone(),
            },
        );
        self.record.history.truncate(HISTORY);
        if outcome == Outcome::Committed {
            self.record.error.clear();
        } else {
            tracing::error!(%detail, "update stopped");
            self.record.error = detail;
        }
        // A failed update stays verified, so it can be applied again.
        if outcome != Outcome::Failed {
            self.record.release = None;
        }
        self.go(Phase::Idle)?;
        self.tidy();
        Ok(())
    }

    /// Unpacked releases, uploads and a saved config nothing refers to any more.
    fn tidy(&self) {
        let _ = std::fs::remove_file(self.dir.join(SAVED_CONFIG));
        let keep = self.record.release.as_ref().map(|r| r.sha256.clone());
        if let Ok(dirs) = std::fs::read_dir(self.dir.join("releases")) {
            for d in dirs.flatten() {
                if Some(d.file_name().to_string_lossy().into_owned()) != keep {
                    let _ = std::fs::remove_dir_all(d.path());
                }
            }
        }
    }

    async fn verifying(&mut self, sha: &str) -> anyhow::Result<Tick> {
        let dir = self.release_dir(sha);
        let _ = std::fs::remove_dir_all(&dir);
        self.detail = "checking the signature and unpacking".into();
        let bundle = self.uploads().bundle();
        let (d, verifier) = (dir.clone(), self.verifier.clone());
        let unpacked =
            tokio::task::spawn_blocking(move || bundle::unpack(&bundle, &d, &verifier)).await?;
        let release = match unpacked.and_then(|manifest| {
            let refs = bundle::layout_refs(&dir.join(bundle::IMAGES))?;
            Ok(Release {
                sha256: sha.into(),
                manifest,
                refs,
                os_done: false,
            })
        }) {
            Ok(r) => r,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                self.record.release = None;
                self.finish(Outcome::Refused, format!("{e:#}"))?;
                return Ok(Tick::Moved);
            }
        };
        self.record.release = Some(release.clone());
        if let Some(why) = self.refusal(&release).await {
            let _ = std::fs::remove_dir_all(&dir);
            self.finish(Outcome::Refused, why)?;
            return Ok(Tick::Moved);
        }
        self.uploads().discard();
        self.record.error.clear();
        self.go(Phase::Idle)?;
        Ok(Tick::Moved)
    }

    /// Why this unit must not take `rel`, checked with reads alone.
    async fn refusal(&self, rel: &Release) -> Option<String> {
        match self.check(rel).await {
            Ok(()) => None,
            Err(e) => Some(format!("{e:#}")),
        }
    }

    async fn check(&self, rel: &Release) -> anyhow::Result<()> {
        use anyhow::ensure;
        for k in [
            "FORMAT",
            "STACK_TAG",
            "STACK_DIGEST",
            "INSTALLER_REF",
            "TALOS_VERSION",
            "BUILT_EPOCH",
            "SECUREBOOT",
        ] {
            ensure!(!rel.get(k).is_empty(), "the MANIFEST lacks {k}");
        }
        ensure!(
            rel.get("FORMAT") == "2",
            "the bundle is format {}, not 2",
            rel.get("FORMAT")
        );
        ensure!(
            rel.get("INSTALLER_REF").contains("@sha256:"),
            "the MANIFEST names the installer by tag, not digest"
        );
        ensure!(
            rel.get("STACK_DIGEST").starts_with("sha256:"),
            "the MANIFEST's STACK_DIGEST is not a sha256"
        );
        let epoch: i64 = rel
            .get("BUILT_EPOCH")
            .parse()
            .context("BUILT_EPOCH is not a number")?;

        let running = self
            .talos
            .version()
            .await
            .context("read the unit's Talos version")?;
        ensure!(
            version_ge(rel.get("TALOS_VERSION"), &running),
            "REFUSING A DOWNGRADE: the unit runs Talos {running} and the bundle installs {}",
            rel.get("TALOS_VERSION")
        );
        let sb = self
            .talos
            .read(SECURE_BOOT)
            .await
            .context("read the Secure Boot state")?;
        if sb.is_some_and(|v| v.get(4) == Some(&1)) {
            ensure!(
                rel.get("SECUREBOOT") == "1",
                "the unit enforces Secure Boot and the bundle was built without it"
            );
        }
        let st = &self.settings.stack;
        let lock = self
            .cluster
            .config_map(&st.lock)
            .await?
            .with_context(|| format!("the unit has no stack lock at {}", st.lock))?;
        for (k, v) in rel
            .manifest
            .iter()
            .filter_map(|(k, v)| Some((k.strip_prefix("LOCK_")?, v)))
        {
            let theirs = lock.get(k).map(String::as_str).unwrap_or_default();
            ensure!(
                theirs == v,
                "the bundle is for {k}={v:?} and the unit has {k}={theirs:?}"
            );
        }
        let (_, tag) = self.cluster.sync(&st.flux_instance).await?;
        if tag != rel.tag() {
            let unit: i64 = lock
                .get("built_epoch")
                .and_then(|e| e.parse().ok())
                .with_context(|| {
                    format!(
                        "{} has no built_epoch to compare the bundle's with",
                        st.lock
                    )
                })?;
            ensure!(
                epoch > unit,
                "REFUSING A DOWNGRADE: the unit's stack ({tag}) is version {unit} and the bundle is {epoch}"
            );
        }
        ensure!(
            self.talos.size(&self.settings.store).await?.is_some(),
            "there is no store at {} to copy before the update",
            self.settings.store
        );
        let merged = self.merged(rel).await?;
        self.talos
            .stage_config(&merged, true)
            .await
            .context("the unit rejects the merged machine config")?;
        Ok(())
    }

    async fn merged(&self, rel: &Release) -> anyhow::Result<String> {
        let patch = std::fs::read_to_string(self.release_dir(&rel.sha256).join(bundle::PATCH))?;
        let unit = self
            .talos
            .machine_config()
            .await
            .context("read the unit's machine config")?;
        machineconfig::merge(&unit, &patch)
    }

    async fn boot(&self) -> anyhow::Result<Boot> {
        let var = |name: &str| format!("/sys/firmware/efi/efivars/{name}-{LOADER}");
        let mut b = Boot::default();
        for (name, dst) in [
            ("LoaderEntrySelected", &mut b.selected),
            ("LoaderEntryDefault", &mut b.default),
            ("LoaderEntryOneShot", &mut b.one_shot),
        ] {
            *dst = self
                .talos
                .read(&var(name))
                .await
                .with_context(|| format!("read {name}"))?
                .map(|v| decode_efivar(&v))
                .unwrap_or_default();
        }
        Ok(b)
    }

    async fn boot_id(&self) -> anyhow::Result<String> {
        let id = self
            .talos
            .read(BOOT_ID)
            .await?
            .context("the node has no boot id")?;
        Ok(String::from_utf8_lossy(&id).trim().to_string())
    }

    async fn starting(&mut self) -> anyhow::Result<Next> {
        let rel = self.release()?.clone();
        if let Some(why) = self.refusal(&rel).await {
            return Ok(Refuse(why));
        }
        let (url, tag) = self
            .cluster
            .sync(&self.settings.stack.flux_instance)
            .await?;
        // Saved before anything stages: a cut after staging boots the old OS on the new config.
        let running = self
            .talos
            .running_config()
            .await
            .context("read the unit's machine config")?;
        edge_common::durable_write_with(&self.dir.join(SAVED_CONFIG), |f| {
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(running.as_bytes())
        })
        .context("save the unit's machine config")?;
        self.record.before = Some(Before {
            talos: self.talos.version().await?,
            url,
            tag,
            default_entry: self.boot().await?.default,
            started: (self.now)(),
            snapshot: None,
            backed_out: false,
            installer: installer_of(&running),
        });
        Ok(Go(Phase::Importing))
    }

    fn committed_refs(&self, n: usize) -> BTreeSet<String> {
        self.record
            .history
            .iter()
            .filter(|e| e.outcome == Outcome::Committed)
            .filter_map(|e| e.release.as_ref())
            .take(n)
            .flat_map(|r| r.refs.iter().cloned())
            .collect()
    }

    /// Also what the cluster runs: a failed update leaves its judge seeded.
    async fn keep(&self, mut refs: BTreeSet<String>) -> anyhow::Result<BTreeSet<String>> {
        refs.extend(
            self.cluster
                .images_in_use()
                .await
                .context("read the images the cluster runs")?,
        );
        Ok(refs)
    }

    async fn importing(&mut self) -> anyhow::Result<Next> {
        self.detail = "importing the images".into();
        let keep = self.keep(self.committed_refs(2)).await?;
        let layout = self
            .release_dir(&self.release()?.sha256)
            .join(bundle::IMAGES);
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || {
            registry.retain(&keep)?;
            registry.import(&layout)
        })
        .await??;
        Ok(Go(Phase::Snapshotting))
    }

    async fn snapshotting(&mut self) -> anyhow::Result<Next> {
        let store = self.settings.store.clone();
        let Some(listed) = self.talos.size(&store).await? else {
            return Ok(Fail(format!("the store at {store} is gone")));
        };
        let tag = self.release()?.tag().to_string();
        let root = self.dir.join("snapshots");
        let dir = root.join(format!("{:012}-{tag}", (self.now)()));
        std::fs::create_dir_all(&dir)?;
        let part = dir.join("state.log.part");
        let got = self.talos.copy(&store, &part).await?;
        // The log only grows, so a whole copy is at least the listed size.
        anyhow::ensure!(
            got >= listed,
            "copied {got} bytes of the store, but it listed {listed}"
        );
        std::fs::File::open(&part)?.sync_all()?;
        std::fs::rename(&part, dir.join("state.log"))?;
        let sha = crate::upload::hash_file(&dir.join("state.log"))?;
        let b = self.before()?;
        let pre = serde_json::json!({
            "taken": (self.now)(), "talos_before": b.talos, "stack_before": b.tag,
            "stack_url_before": b.url, "update": tag, "bytes": got, "sha256": sha,
        });
        edge_common::durable_write(&dir.join("PRE-UPDATE.json"), pre.to_string().as_bytes())?;
        let mut all: Vec<_> = std::fs::read_dir(&root)?
            .flatten()
            .map(|e| e.path())
            .collect();
        all.sort();
        for old in all.iter().rev().skip(SNAPSHOTS) {
            let _ = std::fs::remove_dir_all(old);
        }
        if let Some(b) = self.record.before.as_mut() {
            b.snapshot = Some(sha);
        }
        Ok(Go(Phase::Staging))
    }

    async fn staging(&mut self) -> anyhow::Result<Next> {
        let rel = self.release()?.clone();
        let merged = match self.merged(&rel).await {
            Ok(m) => m,
            Err(e) => return Ok(Fail(format!("{e:#}"))),
        };
        self.talos
            .stage_config(&merged, false)
            .await
            .context("stage the machine config")?;
        Ok(Go(Phase::Installing))
    }

    async fn installing(&mut self) -> anyhow::Result<Next> {
        if self.release()?.os_done {
            return Ok(Go(Phase::Seeding));
        }
        let b = self.boot().await?;
        if b.trial()
            || !b
                .default
                .eq_ignore_ascii_case(&self.before()?.default_entry)
        {
            return Ok(Go(Phase::Trial));
        }
        let rel = self.release()?.clone();
        let installer = installer_pin(rel.get("INSTALLER_REF"));
        if installer == installer_pin(&self.before()?.installer)
            && self.talos.version().await? == rel.get("TALOS_VERSION")
        {
            // The unit runs this OS already: the config alone, and no reboot.
            match self.talos.apply_config(&self.merged(&rel).await?).await {
                Ok(()) => {
                    if let Some(r) = self.record.release.as_mut() {
                        r.os_done = true;
                    }
                    return Ok(Go(Phase::Seeding));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the config needs a reboot: installing the OS as usual");
                }
            }
        }
        self.detail = "installing the new OS beside the running one".into();
        if let Err(e) = self.talos.install(&installer).await {
            if (self.now)() - self.record.since <= INSTALL {
                return Err(e);
            }
            return Ok(Fail(format!(
                "{installer} did not install in {} minutes: {e:#}. The OS is unchanged; {}. \
                 The stack did not move; applying again retries",
                INSTALL / 60,
                self.restore().await?
            )));
        }
        Ok(Go(Phase::Rebooting {
            boot_id: self.boot_id().await?,
        }))
    }

    async fn rebooting(&mut self, before: &str) -> anyhow::Result<Next> {
        if self.boot_id().await? == before {
            self.talos.reboot().await?;
            return poll(30, "rebooting into the new OS");
        }
        let b = self.boot().await?;
        if b.trial()
            || !b
                .default
                .eq_ignore_ascii_case(&self.before()?.default_entry)
        {
            return Ok(Go(Phase::Trial));
        }
        Ok(Fail(format!(
            "the unit rebooted on its previous OS, as the install did not take or the new OS did not stay up; \
             {}. The stack did not move; applying again repeats the upgrade",
            self.restore().await?
        )))
    }

    /// Puts the saved config back, now and for every boot after. Without a
    /// reboot, which the old OS does not need; try mode would undo it.
    async fn restore(&self) -> anyhow::Result<&'static str> {
        let saved = match std::fs::read_to_string(self.dir.join(SAVED_CONFIG)) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok("the update's machine config stays: none was saved before it");
            }
            Err(e) => return Err(e).context("read the saved machine config"),
        };
        self.talos
            .apply_config(&saved)
            .await
            .context("restore the machine config")?;
        Ok("its machine config from before the update is back")
    }

    async fn trial(&mut self) -> anyhow::Result<Next> {
        let b = self.boot().await?;
        if b.trial() {
            return poll(
                30,
                format!(
                    "{} is on trial; the unit commits it after ten healthy minutes",
                    b.selected
                ),
            );
        }
        let before = self.before()?;
        if b.default.eq_ignore_ascii_case(&before.default_entry) {
            let why = if before.backed_out {
                "an operator backed the new OS out by powering the unit down on its trial"
            } else {
                "the new OS did not stay up, and the unit went back to its previous OS by itself"
            };
            return Ok(Fail(format!(
                "{why}; {}. The stack did not move; applying again repeats the upgrade",
                self.restore().await?
            )));
        }
        let want = self.release()?.get("TALOS_VERSION").to_string();
        let running = self.talos.version().await?;
        if running != want {
            return Ok(Fail(format!(
                "the unit committed {} but runs Talos {running}, not {want}",
                b.default
            )));
        }
        if let Some(r) = self.record.release.as_mut() {
            r.os_done = true;
        }
        Ok(Go(Phase::Settling))
    }

    fn seed(&self) -> anyhow::Result<String> {
        let dir = self.release_dir(&self.release()?.sha256);
        Ok(std::fs::read_to_string(dir.join(bundle::SEED))?)
    }

    /// The seed's own workloads are not waited for: seeding replaces them, and
    /// a broken judge must not block the update that brings its fix.
    async fn settling(&mut self) -> anyhow::Result<Next> {
        let replaced = crate::cluster::declared(&self.seed()?)?;
        let mut waiting = self.cluster.not_ready().await?;
        waiting.retain(|w| !replaced.contains(w));
        if waiting.is_empty() {
            return Ok(Go(Phase::Seeding));
        }
        if (self.now)() - self.record.since > SETTLE {
            return Ok(Fail(format!(
                "the new OS is committed but these are not ready: {}. NOT moving the stack; \
                 once they are ready, applying again carries on without reinstalling the OS",
                waiting.join(", ")
            )));
        }
        poll(15, format!("waiting for {}", waiting.join(", ")))
    }

    async fn seeding(&mut self) -> anyhow::Result<Next> {
        let seed = self.seed()?;
        self.cluster
            .apply(&seed)
            .await
            .context("apply the bundle's seed")?;
        let waiting = self.cluster.not_rolled_out(&seed).await?;
        if waiting.is_empty() {
            return Ok(Go(Phase::AwaitingGood));
        }
        if (self.now)() - self.record.since > ROLLOUT {
            return Ok(Fail(format!(
                "{} did not roll out. NOT moving the stack",
                waiting.join(", ")
            )));
        }
        poll(10, format!("rolling out {}", waiting.join(", ")))
    }

    async fn judge(&self) -> anyhow::Result<(String, String)> {
        let r = self
            .cluster
            .config_map(&self.settings.stack.judge)
            .await?
            .unwrap_or_default();
        let get = |k: &str| r.get(k).cloned().unwrap_or_default();
        Ok((get("good"), get("rolled_back")))
    }

    async fn awaiting_good(&mut self) -> anyhow::Result<Next> {
        let tag = self.release()?.tag().to_string();
        let (_, now) = self
            .cluster
            .sync(&self.settings.stack.flux_instance)
            .await?;
        let (good, rolled_back) = self.judge().await?;
        if now == tag {
            return Ok(Go(Phase::Judging { rolled_back }));
        }
        let prev = self.before()?.tag.clone();
        if good == prev {
            return Ok(Go(Phase::Repointing { rolled_back }));
        }
        if (self.now)() - self.record.since > GOOD {
            return Ok(Fail(format!(
                "the unit's judge never recorded {prev} as good, so there is nothing to roll back to. NOT moving the stack"
            )));
        }
        poll(
            15,
            format!("waiting for the judge to record {prev} as good"),
        )
    }

    async fn repointing(&mut self, rolled_back: String) -> anyhow::Result<Next> {
        let rel = self.release()?;
        let st = &self.settings.stack;
        let path = rel.manifest.get("STACK_PATH").map(String::as_str);
        self.cluster
            .repoint(&st.flux_instance, &st.url, rel.tag(), path)
            .await?;
        if let Err(e) = self.cluster.reconcile(&st.source).await {
            tracing::warn!(error = %e, "could not ask Flux to fetch now; it will on its interval");
        }
        Ok(Go(Phase::Judging { rolled_back }))
    }

    async fn judging(&mut self, rolled_back_before: &str) -> anyhow::Result<Next> {
        let rel = self.release()?;
        let tag = rel.tag().to_string();
        let signed = format!("{tag}@{}", rel.get("STACK_DIGEST"));
        if let Some(r) = self
            .cluster
            .applied(&self.settings.stack.kustomization)
            .await?
            && r.starts_with(&format!("{tag}@"))
            && r != signed
        {
            let b = self.before()?.clone();
            let st = &self.settings.stack;
            self.cluster
                .repoint(&st.flux_instance, &b.url, &b.tag, None)
                .await?;
            return Ok(Fail(format!(
                "the unit applied {r}, not the signed {signed}; the stack is back on {}",
                b.tag
            )));
        }
        let (good, rolled_back) = self.judge().await?;
        if rolled_back != rolled_back_before && rolled_back.starts_with(&format!("{tag} ")) {
            return Ok(Fail(format!(
                "the unit found {tag} unhealthy and rolled the stack back to {good} ({rolled_back})"
            )));
        }
        if good == tag {
            return Ok(Go(Phase::Collecting));
        }
        let (_, now) = self
            .cluster
            .sync(&self.settings.stack.flux_instance)
            .await?;
        if now != tag {
            return Ok(Fail(format!(
                "an operator moved the stack to {now} while {tag} was on trial; the update ends here"
            )));
        }
        poll(
            30,
            format!("{tag} is on trial; the unit's judge commits it after ten healthy minutes"),
        )
    }

    async fn collecting(&mut self) -> anyhow::Result<Next> {
        let mut keep = self.release()?.refs.clone();
        keep.extend(self.committed_refs(1));
        self.registry.retain(&self.keep(keep).await?)?;
        Ok(Done)
    }
}

/// The installer a machine config names: its unattended install's, else `machine.install`'s.
fn installer_of(config: &str) -> String {
    use serde::Deserialize;
    let docs: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(config)
        .filter_map(|d| serde_yaml::Value::deserialize(d).ok())
        .collect();
    let image = |d: &serde_yaml::Value, path: &[&str]| {
        path.iter()
            .try_fold(d, |v, k| v.get(k))
            .and_then(|v| v.as_str())
            .map(String::from)
    };
    docs.iter()
        .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("UnattendedInstallConfig"))
        .find_map(|d| image(d, &["installer", "image"]))
        .or_else(|| {
            docs.iter()
                .find_map(|d| image(d, &["machine", "install", "image"]))
        })
        .unwrap_or_default()
}

/// `repo:tag@sha256:…` to `repo@sha256:…`: containerd keeps a tag@digest pull as repo@digest.
pub fn installer_pin(r: &str) -> String {
    let Some((name, digest)) = r.split_once('@') else {
        return r.into();
    };
    let (dir, last) = name.rsplit_once('/').unwrap_or(("", name));
    let last = last.split(':').next().unwrap_or(last);
    if dir.is_empty() {
        format!("{last}@{digest}")
    } else {
        format!("{dir}/{last}@{digest}")
    }
}

fn decode_efivar(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .get(4..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// `a >= b` for vX.Y.Z tags; unparseable is never newer.
pub fn version_ge(a: &str, b: &str) -> bool {
    matches!((version(a), version(b)), (Some(a), Some(b)) if a >= b)
}

#[cfg(test)]
pub(crate) mod tests;
