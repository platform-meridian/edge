//! The update as a record on the state volume. Each step observes the unit,
//! acts idempotently, then records the next phase durably, so a restart, a
//! reboot or a power cut at any point resumes from what the unit shows.
//!
//! Order: verify, import the images, copy the store off, stage the config,
//! install the OS on trial and reboot, wait for the unit to bless it, then for
//! the cluster's workloads to settle on it. A bundle is the OS alone; apps,
//! the base's among them, are MeridianApps the platform operator installs
//! (ADR-0015), so nothing here moves software in the cluster.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::bundle::{self, Manifest, Trust, machineconfig};
use crate::checks::{Check, CheckState};
use crate::diff::{self, Component, Diff};
use crate::steps::{self, State, Step, Taken};
use crate::unit::{Cluster, Registry, Settings, Talos};
use crate::upload::Uploads;

const LOADER: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// boot-commit's record of a bless: the boot it ran in, and the UKI it blessed.
#[derive(Deserialize)]
struct Blessed {
    boot_id: String,
}
const SECURE_BOOT: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const SAVED_CONFIG: &str = "config-before.yaml";
const HISTORY: usize = 50;
const SNAPSHOTS: usize = 2;
const LOG: usize = 200;
/// How long a reboot is expected to take, until the unit has shown one.
const REBOOT: i64 = 180;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Idle,
    Verifying {
        sha256: String,
    },
    Starting,
    Importing,
    /// Rebooting for the boot to sign the new OS's boot files; empty until staged.
    Signing {
        boot_id: String,
        asked: Option<i64>,
    },
    Snapshotting,
    Staging,
    Installing,
    Rebooting {
        boot_id: String,
        /// When the reboot was last requested.
        asked: Option<i64>,
    },
    Trial,
    Settling,
    Collecting,
}

/// A change to the unit's provisioned user volumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VolumeEdit {
    /// The volume, of this many MiB.
    Add(machineconfig::Provisioned, u64),
    Remove(machineconfig::Provisioned),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Release {
    /// Minted by the unit.
    pub id: String,
    /// The bundle's.
    pub sha256: String,
    pub manifest: Manifest,
    pub refs: BTreeSet<String>,
    #[serde(default)]
    pub os_done: bool,
    #[serde(default)]
    pub notes: Option<String>,
    pub signature: bundle::Signature,
    /// The OS step left the kubelet's serving rotation as the unit ran it:
    /// its approver, edge-signer, is an app's, which settles after.
    #[serde(default)]
    pub rotation_held: bool,
    /// Each layout ref and the digest it names.
    #[serde(default)]
    pub images: BTreeMap<String, String>,
    /// What verification found.
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub diff: Option<Diff>,
}

// Tests build releases field by field over this; a unit never makes one
// without the verdict its bundle earned.
#[cfg(test)]
impl Default for Release {
    fn default() -> Self {
        Release {
            id: String::new(),
            sha256: String::new(),
            manifest: Manifest::default(),
            refs: BTreeSet::new(),
            os_done: false,
            notes: None,
            signature: bundle::Signature::Signed(bundle::testkit::SIGNER.into()),
            rotation_held: false,
            images: BTreeMap::new(),
            checks: Vec::new(),
            diff: None,
        }
    }
}

impl Release {
    pub fn get(&self, k: &str) -> &str {
        self.manifest.get(k).map(String::as_str).unwrap_or_default()
    }
    pub fn tag(&self) -> &str {
        &self.id
    }
    pub fn components(&self) -> Vec<Component> {
        diff::of_release(&self.manifest, &self.refs, &self.images)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Before {
    pub talos: String,
    pub default_entry: String,
    pub started: i64,
    pub snapshot: Option<String>,
    /// The installer the unit's config names.
    #[serde(default)]
    pub installer: String,
    /// Who asked to roll the trial back.
    #[serde(default)]
    pub rollback_by: String,
    /// An operator rolled the new OS back on its trial.
    #[serde(default)]
    pub backed_out: bool,
    /// The workloads the unit ran when the update began: what settles on the
    /// new OS. One made since (an app the platform operator installs, its
    /// claim waiting on this engine's provisioner) is not waited on.
    pub workloads: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Committed,
    Failed,
    Refused,
    /// The unit went back to what it ran before.
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub release: Option<Release>,
    pub outcome: Outcome,
    pub detail: String,
    pub started: i64,
    pub finished: i64,
    pub snapshot: Option<String>,
    #[serde(default)]
    pub steps: Vec<Taken>,
    #[serde(default)]
    pub log: Vec<LogLine>,
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub rollback_reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogLine {
    pub unix: i64,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub phase: Phase,
    pub release: Option<Release>,
    pub before: Option<Before>,
    pub history: Vec<Entry>,
    pub error: String,
    /// When the current phase began.
    pub since: i64,
    /// The last update's steps, the upload's and verification's first.
    #[serde(default)]
    pub steps: Vec<Taken>,
    #[serde(default)]
    pub log: Vec<LogLine>,
    /// Who started the update.
    #[serde(default)]
    pub by: String,
}

impl Record {
    /// Why the unit must not be powered down now: an update is under way. Its
    /// OS trial is the exception: a reboot spends one of the new OS's boot tries.
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

impl Record {
    /// The release the unit runs: the last this engine committed, if any.
    pub fn running(&self) -> Option<&Release> {
        self.committed().next()
    }

    /// The release the unit has booted: the one on trial while its OS is,
    /// else the last committed.
    pub fn booted(&self) -> Option<&Release> {
        match self.phase {
            Phase::Trial | Phase::Settling => self.release.as_ref(),
            _ => self.running(),
        }
    }

    /// Each release this engine committed, the newest first.
    fn committed(&self) -> impl Iterator<Item = &Release> {
        self.history
            .iter()
            .filter(|e| e.outcome == Outcome::Committed)
            .filter_map(|e| e.release.as_ref())
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
    pub os_trial: bool,
    pub installer: String,
    pub components: Vec<Component>,
    /// The running release's MANIFEST, if this engine applied it.
    pub manifest: Manifest,
    /// Its id.
    pub release: String,
}

/// The work of the step running, as it goes.
#[derive(Debug, Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
    pub started: AtomicI64,
}

impl Progress {
    fn start(&self, total: u64, now: i64) {
        self.done.store(0, Ordering::Relaxed);
        self.started.store(now, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.total.store(0, Ordering::Relaxed);
    }

    /// Done, total and when it started; none when nothing is counted.
    pub fn now(&self) -> Option<(u64, u64, i64)> {
        let total = self.total.load(Ordering::Relaxed);
        (total > 0).then(|| {
            (
                self.done.load(Ordering::Relaxed),
                total,
                self.started.load(Ordering::Relaxed),
            )
        })
    }
}

/// What the image store holds, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Storage {
    pub held: u64,
    pub previous: u64,
    pub reclaimable: u64,
    pub free: u64,
}

#[derive(Debug, Default, PartialEq)]
pub struct Boot {
    pub selected: String,
    pub default: String,
    pub one_shot: String,
    pub count_path: String,
    /// boot-commit blessed the running UKI this boot.
    pub blessed: bool,
}

impl Boot {
    /// sd-boot did not run this boot: its variables describe an earlier one.
    fn kexec(&self) -> bool {
        self.one_shot == "kexec reboot"
    }

    /// The entry running now: a kexec boots the default.
    fn running(&self) -> &str {
        if self.kexec() || self.selected.is_empty() {
            &self.default
        } else {
            &self.selected
        }
    }

    /// sd-boot counted this boot, and boot-commit has not blessed the UKI yet.
    pub fn trial(&self) -> bool {
        !self.kexec() && !self.count_path.is_empty() && !self.blessed
    }
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Mints a release id.
pub type Mint = Arc<dyn Fn() -> String + Send + Sync>;

/// `r<unix milliseconds>`.
pub fn mint() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    format!("r{ms}")
}

/// What a MANIFEST must say, whatever the unit: a bundle without it is
/// refused as soon as its head has arrived.
pub fn manifest_check(m: &Manifest) -> anyhow::Result<()> {
    use anyhow::ensure;
    let get = |k: &str| m.get(k).map(String::as_str).unwrap_or_default();
    get("BUILT_EPOCH")
        .parse::<i64>()
        .context("BUILT_EPOCH is not a number")?;
    for k in ["INSTALLER_REF", "TALOS_VERSION", "SECUREBOOT"] {
        ensure!(!get(k).is_empty(), "the MANIFEST lacks {k}");
    }
    ensure!(
        get("INSTALLER_REF").contains("@sha256:"),
        "the MANIFEST names the installer by tag, not digest"
    );
    Ok(())
}

/// The bundle installs an OS other than the one the unit runs.
pub fn os_changes(m: &Manifest, talos: &str, installer: &str) -> bool {
    let get = |k: &str| m.get(k).map(String::as_str).unwrap_or_default();
    installer_pin(get("INSTALLER_REF")) != installer_pin(installer) || get("TALOS_VERSION") != talos
}

pub struct Engine {
    dir: PathBuf,
    settings: Settings,
    trust: Arc<dyn Trust>,
    talos: Arc<dyn Talos>,
    cluster: Arc<dyn Cluster>,
    registry: Arc<dyn Registry>,
    now: Clock,
    pub mint: Mint,
    pub record: Record,
    /// What the current phase is waiting for, for a person.
    pub detail: String,
    pub unit: Unit,
    pub progress: Arc<Progress>,
}

enum Next {
    Go(Phase),
    Wait(Duration, String),
    Fail(String),
    Refuse(String),
    /// The unit went back: what happened, and why.
    Back(String, Cause),
    Done,
}

use Next::{Back, Done, Fail, Go, Refuse, Wait};

/// Why the unit went back to its previous OS: a person asked, which ends the
/// update's steps aborted, or the new OS did not hold, which fails them.
enum Cause {
    Asked { by: String },
    Fell(&'static str),
}

impl Cause {
    fn reason(&self) -> String {
        match self {
            Cause::Asked { by } => asked(by),
            Cause::Fell(why) => (*why).into(),
        }
    }

    fn closes(&self) -> State {
        match self {
            Cause::Asked { .. } => State::Aborted,
            Cause::Fell(_) => State::Failed,
        }
    }
}

fn poll(secs: u64, why: impl Into<String>) -> anyhow::Result<Next> {
    Ok(Wait(Duration::from_secs(secs), why.into()))
}

impl Engine {
    pub fn open(
        dir: &Path,
        settings: Settings,
        trust: Arc<dyn Trust>,
        talos: Arc<dyn Talos>,
        cluster: Arc<dyn Cluster>,
        registry: Arc<dyn Registry>,
        now: Clock,
    ) -> anyhow::Result<Self> {
        let path = dir.join("state.json");
        let record = match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(r) => r,
                Err(e) => {
                    // Not trusted: the unit's boot finishes what was started.
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
            trust,
            talos,
            cluster,
            registry,
            now,
            mint: Arc::new(mint),
            record,
            detail: String::new(),
            unit: Unit::default(),
            progress: Arc::default(),
        })
    }

    pub fn uploads(&self) -> Uploads {
        Uploads::with(
            &self.dir.join("upload"),
            Some(self.trust.clone()),
            self.now.clone(),
        )
    }

    /// A line for this update's log, kept with the record at its next save.
    pub fn note(&mut self, text: impl Into<String>) {
        let text = text.into();
        if self.record.log.last().is_some_and(|l| l.text == text) {
            return;
        }
        self.record.log.push(LogLine {
            unix: (self.now)(),
            text,
        });
        let over = self.record.log.len().saturating_sub(LOG);
        self.record.log.drain(..over);
    }

    fn release_dir(&self, id: &str) -> PathBuf {
        self.dir.join("releases").join(id)
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

    /// Adds or removes a provisioned user volume (the storage provisioner's,
    /// `crate::volumes`) in the config the node runs and boots. The engine is
    /// the machine config's one writer, so this waits out an update: refused
    /// unless idle with nothing staged for the next boot. Repeating one is a
    /// no-op.
    pub async fn edit_volume(&mut self, edit: VolumeEdit) -> anyhow::Result<()> {
        anyhow::ensure!(self.idle(), "an update is in progress");
        let running = self.talos.running_config().await?;
        anyhow::ensure!(
            same_config(&running, &self.talos.machine_config().await?),
            "a config is staged for the next boot"
        );
        let have = machineconfig::provisioned(&running)?;
        let next = match &edit {
            VolumeEdit::Add(v, mib) => match have.get(v) {
                Some(had) if had == mib => return Ok(()),
                Some(had) => anyhow::bail!(
                    "{} is {had} MiB, not {mib}: a claim is not resized",
                    v.name()
                ),
                None => machineconfig::with_provisioned(&running, v, *mib)?,
            },
            VolumeEdit::Remove(v) if !have.contains_key(v) => return Ok(()),
            VolumeEdit::Remove(v) => machineconfig::without_provisioned(&running, v)?,
        };
        self.talos.apply_config(&next).await?;
        tracing::info!(edit = ?edit, "provisioned volumes changed");
        Ok(())
    }

    /// While idle.
    pub async fn request_verify(&mut self, sha256: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.idle(), "an update is in progress");
        let up = self
            .uploads()
            .current()
            .filter(|u| u.complete && u.sha256 == sha256)
            .context("no complete upload of that bundle")?;
        anyhow::ensure!(
            up.refused.is_empty(),
            "the bundle is refused: {}",
            up.refused
        );
        self.record.steps = vec![Taken {
            step: Step::Upload,
            state: State::Done,
            started: up.started,
            finished: up.finished,
        }];
        self.record.log.clear();
        self.record.by = up.by.clone();
        self.note(format!(
            "verifying bundle {}{}",
            &sha256[..12.min(sha256.len())],
            from(&up.by)
        ));
        self.go(Phase::Verifying {
            sha256: sha256.into(),
        })
    }

    pub async fn request_apply(&mut self, tag: &str, by: &str) -> anyhow::Result<()> {
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
            "the unit is on trial of {}: wait for it to be blessed or to fall back",
            boot.selected
        );
        self.record.error.clear();
        self.record.by = by.into();
        self.record.steps.retain(|t| t.step <= Step::Verify);
        let who = if by.is_empty() {
            String::new()
        } else {
            format!(" by {by}")
        };
        self.note(format!("applying {tag}{who}"));
        self.go(Phase::Starting)
    }

    /// Rereads the unit, a part that cannot be read keeping its last reading;
    /// true if anything changed.
    pub async fn refresh_unit(&mut self) -> bool {
        let was = self.unit.clone();
        match async {
            let (v, b) = (self.talos.version().await?, self.boot().await?);
            anyhow::Ok((v, b, installer_of(&self.talos.running_config().await?)))
        }
        .await
        {
            Ok((v, b, i)) => {
                (
                    self.unit.talos_version,
                    self.unit.os_trial,
                    self.unit.installer,
                ) = (v, b.trial(), i)
            }
            Err(e) => tracing::debug!(error = format!("{e:#}"), "could not read the unit's OS"),
        }
        match self.record.booted() {
            Some(r) => {
                let u = &mut self.unit;
                (u.components, u.manifest, u.release) =
                    (r.components(), r.manifest.clone(), r.tag().to_string());
            }
            None => match self.cluster.images_in_use().await {
                Ok(refs) => {
                    let registry = &self.registry;
                    self.unit.components = diff::of_refs(&refs, |r| registry.digest(r));
                    self.unit.manifest.clear();
                    self.unit.release.clear();
                }
                Err(e) => tracing::debug!(
                    error = format!("{e:#}"),
                    "could not read what the unit runs"
                ),
            },
        }
        self.unit != was
    }

    /// Reboots or shuts the unit down; says what it boots next.
    pub async fn power(&mut self, p: Power) -> anyhow::Result<String> {
        if let Some(why) = self.record.power_refusal() {
            anyhow::bail!(why);
        }
        let b = self.boot().await?;
        let action = match p {
            Power::Reboot => {
                self.talos.reboot().await?;
                "rebooting"
            }
            Power::Shutdown => {
                self.talos.shutdown().await?;
                "shutting down"
            }
        };
        if !b.trial() {
            return Ok(action.into());
        }
        Ok(format!(
            "{action}: the OS on trial, {}, spends one of its boot tries",
            b.selected
        ))
    }

    fn go(&mut self, p: Phase) -> anyhow::Result<()> {
        let now = (self.now)();
        if let Some(s) = steps::of(&p) {
            // With no new OS there is no OS trial: the system settling is the commit's.
            let s = match s {
                Step::OsTrial if steps::skipped(&self.record.steps, Step::Install) => Step::Commit,
                s => s,
            };
            steps::enter(&mut self.record.steps, s, now);
        }
        if p != Phase::Idle {
            self.note(phase_word(&p));
        }
        self.record.phase = p;
        self.record.since = now;
        self.detail.clear();
        self.save()
    }

    /// A step failed and is retried: in the log, not the record.
    pub fn retrying(&mut self, e: &anyhow::Error) {
        self.detail = format!("retrying: {e:#}");
        self.note(self.detail.clone());
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
            Phase::Signing { boot_id, asked } => self.signing(boot_id, asked).await?,
            Phase::Snapshotting => self.snapshotting().await?,
            Phase::Staging => self.staging().await?,
            Phase::Installing => self.installing().await?,
            Phase::Rebooting { boot_id, asked } => self.rebooting(boot_id, asked).await?,
            Phase::Trial => self.trial().await?,
            Phase::Settling => self.settling().await?,
            Phase::Collecting => self.collecting().await?,
        };
        match next {
            Go(p) => {
                self.go(p)?;
                Ok(Tick::Moved)
            }
            Wait(d, why) => {
                self.note(why.clone());
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
            Back(why, cause) => {
                self.finish_back(why, cause)?;
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
        let closes = if outcome == Outcome::Committed {
            State::Done
        } else {
            State::Failed
        };
        self.finish_as(outcome, detail, String::new(), closes)
    }

    fn finish_back(&mut self, detail: String, cause: Cause) -> anyhow::Result<()> {
        self.finish_as(Outcome::RolledBack, detail, cause.reason(), cause.closes())
    }

    fn finish_as(
        &mut self,
        outcome: Outcome,
        detail: String,
        reason: String,
        closes: State,
    ) -> anyhow::Result<()> {
        let now = (self.now)();
        let ok = outcome == Outcome::Committed;
        steps::close(&mut self.record.steps, closes, now);
        self.note(detail.clone());
        self.progress.stop();
        let b = self.record.before.take();
        let first = self.record.steps.iter().find(|t| t.step > Step::Verify);
        self.record.history.insert(
            0,
            Entry {
                release: self.record.release.clone(),
                outcome,
                started: b
                    .as_ref()
                    .map(|b| b.started)
                    .or(first.map(|t| t.started))
                    .unwrap_or(now),
                finished: now,
                snapshot: b.and_then(|b| b.snapshot),
                detail: detail.clone(),
                steps: self.record.steps.clone(),
                log: self.record.log.clone(),
                by: self.record.by.clone(),
                rollback_reason: reason,
            },
        );
        self.record.history.truncate(HISTORY);
        if ok {
            self.record.error.clear();
        } else {
            tracing::error!(%detail, "update stopped");
            self.record.error = detail;
        }
        // A failed or rolled back update stays verified, so it can be applied again.
        if !matches!(outcome, Outcome::Failed | Outcome::RolledBack) {
            self.record.release = None;
        }
        self.go(Phase::Idle)?;
        self.tidy();
        Ok(())
    }

    /// Unpacked releases, uploads and a saved config nothing refers to any more.
    fn tidy(&self) {
        let _ = std::fs::remove_file(self.dir.join(SAVED_CONFIG));
        let keep = self.record.release.as_ref().map(|r| r.id.clone());
        if let Ok(dirs) = std::fs::read_dir(self.dir.join("releases")) {
            for d in dirs.flatten() {
                if Some(d.file_name().to_string_lossy().into_owned()) != keep {
                    let _ = std::fs::remove_dir_all(d.path());
                }
            }
        }
    }

    async fn verifying(&mut self, sha: &str) -> anyhow::Result<Tick> {
        let id = (self.mint)();
        let dir = self.release_dir(&id);
        let _ = std::fs::remove_dir_all(&dir);
        self.detail = "checking the signature and unpacking".into();
        let bundle = self.uploads().bundle();
        let size = std::fs::metadata(&bundle).map_or(0, |m| m.len());
        self.progress.start(size.max(1), (self.now)());
        let (d, trust, progress) = (dir.clone(), self.trust.clone(), self.progress.clone());
        let unpacked = tokio::task::spawn_blocking(move || {
            bundle::unpack_counting(&bundle, &d, trust.as_ref(), &progress.done)
        })
        .await?;
        self.progress.stop();
        let release = match unpacked.and_then(|u| {
            let (components, _) = bundle::check(&dir)?;
            let images = bundle::layout_images(&dir.join(bundle::IMAGES))?;
            Ok(Release {
                id: id.clone(),
                sha256: sha.into(),
                manifest: u.manifest,
                refs: components.refs(),
                notes: bundle::notes(&dir),
                signature: u.signature,
                images,
                os_done: false,
                rotation_held: false,
                checks: Vec::new(),
                diff: None,
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
        self.refresh_unit().await;
        self.verified(release).await?;
        if self.record.release.is_some() {
            self.uploads().discard();
        }
        Ok(Tick::Moved)
    }

    /// A release checked against the unit: kept for `Apply`, or refused.
    async fn verified(&mut self, mut release: Release) -> anyhow::Result<()> {
        let refusal = self.refusal(&release).await;
        let (checks, diff, short) = self.assess(&release, refusal.as_deref()).await;
        (release.checks, release.diff) = (checks, Some(diff));
        let dir = self.release_dir(&release.id);
        self.record.release = Some(release);
        if let Some(why) = refusal.or(short) {
            let _ = std::fs::remove_dir_all(&dir);
            return self.finish(Outcome::Refused, why);
        }
        self.record.error.clear();
        steps::close(&mut self.record.steps, State::Done, (self.now)());
        self.note("verified");
        self.go(Phase::Idle)
    }

    /// What verification found, for a person: each check passed or not, and
    /// what applying changes. Also why the images would not fit, if they
    /// would not.
    async fn assess(
        &self,
        rel: &Release,
        refusal: Option<&str>,
    ) -> (Vec<Check>, Diff, Option<String>) {
        let u = &self.unit;
        let mut checks = vec![signature(&rel.signature)];
        checks.push(match refusal {
            None => Check::new("compatible", CheckState::Pass, ""),
            Some(why) => Check::new("compatible", CheckState::Fail, why),
        });
        let layout = self.release_dir(&rel.id).join(bundle::IMAGES);
        let mut short = None;
        let missing = match layout.exists() {
            true => self.registry.missing(&layout),
            false => Ok(0),
        };
        match (missing, self.registry.usage()) {
            (Ok(need), Ok((_, free))) => {
                let detail = format!("{need} bytes to store, {free} free");
                if need <= free {
                    checks.push(Check::new("space", CheckState::Pass, detail));
                } else {
                    short = Some(format!(
                        "the images need {need} bytes and the image store has {free} free"
                    ));
                    checks.push(Check::new("space", CheckState::Fail, detail));
                }
            }
            (Err(e), _) | (_, Err(e)) => checks.push(Check::new(
                "space",
                CheckState::Note,
                format!("unknown: {e:#}"),
            )),
        }
        let reboot = os_changes(&rel.manifest, &u.talos_version, &u.installer);
        let config_changes = match async {
            let next = self.merged(rel).await?;
            anyhow::Ok(!same_config(&next, &self.talos.machine_config().await?))
        }
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    error = format!("{e:#}"),
                    "could not compare the machine config"
                );
                true
            }
        };
        let downtime = if reboot { self.reboot_secs() } else { 0 };
        checks.push(Check::new(
            "reboot",
            CheckState::Note,
            if reboot { "needed" } else { "none" },
        ));
        checks.push(Check::new(
            "downtime",
            CheckState::Note,
            format!("{downtime}"),
        ));
        let before = self.record.running();
        let diff = Diff {
            components: diff::components(&u.components, &rel.components(), before.is_some()),
            talos: (u.talos_version.clone(), rel.get("TALOS_VERSION").into()),
            installer: (u.installer.clone(), rel.get("INSTALLER_REF").into()),
            release: (
                before.map(|r| r.tag().to_string()).unwrap_or_default(),
                rel.tag().into(),
            ),
            reboot,
            config_changes,
            downtime_secs: downtime,
            removals_known: before.is_some(),
        };
        (checks, diff, short)
    }

    /// The unit's last reboot through an update, else a guess.
    fn reboot_secs(&self) -> i64 {
        self.record
            .history
            .iter()
            .flat_map(|e| &e.steps)
            .find(|t| t.step == Step::Reboot && t.state == State::Done && t.finished > t.started)
            .map_or(REBOOT, |t| t.finished - t.started)
    }

    /// Why this unit must not take `rel`, checked with reads alone.
    async fn refusal(&self, rel: &Release) -> Option<String> {
        self.check(rel).await.err().map(|e| format!("{e:#}"))
    }

    async fn check(&self, rel: &Release) -> anyhow::Result<()> {
        use anyhow::ensure;
        manifest_check(&rel.manifest)?;
        let dir = self.release_dir(&rel.id);
        let carried = match dir.join(bundle::IMAGES).exists() {
            true => bundle::layout_refs(&dir.join(bundle::IMAGES))?,
            false => BTreeSet::new(),
        };
        let lacking: Vec<&str> = rel
            .refs
            .iter()
            .filter(|r| !carried.contains(*r) && self.registry.digest(r).is_none())
            .map(String::as_str)
            .collect();
        ensure!(
            lacking.is_empty(),
            "the bundle relies on images the unit does not hold: {}",
            lacking.join(", ")
        );
        let running = self
            .talos
            .version()
            .await
            .context("read the unit's Talos version")?;
        ensure!(
            version_ge(rel.get("TALOS_VERSION"), &running),
            "Downgrade: Talos {running} to {}",
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
        // The release the unit runs is the lock: the same profile, and no
        // older base. A unit that has run none takes the bundle it is
        // provisioned with.
        if let Some(running) = self.record.running() {
            for (k, v) in rel.manifest.iter().filter(|(k, _)| k.starts_with("LOCK_")) {
                let theirs = running.get(k);
                ensure!(
                    theirs == v,
                    "the bundle is for {}={v:?} and the unit runs {}={theirs:?}",
                    &k[5..],
                    &k[5..]
                );
            }
            let (unit, epoch): (i64, i64) = (
                running.get("BUILT_EPOCH").parse().unwrap_or(0),
                rel.get("BUILT_EPOCH").parse().unwrap_or(0),
            );
            ensure!(
                epoch >= unit,
                "Downgrade: a base built {} to one built {}",
                built(unit),
                built(epoch)
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
        let at = self.release_dir(&rel.id).join(bundle::PATCH);
        let patch =
            std::fs::read_to_string(&at).with_context(|| format!("reading {}", at.display()))?;
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
            ("LoaderBootCountPath", &mut b.count_path),
        ] {
            *dst = self
                .talos
                .read(&var(name))
                .await
                .with_context(|| format!("read {name}"))?
                .map(|v| decode_efivar(&v))
                .unwrap_or_default();
        }
        // LoaderBootCountPath stays set for the whole boot: the bless is recorded beside it.
        let record = self
            .talos
            .read(&self.settings.bless)
            .await
            .context("read boot-commit's record")?;
        if let Some(r) = record.and_then(|r| serde_json::from_slice::<Blessed>(&r).ok()) {
            b.blessed = r.boot_id.trim() == self.boot_id().await?;
        }
        Ok(b)
    }

    /// The new OS is on trial or already committed.
    async fn left_old_os(&self) -> anyhow::Result<bool> {
        let b = self.boot().await?;
        Ok(b.trial()
            || !b
                .default
                .eq_ignore_ascii_case(&self.before()?.default_entry))
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
            default_entry: self.boot().await?.default,
            started: (self.now)(),
            snapshot: None,
            installer: installer_of(&running),
            rollback_by: String::new(),
            backed_out: false,
            workloads: self
                .cluster
                .workloads()
                .await
                .context("read the workloads the unit runs")?,
        });
        Ok(Go(Phase::Importing))
    }

    /// What this engine's releases named that the newest `n` committed, and
    /// the one under way, do not, nor the cluster runs: what it may collect.
    /// Nothing else in the store is its to collect.
    async fn beyond(&self, n: usize) -> anyhow::Result<BTreeSet<String>> {
        let kept: BTreeSet<&String> = self
            .record
            .committed()
            .take(n)
            .chain(self.record.release.as_ref())
            .flat_map(|r| &r.refs)
            .collect();
        let running = self
            .cluster
            .images_in_use()
            .await
            .context("read the images the cluster runs")?;
        Ok(self
            .record
            .history
            .iter()
            .filter_map(|e| e.release.as_ref())
            .flat_map(|r| &r.refs)
            .filter(|r| !kept.contains(r) && !running.contains(*r))
            .cloned()
            .collect())
    }

    async fn importing(&mut self) -> anyhow::Result<Next> {
        self.detail = "importing the images".into();
        // A partial bundle's release runs on images an older release brought.
        let drop = self.beyond(2).await?;
        let dir = self.release_dir(&self.release()?.id);
        let (layout, apps) = (dir.join(bundle::IMAGES), dir.join(bundle::APPS));
        let (registry, host) = (self.registry.clone(), self.settings.registry.clone());
        tokio::task::spawn_blocking(move || {
            registry.forget(&drop)?;
            if layout.exists() {
                registry.import(&layout)?;
            }
            if apps.exists() {
                registry.import_apps(&apps, &host)?;
            }
            anyhow::Ok(())
        })
        .await??;
        Ok(Go(Phase::Signing {
            boot_id: String::new(),
            asked: None,
        }))
    }

    /// Whether the release changes the OS, not only its config.
    async fn changes_os(&mut self) -> anyhow::Result<bool> {
        let (m, installer) = (
            self.release()?.manifest.clone(),
            self.before()?.installer.clone(),
        );
        Ok(os_changes(&m, &self.talos.version().await?, &installer))
    }

    /// Boot signing, on a unit with boot keys.
    fn boot_keys(&self) -> Option<crate::boot::Settings> {
        self.settings
            .boot_signing
            .clone()
            .filter(crate::boot::Settings::has_keys)
    }

    /// Stages the release's OS for the boot to sign.
    async fn stage_for_signing(&mut self, s: crate::boot::Settings) -> anyhow::Result<Next> {
        self.detail = "staging the new OS for the unit to sign".into();
        let installer = self.release()?.get("INSTALLER_REF").to_string();
        let (registry, release) = (self.registry.clone(), self.release_dir(&self.release()?.id));
        tokio::task::spawn_blocking(move || {
            crate::boot::stage(&*registry, &s, &release, &installer)
        })
        .await??;
        Ok(Go(Phase::Signing {
            boot_id: self.boot_id().await?,
            asked: None,
        }))
    }

    /// A new OS on a unit with boot keys: staged, then a reboot for the boot
    /// to sign it while the keys unseal.
    async fn signing(&mut self, before: String, asked: Option<i64>) -> anyhow::Result<Next> {
        let Some(s) = self.boot_keys() else {
            return Ok(Go(Phase::Snapshotting));
        };
        if before.is_empty() {
            if self.release()?.os_done || !self.changes_os().await? {
                return Ok(Go(Phase::Snapshotting));
            }
            return self.stage_for_signing(s).await;
        }
        let installer = self.release()?.get("INSTALLER_REF").to_string();
        if self.boot_id().await? == before {
            let now = (self.now)();
            if asked.is_none_or(|t| now - t > 2 * self.reboot_secs().max(REBOOT)) {
                self.talos.reboot().await?;
                self.record.phase = Phase::Signing {
                    boot_id: before,
                    asked: Some(now),
                };
                self.save()?;
            }
            return poll(30, "rebooting for the unit to sign the new OS");
        }
        match crate::boot::signed(&s) {
            Ok(signed) if signed == installer => {
                self.note(format!("the unit signed {installer}'s boot files"));
                Ok(Go(Phase::Snapshotting))
            }
            Ok(signed) => Ok(Fail(format!(
                "the unit signed {signed}, not {installer}. The OS is unchanged"
            ))),
            Err(e) => Ok(Fail(format!(
                "the unit did not sign {installer}'s boot files: {e:#}. The OS is unchanged"
            ))),
        }
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
            "taken": (self.now)(), "talos_before": b.talos,
            "release_before": self.record.running().map(|r| r.tag().to_string()), "update": tag, "bytes": got, "sha256": sha,
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

    /// The config the OS step applies: serving rotation stays as the unit runs
    /// it until the release whose edge-signer approves its requests is committed.
    async fn os_config(&mut self) -> anyhow::Result<String> {
        let rel = self.release()?.clone();
        let running = self
            .talos
            .running_config()
            .await
            .context("read the unit's running config")?;
        let (config, held) =
            machineconfig::rotation_as_running(&self.merged(&rel).await?, &running)?;
        if let Some(r) = self.record.release.as_mut() {
            r.rotation_held |= held;
        }
        Ok(config)
    }

    async fn staging(&mut self) -> anyhow::Result<Next> {
        let merged = match self.os_config().await {
            Ok(m) => m,
            Err(e) => return Ok(Fail(format!("{e:#}"))),
        };
        self.talos
            .stage_config(&merged, false)
            .await
            .context("stage the machine config")?;
        Ok(Go(Phase::Installing))
    }

    fn skip_step(&mut self) {
        if let Some(t) = self
            .record
            .steps
            .last_mut()
            .filter(|t| t.state == State::Running)
        {
            t.state = State::Skipped;
            t.finished = (self.now)();
        }
    }

    async fn installing(&mut self) -> anyhow::Result<Next> {
        if self.release()?.os_done {
            self.skip_step();
            return Ok(Go(Phase::Settling));
        }
        let b = self.boot().await?;
        if b.trial() {
            return Ok(Go(Phase::Trial));
        }
        // Installed (the default names the new UKI) but not yet rebooted into it.
        if !b
            .default
            .eq_ignore_ascii_case(&self.before()?.default_entry)
        {
            return Ok(Go(Phase::Rebooting {
                boot_id: self.boot_id().await?,
                asked: None,
            }));
        }
        let installer = installer_pin(self.release()?.get("INSTALLER_REF"));
        if !self.changes_os().await? {
            // The unit runs this OS already: the config alone, and no reboot.
            let config = self.os_config().await?;
            match self.talos.apply_config(&config).await {
                Ok(()) => {
                    if let Some(r) = self.record.release.as_mut() {
                        r.os_done = true;
                    }
                    self.skip_step();
                    return Ok(Go(Phase::Settling));
                }
                Err(e) => {
                    let signed = self.release()?.get("INSTALLER_REF").to_string();
                    if let Some(s) = self.boot_keys()
                        && crate::boot::signed(&s).ok() != Some(signed)
                    {
                        // The staged config applies at the signing reboot.
                        tracing::warn!(error = %e, "the config needs a reboot: rebooting for the unit to sign the OS");
                        return self.stage_for_signing(s).await;
                    }
                    tracing::warn!(error = %e, "the config needs a reboot: installing the OS as usual");
                }
            }
        }
        let image = match self.signed_installer(&installer).await {
            Ok(i) => i,
            Err(e) => {
                return Ok(Fail(format!(
                    "the unit could not sign {installer}'s boot files: {e:#}. The OS is unchanged; {}. \
                     Nothing else changed",
                    self.restore().await?
                )));
            }
        };
        self.detail = "installing the new OS beside the running one".into();
        if let Err(e) = self.talos.install(&image).await {
            // Until the installer runs, the install waits on what serves it.
            if e.downcast_ref::<crate::unit::InstallerFailed>().is_none() {
                return Err(e);
            }
            return Ok(Fail(format!(
                "{installer} did not install: {e:#}. The OS is unchanged; {}. \
                 Nothing else changed; applying again retries",
                self.restore().await?
            )));
        }
        Ok(Go(Phase::Rebooting {
            boot_id: self.boot_id().await?,
            asked: None,
        }))
    }

    /// The installer to install: on a unit with boot keys, with the boot files it signed.
    async fn signed_installer(&mut self, installer: &str) -> anyhow::Result<String> {
        let Some(s) = self.boot_keys() else {
            return Ok(installer.into());
        };
        let (registry, image, scratch) = (
            self.registry.clone(),
            installer.to_string(),
            self.dir.join("boot-signing"),
        );
        let derived = tokio::task::spawn_blocking(move || {
            crate::boot::derive(&*registry, &s, &image, &scratch)
        })
        .await??;
        self.note(format!(
            "the new OS with the boot files the unit signed: {derived}"
        ));
        Ok(derived)
    }

    async fn rebooting(&mut self, before: String, asked: Option<i64>) -> anyhow::Result<Next> {
        if self.boot_id().await? == before {
            // A second request cancels a reboot underway, as it stops pods.
            let now = (self.now)();
            if asked.is_none_or(|t| now - t > 2 * self.reboot_secs().max(REBOOT)) {
                self.talos.reboot().await?;
                self.record.phase = Phase::Rebooting {
                    boot_id: before,
                    asked: Some(now),
                };
                self.save()?;
            }
            return poll(30, "rebooting into the new OS");
        }
        if self.left_old_os().await? {
            return Ok(Go(Phase::Trial));
        }
        Ok(Back(
            format!(
                "the unit rebooted on its previous OS, as the install did not take or the new OS did not stay up; \
                 {}. Nothing else changed; applying again repeats the upgrade",
                self.restore().await?
            ),
            Cause::Fell("the new OS did not boot"),
        ))
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
                    "{} is on trial; the unit blesses it once its watchdog is fed with every check passing",
                    b.selected
                ),
            );
        }
        let before = self.before()?;
        // Fallen back (its tries spent) or rolled back: the default is not what runs, or is the old one.
        if !b.running().eq_ignore_ascii_case(&b.default)
            || b.default.eq_ignore_ascii_case(&before.default_entry)
        {
            let (why, cause) = if before.backed_out {
                (
                    "an operator rolled the update back on its trial",
                    Cause::Asked {
                        by: before.rollback_by.clone(),
                    },
                )
            } else {
                (
                    "the new OS did not stay up, and the unit went back to its previous OS by itself",
                    Cause::Fell("the new OS did not stay up"),
                )
            };
            return Ok(Back(
                format!(
                    "{why}; {}. Applying again repeats the upgrade",
                    self.restore().await?
                ),
                cause,
            ));
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

    /// The new OS is blessed: the cluster's workloads come back on it.
    async fn settling(&mut self) -> anyhow::Result<Next> {
        let before = &self.before()?.workloads;
        let waiting: Vec<String> = self
            .cluster
            .not_ready()
            .await?
            .into_iter()
            .filter(|w| before.contains(w))
            .collect();
        if waiting.is_empty() {
            return Ok(Go(Phase::Collecting));
        }
        poll(15, format!("waiting for {}", waiting.join(", ")))
    }

    async fn collecting(&mut self) -> anyhow::Result<Next> {
        if self.release()?.rotation_held {
            let rel = self.release()?.clone();
            self.talos
                .apply_config(&self.merged(&rel).await?)
                .await
                .context("turn the kubelet's serving certificate rotation on")?;
            if let Some(r) = self.record.release.as_mut() {
                r.rotation_held = false;
            }
            self.note("the kubelet's serving certificate rotation is on: edge-signer approves it");
            self.save()?;
        }
        self.registry.forget(&self.beyond(1).await?)?;
        Ok(Done)
    }

    /// Rolls the release on trial back: the OS on trial through Talos, or, with
    /// it blessed and the system settling, by booting the previous OS again.
    pub async fn request_rollback(&mut self, tag: &str, by: &str) -> anyhow::Result<String> {
        match self.record.phase.clone() {
            Phase::Trial => {
                let rel = self.release()?.tag().to_string();
                anyhow::ensure!(rel == tag, "{rel} is on trial, not {tag}");
                let b = self.boot().await?;
                anyhow::ensure!(b.trial(), "the new OS is not on trial");
                if let Some(b) = self.record.before.as_mut() {
                    b.rollback_by = by.into();
                    b.backed_out = true;
                }
                self.note(format!("{} asked to roll the new OS back", who(by)));
                self.save()?;
                if let Err(e) = self.talos.rollback().await {
                    if let Some(b) = self.record.before.as_mut() {
                        b.backed_out = false;
                    }
                    self.save()?;
                    return Err(e);
                }
                Ok(format!(
                    "rolling the new OS, {}, back: the unit boots {} again",
                    b.selected,
                    self.before()?.default_entry
                ))
            }
            // The OS is blessed and the workloads settling on it: the previous
            // OS, which the unit keeps until the next install, boots again.
            Phase::Settling => {
                let rel = self.release()?.tag().to_string();
                anyhow::ensure!(rel == tag, "{rel} is on trial, not {tag}");
                let rebooted = self.release()?.diff.as_ref().is_none_or(|d| d.reboot);
                if let Some(b) = self.record.before.as_mut() {
                    b.rollback_by = by.into();
                    b.backed_out = true;
                }
                self.note(format!("{} asked to roll the update back", who(by)));
                if !rebooted {
                    self.record.phase = Phase::Trial;
                    self.save()?;
                    return Ok(format!("ending {tag}: it changed no OS"));
                }
                self.record.phase = Phase::Trial;
                self.save()?;
                self.talos.rollback().await?;
                Ok(format!(
                    "rolling {tag} back: the unit boots {} again",
                    self.before()?.default_entry
                ))
            }
            Phase::Idle => anyhow::bail!("nothing is on trial to roll back"),
            _ => anyhow::bail!("the update is under way: nothing is on trial to roll back"),
        }
    }

    /// What the image store holds, in bytes: what only the previous release
    /// holds, and what neither it nor the running one does, which a collect
    /// frees.
    pub async fn storage(&self) -> anyhow::Result<Storage> {
        let (beyond_now, beyond_both) = (self.beyond(1).await?, self.beyond(2).await?);
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || {
            let (held, free) = registry.usage()?;
            let with_previous = registry.forgettable(&beyond_now)?;
            let reclaimable = registry.forgettable(&beyond_both)?;
            anyhow::Ok(Storage {
                held,
                previous: with_previous.saturating_sub(reclaimable),
                reclaimable,
                free,
            })
        })
        .await?
    }

    /// Drops what no kept release names; the previous one's too if asked.
    pub async fn collect(&mut self, previous: bool) -> anyhow::Result<u64> {
        anyhow::ensure!(self.idle(), "an update is in progress");
        let drop = self.beyond(if previous { 1 } else { 2 }).await?;
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || registry.forget(&drop)).await?
    }
}

fn from(by: &str) -> String {
    if by.is_empty() {
        String::new()
    } else {
        format!(" from {by}")
    }
}

fn who(by: &str) -> &str {
    if by.is_empty() { "an operator" } else { by }
}

/// The signature's check, from the trust's verdict: a bundle the policy takes
/// unsigned is taken, not passed, so it is a note for a person to weigh.
fn signature(s: &bundle::Signature) -> Check {
    match s {
        bundle::Signature::Signed(by) => Check::new("signature", CheckState::Pass, by.as_str()),
        bundle::Signature::Unsigned => Check::new("signature", CheckState::Note, ""),
    }
}

/// A base's build instant as a person reads it, in UTC: `2026-10-30 22:59Z`.
fn built(epoch: i64) -> String {
    let (days, secs) = (epoch.div_euclid(86_400), epoch.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year}-{month:02}-{day:02} {:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60
    )
}

fn asked(by: &str) -> String {
    format!("{} asked", who(by))
}

fn phase_word(p: &Phase) -> &'static str {
    match p {
        Phase::Idle => "idle",
        Phase::Verifying { .. } => "verifying",
        Phase::Starting => "starting",
        Phase::Importing => "importing the images",
        Phase::Signing { .. } => "rebooting for the unit to sign the new OS's boot files",
        Phase::Snapshotting => "copying the store",
        Phase::Staging => "staging the machine config",
        Phase::Installing => "installing the OS",
        Phase::Rebooting { .. } => "rebooting",
        Phase::Trial => "the new OS is on trial",
        Phase::Settling => "the new OS is committed; waiting for the system to settle",
        Phase::Collecting => "collecting old images",
    }
}

/// The same documents, whatever their order or formatting.
fn same_config(a: &str, b: &str) -> bool {
    let docs = |y: &str| -> Option<Vec<serde_json::Value>> {
        let mut d = edge_bundle::yaml::documents(y).ok()?;
        d.sort_by_key(serde_json::Value::to_string);
        Some(d)
    };
    docs(a).is_some_and(|a| Some(a) == docs(b))
}

/// The installer a machine config names: its unattended install's, else `machine.install`'s.
fn installer_of(config: &str) -> String {
    let docs = edge_bundle::yaml::documents(config).unwrap_or_default();
    let image = |d: &serde_json::Value, path: &[&str]| {
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
