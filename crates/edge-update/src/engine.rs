//! The update as a record on the state volume. Each step observes the unit,
//! acts idempotently, then records the next phase durably, so a restart, a
//! reboot or a power cut at any point resumes from what the unit shows.
//!
//! Order: verify, import the images, copy the store off, stage the config,
//! install the OS on trial and reboot, wait for the unit to commit it, update
//! the judge, then move the stack and wait for the judge's verdict. The stack
//! never moves before the OS is committed, so a cut leaves the old system or
//! the new OS under the old stack.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::bundle::components::{self, Components, Installed};
use crate::bundle::{self, Manifest, Verifier, machineconfig};
use crate::diff::{self, Component, Diff};
use crate::judge::{self, Check, CheckState, Judge};
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
/// In a release's directory: its stack composed for the merged set, and the set.
const COMPOSED: &str = "composed";
const INSTALLED: &str = "installed.json";

const INSTALL: i64 = 30 * 60;
const SETTLE: i64 = 20 * 60;
const ROLLOUT: i64 = 10 * 60;
const GOOD: i64 = 20 * 60;
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
    Seeding,
    AwaitingGood,
    Repointing {
        rolled_back: String,
    },
    Judging {
        rolled_back: String,
    },
    Collecting,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Release {
    pub sha256: String,
    pub manifest: Manifest,
    pub refs: BTreeSet<String>,
    #[serde(default)]
    pub os_done: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub signer: String,
    /// The OS step left the kubelet's serving rotation off: its approver comes with the stack.
    #[serde(default)]
    pub rotation_held: bool,
    /// The bundle's FluxInstance is applied.
    #[serde(default)]
    pub instance_applied: bool,
    /// Each layout ref and the digest it names.
    #[serde(default)]
    pub images: BTreeMap<String, String>,
    /// What verification found.
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub diff: Option<Diff>,
    /// With components: the stack its set was composed on.
    #[serde(default)]
    pub composed_on: Option<String>,
    /// What the bundle itself brought: a base or not, its modules, and those it removed.
    #[serde(default)]
    pub brings_base: bool,
    #[serde(default)]
    pub modules: BTreeSet<String>,
    #[serde(default)]
    pub removes: BTreeSet<String>,
    /// Each ref of the installed set and what it belongs to: `base` or a module.
    #[serde(default)]
    pub owners: BTreeMap<String, String>,
}

/// A unit's installed set, and the stack composed for it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Composed {
    stack: String,
    /// The repository the stack is tagged in.
    #[serde(default)]
    repo: String,
    installed: Installed,
}

impl Release {
    pub fn get(&self, k: &str) -> &str {
        self.manifest.get(k).map(String::as_str).unwrap_or_default()
    }
    pub fn tag(&self) -> &str {
        self.get("STACK_TAG")
    }
    pub fn components(&self) -> Vec<Component> {
        diff::of_release(&self.manifest, &self.refs, &self.images, &self.owners)
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
    /// The installer the unit's config names.
    #[serde(default)]
    pub installer: String,
    /// Who asked to roll the trial back.
    #[serde(default)]
    pub rollback_by: String,
    /// An operator rolled the new OS back on its trial.
    #[serde(default)]
    pub backed_out: bool,
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
    /// The stack trial this update ended, with nothing to roll back to.
    #[serde(default)]
    pub took_over: String,
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
    /// The release the unit runs, if this engine committed it.
    pub fn running(&self, tag: &str) -> Option<&Release> {
        self.history
            .iter()
            .filter(|e| e.outcome == Outcome::Committed)
            .filter_map(|e| e.release.as_ref())
            .find(|r| !tag.is_empty() && r.tag() == tag)
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
    pub installer: String,
    pub flux_version: String,
    pub components: Vec<Component>,
    /// The running release's MANIFEST, if this engine applied it.
    pub manifest: Manifest,
    /// The modules installed: the running release's, else as the stack records them.
    pub modules: BTreeSet<String>,
    pub judge: Judge,
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

/// What a MANIFEST must say, whatever the unit: a bundle without it is
/// refused as soon as its head has arrived.
pub fn manifest_check(m: &Manifest) -> anyhow::Result<()> {
    use anyhow::ensure;
    let get = |k: &str| m.get(k).map(String::as_str).unwrap_or_default();
    for k in ["STACK_TAG", "BUILT_EPOCH"] {
        ensure!(!get(k).is_empty(), "the MANIFEST lacks {k}");
    }
    get("BUILT_EPOCH")
        .parse::<i64>()
        .context("BUILT_EPOCH is not a number")?;
    // Without a base, the unit's own base says the rest.
    if !bundle::has_base(m) {
        return Ok(());
    }
    for k in [
        "STACK_DIGEST",
        "INSTALLER_REF",
        "TALOS_VERSION",
        "SECUREBOOT",
    ] {
        ensure!(!get(k).is_empty(), "the MANIFEST lacks {k}");
    }
    ensure!(
        get("INSTALLER_REF").contains("@sha256:"),
        "the MANIFEST names the installer by tag, not digest"
    );
    ensure!(
        get("STACK_DIGEST").starts_with("sha256:"),
        "the MANIFEST's STACK_DIGEST is not a sha256"
    );
    Ok(())
}

/// `oci://host/repo` as a ref's repository.
fn stack_repo(url: &str) -> &str {
    url.strip_prefix("oci://").unwrap_or(url)
}

/// The bundle installs an OS other than the one the unit runs.
pub fn os_changes(m: &Manifest, talos: &str, installer: &str) -> bool {
    let get = |k: &str| m.get(k).map(String::as_str).unwrap_or_default();
    installer_pin(get("INSTALLER_REF")) != installer_pin(installer) || get("TALOS_VERSION") != talos
}

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
    pub progress: Arc<Progress>,
}

enum Next {
    Go(Phase),
    Wait(Duration, String),
    Fail(String),
    Refuse(String),
    /// The unit went back: what happened, and why, in short.
    Back(String, String),
    Done,
}

use Next::{Back, Done, Fail, Go, Refuse, Wait};

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
                    // Not trusted: the unit's boot and stack judges finish what was started.
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
            progress: Arc::default(),
        })
    }

    pub fn uploads(&self) -> Uploads {
        Uploads::with(
            &self.dir.join("upload"),
            Some(self.verifier.clone()),
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

    /// While idle, or on a stack trial that cannot end by itself, which it ends.
    pub async fn request_verify(&mut self, sha256: &str) -> anyhow::Result<()> {
        let stuck = match self.idle() {
            true => None,
            false => Some(
                self.stuck()
                    .await
                    .ok()
                    .flatten()
                    .context("an update is in progress")?,
            ),
        };
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
        if let Some(trial) = stuck {
            self.finish(Outcome::Failed, ended(&trial))?;
        }
        self.record.steps = vec![Taken {
            step: Step::Upload,
            state: State::Done,
            started: up.started,
            finished: up.finished,
        }];
        self.record.log.clear();
        self.record.by = up.by.clone();
        let by = if up.by.is_empty() {
            String::new()
        } else {
            format!(" from {}", up.by)
        };
        self.note(format!(
            "verifying bundle {}{by}",
            &sha256[..12.min(sha256.len())]
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
        let stuck = self.stuck().await?;
        self.record.error.clear();
        self.record.by = by.into();
        self.record.steps.retain(|t| t.step <= Step::Verify);
        let who = if by.is_empty() {
            String::new()
        } else {
            format!(" by {by}")
        };
        self.note(format!("applying {tag}{who}"));
        if let Some(trial) = &stuck {
            self.end_stuck(trial, by);
            self.note(ended(trial));
        }
        self.record.took_over = stuck.unwrap_or_default();
        self.go(Phase::Starting)
    }

    /// The stack trial a new bundle may end, read afresh.
    async fn stuck(&self) -> anyhow::Result<Option<String>> {
        let (_, on) = self
            .cluster
            .sync(&self.settings.stack.flux_instance)
            .await?;
        Ok(stuck_trial(&self.record, &on, &self.judge_now().await?))
    }

    /// Records the stuck trial ended, unless its last entry already does.
    fn end_stuck(&mut self, trial: &str, by: &str) {
        let detail = ended(trial);
        let last = self
            .record
            .history
            .iter()
            .find(|e| e.release.as_ref().is_some_and(|r| r.tag() == trial));
        if last.is_some_and(|e| e.outcome == Outcome::Failed && e.detail == detail) {
            return;
        }
        let release = last
            .and_then(|e| e.release.clone())
            .unwrap_or_else(|| Release {
                manifest: [("STACK_TAG".to_string(), trial.to_string())].into(),
                ..Release::default()
            });
        let now = (self.now)();
        self.record.history.insert(
            0,
            Entry {
                release: Some(release),
                outcome: Outcome::Failed,
                detail: detail.clone(),
                started: now,
                finished: now,
                snapshot: None,
                steps: Vec::new(),
                log: vec![LogLine {
                    unix: now,
                    text: detail,
                }],
                by: by.into(),
                rollback_reason: String::new(),
            },
        );
        self.record.history.truncate(HISTORY);
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
        let st = &self.settings.stack;
        match async {
            let (_, tag) = self.cluster.sync(&st.flux_instance).await?;
            let flux = self.cluster.flux_version(&st.flux_instance).await?;
            anyhow::Ok((tag, flux, self.cluster.config_map(&st.judge).await?))
        }
        .await
        {
            Ok((tag, flux, judge)) => {
                let j = Judge::read(&judge.unwrap_or_default());
                let u = &mut self.unit;
                (u.stack_tag, u.flux_version) = (tag, flux);
                (u.good, u.previous, u.trial, u.rolled_back) = (
                    j.good.clone(),
                    j.previous.clone(),
                    j.trial.clone(),
                    j.rolled_back.clone(),
                );
                u.judge = j;
            }
            Err(e) => tracing::debug!(error = format!("{e:#}"), "could not read the unit's stack"),
        }
        match self.record.running(&self.unit.stack_tag) {
            Some(r) => {
                let modules = words(r.manifest.get(components::MODULES_KEY));
                let u = &mut self.unit;
                (u.components, u.manifest, u.modules) =
                    (r.components(), r.manifest.clone(), modules);
            }
            None => {
                match self.cluster.images_in_use().await {
                    Ok(refs) => {
                        let registry = &self.registry;
                        self.unit.components = diff::of_refs(&refs, |r| registry.digest(r));
                        self.unit.manifest.clear();
                    }
                    Err(e) => tracing::debug!(
                        error = format!("{e:#}"),
                        "could not read what the unit runs"
                    ),
                }
                match self.recorded_modules().await {
                    Ok(m) => self.unit.modules = words(m.as_ref()),
                    Err(e) => tracing::debug!(
                        error = format!("{e:#}"),
                        "could not read the stack's record of its modules"
                    ),
                }
            }
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
            Phase::Snapshotting => self.snapshotting().await?,
            Phase::Staging => self.staging().await?,
            Phase::Installing => self.installing().await?,
            Phase::Rebooting { boot_id, asked } => self.rebooting(boot_id, asked).await?,
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
            Back(why, reason) => {
                self.finish_back(why, reason)?;
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
        self.finish_as(outcome, detail, String::new())
    }

    fn finish_back(&mut self, detail: String, reason: String) -> anyhow::Result<()> {
        self.finish_as(Outcome::RolledBack, detail, reason)
    }

    fn finish_as(
        &mut self,
        outcome: Outcome,
        detail: String,
        reason: String,
    ) -> anyhow::Result<()> {
        let now = (self.now)();
        let ok = outcome == Outcome::Committed;
        steps::close(
            &mut self.record.steps,
            if ok { State::Done } else { State::Failed },
            now,
        );
        self.note(detail.clone());
        self.progress.stop();
        self.record.took_over.clear();
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
        let keep = self.record.release.as_ref().map(|r| r.sha256.clone());
        if let Ok(dirs) = std::fs::read_dir(self.dir.join("releases")) {
            for d in dirs.flatten() {
                if Some(d.file_name().to_string_lossy().into_owned()) != keep {
                    let _ = std::fs::remove_dir_all(d.path());
                }
            }
        }
        // An installed set goes with the last release that names its stack.
        let u = &self.unit;
        let tags: BTreeSet<String> = self
            .record
            .history
            .iter()
            .filter_map(|e| e.release.as_ref())
            .chain(self.record.release.as_ref())
            .map(|r| r.tag().to_string())
            .chain([&u.stack_tag, &u.good, &u.previous].map(String::clone))
            .collect();
        if let Ok(files) = std::fs::read_dir(self.dir.join("installed")) {
            for f in files.flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                let tag = name.strip_suffix(".json").unwrap_or(&name);
                if !tags.contains(tag) {
                    let _ = std::fs::remove_file(f.path());
                }
            }
        }
    }

    /// The installed set the unit composed for the stack `tag`, if it did.
    fn installed(&self, tag: &str) -> anyhow::Result<Option<Composed>> {
        let file_name = |t: &str| {
            t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        };
        if tag.is_empty() || tag.starts_with('.') || !file_name(tag) {
            return Ok(None);
        }
        let p = self.dir.join("installed").join(format!("{tag}.json"));
        match std::fs::read(&p) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| {
                format!("{} is not an installed set", p.display())
            })?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// With no recorded set, a bundle stands for the whole of it: it brings a
    /// base and every module the unit runs, as the release it runs or its
    /// stack's record of modules says.
    async fn covers_what_runs(&self, on: &str, c: &Components) -> anyhow::Result<()> {
        let said = match self.record.running(on) {
            Some(r) => r.manifest.get(components::MODULES_KEY).cloned(),
            None => self.recorded_modules().await?,
        };
        let runs: BTreeSet<&str> = said
            .as_deref()
            .context(
                "this unit's installed modules are unknown: bring a base and every module it runs",
            )?
            .split_whitespace()
            .collect();
        let missing: Vec<&str> = runs
            .iter()
            .filter(|m| !c.modules.contains_key(**m) && !c.remove.contains(**m))
            .copied()
            .collect();
        anyhow::ensure!(
            c.base.is_some() && missing.is_empty(),
            "this unit's installed modules are unknown to this engine: bring a base and every module it runs{}",
            if missing.is_empty() {
                String::new()
            } else {
                format!(" (this bundle lacks {})", missing.join(", "))
            }
        );
        Ok(())
    }

    /// The stack's record of its installed modules, if it keeps one.
    async fn recorded_modules(&self) -> anyhow::Result<Option<String>> {
        let Some(at) = &self.settings.stack.modules else {
            return Ok(None);
        };
        Ok(self
            .cluster
            .config_map(at)
            .await?
            .and_then(|m| m.get(components::MODULES_KEY).cloned()))
    }

    /// With components, the bundle merged into the unit's installed set: the
    /// release's MANIFEST and refs become the set's, and its stack the base's
    /// artifact with the set's modules.
    async fn compose(&self, rel: &mut Release) -> anyhow::Result<()> {
        let dir = self.release_dir(&rel.sha256);
        let Some(c) = Components::read(&dir)? else {
            return Ok(());
        };
        let st = &self.settings.stack;
        let (_, on) = self.cluster.sync(&st.flux_instance).await?;
        let current = self.installed(&on)?;
        if current.is_none() && rel.tag() != on {
            self.covers_what_runs(&on, &c).await?;
        }
        let patch = match &c.base {
            Some(_) => Some(std::fs::read_to_string(dir.join(bundle::PATCH))?),
            None => None,
        };
        let next = Installed::after(
            current.as_ref().map(|c| &c.installed),
            &rel.manifest,
            patch.as_deref(),
            &c,
        )?;
        // The bundle's own stack ref, which the composed one then replaces on import.
        let images = dir.join(bundle::IMAGES);
        let brought = bundle::layout_images(&images)?
            .into_iter()
            .find(|(_, d)| *d == rel.get("STACK_DIGEST"))
            .and_then(|(r, _)| r.rsplit_once(':').map(|(repo, _)| repo.to_string()));
        let repo = match (&c.base, &current) {
            (Some(_), _) => brought,
            (None, Some(cur)) => Some(cur.repo.clone()).filter(|r| !r.is_empty()),
            (None, None) => None,
        }
        .unwrap_or_else(|| stack_repo(&st.url).to_string());
        let name = format!("{repo}:{}", rel.tag());
        let mut refs = next.refs();
        let stack = if rel.tag() == on {
            // The bundle of the stack the unit runs, which already has its modules.
            match current.as_ref() {
                Some(c) => c.stack.clone(),
                None => rel.get("STACK_DIGEST").to_string(),
            }
        } else {
            let base = match (&c.base, &current) {
                (Some(_), _) => rel.get("STACK_DIGEST").to_string(),
                (None, Some(cur)) => cur.stack.clone(),
                (None, None) => anyhow::bail!("the unit's stack {on} has no installed set"),
            };
            let record = st
                .modules
                .as_ref()
                .map(|r| (r.namespace.as_str(), r.name.as_str()));
            let files = components::modules_dir(&next.modules, record)?;
            let registry = self.registry.clone();
            let out = dir.join(COMPOSED);
            let _ = std::fs::remove_dir_all(&out);
            refs.insert(name.clone());
            components::compose(
                |d| components::layout_blob(&images, d).or_else(|_| registry.read(d)),
                &base,
                &files,
                &out,
                &name,
            )?
        };
        rel.manifest = next.manifest(&rel.manifest, &c);
        rel.manifest.insert("STACK_DIGEST".into(), stack.clone());
        rel.owners = owners(&next);
        rel.owners.insert(name, "base".into());
        rel.refs = refs;
        rel.composed_on = Some(on);
        rel.brings_base = c.base.is_some();
        rel.modules = c.modules.keys().cloned().collect();
        rel.removes = c.remove.clone();
        std::fs::write(
            dir.join(INSTALLED),
            serde_json::to_vec(&Composed {
                stack,
                repo,
                installed: next,
            })?,
        )?;
        Ok(())
    }

    async fn verifying(&mut self, sha: &str) -> anyhow::Result<Tick> {
        let dir = self.release_dir(sha);
        let _ = std::fs::remove_dir_all(&dir);
        self.detail = "checking the signature and unpacking".into();
        let bundle = self.uploads().bundle();
        let size = std::fs::metadata(&bundle).map_or(0, |m| m.len());
        self.progress.start(size.max(1), (self.now)());
        let (d, verifier, progress) = (dir.clone(), self.verifier.clone(), self.progress.clone());
        let unpacked = tokio::task::spawn_blocking(move || {
            bundle::unpack_counting(&bundle, &d, &verifier, &progress.done)
        })
        .await?;
        self.progress.stop();
        let release = match unpacked.and_then(|manifest| {
            let refs = bundle::release_refs(&dir)?;
            let images = bundle::layout_images(&dir.join(bundle::IMAGES))?;
            Ok(Release {
                sha256: sha.into(),
                brings_base: bundle::has_base(&manifest),
                manifest,
                refs,
                notes: bundle::notes(&dir),
                signer: self.verifier.signer(),
                images,
                ..Release::default()
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
        let mut release = release;
        if let Err(e) = self.compose(&mut release).await {
            let _ = std::fs::remove_dir_all(&dir);
            self.record.release = None;
            self.finish(Outcome::Refused, format!("{e:#}"))?;
            return Ok(Tick::Moved);
        }
        let refusal = self.refusal(&release).await;
        let (checks, diff, short) = self.assess(&release, refusal.as_deref()).await;
        (release.checks, release.diff) = (checks, Some(diff));
        self.record.release = Some(release);
        if let Some(why) = refusal.or(short) {
            let _ = std::fs::remove_dir_all(&dir);
            self.finish(Outcome::Refused, why)?;
            return Ok(Tick::Moved);
        }
        self.uploads().discard();
        self.record.error.clear();
        steps::close(&mut self.record.steps, State::Done, (self.now)());
        self.note("verified");
        self.go(Phase::Idle)?;
        Ok(Tick::Moved)
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
        let mut checks = vec![Check::new(
            "signature",
            CheckState::Pass,
            rel.signer.clone(),
        )];
        checks.push(match refusal {
            None => Check::new("compatible", CheckState::Pass, ""),
            Some(why) => Check::new("compatible", CheckState::Fail, why),
        });
        let layout = self.release_dir(&rel.sha256).join(bundle::IMAGES);
        let mut short = None;
        match (self.registry.missing(&layout), self.registry.usage()) {
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
        let before = self.record.running(&u.stack_tag);
        let diff = Diff {
            components: diff::components(&u.components, &rel.components(), before.is_some()),
            talos: (u.talos_version.clone(), rel.get("TALOS_VERSION").into()),
            installer: (u.installer.clone(), rel.get("INSTALLER_REF").into()),
            stack: (u.stack_tag.clone(), rel.tag().into()),
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
        let dir = self.release_dir(&rel.sha256);
        let mut carried = bundle::layout_refs(&dir.join(bundle::IMAGES))?;
        if dir.join(COMPOSED).exists() {
            carried.extend(bundle::layout_refs(&dir.join(COMPOSED))?);
        }
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
        let epoch: i64 = rel.get("BUILT_EPOCH").parse()?;

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
        if let Some(on) = &rel.composed_on {
            ensure!(
                tag == *on || tag == rel.tag(),
                "the unit's stack moved from {on} to {tag} since the bundle was verified: verify it again"
            );
        }
        if tag != rel.tag() {
            if let Some(cur) = self.installed(&tag)? {
                ensure!(
                    epoch > cur.installed.built_epoch,
                    "REFUSING A DOWNGRADE: the unit's last bundle is version {} and this one is {epoch}",
                    cur.installed.built_epoch
                );
            }
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
        let dir = self.release_dir(&rel.sha256);
        let patch = match std::fs::read(dir.join(INSTALLED)) {
            Ok(b) => serde_json::from_slice::<Composed>(&b)?.installed.patch()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::read_to_string(dir.join(bundle::PATCH))?
            }
            Err(e) => return Err(e.into()),
        };
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
            installer: installer_of(&running),
            rollback_by: String::new(),
            backed_out: false,
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
        let mut keep = self.committed_refs(2);
        // A partial bundle's release runs on images an older release brought.
        keep.extend(self.release()?.refs.iter().cloned());
        let keep = self.keep(keep).await?;
        let dir = self.release_dir(&self.release()?.sha256);
        let (layout, composed) = (dir.join(bundle::IMAGES), dir.join(COMPOSED));
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || {
            registry.retain(&keep)?;
            registry.import(&layout)?;
            if composed.exists() {
                registry.import(&composed)?;
            }
            anyhow::Ok(())
        })
        .await??;
        if let Ok(set) = std::fs::read(dir.join(INSTALLED)) {
            let d = self.dir.join("installed");
            std::fs::create_dir_all(&d)?;
            let tag = self.release()?.tag().to_string();
            edge_common::durable_write(&d.join(format!("{tag}.json")), &set)
                .context("record the installed set")?;
        }
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

    /// The config the OS step applies: serving rotation stays as the unit runs
    /// it until the stack that approves its requests is committed.
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
            return Ok(Go(Phase::Seeding));
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
        let rel = self.release()?.clone();
        let installer = installer_pin(rel.get("INSTALLER_REF"));
        if installer == installer_pin(&self.before()?.installer)
            && self.talos.version().await? == rel.get("TALOS_VERSION")
        {
            // The unit runs this OS already: the config alone, and no reboot.
            let config = self.os_config().await?;
            match self.talos.apply_config(&config).await {
                Ok(()) => {
                    if let Some(r) = self.record.release.as_mut() {
                        r.os_done = true;
                    }
                    self.skip_step();
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
            asked: None,
        }))
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
                 {}. The stack did not move; applying again repeats the upgrade",
                self.restore().await?
            ),
            "the new OS did not boot".into(),
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
                    "{} is on trial; the unit blesses it once it has stayed healthy",
                    b.selected
                ),
            );
        }
        let before = self.before()?;
        // Fallen back (its tries spent) or rolled back: the default is not what runs, or is the old one.
        if !b.running().eq_ignore_ascii_case(&b.default)
            || b.default.eq_ignore_ascii_case(&before.default_entry)
        {
            let (why, reason) = if before.backed_out {
                (
                    "an operator rolled the new OS back on its trial",
                    asked(&before.rollback_by),
                )
            } else {
                (
                    "the new OS did not stay up, and the unit went back to its previous OS by itself",
                    "the new OS did not stay up".into(),
                )
            };
            return Ok(Back(
                format!(
                    "{why}; {}. The stack did not move; applying again repeats the upgrade",
                    self.restore().await?
                ),
                reason,
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

    /// A bundle without a base has none.
    fn seed(&self) -> anyhow::Result<String> {
        let dir = self.release_dir(&self.release()?.sha256);
        match std::fs::read_to_string(dir.join(bundle::SEED)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            r => Ok(r?),
        }
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
        if seed.trim().is_empty() {
            return Ok(Go(Phase::AwaitingGood));
        }
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
        // A trial taken over had nothing to roll back to, and never will.
        let ended = good.is_empty() && self.record.took_over == prev;
        if good == prev || ended {
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

    /// The bundle's FluxInstance, once Flux has applied the stack that brings
    /// the operator knowing its version, and while the stack is still this release's.
    async fn instance(&mut self, applied: Option<&str>) -> anyhow::Result<()> {
        let rel = self.release()?;
        let signed = format!("{}@{}", rel.tag(), rel.get("STACK_DIGEST"));
        if rel.instance_applied || applied != Some(signed.as_str()) {
            return Ok(());
        }
        let Some(instance) = bundle::instance(&self.release_dir(&rel.sha256)) else {
            return Ok(());
        };
        let tag = rel.tag().to_string();
        let (_, now) = self
            .cluster
            .sync(&self.settings.stack.flux_instance)
            .await?;
        if now != tag {
            return Ok(());
        }
        self.cluster
            .apply(&instance)
            .await
            .context("apply the release's FluxInstance")?;
        if let Some(r) = self.record.release.as_mut() {
            r.instance_applied = true;
        }
        self.note("applied the release's FluxInstance");
        self.save()
    }

    async fn judging(&mut self, rolled_back_before: &str) -> anyhow::Result<Next> {
        let applied = self
            .cluster
            .applied(&self.settings.stack.kustomization)
            .await?;
        self.instance(applied.as_deref()).await?;
        let rel = self.release()?;
        let tag = rel.tag().to_string();
        let signed = format!("{tag}@{}", rel.get("STACK_DIGEST"));
        if let Some(r) = applied
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
        let asked_by = self.before()?.rollback_by.clone();
        if rolled_back != rolled_back_before && rolled_back.starts_with(&format!("{tag} ")) {
            if !asked_by.is_empty() {
                return Ok(Back(
                    format!("{tag} was rolled back to {good} as {asked_by} asked ({rolled_back})"),
                    asked(&asked_by),
                ));
            }
            return Ok(Back(
                format!(
                    "the unit found {tag} unhealthy and rolled the stack back to {good} ({rolled_back})"
                ),
                format!("{tag} stayed unhealthy"),
            ));
        }
        if good == tag {
            return Ok(Go(Phase::Collecting));
        }
        let (_, now) = self
            .cluster
            .sync(&self.settings.stack.flux_instance)
            .await?;
        if now != tag {
            if !asked_by.is_empty() {
                return Ok(Back(
                    format!("{tag} was rolled back to {now} as {asked_by} asked"),
                    asked(&asked_by),
                ));
            }
            return Ok(Fail(format!(
                "an operator moved the stack to {now} while {tag} was on trial; the update ends here"
            )));
        }
        poll(
            30,
            format!("{tag} is on trial; the unit's judge commits it once it has stayed healthy"),
        )
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
            self.note("the kubelet's serving certificate rotation is on: the stack approves it");
            self.save()?;
        }
        let mut keep = self.release()?.refs.clone();
        keep.extend(self.committed_refs(1));
        self.registry.retain(&self.keep(keep).await?)?;
        Ok(Done)
    }

    /// The trial running, if any: the stack's, which the judge holds.
    fn stack_trial(&self) -> Option<String> {
        match &self.record.phase {
            Phase::Judging { .. } => self.record.release.as_ref().map(|r| r.tag().to_string()),
            Phase::Idle
                if !self.unit.trial.is_empty() && self.unit.trial == self.unit.stack_tag =>
            {
                Some(self.unit.trial.clone())
            }
            _ => None,
        }
    }

    /// Asks the judge to commit the stack on trial now.
    pub async fn request_commit(&mut self, tag: &str, by: &str) -> anyhow::Result<()> {
        let trial = self.stack_trial().context("no stack is on trial")?;
        anyhow::ensure!(trial == tag, "{trial} is on trial, not {tag}");
        let j = self.judge_now().await?;
        anyhow::ensure!(
            j.takes("commit"),
            "the unit's judge takes no commit requests"
        );
        self.cluster
            .set_key(
                &self.settings.stack.judge,
                judge::REQUEST,
                &judge::request("commit", tag),
            )
            .await?;
        self.note(format!("{} asked to commit {tag}", who(by)));
        Ok(())
    }

    /// Rolls back: the OS on trial through Talos, the stack on trial through its
    /// judge, or with nothing on trial, the stack to the judge's previous good.
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
            Phase::Judging { .. } => {
                let rel = self.release()?.tag().to_string();
                anyhow::ensure!(rel == tag, "{rel} is on trial, not {tag}");
                if let Some(b) = self.record.before.as_mut() {
                    b.rollback_by = by.into();
                }
                self.note(format!("{} asked to roll {tag} back", who(by)));
                self.save()?;
                let st = self.settings.stack.clone();
                if self.judge_now().await?.takes("rollback") {
                    self.cluster
                        .set_key(&st.judge, judge::REQUEST, &judge::request("rollback", tag))
                        .await?;
                } else {
                    let b = self.before()?.clone();
                    self.cluster
                        .repoint(&st.flux_instance, &b.url, &b.tag, None)
                        .await?;
                }
                Ok(format!("rolling {tag} back"))
            }
            Phase::Idle if self.stack_trial().as_deref() == Some(tag) => {
                anyhow::ensure!(
                    self.judge_now().await?.takes("rollback"),
                    "the unit's judge takes no rollback requests"
                );
                self.cluster
                    .set_key(
                        &self.settings.stack.judge,
                        judge::REQUEST,
                        &judge::request("rollback", tag),
                    )
                    .await?;
                Ok(format!("rolling {tag} back"))
            }
            Phase::Idle => self.revert(tag, by).await,
            _ => anyhow::bail!("the update is under way: nothing is on trial to roll back"),
        }
    }

    /// Points the stack at the judge's previous good release, which the judge
    /// then takes on trial like any other.
    async fn revert(&mut self, tag: &str, by: &str) -> anyhow::Result<String> {
        let j = self.judge_now().await?;
        let st = self.settings.stack.clone();
        let (_, running) = self.cluster.sync(&st.flux_instance).await?;
        anyhow::ensure!(
            !j.previous.is_empty(),
            "the unit has no previous good release"
        );
        anyhow::ensure!(
            j.previous == tag,
            "the previous good release is {}, not {tag}",
            j.previous
        );
        anyhow::ensure!(
            j.trial.is_empty() && running == j.good,
            "the unit runs {running}, not its good release {}",
            j.good
        );
        let release = self
            .record
            .history
            .iter()
            .filter_map(|e| e.release.as_ref())
            .find(|r| r.tag() == tag)
            .cloned();
        if let Some(r) = &release {
            anyhow::ensure!(
                r.refs.iter().all(|i| self.registry.digest(i).is_some()),
                "{tag}'s images were collected: it can only be uploaded again"
            );
        }
        let path = release
            .as_ref()
            .and_then(|r| r.manifest.get("STACK_PATH"))
            .cloned();
        self.cluster
            .repoint(&st.flux_instance, &st.url, tag, path.as_deref())
            .await?;
        if let Err(e) = self.cluster.reconcile(&st.source).await {
            tracing::warn!(error = %e, "could not ask Flux to fetch now; it will on its interval");
        }
        let now = (self.now)();
        let detail = format!("{running} rolled back to {tag}");
        self.record.history.insert(
            0,
            Entry {
                release,
                outcome: Outcome::RolledBack,
                detail: detail.clone(),
                started: now,
                finished: now,
                snapshot: None,
                steps: Vec::new(),
                log: vec![LogLine {
                    unix: now,
                    text: format!("{} asked to roll {running} back to {tag}", who(by)),
                }],
                by: by.into(),
                rollback_reason: asked(by),
            },
        );
        self.record.history.truncate(HISTORY);
        self.save()?;
        Ok(detail)
    }

    async fn judge_now(&self) -> anyhow::Result<Judge> {
        Ok(Judge::read(
            &self
                .cluster
                .config_map(&self.settings.stack.judge)
                .await?
                .unwrap_or_default(),
        ))
    }

    /// The refs a collection keeps: what runs, the release verified or being
    /// applied, and the release running; and the previous good release's.
    async fn kept(&self) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
        let mut now = self
            .keep(
                self.record
                    .release
                    .as_ref()
                    .map(|r| r.refs.clone())
                    .unwrap_or_default(),
            )
            .await?;
        if let Some(r) = self.record.running(&self.unit.stack_tag) {
            now.extend(r.refs.iter().cloned());
        }
        let previous = self
            .record
            .history
            .iter()
            .filter_map(|e| e.release.as_ref())
            .find(|r| !self.unit.previous.is_empty() && r.tag() == self.unit.previous)
            .map(|r| r.refs.clone())
            .unwrap_or_default();
        Ok((now, previous))
    }

    pub async fn storage(&self) -> anyhow::Result<Storage> {
        let (now, previous) = self.kept().await?;
        let both: BTreeSet<String> = now.union(&previous).cloned().collect();
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || {
            let (held, free) = registry.usage()?;
            let beyond_now = registry.reclaimable(&now)?;
            let reclaimable = registry.reclaimable(&both)?;
            anyhow::Ok(Storage {
                held,
                previous: beyond_now.saturating_sub(reclaimable),
                reclaimable,
                free,
            })
        })
        .await?
    }

    /// Drops what no kept release names; the previous one's too if asked.
    pub async fn collect(&mut self, previous: bool) -> anyhow::Result<u64> {
        anyhow::ensure!(self.idle(), "an update is in progress");
        let (mut keep, prev) = self.kept().await?;
        if !previous {
            keep.extend(prev);
        }
        let registry = self.registry.clone();
        tokio::task::spawn_blocking(move || registry.retain(&keep)).await?
    }
}

/// Each ref of `set` and what it belongs to: a module's own, else the base's.
fn owners(set: &Installed) -> BTreeMap<String, String> {
    let base = set
        .base
        .refs
        .iter()
        .map(|r| (r.clone(), "base".to_string()));
    let modules = set
        .modules
        .iter()
        .flat_map(|(name, m)| m.refs.iter().map(|r| (r.clone(), name.clone())));
    base.chain(modules).collect()
}

/// The stack trial the unit follows that nothing ends by itself: unhealthy,
/// with no good release for its judge, or this engine, to roll back to.
pub fn stuck_trial(r: &Record, on: &str, j: &Judge) -> Option<String> {
    let trial = j.trial.as_str();
    if trial.is_empty() || trial != on || !j.good.is_empty() {
        return None;
    }
    match &r.phase {
        Phase::Idle => {}
        Phase::Judging { .. } => {
            let back = r.before.as_ref().map_or("", |b| b.tag.as_str());
            let ours = r.release.as_ref().is_some_and(|rel| rel.tag() == trial);
            if !ours || !(back.is_empty() || back == trial) {
                return None;
            }
        }
        _ => return None,
    }
    let unhealthy = j.healthy_since == 0 && j.checks.iter().any(|c| c.state == CheckState::Fail);
    unhealthy.then(|| trial.to_string())
}

fn ended(trial: &str) -> String {
    format!("{trial} stayed unhealthy with no good release to roll back to; a new bundle took over")
}

fn words(s: Option<&String>) -> BTreeSet<String> {
    s.map_or(BTreeSet::new(), |s| {
        s.split_whitespace().map(String::from).collect()
    })
}

fn who(by: &str) -> &str {
    if by.is_empty() { "an operator" } else { by }
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
        Phase::Snapshotting => "copying the store",
        Phase::Staging => "staging the machine config",
        Phase::Installing => "installing the OS",
        Phase::Rebooting { .. } => "rebooting",
        Phase::Trial => "the new OS is on trial",
        Phase::Settling => "the new OS is committed; waiting for the system to settle",
        Phase::Seeding => "updating the judge",
        Phase::AwaitingGood => "waiting for the judge",
        Phase::Repointing { .. } => "moving the stack",
        Phase::Judging { .. } => "the new stack is on trial",
        Phase::Collecting => "collecting old images",
    }
}

/// The same documents, whatever their order or formatting.
fn same_config(a: &str, b: &str) -> bool {
    let docs = |y: &str| -> Option<Vec<serde_yaml::Value>> {
        let mut d: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(y)
            .map(serde_yaml::Value::deserialize)
            .collect::<Result<_, _>>()
            .ok()?;
        d.retain(|v| !v.is_null());
        d.sort_by_key(|v| serde_yaml::to_string(v).unwrap_or_default());
        Some(d)
    };
    docs(a).is_some_and(|a| Some(a) == docs(b))
}

/// The installer a machine config names: its unattended install's, else `machine.install`'s.
fn installer_of(config: &str) -> String {
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
