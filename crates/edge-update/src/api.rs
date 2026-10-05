//! The update API over ConnectRPC. Uploads are handled here; verifying and
//! applying are handed to the engine, whose status every client watches.

use std::sync::{Arc, Mutex};

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::bundle::components::{MODULES_KEY, REMOVE_KEY};
use crate::diff::{Change, Component, Diff};
use crate::engine::{self, Entry, Outcome, Phase, Power, Record, Release, Storage, Unit};
use crate::judge::{Check, CheckState};
use crate::pb::edge::update::v1 as pb;
use crate::steps::{self, State, Step, Taken};
use crate::upload::{Upload, Uploads};

type Reply<T> = oneshot::Sender<anyhow::Result<T>>;

pub enum Command {
    Verify(String, Reply<()>),
    /// The tag, and who applies it.
    Apply(String, String, Reply<()>),
    Power(Power, Reply<String>),
    Commit(String, String, Reply<()>),
    RollBack(String, String, Reply<String>),
    Storage(Reply<Storage>),
    /// Drop the previous release's images too.
    Collect(bool, Reply<u64>),
}

#[derive(Clone, Default, PartialEq)]
pub struct Snapshot {
    pub record: Record,
    pub detail: String,
    pub unit: Unit,
    /// Done, total and since when, of the step running.
    pub progress: Option<(u64, u64, i64)>,
}

pub struct Service {
    commands: mpsc::Sender<Command>,
    status: watch::Receiver<Snapshot>,
    uploads: Arc<Mutex<Uploads>>,
}

impl Service {
    pub fn new(
        commands: mpsc::Sender<Command>,
        status: watch::Receiver<Snapshot>,
        uploads: Uploads,
    ) -> Self {
        Self {
            commands,
            status,
            uploads: Arc::new(Mutex::new(uploads)),
        }
    }

    /// Idle, or on a stack trial a new bundle may take over.
    fn idle(&self) -> Result<(), ConnectError> {
        let s = self.status.borrow();
        if engine::stuck_trial(&s.record, &s.unit.stack_tag, &s.unit.judge).is_some() {
            return Ok(());
        }
        match s.record.phase {
            Phase::Idle => Ok(()),
            _ if s.record.by.is_empty() => Err(ConnectError::failed_precondition(
                "an update is in progress",
            )),
            _ => Err(ConnectError::failed_precondition(format!(
                "an update by {} is in progress",
                s.record.by
            ))),
        }
    }

    async fn uploading<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Uploads) -> anyhow::Result<T> + Send + 'static,
    ) -> Result<T, ConnectError> {
        self.idle()?;
        let uploads = self.uploads.clone();
        tokio::task::spawn_blocking(move || {
            let u = uploads.lock().unwrap_or_else(|e| e.into_inner());
            f(&u)
        })
        .await
        .map_err(|e| ConnectError::internal(e.to_string()))?
        .map_err(|e| ConnectError::failed_precondition(format!("{e:#}")))
    }

    async fn ask<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<T, ConnectError> {
        let (tx, rx) = oneshot::channel();
        fn stopped<E>(_: E) -> ConnectError {
            ConnectError::unavailable("the engine has stopped")
        }
        self.commands.send(make(tx)).await.map_err(stopped)?;
        rx.await
            .map_err(stopped)?
            .map_err(|e| ConnectError::failed_precondition(format!("{e:#}")))
    }

    async fn command<T>(
        &self,
        make: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<pb::Status, ConnectError> {
        self.ask(make).await?;
        // The engine publishes before it replies.
        let s = self.status.borrow().clone();
        Ok(self.convert(&s))
    }

    /// Refused at once while an update runs, not after the engine's current step.
    async fn power(&self, p: Power) -> Result<String, ConnectError> {
        if let Some(why) = self.status.borrow().record.power_refusal() {
            return Err(ConnectError::failed_precondition(why));
        }
        self.ask(|tx| Command::Power(p, tx)).await
    }

    fn convert(&self, s: &Snapshot) -> pb::Status {
        let upload = self.uploads.lock().ok().and_then(|u| u.current());
        status(s, upload.as_ref(), engine::unix_now())
    }
}

fn hex32(b: &[u8]) -> Result<String, ConnectError> {
    if b.len() != 32 {
        return Err(ConnectError::invalid_argument("a sha256 is 32 bytes"));
    }
    Ok(hex::encode(b))
}

fn upload(u: &Upload) -> pb::Upload {
    pb::Upload {
        sha256: hex::decode(&u.sha256).unwrap_or_default(),
        size: u.size,
        chunk_size: u.chunk_size,
        received: u.received.clone(),
        complete: u.complete,
        started_unix: u.started,
        finished_unix: u.finished,
        by: u.by.clone(),
        active_unix: u.active,
        head: u
            .head
            .as_ref()
            .map(|h| pb::Head {
                manifest: h
                    .manifest
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                notes: h.notes.clone().unwrap_or_default(),
                signer: h.signer.clone(),
                brings_base: crate::bundle::has_base(&h.manifest),
                modules: listed(&h.manifest, MODULES_KEY),
                removes: listed(&h.manifest, REMOVE_KEY),
                ..Default::default()
            })
            .into(),
        refused: u.refused.clone(),
        ..Default::default()
    }
}

fn check(c: &Check) -> pb::Check {
    pb::Check {
        name: c.name.clone(),
        state: match c.state {
            CheckState::Pass => pb::CheckState::CHECK_STATE_PASS,
            CheckState::Fail => pb::CheckState::CHECK_STATE_FAIL,
            CheckState::Note => pb::CheckState::CHECK_STATE_NOTE,
        }
        .into(),
        detail: c.detail.clone(),
        ..Default::default()
    }
}

fn component(c: &Component) -> pb::Component {
    pb::Component {
        name: c.name.clone(),
        kind: pb::ComponentKind::COMPONENT_KIND_IMAGE.into(),
        image: c.image.clone(),
        version: c.version.clone(),
        digest: c.digest.clone(),
        dirty: c.dirty,
        carried: c.carried,
        owner: c.owner.clone(),
        ..Default::default()
    }
}

fn listed(m: &crate::bundle::Manifest, key: &str) -> Vec<String> {
    m.get(key)
        .map(|v| v.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

fn diff(d: &Diff) -> pb::Diff {
    pb::Diff {
        components: d
            .components
            .iter()
            .map(|c| pb::ComponentChange {
                name: c.name.clone(),
                change: match c.change {
                    Change::Unchanged => pb::Change::CHANGE_UNCHANGED,
                    Change::Changed => pb::Change::CHANGE_CHANGED,
                    Change::Added => pb::Change::CHANGE_ADDED,
                    Change::Removed => pb::Change::CHANGE_REMOVED,
                }
                .into(),
                from: c.from.as_ref().map(component).into(),
                to: c.to.as_ref().map(component).into(),
                ..Default::default()
            })
            .collect(),
        talos_from: d.talos.0.clone(),
        talos_to: d.talos.1.clone(),
        installer_from: d.installer.0.clone(),
        installer_to: d.installer.1.clone(),
        stack_from: d.stack.0.clone(),
        stack_to: d.stack.1.clone(),
        reboot: d.reboot,
        config_changes: d.config_changes,
        downtime_secs: d.downtime_secs,
        removals_known: d.removals_known,
        ..Default::default()
    }
}

fn release(r: &Release) -> pb::Release {
    pb::Release {
        stack_tag: r.tag().into(),
        talos_version: r.get("TALOS_VERSION").into(),
        built_epoch: r.get("BUILT_EPOCH").parse().unwrap_or_default(),
        manifest: r
            .manifest
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        sha256: hex::decode(&r.sha256).unwrap_or_default(),
        notes: r.notes.clone().unwrap_or_default(),
        signer: r.signer.clone(),
        checks: r.checks.iter().map(check).collect(),
        diff: r.diff.as_ref().map(diff).into(),
        components: r.components().iter().map(component).collect(),
        brings_base: r.brings_base,
        modules: r.modules.iter().cloned().collect(),
        removes: r.removes.iter().cloned().collect(),
        ..Default::default()
    }
}

fn phase(r: &Record) -> pb::Phase {
    match r.phase {
        Phase::Idle if r.release.is_some() => pb::Phase::PHASE_VERIFIED,
        Phase::Idle => pb::Phase::PHASE_IDLE,
        Phase::Verifying { .. } => pb::Phase::PHASE_VERIFYING,
        Phase::Starting | Phase::Importing => pb::Phase::PHASE_IMPORTING,
        Phase::Snapshotting => pb::Phase::PHASE_SNAPSHOTTING,
        Phase::Staging => pb::Phase::PHASE_STAGING,
        Phase::Installing => pb::Phase::PHASE_INSTALLING,
        Phase::Rebooting { .. } => pb::Phase::PHASE_REBOOTING,
        Phase::Trial | Phase::Settling => pb::Phase::PHASE_TRIAL,
        Phase::Seeding => pb::Phase::PHASE_SEEDING,
        Phase::AwaitingGood => pb::Phase::PHASE_AWAITING_GOOD,
        Phase::Repointing { .. } => pb::Phase::PHASE_REPOINTING,
        Phase::Judging { .. } => pb::Phase::PHASE_JUDGING,
        Phase::Collecting => pb::Phase::PHASE_COLLECTING,
    }
}

fn unit(u: &Unit) -> pb::Unit {
    pb::Unit {
        talos_version: u.talos_version.clone(),
        stack_tag: u.stack_tag.clone(),
        good: u.good.clone(),
        previous: u.previous.clone(),
        trial: u.trial.clone(),
        rolled_back: u.rolled_back.clone(),
        os_trial: u.os_trial,
        installer: u.installer.clone(),
        flux_version: u.flux_version.clone(),
        components: u.components.iter().map(component).collect(),
        manifest: u
            .manifest
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        modules: u.modules.iter().cloned().collect(),
        ..Default::default()
    }
}

fn step(t: &Taken) -> pb::Step {
    pb::Step {
        kind: match t.step {
            Step::Upload => pb::StepKind::STEP_KIND_UPLOAD,
            Step::Verify => pb::StepKind::STEP_KIND_VERIFY,
            Step::Stage => pb::StepKind::STEP_KIND_STAGE,
            Step::Install => pb::StepKind::STEP_KIND_INSTALL,
            Step::Reboot => pb::StepKind::STEP_KIND_REBOOT,
            Step::OsTrial => pb::StepKind::STEP_KIND_OS_TRIAL,
            Step::Stack => pb::StepKind::STEP_KIND_STACK,
            Step::Trial => pb::StepKind::STEP_KIND_TRIAL,
            Step::Commit => pb::StepKind::STEP_KIND_COMMIT,
        }
        .into(),
        state: match t.state {
            State::Pending => pb::StepState::STEP_STATE_PENDING,
            State::Running => pb::StepState::STEP_STATE_RUNNING,
            State::Done => pb::StepState::STEP_STATE_DONE,
            State::Failed => pb::StepState::STEP_STATE_FAILED,
            State::Skipped => pb::StepState::STEP_STATE_SKIPPED,
        }
        .into(),
        started_unix: t.started,
        finished_unix: t.finished,
        ..Default::default()
    }
}

/// The update's steps: an upload's, with the plan its head implies; else the
/// record's, the plan filled in while the update is still to come or under way.
fn steps(s: &Snapshot, up: Option<&Upload>) -> Vec<Taken> {
    let r = &s.record;
    let u = &s.unit;
    if let (Phase::Idle, None, Some(up)) = (&r.phase, &r.release, up) {
        let state = match (up.complete, up.refused.is_empty()) {
            (_, false) => State::Failed,
            (true, true) => State::Done,
            (false, true) => State::Running,
        };
        let taken = [Taken {
            step: Step::Upload,
            state,
            started: up.started,
            finished: up.finished,
        }];
        let os = up
            .head
            .as_ref()
            .is_none_or(|h| engine::os_changes(&h.manifest, &u.talos_version, &u.installer));
        return steps::merged(&taken, &steps::plan(os));
    }
    let ended = r.steps.iter().any(|t| t.state == State::Failed)
        || (r.phase == Phase::Idle && r.steps.iter().any(|t| t.step > Step::Verify));
    if ended || r.steps.is_empty() {
        return r.steps.clone();
    }
    let os = r
        .release
        .as_ref()
        .and_then(|r| r.diff.as_ref())
        .is_none_or(|d| d.reboot);
    steps::merged(&r.steps, &steps::plan(os))
}

/// The trial running: the OS's, which the unit commits by itself, or the
/// stack's, which its judge holds.
fn trial(s: &Snapshot) -> Option<pb::Trial> {
    let (r, u) = (&s.record, &s.unit);
    let tag = r
        .release
        .as_ref()
        .map(|r| r.tag().to_string())
        .unwrap_or_default();
    let started = |k: Step| {
        r.steps
            .iter()
            .rev()
            .find(|t| t.step == k)
            .map_or(0, |t| t.started)
    };
    let j = &u.judge;
    let stack = |tag: String, started: i64| pb::Trial {
        kind: pb::TrialKind::TRIAL_KIND_STACK.into(),
        stack_tag: tag,
        started_unix: started,
        window_secs: j.window_secs,
        healthy_since_unix: j.healthy_since,
        fail_after_secs: j.fail_after_secs,
        unhealthy_secs: j.unhealthy_secs,
        checks: j.checks.iter().map(check).collect(),
        can_commit: j.takes("commit"),
        can_roll_back: true,
        ..Default::default()
    };
    Some(match r.phase {
        Phase::Trial | Phase::Settling => pb::Trial {
            kind: pb::TrialKind::TRIAL_KIND_OS.into(),
            stack_tag: tag,
            started_unix: started(Step::OsTrial),
            can_roll_back: r.phase == Phase::Trial,
            ..Default::default()
        },
        Phase::Judging { .. } => stack(tag, started(Step::Trial)),
        Phase::Idle if !u.trial.is_empty() && u.trial == u.stack_tag => pb::Trial {
            can_roll_back: j.takes("rollback"),
            ..stack(u.trial.clone(), 0)
        },
        _ => return None,
    })
}

/// Who holds the unit's update: the one applying, or a live upload's sender.
fn lock(s: &Snapshot, up: Option<&Upload>, now: i64) -> Option<pb::Lock> {
    let r = &s.record;
    if !matches!(r.phase, Phase::Idle) {
        return Some(pb::Lock {
            by: r.by.clone(),
            since_unix: r
                .steps
                .iter()
                .find(|t| t.step > Step::Upload)
                .map_or(r.since, |t| t.started),
            ..Default::default()
        });
    }
    let up = up
        .filter(|u| !u.complete && u.refused.is_empty() && now - u.active < crate::upload::LEASE)?;
    Some(pb::Lock {
        by: up.by.clone(),
        since_unix: up.started,
        uploading: true,
        ..Default::default()
    })
}

fn status(s: &Snapshot, up: Option<&Upload>, now: i64) -> pb::Status {
    let r = &s.record;
    pb::Status {
        phase: phase(r).into(),
        detail: s.detail.clone(),
        release: r.release.as_ref().map(release).into(),
        error: r.error.clone(),
        upload: up.map(upload).into(),
        updated_unix: r.since,
        unit: Some(unit(&s.unit)).into(),
        steps: steps(s, up).iter().map(step).collect(),
        progress: s
            .progress
            .map(|(done, total, started)| pb::Progress {
                done,
                total,
                started_unix: started,
                ..Default::default()
            })
            .into(),
        trial: trial(s).into(),
        lock: lock(s, up, now).into(),
        ..Default::default()
    }
}

fn entry(e: &Entry) -> pb::HistoryEntry {
    pb::HistoryEntry {
        release: e.release.as_ref().map(release).into(),
        outcome: match e.outcome {
            Outcome::Committed => pb::Outcome::OUTCOME_COMMITTED,
            Outcome::Failed => pb::Outcome::OUTCOME_FAILED,
            Outcome::Refused => pb::Outcome::OUTCOME_REFUSED,
            Outcome::RolledBack => pb::Outcome::OUTCOME_ROLLED_BACK,
        }
        .into(),
        detail: e.detail.clone(),
        started_unix: e.started,
        finished_unix: e.finished,
        snapshot_sha256: e.snapshot.clone().unwrap_or_default(),
        steps: e.steps.iter().map(step).collect(),
        by: e.by.clone(),
        rollback_reason: e.rollback_reason.clone(),
        ..Default::default()
    }
}

/// The current or last update's log, or the one that started at `started`.
fn log(r: &Record, started: i64) -> Option<Vec<pb::LogLine>> {
    let lines = if started == 0 {
        &r.log
    } else {
        &r.history.iter().find(|e| e.started == started)?.log
    };
    Some(
        lines
            .iter()
            .map(|l| pb::LogLine {
                unix: l.unix,
                text: l.text.clone(),
                ..Default::default()
            })
            .collect(),
    )
}

// Concrete bodies, where the trait allows any encodable one.
#[allow(refining_impl_trait)]
impl pb::UpdateService for Service {
    async fn begin_upload(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::BeginUploadRequest>,
    ) -> ServiceResult<pb::BeginUploadResponse> {
        let (size, sha, by) = (request.size, hex32(request.sha256)?, request.by.to_string());
        let u = self.uploading(move |up| up.begin(size, &sha, &by)).await?;
        Response::ok(pb::BeginUploadResponse {
            upload: upload(&u).into(),
            ..Default::default()
        })
    }

    async fn put_chunk(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::PutChunkRequest>,
    ) -> ServiceResult<pb::PutChunkResponse> {
        let sha = hex32(request.sha256)?;
        let (index, data, chunk_sha) = (
            request.index,
            request.data.to_vec(),
            request.data_sha256.to_vec(),
        );
        let u = self
            .uploading(move |up| up.put(&sha, index, &data, &chunk_sha))
            .await?;
        Response::ok(pb::PutChunkResponse {
            upload: upload(&u).into(),
            ..Default::default()
        })
    }

    async fn verify(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::VerifyRequest>,
    ) -> ServiceResult<pb::VerifyResponse> {
        let sha = hex32(request.sha256)?;
        Response::ok(pb::VerifyResponse {
            status: self.command(|tx| Command::Verify(sha, tx)).await?.into(),
            ..Default::default()
        })
    }

    async fn apply(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::ApplyRequest>,
    ) -> ServiceResult<pb::ApplyResponse> {
        let (tag, by) = (request.stack_tag.to_string(), request.by.to_string());
        Response::ok(pb::ApplyResponse {
            status: self.command(|tx| Command::Apply(tag, by, tx)).await?.into(),
            ..Default::default()
        })
    }

    async fn get_status(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, pb::GetStatusRequest>,
    ) -> ServiceResult<pb::GetStatusResponse> {
        let s = self.status.borrow().clone();
        Response::ok(pb::GetStatusResponse {
            status: self.convert(&s).into(),
            ..Default::default()
        })
    }

    async fn watch_status(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, pb::WatchStatusRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchStatusResponse>> {
        let mut rx = self.status.clone();
        rx.mark_changed();
        let uploads = self.uploads.clone();
        let stream = futures::stream::unfold(rx, move |mut rx| {
            let uploads = uploads.clone();
            async move {
                rx.changed().await.ok()?;
                let s = rx.borrow_and_update().clone();
                let up = uploads.lock().ok().and_then(|u| u.current());
                let status = status(&s, up.as_ref(), engine::unix_now()).into();
                Some((
                    Ok(pb::WatchStatusResponse {
                        status,
                        ..Default::default()
                    }),
                    rx,
                ))
            }
        });
        Ok(Response::new(
            Box::pin(stream) as ServiceStream<pb::WatchStatusResponse>
        ))
    }

    async fn list_history(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, pb::ListHistoryRequest>,
    ) -> ServiceResult<pb::ListHistoryResponse> {
        let entries = self
            .status
            .borrow()
            .record
            .history
            .iter()
            .map(entry)
            .collect();
        Response::ok(pb::ListHistoryResponse {
            entries,
            ..Default::default()
        })
    }

    async fn reboot(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, pb::RebootRequest>,
    ) -> ServiceResult<pb::RebootResponse> {
        Response::ok(pb::RebootResponse {
            detail: self.power(Power::Reboot).await?,
            ..Default::default()
        })
    }

    async fn shutdown(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, pb::ShutdownRequest>,
    ) -> ServiceResult<pb::ShutdownResponse> {
        Response::ok(pb::ShutdownResponse {
            detail: self.power(Power::Shutdown).await?,
            ..Default::default()
        })
    }

    async fn commit_trial(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::CommitTrialRequest>,
    ) -> ServiceResult<pb::CommitTrialResponse> {
        let (tag, by) = (request.stack_tag.to_string(), request.by.to_string());
        Response::ok(pb::CommitTrialResponse {
            status: self
                .command(|tx| Command::Commit(tag, by, tx))
                .await?
                .into(),
            ..Default::default()
        })
    }

    async fn roll_back(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::RollBackRequest>,
    ) -> ServiceResult<pb::RollBackResponse> {
        let (tag, by) = (request.stack_tag.to_string(), request.by.to_string());
        Response::ok(pb::RollBackResponse {
            status: self
                .command(|tx| Command::RollBack(tag, by, tx))
                .await?
                .into(),
            ..Default::default()
        })
    }

    async fn get_log(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::GetLogRequest>,
    ) -> ServiceResult<pb::GetLogResponse> {
        let lines = log(&self.status.borrow().record, request.started_unix)
            .ok_or_else(|| ConnectError::not_found("no update started then"))?;
        Response::ok(pb::GetLogResponse {
            lines,
            ..Default::default()
        })
    }

    async fn get_storage(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, pb::GetStorageRequest>,
    ) -> ServiceResult<pb::GetStorageResponse> {
        let s = self.ask(Command::Storage).await?;
        Response::ok(pb::GetStorageResponse {
            held_bytes: s.held,
            previous_bytes: s.previous,
            reclaimable_bytes: s.reclaimable,
            free_bytes: s.free,
            ..Default::default()
        })
    }

    async fn collect_garbage(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::CollectGarbageRequest>,
    ) -> ServiceResult<pb::CollectGarbageResponse> {
        let previous = request.previous;
        let freed = self.ask(|tx| Command::Collect(previous, tx)).await?;
        Response::ok(pb::CollectGarbageResponse {
            freed_bytes: freed,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::edge::update::v1::{UpdateServiceClient, UpdateServiceExt};
    use connectrpc::client::{ClientConfig, HttpClient};
    use sha2::{Digest, Sha256};

    async fn serve(
        dir: &std::path::Path,
    ) -> (
        UpdateServiceClient<HttpClient>,
        watch::Sender<Snapshot>,
        mpsc::Receiver<Command>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let (publish, status) = watch::channel(Snapshot::default());
        let svc = Arc::new(Service::new(tx, status, Uploads::new(dir)));
        let bound = connectrpc::Server::bind("127.0.0.1:0").await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(bound.serve(svc.register(connectrpc::Router::new())));
        let client = UpdateServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{addr}").parse().unwrap()),
        );
        (client, publish, rx)
    }

    #[tokio::test]
    async fn an_upload_over_the_wire_resumes_and_completes() {
        let d = tempfile::tempdir().unwrap();
        let (c, _publish, _rx) = serve(d.path()).await;
        let data = vec![7u8; crate::upload::CHUNK as usize + 3];
        let sha = Sha256::digest(&data).to_vec();
        let begin = || pb::BeginUploadRequest {
            size: data.len() as u64,
            sha256: sha.clone(),
            ..Default::default()
        };
        let u = c.begin_upload(begin()).await.unwrap().into_owned();
        let u = (*u.upload).clone();
        assert_eq!(
            (u.chunk_size, u.received.clone()),
            (crate::upload::CHUNK, vec![0])
        );
        let chunk = |i: usize| {
            let part =
                &data[i * u.chunk_size as usize..((i + 1) * u.chunk_size as usize).min(data.len())];
            pb::PutChunkRequest {
                sha256: sha.clone(),
                index: i as u32,
                data: part.to_vec(),
                data_sha256: Sha256::digest(part).to_vec(),
                ..Default::default()
            }
        };
        c.put_chunk(chunk(1)).await.unwrap();
        assert_eq!(
            c.begin_upload(begin())
                .await
                .unwrap()
                .into_owned()
                .upload
                .received,
            vec![0b10]
        );
        let mut bad = chunk(0);
        bad.data_sha256 = vec![0; 32];
        assert!(c.put_chunk(bad).await.is_err());
        assert!(
            c.put_chunk(chunk(0))
                .await
                .unwrap()
                .into_owned()
                .upload
                .complete
        );
        let short = pb::BeginUploadRequest {
            sha256: vec![1; 3],
            ..begin()
        };
        assert!(c.begin_upload(short).await.is_err());
    }

    #[tokio::test]
    async fn uploads_wait_for_an_update_unless_its_trial_is_stuck() {
        let d = tempfile::tempdir().unwrap();
        let (c, publish, _rx) = serve(d.path()).await;
        let begin = pb::BeginUploadRequest {
            size: 10,
            sha256: vec![1; 32],
            ..Default::default()
        };
        let judging = |checks: &str, good: &str| {
            let mut s = Snapshot::default();
            s.record.phase = Phase::Judging {
                rolled_back: String::new(),
            };
            s.record.release = Some(Release {
                manifest: [("STACK_TAG".to_string(), "s1".to_string())].into(),
                ..Release::default()
            });
            s.unit.stack_tag = "s1".into();
            s.unit.judge = crate::judge::Judge::read(
                &[("trial", "s1"), ("good", good), ("checks", checks)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            );
            s
        };
        for (checks, good) in [("pass ready", ""), ("fail ready: x", "s0")] {
            publish.send_replace(judging(checks, good));
            let e = c.begin_upload(begin.clone()).await.unwrap_err();
            assert!(
                e.to_string().contains("in progress"),
                "{checks} {good}: {e}"
            );
        }
        publish.send_replace(judging("fail ready: x", ""));
        c.begin_upload(begin).await.unwrap();
    }

    #[tokio::test]
    async fn commands_reach_the_engine_and_its_status_comes_back() {
        let d = tempfile::tempdir().unwrap();
        let (c, publish, mut rx) = serve(d.path()).await;
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let Command::Verify(sha, reply) = cmd else {
                    unreachable!()
                };
                publish.send_replace(Snapshot {
                    record: Record {
                        phase: Phase::Verifying { sha256: sha },
                        ..Record::default()
                    },
                    detail: "unpacking".into(),
                    ..Snapshot::default()
                });
                let _ = reply.send(Ok(()));
            }
        });
        let s = c
            .verify(pb::VerifyRequest {
                sha256: vec![9; 32],
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned()
            .status;
        assert_eq!(s.phase, buffa::EnumValue::from(pb::Phase::PHASE_VERIFYING));
        assert_eq!(s.detail, "unpacking");
        // Busy: uploads wait until the engine is idle again.
        let e = c
            .begin_upload(pb::BeginUploadRequest {
                size: 1,
                sha256: vec![1; 32],
                ..Default::default()
            })
            .await;
        assert!(e.is_err());
        assert!(
            c.list_history(pb::ListHistoryRequest::default())
                .await
                .unwrap()
                .into_owned()
                .entries
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_status_carries_the_unit() {
        let d = tempfile::tempdir().unwrap();
        let (c, publish, _rx) = serve(d.path()).await;
        publish.send_replace(Snapshot {
            unit: Unit {
                talos_version: "v1.14.1".into(),
                stack_tag: "s2".into(),
                good: "s2".into(),
                previous: "s1".into(),
                trial: "s3".into(),
                rolled_back: "s0 2026-09-01T00:00:00Z".into(),
                os_trial: true,
                ..Unit::default()
            },
            ..Snapshot::default()
        });
        let u = c
            .get_status(pb::GetStatusRequest::default())
            .await
            .unwrap()
            .into_owned()
            .status
            .unit
            .clone();
        assert_eq!(
            (
                u.talos_version.as_str(),
                u.stack_tag.as_str(),
                u.good.as_str(),
                u.previous.as_str(),
                u.trial.as_str(),
                u.rolled_back.as_str(),
                u.os_trial
            ),
            (
                "v1.14.1",
                "s2",
                "s2",
                "s1",
                "s3",
                "s0 2026-09-01T00:00:00Z",
                true
            )
        );
    }

    #[tokio::test]
    async fn power_is_refused_at_once_mid_update_and_asked_of_the_engine_otherwise() {
        let d = tempfile::tempdir().unwrap();
        let (c, publish, mut rx) = serve(d.path()).await;
        publish.send_replace(Snapshot {
            record: Record {
                phase: Phase::Installing,
                ..Record::default()
            },
            ..Snapshot::default()
        });
        let e = c.reboot(pb::RebootRequest::default()).await.unwrap_err();
        assert_eq!(e.code, connectrpc::ErrorCode::FailedPrecondition);
        assert!(e.message.unwrap().contains("under way"));
        assert!(rx.try_recv().is_err(), "the engine was asked");

        publish.send_replace(Snapshot::default());
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let Command::Power(p, reply) = cmd else {
                    unreachable!()
                };
                let _ = reply.send(match p {
                    Power::Reboot => Ok("rebooting".into()),
                    Power::Shutdown => Err(anyhow::anyhow!("apid said no")),
                });
            }
        });
        let r = c.reboot(pb::RebootRequest::default()).await.unwrap();
        assert_eq!(r.into_owned().detail, "rebooting");
        let e = c
            .shutdown(pb::ShutdownRequest::default())
            .await
            .unwrap_err();
        assert_eq!(e.message.as_deref(), Some("apid said no"));
    }

    fn kinds(s: &Snapshot, up: Option<&Upload>) -> Vec<(Step, State)> {
        steps(s, up).iter().map(|t| (t.step, t.state)).collect()
    }

    fn uploading(head: Option<&str>) -> Upload {
        Upload {
            sha256: "aa".repeat(32),
            size: 10,
            chunk_size: 4,
            received: vec![1],
            complete: false,
            started: 100,
            finished: 0,
            by: "ann".into(),
            active: 990,
            head: head.map(|installer| crate::upload::Head {
                manifest: [
                    ("INSTALLER_REF".to_string(), installer.to_string()),
                    ("TALOS_VERSION".into(), "v1.14.1".into()),
                ]
                .into(),
                notes: None,
                signer: String::new(),
            }),
            refused: String::new(),
        }
    }

    #[test]
    fn an_upload_shows_the_steps_its_head_implies() {
        let s = Snapshot {
            unit: Unit {
                talos_version: "v1.14.1".into(),
                installer: "r/i:1@sha256:aa".into(),
                ..Unit::default()
            },
            ..Snapshot::default()
        };
        use State::{Pending, Running};
        // Unknown until the head arrives: every step.
        assert_eq!(kinds(&s, Some(&uploading(None))).len(), 9);
        assert_eq!(
            kinds(&s, Some(&uploading(Some("r/i:2@sha256:aa")))),
            [
                (Step::Upload, Running),
                (Step::Verify, Pending),
                (Step::Stage, Pending),
                (Step::Stack, Pending),
                (Step::Trial, Pending),
                (Step::Commit, Pending),
            ]
        );
        assert_eq!(
            kinds(&s, Some(&uploading(Some("r/i:2@sha256:bb")))).len(),
            9
        );
        let mut refused = uploading(None);
        refused.refused = "not ours".into();
        assert_eq!(kinds(&s, Some(&refused))[0], (Step::Upload, State::Failed));
        assert!(kinds(&Snapshot::default(), None).is_empty());
    }

    #[test]
    fn an_update_shows_what_is_left_and_an_ended_one_only_what_it_took() {
        let mut s = Snapshot::default();
        s.record.phase = Phase::Importing;
        s.record.release = Some(Release {
            diff: Some(Diff::default()),
            ..Release::default()
        });
        for st in [Step::Upload, Step::Verify, Step::Stage] {
            steps::enter(&mut s.record.steps, st, 1);
        }
        assert_eq!(
            kinds(&s, None).last(),
            Some(&(Step::Commit, State::Pending)),
            "no reboot: no OS steps"
        );
        assert_eq!(kinds(&s, None).len(), 6);
        steps::close(&mut s.record.steps, State::Failed, 2);
        s.record.phase = Phase::Idle;
        assert_eq!(kinds(&s, None).last(), Some(&(Step::Stage, State::Failed)));
    }

    #[test]
    fn a_trial_says_its_window_streak_and_checks() {
        let mut s = Snapshot::default();
        s.record.phase = Phase::Judging {
            rolled_back: String::new(),
        };
        s.record.release = Some(Release {
            manifest: [("STACK_TAG".to_string(), "s2".to_string())].into(),
            ..Release::default()
        });
        steps::enter(&mut s.record.steps, Step::Trial, 500);
        s.unit.judge = crate::judge::Judge::read(
            &[
                ("commit_after_secs", "300"),
                ("healthy_since", "1970-01-01T00:10:00Z"),
                ("checks", "pass applied\nfail ready: no"),
                ("requests", "rollback"),
                ("fail_after_secs", "900"),
                ("unhealthy_secs", "45"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        );
        let t = trial(&s).unwrap();
        assert_eq!(
            t.kind,
            buffa::EnumValue::from(pb::TrialKind::TRIAL_KIND_STACK)
        );
        assert_eq!(
            (
                t.stack_tag.as_str(),
                t.started_unix,
                t.window_secs,
                t.healthy_since_unix
            ),
            ("s2", 500, 300, 600)
        );
        assert_eq!(t.checks.len(), 2);
        assert_eq!((t.fail_after_secs, t.unhealthy_secs), (900, 45));
        assert!(!t.can_commit && t.can_roll_back);
        s.unit.judge.requests.insert("commit".into());
        assert!(trial(&s).unwrap().can_commit);

        s.record.phase = Phase::Trial;
        steps::enter(&mut s.record.steps, Step::OsTrial, 700);
        let t = trial(&s).unwrap();
        assert_eq!(t.kind, buffa::EnumValue::from(pb::TrialKind::TRIAL_KIND_OS));
        assert_eq!((t.stack_tag.as_str(), t.started_unix), ("s2", 700));
        assert!(t.can_roll_back && !t.can_commit);
        s.record.phase = Phase::Settling;
        assert!(!trial(&s).unwrap().can_roll_back, "the OS is committed");

        s.record.phase = Phase::Idle;
        assert!(trial(&s).is_none());
        // A rollback to the previous release puts it on trial, engine idle.
        (s.unit.trial, s.unit.stack_tag) = ("s1".into(), "s1".into());
        let t = trial(&s).unwrap();
        assert_eq!((t.stack_tag.as_str(), t.can_roll_back), ("s1", true));
        s.unit.judge.requests.clear();
        assert!(
            !trial(&s).unwrap().can_roll_back,
            "the judge takes no rollback"
        );
    }

    #[test]
    fn the_lock_names_who_updates_or_uploads() {
        let mut s = Snapshot::default();
        let up = uploading(None);
        let l = lock(&s, Some(&up), 1000).unwrap();
        assert_eq!(
            (l.by.as_str(), l.since_unix, l.uploading),
            ("ann", 100, true)
        );
        assert!(
            lock(&s, Some(&up), 990 + crate::upload::LEASE).is_none(),
            "abandoned"
        );
        assert!(lock(&s, None, 1000).is_none());
        s.record.phase = Phase::Installing;
        s.record.by = "bob".into();
        steps::enter(&mut s.record.steps, Step::Verify, 200);
        let l = lock(&s, None, 1000).unwrap();
        assert_eq!(
            (l.by.as_str(), l.since_unix, l.uploading),
            ("bob", 200, false)
        );
    }

    #[test]
    fn a_log_is_the_current_or_one_from_the_history() {
        let line = |t: &str| crate::engine::LogLine {
            unix: 1,
            text: t.into(),
        };
        let mut r = Record {
            log: vec![line("now")],
            ..Record::default()
        };
        r.history.push(Entry {
            release: None,
            outcome: Outcome::Committed,
            detail: String::new(),
            started: 7,
            finished: 8,
            snapshot: None,
            steps: Vec::new(),
            log: vec![line("then")],
            by: String::new(),
            rollback_reason: String::new(),
        });
        assert_eq!(log(&r, 0).unwrap()[0].text, "now");
        assert_eq!(log(&r, 7).unwrap()[0].text, "then");
        assert!(log(&r, 9).is_none());
    }

    #[test]
    fn an_upload_says_everything_it_holds() {
        let mut u = uploading(Some("r/i:1@sha256:aa"));
        u.complete = true;
        u.finished = 200;
        u.refused = "not ours".into();
        u.head.as_mut().unwrap().notes = Some("# 2".into());
        u.head.as_mut().unwrap().signer = "SHA256:x k".into();
        let m = &mut u.head.as_mut().unwrap().manifest;
        m.insert("MODULES".into(), "gw esm".into());
        m.insert("REMOVE".into(), "old".into());
        let p = upload(&u);
        let h = p.head.as_option().unwrap();
        assert_eq!(
            (h.brings_base, h.modules.clone(), h.removes.clone()),
            (
                false,
                vec!["gw".to_string(), "esm".into()],
                vec!["old".into()]
            )
        );
        u.head
            .as_mut()
            .unwrap()
            .manifest
            .insert("STACK_DIGEST".into(), "sha256:s".into());
        assert!(upload(&u).head.as_option().unwrap().brings_base);
        assert_eq!(
            (
                p.sha256.clone(),
                p.size,
                p.chunk_size,
                p.received.clone(),
                p.complete
            ),
            (vec![0xaa; 32], 10, 4, vec![1], true)
        );
        assert_eq!(
            (
                p.started_unix,
                p.finished_unix,
                p.by.as_str(),
                p.active_unix,
                p.refused.as_str()
            ),
            (100, 200, "ann", 990, "not ours")
        );
        let h = p.head.as_option().unwrap();
        assert_eq!(
            (
                h.manifest["TALOS_VERSION"].as_str(),
                h.notes.as_str(),
                h.signer.as_str()
            ),
            ("v1.14.1", "# 2", "SHA256:x k")
        );
    }

    #[test]
    fn a_release_carries_its_checks_diff_and_components() {
        use crate::diff::{ComponentChange, Diff};
        let comp = |v: &str| Component {
            name: "app".into(),
            image: format!("r.io/app:{v}"),
            version: v.into(),
            digest: format!("sha256:{v}"),
            dirty: v == "2",
            carried: v == "2",
            owner: "gw".into(),
        };
        let r = Release {
            sha256: "bb".repeat(32),
            manifest: [
                ("STACK_TAG", "s2"),
                ("TALOS_VERSION", "v1.15.0"),
                ("BUILT_EPOCH", "77"),
                ("COMPONENT_APP", "r.io/app:2 sha256:2 2 dirty=true"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            notes: Some("notes".into()),
            signer: "SHA256:k s".into(),
            images: [("r.io/app:2".to_string(), "sha256:2".to_string())].into(),
            owners: [("r.io/app:2".to_string(), "gw".to_string())].into(),
            brings_base: true,
            modules: ["gw".to_string()].into(),
            removes: ["old".to_string()].into(),
            checks: vec![
                Check::new("space", CheckState::Fail, "full"),
                Check::new("reboot", CheckState::Note, "needed"),
                Check::new("signature", CheckState::Pass, "k"),
            ],
            diff: Some(Diff {
                components: vec![ComponentChange {
                    name: "app".into(),
                    change: Change::Changed,
                    from: Some(comp("1")),
                    to: Some(comp("2")),
                }],
                talos: ("v1.14.1".into(), "v1.15.0".into()),
                installer: ("i@sha256:1".into(), "i@sha256:2".into()),
                stack: ("s1".into(), "s2".into()),
                reboot: true,
                config_changes: true,
                downtime_secs: 120,
                removals_known: true,
            }),
            ..Release::default()
        };
        let p = release(&r);
        assert_eq!(
            (
                p.stack_tag.as_str(),
                p.talos_version.as_str(),
                p.built_epoch,
                p.sha256.clone()
            ),
            ("s2", "v1.15.0", 77, vec![0xbb; 32])
        );
        assert_eq!(
            (p.notes.as_str(), p.signer.as_str()),
            ("notes", "SHA256:k s")
        );
        assert_eq!(p.manifest.len(), 4);
        let checks: Vec<_> = p
            .checks
            .iter()
            .map(|c| (c.name.as_str(), c.state, c.detail.as_str()))
            .collect();
        assert_eq!(
            checks,
            [
                ("space", pb::CheckState::CHECK_STATE_FAIL.into(), "full"),
                ("reboot", pb::CheckState::CHECK_STATE_NOTE.into(), "needed"),
                ("signature", pb::CheckState::CHECK_STATE_PASS.into(), "k"),
            ]
        );
        let d = p.diff.as_option().unwrap();
        assert_eq!(
            (
                d.talos_from.as_str(),
                d.talos_to.as_str(),
                d.installer_from.as_str(),
                d.installer_to.as_str(),
                d.stack_from.as_str(),
                d.stack_to.as_str()
            ),
            ("v1.14.1", "v1.15.0", "i@sha256:1", "i@sha256:2", "s1", "s2")
        );
        assert_eq!(
            (
                d.reboot,
                d.config_changes,
                d.downtime_secs,
                d.removals_known
            ),
            (true, true, 120, true)
        );
        let c = &d.components[0];
        assert_eq!(
            (c.name.as_str(), c.change),
            ("app", pb::Change::CHANGE_CHANGED.into())
        );
        let (from, to) = (c.from.as_option().unwrap(), c.to.as_option().unwrap());
        assert_eq!(
            (
                from.version.as_str(),
                to.version.as_str(),
                to.digest.as_str(),
                to.image.as_str(),
                to.dirty,
                from.dirty
            ),
            ("1", "2", "sha256:2", "r.io/app:2", true, false)
        );
        assert_eq!(
            (to.carried, from.carried, to.owner.as_str()),
            (true, false, "gw")
        );
        assert_eq!(
            (p.brings_base, p.modules.clone(), p.removes.clone()),
            (true, vec!["gw".to_string()], vec!["old".to_string()])
        );
        assert_eq!(to.kind, pb::ComponentKind::COMPONENT_KIND_IMAGE);
        let comps: Vec<_> = p
            .components
            .iter()
            .map(|c| {
                (
                    c.name.as_str(),
                    c.version.as_str(),
                    c.dirty,
                    c.carried,
                    c.owner.as_str(),
                )
            })
            .collect();
        assert_eq!(comps, [("app", "2", true, true, "gw")]);
        for (ch, want) in [
            (Change::Unchanged, pb::Change::CHANGE_UNCHANGED),
            (Change::Added, pb::Change::CHANGE_ADDED),
            (Change::Removed, pb::Change::CHANGE_REMOVED),
        ] {
            let d = diff(&Diff {
                components: vec![ComponentChange {
                    name: "x".into(),
                    change: ch,
                    from: None,
                    to: None,
                }],
                ..Diff::default()
            });
            assert_eq!(d.components[0].change, want);
        }
    }

    #[test]
    fn the_unit_and_an_entry_say_everything_they_hold() {
        let u = unit(&Unit {
            installer: "i@sha256:1".into(),
            flux_version: "v2.6.4".into(),
            components: vec![Component {
                name: "app".into(),
                ..Component::default()
            }],
            manifest: [("GIT_REV".to_string(), "abc".to_string())].into(),
            modules: ["esm".to_string(), "gw".into()].into(),
            ..Unit::default()
        });
        assert_eq!(u.modules, ["esm", "gw"]);
        assert_eq!(
            (
                u.installer.as_str(),
                u.flux_version.as_str(),
                u.components[0].name.as_str(),
                u.manifest["GIT_REV"].as_str()
            ),
            ("i@sha256:1", "v2.6.4", "app", "abc")
        );
        let mut steps = Vec::new();
        steps::enter(&mut steps, Step::Trial, 5);
        steps::close(&mut steps, State::Failed, 9);
        let e = entry(&Entry {
            release: None,
            outcome: Outcome::RolledBack,
            detail: "d".into(),
            started: 5,
            finished: 9,
            snapshot: Some("ff".into()),
            steps,
            log: Vec::new(),
            by: "ann".into(),
            rollback_reason: "s2 stayed unhealthy".into(),
        });
        assert_eq!(e.outcome, pb::Outcome::OUTCOME_ROLLED_BACK);
        assert_eq!(
            (
                e.detail.as_str(),
                e.started_unix,
                e.finished_unix,
                e.snapshot_sha256.as_str(),
                e.by.as_str(),
                e.rollback_reason.as_str()
            ),
            ("d", 5, 9, "ff", "ann", "s2 stayed unhealthy")
        );
        let s = &e.steps[0];
        assert_eq!(
            (s.kind, s.state, s.started_unix, s.finished_unix),
            (
                pb::StepKind::STEP_KIND_TRIAL.into(),
                pb::StepState::STEP_STATE_FAILED.into(),
                5,
                9
            )
        );
        let kinds: Vec<_> = [
            Step::Upload,
            Step::Verify,
            Step::Stage,
            Step::Install,
            Step::Reboot,
            Step::OsTrial,
            Step::Stack,
            Step::Trial,
            Step::Commit,
        ]
        .into_iter()
        .map(|k| {
            step(&Taken {
                step: k,
                state: State::Pending,
                started: 0,
                finished: 0,
            })
            .kind
            .to_i32()
        })
        .collect();
        assert_eq!(kinds, (1..=9).collect::<Vec<_>>());
        let states: Vec<_> = [
            State::Pending,
            State::Running,
            State::Done,
            State::Failed,
            State::Skipped,
        ]
        .into_iter()
        .map(|st| {
            step(&Taken {
                step: Step::Upload,
                state: st,
                started: 0,
                finished: 0,
            })
            .state
            .to_i32()
        })
        .collect();
        assert_eq!(states, (1..=5).collect::<Vec<_>>());
    }

    #[test]
    fn progress_reaches_the_status() {
        let s = Snapshot {
            progress: Some((5, 10, 99)),
            ..Snapshot::default()
        };
        let p = status(&s, None, 0).progress.into_option().unwrap();
        assert_eq!((p.done, p.total, p.started_unix), (5, 10, 99));
        assert!(
            status(&Snapshot::default(), None, 0)
                .progress
                .as_option()
                .is_none()
        );
    }

    #[test]
    fn the_status_carries_every_part() {
        let mut s = Snapshot::default();
        s.record.phase = Phase::Judging {
            rolled_back: String::new(),
        };
        s.record.release = Some(Release {
            manifest: [("STACK_TAG".to_string(), "s2".to_string())].into(),
            ..Release::default()
        });
        s.record.error = "last one failed".into();
        s.record.since = 321;
        s.record.by = "ann".into();
        steps::enter(&mut s.record.steps, Step::Trial, 300);
        let up = uploading(None);
        let st = status(&s, Some(&up), 1000);
        assert_eq!(
            st.release.as_option().map(|r| r.stack_tag.as_str()),
            Some("s2")
        );
        assert_eq!(
            (st.error.as_str(), st.updated_unix),
            ("last one failed", 321)
        );
        assert_eq!(st.upload.as_option().map(|u| u.by.as_str()), Some("ann"));
        assert_eq!(st.steps.len(), 9, "the trial running, the rest planned");
        assert_eq!(
            st.trial.as_option().map(|t| t.stack_tag.as_str()),
            Some("s2")
        );
        assert_eq!(st.lock.as_option().map(|l| l.by.as_str()), Some("ann"));

        let e = entry(&Entry {
            release: s.record.release.clone(),
            outcome: Outcome::Committed,
            detail: String::new(),
            started: 1,
            finished: 2,
            snapshot: None,
            steps: Vec::new(),
            log: Vec::new(),
            by: String::new(),
            rollback_reason: String::new(),
        });
        assert_eq!(
            e.release.as_option().map(|r| r.stack_tag.as_str()),
            Some("s2")
        );
        let r = Record {
            log: vec![crate::engine::LogLine {
                unix: 42,
                text: "x".into(),
            }],
            ..Record::default()
        };
        assert_eq!(log(&r, 0).unwrap()[0].unix, 42);
    }

    #[tokio::test]
    async fn trial_actions_storage_and_cleanup_reach_the_engine_and_answer() {
        let d = tempfile::tempdir().unwrap();
        let (c, publish, mut rx) = serve(d.path()).await;
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let busy = |by: String| Snapshot {
                    record: Record {
                        phase: Phase::Importing,
                        by,
                        ..Record::default()
                    },
                    ..Snapshot::default()
                };
                match cmd {
                    Command::Apply(_, by, reply) | Command::Commit(_, by, reply) => {
                        publish.send_replace(busy(by));
                        let _ = reply.send(Ok(()));
                    }
                    Command::RollBack(tag, by, reply) => {
                        publish.send_replace(busy(by));
                        let _ = reply.send(Ok(tag));
                    }
                    Command::Storage(reply) => {
                        let _ = reply.send(Ok(Storage {
                            held: 4,
                            previous: 3,
                            reclaimable: 2,
                            free: 1,
                        }));
                    }
                    Command::Collect(previous, reply) => {
                        let _ = reply.send(Ok(if previous { 9 } else { 8 }));
                    }
                    _ => unreachable!(),
                }
            }
        });
        let by = |r: Option<String>| r;
        let s = c
            .apply(pb::ApplyRequest {
                stack_tag: "s2".into(),
                by: "ann".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned()
            .status;
        assert_eq!(
            by(s.lock.as_option().map(|l| l.by.clone())).as_deref(),
            Some("ann")
        );
        let s = c
            .commit_trial(pb::CommitTrialRequest {
                stack_tag: "s2".into(),
                by: "bob".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned()
            .status;
        assert_eq!(s.lock.as_option().map(|l| l.by.as_str()), Some("bob"));
        let s = c
            .roll_back(pb::RollBackRequest {
                stack_tag: "s2".into(),
                by: "cy".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned()
            .status;
        assert_eq!(s.lock.as_option().map(|l| l.by.as_str()), Some("cy"));
        let st = c
            .get_storage(pb::GetStorageRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            (
                st.held_bytes,
                st.previous_bytes,
                st.reclaimable_bytes,
                st.free_bytes
            ),
            (4, 3, 2, 1)
        );
        for (previous, freed) in [(false, 8), (true, 9)] {
            let got = c
                .collect_garbage(pb::CollectGarbageRequest {
                    previous,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned();
            assert_eq!(got.freed_bytes, freed);
        }
        let l = c
            .get_log(pb::GetLogRequest {
                started_unix: 5,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(l.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn a_log_comes_over_the_wire() {
        let d = tempfile::tempdir().unwrap();
        let (c, publish, _rx) = serve(d.path()).await;
        publish.send_replace(Snapshot {
            record: Record {
                log: vec![crate::engine::LogLine {
                    unix: 7,
                    text: "verifying".into(),
                }],
                ..Record::default()
            },
            ..Snapshot::default()
        });
        let got = c
            .get_log(pb::GetLogRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            got.lines
                .iter()
                .map(|l| (l.unix, l.text.as_str()))
                .collect::<Vec<_>>(),
            [(7, "verifying")]
        );
    }
}
