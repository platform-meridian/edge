//! The update API over ConnectRPC. Uploads are handled here; verifying and
//! applying are handed to the engine, whose status every client watches.

use std::sync::{Arc, Mutex};

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use tokio::sync::{mpsc, oneshot, watch};

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

    fn idle(&self) -> Result<(), ConnectError> {
        let s = self.status.borrow();
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
        ..Default::default()
    }
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
        assert!(!t.can_commit && t.can_roll_back);

        s.record.phase = Phase::Trial;
        let t = trial(&s).unwrap();
        assert_eq!(t.kind, buffa::EnumValue::from(pb::TrialKind::TRIAL_KIND_OS));
        assert!(t.can_roll_back && !t.can_commit);
        s.record.phase = Phase::Settling;
        assert!(!trial(&s).unwrap().can_roll_back, "the OS is committed");

        s.record.phase = Phase::Idle;
        assert!(trial(&s).is_none());
        // A rollback to the previous release puts it on trial, engine idle.
        (s.unit.trial, s.unit.stack_tag) = ("s1".into(), "s1".into());
        let t = trial(&s).unwrap();
        assert_eq!((t.stack_tag.as_str(), t.can_roll_back), ("s1", true));
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
}
