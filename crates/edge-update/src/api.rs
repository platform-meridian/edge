//! The update API over ConnectRPC. Uploads are handled here; verifying and
//! applying are handed to the engine, whose status every client watches.

use std::sync::{Arc, Mutex};

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::engine::{Entry, Outcome, Phase, Power, Record, Release, Unit};
use crate::pb::edge::update::v1 as pb;
use crate::upload::{Upload, Uploads};

pub enum Command {
    Verify(String, oneshot::Sender<anyhow::Result<()>>),
    Apply(String, oneshot::Sender<anyhow::Result<()>>),
    Power(Power, oneshot::Sender<anyhow::Result<String>>),
}

#[derive(Clone, Default, PartialEq)]
pub struct Snapshot {
    pub record: Record,
    pub detail: String,
    pub unit: Unit,
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
        match self.status.borrow().record.phase {
            Phase::Idle => Ok(()),
            _ => Err(ConnectError::failed_precondition(
                "an update is in progress",
            )),
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
        .map_err(|e| ConnectError::invalid_argument(format!("{e:#}")))
    }

    async fn ask<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<anyhow::Result<T>>) -> Command,
    ) -> Result<T, ConnectError> {
        let (tx, rx) = oneshot::channel();
        fn stopped<E>(_: E) -> ConnectError {
            ConnectError::unavailable("the engine has stopped")
        }
        self.commands.send(make(tx)).await.map_err(stopped)?;
        rx.await
            .map_err(stopped)?
            .map_err(|e| ConnectError::failed_precondition(format!("{e:#}")))
    }

    async fn command(
        &self,
        make: impl FnOnce(oneshot::Sender<anyhow::Result<()>>) -> Command,
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
        status(s, upload.as_ref())
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
        ..Default::default()
    }
}

fn status(s: &Snapshot, up: Option<&Upload>) -> pb::Status {
    let r = &s.record;
    pb::Status {
        phase: phase(r).into(),
        detail: s.detail.clone(),
        release: r.release.as_ref().map(release).into(),
        error: r.error.clone(),
        upload: up.map(upload).into(),
        updated_unix: r.since,
        unit: Some(unit(&s.unit)).into(),
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
        }
        .into(),
        detail: e.detail.clone(),
        started_unix: e.started,
        finished_unix: e.finished,
        snapshot_sha256: e.snapshot.clone().unwrap_or_default(),
        ..Default::default()
    }
}

// Concrete bodies, where the trait allows any encodable one.
#[allow(refining_impl_trait)]
impl pb::UpdateService for Service {
    async fn begin_upload(
        &self,
        _: RequestContext,
        request: ServiceRequest<'_, pb::BeginUploadRequest>,
    ) -> ServiceResult<pb::BeginUploadResponse> {
        let (size, sha) = (request.size, hex32(request.sha256)?);
        let u = self.uploading(move |up| up.begin(size, &sha)).await?;
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
        let tag = request.stack_tag.to_string();
        Response::ok(pb::ApplyResponse {
            status: self.command(|tx| Command::Apply(tag, tx)).await?.into(),
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
                let status = status(&s, up.as_ref()).into();
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
}
