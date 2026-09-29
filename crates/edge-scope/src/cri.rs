//! After the clock goes backwards the kubelet takes a pod's newest-created container
//! as current, so a dead one stamped in the future wedges it. Only what is not
//! running goes, and only from the future.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::Context;
use tonic::transport::{Endpoint, Uri};

pub mod pb {
    #![allow(clippy::enum_variant_names)]
    tonic::include_proto!("runtime.v1");
}

use pb::runtime_service_client::RuntimeServiceClient;
use pb::{ContainerState, PodSandboxState};

/// Clock error a creation stamp may carry without being from the future.
pub const SLACK: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_secs(1);
const EVERY: Duration = Duration::from_secs(15);
const CALL: Duration = Duration::from_secs(10);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stale {
    pub containers: Vec<String>,
    pub sandboxes: Vec<String>,
    pub ahead_secs: u64,
}

impl Stale {
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty() && self.sandboxes.is_empty()
    }
}

/// A sandbox goes only with none of its containers running.
pub fn stale(now: i64, containers: &[pb::Container], sandboxes: &[pb::PodSandbox]) -> Stale {
    let horizon = now.saturating_add(SLACK.as_nanos() as i64);
    let mut out = Stale::default();
    let mut note = |created: i64| {
        out.ahead_secs = out
            .ahead_secs
            .max((created.saturating_sub(now) / 1_000_000_000) as u64);
    };
    let running = |c: &pb::Container| c.state() == ContainerState::ContainerRunning;
    let mut gone = Vec::new();
    for c in containers {
        if c.created_at > horizon
            && matches!(
                c.state(),
                ContainerState::ContainerExited | ContainerState::ContainerCreated
            )
        {
            note(c.created_at);
            gone.push(c.id.clone());
        }
    }
    let mut sbs = Vec::new();
    for s in sandboxes {
        if s.created_at > horizon
            && s.state() == PodSandboxState::SandboxNotready
            && !containers
                .iter()
                .any(|c| c.pod_sandbox_id == s.id && running(c))
        {
            note(s.created_at);
            sbs.push(s.id.clone());
        }
    }
    out.containers = gone;
    out.sandboxes = sbs;
    out
}

async fn connect(sock: &Path) -> anyhow::Result<RuntimeServiceClient<tonic::transport::Channel>> {
    let sock: PathBuf = sock.to_path_buf();
    anyhow::ensure!(sock.exists(), "no CRI socket at {}", sock.display());
    // tonic dials URIs; the connector ignores this one and opens the socket.
    let channel = Endpoint::try_from("http://[::]:50051")?
        .timeout(CALL)
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let sock = sock.clone();
            async move {
                let io = tokio::net::UnixStream::connect(sock).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io))
            }
        }))
        .await
        .context("connect to the CRI socket")?;
    Ok(RuntimeServiceClient::new(channel))
}

pub async fn sweep(sock: &Path, now: impl Fn() -> i64) -> anyhow::Result<Stale> {
    let mut c = connect(sock).await?;
    let sandboxes = c
        .list_pod_sandbox(pb::ListPodSandboxRequest {})
        .await
        .context("list sandboxes")?
        .into_inner()
        .items;
    let containers = c
        .list_containers(pb::ListContainersRequest {})
        .await
        .context("list containers")?
        .into_inner()
        .containers;
    let now = now();
    let found = stale(now, &containers, &sandboxes);
    let mut done = Stale {
        ahead_secs: found.ahead_secs,
        ..Default::default()
    };
    let name = |id: &str| -> String {
        containers
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.metadata.as_ref())
            .map(|m| format!("{}/{}", m.name, m.attempt))
            .or_else(|| {
                sandboxes
                    .iter()
                    .find(|s| s.id == id)
                    .and_then(|s| s.metadata.as_ref())
                    .map(|m| format!("{}/{}/{}", m.namespace, m.name, m.attempt))
            })
            .unwrap_or_default()
    };
    for id in found.containers {
        match c
            .remove_container(pb::RemoveContainerRequest {
                container_id: id.clone(),
            })
            .await
        {
            Ok(_) => {
                tracing::warn!(container = %id, name = %name(&id), "removed a dead container stamped in the future");
                done.containers.push(id);
            }
            Err(e) => {
                tracing::warn!(container = %id, error = %e, "could not remove a container stamped in the future")
            }
        }
    }
    for id in found.sandboxes {
        let r = async {
            c.stop_pod_sandbox(pb::StopPodSandboxRequest {
                pod_sandbox_id: id.clone(),
            })
            .await?;
            c.remove_pod_sandbox(pb::RemovePodSandboxRequest {
                pod_sandbox_id: id.clone(),
            })
            .await
        }
        .await;
        match r {
            Ok(_) => {
                tracing::warn!(sandbox = %id, name = %name(&id), "removed a dead sandbox stamped in the future");
                done.sandboxes.push(id);
            }
            Err(e) => {
                tracing::warn!(sandbox = %id, error = %e, "could not remove a sandbox stamped in the future")
            }
        }
    }
    Ok(done)
}

pub fn wall_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Repeats: the clock can also go back during a boot.
pub fn spawn(sock: PathBuf, tx: Sender<Stale>) -> std::io::Result<()> {
    std::thread::Builder::new().name("cri".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(error = %e, "no runtime for the CRI sweep; it is off");
                return;
            }
        };
        let mut ok_once = false;
        loop {
            match rt.block_on(sweep(&sock, wall_ns)) {
                Ok(done) => {
                    if !ok_once {
                        tracing::info!(socket = %sock.display(), "sweeping CRI state stamped in the future");
                    }
                    ok_once = true;
                    if !done.is_empty() && tx.send(done).is_err() {
                        return;
                    }
                }
                Err(e) if ok_once => {
                    tracing::warn!(error = %format!("{e:#}"), "CRI sweep failed; retrying")
                }
                Err(_) => {}
            }
            std::thread::sleep(if ok_once { EVERY } else { RETRY });
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::runtime_service_server::{RuntimeService, RuntimeServiceServer};
    use std::sync::{Arc, Mutex};
    use tonic::{Request, Response, Status};

    const S: i64 = 1_000_000_000;
    const NOW: i64 = 1_790_537_906 * S;
    const YEAR: i64 = 31_536_000 * S;

    fn ctr(id: &str, sb: &str, state: ContainerState, created: i64) -> pb::Container {
        pb::Container {
            id: id.into(),
            pod_sandbox_id: sb.into(),
            metadata: Some(pb::ContainerMetadata {
                name: format!("n-{id}"),
                attempt: 3,
            }),
            state: state as i32,
            created_at: created,
        }
    }

    fn sbx(id: &str, state: PodSandboxState, created: i64) -> pb::PodSandbox {
        pb::PodSandbox {
            id: id.into(),
            metadata: Some(pb::PodSandboxMetadata {
                name: format!("p-{id}"),
                uid: "u".into(),
                namespace: "ns".into(),
                attempt: 1,
            }),
            state: state as i32,
            created_at: created,
        }
    }

    use ContainerState::*;
    use PodSandboxState::*;

    #[test]
    fn only_dead_future_state_stale() {
        let containers = vec![
            ctr("future-exited", "sb-future", ContainerExited, NOW + YEAR),
            ctr("future-created", "sb-future", ContainerCreated, NOW + YEAR),
            ctr(
                "future-running",
                "sb-live-future",
                ContainerRunning,
                NOW + YEAR,
            ),
            ctr("future-unknown", "sb-future", ContainerUnknown, NOW + YEAR),
            ctr("past-exited", "sb-past", ContainerExited, NOW - YEAR),
            ctr("in-slack", "sb-past", ContainerExited, NOW + 59 * S),
            ctr(
                "at-slack",
                "sb-past",
                ContainerExited,
                NOW + SLACK.as_nanos() as i64,
            ),
            ctr(
                "running-in-dead",
                "sb-dead-future-busy",
                ContainerRunning,
                NOW,
            ),
        ];
        let sandboxes = vec![
            sbx("sb-future", SandboxNotready, NOW + YEAR),
            sbx("sb-live-future", SandboxReady, NOW + YEAR),
            sbx("sb-dead-future-busy", SandboxNotready, NOW + 2 * YEAR),
            sbx("sb-past", SandboxNotready, NOW - S),
            sbx(
                "sb-in-slack",
                SandboxNotready,
                NOW + SLACK.as_nanos() as i64,
            ),
        ];
        let s = stale(NOW, &containers, &sandboxes);
        assert_eq!(s.containers, ["future-exited", "future-created"]);
        assert_eq!(s.sandboxes, ["sb-future"]);
        assert_eq!(s.ahead_secs, (YEAR / S) as u64);
        assert!(!s.is_empty());
        assert!(stale(NOW + 2 * YEAR, &containers, &sandboxes).is_empty());
        let only_sandboxes = stale(NOW, &[], &sandboxes[..1]);
        assert_eq!(only_sandboxes.sandboxes, ["sb-future"]);
        assert!(!only_sandboxes.is_empty());
    }

    #[test]
    fn wall_ns_is_wall_clock() {
        let sys = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        assert!((wall_ns() - sys).abs() < 5 * S, "{} vs {sys}", wall_ns());
    }

    #[derive(Default)]
    struct Fake {
        containers: Mutex<Vec<pb::Container>>,
        sandboxes: Mutex<Vec<pb::PodSandbox>>,
        calls: Mutex<Vec<String>>,
        refuse: Mutex<Vec<String>>,
    }

    #[tonic::async_trait]
    impl RuntimeService for Arc<Fake> {
        async fn stop_pod_sandbox(
            &self,
            r: Request<pb::StopPodSandboxRequest>,
        ) -> Result<Response<pb::StopPodSandboxResponse>, Status> {
            let id = r.into_inner().pod_sandbox_id;
            self.calls.lock().unwrap().push(format!("stop {id}"));
            Ok(Response::new(pb::StopPodSandboxResponse {}))
        }
        async fn remove_pod_sandbox(
            &self,
            r: Request<pb::RemovePodSandboxRequest>,
        ) -> Result<Response<pb::RemovePodSandboxResponse>, Status> {
            let id = r.into_inner().pod_sandbox_id;
            self.calls.lock().unwrap().push(format!("rm-sandbox {id}"));
            self.sandboxes.lock().unwrap().retain(|s| s.id != id);
            self.containers
                .lock()
                .unwrap()
                .retain(|c| c.pod_sandbox_id != id);
            Ok(Response::new(pb::RemovePodSandboxResponse {}))
        }
        async fn list_pod_sandbox(
            &self,
            _: Request<pb::ListPodSandboxRequest>,
        ) -> Result<Response<pb::ListPodSandboxResponse>, Status> {
            Ok(Response::new(pb::ListPodSandboxResponse {
                items: self.sandboxes.lock().unwrap().clone(),
            }))
        }
        async fn remove_container(
            &self,
            r: Request<pb::RemoveContainerRequest>,
        ) -> Result<Response<pb::RemoveContainerResponse>, Status> {
            let id = r.into_inner().container_id;
            if self.refuse.lock().unwrap().contains(&id) {
                return Err(Status::unavailable("busy"));
            }
            self.calls.lock().unwrap().push(format!("rm {id}"));
            self.containers.lock().unwrap().retain(|c| c.id != id);
            Ok(Response::new(pb::RemoveContainerResponse {}))
        }
        async fn list_containers(
            &self,
            _: Request<pb::ListContainersRequest>,
        ) -> Result<Response<pb::ListContainersResponse>, Status> {
            Ok(Response::new(pb::ListContainersResponse {
                containers: self.containers.lock().unwrap().clone(),
            }))
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("edge-scope-cri-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn serve(sock: &Path, fake: Arc<Fake>) {
        let listener = tokio::net::UnixListener::bind(sock).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(RuntimeServiceServer::new(fake))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
        );
    }

    #[tokio::test]
    async fn sweep_removes_future_state() {
        let d = scratch("sweep");
        let sock = d.join("containerd.sock");
        assert!(sweep(&sock, || NOW).await.is_err(), "no socket yet");
        let fake = Arc::new(Fake::default());
        *fake.sandboxes.lock().unwrap() = vec![
            sbx("sb-old-boot", SandboxNotready, NOW + YEAR),
            sbx("sb-now", SandboxReady, NOW),
        ];
        *fake.containers.lock().unwrap() = vec![
            ctr("old-boot", "sb-old-boot", ContainerExited, NOW + YEAR),
            ctr("stuck", "sb-now", ContainerExited, NOW + YEAR - S),
            ctr("live", "sb-now", ContainerRunning, NOW),
            ctr("refused", "sb-now", ContainerExited, NOW + YEAR),
        ];
        fake.refuse.lock().unwrap().push("refused".into());
        serve(&sock, fake.clone());

        let done = sweep(&sock, || NOW).await.unwrap();
        assert_eq!(done.containers, ["old-boot", "stuck"]);
        assert_eq!(done.sandboxes, ["sb-old-boot"]);
        assert_eq!(done.ahead_secs, (YEAR / S) as u64);
        assert_eq!(
            *fake.calls.lock().unwrap(),
            [
                "rm old-boot",
                "rm stuck",
                "stop sb-old-boot",
                "rm-sandbox sb-old-boot"
            ]
        );
        let left: Vec<_> = fake
            .containers
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.id.clone())
            .collect();
        assert_eq!(left, ["live", "refused"]);

        fake.refuse.lock().unwrap().clear();
        let again = sweep(&sock, || NOW).await.unwrap();
        assert_eq!(again.containers, ["refused"], "a failed removal is retried");
        assert!(sweep(&sock, || NOW).await.unwrap().is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn sweeper_waits_for_socket() {
        let d = scratch("spawn");
        let sock = d.join("containerd.sock");
        let (tx, rx) = std::sync::mpsc::channel();
        spawn(sock.clone(), tx).unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let fake = Arc::new(Fake::default());
        let future = wall_ns() + YEAR;
        *fake.containers.lock().unwrap() = vec![
            ctr("old-boot", "sb", ContainerExited, future),
            ctr("live", "sb", ContainerRunning, future),
        ];
        serve(&sock, fake.clone());
        let got = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .expect("a report within one retry");
        assert_eq!(got.containers, ["old-boot"]);
        assert!(got.ahead_secs > (YEAR / S) as u64 - 60);
        assert_eq!(*fake.calls.lock().unwrap(), ["rm old-boot"]);
        std::fs::remove_dir_all(&d).ok();
    }
}
