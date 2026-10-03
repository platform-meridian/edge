//! Wiping EPHEMERAL drops Kubernetes state and pulled images; the machine config,
//! sealed in STATE, stays, so the node bootstraps again from the image cache.
//! machined authorises by caller PID: an `ext-*` service may claim any role.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use tonic::transport::{Endpoint, Uri};

pub mod pb {
    tonic::include_proto!("machine");
}

use pb::machine_service_client::MachineServiceClient;
use pb::reset_request::WipeMode;
use pb::{ResetPartitionSpec, ResetRequest};

const CALL: Duration = Duration::from_secs(30);

pub fn wipe_ephemeral() -> ResetRequest {
    ResetRequest {
        // Graceful drains and leaves etcd: on one node there is nothing to
        // hand over, and a wedged cluster would stall it.
        graceful: false,
        reboot: true,
        system_partitions_to_wipe: vec![ResetPartitionSpec {
            label: "EPHEMERAL".into(),
            wipe: true,
        }],
        user_disks_to_wipe: vec![],
        mode: WipeMode::SystemDisk as i32,
    }
}

pub async fn reset_ephemeral(socket: &Path) -> anyhow::Result<()> {
    let socket: PathBuf = socket.to_path_buf();
    anyhow::ensure!(
        socket.exists(),
        "no machined socket at {}",
        socket.display()
    );
    // tonic dials URIs; the connector ignores this one and opens the socket.
    let channel = Endpoint::try_from("http://[::]:50000")?
        .timeout(CALL)
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let io = tokio::net::UnixStream::connect(socket).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io))
            }
        }))
        .await
        .context("connect to machined")?;
    let mut req = tonic::Request::new(wipe_ephemeral());
    req.metadata_mut().insert(
        "talos-role",
        tonic::metadata::MetadataValue::from_static("os:admin"),
    );
    let reply = MachineServiceClient::new(channel)
        .reset(req)
        .await
        .context("machined refused the reset")?;
    let actor = reply
        .into_inner()
        .messages
        .into_iter()
        .next()
        .map(|m| m.actor_id)
        .unwrap_or_default();
    tracing::warn!(actor, "machined accepted the EPHEMERAL wipe");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::machine_service_server::{MachineService, MachineServiceServer};
    use pb::{Reset, ResetResponse};
    use std::sync::{Arc, Mutex};

    type Seen = (ResetRequest, Option<String>);

    #[derive(Clone, Default)]
    struct Machined {
        seen: Arc<Mutex<Vec<Seen>>>,
        refuse: bool,
    }

    #[tonic::async_trait]
    impl MachineService for Machined {
        async fn reset(
            &self,
            req: tonic::Request<ResetRequest>,
        ) -> Result<tonic::Response<ResetResponse>, tonic::Status> {
            let role = req
                .metadata()
                .get("talos-role")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            self.seen.lock().unwrap().push((req.into_inner(), role));
            if self.refuse {
                return Err(tonic::Status::permission_denied("not authorized"));
            }
            Ok(tonic::Response::new(ResetResponse {
                messages: vec![Reset {
                    actor_id: "actor-1".into(),
                }],
            }))
        }
    }

    async fn serve(sock: &Path, m: Machined) {
        let listener = tokio::net::UnixListener::bind(sock).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(MachineServiceServer::new(m))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
        );
    }

    #[tokio::test]
    async fn wipes_only_ephemeral_as_admin() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let sock = d.join("machine.sock");
        let m = Machined::default();
        serve(&sock, m.clone()).await;
        reset_ephemeral(&sock).await.unwrap();
        let seen = m.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let (req, role) = &seen[0];
        assert_eq!(role.as_deref(), Some("os:admin"));
        assert!(!req.graceful && req.reboot);
        assert_eq!(req.mode, WipeMode::SystemDisk as i32);
        assert!(req.user_disks_to_wipe.is_empty());
        assert_eq!(
            req.system_partitions_to_wipe,
            vec![ResetPartitionSpec {
                label: "EPHEMERAL".into(),
                wipe: true
            }]
        );
    }

    #[tokio::test]
    async fn refusal_and_absence_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let sock = d.join("machine.sock");
        serve(
            &sock,
            Machined {
                refuse: true,
                ..Default::default()
            },
        )
        .await;
        let e = format!("{:#}", reset_ephemeral(&sock).await.unwrap_err());
        assert!(e.contains("not authorized"), "{e}");
        let e = format!(
            "{:#}",
            reset_ephemeral(&d.join("absent.sock")).await.unwrap_err()
        );
        assert!(e.contains("no machined socket"), "{e}");
    }
}
