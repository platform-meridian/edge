//! Talos unmounts volumes before it stops extension services, so a ring still
//! open then keeps the evidence volume busy and the reboot falls back to a
//! forced one. machined announces the sequence first; that is the cue to stop.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::Context;
use prost::Message;
use tonic::transport::{Endpoint, Uri};

pub mod pb {
    tonic::include_proto!("machine");
}

use pb::machine_service_client::MachineServiceClient;
use pb::sequence_event::Action;

const RETRY: Duration = Duration::from_secs(5);
const ENDS_THE_BOOT: [&str; 5] = ["reboot", "shutdown", "upgrade", "stageUpgrade", "reset"];

pub fn ending(event: &pb::Event) -> Option<String> {
    let data = event.data.as_ref()?;
    if data.type_url.rsplit('/').next() != Some("machine.SequenceEvent") {
        return None;
    }
    let s = pb::SequenceEvent::decode(data.value.as_slice()).ok()?;
    (s.action() == Action::Start && ENDS_THE_BOOT.contains(&s.sequence.as_str()))
        .then_some(s.sequence)
}

pub async fn wait(socket: &Path) -> anyhow::Result<String> {
    let socket: PathBuf = socket.to_path_buf();
    anyhow::ensure!(
        socket.exists(),
        "no machined socket at {}",
        socket.display()
    );
    // tonic dials URIs; the connector ignores this one and opens the socket.
    let channel = Endpoint::try_from("http://[::]:50000")?
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let io = tokio::net::UnixStream::connect(socket).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io))
            }
        }))
        .await
        .context("connect to machined")?;
    let mut req = tonic::Request::new(pb::EventsRequest {});
    req.metadata_mut().insert(
        "talos-role",
        tonic::metadata::MetadataValue::from_static("os:reader"),
    );
    let mut events = MachineServiceClient::new(channel)
        .events(req)
        .await
        .context("machined refused the event stream")?
        .into_inner();
    while let Some(event) = events.message().await.context("read an event")? {
        if let Some(seq) = ending(&event) {
            return Ok(seq);
        }
    }
    anyhow::bail!("machined closed the event stream")
}

pub fn spawn(socket: PathBuf, tx: Sender<String>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("shutdown".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "no runtime to watch for shutdown; the ring stays open to the end");
                    return;
                }
            };
            let mut warned = false;
            loop {
                match rt.block_on(wait(&socket)) {
                    Ok(seq) => {
                        tx.send(seq).ok();
                        return;
                    }
                    Err(e) if !warned => {
                        tracing::warn!(error = %format!("{e:#}"), "cannot watch machined for shutdown; retrying");
                        warned = true;
                    }
                    Err(_) => {}
                }
                std::thread::sleep(RETRY);
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::machine_service_server::{MachineService, MachineServiceServer};
    use std::sync::{Arc, Mutex};

    fn event(type_url: &str, sequence: &str, action: Action) -> pb::Event {
        pb::Event {
            data: Some(pb::Any {
                type_url: type_url.into(),
                value: pb::SequenceEvent {
                    sequence: sequence.into(),
                    action: action as i32,
                }
                .encode_to_vec(),
            }),
        }
    }

    fn seq(sequence: &str, action: Action) -> pb::Event {
        event("talos/runtime/machine.SequenceEvent", sequence, action)
    }

    #[test]
    fn ending_starts_only() {
        for s in ENDS_THE_BOOT {
            assert_eq!(ending(&seq(s, Action::Start)).as_deref(), Some(s));
            assert_eq!(ending(&seq(s, Action::Stop)), None, "{s}");
        }
        for s in ["boot", "initialize", "install", "noop"] {
            assert_eq!(ending(&seq(s, Action::Start)), None, "{s}");
        }
        assert_eq!(
            ending(&event(
                "talos/runtime/machine.PhaseEvent",
                "reboot",
                Action::Start
            )),
            None
        );
        assert_eq!(ending(&pb::Event { data: None }), None);
    }

    #[derive(Clone)]
    struct Machined {
        events: Vec<pb::Event>,
        roles: Arc<Mutex<Vec<Option<String>>>>,
    }

    #[tonic::async_trait]
    impl MachineService for Machined {
        type EventsStream =
            tokio_stream::Iter<std::vec::IntoIter<Result<pb::Event, tonic::Status>>>;

        async fn events(
            &self,
            req: tonic::Request<pb::EventsRequest>,
        ) -> Result<tonic::Response<Self::EventsStream>, tonic::Status> {
            let role = req
                .metadata()
                .get("talos-role")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            self.roles.lock().unwrap().push(role);
            let events: Vec<_> = self.events.iter().cloned().map(Ok).collect();
            Ok(tonic::Response::new(tokio_stream::iter(events)))
        }
    }

    fn socket_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("edge-scope-machined-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn serve(sock: &Path, events: Vec<pb::Event>) -> Machined {
        let m = Machined {
            events,
            roles: Arc::default(),
        };
        let listener = tokio::net::UnixListener::bind(sock).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(MachineServiceServer::new(m.clone()))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
        );
        m
    }

    #[tokio::test]
    async fn waits_past_boot_for_reboot() {
        let d = socket_dir("reboot");
        let sock = d.join("machine.sock");
        let m = serve(
            &sock,
            vec![
                seq("boot", Action::Start),
                seq("boot", Action::Stop),
                seq("reboot", Action::Start),
            ],
        )
        .await;
        assert_eq!(wait(&sock).await.unwrap(), "reboot");
        assert_eq!(*m.roles.lock().unwrap(), vec![Some("os:reader".into())]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn stream_end_and_absence_are_errors() {
        let d = socket_dir("end");
        let sock = d.join("machine.sock");
        serve(&sock, vec![seq("boot", Action::Start)]).await;
        let e = format!("{:#}", wait(&sock).await.unwrap_err());
        assert!(e.contains("closed the event stream"), "{e}");
        let e = format!("{:#}", wait(&d.join("absent.sock")).await.unwrap_err());
        assert!(e.contains("no machined socket"), "{e}");
        std::fs::remove_dir_all(&d).ok();
    }
}
