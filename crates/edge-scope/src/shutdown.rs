//! machined's event stream: its service state changes are recorded, and the
//! sequence ending the boot is the cue to stop. Talos unmounts volumes before it
//! stops extension services, so a ring still open then keeps the evidence volume
//! busy and the reboot falls back to a forced one.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::Context;
use edge_scope::services::{self, Transition};
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
    let s = pb::SequenceEvent::decode(payload(event, "machine.SequenceEvent")?).ok()?;
    (s.action() == Action::Start && ENDS_THE_BOOT.contains(&s.sequence.as_str()))
        .then_some(s.sequence)
}

fn payload<'a>(event: &'a pb::Event, name: &str) -> Option<&'a [u8]> {
    let data = event.data.as_ref()?;
    (data.type_url.rsplit('/').next() == Some(name)).then_some(data.value.as_slice())
}

/// The seconds an xid starts with: its first 32 of 96 bits, base32hex.
fn xid_secs(id: &str) -> Option<u64> {
    if id.len() != 20 {
        return None;
    }
    let bits = id.bytes().take(7).try_fold(0u64, |acc, c| {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            _ => return None,
        };
        Some(acc << 5 | u64::from(v))
    })?;
    Some(bits >> 3)
}

fn state_name(action: i32) -> String {
    let Ok(a) = pb::service_state_event::Action::try_from(action) else {
        return "Unknown".into();
    };
    let upper = a.as_str_name();
    upper[..1].to_string() + &upper[1..].to_ascii_lowercase()
}

pub fn transition(event: &pb::Event, now: u64) -> Option<Transition> {
    let s = pb::ServiceStateEvent::decode(payload(event, "machine.ServiceStateEvent")?).ok()?;
    Some(Transition {
        t: xid_secs(&event.id).unwrap_or(now),
        id: event.id.clone(),
        state: state_name(s.action),
        healthy: s.health.filter(|h| !h.unknown).map(|h| h.healthy),
        svc: s.service,
        msg: s.message,
        ..Default::default()
    })
}

fn wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub async fn wait(socket: &Path, services: &mut services::Store) -> anyhow::Result<String> {
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
    let mut req = tonic::Request::new(pb::EventsRequest { tail_events: -1 });
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
        if let Some(t) = transition(&event, wall()) {
            services.record(t);
        }
        if let Some(seq) = ending(&event) {
            return Ok(seq);
        }
    }
    anyhow::bail!("machined closed the event stream")
}

pub fn spawn(
    socket: PathBuf,
    mut services: services::Store,
    tx: Sender<String>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("shutdown".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "no runtime to watch machined; the ring stays open to the end");
                    return;
                }
            };
            let mut warned = false;
            loop {
                match rt.block_on(wait(&socket, &mut services)) {
                    Ok(seq) => {
                        drop(services);
                        tx.send(seq).ok();
                        return;
                    }
                    Err(e) if !warned => {
                        tracing::warn!(error = %format!("{e:#}"), "cannot watch machined; retrying");
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
    use pb::service_state_event::Action as State;
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
            id: String::new(),
        }
    }

    fn seq(sequence: &str, action: Action) -> pb::Event {
        event("talos/runtime/machine.SequenceEvent", sequence, action)
    }

    fn svc(id: &str, service: &str, state: State, health: Option<bool>, msg: &str) -> pb::Event {
        pb::Event {
            data: Some(pb::Any {
                type_url: "talos/runtime/machine.ServiceStateEvent".into(),
                value: pb::ServiceStateEvent {
                    service: service.into(),
                    action: state as i32,
                    message: msg.into(),
                    health: Some(pb::ServiceHealth {
                        unknown: health.is_none(),
                        healthy: health.unwrap_or(false),
                    }),
                }
                .encode_to_vec(),
            }),
            id: id.into(),
        }
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
        assert_eq!(
            ending(&pb::Event {
                data: None,
                id: String::new()
            }),
            None
        );
    }

    #[test]
    fn xid_time() {
        assert_eq!(xid_secs("9m4e2mr0ui3e8a215n4g"), Some(1_300_816_219));
        assert_eq!(xid_secs("00000000000000000000"), Some(0));
        for bad in [
            "",
            "9m4e2mr0ui3e8a215n4",
            "9M4E2MR0UI3E8A215N4G",
            "9m4e2mr0ui3e8a215n4gx",
        ] {
            assert_eq!(xid_secs(bad), None, "{bad}");
        }
    }

    #[test]
    fn service_events_become_transitions() {
        let t = transition(
            &svc(
                "9m4e2mr0ui3e8a215n4g",
                "etcd",
                State::Running,
                Some(false),
                "Health check failed: x",
            ),
            7,
        )
        .unwrap();
        assert_eq!(
            t,
            Transition {
                t: 1_300_816_219,
                id: "9m4e2mr0ui3e8a215n4g".into(),
                svc: "etcd".into(),
                state: "Running".into(),
                healthy: Some(false),
                msg: "Health check failed: x".into(),
                ..Default::default()
            }
        );
        let t = transition(&svc("odd", "cri", State::Initialized, None, ""), 7).unwrap();
        assert_eq!((t.t, t.state.as_str(), t.healthy), (7, "Initialized", None));
        let mut future = svc("", "cri", State::Starting, None, "");
        future.data.as_mut().unwrap().value = pb::ServiceStateEvent {
            action: 99,
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(transition(&future, 0).unwrap().state, "Unknown");
        for (a, name) in [(State::Starting, "Starting"), (State::Failed, "Failed")] {
            assert_eq!(
                transition(&svc("", "x", a, None, ""), 0).unwrap().state,
                name
            );
        }
        assert_eq!(transition(&seq("reboot", Action::Start), 0), None);
    }

    /// The role and `tail_events` of one subscription.
    type Asked = (Option<String>, i32);

    #[derive(Clone)]
    struct Machined {
        events: Vec<pb::Event>,
        requests: Arc<Mutex<Vec<Asked>>>,
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
            self.requests
                .lock()
                .unwrap()
                .push((role, req.get_ref().tail_events));
            let events: Vec<_> = self.events.iter().cloned().map(Ok).collect();
            Ok(tonic::Response::new(tokio_stream::iter(events)))
        }
    }

    async fn serve(sock: &Path, events: Vec<pb::Event>) -> Machined {
        let m = Machined {
            events,
            requests: Arc::default(),
        };
        let listener = tokio::net::UnixListener::bind(sock).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(MachineServiceServer::new(m.clone()))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
        );
        m
    }

    fn store(d: &Path) -> services::Store {
        services::Store::new(d.join(services::FILE), "b".into())
    }

    #[tokio::test]
    async fn waits_past_boot_for_reboot() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
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
        assert_eq!(wait(&sock, &mut store(d)).await.unwrap(), "reboot");
        assert_eq!(
            *m.requests.lock().unwrap(),
            vec![(Some("os:reader".into()), -1)]
        );
    }

    #[tokio::test]
    async fn service_states_recorded_once_from_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let sock = d.join("machine.sock");
        let backlog = vec![
            svc("1", "etcd", State::Preparing, None, "Running pre state"),
            seq("boot", Action::Start),
            svc("2", "etcd", State::Running, None, "Process started"),
            svc("3", "kubelet", State::Waiting, None, "Waiting for etcd"),
            svc(
                "4",
                "etcd",
                State::Running,
                Some(true),
                "Health check successful",
            ),
        ];
        serve(&sock, backlog).await;
        let mut s = store(d);
        for _ in 0..2 {
            assert!(wait(&sock, &mut s).await.is_err(), "the stream ends");
        }
        drop(s);
        assert!(wait(&sock, &mut store(d)).await.is_err());
        let all = services::read(&d.join(services::FILE)).unwrap();
        let got: Vec<_> = all
            .iter()
            .map(|t| (t.id.as_str(), t.svc.as_str(), t.state.as_str(), t.healthy))
            .collect();
        assert_eq!(
            got,
            [
                ("1", "etcd", "Preparing", None),
                ("2", "etcd", "Running", None),
                ("3", "kubelet", "Waiting", None),
                ("4", "etcd", "Running", Some(true)),
            ]
        );
        assert!(all.iter().all(|t| t.boot == "b"));
        assert!(
            all.iter().all(|t| t.t > 1_700_000_000),
            "an id that is no xid is timed by the clock"
        );
        let now = services::latest(&all, "b");
        assert_eq!(now["etcd"].msg, "Health check successful");
        assert_eq!(now["kubelet"].state, "Waiting");
    }

    #[test]
    fn ending_releases_services_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let sock = d.join("machine.sock");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(serve(
            &sock,
            vec![
                svc("1", "etcd", State::Running, None, ""),
                seq("shutdown", Action::Start),
            ],
        ));
        let (tx, rx) = std::sync::mpsc::channel();
        spawn(sock, store(d), tx).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(20)).unwrap(),
            "shutdown"
        );
        let ring = d.join(services::FILE);
        let mut writer = edge_scope::ring::Ring::open_with(&ring, 4, services::RECORD_SIZE)
            .expect("the ring is no longer held");
        writer.append(b"{}").unwrap();
    }

    #[tokio::test]
    async fn stream_end_and_absence_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let sock = d.join("machine.sock");
        serve(&sock, vec![seq("boot", Action::Start)]).await;
        let e = format!("{:#}", wait(&sock, &mut store(d)).await.unwrap_err());
        assert!(e.contains("closed the event stream"), "{e}");
        let e = format!(
            "{:#}",
            wait(&d.join("absent.sock"), &mut store(d))
                .await
                .unwrap_err()
        );
        assert!(e.contains("no machined socket"), "{e}");
    }
}
