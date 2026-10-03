use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod pb {
    tonic::include_proto!("machine");
}

use pb::machine_service_server::{MachineService, MachineServiceServer};
use pb::{ResetRequest, ResetResponse};

#[derive(Clone, Default)]
struct Machined {
    resets: Arc<Mutex<Vec<ResetRequest>>>,
}

#[tonic::async_trait]
impl MachineService for Machined {
    async fn reset(
        &self,
        req: tonic::Request<ResetRequest>,
    ) -> Result<tonic::Response<ResetResponse>, tonic::Status> {
        self.resets.lock().unwrap().push(req.into_inner());
        Ok(tonic::Response::new(ResetResponse::default()))
    }
}

struct Unit {
    dir: tempfile::TempDir,
    machined: Machined,
}

impl Unit {
    async fn new(name: &str, check_addr: &str, record: &str) -> Self {
        Self::with_recovery(name, check_addr, record, 2).await
    }

    async fn with_recovery(name: &str, check_addr: &str, record: &str, recovery_secs: u64) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("edge-watch-ladder-{name}-"))
            .tempdir()
            .unwrap();
        let dir = tmp.path();
        for d in ["cfg", "state", "machined"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(
            dir.join("cfg/10-test.yaml"),
            format!(
                "interval_secs: 1\ntimeout_secs: 2\nstartup_grace_secs: 0\nrecovery_secs: {recovery_secs}\n\
                 checks: [ {{ name: probe, kind: tcp, addr: '{check_addr}', grace_secs: 1 }} ]\n"
            ),
        )
        .unwrap();
        std::fs::write(dir.join("state/state.json"), record).unwrap();
        std::fs::write(dir.join("watchdog"), b"").unwrap();
        let machined = Machined::default();
        let listener = tokio::net::UnixListener::bind(dir.join("machined/machine.sock")).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(MachineServiceServer::new(machined.clone()))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
        );
        Self { dir: tmp, machined }
    }

    fn start(&self) -> Child {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_edge-watch"));
        // SAFETY: prctl is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL);
                Ok(())
            });
        }
        cmd.env("EDGE_WATCH_CONFIG", self.dir.path().join("cfg"))
            .env("EDGE_WATCH_DEVICE", self.dir.path().join("watchdog"))
            .env("EDGE_WATCH_STATE", self.dir.path().join("state"))
            .env(
                "EDGE_WATCH_MACHINED",
                self.dir.path().join("machined/machine.sock"),
            )
            .env_remove("EDGE_EVIDENCE")
            .spawn()
            .unwrap()
    }

    fn record(&self) -> serde_json::Value {
        let text = std::fs::read_to_string(self.dir.path().join("state/state.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn watchdog_bytes(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("watchdog")).unwrap()
    }

    fn resets(&self) -> usize {
        self.machined.resets.lock().unwrap().len()
    }
}

async fn until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < limit, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn stop(mut child: Child) {
    // SAFETY: signalling our own child.
    unsafe { nix::libc::kill(child.id() as i32, nix::libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
}

fn closed_port() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn tripped_boot_repairs() {
    let u = Unit::new("repair", &closed_port(), r#"{"consecutive_resets": 3}"#).await;
    let child = u.start();
    until("the reset request", Duration::from_secs(15), || {
        u.resets() == 1
    })
    .await;
    let req = u.machined.resets.lock().unwrap()[0].clone();
    assert_eq!(req.system_partitions_to_wipe[0].label, "EPHEMERAL");
    let rec = u.record();
    assert_eq!(
        (
            &rec["repairs"],
            &rec["consecutive_resets"],
            &rec["last_failure"]
        ),
        (&1.into(), &0.into(), &serde_json::json!(["probe"]))
    );
    let at = rec["last_repair_at"].as_str().unwrap();
    assert!(
        at.strip_prefix("epoch:")
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|s| s > 1_700_000_000),
        "{at}"
    );
    assert!(
        rec["healthy_since"].is_null(),
        "a failing check is not health"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(u.resets(), 1, "one repair per rung");
    stop(child);
    assert!(
        !u.watchdog_bytes().contains(&b'V'),
        "SIGTERM mid-repair must leave the watchdog armed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exhausted_stays_disarmed() {
    let u = Unit::new(
        "exhausted",
        &closed_port(),
        r#"{"consecutive_resets": 3, "repairs": 1}"#,
    )
    .await;
    let child = u.start();
    until("the exhausted mark", Duration::from_secs(10), || {
        u.record()["exhausted"] == true
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(u.resets(), 0);
    assert!(u.watchdog_bytes().is_empty(), "never armed, never petted");
    assert!(
        u.record()["healthy_since"].is_null(),
        "a failing check is not health"
    );
    stop(child);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_clears_and_arms() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move { while l.accept().await.is_ok() {} });
    let u = Unit::new(
        "recover",
        &addr,
        r#"{"consecutive_resets": 3, "repairs": 1, "exhausted": true}"#,
    )
    .await;
    let child = u.start();
    until("pets after recovery", Duration::from_secs(15), || {
        !u.watchdog_bytes().is_empty()
    })
    .await;
    let rec = u.record();
    assert_eq!(
        (
            &rec["consecutive_resets"],
            &rec["repairs"],
            &rec["exhausted"]
        ),
        (&0.into(), &0.into(), &false.into())
    );
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    assert_eq!(rec["healthy_since"]["boot_id"], boot_id.trim());
    let uptime: f64 = std::fs::read_to_string("/proc/uptime")
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let since = rec["healthy_since"]["boottime_secs"].as_u64().unwrap() as f64;
    assert!(
        since <= uptime && uptime - since < 30.0,
        "since {since}, uptime {uptime}"
    );
    stop(child);
    assert_eq!(
        u.watchdog_bytes().last(),
        Some(&b'V'),
        "an orderly stop disarms"
    );
    assert_eq!(u.resets(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn armed_ladder_clears_after_sustained_health() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move { while l.accept().await.is_ok() {} });
    let u = Unit::with_recovery("sustained", &addr, r#"{"consecutive_resets": 2}"#, 4).await;
    let child = u.start();
    until("pets", Duration::from_secs(10), || {
        !u.watchdog_bytes().is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        u.record()["consecutive_resets"],
        2,
        "one healthy round is not recovery"
    );
    until("the ladder cleared", Duration::from_secs(10), || {
        u.record()["consecutive_resets"] == 0
    })
    .await;
    stop(child);
}
