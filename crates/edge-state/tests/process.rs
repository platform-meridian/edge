mod common;

use common::{Rng, apply, dump, script};
use edge_state::entry::Entry;
use edge_state::log::{self, Log};
use edge_state::pb::etcdserverpb::{RangeRequest, kv_client::KvClient};
use edge_state::store::Store;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// A forked child shares a held flock until it execs, so tests here run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn build(path: &Path, seed: u64, n: usize) -> Vec<(u64, common::Dump)> {
    let mut s = Store::open(path).unwrap();
    let mut cps = vec![(0, dump(&s))];
    for op in script(seed, n) {
        let before = s.log_len();
        apply(&mut s, &op);
        if s.log_len() > before {
            cps.push((s.log_len(), dump(&s)));
        }
    }
    cps
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(log: &Path) -> (Child, u16) {
    let port = free_port();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_edge-state"))
        .env("EDGE_STATE_LOG", log)
        .env("EDGE_STATE_LISTEN", format!("127.0.0.1:{port}"))
        .env_remove("RUST_LOG")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    (Child(child), port)
}

async fn assert_serves(log: &Path, what: &str) {
    let (mut child, port) = spawn(log);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut kv = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("{what}: the process EXITED ({status}) instead of serving");
        }
        if let Ok(c) = KvClient::connect(format!("http://127.0.0.1:{port}")).await {
            break c;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: never started serving"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    kv.range(RangeRequest {
        key: b"/".to_vec(),
        range_end: b"0".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|e| panic!("{what}: serving but Range failed: {e}"));
    kv.put(edge_state::pb::etcdserverpb::PutRequest {
        key: b"/proof".to_vec(),
        value: b"1".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|e| panic!("{what}: could not write: {e}"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn serves_from_damaged_disks() {
    let _serial = serial();
    let _one = ONE_AT_A_TIME.lock().await;
    let mut rng = Rng(4242);
    let make = || {
        let d = tmp();
        let p = d.path().join("state.log");
        (d, p)
    };

    let (d, p) = make();
    let cps = build(&p, 31, 40);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[cps[cps.len() / 2].0 as usize + 10] ^= 0xff;
    std::fs::write(&p, bytes).unwrap();
    assert_serves(&p, "mid-file corruption").await;
    drop(d);

    let (d, p) = make();
    build(&p, 32, 20);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[9] ^= 0xff;
    std::fs::write(&p, bytes).unwrap();
    assert_serves(&p, "corrupted first record").await;
    drop(d);

    let (d, p) = make();
    std::fs::write(&p, (0..3000).map(|_| rng.next() as u8).collect::<Vec<_>>()).unwrap();
    assert_serves(&p, "random garbage").await;
    drop(d);

    let (d, p) = make();
    std::fs::write(&p, b"").unwrap();
    assert_serves(&p, "an empty file").await;
    drop(d);

    let (d, p) = make();
    build(&p, 33, 20);
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .unwrap()
        .write_all(&[0u8; 4096])
        .unwrap();
    assert_serves(&p, "a zero-filled tail").await;
    drop(d);

    let (d, p) = make();
    {
        let (mut lg, _) = Log::open(&p).unwrap();
        lg.append(
            &Entry::Put {
                revision: 2,
                key: b"/a".to_vec(),
                value: b"1".to_vec(),
                lease: 0,
            }
            .encode(),
            true,
        )
        .unwrap();
        lg.append(&[250, 3, 0, 0, 0, 0, 0, 0, 0, 9, 9], true)
            .unwrap();
    }
    assert_serves(&p, "a newer build's records").await;
    drop(d);

    let (d, p) = make();
    build(&p, 34, 10);
    std::fs::write(log::rotation_temp_path(&p), b"half").unwrap();
    assert_serves(&p, "a leftover rotation temp").await;
    drop(d);

    let (d, p) = make();
    std::fs::create_dir(&p).unwrap();
    assert_serves(&p, "a directory where the log belongs").await;
    drop(d);

    let d = tmp();
    assert_serves(
        &d.path().join("no/such/dir/state.log"),
        "a missing data directory",
    )
    .await;
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn waits_for_held_lock() {
    let _serial = serial();
    let _one = ONE_AT_A_TIME.lock().await;
    let d = tmp();
    let p = d.path().join("state.log");
    let holder = Store::open(&p).unwrap();
    let (mut child, port) = spawn(&p);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process exited instead of waiting for the lock"
    );
    assert!(
        KvClient::connect(format!("http://127.0.0.1:{port}"))
            .await
            .is_err(),
        "it must not serve while another instance holds the log"
    );
    drop(holder);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Ok(mut c) = KvClient::connect(format!("http://127.0.0.1:{port}")).await
            && c.range(RangeRequest {
                key: b"/".to_vec(),
                ..Default::default()
            })
            .await
            .is_ok()
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never took over");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[test]
fn damaged_history_warns() {
    let _serial = serial();
    let _one = ONE_AT_A_TIME.blocking_lock();
    let d = tmp();
    let p = d.path().join("state.log");
    {
        let mut s = Store::open(&p).unwrap();
        for i in 0..6 {
            s.put(format!("/registry/pods/ns/p{i}").as_bytes(), b"x", 0)
                .unwrap();
        }
    }
    let third = 3 * (std::fs::metadata(&p).unwrap().len() as usize / 6);
    common::fill_past_a_batch(&p);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[third + 12] ^= 0xff;
    std::fs::write(&p, &bytes).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_edge-state"))
        .arg("history")
        .env("EDGE_STATE_LOG", &p)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("WARNING: the log is damaged"));
    assert_eq!(
        std::fs::read(&p).unwrap(),
        bytes,
        "a read-only command must not repair the log"
    );
}

#[test]
fn torn_tail_reported_when_present() {
    let _serial = serial();
    let d = tmp();
    let p = d.path().join("state.log");
    {
        let mut s = Store::open(&p).unwrap();
        s.put(b"/k", b"v", 0).unwrap();
    }
    let reported = || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_edge-state"))
            .arg("history")
            .env("EDGE_STATE_LOG", &p)
            .env_remove("RUST_LOG")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let all = [out.stdout, out.stderr].concat();
        String::from_utf8_lossy(&all).contains("cut unsynced writes")
    };
    assert!(!reported(), "a clean log reported a torn tail");
    let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
    std::io::Write::write_all(&mut f, &[9, 0, 0]).unwrap();
    assert!(reported(), "a torn tail was not reported");
}
