use edge_state::store::Store;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

/// A forked child shares a held flock until it execs, so spawning and locking tests
/// must not overlap.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn run(sub: &[&str], log: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_edge-state"))
        .args(sub)
        .env("EDGE_STATE_LOG", log)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

#[test]
fn offline_never_creates_log() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let dir_inside = dir.path().join("not-yet");
    let log = dir_inside.join("state.log");
    for sub in [&["history"][..], &["diff", "1", "1"][..]] {
        let out = run(sub, &log);
        assert!(!out.status.success(), "{sub:?} on a missing log must fail");
        assert!(!log.exists(), "{sub:?} created the log");
        assert!(!dir_inside.exists(), "{sub:?} created the data directory");
    }
}

#[test]
fn offline_leaves_log_unchanged() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("state.log");
    {
        let mut s = Store::open(&log).unwrap();
        s.put(b"/registry/pods/ns/a", b"1", 0).unwrap();
        s.put(b"/registry/pods/ns/b", b"22", 0).unwrap();
    }
    {
        let (mut lg, _) = edge_state::log::Log::open(&log).unwrap();
        lg.append(&[222, 1, 2], true).unwrap();
    }
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 2, 3, 4, 5]).unwrap();
    }
    let before = std::fs::read(&log).unwrap();

    let out = run(&["history"], &log);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("2 change(s)"), "{stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 record(s) in the log could not be decoded"),
        "{stderr}"
    );
    let out = run(&["diff", "1", "3"], &log);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&log).unwrap(),
        before,
        "an offline command modified the log"
    );
}

#[test]
fn diff_below_floor_is_refused() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("state.log");
    {
        let mut s = Store::open(&log).unwrap();
        s.put(b"/registry/pods/ns/a", b"1", 0).unwrap();
        s.put(b"/registry/pods/ns/a", b"22", 0).unwrap();
        let r = s.revision();
        s.compact(r).unwrap();
    }
    let out = run(&["diff", "1", "3"], &log);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("compaction floor"));
}
