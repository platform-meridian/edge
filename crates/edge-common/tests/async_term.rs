// Its own binary: tokio's signal driver and `install()` each own the SIGTERM
// disposition, so the two must not share a process.

use std::time::Duration;

use edge_common::{Terminator, terminated};
use tokio::sync::Mutex;

// Signals are process-wide: these tests must not overlap.
static SERIAL: Mutex<()> = Mutex::const_new(());

fn kill_self_after(d: Duration) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(d);
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
            .unwrap();
    })
}

#[tokio::test]
async fn terminated_waits_for_sigterm() {
    let _g = SERIAL.lock().await;
    let t = kill_self_after(Duration::from_millis(300));
    let start = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(3), terminated())
        .await
        .expect("terminated() must resolve on SIGTERM");
    assert!(start.elapsed() >= Duration::from_millis(250));
    t.join().unwrap();
}

fn sigterm_self() {
    nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM).unwrap();
}

#[tokio::test]
async fn terminator_keeps_early_signal() {
    let _g = SERIAL.lock().await;
    let mut term = Terminator::new();
    sigterm_self();
    tokio::time::timeout(Duration::from_secs(3), term.wait())
        .await
        .expect("the early signal must be kept");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), term.wait())
            .await
            .is_err(),
        "nothing pending: wait must block"
    );
    sigterm_self();
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::timeout(Duration::from_secs(3), term.wait())
        .await
        .expect("the signal between waits must be kept");
}
