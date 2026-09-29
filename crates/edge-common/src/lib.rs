//! Each daemon is PID 1 of its container, where the kernel applies no default
//! signal action: without a handler SIGTERM is ignored.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

mod durable;
mod logging;
pub mod mount;
mod outage;
pub mod sandbox;
mod supervise;
pub mod watch_state;

pub use durable::{TMP_SUFFIX, durable_write, durable_write_with, set_aside};
pub use logging::init_tracing;
pub use outage::Outage;
pub use supervise::forever;

static REQUESTED: AtomicBool = AtomicBool::new(false);

// Self-pipe: a signal landing between the flag check and poll(2) stays in it.
static WAKE_W: AtomicI32 = AtomicI32::new(-1);
static WAKE_R: AtomicI32 = AtomicI32::new(-1);
static PIPE: OnceLock<(OwnedFd, OwnedFd)> = OnceLock::new();

extern "C" fn on_signal(_: nix::libc::c_int) {
    // Async-signal-safe only; errno is restored for the interrupted code.
    let saved = nix::errno::Errno::last_raw();
    REQUESTED.store(true, Ordering::SeqCst);
    let fd = WAKE_W.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = 1u8;
        // EAGAIN on a full pipe is fine: a wakeup is already pending.
        unsafe { nix::libc::write(fd, (&b as *const u8).cast(), 1) };
    }
    nix::errno::Errno::set_raw(saved);
}

fn make_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as nix::libc::c_int; 2];
    // SAFETY: fds is a valid 2-element array.
    if unsafe {
        nix::libc::pipe2(
            fds.as_mut_ptr(),
            nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 just returned these, and nothing else owns them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Use this or [`Terminator`], not both: the later installer owns the disposition.
pub fn install() -> nix::Result<()> {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
    if PIPE.get().is_none()
        && let Ok(p) = make_pipe()
        && PIPE.set(p).is_ok()
        && let Some((r, w)) = PIPE.get()
    {
        WAKE_R.store(r.as_raw_fd(), Ordering::SeqCst);
        WAKE_W.store(w.as_raw_fd(), Ordering::SeqCst);
    }
    let action = SigAction::new(
        SigHandler::Handler(on_signal),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    for sig in [Signal::SIGTERM, Signal::SIGINT] {
        // SAFETY: the handler only touches atomics and calls write(2), both async-signal-safe.
        unsafe { sigaction(sig, &action)? };
    }
    Ok(())
}

pub fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// Returns `true` once termination is requested.
pub fn sleep(total: Duration) -> bool {
    let until = Instant::now() + total;
    loop {
        if requested() {
            return true;
        }
        let now = Instant::now();
        if now >= until {
            return false;
        }
        let fd = WAKE_R.load(Ordering::SeqCst);
        if fd < 0 {
            std::thread::sleep(until - now);
            continue;
        }
        // Round UP so a sub-millisecond remainder does not spin.
        let ms = (until - now)
            .as_micros()
            .div_ceil(1000)
            .min(i32::MAX as u128) as nix::libc::c_int;
        let mut p = nix::libc::pollfd {
            fd,
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd. EINTR loops to re-check the flag.
        unsafe { nix::libc::poll(&mut p, 1, ms) };
    }
}

/// Registers eagerly, so a signal landing before or between waits is kept.
/// Must be created inside a tokio runtime.
pub struct Terminator {
    sigs: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
}

impl Terminator {
    pub fn new() -> Self {
        use tokio::signal::unix::{SignalKind, signal};
        let sigs = match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(t), Ok(i)) => Some((t, i)),
            _ => None,
        };
        Self { sigs }
    }

    pub async fn wait(&mut self) {
        let Some((term, int)) = self.sigs.as_mut() else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
}

impl Default for Terminator {
    fn default() -> Self {
        Self::new()
    }
}

/// Never resolves if the handlers cannot be installed: a daemon that must be
/// killed beats one that exits at startup.
pub async fn terminated() {
    Terminator::new().wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Signals are process-wide: these tests must not overlap.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn switches() -> u64 {
        std::fs::read_to_string("/proc/thread-self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("voluntary_ctxt_switches:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[test]
    fn sigterm_wakes_sleep() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        install().unwrap();
        REQUESTED.store(false, Ordering::SeqCst);
        let signalled = std::sync::Arc::new(Mutex::new(None::<Instant>));
        let s2 = signalled.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            *s2.lock().unwrap() = Some(Instant::now());
            nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
                .unwrap();
        });
        assert!(sleep(Duration::from_secs(30)));
        let woke = Instant::now();
        t.join().unwrap();
        let lag = woke.duration_since(signalled.lock().unwrap().unwrap());
        assert!(
            lag < Duration::from_millis(50),
            "woke {lag:?} after the signal"
        );
        assert!(requested());
    }

    #[test]
    fn idle_sleep_blocks() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        install().unwrap();
        REQUESTED.store(false, Ordering::SeqCst);
        let (start, before) = (Instant::now(), switches());
        assert!(!sleep(Duration::from_secs(1)));
        let n = switches() - before;
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert!(n <= 3, "{n} wakeups during a 1s sleep");
    }
}
