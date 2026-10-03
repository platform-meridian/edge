//! Liveness without a port: the main loop stamps the monotonic clock into a
//! file each time it gets round, and `edge-signer check` (the kubelet's exec
//! probe) fails once that stamp is older than [`STALE_AFTER`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};

pub const DIR: &str = "/run/edge-signer";
/// Six loop ticks, and twice the longest an apiserver call may take.
pub const STALE_AFTER: Duration = Duration::from_secs(30);

const FILE: &str = "heartbeat";

pub struct Heartbeat {
    path: PathBuf,
    tmp: PathBuf,
}

impl Heartbeat {
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(FILE),
            tmp: dir.join(format!("{FILE}.tmp")),
        }
    }

    /// Replaced by rename so `check` never reads a half-written stamp; tmpfs
    /// and liveness need no fsync.
    pub fn beat(&self) -> std::io::Result<()> {
        std::fs::write(&self.tmp, monotonic().as_millis().to_string())?;
        std::fs::rename(&self.tmp, &self.path)
    }
}

pub fn check(dir: &Path, now: Duration) -> anyhow::Result<()> {
    let path = dir.join(FILE);
    let stamp = std::fs::read_to_string(&path).with_context(|| format!("{}", path.display()))?;
    let stamp = Duration::from_millis(
        stamp
            .parse()
            .with_context(|| format!("{}: not a stamp", path.display()))?,
    );
    let age = now.saturating_sub(stamp);
    ensure!(
        age <= STALE_AFTER,
        "main loop stalled for {}s",
        age.as_secs()
    );
    Ok(())
}

/// Monotonic, not wall time: the signer runs across clock steps, and the
/// clock is shared by every process on the machine.
pub fn monotonic() -> Duration {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_or(Duration::ZERO, Duration::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_passes_stale_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::write(d.join(FILE), "5000").unwrap();
        let stamp = Duration::from_secs(5);
        assert!(check(d, stamp).is_ok());
        assert!(check(d, stamp - Duration::from_secs(1)).is_ok(), "ahead");
        assert!(check(d, stamp + STALE_AFTER).is_ok());
        let e = check(d, stamp + STALE_AFTER + Duration::from_millis(1)).unwrap_err();
        assert!(e.to_string().contains("stalled for 30s"), "{e}");
    }

    #[test]
    fn missing_or_garbled_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        assert!(check(d, monotonic()).is_err());
        std::fs::write(d.join(FILE), "").unwrap();
        assert!(check(d, monotonic()).is_err());
        std::fs::write(d.join(FILE), "soon").unwrap();
        assert!(check(d, monotonic()).is_err());
    }

    #[test]
    fn beat_advances_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let hb = Heartbeat::new(d);
        hb.beat().unwrap();
        let first = std::fs::read_to_string(d.join(FILE)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        hb.beat().unwrap();
        let second = std::fs::read_to_string(d.join(FILE)).unwrap();
        assert!(second.parse::<u64>().unwrap() > first.parse::<u64>().unwrap());
        assert!(check(d, monotonic()).is_ok());
        assert!(!d.join("heartbeat.tmp").exists());
    }
}
