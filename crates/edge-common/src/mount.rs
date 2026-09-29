//! The evidence volume can be mounted after a daemon starts, which would misread the
//! empty directory underneath as a first boot.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub const EVIDENCE_ENV: &str = "EDGE_EVIDENCE";

const EVIDENCE_PATIENCE: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(250);

pub fn is_mount_point(dir: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(dir) else {
        return false;
    };
    let parent = dir.join("..");
    match std::fs::metadata(&parent) {
        Ok(p) => p.dev() != meta.dev() || p.ino() == meta.ino(),
        Err(_) => false,
    }
}

pub fn await_mount(dir: &Path, patience: Duration) -> bool {
    let until = Instant::now() + patience;
    loop {
        if is_mount_point(dir) {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

pub fn await_evidence_volume() {
    let Some(dir) = std::env::var_os(EVIDENCE_ENV) else {
        return;
    };
    let dir = Path::new(&dir);
    if await_mount(dir, EVIDENCE_PATIENCE) {
        tracing::info!(volume = %dir.display(), "evidence volume mounted");
    } else {
        tracing::error!(
            volume = %dir.display(), waited = ?EVIDENCE_PATIENCE,
            "evidence volume not mounted; using the directory underneath, which an EPHEMERAL wipe loses"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("edge-mount-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn mount_points_detected() {
        let d = scratch("detect");
        assert!(is_mount_point(Path::new("/proc")));
        assert!(is_mount_point(Path::new("/")));
        assert!(!is_mount_point(&d));
        assert!(!is_mount_point(&d.join("absent")));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn plain_dir_waits_out_patience() {
        let d = scratch("patience");
        let t = Instant::now();
        assert!(!await_mount(&d, Duration::from_millis(600)));
        assert!(t.elapsed() >= Duration::from_millis(600));
        let t = Instant::now();
        assert!(await_mount(Path::new("/proc"), Duration::from_secs(30)));
        assert!(t.elapsed() < Duration::from_secs(1));
        std::fs::remove_dir_all(&d).ok();
    }
}
