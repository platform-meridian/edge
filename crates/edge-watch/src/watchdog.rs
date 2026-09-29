//! The hardware watchdog. Any byte written is a keepalive; stop writing and
//! the machine resets `timeout` seconds after the last one.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::Context;

// linux/watchdog.h. SETTIMEOUT writes the request; GETTIMEOUT reads the grant.
nix::ioctl_readwrite!(wdioc_settimeout, b'W', 6, nix::libc::c_int);
nix::ioctl_read!(wdioc_gettimeout, b'W', 7, nix::libc::c_int);

pub struct Watchdog {
    dev: File,
    /// What the driver granted: it may round, clamp or ignore the request.
    pub timeout_secs: u32,
    disarmed: bool,
}

impl Watchdog {
    /// Open and arm: the timer runs from here, including through a panic.
    pub fn open(path: &Path, want_secs: u32) -> anyhow::Result<Self> {
        let dev = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;

        let mut secs = want_secs as nix::libc::c_int;
        // Some drivers have no SETTIMEOUT and run a fixed timeout.
        // SAFETY: `dev` is an open watchdog device and both pointers are to live
        // c_ints for the duration of the ioctls.
        unsafe {
            if let Err(e) = wdioc_settimeout(dev.as_raw_fd(), &mut secs) {
                tracing::warn!(error = %e, want_secs, "driver refused SETTIMEOUT; using its default");
            }
            let mut got: nix::libc::c_int = 0;
            if wdioc_gettimeout(dev.as_raw_fd(), &mut got).is_ok() && got > 0 {
                secs = got;
            }
        }

        let timeout_secs = secs.max(1) as u32;
        if timeout_secs != want_secs {
            tracing::warn!(
                want_secs,
                granted = timeout_secs,
                "watchdog timeout differs from the request"
            );
        }
        tracing::info!(device = %path.display(), timeout_secs, "watchdog armed");
        Ok(Self {
            dev,
            timeout_secs,
            disarmed: false,
        })
    }

    /// A write, not WDIOC_KEEPALIVE: every driver implements the write.
    pub fn pet(&mut self) -> anyhow::Result<()> {
        self.dev.write_all(b"\0").context("write keepalive")?;
        self.dev.flush().context("flush keepalive")
    }

    /// The magic close: `V` right before close disarms even a `nowayout=1`
    /// driver. No Drop impl: a watchdog dropped by a panic must still fire.
    pub fn disarm(&mut self) -> anyhow::Result<()> {
        self.dev.write_all(b"V").context("write magic close")?;
        self.dev.flush().context("flush magic close")?;
        self.disarmed = true;
        tracing::warn!("watchdog disarmed");
        Ok(())
    }
}

/// The device's sysfs directory, symlinks resolved, so a stable link to the
/// device and Landlock (which checks the resolved path) both work.
pub fn sys_dir(dev: &Path) -> Option<PathBuf> {
    sys_dir_in(Path::new("/sys/class/watchdog"), dev)
}

fn sys_dir_in(class: &Path, dev: &Path) -> Option<PathBuf> {
    let name = std::fs::canonicalize(dev).ok()?.file_name()?.to_owned();
    std::fs::canonicalize(class.join(name)).ok()
}

/// The driver's `bootstatus`. A hint only: iTCO always reports 0, so the
/// ladder counts the persisted intent instead.
pub fn boot_status(sys_dir: &Path) -> Option<u32> {
    std::fs::read_to_string(sys_dir.join("bootstatus"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub struct Backoff {
    next: std::time::Duration,
    cap: std::time::Duration,
}

impl Backoff {
    pub fn new(base: std::time::Duration, cap: std::time::Duration) -> Self {
        Self { next: base, cap }
    }

    pub fn next_delay(&mut self) -> std::time::Duration {
        let d = self.next.min(self.cap);
        self.next = (self.next * 2).min(self.cap);
        d
    }
}

pub fn effective_interval(cfg_interval_secs: u64, granted_timeout_secs: u32) -> u64 {
    let ceiling = (granted_timeout_secs as u64 / 2).max(1);
    let eff = cfg_interval_secs.min(ceiling).max(1);
    if eff != cfg_interval_secs {
        tracing::warn!(
            configured = cfg_interval_secs,
            granted_timeout_secs,
            using = eff,
            "driver granted a shorter timeout; probing more often"
        );
    }
    eff
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn backoff_doubles_to_cap() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let got: Vec<u64> = (0..8).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn missing_device_errors() {
        let e = Watchdog::open(Path::new("/nonexistent/watchdog0"), 30)
            .err()
            .expect("must fail");
        assert!(format!("{e:#}").contains("/nonexistent/watchdog0"));
    }

    #[test]
    fn pet_and_disarm_bytes() {
        // A plain file fails the ioctls, like a fixed-timeout driver.
        let p = std::env::temp_dir().join(format!("edge-watch-fakedev-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        let mut wd = Watchdog::open(&p, 30).unwrap();
        assert_eq!(wd.timeout_secs, 30);
        wd.pet().unwrap();
        wd.disarm().unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"\0V");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sys_dir_follows_links() {
        let d = std::env::temp_dir().join(format!("edge-watch-class-{}", std::process::id()));
        let (dev, class, real) = (d.join("dev"), d.join("class"), d.join("devices/wd1"));
        for p in [&dev, &class, &real] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(dev.join("watchdog1"), b"").unwrap();
        std::os::unix::fs::symlink(dev.join("watchdog1"), dev.join("watchdog-board")).unwrap();
        std::os::unix::fs::symlink(&real, class.join("watchdog1")).unwrap();
        let want = std::fs::canonicalize(&real).unwrap();
        assert_eq!(
            sys_dir_in(&class, &dev.join("watchdog1")),
            Some(want.clone())
        );
        assert_eq!(sys_dir_in(&class, &dev.join("watchdog-board")), Some(want));
        assert_eq!(sys_dir_in(&class, &dev.join("absent")), None);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn boot_status_reads_flags() {
        let d = std::env::temp_dir().join(format!("edge-watch-sys-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(boot_status(&d), None);
        std::fs::write(d.join("bootstatus"), "32\n").unwrap();
        assert_eq!(boot_status(&d), Some(32));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn short_grant_lowers_interval() {
        assert_eq!(effective_interval(10, 60), 10, "plenty of room: unchanged");
        assert_eq!(effective_interval(10, 20), 10, "exactly 2x: unchanged");
        assert_eq!(effective_interval(10, 12), 6);
        assert_eq!(
            effective_interval(10, 1),
            1,
            "never zero, which would panic the ticker"
        );
    }
}
