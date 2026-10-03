//! A `cpu.max` quota, not `cgroup.freeze`: both targets are liveness-probed and
//! a frozen process fails its probe. A restarted static pod gets a new cgroup,
//! so it is looked up afresh each time.

use std::path::{Path, PathBuf};

/// TASK_COMM_LEN is 16 including the NUL.
const COMM_MAX: usize = 15;

pub fn comm_for(name: &str) -> &str {
    &name[..name.len().min(COMM_MAX)]
}

/// `comm`, not `cmdline`, so a flag containing the name cannot match.
pub fn pids_named(proc_dir: &Path, name: &str) -> Vec<u32> {
    let want = comm_for(name);
    let Ok(rd) = std::fs::read_dir(proc_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(comm) = std::fs::read_to_string(e.path().join("comm"))
            && comm.trim() == want
        {
            out.push(pid);
        }
    }
    out.sort_unstable();
    out
}

/// `/proc/<pid>/cgroup` is relative to the reader's cgroup namespace, whose root
/// a container cannot name, so the host hierarchy is searched for the pid.
pub fn cgroup_dir_for(proc_dir: &Path, cgroup_root: &Path, name: &str) -> Option<PathBuf> {
    let pid = pids_named(proc_dir, name).into_iter().next()?;
    cgroup_listing(cgroup_root, pid)
}

fn cgroup_listing(dir: &Path, pid: u32) -> Option<PathBuf> {
    let procs = std::fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
    if procs.lines().any(|l| l.parse() == Ok(pid)) {
        return Some(dir.to_path_buf());
    }
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .find_map(|e| cgroup_listing(&e.path(), pid))
}

/// The smallest quota cgroup v2 accepts (`min_cfs_quota_period`, 1ms): 1% of
/// a core at the default period.
const IDLE_QUOTA_US: u32 = 1_000;
const PERIOD_US: u32 = 100_000;

pub fn quota_for(throttled: bool) -> String {
    if throttled {
        format!("{IDLE_QUOTA_US} {PERIOD_US}")
    } else {
        format!("max {PERIOD_US}")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Owner {
    Unlimited,
    Ours,
    Foreign,
    Unknown,
}

pub fn owner_of(cgroup_dir: &Path) -> Owner {
    let Ok(text) = std::fs::read_to_string(cgroup_dir.join("cpu.max")) else {
        return Owner::Unknown;
    };
    let text = text.trim();
    if text == quota_for(true) {
        Owner::Ours
    } else if text.starts_with("max") {
        Owner::Unlimited
    } else {
        Owner::Foreign
    }
}

pub fn set_throttled(cgroup_dir: &Path, throttled: bool) -> anyhow::Result<bool> {
    let owner = owner_of(cgroup_dir);
    let act = matches!(
        (throttled, &owner),
        (true, Owner::Unlimited) | (false, Owner::Ours)
    );
    if !act {
        if owner == Owner::Foreign {
            tracing::debug!(
                cgroup = %cgroup_dir.display(),
                "a CPU limit is already set by something else; leaving it alone"
            );
        }
        return Ok(false);
    }
    let f = cgroup_dir.join("cpu.max");
    std::fs::write(&f, quota_for(throttled))
        .map_err(|e| anyhow::anyhow!("write {}: {e}", f.display()))?;
    Ok(true)
}

pub fn is_throttled(cgroup_dir: &Path) -> bool {
    owner_of(cgroup_dir) == Owner::Ours
}

pub fn clear_stale_freeze(cgroup_dir: &Path) -> Option<anyhow::Result<()>> {
    let f = cgroup_dir.join("cgroup.freeze");
    let frozen = std::fs::read_to_string(&f).ok()?.trim() == "1";
    frozen
        .then(|| std::fs::write(&f, "0").map_err(|e| anyhow::anyhow!("write {}: {e}", f.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A /proc with the two targets (the controller-manager's comm truncated
    /// as the kernel writes it), an unrelated process and a non-pid entry.
    fn fixture() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for (pid, comm, cg) in [
            (100, "kube-scheduler", "kubepods/burstable/podAAA/sched"),
            (200, "kube-controller", "kubepods/burstable/podBBB/kcm"),
            (300, "apps", "kubepods/besteffort/podCCC/app"),
            (400, "kube-scheduler", "kubepods/burstable/podDDD/second"),
        ] {
            let p = d.join("proc").join(pid.to_string());
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("comm"), format!("{comm}\n")).unwrap();
            let c = d.join("cg").join(cg);
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        }
        std::fs::create_dir_all(d.join("proc/self")).unwrap();
        std::fs::write(d.join("proc/self/comm"), "kube-scheduler\n").unwrap();
        tmp
    }

    #[test]
    fn finds_pids_by_truncated_comm() {
        let tmp = fixture();
        let d = tmp.path();
        let proc_dir = d.join("proc");
        assert_eq!(comm_for("kube-controller-manager"), "kube-controller");
        assert_eq!(comm_for("kube-scheduler"), "kube-scheduler");
        assert_eq!(pids_named(&proc_dir, "kube-scheduler"), [100, 400]);
        assert_eq!(pids_named(&proc_dir, "kube-controller-manager"), [200]);
        assert!(pids_named(&proc_dir, "kube").is_empty());
        assert!(pids_named(&d.join("no-proc"), "kube-scheduler").is_empty());

        let cg = d.join("cg");
        assert_eq!(
            cgroup_dir_for(&proc_dir, &cg, "kube-scheduler").unwrap(),
            cg.join("kubepods/burstable/podAAA/sched"),
            "the lowest pid, under the given root"
        );
        assert_eq!(
            cgroup_dir_for(&proc_dir, &cg, "kube-controller-manager").unwrap(),
            cg.join("kubepods/burstable/podBBB/kcm")
        );
        assert!(cgroup_dir_for(&proc_dir, &cg, "not-running").is_none());
    }

    #[test]
    fn finds_cgroup_by_pid() {
        let tmp = fixture();
        let d = tmp.path();
        let proc_dir = d.join("proc");
        let cg = d.join("cg");
        let sched = cg.join("kubepods/burstable/podAAA/sched");
        std::fs::write(cg.join("cgroup.procs"), "1\n1000\n").unwrap();
        std::fs::write(
            cg.join("kubepods/besteffort/podCCC/app/cgroup.procs"),
            "10\n",
        )
        .unwrap();
        std::fs::write(sched.join("cgroup.procs"), "99\n100\n").unwrap();
        assert_eq!(
            cgroup_dir_for(&proc_dir, &cg, "kube-scheduler").unwrap(),
            sched
        );
        std::fs::remove_file(sched.join("cgroup.procs")).unwrap();
        assert!(cgroup_dir_for(&proc_dir, &cg, "kube-scheduler").is_none());
    }

    #[test]
    fn set_throttled_only_touches_own() {
        let tmp = fixture();
        let d = tmp.path();
        let cg = d.join("cg/kubepods/burstable/podAAA/sched");
        let cpu_max = cg.join("cpu.max");
        let read = || std::fs::read_to_string(&cpu_max).unwrap();

        assert_eq!(owner_of(&cg), Owner::Unknown);
        assert!(!set_throttled(&cg, true).unwrap());
        assert!(!cpu_max.exists());

        std::fs::write(&cpu_max, "max 100000\n").unwrap();
        assert_eq!(owner_of(&cg), Owner::Unlimited);
        assert!(!set_throttled(&cg, false).unwrap());
        assert!(set_throttled(&cg, true).unwrap());
        assert_eq!(read(), "1000 100000");
        assert!(is_throttled(&cg));
        assert!(!set_throttled(&cg, true).unwrap());
        assert!(set_throttled(&cg, false).unwrap());
        assert_eq!(read(), "max 100000");
        assert!(!is_throttled(&cg));

        std::fs::write(&cpu_max, "50000 100000\n").unwrap();
        assert_eq!(owner_of(&cg), Owner::Foreign);
        assert!(!is_throttled(&cg));
        assert!(!set_throttled(&cg, true).unwrap());
        assert!(!set_throttled(&cg, false).unwrap());
        assert_eq!(read(), "50000 100000\n");
    }

    #[test]
    fn failed_write_errors() {
        let tmp = fixture();
        let d = tmp.path();
        let cg = d.join("cg/kubepods/burstable/podAAA/sched");
        std::fs::write(cg.join("cpu.max"), "max 100000\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cg.join("cpu.max"), std::fs::Permissions::from_mode(0o444))
            .unwrap();
        if unsafe { nix::libc::geteuid() } != 0 {
            assert!(set_throttled(&cg, true).is_err());
        }
    }

    #[test]
    fn stale_freeze_thawed() {
        let tmp = fixture();
        let d = tmp.path();
        let cg = d.join("cg/kubepods/burstable/podAAA/sched");
        let freeze = cg.join("cgroup.freeze");
        assert!(clear_stale_freeze(&cg).is_none(), "no freezer file");
        std::fs::write(&freeze, "0\n").unwrap();
        assert!(clear_stale_freeze(&cg).is_none());
        assert_eq!(std::fs::read_to_string(&freeze).unwrap(), "0\n");
        std::fs::write(&freeze, "1\n").unwrap();
        assert!(clear_stale_freeze(&cg).unwrap().is_ok());
        assert_eq!(std::fs::read_to_string(&freeze).unwrap(), "0");
    }
}
