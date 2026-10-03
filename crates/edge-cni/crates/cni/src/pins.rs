//! Pins outlive the daemon, so a restart adopts the running dataplane. A new object
//! takes each hook over from the previous version only once its own maps are programmed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use aya::maps::{Map, MapData};
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use edge_cni_common::{Affinity, AffinityKey, BackendVal, RevNat, RevNatKey, ServiceKey};

pub const OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/ebpf/bpfel-unknown-none/release/edge-cni-ebpf"
));

const PIN_BASE: &str = "/sys/fs/bpf/edge-cni";
const PROGRAMS: [&str; 3] = ["connect4", "sendmsg4", "recvmsg4"];

// A directory: bpffs refuses plain files.
pub(crate) const SYNCED: &str = "synced";

pub(crate) fn load(vdir: &str) -> anyhow::Result<aya::Ebpf> {
    std::fs::create_dir_all(format!("{vdir}/links"))?;
    Ok(aya::EbpfLoader::new()
        .default_map_pin_directory(vdir)
        .load(OBJECT)?)
}

pub(crate) fn load_socket_programs(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    for name in PROGRAMS {
        socket_program(bpf, name)?
            .load()
            .with_context(|| format!("load {name}"))?;
    }
    Ok(())
}

fn socket_program<'a>(
    bpf: &'a mut aya::Ebpf,
    name: &str,
) -> anyhow::Result<&'a mut CgroupSockAddr> {
    Ok(bpf
        .program_mut(name)
        .with_context(|| format!("no program {name} in the object"))?
        .try_into()?)
}

// Only once SERVICES and BACKENDS hold the full listing: an older version keeps
// serving until then.
pub fn take_over_sockets(bpf: &mut aya::Ebpf, vdir: &str, cgroup: &Path) -> anyhow::Result<()> {
    let vdir = Path::new(vdir);
    if PROGRAMS
        .iter()
        .any(|n| !vdir.join("links").join(n).exists())
    {
        // Host ports and node addresses cover the gap until they are next
        // programmed; stale ones are removed then.
        let carried = carry_over::<RevNatKey, RevNat>(vdir, "REVNAT")
            + carry_over::<AffinityKey, Affinity>(vdir, "AFFINITY")
            + carry_over::<ServiceKey, BackendVal>(vdir, "HOSTPORTS")
            + carry_over::<u32, u8>(vdir, "NODE_ADDRS");
        if carried > 0 {
            tracing::info!(
                carried,
                "carried reply translations, client affinity and host ports over"
            );
        }
    }
    let cgroup =
        std::fs::File::open(cgroup).with_context(|| format!("open cgroup {}", cgroup.display()))?;
    for name in PROGRAMS {
        let prog = socket_program(bpf, name)?;
        take_over(vdir, &format!("links/{name}"), |old| {
            let id = match old {
                Some(old) => prog.attach_to_link(CgroupSockAddrLink::try_from(old)?)?,
                // Link-based attach: programs coexist anyway, and ALLOW_MULTI is EINVAL.
                None => prog.attach(&cgroup, CgroupAttachMode::Single)?,
            };
            Ok(prog.take_link(id)?.try_into()?)
        })?;
    }
    Ok(())
}

// Another version's link is switched to our program in place, so the hook is never empty.
pub(crate) fn take_over(
    vdir: &Path,
    rel: &str,
    mut link: impl FnMut(Option<FdLink>) -> anyhow::Result<FdLink>,
) -> anyhow::Result<()> {
    let ours = vdir.join(rel);
    let theirs = inherited(vdir, rel);
    if !ours.exists() {
        let old = theirs.iter().find_map(|p| PinnedLink::from_pin(p).ok());
        let fd = match old.map(|old| link(Some(old.into()))) {
            Some(Ok(fd)) => {
                tracing::info!(hook = rel, "took the hook over in place");
                fd
            }
            Some(Err(e)) => {
                tracing::warn!(hook = rel, error = %format!("{e:#}"), "cannot switch the old link to the new program; attaching alongside it");
                link(None)?
            }
            None => link(None)?,
        };
        fd.pin(&ours)
            .with_context(|| format!("pin {}", ours.display()))?;
    }
    // A switched link is pinned twice now: dropping the old pin detaches nothing.
    for p in theirs {
        unpin_link(&p);
    }
    Ok(())
}

pub(crate) fn is_inherited(vdir: &Path, rel: &str) -> bool {
    !inherited(vdir, rel).is_empty()
}

fn inherited(vdir: &Path, rel: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = other_versions(vdir)
        .into_iter()
        .map(|v| v.join(rel))
        .filter(|p| p.exists())
        .collect();
    found.sort();
    found
}

fn other_versions(vdir: &Path) -> Vec<PathBuf> {
    let (Some(base), Some(ours)) = (vdir.parent(), vdir.file_name()) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_name() != ours)
        .map(|e| e.path())
        .collect()
}

pub(crate) fn carry_over<K: aya::Pod, V: aya::Pod>(vdir: &Path, name: &str) -> usize {
    fn open<K: aya::Pod, V: aya::Pod>(
        pin: &Path,
    ) -> anyhow::Result<aya::maps::HashMap<MapData, K, V>> {
        Ok(aya::maps::HashMap::try_from(Map::from_map_data(
            MapData::from_pin(pin)?,
        )?)?)
    }
    let Ok(mut ours) = open::<K, V>(&vdir.join(name)) else {
        return 0;
    };
    let mut carried = 0;
    for pin in inherited(vdir, name) {
        let Ok(theirs) = open::<K, V>(&pin) else {
            continue;
        };
        for (k, v) in theirs.iter().flatten() {
            carried += usize::from(ours.insert(&k, &v, 0).is_ok());
        }
    }
    carried
}

pub(crate) fn retire_old_versions(vdir: &Path, live: &HashSet<String>) -> usize {
    let mut retired = 0;
    for v in other_versions(vdir) {
        if !v.is_dir() {
            let _ = std::fs::remove_file(&v);
            continue;
        }
        let sockets = PROGRAMS.iter().any(|n| v.join("links").join(n).exists());
        let veths = std::fs::read_dir(v.join("np")).is_ok_and(|entries| {
            entries.flatten().any(|e| {
                live.contains(crate::netpol::pinned_veth(&e.file_name().to_string_lossy()))
            })
        });
        if !sockets && !veths {
            purge_version_dir(&v);
            retired += 1;
        }
    }
    retired
}

pub(crate) fn version_dir() -> String {
    format!("{PIN_BASE}/{}", fnv1a(OBJECT))
}

fn pin_base() -> String {
    std::env::var("EDGE_CNI_PIN_BASE").unwrap_or_else(|_| PIN_BASE.into())
}

/// This build's own: the probe of the daemon that is running.
pub fn synced() -> bool {
    synced_in(Path::new(&pin_base()))
}

fn synced_in(base: &Path) -> bool {
    base.join(fnv1a(OBJECT)).join(SYNCED).is_dir()
}

// So a new pod cannot dial a ClusterIP before connect4 can rewrite it. Any
// version counts: the plugin on disk may be another build.
pub fn wait_for_dataplane(limit: Duration) -> anyhow::Result<()> {
    wait_for_dataplane_in(Path::new(&pin_base()), limit)
}

fn wait_for_dataplane_in(base: &Path, limit: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        let ready = std::fs::read_dir(base)
            .is_ok_and(|entries| entries.flatten().any(|e| e.path().join(SYNCED).is_dir()));
        if ready {
            return Ok(());
        }
        if start.elapsed() >= limit {
            anyhow::bail!(
                "the edge-cni dataplane is not ready after {}s (no {}/*/{SYNCED}); is the edge-cni DaemonSet running?",
                limit.as_secs(),
                base.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HooksWait {
    Attached,
    NotEnforced,
    TimedOut,
}

pub fn wait_for_hooks(host_veth: &str, limit: Duration) -> HooksWait {
    wait_for_hooks_in(Path::new(&pin_base()), host_veth, limit)
}

fn wait_for_hooks_in(base: &Path, host_veth: &str, limit: Duration) -> HooksWait {
    let start = Instant::now();
    loop {
        let (mut enforced, mut attached) = (false, false);
        if let Ok(entries) = std::fs::read_dir(base) {
            for e in entries.flatten() {
                let np = e.path().join("np");
                if !np.is_dir() {
                    continue;
                }
                // Unsynced: a dead version's leftovers must not delay every pod.
                enforced |= e.path().join(SYNCED).is_dir();
                // Any version: mid-upgrade, the new one hooks new pods before it is synced.
                attached |= crate::netpol::hook_suffixes()
                    .iter()
                    .all(|s| np.join(format!("{host_veth}-{s}")).exists());
            }
        }
        if enforced && attached {
            return HooksWait::Attached;
        }
        if !enforced {
            return HooksWait::NotEnforced;
        }
        if start.elapsed() >= limit {
            return HooksWait::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn purge_version_dir(dir: &Path) {
    if let Ok(links) = std::fs::read_dir(dir.join("links")) {
        for l in links.flatten() {
            unpin_link(&l.path());
        }
    }
    crate::netpol::unpin_all(&dir.to_string_lossy());
    let _ = std::fs::remove_dir(dir.join(SYNCED));
    if let Ok(entries) = std::fs::read_dir(dir) {
        for m in entries.flatten() {
            let p = m.path();
            if p.is_dir() {
                let _ = std::fs::remove_dir(&p);
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let _ = std::fs::remove_dir(dir.join("links"));
    let _ = std::fs::remove_dir(dir);
}

// Unpinning a link's last pin detaches its program.
pub(crate) fn unpin_link(pin: &Path) {
    match PinnedLink::from_pin(pin) {
        Ok(pinned) => {
            let _ = pinned.unpin();
        }
        Err(_) => {
            let _ = std::fs::remove_file(pin);
        }
    }
}

fn fnv1a(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_removes_malformed_version_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("abcdef");
        std::fs::create_dir_all(d.join("links")).unwrap();
        std::fs::create_dir_all(d.join("np")).unwrap();
        std::fs::create_dir_all(d.join(SYNCED)).unwrap();
        for f in [
            "links/connect4",
            "links/recvmsg4",
            "np/edge1234-in",
            "SERVICES",
            "BACKENDS",
            "NP_PODS",
            "stray",
        ] {
            std::fs::write(d.join(f), b"not a bpf object").unwrap();
        }
        std::fs::create_dir_all(d.join("weird/sub")).unwrap();
        purge_version_dir(&d);
        for f in [
            "links", "np", SYNCED, "SERVICES", "BACKENDS", "NP_PODS", "stray",
        ] {
            assert!(!d.join(f).exists(), "{f}");
        }
    }

    #[test]
    fn synced_means_this_build() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        assert!(!synced_in(d));
        std::fs::create_dir_all(d.join("v1").join(SYNCED)).unwrap();
        assert!(!synced_in(d), "another build's");
        std::fs::create_dir_all(d.join(fnv1a(OBJECT))).unwrap();
        assert!(!synced_in(d), "loaded, not synced");
        std::fs::create_dir_all(d.join(fnv1a(OBJECT)).join(SYNCED)).unwrap();
        assert!(synced_in(d));
    }

    #[test]
    fn dataplane_wait_is_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let t = Instant::now();
        let e = wait_for_dataplane_in(d, Duration::from_millis(120)).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(format!("{e:#}").contains("not ready"), "{e:#}");
        std::fs::create_dir_all(d.join("v1").join(SYNCED)).unwrap();
        wait_for_dataplane_in(d, Duration::from_millis(120)).unwrap();
    }

    #[test]
    fn hooks_wait_for_own_veth() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let limit = Duration::from_secs(3);

        let t = Instant::now();
        assert_eq!(
            wait_for_hooks_in(d, "edgeaaaa", limit),
            HooksWait::NotEnforced
        );
        std::fs::create_dir_all(d.join("v0/np")).unwrap();
        assert_eq!(
            wait_for_hooks_in(d, "edgeaaaa", limit),
            HooksWait::NotEnforced,
            "a version without the sync marker is not trusted"
        );
        assert!(t.elapsed() < Duration::from_millis(500));

        std::fs::create_dir_all(d.join("v1/np")).unwrap();
        std::fs::create_dir_all(d.join("v1").join(SYNCED)).unwrap();
        let np = d.join("v1/np");
        let attach = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let [a, b] = crate::netpol::hook_suffixes();
            std::fs::write(np.join(format!("edgeaaaa-{a}")), b"").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            std::fs::write(np.join(format!("edgeaaaa-{b}")), b"").unwrap();
        });
        let t = Instant::now();
        assert_eq!(wait_for_hooks_in(d, "edgeaaaa", limit), HooksWait::Attached);
        assert!(
            t.elapsed() >= Duration::from_millis(350),
            "returned before both hooks: {:?}",
            t.elapsed()
        );
        assert!(t.elapsed() < Duration::from_secs(2));
        attach.join().unwrap();

        let t = Instant::now();
        assert_eq!(
            wait_for_hooks_in(d, "edgebbbb", Duration::from_millis(200)),
            HooksWait::TimedOut
        );
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn inherited_only_from_other_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        for pin in [
            "old/links/connect4",
            "new/links/connect4",
            "older/links/sendmsg4",
        ] {
            std::fs::create_dir_all(base.join(pin).parent().unwrap()).unwrap();
            std::fs::write(base.join(pin), b"").unwrap();
        }
        let new = base.join("new");
        assert_eq!(
            inherited(&new, "links/connect4"),
            [base.join("old/links/connect4")]
        );
        assert!(is_inherited(&new, "links/sendmsg4"));
        assert!(!is_inherited(&new, "links/recvmsg4"));
    }

    #[test]
    fn failed_attach_keeps_old_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("old/links")).unwrap();
        std::fs::create_dir_all(base.join("new/links")).unwrap();
        std::fs::write(base.join("old/links/connect4"), b"").unwrap();
        let mut calls = Vec::new();
        let r = take_over(&base.join("new"), "links/connect4", |old| {
            calls.push(old.is_some());
            anyhow::bail!("EPERM")
        });
        assert!(r.is_err());
        assert_eq!(calls, [false]);
        assert!(base.join("old/links/connect4").exists());
    }

    #[test]
    fn held_hook_drops_old_pins() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        for pin in ["old/np/edgea-in", "new/np/edgea-in"] {
            std::fs::create_dir_all(base.join(pin).parent().unwrap()).unwrap();
            std::fs::write(base.join(pin), b"").unwrap();
        }
        take_over(&base.join("new"), "np/edgea-in", |_| {
            panic!("a held hook is not attached again")
        })
        .unwrap();
        assert!(!base.join("old/np/edgea-in").exists());
        assert!(base.join("new/np/edgea-in").exists());
    }

    #[test]
    fn old_version_retired_when_idle() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        for pin in [
            "new/links/connect4",
            "old/links/connect4",
            "old/np/edgea-in",
            "dead/np/edgeb-in",
        ] {
            std::fs::create_dir_all(base.join(pin).parent().unwrap()).unwrap();
            std::fs::write(base.join(pin), b"").unwrap();
        }
        std::fs::write(base.join("stray"), b"").unwrap();
        let new = base.join("new");
        let live = HashSet::from(["edgea".to_string()]);

        assert_eq!(retire_old_versions(&new, &live), 1);
        assert!(!base.join("dead").exists() && !base.join("stray").exists());
        assert!(base.join("old").exists());

        std::fs::remove_file(base.join("old/links/connect4")).unwrap();
        assert_eq!(retire_old_versions(&new, &live), 0, "a live veth's hook");
        std::fs::remove_file(base.join("old/np/edgea-in")).unwrap();
        assert_eq!(retire_old_versions(&new, &live), 1);
        assert!(!base.join("old").exists());
        assert!(base.join("new/links/connect4").exists());
    }

    #[test]
    fn hooks_under_unsynced_version_count() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::create_dir_all(d.join("old/np")).unwrap();
        std::fs::create_dir_all(d.join("old").join(SYNCED)).unwrap();
        std::fs::create_dir_all(d.join("new/np")).unwrap();
        for s in crate::netpol::hook_suffixes() {
            std::fs::write(d.join(format!("new/np/edgeaaaa-{s}")), b"").unwrap();
        }
        let t = Instant::now();
        assert_eq!(
            wait_for_hooks_in(d, "edgeaaaa", Duration::from_secs(3)),
            HooksWait::Attached
        );
        assert!(t.elapsed() < Duration::from_secs(1));
    }
}
