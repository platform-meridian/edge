//! Landlock, best effort by kernel ABI. restrict_self covers only the calling
//! thread and those it creates later, so [`restrict`] runs before any thread starts.

use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, LandlockStatus, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus,
};

const ABI_KNOWN: ABI = ABI::V9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Device,
    Socket,
}

#[derive(Debug, Default)]
pub struct Rules {
    pub paths: Vec<(PathBuf, Access)>,
    pub bind_tcp: Option<Vec<u16>>,
    pub connect_tcp: Option<Vec<u16>>,
}

impl Rules {
    fn with(mut self, access: Access, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.paths
            .extend(paths.into_iter().map(|p| (p.into(), access)));
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Full,
    Partial,
    Unrestricted,
}

pub fn restrict(rules: &Rules) -> Outcome {
    restrict_at(rules, ABI_KNOWN)
}

fn restrict_at(rules: &Rules, abi: ABI) -> Outcome {
    if let Some(n) = threads().filter(|&n| n > 1) {
        tracing::warn!(
            threads = n,
            "landlock: restricting after threads were started; those stay unrestricted"
        );
    }
    let status = match build(rules, abi).and_then(RulesetCreated::restrict_self) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "landlock: not enforced; running unrestricted");
            return Outcome::Unrestricted;
        }
    };
    let outcome = match status.ruleset {
        RulesetStatus::FullyEnforced => Outcome::Full,
        RulesetStatus::PartiallyEnforced => Outcome::Partial,
        RulesetStatus::NotEnforced => Outcome::Unrestricted,
    };
    match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => tracing::info!(
            abi = effective_abi as i32,
            enforced = ?outcome,
            bind_tcp = ?rules.bind_tcp,
            connect_tcp = ?rules.connect_tcp,
            "landlock"
        ),
        other => tracing::warn!(
            kernel = ?other,
            "landlock: not supported by this kernel; running unrestricted"
        ),
    }
    outcome
}

fn build(rules: &Rules, abi: ABI) -> Result<RulesetCreated, RulesetError> {
    let handled = AccessFs::from_all(abi);
    let mut rs = Ruleset::default().handle_access(handled)?;
    if rules.bind_tcp.is_some() {
        rs = rs.handle_access(AccessNet::BindTcp)?;
    }
    if rules.connect_tcp.is_some() {
        rs = rs.handle_access(AccessNet::ConnectTcp)?;
    }
    let mut rs = rs.create()?;
    for (path, access) in &rules.paths {
        if *access == Access::Write
            && let Err(e) = std::fs::create_dir_all(path)
        {
            tracing::warn!(path = %path.display(), error = %e, "landlock: cannot create a writable directory");
        }
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(_) => {
                tracing::warn!(path = %path.display(), ?access, "landlock: path missing; not granted");
                continue;
            }
        };
        let mut allowed = rights(*access, abi) & handled;
        if !path.is_dir() {
            allowed &= AccessFs::from_file(abi);
        }
        if !allowed.is_empty() {
            rs = rs.add_rule(PathBeneath::new(fd, allowed))?;
        }
    }
    for (ports, access) in [
        (&rules.bind_tcp, AccessNet::BindTcp),
        (&rules.connect_tcp, AccessNet::ConnectTcp),
    ] {
        for &p in ports.iter().flatten() {
            rs = rs.add_rule(NetPort::new(p, access))?;
        }
    }
    Ok(rs)
}

fn rights(access: Access, abi: ABI) -> BitFlags<AccessFs> {
    match access {
        Access::Read => AccessFs::ReadFile | AccessFs::ReadDir,
        Access::Write => AccessFs::from_all(abi) & !AccessFs::Execute,
        Access::Device => {
            AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::WriteFile | AccessFs::IoctlDev
        }
        Access::Socket => AccessFs::ResolveUnix.into(),
    }
}

fn threads() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))?
        .trim()
        .parse()
        .ok()
}

fn port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}

/// A mounted ConfigMap or Secret swaps its files by symlink, so the stable
/// grant is the directory holding them.
fn dir_of(file: &Path) -> PathBuf {
    match file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

fn kube(rules: Rules) -> (Rules, Option<u16>) {
    let port = std::env::var("KUBERNETES_SERVICE_PORT")
        .ok()
        .and_then(|p| p.parse().ok());
    let rules = rules.with(
        Access::Read,
        [SERVICE_ACCOUNT, "/etc/resolv.conf", "/etc/hosts"],
    );
    (rules, port)
}

/// Backends come from HTTPRoutes, so connect stays open.
pub fn gateway(config: &Path, tls: &[&Path], listen: &str) -> Rules {
    let (rules, _) = kube(Rules::default());
    Rules {
        bind_tcp: port(listen).map(|p| vec![p]),
        ..rules.with(
            Access::Read,
            std::iter::once(config)
                .chain(tls.iter().copied())
                .map(dir_of),
        )
    }
}

pub fn dns(bind: &str) -> Rules {
    let (rules, api) = kube(Rules::default());
    Rules {
        bind_tcp: port(bind).map(|p| vec![p]),
        connect_tcp: api.map(|api| vec![53, api]),
        ..rules
    }
}

pub fn state(log: &Path, tls: &[&Path], listen: &str) -> Rules {
    Rules {
        bind_tcp: port(listen).map(|p| vec![p]),
        connect_tcp: Some(vec![]),
        ..Rules::default()
            .with(Access::Write, [dir_of(log)])
            .with(Access::Read, tls.iter().copied().map(dir_of))
    }
}

pub struct Watch<'a> {
    pub config_dir: &'a Path,
    pub device: &'a Path,
    /// The device's resolved sysfs directory: Landlock checks the path a
    /// symlink resolves to, not `/sys/class/watchdog`.
    pub sys: Option<&'a Path>,
    pub state: &'a Path,
    pub machined_socket: &'a Path,
}

/// Probe addresses come from the config, so connect stays open.
pub fn watch(w: Watch) -> Rules {
    Rules {
        bind_tcp: Some(vec![]),
        ..Rules::default()
            .with(
                Access::Read,
                std::iter::once(w.config_dir.to_path_buf()).chain(w.sys.map(Path::to_path_buf)),
            )
            .with(Access::Device, [w.device])
            .with(Access::Write, [w.state])
            .with(Access::Socket, [dir_of(w.machined_socket)])
    }
}

pub struct Scope<'a> {
    pub ring: &'a Path,
    pub time_file: &'a Path,
    pub proc_dir: &'a Path,
    pub sys_dir: &'a Path,
    pub dev_dir: &'a Path,
    pub watch_state: &'a Path,
    pub cri_socket: &'a Path,
    pub machined_socket: &'a Path,
}

/// NTP and the log sink are UDP, which Landlock cannot restrict.
pub fn scope(s: Scope) -> Rules {
    Rules {
        bind_tcp: Some(vec![]),
        connect_tcp: Some(vec![]),
        ..Rules::default()
            .with(Access::Write, [dir_of(s.ring), dir_of(s.time_file)])
            .with(Access::Read, [s.proc_dir, s.sys_dir, s.watch_state])
            .with(Access::Device, [s.dev_dir])
            .with(
                Access::Socket,
                [dir_of(s.cri_socket), dir_of(s.machined_socket)],
            )
    }
}

pub fn idle(proc_dir: &Path, cgroup_root: &Path, health: &str) -> Rules {
    let (rules, api) = kube(Rules::default());
    Rules {
        bind_tcp: Some(port(health).into_iter().collect()),
        connect_tcp: api.map(|api| vec![api]),
        ..rules
            .with(Access::Read, [proc_dir])
            .with(Access::Write, [cgroup_root])
    }
}

pub fn signer(health: &str) -> Rules {
    let (rules, api) = kube(Rules::default());
    Rules {
        bind_tcp: Some(port(health).into_iter().collect()),
        connect_tcp: api.map(|api| vec![api]),
        ..rules
    }
}

/// The parents, not the directories: containerd may not have created its root
/// yet, and creating it here would race it.
pub fn layers(root: &Path, state: &Path, image_caches: &Path) -> Rules {
    Rules {
        bind_tcp: Some(vec![]),
        connect_tcp: Some(vec![]),
        ..Rules::default()
            .with(Access::Write, [dir_of(root), dir_of(state)])
            .with(Access::Read, [image_caches])
    }
}

/// Writes the store only to remove what fails its digest.
pub fn registry(root: &Path, port: u16, upstream_port: u16) -> Rules {
    Rules {
        bind_tcp: Some(vec![port]),
        connect_tcp: Some(vec![upstream_port]),
        ..Rules::default().with(Access::Write, [root])
    }
}

/// DHCP and DNS are UDP, which Landlock cannot restrict. The lease file is
/// replaced by rename, so the grant is its directory.
pub fn dhcp(lease_file: Option<&Path>) -> Rules {
    Rules {
        bind_tcp: Some(vec![]),
        connect_tcp: Some(vec![]),
        ..Rules::default().with(Access::Write, lease_file.map(dir_of))
    }
}

/// aya reads BTF and CPU topology from /sys and /proc.
pub fn cni_daemon(bpffs: &Path, cni_bin: &Path, cni_conf: &Path) -> Rules {
    let (rules, api) = kube(Rules::default());
    Rules {
        bind_tcp: Some(vec![]),
        connect_tcp: api.map(|api| vec![api]),
        ..rules
            .with(Access::Read, ["/sys", "/proc"])
            .with(Access::Read, std::env::current_exe().ok())
            .with(Access::Write, [bpffs, cni_bin, cni_conf])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use nix::libc;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, fork, pipe};

    const SKIP: i32 = 77;

    type Check = Result<(), String>;

    /// restrict_self is irreversible and must never reach the test harness.
    fn in_child(f: impl FnOnce() -> Result<bool, String>) {
        let (r, w) = pipe().unwrap();
        // SAFETY: the child only runs `f` and exits; it never returns into the harness.
        match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                drop(r);
                let code = match catch_unwind(AssertUnwindSafe(f)) {
                    Ok(Ok(true)) => 0,
                    Ok(Ok(false)) => SKIP,
                    Ok(Err(msg)) => {
                        let _ = std::fs::File::from(w).write_all(msg.as_bytes());
                        1
                    }
                    Err(p) => {
                        let msg = p
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                            .unwrap_or_default();
                        let _ =
                            std::fs::File::from(w).write_all(format!("panic: {msg}").as_bytes());
                        1
                    }
                };
                unsafe { libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                drop(w);
                let mut msg = String::new();
                std::fs::File::from(r).read_to_string(&mut msg).unwrap();
                match waitpid(child, None).unwrap() {
                    WaitStatus::Exited(_, 0) => {}
                    WaitStatus::Exited(_, SKIP) => {
                        eprintln!("skipped: this kernel has no Landlock")
                    }
                    other => panic!("{other:?}: {msg}"),
                }
            }
        }
    }

    fn sandboxed(rules: impl FnOnce() -> Rules, check: impl FnOnce() -> Check) {
        in_child(|| {
            if restrict(&rules()) == Outcome::Unrestricted {
                return no_landlock();
            }
            check().map(|()| true)
        });
    }

    fn no_landlock() -> Result<bool, String> {
        match kernel_abi() {
            abi if abi < 1 => Ok(false),
            abi => Err(format!("unrestricted on a kernel with Landlock ABI {abi}")),
        }
    }

    fn allowed<T>(what: &str, r: io::Result<T>) -> Check {
        r.map(drop).map_err(|e| format!("{what}: {e}"))
    }

    fn denied<T>(what: &str, r: io::Result<T>) -> Check {
        match r {
            Err(e) if e.raw_os_error() == Some(libc::EACCES) => Ok(()),
            Err(e) => Err(format!("{what}: failed with {e}, not EACCES")),
            Ok(_) => Err(format!("{what}: allowed")),
        }
    }

    fn read(p: impl AsRef<Path>) -> io::Result<()> {
        let p = p.as_ref();
        if p.is_dir() {
            std::fs::read_dir(p).map(drop)
        } else {
            std::fs::read(p).map(drop)
        }
    }

    fn write_in(dir: impl AsRef<Path>) -> io::Result<()> {
        let (a, b) = (dir.as_ref().join("probe.tmp"), dir.as_ref().join("probe"));
        std::fs::write(&a, b"x")?;
        std::fs::File::open(dir.as_ref())?.sync_all()?;
        std::fs::rename(&a, &b)?;
        std::fs::remove_file(&b)
    }

    fn bind(port: u16) -> io::Result<TcpListener> {
        TcpListener::bind(("127.0.0.1", port))
    }

    fn dial(port: u16) -> io::Result<TcpStream> {
        TcpStream::connect(("127.0.0.1", port))
    }

    fn free_port() -> u16 {
        bind(0).unwrap().local_addr().unwrap().port()
    }

    fn listening() -> (TcpListener, u16) {
        let l = bind(0).unwrap();
        let p = l.local_addr().unwrap().port();
        (l, p)
    }

    fn outside(d: &Path) -> PathBuf {
        let f = d.join("outside/secret");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"s").unwrap();
        read(&f).unwrap();
        f
    }

    fn set_api_port(port: u16) {
        // SAFETY: called in the single-threaded forked child.
        unsafe { std::env::set_var("KUBERNETES_SERVICE_PORT", port.to_string()) };
    }

    fn kernel_abi() -> i64 {
        // SAFETY: the version query takes no pointers.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                1u32,
            )
        }
    }

    /// Kubernetes' layout: files are symlinks through `..data`, which is swapped.
    fn projected(dir: &Path, generation: &str, file: &str, body: &str) {
        let real = dir.join(generation);
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join(file), body).unwrap();
        let tmp = dir.join("..data_tmp");
        std::os::unix::fs::symlink(generation, &tmp).unwrap();
        std::fs::rename(&tmp, dir.join("..data")).unwrap();
        let link = dir.join(file);
        if link.symlink_metadata().is_err() {
            std::os::unix::fs::symlink(format!("..data/{file}"), link).unwrap();
        }
    }

    #[test]
    fn gateway_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        std::fs::create_dir_all(d.join("config")).unwrap();
        let config = d.join("config/edge-gateway.yaml");
        std::fs::write(&config, "listen: x\n").unwrap();
        projected(&d.join("tls"), "..v1", "tls.crt", "one");
        let (cert, key) = (d.join("tls/tls.crt"), d.join("tls/tls.key"));
        let (listen, other) = (free_port(), free_port());
        let (_backend, backend) = listening();

        // The kubelet, outside the sandbox, rotates the secret once the child is restricted.
        let (ready_r, ready_w) = pipe().unwrap();
        let (done_r, done_w) = pipe().unwrap();
        let tls = d.join("tls");
        let rotator = std::thread::spawn(move || {
            let mut b = [0u8];
            if std::fs::File::from(ready_r).read_exact(&mut b).is_ok() {
                projected(&tls, "..v2", "tls.crt", "two");
                std::fs::File::from(done_w).write_all(b"k").unwrap();
            }
        });

        sandboxed(
            || gateway(&config, &[&cert, &key], &format!("0.0.0.0:{listen}")),
            || {
                allowed("read the config", read(&config))?;
                allowed("read the cert", read(&cert))?;
                std::fs::File::from(ready_w).write_all(b"r").unwrap();
                std::fs::File::from(done_r).read_exact(&mut [0u8]).unwrap();
                let rotated =
                    std::fs::read_to_string(&cert).map_err(|e| format!("rotated cert: {e}"))?;
                if rotated != "two" {
                    return Err(format!("read {rotated:?} after rotation"));
                }
                denied("write beside the config", write_in(d.join("config")))?;
                denied("read outside", read(&secret))?;
                allowed("bind the listen port", bind(listen))?;
                denied("bind another port", bind(other))?;
                allowed("dial a backend", dial(backend))
            },
        );
        rotator.join().unwrap();
    }

    #[test]
    fn dns_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        let (listen, other) = (free_port(), free_port());
        let (_api, api) = listening();
        let (_x, unlisted) = listening();
        sandboxed(
            || {
                set_api_port(api);
                dns(&format!("0.0.0.0:{listen}"))
            },
            || {
                if Path::new("/etc/resolv.conf").exists() {
                    allowed("read resolv.conf", read("/etc/resolv.conf"))?;
                }
                denied("read outside", read(&secret))?;
                allowed("bind the DNS port", bind(listen))?;
                denied("bind another port", bind(other))?;
                allowed("dial the apiserver", dial(api))?;
                denied("dial another port", dial(unlisted))
            },
        );
    }

    #[test]
    fn state_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        // Missing: the Write grant creates it.
        let log = d.join("data/state.log");
        std::fs::create_dir_all(d.join("pki")).unwrap();
        std::fs::write(d.join("pki/server.crt"), b"c").unwrap();
        let (cert, key) = (d.join("pki/server.crt"), d.join("pki/server.key"));
        let (listen, other) = (free_port(), free_port());
        let (_peer, peer) = listening();
        sandboxed(
            || state(&log, &[&cert, &key], &format!("0.0.0.0:{listen}")),
            || {
                allowed("durable write beside the log", write_in(d.join("data")))?;
                allowed("read the cert", read(&cert))?;
                denied("write beside the cert", write_in(d.join("pki")))?;
                denied("read outside", read(&secret))?;
                allowed("bind the client port", bind(listen))?;
                denied("bind another port", bind(other))?;
                denied("dial anything", dial(peer))
            },
        );
    }

    #[test]
    fn watch_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        std::fs::create_dir_all(d.join("dev")).unwrap();
        let config = d.join("cfg/config.yaml");
        std::fs::write(&config, "checks: []\n").unwrap();
        let (dev, other_dev) = (d.join("dev/watchdog0"), d.join("dev/nvme0"));
        std::fs::write(&dev, b"").unwrap();
        std::fs::write(&other_dev, b"").unwrap();
        let (real, other) = (d.join("sys/devices/wd0"), d.join("sys/devices/other"));
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(real.join("bootstatus"), "0\n").unwrap();
        std::fs::write(other.join("bootstatus"), "0\n").unwrap();
        std::fs::create_dir_all(d.join("sys/class")).unwrap();
        std::os::unix::fs::symlink(&real, d.join("sys/class/watchdog0")).unwrap();
        let sys = std::fs::canonicalize(&real).unwrap();
        std::fs::create_dir_all(d.join("machined")).unwrap();
        std::fs::create_dir_all(d.join("elsewhere")).unwrap();
        let _machined = UnixListener::bind(d.join("machined/machine.sock")).unwrap();
        let _other = UnixListener::bind(d.join("elsewhere/x.sock")).unwrap();
        let (_probe, probe) = listening();
        let open_rw = |p: &Path| std::fs::OpenOptions::new().write(true).open(p);
        let port = free_port();
        sandboxed(
            || {
                watch(Watch {
                    config_dir: &d.join("cfg"),
                    device: &dev,
                    sys: Some(&sys),
                    state: &d.join("state"),
                    machined_socket: &d.join("machined/machine.sock"),
                })
            },
            || {
                allowed(
                    "reach machined",
                    UnixStream::connect(d.join("machined/machine.sock")),
                )?;
                if kernel_abi() >= 9 {
                    denied(
                        "reach another socket",
                        UnixStream::connect(d.join("elsewhere/x.sock")),
                    )?;
                }
                allowed("read the config", read(&config))?;
                allowed(
                    "read bootstatus through the class link",
                    read(d.join("sys/class/watchdog0/bootstatus")),
                )?;
                denied(
                    "read another device's sysfs",
                    read(other.join("bootstatus")),
                )?;
                allowed("open the watchdog", open_rw(&dev))?;
                denied("open another device", open_rw(&other_dev))?;
                allowed("durable write of the state", write_in(d.join("state")))?;
                denied("read outside", read(&secret))?;
                denied("bind", bind(port))?;
                allowed("probe a local port", dial(probe))
            },
        );
    }

    #[test]
    fn scope_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        for s in ["dev", "watch", "run", "machined", "elsewhere"] {
            std::fs::create_dir_all(d.join(s)).unwrap();
        }
        std::fs::write(d.join("dev/nvme0"), b"").unwrap();
        std::fs::write(d.join("watch/state.json"), b"{}").unwrap();
        let ring = d.join("scope/ring.bin");
        let _cri = UnixListener::bind(d.join("run/containerd.sock")).unwrap();
        let _machined = UnixListener::bind(d.join("machined/machine.sock")).unwrap();
        let _other = UnixListener::bind(d.join("elsewhere/x.sock")).unwrap();
        let (_tcp, tcp) = listening();
        let port = free_port();
        sandboxed(
            || {
                scope(Scope {
                    ring: &ring,
                    time_file: &ring.with_file_name("time.json"),
                    proc_dir: Path::new("/proc"),
                    sys_dir: Path::new("/sys"),
                    dev_dir: &d.join("dev"),
                    watch_state: &d.join("watch"),
                    cri_socket: &d.join("run/containerd.sock"),
                    machined_socket: &d.join("machined/machine.sock"),
                })
            },
            || {
                allowed("durable write in the ring dir", write_in(d.join("scope")))?;
                allowed("read /proc", read("/proc/loadavg"))?;
                allowed("read /sys", read("/sys/class"))?;
                allowed("read an NVMe node", read(d.join("dev/nvme0")))?;
                allowed("read edge-watch's record", read(d.join("watch/state.json")))?;
                denied("write edge-watch's record", write_in(d.join("watch")))?;
                denied("read outside", read(&secret))?;
                allowed(
                    "reach containerd",
                    UnixStream::connect(d.join("run/containerd.sock")),
                )?;
                allowed(
                    "reach machined",
                    UnixStream::connect(d.join("machined/machine.sock")),
                )?;
                if kernel_abi() >= 9 {
                    denied(
                        "reach another socket",
                        UnixStream::connect(d.join("elsewhere/x.sock")),
                    )?;
                }
                denied("bind", bind(port))?;
                denied("dial", dial(tcp))
            },
        );
    }

    #[test]
    fn idle_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        std::fs::create_dir_all(d.join("cg/pod")).unwrap();
        let (_api, api) = listening();
        let (_x, unlisted) = listening();
        let (port, health) = (free_port(), free_port());
        sandboxed(
            || {
                set_api_port(api);
                idle(
                    Path::new("/proc"),
                    &d.join("cg"),
                    &format!("0.0.0.0:{health}"),
                )
            },
            || {
                allowed("read pid 1's comm", read("/proc/1/comm"))?;
                allowed("read pid 1's cgroup", read("/proc/1/cgroup"))?;
                allowed("write a cgroup's cpu.max", write_in(d.join("cg/pod")))?;
                denied("read outside", read(&secret))?;
                allowed("dial the apiserver", dial(api))?;
                denied("dial another port", dial(unlisted))?;
                allowed("bind its health port", bind(health))?;
                denied("bind", bind(port))
            },
        );
    }

    #[test]
    fn signer_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        let (_api, api) = listening();
        let (_x, unlisted) = listening();
        let (port, health) = (free_port(), free_port());
        sandboxed(
            || {
                set_api_port(api);
                signer(&format!("0.0.0.0:{health}"))
            },
            || {
                denied("read outside", read(&secret))?;
                denied("write outside", write_in(d))?;
                allowed("dial the apiserver", dial(api))?;
                denied("dial another port", dial(unlisted))?;
                allowed("bind its health port", bind(health))?;
                denied("bind", bind(port))
            },
        );
    }

    #[test]
    fn registry_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        let root = d.join("store");
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        let (listen, other) = (free_port(), free_port());
        let (_upstream, upstream) = listening();
        let (_tcp, tcp) = listening();
        sandboxed(
            || registry(&root, listen, upstream),
            || {
                allowed("durable write in the store", write_in(root.join("blobs")))?;
                denied("read outside", read(&secret))?;
                denied("write outside", write_in(d.join("outside")))?;
                allowed("bind the listen port", bind(listen))?;
                denied("bind another port", bind(other))?;
                allowed("dial the upstream", dial(upstream))?;
                denied("dial another port", dial(tcp))
            },
        );
    }

    #[test]
    fn dhcp_writes_only_its_lease_file() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        let leases = d.join("leases/file");
        sandboxed(
            || dhcp(Some(&leases)),
            || {
                allowed("write the lease file", crate::durable_write(&leases, b"x"))?;
                denied("read anything else", read(&secret))?;
                denied("write anything else", write_in(d))
            },
        );
    }

    #[test]
    fn dhcp_udp_only() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        let (_tcp, tcp) = listening();
        let port = free_port();
        sandboxed(
            || dhcp(None),
            || {
                denied("read anything", read(&secret))?;
                denied("write anything", write_in(d))?;
                denied("bind TCP", bind(port))?;
                denied("dial TCP", dial(tcp))?;
                let udp = std::net::UdpSocket::bind("127.0.0.1:0")
                    .map_err(|e| format!("bind UDP: {e}"))?;
                allowed("send UDP", udp.send_to(b"x", udp.local_addr().unwrap()))?;
                allowed("receive UDP", udp.recv(&mut [0u8; 1]))
            },
        );
    }

    #[test]
    fn layers_confined_before_containerd_root() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        std::fs::create_dir_all(d.join("lib")).unwrap();
        std::fs::create_dir_all(d.join("imagecache/disk")).unwrap();
        std::fs::write(d.join("imagecache/disk/blob"), b"b").unwrap();
        let (root, state) = (d.join("lib/containerd"), d.join("lib/edge-layers"));
        let (_tcp, tcp) = listening();
        let port = free_port();
        sandboxed(
            || layers(&root, &state, &d.join("imagecache")),
            || {
                allowed("containerd creates its root", std::fs::create_dir(&root))?;
                allowed("repair a file in the root", write_in(&root))?;
                allowed("read the image cache", read(d.join("imagecache/disk/blob")))?;
                denied("write the image cache", write_in(d.join("imagecache/disk")))?;
                denied("read outside", read(&secret))?;
                denied("bind", bind(port))?;
                denied("dial", dial(tcp))
            },
        );
    }

    #[test]
    fn cni_daemon_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        let (bpf, bin, conf) = (d.join("bpf"), d.join("bin"), d.join("net.d"));
        let (_api, api) = listening();
        let (_x, unlisted) = listening();
        let port = free_port();
        sandboxed(
            || {
                set_api_port(api);
                cni_daemon(&bpf, &bin, &conf)
            },
            || {
                allowed("pin under bpffs", write_in(&bpf))?;
                allowed("install the plugin", write_in(&bin))?;
                allowed("write the conflist", write_in(&conf))?;
                allowed("read this binary", read(std::env::current_exe().unwrap()))?;
                allowed(
                    "read CPU topology",
                    read("/sys/devices/system/cpu/possible"),
                )?;
                allowed("read /proc", read("/proc/self/status"))?;
                denied(
                    "write under /proc",
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open("/proc/self/comm"),
                )?;
                denied("read outside", read(&secret))?;
                allowed("dial the apiserver", dial(api))?;
                denied("dial another port", dial(unlisted))?;
                denied("bind", bind(port))
            },
        );
    }

    #[test]
    fn no_landlock_runs_unrestricted() {
        // ENOSYS: not built in. EOPNOTSUPP: built in but off at boot.
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
            in_child(|| {
                deny_landlock_syscalls(errno);
                let got = restrict(&state(&d.join("data/state.log"), &[], "0.0.0.0:0"));
                if got != Outcome::Unrestricted {
                    return Err(format!("errno {errno}: {got:?}"));
                }
                allowed("read outside", read(&secret))?;
                Ok(true)
            });
        }
    }

    #[test]
    fn abi7_drops_socket_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let secret = outside(d);
        std::fs::create_dir_all(d.join("run")).unwrap();
        std::fs::create_dir_all(d.join("elsewhere")).unwrap();
        let _other = UnixListener::bind(d.join("elsewhere/x.sock")).unwrap();
        in_child(|| {
            let rules = Rules::default()
                .with(Access::Socket, [d.join("run")])
                .with(Access::Write, [d.join("ring")]);
            match restrict_at(&rules, ABI::V7) {
                Outcome::Unrestricted => return no_landlock(),
                Outcome::Full => {}
                other => return Err(format!("{other:?}")),
            }
            allowed("write the ring", write_in(d.join("ring")))?;
            denied("read outside", read(&secret))?;
            allowed(
                "unix connect is not handled",
                UnixStream::connect(d.join("elsewhere/x.sock")),
            )?;
            Ok(true)
        });
    }

    fn deny_landlock_syscalls(errno: i32) {
        const LD_W_ABS: u16 = 0x20;
        const JEQ_K: u16 = 0x15;
        const RET_K: u16 = 0x06;
        let op = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        let prog = [
            op(LD_W_ABS, 0, 0, 0),
            op(JEQ_K, 0, 1, libc::SYS_landlock_create_ruleset as u32),
            op(RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | errno as u32),
            op(RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        ];
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut _,
        };
        // SAFETY: a valid filter program that outlives the call.
        unsafe {
            let (one, zero): (libc::c_ulong, libc::c_ulong) = (1, 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero),
                0
            );
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &fprog as *const libc::sock_fprog
                ),
                0
            );
        }
    }
}
