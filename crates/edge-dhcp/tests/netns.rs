use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

const INSIDE_NETNS_ENV: &str = "EDGE_DHCP_IN_NETNS";
const TEST: &str = "laptop_lease_and_name_across_restart";
/// A PID namespace too, so every dhcpcd helper dies with the test, pass or fail.
const UNSHARE_ARGS: [&str; 8] = [
    "--map-auto",
    "--map-root-user",
    "--net",
    "--mount",
    "--pid",
    "--fork",
    "--mount-proc",
    "--",
];
const LAPTOP_MAC: &str = "02:11:22:33:44:55";
const STRANGER_MAC: &str = "02:99:88:77:66:55";

#[test]
fn laptop_lease_and_name_across_restart() {
    if std::env::var_os(INSIDE_NETNS_ENV).is_some() {
        return inside();
    }
    let Some(dhcpcd) = ["/usr/sbin/dhcpcd", "/sbin/dhcpcd"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
    else {
        skip("no dhcpcd on this host");
        return;
    };
    // dhcpcd drops privileges to its own user, so the namespace needs a
    // subordinate id range mapped, not just root.
    if !Command::new("unshare")
        .args(UNSHARE_ARGS)
        .arg("true")
        .status()
        .is_ok_and(|s| s.success())
    {
        skip("this host gives no user namespace with a subordinate id map");
        return;
    }
    let status = Command::new("unshare")
        .args(UNSHARE_ARGS)
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env(INSIDE_NETNS_ENV, "1")
        .env("DHCPCD", dhcpcd)
        .status()
        .unwrap();
    assert!(status.success(), "inside the namespace: {status}");
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn ip(args: &str) -> String {
    run(Command::new("ip").args(args.split_whitespace()))
}

struct Laptop {
    ns: Child,
    dhcpcd: PathBuf,
}

impl Laptop {
    fn cmd(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut c = Command::new("nsenter");
        c.args(["-t", &self.ns.id().to_string(), "-n", "--"])
            .arg(program);
        c
    }

    fn ip(&self, args: &str) -> String {
        run(self.cmd("ip").args(args.split_whitespace()))
    }

    /// Bounded from outside: dhcpcd's own timeout does not end a solicit.
    fn dhcp(&self, iface: &str, secs: u32, extra: &[&str]) -> bool {
        self.cmd("timeout")
            .arg(secs.to_string())
            .arg(&self.dhcpcd)
            .args(["-4", "-B", "-1", "--noipv4ll", "-c", "/bin/true"])
            .args(extra)
            .arg(iface)
            .status()
            .unwrap()
            .success()
    }

    fn addr(&self, iface: &str) -> Option<String> {
        let out = self.ip(&format!("-4 -o addr show dev {iface}"));
        out.split_whitespace()
            .skip_while(|w| *w != "inet")
            .nth(1)
            .map(str::to_owned)
    }

    fn resolve(&self, name: &str, qtype: RecordType) -> Message {
        let netns = format!("/proc/{}/ns/net", self.ns.id());
        let name = Name::from_ascii(name).unwrap();
        std::thread::spawn(move || {
            let f = std::fs::File::open(netns).unwrap();
            nix::sched::setns(f, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
            let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut q = Message::new(0x4242, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(name, qtype));
            sock.send_to(&q.to_vec().unwrap(), "10.51.0.1:53").unwrap();
            let mut buf = [0u8; 512];
            let n = sock.recv(&mut buf).expect("no DNS answer");
            Message::from_vec(&buf[..n]).unwrap()
        })
        .join()
        .unwrap()
    }
}

impl Drop for Laptop {
    fn drop(&mut self) {
        let _ = self.ns.kill();
        let _ = self.ns.wait();
    }
}

struct Daemon {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    fn start(leases: &Path) -> Daemon {
        let mut child = Command::new(env!("CARGO_BIN_EXE_edge-dhcp"))
            .env("EDGE_DHCP_ADDR", "10.51.0.1/24")
            .env("EDGE_DHCP_DOMAIN", "example.lan")
            .env("EDGE_DHCP_LEASES", leases)
            .env("RUST_LOG", "debug")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let (out, sink) = (child.stdout.take().unwrap(), log.clone());
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                eprintln!("edge-dhcp: {line}");
                sink.lock().unwrap().push(line);
            }
        });
        let daemon = Daemon { child, log };
        daemon.wait_for("edge-dhcp serving");
        daemon
    }

    fn lines(&self, needle: &str) -> Vec<String> {
        let log = self.log.lock().unwrap();
        log.iter().filter(|l| l.contains(needle)).cloned().collect()
    }

    fn wait_for(&self, needle: &str) {
        let until = Instant::now() + Duration::from_secs(10);
        while self.lines(needle).is_empty() {
            assert!(Instant::now() < until, "edge-dhcp never logged {needle:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    fn stop(mut self) {
        let pid = nix::unistd::Pid::from_raw(self.child.id() as i32);
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < until, "still running 2s after SIGTERM");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "{status}");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs a copy of dhcpcd: the installed binary enters an SELinux domain that
/// cannot write the private state directories.
fn dhcpcd_sandbox(scratch: &Path) -> PathBuf {
    for dir in ["/run", "/var/lib"] {
        run(Command::new("mount").args(["-t", "tmpfs", "none", dir]));
    }
    for dir in ["/run/dhcpcd", "/var/lib/dhcpcd"] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::create_dir_all(scratch).unwrap();
    let copy = scratch.join("dhcpcd");
    std::fs::copy(std::env::var("DHCPCD").unwrap(), &copy).unwrap();
    copy
}

fn laptop(dhcpcd: PathBuf) -> Laptop {
    let ns = Command::new("unshare")
        .args(["--net", "sleep", "600"])
        .spawn()
        .unwrap();
    let mine = std::fs::read_link("/proc/self/ns/net").unwrap();
    let theirs = format!("/proc/{}/ns/net", ns.id());
    while std::fs::read_link(&theirs).ok().is_none_or(|n| n == mine) {
        std::thread::sleep(Duration::from_millis(5));
    }
    Laptop { ns, dhcpcd }
}

/// Each line but the lease's expiry, once a file other than `stale` is there.
fn lease_lines(file: &Path, stale: Option<u64>) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let fresh = std::fs::metadata(file).is_ok_and(|m| Some(m.ino()) != stale);
        let text = std::fs::read_to_string(file).unwrap_or_default();
        if fresh && text.lines().count() > 1 || Instant::now() > until {
            return text
                .lines()
                .map(|l| {
                    let mut f: Vec<&str> = l.split(' ').collect();
                    if f[0] == "lease" {
                        f.remove(1);
                    }
                    f.join(" ")
                })
                .collect();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn inode(file: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(file).ok().map(|m| m.ino())
}

fn inside() {
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR")).join("edge-dhcp-netns");
    let dhcpcd = dhcpcd_sandbox(&scratch);
    let leases = scratch.join("state/leases");
    std::fs::remove_file(&leases).ok();
    let laptop = laptop(dhcpcd);
    let pid = laptop.ns.id();
    ip("link set lo up");
    ip(&format!(
        "link add operator type veth peer name laptop netns {pid}"
    ));
    ip(&format!(
        "link add mgmt type veth peer name stranger netns {pid}"
    ));
    ip("addr add 192.0.2.1/24 dev mgmt");
    ip("link set operator up");
    ip("link set mgmt up");
    laptop.ip(&format!("link set laptop address {LAPTOP_MAC}"));
    laptop.ip(&format!("link set stranger address {STRANGER_MAC}"));
    for l in ["lo", "laptop", "stranger"] {
        laptop.ip(&format!("link set {l} up"));
    }

    let mut dhcp = Daemon::start(&leases);
    assert!(!laptop.dhcp("laptop", 3, &[]), "a lease with the port dark");
    assert!(dhcp.running(), "edge-dhcp gave up while the port was dark");

    ip("addr add 10.51.0.1/24 dev operator");
    assert!(laptop.dhcp("laptop", 15, &["-r", "10.51.0.150"]));
    assert_eq!(laptop.addr("laptop").as_deref(), Some("10.51.0.150/24"));
    dhcp.wait_for("addr=10.51.0.150");
    assert_eq!(dhcp.lines("lease granted").len(), 1);
    let recorded = lease_lines(&leases, None);
    assert_eq!(recorded.len(), 2, "{recorded:?}");
    assert_eq!(recorded[0], "serving 10.51.0.1/24 example.lan");
    assert!(
        recorded[1].starts_with(&format!("lease {LAPTOP_MAC} 10.51.0.150 ")),
        "{recorded:?}"
    );

    let a = laptop.resolve("flux.example.lan.", RecordType::A);
    assert_eq!(a.metadata.response_code, ResponseCode::NoError);
    assert_eq!(a.answers.len(), 1);
    assert_eq!(
        a.answers[0].data,
        RData::A(Ipv4Addr::new(10, 51, 0, 1).into())
    );
    let aaaa = laptop.resolve("example.lan.", RecordType::AAAA);
    assert_eq!(
        (aaaa.metadata.response_code, aaaa.answers.len()),
        (ResponseCode::NoError, 0)
    );
    let other = laptop.resolve("example.com.", RecordType::A);
    assert_eq!(other.metadata.response_code, ResponseCode::Refused);

    assert!(
        !laptop.dhcp("stranger", 3, &[]),
        "a lease on the management port"
    );
    assert!(dhcp.lines(STRANGER_MAC).is_empty());

    dhcp.stop();
    let before = inode(&leases);
    let dhcp = Daemon::start(&leases);
    assert_eq!(
        lease_lines(&leases, before),
        recorded,
        "the restart forgot the lease"
    );
    assert!(laptop.dhcp("laptop", 15, &[]));
    assert_eq!(laptop.addr("laptop").as_deref(), Some("10.51.0.150/24"));
    dhcp.wait_for("addr=10.51.0.150");
    assert!(
        dhcp.lines("NAK").is_empty(),
        "the rebooting laptop was refused"
    );
    assert!(
        dhcp.lines("offer").is_empty(),
        "the laptop had to start over"
    );
}

pub fn skip(why: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "{why}, and CI must run this test"
    );
    eprintln!("SKIP: {why}");
}
