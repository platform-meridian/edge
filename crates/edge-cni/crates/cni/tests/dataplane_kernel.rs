use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use aya::maps::HashMap as BpfHashMap;
use aya::maps::{Array, lpm_trie::LpmTrie};
use aya::programs::links::{FdLink, PinnedLink};
use common::{lo_up, make_pod, on_ns, rt, seen_as};
use edge_cni::netlink::Net;
use edge_cni::netpol::{self, AyaPolicyMaps};
use edge_cni::{daemon, pins, ports};
use edge_kube::ServiceView;
use edge_kube::policy::{Allow, HostPort, Ipv4Net, PodPolicy, Proto};
use k8s_openapi::api::core::v1::{
    ClientIPConfig, Service, ServicePort, ServiceSpec, SessionAffinityConfig,
};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointPort, EndpointSlice};

mod common;

const SERVICES_TEST: &str = "services_rewritten_in_cgroup";
const DUAL_STACK_TEST: &str = "services_rewritten_for_dual_stack_sockets";
const HANDOVER_TEST: &str = "socket_hooks_handed_over";
const PROBE_ENV: &str = "EDGE_CNI_PROBE";
const SOCKET_PROGRAMS: [&str; 5] = ["connect4", "connect6", "sendmsg4", "recvmsg4", "recvmsg6"];
const VIP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const NO_BACKENDS_VIP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 11);
const REPLY: &str = "backend";
const TIMEOUT: Duration = Duration::from_millis(700);

struct Pins(PathBuf);

impl Pins {
    fn new(tag: &str) -> Self {
        // Its own parent: edge-cni takes sibling directories for its other versions.
        let dir = PathBuf::from(format!(
            "/sys/fs/bpf/edge-cni-test-{}-{tag}/pins",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Pins(dir)
    }

    fn load(&self) -> aya::Ebpf {
        aya::EbpfLoader::new()
            .default_map_pin_directory(&self.0)
            .load(pins::OBJECT)
            .unwrap()
    }

    fn dir(&self) -> &str {
        self.0.to_str().unwrap()
    }

    fn version(&self, name: &str) -> String {
        format!("{}/{name}", self.dir())
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        netpol::unpin_all(self.dir());
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

struct Cgroup(PathBuf);

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn test_cgroup(tag: &str) -> Option<Cgroup> {
    if unsafe { nix::libc::geteuid() } != 0 {
        common::skip("needs root");
        return None;
    }
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        common::skip("no cgroup v2 at /sys/fs/cgroup");
        return None;
    }
    let dir = PathBuf::from(format!(
        "/sys/fs/cgroup/edge-cni-test-{}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).unwrap();
    Some(Cgroup(dir))
}

fn service(name: &str, ip: Ipv4Addr, ports: &[(&str, i32, &str)]) -> Service {
    let mut s = Service::default();
    s.metadata.name = Some(name.into());
    s.metadata.namespace = Some("ns".into());
    s.spec = Some(ServiceSpec {
        cluster_ip: Some(ip.to_string()),
        ports: Some(
            ports
                .iter()
                .map(|(name, port, proto)| ServicePort {
                    name: Some(name.to_string()),
                    port: *port,
                    protocol: Some(proto.to_string()),
                    ..Default::default()
                })
                .collect(),
        ),
        ..Default::default()
    });
    s
}

fn slice(service: &str, ports: &[(&str, u16)], address: Ipv4Addr) -> EndpointSlice {
    let mut e = EndpointSlice {
        address_type: "IPv4".into(),
        ..Default::default()
    };
    e.metadata.name = Some(format!("{service}-1"));
    e.metadata.namespace = Some("ns".into());
    e.metadata.labels = Some(
        [(
            "kubernetes.io/service-name".to_string(),
            service.to_string(),
        )]
        .into(),
    );
    e.ports = Some(
        ports
            .iter()
            .map(|(name, port)| EndpointPort {
                name: Some(name.to_string()),
                port: Some(*port as i32),
                ..Default::default()
            })
            .collect(),
    );
    e.endpoints = Some(vec![Endpoint {
        addresses: vec![address.to_string()],
        ..Default::default()
    }]);
    e
}

fn tcp_reply(to: SocketAddr) -> String {
    match TcpStream::connect_timeout(&to, TIMEOUT) {
        Ok(mut s) => {
            s.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut reply = String::new();
            let _ = s.read_to_string(&mut reply);
            reply
        }
        Err(e) => format!("{:?}", e.kind()),
    }
}

// A dual-stack socket (AF_INET6, IPV6_V6ONLY off) dials IPv4 as `::ffff:a.b.c.d`.
fn dual_stack(ip: Ipv4Addr) -> IpAddr {
    IpAddr::V6(ip.to_ipv6_mapped())
}

fn probe(at: fn(Ipv4Addr) -> IpAddr) {
    println!("tcp={}", tcp_reply(SocketAddr::new(at(VIP), 80)));

    let any = match at(Ipv4Addr::UNSPECIFIED) {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let udp = UdpSocket::bind((any, 0)).unwrap();
    udp.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut b = [0u8; 64];
    let udp = match udp
        .send_to(b"ping", (at(VIP), 53))
        .and_then(|_| udp.recv_from(&mut b))
    {
        Ok((n, from)) => format!("{from} {}", String::from_utf8_lossy(&b[..n])),
        Err(e) => format!("{:?}", e.kind()),
    };
    println!("udp={udp}");

    // Connected, as c-ares does: the reply's source is still checked.
    let udp = UdpSocket::bind((any, 0)).unwrap();
    udp.set_read_timeout(Some(TIMEOUT)).unwrap();
    let connected = match udp
        .connect((at(VIP), 53))
        .and_then(|_| udp.send(b"ping"))
        .and_then(|_| udp.recv_from(&mut b))
    {
        Ok((n, from)) => format!("{from} {}", String::from_utf8_lossy(&b[..n])),
        Err(e) => format!("{:?}", e.kind()),
    };
    println!("udp_connected={connected}");

    let no_backends =
        match TcpStream::connect_timeout(&SocketAddr::new(at(NO_BACKENDS_VIP), 80), TIMEOUT) {
            Ok(_) => "connected".to_string(),
            Err(e) => format!("{:?}", e.kind()),
        };
    println!("no_backends={no_backends}");
}

fn join_cgroup(procs: RawFd) -> std::io::Result<()> {
    // "0" moves the writing process.
    match unsafe { nix::libc::write(procs, b"0".as_ptr().cast(), 1) } {
        1 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

fn probe_command(test: &str, cgroup: Option<&Path>) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test, "--include-ignored", "--nocapture"])
        .env(PROBE_ENV, "1");
    if let Some(c) = cgroup {
        let procs = OpenOptions::new()
            .write(true)
            .open(c.join("cgroup.procs"))
            .unwrap();
        // SAFETY: only write(2) runs between fork and exec.
        unsafe { cmd.pre_exec(move || join_cgroup(procs.as_raw_fd())) };
    }
    cmd
}

fn probe_from(cgroup: Option<&Path>) -> BTreeMap<String, String> {
    probe_test(SERVICES_TEST, cgroup)
}

fn probe_test(test: &str, cgroup: Option<&Path>) -> BTreeMap<String, String> {
    let out = probe_command(test, cgroup).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe failed: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| ["tcp", "udp", "udp_connected", "no_backends"].contains(k))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn tcp_backend(reply: &'static str) -> u16 {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in tcp.incoming().flatten() {
            let _ = s.write_all(reply.as_bytes());
        }
    });
    port
}

fn udp_backend(reply: &'static str) -> u16 {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut b = [0u8; 64];
        while let Ok((_, from)) = udp.recv_from(&mut b) {
            let _ = udp.send_to(reply.as_bytes(), from);
        }
    });
    port
}

#[test]
#[ignore = "needs root"]
fn services_rewritten_in_cgroup() {
    if std::env::var_os(PROBE_ENV).is_some() {
        return probe(IpAddr::V4);
    }
    let Some(cgroup) = test_cgroup("svc") else {
        return;
    };
    let (tcp_port, udp_port) = (tcp_backend(REPLY), udp_backend(REPLY));

    let pins = Pins::new("svc");
    let vdir = pins.version("v1");
    let (mut bpf, mut programmer) = daemon::load_services(&vdir).unwrap();
    let mut view = ServiceView::default();
    view.apply_service(service(
        "web",
        VIP,
        &[("http", 80, "TCP"), ("dns", 53, "UDP")],
    ));
    view.apply_slice(slice(
        "web",
        &[("http", tcp_port), ("dns", udp_port)],
        Ipv4Addr::LOCALHOST,
    ));
    view.apply_service(service("idle", NO_BACKENDS_VIP, &[("http", 80, "TCP")]));
    programmer.on_synced(&view).unwrap();
    assert_eq!(programmer.service_count(), 3);
    pins::take_over_sockets(&mut bpf, &vdir, &cgroup.0).unwrap();

    let inside = probe_from(Some(&cgroup.0));
    assert_eq!(inside["tcp"], REPLY, "TCP to the VIP reaches the backend");
    assert_eq!(
        inside["udp"],
        format!("{VIP}:53 {REPLY}"),
        "the UDP reply comes from the VIP"
    );
    assert_eq!(
        inside["udp_connected"],
        format!("{VIP}:53 {REPLY}"),
        "a connected socket's UDP reply comes from the VIP"
    );
    assert_eq!(inside["no_backends"], "ConnectionRefused");

    drop((bpf, programmer));
    let pinned = probe_from(Some(&cgroup.0));
    assert_eq!(pinned, inside, "the pinned links outlive the daemon");

    let outside = probe_from(None);
    let unpinned = {
        for name in SOCKET_PROGRAMS {
            std::fs::remove_file(format!("{vdir}/links/{name}")).unwrap();
        }
        probe_from(Some(&cgroup.0))
    };
    for (who, seen) in [("outside the cgroup", outside), ("unpinned", unpinned)] {
        assert_ne!(seen["tcp"], REPLY, "{who}: {seen:?}");
        assert!(!seen["udp"].ends_with(REPLY), "{who}: {seen:?}");
        assert!(!seen["udp_connected"].ends_with(REPLY), "{who}: {seen:?}");
        assert_ne!(seen["no_backends"], "ConnectionRefused", "{who}: {seen:?}");
    }
}

#[test]
#[ignore = "needs root"]
fn services_rewritten_for_dual_stack_sockets() {
    if std::env::var_os(PROBE_ENV).is_some() {
        return probe(dual_stack);
    }
    let Some(cgroup) = test_cgroup("dual") else {
        return;
    };
    let (tcp_port, udp_port) = (tcp_backend(REPLY), udp_backend(REPLY));

    let pins = Pins::new("dual");
    let vdir = pins.version("v1");
    let (mut bpf, mut programmer) = daemon::load_services(&vdir).unwrap();
    let mut view = ServiceView::default();
    view.apply_service(service(
        "web",
        VIP,
        &[("http", 80, "TCP"), ("dns", 53, "UDP")],
    ));
    view.apply_slice(slice(
        "web",
        &[("http", tcp_port), ("dns", udp_port)],
        Ipv4Addr::LOCALHOST,
    ));
    view.apply_service(service("idle", NO_BACKENDS_VIP, &[("http", 80, "TCP")]));
    programmer.on_synced(&view).unwrap();
    pins::take_over_sockets(&mut bpf, &vdir, &cgroup.0).unwrap();

    let inside = probe_test(DUAL_STACK_TEST, Some(&cgroup.0));
    assert_eq!(
        inside["tcp"], REPLY,
        "TCP to the mapped VIP reaches the backend"
    );
    assert_eq!(
        inside["udp"],
        format!("{} {REPLY}", SocketAddr::new(dual_stack(VIP), 53)),
        "the UDP reply comes from the mapped VIP"
    );
    assert_eq!(
        inside["udp_connected"],
        format!("{} {REPLY}", SocketAddr::new(dual_stack(VIP), 53)),
        "a connected socket's UDP reply comes from the mapped VIP"
    );
    assert_eq!(inside["no_backends"], "ConnectionRefused");

    let outside = probe_test(DUAL_STACK_TEST, None);
    assert_ne!(outside["tcp"], REPLY, "{outside:?}");
    assert!(!outside["udp"].ends_with(REPLY), "{outside:?}");
    assert!(!outside["udp_connected"].ends_with(REPLY), "{outside:?}");
}

fn dial_until_stdin_closes() {
    let stop = Arc::new(AtomicBool::new(false));
    let stopper = stop.clone();
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
        stopper.store(true, Ordering::SeqCst);
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        println!("reply={}", tcp_reply(SocketAddr::from((VIP, 80))));
        if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn load_programmed(vdir: &str, port: u16) -> aya::Ebpf {
    let (bpf, mut programmer) = daemon::load_services(vdir).unwrap();
    let mut view = ServiceView::default();
    view.apply_service(service("web", VIP, &[("http", 80, "TCP")]));
    view.apply_slice(slice("web", &[("http", port)], Ipv4Addr::LOCALHOST));
    programmer.on_synced(&view).unwrap();
    bpf
}

fn pinned_links(vdir: &str) -> BTreeMap<String, (u32, u32)> {
    std::fs::read_dir(format!("{vdir}/links"))
        .unwrap()
        .flatten()
        .map(|e| {
            let info = FdLink::from(PinnedLink::from_pin(e.path()).unwrap())
                .info()
                .unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                (info.id(), info.program_id()),
            )
        })
        .collect()
}

fn program_id(bpf: &aya::Ebpf, name: &str) -> u32 {
    bpf.program(name).unwrap().info().unwrap().id()
}

fn replies(out: impl Read) -> impl Iterator<Item = String> {
    BufReader::new(out)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| l.split_once("reply=").map(|(_, r)| r.to_string()))
}

#[test]
#[ignore = "needs root"]
fn socket_hooks_handed_over() {
    if std::env::var_os(PROBE_ENV).is_some() {
        return dial_until_stdin_closes();
    }
    let Some(cgroup) = test_cgroup("handover") else {
        return;
    };
    let pins = Pins::new("handover");
    let (old, new) = (pins.version("old"), pins.version("new"));

    let mut old_bpf = load_programmed(&old, tcp_backend("old"));
    pins::take_over_sockets(&mut old_bpf, &old, &cgroup.0).unwrap();
    let old_links = pinned_links(&old);
    assert_eq!(old_links.len(), SOCKET_PROGRAMS.len(), "{old_links:?}");

    let mut dialer = probe_command(HANDOVER_TEST, Some(&cgroup.0))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut seen = replies(dialer.stdout.take().unwrap());
    let mut log = vec![seen.next().expect("the dialer ended")];

    let mut new_bpf = load_programmed(&new, tcp_backend("new"));
    pins::take_over_sockets(&mut new_bpf, &new, &cgroup.0).unwrap();
    for reply in seen.by_ref() {
        log.push(reply);
        if log.len() >= 20 && log[log.len() - 20..].iter().all(|r| r == "new") {
            break;
        }
    }
    drop(dialer.stdin.take());
    log.extend(seen);
    assert!(dialer.wait().unwrap().success());

    assert_eq!(log[0], "old", "{log:?}");
    let first_new = log.iter().position(|r| r == "new");
    let first_new = first_new.unwrap_or_else(|| panic!("never reached the new version: {log:?}"));
    assert!(
        log[..first_new].iter().all(|r| r == "old") && log[first_new..].iter().all(|r| r == "new"),
        "every dial reached a backend, and the old version never again: {log:?}"
    );

    assert!(pinned_links(&old).is_empty(), "the old version's pins go");
    let new_links = pinned_links(&new);
    for name in SOCKET_PROGRAMS {
        assert_eq!(
            new_links[name],
            (old_links[name].0, program_id(&new_bpf, name)),
            "{name}: the old link runs the new program, none attached alongside"
        );
    }

    drop((old_bpf, new_bpf));
    let mut after = probe_command(HANDOVER_TEST, Some(&cgroup.0))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let last: Vec<String> = replies(after.stdout.take().unwrap()).collect();
    assert!(after.wait().unwrap().success());
    assert!(
        !last.is_empty() && last.iter().all(|r| r == "new"),
        "only the new version's links serve: {last:?}"
    );
}

fn policy_child() {
    lo_up();
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").unwrap();
    // Proxy ARP answers the pods' gateway only if it is routable elsewhere.
    rt().block_on(async {
        Net::open()
            .unwrap()
            .add_addr("lo", "169.254.1.1".parse().unwrap(), 32)
            .await
            .unwrap();
    });
    let server = make_pod("10.244.0.1".parse().unwrap(), 1, &[8080, 8081]);
    let client = make_pod("10.244.0.2".parse().unwrap(), 2, &[]);
    let allowed = SocketAddr::from((server.ip, 8080));
    let denied = SocketAddr::from((server.ip, 8081));
    let client_ip = client.ip.to_string();

    let pins = Pins::new("np");
    let mut bpf = pins.load();
    netpol::load_programs(&mut bpf).unwrap();
    let mut maps = AyaPolicyMaps {
        pods: BpfHashMap::try_from(bpf.take_map("NP_PODS").unwrap()).unwrap(),
        pod_ips: BpfHashMap::try_from(bpf.take_map("NP_POD_IPS").unwrap()).unwrap(),
        allow: LpmTrie::try_from(bpf.take_map("NP_ALLOW").unwrap()).unwrap(),
        armed: Array::try_from(bpf.take_map("NP_ARMED").unwrap()).unwrap(),
    };
    for veth in ["edge1", "edge2"] {
        assert!(
            netpol::hook_veth(&mut bpf, pins.dir(), veth, false)
                .unwrap()
                .attached
        );
    }
    assert!(
        !netpol::hook_veth(&mut bpf, pins.dir(), "edge1", false)
            .unwrap()
            .attached,
        "pinned hooks are not attached twice"
    );
    let attached: BTreeMap<u32, Ipv4Addr> = rt().block_on(async {
        let net = Net::open().unwrap();
        BTreeMap::from([
            (net.link_index("edge1").await.unwrap(), server.ip),
            (net.link_index("edge2").await.unwrap(), client.ip),
        ])
    });
    let open = netpol::lower(&BTreeMap::new(), &attached);
    let isolated = netpol::lower(
        &BTreeMap::from([(
            server.ip,
            PodPolicy {
                ingress: Some(vec![Allow {
                    peer: Ipv4Net::host(client.ip),
                    proto: Proto::Tcp,
                    lo: 8080,
                    hi: 8080,
                }]),
                egress: None,
            },
        )]),
        &attached,
    );

    netpol::reconcile(&mut maps, &open).unwrap();
    assert_eq!(seen_as(Some(&client.ns), allowed), Some(client_ip.clone()));
    assert_eq!(
        seen_as(Some(&client.ns), denied),
        Some(client_ip.clone()),
        "no policy: open"
    );

    netpol::reconcile(&mut maps, &isolated).unwrap();
    assert_eq!(seen_as(Some(&client.ns), allowed), Some(client_ip.clone()));
    assert_eq!(
        seen_as(Some(&client.ns), denied),
        None,
        "a port the policy does not allow is dropped"
    );
    assert!(
        seen_as(None, denied).is_some(),
        "the node itself passes (kubelet probes)"
    );

    netpol::reconcile(&mut maps, &open).unwrap();
    assert_eq!(
        seen_as(Some(&client.ns), denied),
        Some(client_ip),
        "policy removed: open again"
    );
}

#[test]
#[ignore = "needs root"]
fn policy_enforced_on_veths() {
    let Some((passed, text)) = common::in_netns("policy_enforced_on_veths", policy_child) else {
        return;
    };
    assert!(passed, "netns child failed:\n{text}");
}

fn udp_echo_peer_addr(ns: &File, port: u16) {
    on_ns(ns, || {
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            while let Ok((_, from)) = udp.recv_from(&mut b) {
                let _ = udp.send_to(from.ip().to_string().as_bytes(), from);
            }
        });
    });
}

fn udp_seen_as(from: Option<&File>, to: SocketAddr) -> Option<String> {
    let f = move || {
        let udp = UdpSocket::bind("0.0.0.0:0").ok()?;
        udp.set_read_timeout(Some(TIMEOUT)).ok()?;
        udp.send_to(b"ping", to).ok()?;
        let mut b = [0u8; 64];
        let (n, _) = udp.recv_from(&mut b).ok()?;
        Some(String::from_utf8_lossy(&b[..n]).into_owned())
    };
    match from {
        Some(ns) => on_ns(ns, f),
        None => f(),
    }
}

fn replies_child() {
    lo_up();
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").unwrap();
    let node_ip: Ipv4Addr = "169.254.1.1".parse().unwrap();
    rt().block_on(async {
        Net::open()
            .unwrap()
            .add_addr("lo", node_ip, 32)
            .await
            .unwrap();
    });
    let node_listener = TcpListener::bind((node_ip, 0)).unwrap();
    let node = node_listener.local_addr().unwrap();
    std::thread::spawn(move || common::reply_with_peer_addr(node_listener));

    let server = make_pod("10.244.0.1".parse().unwrap(), 1, &[8080]);
    let client = make_pod("10.244.0.2".parse().unwrap(), 2, &[8080]);
    // Unhooked and outside the pod set: stands in for a client beyond the node.
    let outside = make_pod("192.0.2.2".parse().unwrap(), 3, &[8080]);
    for pod in [&server, &outside] {
        udp_echo_peer_addr(&pod.ns, 5353);
    }
    let tcp = |pod: &common::Pod| SocketAddr::from((pod.ip, 8080));
    let udp = |pod: &common::Pod| SocketAddr::from((pod.ip, 5353));
    let (server_ip, client_ip, outside_ip) = (
        server.ip.to_string(),
        client.ip.to_string(),
        outside.ip.to_string(),
    );

    let pins = Pins::new("npr");
    let mut bpf = pins.load();
    netpol::load_programs(&mut bpf).unwrap();
    let mut maps = AyaPolicyMaps {
        pods: BpfHashMap::try_from(bpf.take_map("NP_PODS").unwrap()).unwrap(),
        pod_ips: BpfHashMap::try_from(bpf.take_map("NP_POD_IPS").unwrap()).unwrap(),
        allow: LpmTrie::try_from(bpf.take_map("NP_ALLOW").unwrap()).unwrap(),
        armed: Array::try_from(bpf.take_map("NP_ARMED").unwrap()).unwrap(),
    };
    for veth in ["edge1", "edge2"] {
        assert!(
            netpol::hook_veth(&mut bpf, pins.dir(), veth, false)
                .unwrap()
                .attached
        );
    }
    let attached: BTreeMap<u32, Ipv4Addr> = rt().block_on(async {
        let net = Net::open().unwrap();
        BTreeMap::from([
            (net.link_index("edge1").await.unwrap(), server.ip),
            (net.link_index("edge2").await.unwrap(), client.ip),
        ])
    });
    let deny_all = |ingress: bool| {
        let policy = if ingress {
            PodPolicy {
                ingress: Some(vec![]),
                egress: None,
            }
        } else {
            PodPolicy {
                ingress: None,
                egress: Some(vec![]),
            }
        };
        netpol::lower(&BTreeMap::from([(server.ip, policy)]), &attached)
    };

    netpol::reconcile(&mut maps, &deny_all(false)).unwrap();
    assert_eq!(
        seen_as(Some(&outside.ns), tcp(&server)),
        Some(outside_ip.clone())
    );
    assert_eq!(
        udp_seen_as(Some(&outside.ns), udp(&server)),
        Some(outside_ip.clone())
    );
    assert!(seen_as(None, tcp(&server)).is_some(), "node");
    assert_eq!(seen_as(Some(&client.ns), tcp(&server)), Some(client_ip));
    assert_eq!(seen_as(Some(&server.ns), tcp(&outside)), None);
    assert_eq!(udp_seen_as(Some(&server.ns), udp(&outside)), None);
    assert_eq!(seen_as(Some(&server.ns), node), None);
    assert_eq!(seen_as(Some(&server.ns), tcp(&client)), None);

    netpol::reconcile(&mut maps, &deny_all(true)).unwrap();
    assert_eq!(
        seen_as(Some(&server.ns), tcp(&outside)),
        Some(server_ip.clone())
    );
    assert_eq!(
        udp_seen_as(Some(&server.ns), udp(&outside)),
        Some(server_ip.clone())
    );
    assert!(seen_as(Some(&server.ns), node).is_some(), "node");
    assert_eq!(seen_as(Some(&server.ns), tcp(&client)), Some(server_ip));
    assert_eq!(seen_as(Some(&outside.ns), tcp(&server)), None);
    assert_eq!(udp_seen_as(Some(&outside.ns), udp(&server)), None);
    assert_eq!(seen_as(Some(&client.ns), tcp(&server)), None);
}

#[test]
#[ignore = "needs root"]
fn replies_pass_isolation() {
    let Some((passed, text)) = common::in_netns("replies_pass_isolation", replies_child) else {
        return;
    };
    assert!(passed, "netns child failed:\n{text}");
}

const AFFINITY_TEST: &str = "client_affinity_at_connect";
const PORTS_TEST: &str = "node_and_host_ports_at_connect";
const DIALS_ENV: &str = "EDGE_CNI_DIALS";
// libtest may print the test's name on the line before the first result.
const DIALED: &str = "dialed ";

fn udp_reply(to: SocketAddr) -> String {
    let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
    udp.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut b = [0u8; 64];
    match udp.send_to(b"ping", to).and_then(|_| udp.recv_from(&mut b)) {
        Ok((n, from)) => format!("{from} {}", String::from_utf8_lossy(&b[..n])),
        Err(e) => format!("{:?}", e.kind()),
    }
}

// Each dial is `name=tcp:addr:port`, `name=udp:addr:port` or `pause=ms`.
fn dial_all() {
    for dial in std::env::var(DIALS_ENV).unwrap().split_whitespace() {
        let (name, target) = dial.split_once('=').unwrap();
        if name == "pause" {
            std::thread::sleep(Duration::from_millis(target.parse().unwrap()));
            continue;
        }
        let (proto, addr) = target.split_once(':').unwrap();
        let addr: SocketAddr = addr.parse().unwrap();
        let result = match proto {
            "tcp" => tcp_reply(addr),
            _ => udp_reply(addr),
        };
        println!("{DIALED}{name}={result}");
    }
}

fn dial_from(test: &str, cgroup: &Path, dials: &[String]) -> Vec<(String, String)> {
    let out = probe_command(test, Some(cgroup))
        .env(DIALS_ENV, dials.join(" "))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dialer failed: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .filter_map(|l| l.split_once(DIALED)?.1.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn vip_dials(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("d{i}=tcp:{VIP}:80")).collect()
}

fn replies_of(seen: &[(String, String)]) -> BTreeSet<String> {
    seen.iter().map(|(_, v)| v.clone()).collect()
}

fn sticky_view(ports: &[u16], affinity_secs: Option<i32>) -> ServiceView {
    let mut s = service("web", VIP, &[("http", 80, "TCP")]);
    if let Some(secs) = affinity_secs {
        let spec = s.spec.as_mut().unwrap();
        spec.session_affinity = Some("ClientIP".into());
        spec.session_affinity_config = Some(SessionAffinityConfig {
            client_ip: Some(ClientIPConfig {
                timeout_seconds: Some(secs),
            }),
        });
    }
    let mut view = ServiceView::default();
    view.apply_service(s);
    for (i, port) in ports.iter().enumerate() {
        let mut e = slice("web", &[("http", *port)], Ipv4Addr::LOCALHOST);
        e.metadata.name = Some(format!("web-{i}"));
        view.apply_slice(e);
    }
    view
}

fn affinity_child() {
    lo_up();
    let Some(cgroup) = test_cgroup("affinity") else {
        return;
    };
    let ports = [tcp_backend("a"), tcp_backend("b"), tcp_backend("c")];
    let pins = Pins::new("affinity");
    let vdir = pins.version("v1");
    let (mut bpf, mut programmer) = daemon::load_services(&vdir).unwrap();
    programmer
        .on_synced(&sticky_view(&ports, Some(3600)))
        .unwrap();
    pins::take_over_sockets(&mut bpf, &vdir, &cgroup.0).unwrap();

    let pinned = dial_from(AFFINITY_TEST, &cgroup.0, &vip_dials(20));
    assert_eq!(pinned.len(), 20, "{pinned:?}");
    let backends = replies_of(&pinned);
    assert!(
        backends.len() == 1 && ["a", "b", "c"].contains(&backends.first().unwrap().as_str()),
        "one client stays on one backend: {pinned:?}"
    );

    programmer
        .on_change(&sticky_view(&ports, None), "ns/web")
        .unwrap();
    let spread = dial_from(AFFINITY_TEST, &cgroup.0, &vip_dials(30));
    assert!(
        replies_of(&spread).len() > 1,
        "affinity switched off spreads again: {spread:?}"
    );

    programmer
        .on_change(&sticky_view(&ports, Some(1)), "ns/web")
        .unwrap();
    let held = dial_from(AFFINITY_TEST, &cgroup.0, &vip_dials(10));
    assert_eq!(replies_of(&held).len(), 1, "switched on again: {held:?}");
    let mut spaced = Vec::new();
    for i in 0..10 {
        spaced.push("pause=1300".to_string());
        spaced.push(format!("d{i}=tcp:{VIP}:80"));
    }
    let expired = dial_from(AFFINITY_TEST, &cgroup.0, &spaced);
    assert_eq!(expired.len(), 10, "{expired:?}");
    assert!(
        replies_of(&expired).len() > 1,
        "an expired pin picks again: {expired:?}"
    );
}

#[test]
#[ignore = "needs root"]
fn client_affinity_at_connect() {
    if std::env::var_os(PROBE_ENV).is_some() {
        return dial_all();
    }
    let Some((passed, text)) = common::in_netns(AFFINITY_TEST, affinity_child) else {
        return;
    };
    assert!(passed, "netns child failed:\n{text}");
}

fn ports_child() {
    lo_up();
    let node: Ipv4Addr = "10.70.0.1".parse().unwrap();
    rt().block_on(async {
        Net::open().unwrap().add_addr("lo", node, 32).await.unwrap();
    });
    let Some(cgroup) = test_cgroup("ports") else {
        return;
    };
    let node_port_backend = tcp_backend("nodeport");
    let pins = Pins::new("ports");
    let vdir = pins.version("v1");
    let (mut bpf, mut programmer) = daemon::load_services(&vdir).unwrap();
    let mut port_maps = daemon::load_port_maps(&mut bpf).unwrap();
    let mut s = service("web", VIP, &[("http", 80, "TCP")]);
    s.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].node_port = Some(30080);
    let mut view = ServiceView::default();
    view.apply_service(s);
    view.apply_slice(slice(
        "web",
        &[("http", node_port_backend)],
        Ipv4Addr::LOCALHOST,
    ));
    programmer.on_synced(&view).unwrap();

    let host_port = |host_ip: Option<Ipv4Addr>, proto, container_port| {
        (
            Ipv4Addr::LOCALHOST,
            HostPort {
                proto,
                host_ip,
                host_port: if host_ip.is_some() { 54323 } else { 31000 },
                container_port,
            },
        )
    };
    let host_ports = [
        host_port(
            Some(Ipv4Addr::LOCALHOST),
            Proto::Tcp,
            tcp_backend("loopback"),
        ),
        host_port(Some(node), Proto::Tcp, tcp_backend("node")),
        host_port(Some(node), Proto::Udp, udp_backend("node-udp")),
        host_port(None, Proto::Tcp, tcp_backend("any")),
    ];
    let live = HashSet::from([Ipv4Addr::LOCALHOST]);
    let entries = ports::host_port_entries(&host_ports, &live);
    assert_eq!(entries.len(), 4);
    ports::reconcile(&mut port_maps.host_ports, &entries).unwrap();
    ports::reconcile(
        &mut port_maps.node_addrs,
        &ports::node_addr_entries(&[node]),
    )
    .unwrap();
    pins::take_over_sockets(&mut bpf, &vdir, &cgroup.0).unwrap();

    let dials: Vec<String> = [
        "node_port=tcp:10.70.0.1:30080",
        "loopback_node_port=tcp:127.0.0.1:30080",
        "off_node=tcp:192.0.2.99:30080",
        "loopback=tcp:127.0.0.1:54323",
        "node=tcp:10.70.0.1:54323",
        "node_udp=udp:10.70.0.1:54323",
        "any=tcp:10.70.0.1:31000",
        "cluster_ip=tcp:198.51.100.10:80",
    ]
    .iter()
    .map(|d| d.to_string())
    .collect();
    let seen: BTreeMap<String, String> = dial_from(PORTS_TEST, &cgroup.0, &dials)
        .into_iter()
        .collect();
    assert_eq!(seen["node_port"], "nodeport", "{seen:?}");
    assert_eq!(seen["cluster_ip"], "nodeport", "{seen:?}");
    assert_ne!(
        seen["loopback_node_port"], "nodeport",
        "only programmed node addresses answer node ports: {seen:?}"
    );
    assert_ne!(seen["off_node"], "nodeport", "{seen:?}");
    assert_eq!(seen["loopback"], "loopback", "{seen:?}");
    assert_eq!(seen["node"], "node", "{seen:?}");
    assert_eq!(
        seen["node_udp"], "10.70.0.1:54323 node-udp",
        "the UDP reply comes from the host port: {seen:?}"
    );
    assert_eq!(seen["any"], "any", "{seen:?}");

    ports::reconcile(&mut port_maps.host_ports, &BTreeMap::new()).unwrap();
    let gone: BTreeMap<String, String> = dial_from(PORTS_TEST, &cgroup.0, &dials[3..5])
        .into_iter()
        .collect();
    assert_eq!(gone["loopback"], "ConnectionRefused", "{gone:?}");
    assert_eq!(gone["node"], "ConnectionRefused", "{gone:?}");
}

#[test]
#[ignore = "needs root"]
fn node_and_host_ports_at_connect() {
    if std::env::var_os(PROBE_ENV).is_some() {
        return dial_all();
    }
    let Some((passed, text)) = common::in_netns(PORTS_TEST, ports_child) else {
        return;
    };
    assert!(passed, "netns child failed:\n{text}");
}
