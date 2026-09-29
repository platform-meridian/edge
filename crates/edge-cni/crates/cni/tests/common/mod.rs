#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::Duration;

use edge_cni::netlink::{Net, enable_proxy_arp};

const CHILD_ENV: &str = "EDGE_CNI_KERNEL_CHILD";
const CHILD_OK: &str = "KERNEL-CHILD-OK";

pub fn skip(why: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "{why}, and CI must run this test"
    );
    eprintln!("SKIP: {why}");
}

// Re-runs the test under `unshare`: a multi-threaded process cannot unshare a
// user namespace itself.
pub fn in_user_netns(test: &str, body: impl FnOnce()) -> Option<(bool, String)> {
    in_unshared(test, "-Urn", body)
}

// Keeps the caller's user namespace, so a root caller keeps the capabilities BPF needs.
pub fn in_netns(test: &str, body: impl FnOnce()) -> Option<(bool, String)> {
    in_unshared(test, "-n", body)
}

fn in_unshared(test: &str, flags: &str, body: impl FnOnce()) -> Option<(bool, String)> {
    if std::env::var_os(CHILD_ENV).is_some() {
        body();
        println!("{CHILD_OK}");
        return None;
    }
    let probe = Command::new("unshare").args([flags, "true"]).status();
    if !probe.is_ok_and(|s| s.success()) {
        skip(&format!("cannot unshare {flags} here"));
        return None;
    }
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("unshare")
        .args([
            flags,
            exe.to_str().unwrap(),
            "--exact",
            test,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some((out.status.success() && text.contains(CHILD_OK), text))
}

pub fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub fn on_ns<R: Send>(ns: &File, f: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|s| {
        s.spawn(|| {
            assert_eq!(
                unsafe { nix::libc::setns(ns.as_raw_fd(), nix::libc::CLONE_NEWNET) },
                0,
                "setns"
            );
            f()
        })
        .join()
        .unwrap()
    })
}

pub fn new_netns() -> File {
    std::thread::spawn(|| {
        assert_eq!(
            unsafe { nix::libc::unshare(nix::libc::CLONE_NEWNET) },
            0,
            "unshare netns"
        );
        File::open("/proc/thread-self/ns/net").unwrap()
    })
    .join()
    .unwrap()
}

pub fn lo_up() {
    rt().block_on(async {
        Net::open().unwrap().set_up("lo").await.unwrap();
    });
}

pub struct Pod {
    pub ip: Ipv4Addr,
    pub ns: File,
}

pub fn make_pod(ip: Ipv4Addr, n: u32, ports: &[u16]) -> Pod {
    let ns = new_netns();
    let (host, peer) = (format!("edge{n}"), format!("edgp{n}"));
    rt().block_on(async {
        let net = Net::open().unwrap();
        net.create_veth(&host, &peer, 1500).await.unwrap();
        net.move_to_netns(&peer, ns.as_raw_fd()).await.unwrap();
        net.set_up(&host).await.unwrap();
        enable_proxy_arp(&host).unwrap();
        assert!(net.claim_host_route(ip, &host).await.unwrap());
    });
    on_ns(&ns, || {
        rt().block_on(async {
            let net = Net::open().unwrap();
            let idx = net.link_index(&peer).await.unwrap();
            net.rename(idx, "eth0", 1500).await.unwrap();
            net.set_up("eth0").await.unwrap();
            net.set_up("lo").await.unwrap();
            net.add_addr("eth0", ip, 32).await.unwrap();
            net.add_default_via_gateway("eth0").await.unwrap();
        });
        for &port in ports {
            let l = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap();
            std::thread::spawn(move || reply_with_peer_addr(l));
        }
    });
    Pod { ip, ns }
}

pub fn reply_with_peer_addr(l: TcpListener) {
    for s in l.incoming().flatten() {
        let mut s = s;
        let peer = s.peer_addr().unwrap().ip().to_string();
        let mut b = [0u8; 4];
        let _ = s.read(&mut b);
        let _ = s.write_all(peer.as_bytes());
    }
}

pub fn seen_as(from: Option<&File>, to: SocketAddr) -> Option<String> {
    let f = move || {
        let mut s = TcpStream::connect_timeout(&to, Duration::from_millis(700)).ok()?;
        s.set_read_timeout(Some(Duration::from_millis(700))).ok()?;
        s.write_all(b"ping").ok()?;
        let mut out = String::new();
        s.read_to_string(&mut out).ok()?;
        Some(out)
    };
    match from {
        Some(ns) => on_ns(ns, f),
        None => f(),
    }
}
