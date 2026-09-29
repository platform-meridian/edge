use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use common::{lo_up, make_pod, new_netns, on_ns, reply_with_peer_addr, rt, seen_as};
use edge_cni::netlink::Net;
use edge_cni::nft;

mod common;

fn udp_seen_as(ns: &File, to: SocketAddr) -> Option<String> {
    on_ns(ns, || {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(700)))
            .unwrap();
        s.send_to(b"x", to).unwrap();
        let mut b = [0u8; 64];
        let (n, _) = s.recv_from(&mut b).ok()?;
        Some(String::from_utf8_lossy(&b[..n]).into_owned())
    })
}

fn kernel_child() {
    lo_up();
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").unwrap();
    rt().block_on(async {
        let net = Net::open().unwrap();
        net.add_addr("lo", "10.0.0.1".parse().unwrap(), 32)
            .await
            .unwrap();
        // Proxy ARP answers the gateway only if it is routable elsewhere.
        net.add_addr("lo", "169.254.1.1".parse().unwrap(), 32)
            .await
            .unwrap();
    });
    let host_l = TcpListener::bind("0.0.0.0:9000").unwrap();
    std::thread::spawn(move || reply_with_peer_addr(host_l));
    let host_u = UdpSocket::bind("0.0.0.0:9001").unwrap();
    std::thread::spawn(move || {
        let mut b = [0u8; 64];
        while let Ok((_, from)) = host_u.recv_from(&mut b) {
            let _ = host_u.send_to(from.ip().to_string().as_bytes(), from);
        }
    });

    // Off-node: behind an uplink, with no route back to the pod CIDR.
    let ext = new_netns();
    rt().block_on(async {
        let net = Net::open().unwrap();
        net.create_veth("up0", "upx", 1500).await.unwrap();
        net.move_to_netns("upx", ext.as_raw_fd()).await.unwrap();
        net.set_up("up0").await.unwrap();
        net.add_addr("up0", "192.0.2.1".parse().unwrap(), 24)
            .await
            .unwrap();
    });
    on_ns(&ext, || {
        rt().block_on(async {
            let net = Net::open().unwrap();
            net.set_up("upx").await.unwrap();
            net.set_up("lo").await.unwrap();
            net.add_addr("upx", "192.0.2.2".parse().unwrap(), 24)
                .await
                .unwrap();
        });
        let l = TcpListener::bind("0.0.0.0:80").unwrap();
        std::thread::spawn(move || reply_with_peer_addr(l));
        let u = UdpSocket::bind("0.0.0.0:53").unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            while let Ok((_, from)) = u.recv_from(&mut b) {
                let _ = u.send_to(from.ip().to_string().as_bytes(), from);
            }
        });
    });

    let a = make_pod("10.244.0.1".parse().unwrap(), 1, &[8080]);
    let b = make_pod("10.244.0.2".parse().unwrap(), 2, &[8080]);
    let ext_srv: SocketAddr = "192.0.2.2:80".parse().unwrap();
    let net = ("10.244.0.0".parse::<Ipv4Addr>().unwrap(), 24u8);

    assert_eq!(
        seen_as(Some(&a.ns), ext_srv),
        None,
        "no route back to the pod CIDR: must fail before masquerade"
    );

    assert_eq!(
        nft::ensure(net.0, net.1, Some(&[])).unwrap(),
        nft::Outcome::Installed
    );
    let found = nft::installed().unwrap();
    assert_eq!(found.rules.len(), 1);

    assert_eq!(
        seen_as(Some(&a.ns), ext_srv).as_deref(),
        Some("192.0.2.1"),
        "pod -> off-node wears the node's address"
    );
    assert_eq!(seen_as(Some(&b.ns), ext_srv).as_deref(), Some("192.0.2.1"));
    assert_eq!(
        udp_seen_as(&a.ns, "192.0.2.2:53".parse().unwrap()).as_deref(),
        Some("192.0.2.1"),
        "UDP too"
    );
    assert_eq!(
        seen_as(Some(&a.ns), SocketAddr::from((b.ip, 8080))).as_deref(),
        Some("10.244.0.1"),
        "pod -> pod keeps its address"
    );
    assert_eq!(
        seen_as(Some(&a.ns), "10.0.0.1:9000".parse().unwrap()).as_deref(),
        Some("10.244.0.1"),
        "pod -> node address is local: not translated"
    );
    assert_eq!(
        seen_as(Some(&a.ns), "192.0.2.1:9000".parse().unwrap()).as_deref(),
        Some("10.244.0.1"),
        "pod -> the uplink's own address is local too"
    );
    assert_eq!(
        udp_seen_as(&a.ns, "10.0.0.1:9001".parse().unwrap()).as_deref(),
        Some("10.244.0.1")
    );
    assert_eq!(
        seen_as(None, ext_srv).as_deref(),
        Some("192.0.2.1"),
        "the host is not rewritten"
    );

    for _ in 0..25 {
        assert_eq!(
            nft::ensure(net.0, net.1, Some(&[])).unwrap(),
            nft::Outcome::Present
        );
    }
    let found = nft::installed().unwrap();
    assert_eq!(
        (found.chains.len(), found.rules.len()),
        (2, 1),
        "still exactly the two chains and one rule"
    );

    nft::remove().unwrap();
    assert_eq!(nft::installed().unwrap(), nft::Found::default());
    assert_eq!(
        seen_as(Some(&a.ns), ext_srv),
        None,
        "wiped: off-node fails again"
    );
    assert_eq!(
        nft::ensure(net.0, net.1, Some(&[])).unwrap(),
        nft::Outcome::Installed
    );
    assert_eq!(
        seen_as(Some(&a.ns), ext_srv).as_deref(),
        Some("192.0.2.1"),
        "repaired"
    );
    nft::remove().unwrap();
    nft::remove().unwrap();
    assert_eq!(
        nft::ensure(net.0, net.1, Some(&[])).unwrap(),
        nft::Outcome::Installed
    );

    assert_eq!(
        nft::ensure("10.99.0.0".parse().unwrap(), 24, Some(&[])).unwrap(),
        nft::Outcome::Installed
    );
    assert_eq!(
        seen_as(Some(&a.ns), ext_srv),
        None,
        "the old CIDR no longer masquerades"
    );
    assert_eq!(
        nft::ensure(net.0, net.1, Some(&[])).unwrap(),
        nft::Outcome::Installed
    );
    assert_eq!(nft::installed().unwrap().rules.len(), 1);
    assert_eq!(seen_as(Some(&a.ns), ext_srv).as_deref(), Some("192.0.2.1"));
}

#[test]
fn masquerade_on_real_kernel() {
    let Some((passed, text)) = common::in_user_netns("masquerade_on_real_kernel", kernel_child)
    else {
        return;
    };
    if text.contains("nf_tables refused") && text.contains("Operation not supported") {
        common::skip(&format!(
            "this kernel has no nf_tables/NAT for unprivileged namespaces\n{text}"
        ));
        return;
    }
    assert!(passed, "kernel child failed:\n{text}");
}
