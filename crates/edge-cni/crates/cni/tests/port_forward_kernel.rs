use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use common::{lo_up, make_pod, new_netns, on_ns, rt, seen_as};
use edge_cni::netlink::Net;
use edge_cni::nft::{self, Forward, Outcome};
use rtnetlink::RouteMessageBuilder;

mod common;

const NODE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const SECOND_NODE_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const POD_NET: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 244, 0, 0), 24);
const TCP: u8 = 6;
const UDP: u8 = 17;

fn serve(ns: &File, pod: Ipv4Addr) {
    on_ns(ns, || {
        let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).unwrap();
        std::thread::spawn(move || {
            for mut s in tcp.incoming().flatten() {
                // Closing with the probe's bytes unread would reset the connection.
                let _ = s.read(&mut [0u8; 4]);
                let _ = s.write_all(pod.to_string().as_bytes());
            }
        });
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 5353)).unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            while let Ok((_, from)) = udp.recv_from(&mut b) {
                let _ = udp.send_to(format!("{pod} {}", from.ip()).as_bytes(), from);
            }
        });
    });
}

fn udp_reply(ns: &File, to: SocketAddr) -> Option<(String, SocketAddr)> {
    on_ns(ns, || {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(700)))
            .unwrap();
        s.send_to(b"x", to).unwrap();
        let mut b = [0u8; 64];
        let (n, from) = s.recv_from(&mut b).ok()?;
        Some((String::from_utf8_lossy(&b[..n]).into_owned(), from))
    })
}

fn forward(proto: u8, addr: Option<Ipv4Addr>, port: u16, backends: &[(Ipv4Addr, u16)]) -> Forward {
    Forward {
        proto,
        addr,
        port,
        backends: backends
            .iter()
            .map(|(ip, port)| SocketAddrV4::new(*ip, *port))
            .collect(),
        affinity: false,
    }
}

// Each probe is a new flow from a fresh source port.
fn udp_backend(ns: &File, from: Ipv4Addr, to: SocketAddr) -> Option<String> {
    on_ns(ns, || {
        let s = UdpSocket::bind((from, 0)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(700)))
            .unwrap();
        s.send_to(b"x", to).unwrap();
        let mut b = [0u8; 64];
        let n = s.recv(&mut b).ok()?;
        let reply = String::from_utf8_lossy(&b[..n]).into_owned();
        let (pod, seen) = reply.split_once(' ')?;
        assert_eq!(seen, from.to_string(), "the pod sees the client");
        Some(pod.to_string())
    })
}

fn reached(ext: &File, to: SocketAddr, tries: usize) -> BTreeSet<Option<String>> {
    (0..tries).map(|_| seen_as(Some(ext), to)).collect()
}

fn ensure(forwards: Option<&[Forward]>) -> Outcome {
    nft::ensure(POD_NET.0, POD_NET.1, forwards).unwrap()
}

fn kernel_child() {
    lo_up();
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").unwrap();
    rt().block_on(async {
        let net = Net::open().unwrap();
        net.add_addr("lo", SECOND_NODE_ADDR, 32).await.unwrap();
        // Proxy ARP answers the gateway only if it is routable elsewhere.
        net.add_addr("lo", "169.254.1.1".parse().unwrap(), 32)
            .await
            .unwrap();
    });
    let ext = new_netns();
    rt().block_on(async {
        let net = Net::open().unwrap();
        net.create_veth("up0", "upx", 1500).await.unwrap();
        net.move_to_netns("upx", ext.as_raw_fd()).await.unwrap();
        net.set_up("up0").await.unwrap();
        net.add_addr("up0", NODE, 24).await.unwrap();
        let local = net.local_addrs().await.unwrap();
        for addr in [Ipv4Addr::LOCALHOST, NODE, SECOND_NODE_ADDR] {
            assert!(local.contains(&addr), "{addr} in {local:?}");
        }
    });
    on_ns(&ext, || {
        rt().block_on(async {
            let net = Net::open().unwrap();
            net.set_up("upx").await.unwrap();
            net.set_up("lo").await.unwrap();
            net.add_addr("upx", CLIENT, 24).await.unwrap();
            let via_node = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(SECOND_NODE_ADDR, 32)
                .gateway(NODE)
                .build();
            net.handle.route().add(via_node).execute().await.unwrap();
        });
    });

    let a = make_pod("10.244.0.1".parse().unwrap(), 1, &[]);
    let b = make_pod("10.244.0.2".parse().unwrap(), 2, &[]);
    serve(&a.ns, a.ip);
    serve(&b.ns, b.ip);
    let node_port = SocketAddr::from((NODE, 30080));
    assert_eq!(seen_as(Some(&ext), node_port), None, "nothing forwards yet");

    let forwards = [
        forward(TCP, None, 30080, &[(a.ip, 8080), (b.ip, 8080)]),
        forward(TCP, None, 31000, &[(b.ip, 8080)]),
        forward(TCP, Some(NODE), 31000, &[(a.ip, 8080)]),
        forward(UDP, Some(NODE), 30053, &[(a.ip, 5353)]),
    ];
    assert_eq!(ensure(Some(&forwards)), Outcome::Installed);
    assert_eq!(
        ensure(Some(&forwards)),
        Outcome::Present,
        "the kernel's dump decodes to what was installed"
    );

    assert_eq!(
        reached(&ext, node_port, 40),
        BTreeSet::from([Some(a.ip.to_string()), Some(b.ip.to_string())]),
        "a node port spreads over its backends, and every connection lands"
    );
    assert_eq!(
        seen_as(Some(&ext), SocketAddr::from((NODE, 31000))),
        Some(a.ip.to_string()),
        "the addressed host port wins over the wildcard on its own address"
    );
    assert_eq!(
        seen_as(Some(&ext), SocketAddr::from((SECOND_NODE_ADDR, 31000))),
        Some(b.ip.to_string()),
        "the wildcard answers on every other node address"
    );
    assert!(seen_as(Some(&ext), SocketAddr::from((SECOND_NODE_ADDR, 30080))).is_some());
    let udp = SocketAddr::from((NODE, 30053));
    assert_eq!(
        udp_reply(&ext, udp),
        Some((format!("{} {CLIENT}", a.ip), udp)),
        "UDP reaches the pod with the client's address and replies from the node port"
    );

    assert_eq!(
        ensure(None),
        Outcome::Present,
        "unknown forwards keep the installed ones"
    );
    assert!(seen_as(Some(&ext), node_port).is_some());

    assert_eq!(ensure(Some(&forwards[1..])), Outcome::Installed);
    assert_eq!(
        seen_as(Some(&ext), node_port),
        None,
        "a removed node port stops forwarding"
    );
    assert_eq!(nft::installed().unwrap().chains.len(), 2);

    nft::remove().unwrap();
    assert_eq!(
        ensure(None),
        Outcome::Installed,
        "wiped: masquerade comes back"
    );
    assert_eq!(nft::installed().unwrap().rules.len(), 1);
    assert_eq!(ensure(Some(&forwards)), Outcome::Installed);
    assert!(seen_as(Some(&ext), node_port).is_some(), "repaired");

    let clients: Vec<Ipv4Addr> = (10..30).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect();
    on_ns(&ext, || {
        rt().block_on(async {
            let net = Net::open().unwrap();
            for c in &clients {
                net.add_addr("upx", *c, 24).await.unwrap();
            }
        })
    });
    let sticky = Forward {
        affinity: true,
        ..forward(UDP, None, 30054, &[(a.ip, 5353), (b.ip, 5353)])
    };
    let forwards = [forwards[0].clone(), sticky];
    assert_eq!(ensure(Some(&forwards)), Outcome::Installed);
    assert_eq!(
        ensure(Some(&forwards)),
        Outcome::Present,
        "the kernel's dump of a hashed rule decodes to what was installed"
    );
    let sticky_port = SocketAddr::from((NODE, 30054));
    let mut landed = BTreeSet::new();
    for c in &clients {
        let seen: BTreeSet<Option<String>> =
            (0..5).map(|_| udp_backend(&ext, *c, sticky_port)).collect();
        assert_eq!(seen.len(), 1, "{c} stays on one backend: {seen:?}");
        landed.extend(seen);
    }
    assert_eq!(
        landed,
        BTreeSet::from([Some(a.ip.to_string()), Some(b.ip.to_string())]),
        "clients spread over the backends"
    );
}

#[test]
fn node_and_host_ports_forwarded() {
    let Some((passed, text)) = common::in_user_netns("node_and_host_ports_forwarded", kernel_child)
    else {
        return;
    };
    assert!(passed, "kernel child failed:\n{text}");
}
