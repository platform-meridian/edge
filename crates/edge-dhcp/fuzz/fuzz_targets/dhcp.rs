#![no_main]

use std::net::Ipv4Addr;
use std::time::Instant;

use edge_dhcp::Subnet;
use edge_dhcp::dhcp::Server;
use edge_dhcp::wire::{Kind, decode};
use libfuzzer_sys::fuzz_target;

const SUBNET: Subnet = Subnet {
    addr: Ipv4Addr::new(10, 51, 0, 1),
    prefix: 24,
};

fuzz_target!(|data: &[u8]| {
    let Some(req) = decode(data) else { return };
    let mut server = Server::new(SUBNET, Some("example.test".into()));
    let now = Instant::now();
    // Twice: the second answer sees the state the first left.
    for _ in 0..2 {
        let Some((reply, _)) = server.handle(&req, now) else {
            continue;
        };
        assert!(matches!(reply.kind, Kind::Offer | Kind::Ack | Kind::Nak));
        assert!(reply.yiaddr.is_unspecified() || SUBNET.in_pool(reply.yiaddr));
        let b = reply.encode();
        assert!((300..=576).contains(&b.len()), "{} bytes", b.len());
        assert_eq!(b[0], 2);
        assert_eq!(b[4..8], data[4..8]);
        assert_eq!(b[28..28 + usize::from(b[2])], req.chaddr[..]);
    }
});
