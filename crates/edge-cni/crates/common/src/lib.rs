//! Map layouts shared by the BPF programs and the daemon: #[repr(C)], explicit
//! padding, and service addresses/ports in network byte order as `sock_addr`
//! presents them, so the BPF side never byte-swaps.

#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceKey {
    pub addr: u32,
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

// A ServiceKey with this address matches every address in NODE_ADDRS.
pub const ANY_NODE_ADDR: u32 = 0;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceVal {
    pub id: u32,
    pub backend_count: u32,
    pub affinity_secs: u32,
}

// A netns is one client address: a pod's own, or the node's for host processes,
// and sock_addr hooks run before the source is chosen.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffinityKey {
    pub netns: u64,
    pub service: ServiceKey,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Affinity {
    pub last_used_ns: u64,
    pub backend: BackendVal,
    pub slot: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendKey {
    pub id: u32,
    pub slot: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendVal {
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevNatKey {
    pub cookie: u64,
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RevNat {
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_SCTP: u8 = 132;

pub const MAX_RANGES: usize = 8;

pub const FLAG_INGRESS_ISOLATED: u32 = 1;
pub const FLAG_EGRESS_ISOLATED: u32 = 2;

pub const DIR_INGRESS: u8 = 0;
pub const DIR_EGRESS: u8 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodVal {
    pub ip: u32,
    pub flags: u32,
}

// Everything before `peer` is matched exactly by the LPM trie.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowKey {
    pub subject: u32,
    pub dir: u8,
    // Scalars, not an array: an array compiles to a memset the BPF backend refuses.
    pub _pad1: u8,
    pub _pad2: u16,
    pub peer: u32,
}

pub const ALLOW_EXACT_BITS: u32 = 64;

// Host byte order.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
    pub proto: u8,
    pub _pad1: u8,
    pub _pad2: u16,
}

impl PortRange {
    pub const NONE: PortRange = PortRange {
        lo: 0,
        hi: 0,
        proto: 0,
        _pad1: 0,
        _pad2: 0,
    };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowVal {
    pub n: u32,
    pub ranges: [PortRange; MAX_RANGES],
}

// Host byte order ports.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtKey {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub _pad1: u8,
    pub _pad2: u16,
}

pub const IPPROTO_UDP: u8 = 17;

// `::ffff:0:0/96`'s third word as `sock_addr`'s user_ip6 holds it.
const V4_MAPPED_WORD: u32 = u32::from_ne_bytes([0, 0, 0xff, 0xff]);

/// The IPv4 address inside `::ffff:a.b.c.d`, as user_ip4 would hold it: dual-stack
/// sockets reach IPv4 peers through the IPv6 hooks with these.
#[inline(always)]
pub fn v4_mapped(ip6: [u32; 4]) -> Option<u32> {
    // Word by word: a slice compare is a bcmp the BPF backend cannot emit.
    if ip6[0] == 0 && ip6[1] == 0 && ip6[2] == V4_MAPPED_WORD {
        Some(ip6[3])
    } else {
        None
    }
}

#[inline(always)]
pub fn set_v4_mapped(ip6: &mut [u32; 4], addr: u32) {
    ip6[3] = addr;
}

#[cfg(feature = "user")]
mod user {
    use super::*;
    // SAFETY: #[repr(C)], explicit padding, every bit pattern valid.
    unsafe impl aya::Pod for ServiceKey {}
    unsafe impl aya::Pod for ServiceVal {}
    unsafe impl aya::Pod for AffinityKey {}
    unsafe impl aya::Pod for Affinity {}
    unsafe impl aya::Pod for BackendKey {}
    unsafe impl aya::Pod for BackendVal {}
    unsafe impl aya::Pod for RevNat {}
    unsafe impl aya::Pod for RevNatKey {}
    unsafe impl aya::Pod for PodVal {}
    unsafe impl aya::Pod for AllowKey {}
    unsafe impl aya::Pod for PortRange {}
    unsafe impl aya::Pod for AllowVal {}
    unsafe impl aya::Pod for CtKey {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn no_implicit_padding() {
        assert_eq!(size_of::<ServiceKey>(), 8);
        assert_eq!(size_of::<ServiceVal>(), 12);
        assert_eq!(size_of::<AffinityKey>(), 16);
        assert_eq!(size_of::<Affinity>(), 24);
        assert_eq!(size_of::<BackendKey>(), 8);
        assert_eq!(size_of::<BackendVal>(), 8);
        assert_eq!(size_of::<RevNatKey>(), 16);
        assert_eq!(align_of::<RevNatKey>(), 8);
        assert_eq!(size_of::<RevNat>(), 8);
        assert_eq!(size_of::<PodVal>(), 8);
        assert_eq!(size_of::<AllowKey>(), 12);
        assert_eq!(size_of::<PortRange>(), 8);
        assert_eq!(size_of::<AllowVal>(), 4 + 8 * MAX_RANGES);
        assert_eq!(size_of::<CtKey>(), 16);
        assert_eq!(
            ALLOW_EXACT_BITS as usize / 8,
            core::mem::offset_of!(AllowKey, peer)
        );
    }

    extern crate std;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn words(ip: Ipv6Addr) -> [u32; 4] {
        let o = ip.octets();
        core::array::from_fn(|i| u32::from_ne_bytes(o[i * 4..i * 4 + 4].try_into().unwrap()))
    }

    fn user_ip4(ip: Ipv4Addr) -> u32 {
        u32::from_ne_bytes(ip.octets())
    }

    #[test]
    fn v4_mapped_yields_the_ipv4_address() {
        let ip = Ipv4Addr::new(10, 96, 0, 1);
        assert_eq!(v4_mapped(words(ip.to_ipv6_mapped())), Some(user_ip4(ip)));
        assert_eq!(
            v4_mapped(words(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped())),
            Some(0)
        );
    }

    #[test]
    fn genuine_ipv6_is_not_v4_mapped() {
        for ip in [
            "::1",
            "::",
            "::10.96.0.1",
            "::ffff:0:10.96.0.1",
            "64:ff9b::10.96.0.1",
            "fd00::ffff:a60:1",
            "0:0:1::ffff:a60:1",
            "2001:db8::ffff:a60:1",
            "ffff::ffff:a60:1",
        ] {
            assert_eq!(v4_mapped(words(ip.parse().unwrap())), None, "{ip}");
        }
    }

    #[test]
    fn set_v4_mapped_keeps_it_mapped() {
        let backend = Ipv4Addr::new(10, 244, 0, 7);
        let mut ip6 = words(Ipv4Addr::new(10, 96, 0, 1).to_ipv6_mapped());
        set_v4_mapped(&mut ip6, user_ip4(backend));
        assert_eq!(ip6, words(backend.to_ipv6_mapped()));
        assert_eq!(v4_mapped(ip6), Some(user_ip4(backend)));
    }
}
