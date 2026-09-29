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
}
