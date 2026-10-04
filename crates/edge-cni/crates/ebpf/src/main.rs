//! Service resolution at the syscall (cgroup sock_addr at the root cgroup) and
//! NetworkPolicy on pod veths (tcx).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    helpers::{
        bpf_get_netns_cookie, bpf_get_prandom_u32, bpf_get_socket_cookie, bpf_ktime_get_boot_ns,
        bpf_set_retval,
    },
    macros::{cgroup_sock_addr, classifier, map},
    maps::{Array, HashMap, LpmTrie, LruHashMap, lpm_trie::Key},
    programs::{SockAddrContext, TcContext},
};
use edge_cni_common::{
    ALLOW_EXACT_BITS, ANY_NODE_ADDR, Affinity, AffinityKey, AllowKey, AllowVal, BackendKey,
    BackendVal, CtKey, DIR_EGRESS, DIR_INGRESS, FLAG_EGRESS_ISOLATED, FLAG_INGRESS_ISOLATED,
    IPPROTO_ICMP, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP, MAX_RANGES, PodVal, RevNat, RevNatKey,
    ServiceKey, ServiceVal, set_v4_mapped, v4_mapped,
};

// NO_PREALLOC: only userspace writes these, so entries are allocated on insert.
// LRU maps cannot be NO_PREALLOC (ENOTSUPP).
#[map]
static SERVICES: HashMap<ServiceKey, ServiceVal> = HashMap::pinned(4096, BPF_F_NO_PREALLOC);

#[map]
static BACKENDS: HashMap<BackendKey, BackendVal> = HashMap::pinned(16384, BPF_F_NO_PREALLOC);

// LRU: a socket that never receives again must not hold its entry forever.
#[map]
static REVNAT: LruHashMap<RevNatKey, RevNat> = LruHashMap::pinned(4096, 0);

#[map]
static NODE_ADDRS: HashMap<u32, u8> = HashMap::pinned(256, BPF_F_NO_PREALLOC);

#[map]
static HOSTPORTS: HashMap<ServiceKey, BackendVal> = HashMap::pinned(1024, BPF_F_NO_PREALLOC);

#[map]
static AFFINITY: LruHashMap<AffinityKey, Affinity> = LruHashMap::pinned(16384, 0);

enum Resolved {
    NotAService,
    NoBackends,
    Backend(ServiceKey, BackendVal),
}

enum Target {
    Service(ServiceKey, ServiceVal),
    HostPort(BackendVal),
}

const ECONNREFUSED: i32 = 111;

#[inline(always)]
fn target(key: &ServiceKey) -> Option<Target> {
    if let Some(svc) = unsafe { SERVICES.get(key) } {
        return Some(Target::Service(*key, *svc));
    }
    if let Some(backend) = unsafe { HOSTPORTS.get(key) } {
        return Some(Target::HostPort(*backend));
    }
    None
}

/// `sticky` picks the backend by socket cookie rather than at random: unconnected
/// UDP resolves every datagram, and one socket's datagrams must stay one flow.
/// `addr` is the destination as user_ip4 holds it; the caller rewrites it.
#[inline(always)]
fn resolve(ctx: &SockAddrContext, addr: u32, proto: u8, sticky: bool) -> Resolved {
    let key = ServiceKey {
        addr,
        // A u32 holding a be16 in its low half.
        port: (unsafe { (*ctx.sock_addr).user_port } & 0xffff) as u16,
        proto,
        _pad: 0,
    };
    let found = match target(&key) {
        Some(t) => Some(t),
        None if unsafe { NODE_ADDRS.get(key.addr) }.is_some() => target(&ServiceKey {
            addr: ANY_NODE_ADDR,
            ..key
        }),
        None => None,
    };
    let backend = match found {
        None => return Resolved::NotAService,
        Some(Target::HostPort(backend)) => backend,
        Some(Target::Service(svc_key, svc)) => {
            // Passed through, the call would go to the ClusterIP itself, which nothing
            // answers: a connect would hang for its whole timeout instead of failing.
            if svc.backend_count == 0 {
                return Resolved::NoBackends;
            }
            match pick(ctx, &svc_key, &svc, sticky) {
                Some(backend) => backend,
                // A count ahead of its slots is a transient mid-update: do not refuse.
                None => return Resolved::NotAService,
            }
        }
    };
    unsafe { (*ctx.sock_addr).user_port = backend.port as u32 };
    Resolved::Backend(key, backend)
}

#[inline(always)]
fn pick(
    ctx: &SockAddrContext,
    svc_key: &ServiceKey,
    svc: &ServiceVal,
    sticky: bool,
) -> Option<BackendVal> {
    let sel: u64 = if sticky {
        unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) }
    } else {
        unsafe { bpf_get_prandom_u32() as u64 }
    };
    let slot = (sel % svc.backend_count as u64) as u32;
    if svc.affinity_secs == 0 {
        return unsafe { BACKENDS.get(BackendKey { id: svc.id, slot }) }.copied();
    }
    let key = AffinityKey {
        netns: unsafe { bpf_get_netns_cookie(ctx.sock_addr as *mut _) },
        service: *svc_key,
    };
    let now = unsafe { bpf_ktime_get_boot_ns() };
    if let Some(pinned) = AFFINITY.get_ptr_mut(key) {
        let pinned = unsafe { &mut *pinned };
        let timeout_ns = svc.affinity_secs as u64 * 1_000_000_000;
        let fresh = now.wrapping_sub(pinned.last_used_ns) < timeout_ns;
        if fresh && pinned.slot < svc.backend_count {
            // Endpoint changes can move another backend into the pinned slot.
            let same = unsafe {
                BACKENDS.get(BackendKey {
                    id: svc.id,
                    slot: pinned.slot,
                })
            };
            if let Some(backend) = same
                && *backend == pinned.backend
            {
                pinned.last_used_ns = now;
                return Some(*backend);
            }
        }
    }
    let backend = *unsafe { BACKENDS.get(BackendKey { id: svc.id, slot }) }?;
    let pinned = Affinity {
        last_used_ns: now,
        backend,
        slot,
        _pad: 0,
    };
    let _ = AFFINITY.insert(key, pinned, 0);
    Some(backend)
}

/// Returning 0 alone surfaces as EPERM; callers retry on ECONNREFUSED.
#[inline(always)]
fn refuse() -> i32 {
    unsafe { bpf_set_retval(-ECONNREFUSED) };
    0
}

/// Returns the backend for the caller to write in, or None to pass the call.
#[inline(always)]
fn connect(ctx: &SockAddrContext, addr: u32) -> Result<Option<u32>, i32> {
    let proto = unsafe { (*ctx.sock_addr).protocol } as u8;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok(None);
    }
    match resolve(ctx, addr, proto, false) {
        Resolved::Backend(_, backend) => Ok(Some(backend.addr)),
        Resolved::NoBackends => Err(refuse()),
        Resolved::NotAService => Ok(None),
    }
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    match connect(&ctx, sock_addr.user_ip4) {
        Ok(Some(backend)) => sock_addr.user_ip4 = backend,
        Ok(None) => {}
        Err(verdict) => return verdict,
    }
    1
}

// Dual-stack sockets dial IPv4 as `::ffff:a.b.c.d`; genuine IPv6 passes untouched.
#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    let Some(addr) = v4_mapped(sock_addr.user_ip6) else {
        return 1;
    };
    match connect(&ctx, addr) {
        Ok(Some(backend)) => set_v4_mapped(&mut sock_addr.user_ip6, backend),
        Ok(None) => {}
        Err(verdict) => return verdict,
    }
    1
}

// A dual-stack socket's datagram to `::ffff:a.b.c.d` is sent as IPv4, through
// this hook: the kernel never runs sendmsg6 on a mapped address.
#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    match resolve(&ctx, sock_addr.user_ip4, IPPROTO_UDP, true) {
        Resolved::Backend(orig, backend) => {
            sock_addr.user_ip4 = backend.addr;
            let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
            // The backend is the source recvmsg will see.
            let key = RevNatKey {
                cookie,
                addr: backend.addr,
                port: backend.port,
                _pad: 0,
            };
            let rev = RevNat {
                addr: orig.addr,
                port: orig.port,
                _pad: 0,
            };
            let _ = REVNAT.insert(key, rev, 0);
            1
        }
        Resolved::NoBackends => refuse(),
        Resolved::NotAService => 1,
    }
}

/// `addr` is the datagram's source as user_ip4 holds it; user_port is rewritten.
#[inline(always)]
fn reverse(ctx: &SockAddrContext, addr: u32) -> Option<u32> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    let key = RevNatKey {
        cookie: unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) },
        addr,
        port: (sock_addr.user_port & 0xffff) as u16,
        _pad: 0,
    };
    let rev = unsafe { REVNAT.get(key) }?;
    sock_addr.user_port = rev.port as u32;
    Some(rev.addr)
}

// Resolvers drop replies whose source is not the address they sent to.
#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    if let Some(addr) = reverse(&ctx, sock_addr.user_ip4) {
        sock_addr.user_ip4 = addr;
    }
    1
}

// A dual-stack socket sees an IPv4 reply's source as `::ffff:a.b.c.d`.
#[cgroup_sock_addr(recvmsg6)]
pub fn recvmsg6(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &mut *ctx.sock_addr };
    if let Some(addr) = v4_mapped(sock_addr.user_ip6)
        && let Some(orig) = reverse(&ctx, addr)
    {
        set_v4_mapped(&mut sock_addr.user_ip6, orig);
    }
    1
}

#[map]
static NP_ARMED: Array<u32> = Array::pinned(1, 0);

#[map]
static NP_PODS: HashMap<u32, PodVal> = HashMap::pinned(1024, 0);

#[map]
static NP_POD_IPS: HashMap<u32, u32> = HashMap::pinned(1024, 0);

// Userspace pushes covering prefixes' ports down, so the longest match is complete.
#[map]
static NP_ALLOW: LpmTrie<AllowKey, AllowVal> = LpmTrie::pinned(32768, 0);

#[map]
static NP_CT: LruHashMap<CtKey, u8> = LruHashMap::pinned(8192, 0);

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

struct Pkt {
    saddr: u32,
    daddr: u32,
    proto: u8,
    sport: u16,
    dport: u16,
    later_fragment: bool,
}

#[inline(always)]
fn parse(ctx: &TcContext) -> Option<Pkt> {
    let ethertype: u16 = ctx.load(12).ok()?;
    if u16::from_be(ethertype) != 0x0800 {
        return None; // ARP (the pods' gateway is proxy ARP), IPv6
    }
    let vihl: u8 = ctx.load(14).ok()?;
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let frag: u16 = ctx.load(14 + 6).ok()?;
    let proto: u8 = ctx.load(14 + 9).ok()?;
    let saddr: u32 = ctx.load(14 + 12).ok()?;
    let daddr: u32 = ctx.load(14 + 16).ok()?;
    let later_fragment = u16::from_be(frag) & 0x1fff != 0;
    let (mut sport, mut dport) = (0u16, 0u16);
    if !later_fragment && (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP) {
        let l4 = 14 + ihl;
        let s: u16 = ctx.load(l4).ok()?;
        let d: u16 = ctx.load(l4 + 2).ok()?;
        sport = u16::from_be(s);
        dport = u16::from_be(d);
    }
    Some(Pkt {
        saddr,
        daddr,
        proto,
        sport,
        dport,
        later_fragment,
    })
}

#[inline(always)]
fn forward_key(p: &Pkt) -> CtKey {
    CtKey {
        saddr: p.saddr,
        daddr: p.daddr,
        sport: p.sport,
        dport: p.dport,
        proto: p.proto,
        _pad1: 0,
        _pad2: 0,
    }
}

#[inline(always)]
fn reverse_key(p: &Pkt) -> CtKey {
    CtKey {
        saddr: p.daddr,
        daddr: p.saddr,
        sport: p.dport,
        dport: p.sport,
        proto: p.proto,
        _pad1: 0,
        _pad2: 0,
    }
}

#[inline(always)]
fn ct_remember(p: &Pkt) {
    let k = forward_key(p);
    if unsafe { NP_CT.get(k) }.is_none() {
        let _ = NP_CT.insert(k, 1, 0);
    }
}

#[inline(always)]
fn allowed(subject: u32, dir: u8, peer: u32, proto: u8, port: u16) -> bool {
    let key = Key::new(
        ALLOW_EXACT_BITS + 32,
        AllowKey {
            subject,
            dir,
            _pad1: 0,
            _pad2: 0,
            peer,
        },
    );
    let Some(val) = NP_ALLOW.get(&key) else {
        return false;
    };
    let n = val.n as usize;
    let mut i = 0;
    while i < MAX_RANGES {
        if i >= n {
            break;
        }
        let r = &val.ranges[i];
        if r.proto == proto && port >= r.lo && port <= r.hi {
            return true;
        }
        i += 1;
    }
    false
}

#[inline(always)]
fn np_decide(ctx: &TcContext, to_pod: bool) -> i32 {
    match NP_ARMED.get(0) {
        Some(1) => {}
        _ => return TC_ACT_OK,
    }
    let Some(p) = parse(ctx) else {
        return TC_ACT_OK;
    };
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let Some(pod) = (unsafe { NP_PODS.get(ifindex) }) else {
        return TC_ACT_OK;
    };
    if p.proto == IPPROTO_ICMP || p.later_fragment {
        return TC_ACT_OK;
    }

    if !to_pod {
        // Rules name addresses, so a pod may only send as itself.
        if p.saddr != pod.ip {
            return TC_ACT_SHOT;
        }
        let dst_is_pod = unsafe { NP_POD_IPS.get(p.daddr) }.is_some();
        if pod.flags & FLAG_EGRESS_ISOLATED != 0 {
            let reply = unsafe { NP_CT.get(reverse_key(&p)) }.is_some();
            if !reply && !allowed(pod.ip, DIR_EGRESS, p.daddr, p.proto, p.dport) {
                return TC_ACT_SHOT;
            }
        }
        // Off-node peers have no hook of ours to note the flow. A pod peer notes
        // it at its own hook, after its ingress policy: noting it here would let
        // a refused connection's peer talk back.
        if !dst_is_pod && pod.flags & FLAG_INGRESS_ISOLATED != 0 {
            ct_remember(&p);
        }
        return TC_ACT_OK;
    }

    // Node-originated packets (kubelet probes) always pass.
    let from_node = unsafe { (*ctx.skb.skb).ingress_ifindex } == 0;
    if !from_node && pod.flags & FLAG_INGRESS_ISOLATED != 0 {
        let reply = unsafe { NP_CT.get(reverse_key(&p)) }.is_some();
        if !reply && !allowed(pod.ip, DIR_INGRESS, p.saddr, p.proto, p.dport) {
            return TC_ACT_SHOT;
        }
    }
    // Noted after ingress policy: this pod's egress hook needs every admitted flow,
    // whatever the peer (DNAT keeps an off-node client's address).
    let src_ingress_isolated = match unsafe { NP_POD_IPS.get(p.saddr) } {
        Some(src_ifindex) => match unsafe { NP_PODS.get(src_ifindex) } {
            Some(sp) => sp.flags & FLAG_INGRESS_ISOLATED != 0,
            None => false,
        },
        None => false,
    };
    if pod.flags & FLAG_EGRESS_ISOLATED != 0 || src_ingress_isolated {
        ct_remember(&p);
    }
    TC_ACT_OK
}

#[classifier]
pub fn np_from_pod(ctx: TcContext) -> i32 {
    np_decide(&ctx, false)
}

#[classifier]
pub fn np_to_pod(ctx: TcContext) -> i32 {
    np_decide(&ctx, true)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
