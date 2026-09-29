//! Service DNAT has already happened at connect(), so the veth hooks see pod
//! addresses and target ports. Replies pass via `NP_CT`, recorded at the last hook
//! an allowed flow crosses so a refused connection's peer cannot answer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use anyhow::Context;
use aya::programs::tc::SchedClassifierLink;
use aya::programs::{SchedClassifier, TcAttachType};
use edge_cni_common::{
    ALLOW_EXACT_BITS, AllowKey, AllowVal, DIR_EGRESS, DIR_INGRESS, FLAG_EGRESS_ISOLATED,
    FLAG_INGRESS_ISOLATED, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP, MAX_RANGES, PodVal, PortRange,
};
use edge_kube::policy::{Allow, Ipv4Net, PodPolicy, Proto};

use crate::services::absent_is_fine;

fn proto_number(p: Proto) -> u8 {
    match p {
        Proto::Tcp => IPPROTO_TCP,
        Proto::Udp => IPPROTO_UDP,
        Proto::Sctp => IPPROTO_SCTP,
    }
}

fn covers(outer: Ipv4Net, inner: Ipv4Net) -> bool {
    outer.prefix <= inner.prefix && outer.contains(inner.address())
}

pub fn allow_key(subject: Ipv4Addr, dir: u8, peer: Ipv4Net) -> (u32, AllowKey) {
    (
        ALLOW_EXACT_BITS + peer.prefix as u32,
        AllowKey {
            subject: u32::from(subject).to_be(),
            dir,
            _pad1: 0,
            _pad2: 0,
            peer: peer.addr.to_be(),
        },
    )
}

fn coalesce(mut ranges: Vec<(u8, u16, u16)>) -> Vec<(u8, u16, u16)> {
    ranges.sort();
    let mut out: Vec<(u8, u16, u16)> = Vec::new();
    for (proto, lo, hi) in ranges {
        match out.last_mut() {
            Some((p, _, h)) if *p == proto && (lo as u32) <= (*h as u32) + 1 => *h = (*h).max(hi),
            _ => out.push((proto, lo, hi)),
        }
    }
    out
}

// A longest-prefix lookup returns one entry, so each prefix carries the ports of
// every prefix covering it.
pub fn lower_rules(rules: &[Allow]) -> (BTreeMap<Ipv4Net, AllowVal>, usize) {
    let peers: BTreeSet<Ipv4Net> = rules.iter().map(|r| r.peer).collect();
    let mut out = BTreeMap::new();
    let mut dropped = 0;
    for peer in peers {
        let ranges = coalesce(
            rules
                .iter()
                .filter(|r| covers(r.peer, peer))
                .map(|r| (proto_number(r.proto), r.lo, r.hi))
                .collect(),
        );
        let mut val = AllowVal {
            n: 0,
            ranges: [PortRange::NONE; MAX_RANGES],
        };
        for (i, (proto, lo, hi)) in ranges.iter().enumerate() {
            if i >= MAX_RANGES {
                // Dropping a range REFUSES traffic the policy allows; widening
                // would ADMIT traffic it does not. Refuse, and say so.
                dropped += ranges.len() - MAX_RANGES;
                break;
            }
            val.ranges[i] = PortRange {
                lo: *lo,
                hi: *hi,
                proto: *proto,
                _pad1: 0,
                _pad2: 0,
            };
            val.n += 1;
        }
        out.insert(peer, val);
    }
    (out, dropped)
}

#[derive(Debug, Default, PartialEq)]
pub struct Desired {
    pub pods: BTreeMap<u32, PodVal>,
    pub pod_ips: BTreeMap<u32, u32>,
    pub allow: BTreeMap<(u32, [u8; 12]), (AllowKey, AllowVal)>,
    pub armed: bool,
    pub dropped_ranges: usize,
}

pub(crate) fn key_bytes(k: &AllowKey) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&k.subject.to_ne_bytes());
    b[4] = k.dir;
    b[8..12].copy_from_slice(&k.peer.to_ne_bytes());
    b
}

// An attached pod the API has not described is unrestricted.
pub fn lower(
    compiled: &BTreeMap<Ipv4Addr, PodPolicy>,
    attached: &BTreeMap<u32, Ipv4Addr>,
) -> Desired {
    let mut d = Desired::default();
    for (&ifindex, &ip) in attached {
        let policy = compiled.get(&ip);
        let mut flags = 0;
        if policy.is_some_and(|p| p.ingress.is_some()) {
            flags |= FLAG_INGRESS_ISOLATED;
        }
        if policy.is_some_and(|p| p.egress.is_some()) {
            flags |= FLAG_EGRESS_ISOLATED;
        }
        d.armed |= flags != 0;
        let be = u32::from(ip).to_be();
        d.pods.insert(ifindex, PodVal { ip: be, flags });
        d.pod_ips.insert(be, ifindex);
        let Some(policy) = policy else { continue };
        for (dir, rules) in [(DIR_INGRESS, &policy.ingress), (DIR_EGRESS, &policy.egress)] {
            let Some(rules) = rules else { continue };
            let (entries, dropped) = lower_rules(rules);
            d.dropped_ranges += dropped;
            for (peer, val) in entries {
                let (bits, key) = allow_key(ip, dir, peer);
                d.allow.insert((bits, key_bytes(&key)), (key, val));
            }
        }
    }
    d
}

// Deleting an absent key is Ok.
pub trait PolicyMaps {
    fn dump_pods(&self) -> anyhow::Result<Vec<(u32, PodVal)>>;
    fn dump_pod_ips(&self) -> anyhow::Result<Vec<(u32, u32)>>;
    fn dump_allow(&self) -> anyhow::Result<Vec<(u32, AllowKey, AllowVal)>>;
    fn armed(&self) -> anyhow::Result<bool>;
    fn put_pod(&mut self, ifindex: u32, v: &PodVal) -> anyhow::Result<()>;
    fn del_pod(&mut self, ifindex: u32) -> anyhow::Result<()>;
    fn put_pod_ip(&mut self, ip: u32, ifindex: u32) -> anyhow::Result<()>;
    fn del_pod_ip(&mut self, ip: u32) -> anyhow::Result<()>;
    fn put_allow(&mut self, bits: u32, k: &AllowKey, v: &AllowVal) -> anyhow::Result<()>;
    fn del_allow(&mut self, bits: u32, k: &AllowKey) -> anyhow::Result<()>;
    fn set_armed(&mut self, on: bool) -> anyhow::Result<()>;
}

// Ordered so no hook sees a pod flagged isolated before its rules exist: disarm
// first, rules, addresses, pods, removals, arm last.
pub fn reconcile<M: PolicyMaps>(maps: &mut M, want: &Desired) -> anyhow::Result<usize> {
    let mut writes = 0;
    if !want.armed && maps.armed()? {
        maps.set_armed(false).context("disarm")?;
        writes += 1;
    }

    let have_allow: BTreeMap<(u32, [u8; 12]), (AllowKey, AllowVal)> = maps
        .dump_allow()
        .context("read NP_ALLOW")?
        .into_iter()
        .map(|(bits, k, v)| ((bits, key_bytes(&k)), (k, v)))
        .collect();
    for ((bits, kb), (k, v)) in &want.allow {
        if have_allow.get(&(*bits, *kb)).map(|(_, hv)| hv) != Some(v) {
            maps.put_allow(*bits, k, v).context("write NP_ALLOW")?;
            writes += 1;
        }
    }

    let have_ips: BTreeMap<u32, u32> = maps
        .dump_pod_ips()
        .context("read NP_POD_IPS")?
        .into_iter()
        .collect();
    for (ip, ifx) in &want.pod_ips {
        if have_ips.get(ip) != Some(ifx) {
            maps.put_pod_ip(*ip, *ifx).context("write NP_POD_IPS")?;
            writes += 1;
        }
    }
    let have_pods: BTreeMap<u32, PodVal> = maps
        .dump_pods()
        .context("read NP_PODS")?
        .into_iter()
        .collect();
    for (ifx, v) in &want.pods {
        if have_pods.get(ifx) != Some(v) {
            maps.put_pod(*ifx, v).context("write NP_PODS")?;
            writes += 1;
        }
    }

    for ifx in have_pods.keys().filter(|i| !want.pods.contains_key(i)) {
        maps.del_pod(*ifx).context("delete from NP_PODS")?;
        writes += 1;
    }
    for ip in have_ips.keys().filter(|i| !want.pod_ips.contains_key(i)) {
        maps.del_pod_ip(*ip).context("delete from NP_POD_IPS")?;
        writes += 1;
    }
    for ((bits, kb), (k, _)) in &have_allow {
        if !want.allow.contains_key(&(*bits, *kb)) {
            maps.del_allow(*bits, k).context("delete from NP_ALLOW")?;
            writes += 1;
        }
    }

    if want.armed && !maps.armed()? {
        maps.set_armed(true).context("arm")?;
        writes += 1;
    }
    Ok(writes)
}

pub struct AyaPolicyMaps {
    pub pods: aya::maps::HashMap<aya::maps::MapData, u32, PodVal>,
    pub pod_ips: aya::maps::HashMap<aya::maps::MapData, u32, u32>,
    pub allow: aya::maps::lpm_trie::LpmTrie<aya::maps::MapData, AllowKey, AllowVal>,
    pub armed: aya::maps::Array<aya::maps::MapData, u32>,
}

impl PolicyMaps for AyaPolicyMaps {
    fn dump_pods(&self) -> anyhow::Result<Vec<(u32, PodVal)>> {
        Ok(self.pods.iter().collect::<Result<_, _>>()?)
    }
    fn dump_pod_ips(&self) -> anyhow::Result<Vec<(u32, u32)>> {
        Ok(self.pod_ips.iter().collect::<Result<_, _>>()?)
    }
    fn dump_allow(&self) -> anyhow::Result<Vec<(u32, AllowKey, AllowVal)>> {
        let mut out = Vec::new();
        for item in self.allow.iter() {
            let (k, v) = item?;
            out.push((k.prefix_len(), k.data(), v));
        }
        Ok(out)
    }
    fn armed(&self) -> anyhow::Result<bool> {
        Ok(self.armed.get(&0, 0)? == 1)
    }
    fn put_pod(&mut self, ifindex: u32, v: &PodVal) -> anyhow::Result<()> {
        Ok(self.pods.insert(&ifindex, v, 0)?)
    }
    fn del_pod(&mut self, ifindex: u32) -> anyhow::Result<()> {
        absent_is_fine(self.pods.remove(&ifindex))
    }
    fn put_pod_ip(&mut self, ip: u32, ifindex: u32) -> anyhow::Result<()> {
        Ok(self.pod_ips.insert(&ip, &ifindex, 0)?)
    }
    fn del_pod_ip(&mut self, ip: u32) -> anyhow::Result<()> {
        absent_is_fine(self.pod_ips.remove(&ip))
    }
    fn put_allow(&mut self, bits: u32, k: &AllowKey, v: &AllowVal) -> anyhow::Result<()> {
        Ok(self
            .allow
            .insert(&aya::maps::lpm_trie::Key::new(bits, *k), v, 0)?)
    }
    fn del_allow(&mut self, bits: u32, k: &AllowKey) -> anyhow::Result<()> {
        absent_is_fine(self.allow.remove(&aya::maps::lpm_trie::Key::new(bits, *k)))
    }
    fn set_armed(&mut self, on: bool) -> anyhow::Result<()> {
        Ok(self.armed.set(0, &(on as u32), 0)?)
    }
}

const HOOKS: [(&str, TcAttachType, &str); 2] = [
    ("np_from_pod", TcAttachType::Ingress, "in"),
    ("np_to_pod", TcAttachType::Egress, "eg"),
];

pub fn hook_suffixes() -> [&'static str; 2] {
    [HOOKS[0].2, HOOKS[1].2]
}

pub fn pin_dir(vdir: &str) -> String {
    format!("{vdir}/np")
}

pub fn load_programs(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    for (name, _, _) in HOOKS {
        let p: &mut SchedClassifier = bpf
            .program_mut(name)
            .with_context(|| format!("no program {name} in the object"))?
            .try_into()?;
        p.load().with_context(|| format!("load {name}"))?;
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct Hooked {
    pub attached: bool,
    // Some hook still runs another version's program.
    pub inherited: bool,
}

// Take another version's hook over only once the maps hold this veth's policy.
pub fn hook_veth(
    bpf: &mut aya::Ebpf,
    vdir: &str,
    ifname: &str,
    take_over: bool,
) -> anyhow::Result<Hooked> {
    std::fs::create_dir_all(pin_dir(vdir)).context("create the link pin directory")?;
    let vdir = std::path::Path::new(vdir);
    let mut hooked = Hooked::default();
    for (name, at, suffix) in HOOKS {
        let rel = format!("np/{ifname}-{suffix}");
        let inherited = crate::pins::is_inherited(vdir, &rel);
        if vdir.join(&rel).exists() && !inherited {
            continue;
        }
        if inherited && !take_over {
            hooked.inherited = true;
            continue;
        }
        let p: &mut SchedClassifier = bpf
            .program_mut(name)
            .with_context(|| format!("no program {name} in the object"))?
            .try_into()?;
        crate::pins::take_over(vdir, &rel, |old| {
            let id = match old {
                Some(old) => p.attach_to_link(SchedClassifierLink::try_from(old)?)?,
                None => p
                    .attach(ifname, at)
                    .with_context(|| format!("attach {name} to {ifname}"))?,
            };
            p.take_link(id)?
                .try_into()
                .context("a tcx link (kernel >= 6.6) is required to pin")
        })?;
        hooked.attached |= !inherited;
    }
    Ok(hooked)
}

pub(crate) fn pinned_veth(pin: &str) -> &str {
    pin.rsplit_once('-').map_or(pin, |(veth, _)| veth)
}

// The pin keeps a dead veth's link alive.
pub fn prune_pins(vdir: &str, live: &std::collections::HashSet<String>) -> usize {
    let Ok(entries) = std::fs::read_dir(pin_dir(vdir)) else {
        return 0;
    };
    let mut n = 0;
    for e in entries.flatten() {
        if live.contains(pinned_veth(&e.file_name().to_string_lossy())) {
            continue;
        }
        crate::pins::unpin_link(&e.path());
        n += 1;
    }
    n
}

pub fn unpin_all(vdir: &str) {
    prune_pins(vdir, &std::collections::HashSet::new());
    let _ = std::fs::remove_dir(pin_dir(vdir));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Mem;

    fn net(s: &str) -> Ipv4Net {
        Ipv4Net::parse(s).unwrap()
    }
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn allow(peer: &str, proto: Proto, lo: u16, hi: u16) -> Allow {
        Allow {
            peer: net(peer),
            proto,
            lo,
            hi,
        }
    }
    fn ranges(v: &AllowVal) -> Vec<(u8, u16, u16)> {
        v.ranges[..v.n as usize]
            .iter()
            .map(|r| (r.proto, r.lo, r.hi))
            .collect()
    }

    #[test]
    fn narrower_prefix_inherits_ports() {
        let (e, dropped) = lower_rules(&[
            allow("10.0.0.0/8", Proto::Tcp, 80, 80),
            allow("10.1.0.0/16", Proto::Tcp, 443, 443),
            allow("192.168.0.0/16", Proto::Tcp, 22, 22),
        ]);
        assert_eq!(dropped, 0);
        assert_eq!(ranges(&e[&net("10.0.0.0/8")]), vec![(IPPROTO_TCP, 80, 80)]);
        assert_eq!(
            ranges(&e[&net("10.1.0.0/16")]),
            vec![(IPPROTO_TCP, 80, 80), (IPPROTO_TCP, 443, 443)],
            "10.1.x.x may reach 80 too, by the /8"
        );
        assert_eq!(
            ranges(&e[&net("192.168.0.0/16")]),
            vec![(IPPROTO_TCP, 22, 22)],
            "a prefix the /8 does not contain inherits nothing"
        );
    }

    #[test]
    fn ranges_merge_per_protocol() {
        let (e, _) = lower_rules(&[
            allow("0.0.0.0/0", Proto::Tcp, 80, 90),
            allow("0.0.0.0/0", Proto::Tcp, 91, 100),
            allow("0.0.0.0/0", Proto::Tcp, 50, 85),
            allow("0.0.0.0/0", Proto::Udp, 53, 53),
        ]);
        assert_eq!(
            ranges(&e[&net("0.0.0.0/0")]),
            vec![(IPPROTO_TCP, 50, 100), (IPPROTO_UDP, 53, 53)]
        );
    }

    #[test]
    fn full_range_merge_no_overflow() {
        let (e, _) = lower_rules(&[
            allow("0.0.0.0/0", Proto::Tcp, 0, 65535),
            allow("0.0.0.0/0", Proto::Tcp, 65535, 65535),
        ]);
        assert_eq!(ranges(&e[&net("0.0.0.0/0")]), vec![(IPPROTO_TCP, 0, 65535)]);
    }

    #[test]
    fn excess_ranges_dropped_not_widened() {
        let rules: Vec<Allow> = (0..12)
            .map(|i| allow("10.0.0.0/8", Proto::Tcp, 100 + 10 * i, 100 + 10 * i))
            .collect();
        let (e, dropped) = lower_rules(&rules);
        let v = &e[&net("10.0.0.0/8")];
        assert_eq!(v.n as usize, MAX_RANGES);
        assert_eq!(dropped, 12 - MAX_RANGES);
        assert!(
            ranges(v).iter().all(|(_, lo, hi)| lo == hi),
            "no range was widened"
        );
    }

    #[test]
    fn allow_key_layout() {
        let (bits, k) = allow_key(ip("10.244.0.5"), DIR_EGRESS, net("192.168.0.0/16"));
        assert_eq!(bits, 64 + 16);
        assert_eq!(k.subject, u32::from_be_bytes([10, 244, 0, 5]).to_be());
        assert_eq!(k.peer, u32::from_be_bytes([192, 168, 0, 0]).to_be());
        assert_eq!(k.dir, DIR_EGRESS);
    }

    fn policy(ingress: Option<Vec<Allow>>, egress: Option<Vec<Allow>>) -> PodPolicy {
        PodPolicy { ingress, egress }
    }

    #[test]
    fn only_attached_pods_lowered() {
        let mut compiled = BTreeMap::new();
        compiled.insert(
            ip("10.244.0.5"),
            policy(
                Some(vec![
                    allow("10.244.0.6/32", Proto::Tcp, 80, 80),
                    allow("10.244.0.8/32", Proto::Tcp, 80, 80),
                ]),
                None,
            ),
        );
        compiled.insert(ip("10.244.0.6"), policy(None, None));
        let overflowing: Vec<Allow> = (0..10)
            .map(|i| allow("10.0.0.0/8", Proto::Udp, 100 + 10 * i, 100 + 10 * i))
            .collect();
        compiled.insert(ip("10.244.0.7"), policy(Some(overflowing), Some(vec![])));
        compiled.insert(ip("10.244.0.9"), policy(Some(vec![]), Some(vec![])));
        let attached = BTreeMap::from([
            (11, ip("10.244.0.5")),
            (12, ip("10.244.0.6")),
            (13, ip("10.244.0.7")),
            (99, ip("10.244.0.99")),
        ]);
        let d = lower(&compiled, &attached);
        assert_eq!(d.pods[&11].flags, FLAG_INGRESS_ISOLATED);
        assert_eq!(d.pods[&12].flags, 0);
        assert_eq!(
            d.pods[&13].flags,
            FLAG_INGRESS_ISOLATED | FLAG_EGRESS_ISOLATED
        );
        assert_eq!(
            d.pods[&99].flags, 0,
            "attached but unknown to the API: unrestricted"
        );
        assert_eq!(d.pods.len(), 4, ".9 is not attached: no entry");
        assert_eq!(d.allow.len(), 3, "one entry per (subject, direction, peer)");
        assert_eq!(d.dropped_ranges, 10 - MAX_RANGES);
        assert!(d.armed);
        assert_eq!(d.pod_ips[&u32::from(ip("10.244.0.5")).to_be()], 11);
    }

    #[test]
    fn unisolated_is_unarmed() {
        let compiled = BTreeMap::from([(ip("10.244.0.5"), policy(None, None))]);
        let d = lower(&compiled, &BTreeMap::from([(11, ip("10.244.0.5"))]));
        assert!(!d.armed);
    }

    fn desired_with_policy() -> Desired {
        let compiled = BTreeMap::from([(
            ip("10.244.0.5"),
            policy(Some(vec![allow("10.244.0.6/32", Proto::Tcp, 80, 80)]), None),
        )]);
        lower(
            &compiled,
            &BTreeMap::from([(11, ip("10.244.0.5")), (12, ip("10.244.0.6"))]),
        )
    }

    #[test]
    fn rules_before_flags_arm_last() {
        let mut m = Mem::default();
        let writes = reconcile(&mut m, &desired_with_policy()).unwrap();
        assert_eq!(writes, m.log.len());
        assert_eq!((m.allow.len(), m.ips.len(), m.pods.len()), (1, 2, 2));
        let pos = |s: &str| m.log.iter().position(|l| l == s).unwrap();
        assert!(pos("put_allow") < pos("put_pod"), "{:?}", m.log);
        assert!(pos("put_pod") < pos("armed=true"), "{:?}", m.log);
        assert!(m.armed);
    }

    #[test]
    fn second_reconcile_writes_nothing() {
        let mut m = Mem::default();
        let d = desired_with_policy();
        reconcile(&mut m, &d).unwrap();
        m.log.clear();
        assert_eq!(reconcile(&mut m, &d).unwrap(), 0);
        assert!(m.log.is_empty());
    }

    #[test]
    fn last_policy_removal_disarms_first() {
        let mut m = Mem::default();
        reconcile(&mut m, &desired_with_policy()).unwrap();
        m.log.clear();
        let none = lower(
            &BTreeMap::new(),
            &BTreeMap::from([(11, ip("10.244.0.5")), (12, ip("10.244.0.6"))]),
        );
        let writes = reconcile(&mut m, &none).unwrap();
        assert_eq!(writes, m.log.len());
        assert_eq!(m.log[0], "armed=false", "{:?}", m.log);
        assert!(m.allow.is_empty());
        assert!(!m.armed);
        assert_eq!(m.pods[&11].flags, 0);
    }

    #[test]
    fn gone_veth_pod_removed() {
        let mut m = Mem::default();
        reconcile(&mut m, &desired_with_policy()).unwrap();
        m.log.clear();
        let only12 = lower(&BTreeMap::new(), &BTreeMap::from([(12, ip("10.244.0.6"))]));
        let writes = reconcile(&mut m, &only12).unwrap();
        assert_eq!(writes, m.log.len());
        assert!(!m.pods.contains_key(&11));
        assert!(!m.ips.contains_key(&u32::from(ip("10.244.0.5")).to_be()));
    }

    #[test]
    fn gone_veth_pins_pruned() {
        let vdir = std::env::temp_dir().join(format!("edge-cni-netpol-{}", std::process::id()));
        let np = std::path::PathBuf::from(pin_dir(&vdir.to_string_lossy()));
        std::fs::create_dir_all(&np).unwrap();
        for f in ["edgea-in", "edgea-eg", "edgeb-in", "edgeb-eg"] {
            std::fs::write(np.join(f), b"").unwrap();
        }
        let live = std::collections::HashSet::from(["edgea".to_string()]);
        assert_eq!(prune_pins(&vdir.to_string_lossy(), &live), 2);
        assert!(np.join("edgea-in").exists() && !np.join("edgeb-in").exists());
        unpin_all(&vdir.to_string_lossy());
        assert!(!np.exists());
        std::fs::remove_dir_all(&vdir).ok();
    }
}
