//! Where the API is silent: ICMP always passes, the node is always let in
//! (kubelet probes), non-first IP fragments pass, and IPv6 is ignored.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{ContainerPort, Namespace, Pod};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::{Api, Client, Resource, ResourceExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    Sctp,
}

impl Proto {
    fn parse(s: Option<&str>) -> Option<Proto> {
        match s {
            None | Some("TCP") => Some(Proto::Tcp),
            Some("UDP") => Some(Proto::Udp),
            Some("SCTP") => Some(Proto::Sctp),
            Some(_) => None,
        }
    }

    pub const ALL: [Proto; 3] = [Proto::Tcp, Proto::Udp, Proto::Sctp];
}

// Host byte order, always masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Net {
    pub addr: u32,
    pub prefix: u8,
}

impl Ipv4Net {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        Self {
            addr: u32::from(addr) & mask(prefix),
            prefix,
        }
    }

    pub fn host(addr: Ipv4Addr) -> Self {
        Self::new(addr, 32)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = s.split_once('/').map_or((s, "32"), |(a, p)| (a, p));
        let addr: Ipv4Addr = a.parse().ok()?;
        let prefix: u8 = p.parse().ok().filter(|p| *p <= 32)?;
        Some(Self::new(addr, prefix))
    }

    pub fn first(&self) -> u32 {
        self.addr
    }

    pub fn last(&self) -> u32 {
        self.addr | !mask(self.prefix)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == self.addr
    }

    pub fn address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.addr)
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn range_to_cidrs(mut lo: u64, hi: u64, out: &mut Vec<Ipv4Net>) {
    while lo <= hi {
        let align = if lo == 0 {
            32
        } else {
            lo.trailing_zeros().min(32)
        };
        let mut bits = align;
        while bits > 0 && lo + (1u64 << bits) - 1 > hi {
            bits -= 1;
        }
        out.push(Ipv4Net {
            addr: lo as u32,
            prefix: (32 - bits) as u8,
        });
        lo += 1u64 << bits;
    }
}

pub fn subtract(cidr: Ipv4Net, excepts: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut ranges: Vec<(u64, u64)> = vec![(cidr.first() as u64, cidr.last() as u64)];
    for e in excepts {
        let (elo, ehi) = (e.first() as u64, e.last() as u64);
        let mut next = Vec::new();
        for (lo, hi) in ranges {
            if ehi < lo || elo > hi {
                next.push((lo, hi));
                continue;
            }
            if elo > lo {
                next.push((lo, elo - 1));
            }
            if ehi < hi {
                next.push((ehi + 1, hi));
            }
        }
        ranges = next;
    }
    let mut out = Vec::new();
    for (lo, hi) in ranges {
        range_to_cidrs(lo, hi, &mut out);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPort {
    pub name: String,
    pub proto: Proto,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPort {
    pub proto: Proto,
    pub host_ip: Option<Ipv4Addr>,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PodInfo {
    pub namespace: String,
    pub name: String,
    pub ip: Option<Ipv4Addr>,
    pub labels: BTreeMap<String, String>,
    // NetworkPolicy does not apply to hostNetwork pods, as subjects or peers.
    pub host_network: bool,
    pub ports: Vec<NamedPort>,
    pub host_ports: Vec<HostPort>,
}

impl PodInfo {
    // Succeeded/Failed pods keep `podIP` after the address is free for another pod.
    pub fn from_pod(p: &Pod) -> Option<Self> {
        let status = p.status.as_ref();
        if matches!(
            status.and_then(|s| s.phase.as_deref()),
            Some("Succeeded" | "Failed")
        ) {
            return None;
        }
        let ip = status.and_then(|s| {
            s.pod_ips
                .iter()
                .flatten()
                .filter_map(|i| i.ip.parse::<Ipv4Addr>().ok())
                .next()
                .or_else(|| s.pod_ip.as_deref().and_then(|i| i.parse().ok()))
        });
        let spec = p.spec.as_ref();
        let mut ports = Vec::new();
        for c in spec.iter().flat_map(|s| {
            s.containers
                .iter()
                .chain(s.init_containers.iter().flatten())
        }) {
            for cp in c.ports.iter().flatten() {
                let (Some(name), Some(proto)) =
                    (cp.name.clone(), Proto::parse(cp.protocol.as_deref()))
                else {
                    continue;
                };
                if let Ok(port) = u16::try_from(cp.container_port) {
                    ports.push(NamedPort { name, proto, port });
                }
            }
        }
        let host_network = spec.and_then(|s| s.host_network).unwrap_or(false);
        // The runtime maps only app containers' ports; a hostNetwork pod needs none.
        let host_ports = spec
            .filter(|_| !host_network)
            .iter()
            .flat_map(|s| s.containers.iter().flat_map(|c| c.ports.iter().flatten()))
            .filter_map(host_port)
            .collect();
        Some(Self {
            namespace: p.namespace().unwrap_or_default(),
            name: p.name_any(),
            ip,
            labels: p.labels().clone(),
            host_network,
            ports,
            host_ports,
        })
    }
}

fn host_port(cp: &ContainerPort) -> Option<HostPort> {
    let host_ip = match cp.host_ip.as_deref() {
        None | Some("" | "0.0.0.0") => None,
        Some(ip) => Some(ip.parse().ok()?),
    };
    Some(HostPort {
        proto: Proto::parse(cp.protocol.as_deref())?,
        host_ip,
        host_port: u16::try_from(cp.host_port?).ok().filter(|p| *p != 0)?,
        container_port: u16::try_from(cp.container_port).ok()?,
    })
}

#[derive(Debug, Default, Clone)]
pub struct PolicyView {
    pub pods: HashMap<String, PodInfo>,
    pub namespaces: HashMap<String, BTreeMap<String, String>>,
    pub policies: HashMap<String, NetworkPolicy>,
}

// Ports inclusive, host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Allow {
    pub peer: Ipv4Net,
    pub proto: Proto,
    pub lo: u16,
    pub hi: u16,
}

// Per direction: `None` is not isolated; `Some(rules)` allows only `rules`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodPolicy {
    pub ingress: Option<Vec<Allow>>,
    pub egress: Option<Vec<Allow>>,
}

impl PodPolicy {
    pub fn is_isolated(&self) -> bool {
        self.ingress.is_some() || self.egress.is_some()
    }
}

pub fn selector_matches(sel: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    for (k, v) in sel.match_labels.iter().flatten() {
        if labels.get(k) != Some(v) {
            return false;
        }
    }
    for req in sel.match_expressions.iter().flatten() {
        let has = labels.get(&req.key);
        let values = req.values.as_deref().unwrap_or(&[]);
        let ok = match req.operator.as_str() {
            "In" => has.is_some_and(|v| values.contains(v)),
            "NotIn" => has.is_none_or(|v| !values.contains(v)),
            "Exists" => has.is_some(),
            "DoesNotExist" => has.is_none(),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

// Unset `policyTypes` means Ingress, plus Egress if there are egress rules.
fn policy_types(p: &NetworkPolicy) -> (bool, bool) {
    let Some(spec) = p.spec.as_ref() else {
        return (false, false);
    };
    match spec.policy_types.as_deref() {
        Some(types) if !types.is_empty() => (
            types.iter().any(|t| t == "Ingress"),
            types.iter().any(|t| t == "Egress"),
        ),
        _ => (true, spec.egress.as_ref().is_some_and(|e| !e.is_empty())),
    }
}

struct Peer<'a> {
    net: Ipv4Net,
    pod: Option<&'a PodInfo>,
}

// None: no peers listed, which means everyone.
fn resolve_peers<'a>(
    peers: Option<&[NetworkPolicyPeer]>,
    policy_ns: &str,
    view: &'a PolicyView,
) -> Option<Vec<Peer<'a>>> {
    let peers = peers.filter(|p| !p.is_empty())?;
    let mut out = Vec::new();
    for peer in peers {
        if let Some(ipb) = &peer.ip_block {
            let Some(cidr) = Ipv4Net::parse(&ipb.cidr) else {
                continue;
            };
            let excepts: Vec<Ipv4Net> = ipb
                .except
                .iter()
                .flatten()
                .filter_map(|e| Ipv4Net::parse(e))
                .collect();
            out.extend(
                subtract(cidr, &excepts)
                    .into_iter()
                    .map(|net| Peer { net, pod: None }),
            );
            continue;
        }
        for pod in view.pods.values() {
            let Some(ip) = pod.ip else { continue };
            if pod.host_network {
                continue;
            }
            let ns_ok = match &peer.namespace_selector {
                Some(nsel) => {
                    let empty = BTreeMap::new();
                    selector_matches(nsel, view.namespaces.get(&pod.namespace).unwrap_or(&empty))
                }
                None => pod.namespace == policy_ns,
            };
            let pod_ok = peer
                .pod_selector
                .as_ref()
                .is_none_or(|s| selector_matches(s, &pod.labels));
            if ns_ok && pod_ok {
                out.push(Peer {
                    net: Ipv4Net::host(ip),
                    pod: Some(pod),
                });
            }
        }
    }
    Some(out)
}

// Named ports resolve against `target`; against an ipBlock they match nothing.
fn resolve_ports(
    ports: Option<&[NetworkPolicyPort]>,
    target: Option<&PodInfo>,
) -> Vec<(Proto, u16, u16)> {
    let Some(ports) = ports.filter(|p| !p.is_empty()) else {
        return Proto::ALL.iter().map(|p| (*p, 0, u16::MAX)).collect();
    };
    let mut out = Vec::new();
    for p in ports {
        let Some(proto) = Proto::parse(p.protocol.as_deref()) else {
            continue;
        };
        match &p.port {
            None => out.push((proto, 0, u16::MAX)),
            Some(IntOrString::Int(n)) => {
                let Ok(lo) = u16::try_from(*n) else { continue };
                let hi = p
                    .end_port
                    .and_then(|e| u16::try_from(e).ok())
                    .filter(|e| *e >= lo)
                    .unwrap_or(lo);
                out.push((proto, lo, hi));
            }
            Some(IntOrString::String(name)) => {
                if let Some(t) = target {
                    for np in t
                        .ports
                        .iter()
                        .filter(|np| np.name == *name && np.proto == proto)
                    {
                        out.push((proto, np.port, np.port));
                    }
                }
            }
        }
    }
    out
}

fn named_ports(ports: Option<&[NetworkPolicyPort]>) -> Vec<NetworkPolicyPort> {
    ports
        .iter()
        .copied()
        .flatten()
        .filter(|p| matches!(p.port, Some(IntOrString::String(_))))
        .cloned()
        .collect()
}

const ANYWHERE: Ipv4Net = Ipv4Net { addr: 0, prefix: 0 };

pub fn compile(view: &PolicyView) -> BTreeMap<Ipv4Addr, PodPolicy> {
    let mut out: BTreeMap<Ipv4Addr, PodPolicy> = BTreeMap::new();
    for pod in view.pods.values() {
        if let (Some(ip), false) = (pod.ip, pod.host_network) {
            out.entry(ip).or_default();
        }
    }

    // A named port means whatever each destination pod names it, so an egress
    // rule to anyone resolves it against every pod.
    let every_pod: Vec<Peer> = view
        .pods
        .values()
        .filter(|p| !p.host_network)
        .filter_map(|pod| {
            pod.ip.map(|ip| Peer {
                net: Ipv4Net::host(ip),
                pod: Some(pod),
            })
        })
        .collect();

    let mut keys: Vec<&String> = view.policies.keys().collect();
    keys.sort();
    for key in keys {
        let np = &view.policies[key];
        let Some(spec) = np.spec.as_ref() else {
            continue;
        };
        let ns = np.namespace().unwrap_or_default();
        let (ingress, egress) = policy_types(np);
        let empty_sel = LabelSelector::default();
        let selector = spec.pod_selector.as_ref().unwrap_or(&empty_sel);

        let in_rules: Vec<_> = spec
            .ingress
            .iter()
            .flatten()
            .map(|r| {
                (
                    resolve_peers(r.from.as_deref(), &ns, view),
                    r.ports.as_deref(),
                )
            })
            .collect();
        let out_rules: Vec<_> = spec
            .egress
            .iter()
            .flatten()
            .map(|r| {
                (
                    resolve_peers(r.to.as_deref(), &ns, view),
                    r.ports.as_deref(),
                )
            })
            .collect();

        for subject in view.pods.values() {
            let (Some(ip), false) = (subject.ip, subject.host_network) else {
                continue;
            };
            if subject.namespace != ns || !selector_matches(selector, &subject.labels) {
                continue;
            }
            let entry = out.entry(ip).or_default();

            if ingress {
                let rules = entry.ingress.get_or_insert_with(Vec::new);
                for (peers, ports) in &in_rules {
                    let ports = resolve_ports(*ports, Some(subject));
                    push_rules(rules, peers.as_deref(), |_| ports.clone());
                }
            }
            if egress {
                let rules = entry.egress.get_or_insert_with(Vec::new);
                for (peers, ports) in &out_rules {
                    push_rules(rules, peers.as_deref(), |peer| {
                        resolve_ports(*ports, peer.pod)
                    });
                    let named = named_ports(*ports);
                    if peers.is_none() && !named.is_empty() {
                        push_rules(rules, Some(&every_pod), |peer| {
                            resolve_ports(Some(&named), peer.pod)
                        });
                    }
                }
            }
        }
    }

    for p in out.values_mut() {
        for rules in [&mut p.ingress, &mut p.egress].into_iter().flatten() {
            rules.sort();
            rules.dedup();
        }
    }
    out
}

fn push_rules<'a>(
    rules: &mut Vec<Allow>,
    peers: Option<&[Peer<'a>]>,
    ports: impl Fn(&Peer<'a>) -> Vec<(Proto, u16, u16)>,
) {
    match peers {
        None => {
            let anyone = Peer {
                net: ANYWHERE,
                pod: None,
            };
            for (proto, lo, hi) in ports(&anyone) {
                rules.push(Allow {
                    peer: ANYWHERE,
                    proto,
                    lo,
                    hi,
                });
            }
        }
        Some(peers) => {
            for peer in peers {
                for (proto, lo, hi) in ports(peer) {
                    rules.push(Allow {
                        peer: peer.net,
                        proto,
                        lo,
                        hi,
                    });
                }
            }
        }
    }
}

#[derive(Default)]
struct Relist {
    seen: Option<HashSet<String>>,
    listed: bool,
}

impl Relist {
    fn event<K: Resource, T: PartialEq>(
        &mut self,
        objs: &mut HashMap<String, T>,
        ev: Event<K>,
        conv: impl Fn(&K) -> Option<T>,
    ) -> bool {
        let put = |objs: &mut HashMap<String, T>, k: String, v: Option<T>| match v {
            Some(v) => {
                let changed = objs.get(&k) != Some(&v);
                objs.insert(k, v);
                changed
            }
            None => objs.remove(&k).is_some(),
        };
        match ev {
            Event::Init => {
                self.seen = Some(HashSet::new());
                false
            }
            Event::InitApply(o) => {
                let k = crate::object_key(&o);
                if let Some(seen) = self.seen.as_mut() {
                    seen.insert(k.clone());
                }
                put(objs, k, conv(&o))
            }
            Event::Apply(o) => put(objs, crate::object_key(&o), conv(&o)),
            Event::Delete(o) => objs.remove(&crate::object_key(&o)).is_some(),
            Event::InitDone => {
                self.listed = true;
                let Some(seen) = self.seen.take() else {
                    return false;
                };
                let before = objs.len();
                objs.retain(|k, _| seen.contains(k));
                objs.len() != before
            }
        }
    }
}

#[derive(Default)]
struct PolicyFold {
    pods: Relist,
    nss: Relist,
    nps: Relist,
}

impl PolicyFold {
    fn synced(&self) -> bool {
        self.pods.listed && self.nss.listed && self.nps.listed
    }

    fn pod(&mut self, v: &mut PolicyView, ev: Event<Pod>) -> bool {
        self.pods.event(&mut v.pods, ev, PodInfo::from_pod)
    }

    fn namespace(&mut self, v: &mut PolicyView, ev: Event<Namespace>) -> bool {
        self.nss.event(&mut v.namespaces, ev, |n: &Namespace| {
            Some(n.labels().clone())
        })
    }

    fn policy(&mut self, v: &mut PolicyView, ev: Event<NetworkPolicy>) -> bool {
        self.nps
            .event(&mut v.policies, ev, |n: &NetworkPolicy| Some(n.clone()))
    }
}

#[allow(clippy::large_enum_variant)]
enum WatchEvent {
    Pod(Result<Event<Pod>, watcher::Error>),
    Ns(Result<Event<Namespace>, watcher::Error>),
    Np(Result<Event<NetworkPolicy>, watcher::Error>),
}

pub async fn run<F, S>(client: Client, mut on_change: F, on_synced: S) -> anyhow::Result<()>
where
    F: FnMut(&PolicyView) -> anyhow::Result<()>,
    S: FnOnce(&PolicyView) -> anyhow::Result<()>,
{
    let pods = crate::watch(Api::<Pod>::all(client.clone()), "pods").map(WatchEvent::Pod);
    let nss = crate::watch(Api::<Namespace>::all(client.clone()), "namespaces").map(WatchEvent::Ns);
    let nps =
        crate::watch(Api::<NetworkPolicy>::all(client), "networkpolicies").map(WatchEvent::Np);
    let mut stream = futures::stream::select_all([pods.boxed(), nss.boxed(), nps.boxed()]);
    let mut view = PolicyView::default();
    let mut fold = PolicyFold::default();
    let mut on_synced = Some(on_synced);

    while let Some(ev) = stream.next().await {
        let changed = match ev {
            WatchEvent::Pod(Ok(e)) => fold.pod(&mut view, e),
            WatchEvent::Ns(Ok(e)) => fold.namespace(&mut view, e),
            WatchEvent::Np(Ok(e)) => fold.policy(&mut view, e),
            WatchEvent::Pod(Err(_)) | WatchEvent::Ns(Err(_)) | WatchEvent::Np(Err(_)) => false,
        };
        if fold.synced() {
            if let Some(f) = on_synced.take() {
                f(&view)?;
            } else if changed {
                on_change(&view)?;
            }
        }
    }
    anyhow::bail!("pod/namespace/networkpolicy watch ended unexpectedly")
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Container, ContainerPort, PodSpec, PodStatus};
    use k8s_openapi::api::networking::v1::{
        IPBlock, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicySpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelectorRequirement, ObjectMeta};
    use std::collections::BTreeSet;

    type Labels<'a> = &'a [(&'a str, &'a str)];

    fn labels(kv: Labels) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn sel(kv: Labels) -> LabelSelector {
        LabelSelector {
            match_labels: Some(labels(kv)),
            ..Default::default()
        }
    }

    fn pod(ns: &str, name: &str, ip: &str, kv: Labels) -> PodInfo {
        PodInfo {
            namespace: ns.into(),
            name: name.into(),
            ip: Some(ip.parse().unwrap()),
            labels: labels(kv),
            ..Default::default()
        }
    }

    fn with_port(mut p: PodInfo, name: &str, port: u16) -> PodInfo {
        p.ports.push(NamedPort {
            name: name.into(),
            proto: Proto::Tcp,
            port,
        });
        p
    }

    fn to_pod(p: &PodInfo) -> Pod {
        Pod {
            metadata: ObjectMeta {
                namespace: Some(p.namespace.clone()),
                name: Some(p.name.clone()),
                labels: Some(p.labels.clone()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                host_network: Some(p.host_network),
                containers: vec![Container {
                    name: "c".into(),
                    ports: Some(
                        p.ports
                            .iter()
                            .map(|np| ContainerPort {
                                name: Some(np.name.clone()),
                                container_port: np.port.into(),
                                protocol: Some(
                                    match np.proto {
                                        Proto::Tcp => "TCP",
                                        Proto::Udp => "UDP",
                                        Proto::Sctp => "SCTP",
                                    }
                                    .into(),
                                ),
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: p.ip.map(|ip| ip.to_string()),
                phase: Some("Running".into()),
                ..Default::default()
            }),
        }
    }

    fn kns(name: &str, kv: Labels) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(name.into()),
                labels: Some(labels(kv)),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn compile_view(
        pods: Vec<PodInfo>,
        nss: &[(&str, Labels)],
        policies: Vec<NetworkPolicy>,
    ) -> BTreeMap<Ipv4Addr, PodPolicy> {
        let mut v = PolicyView::default();
        let mut f = PolicyFold::default();
        for p in &pods {
            f.pod(&mut v, Event::Apply(to_pod(p)));
        }
        for (n, l) in nss {
            f.namespace(&mut v, Event::Apply(kns(n, l)));
        }
        for p in policies {
            f.policy(&mut v, Event::Apply(p));
        }
        let key = |p: &PodInfo| (p.namespace.clone(), p.name.clone());
        let mut folded: Vec<PodInfo> = v.pods.values().cloned().collect();
        folded.sort_by_key(key);
        let mut given = pods;
        given.sort_by_key(key);
        assert_eq!(folded, given, "the fold keeps every pod as given");
        compile(&v)
    }

    fn np(name: &str, spec: NetworkPolicySpec) -> NetworkPolicy {
        NetworkPolicy {
            metadata: ObjectMeta {
                namespace: Some("a".into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: Some(spec),
        }
    }

    fn ingress_policy(
        selector: LabelSelector,
        from: Option<Vec<NetworkPolicyPeer>>,
        ports: Option<Vec<NetworkPolicyPort>>,
    ) -> NetworkPolicy {
        np(
            "in",
            NetworkPolicySpec {
                pod_selector: Some(selector),
                ingress: Some(vec![NetworkPolicyIngressRule { from, ports }]),
                ..Default::default()
            },
        )
    }

    fn egress_only_policy(
        selector: LabelSelector,
        to: Vec<NetworkPolicyPeer>,
        ports: Vec<NetworkPolicyPort>,
    ) -> NetworkPolicy {
        np(
            "eg",
            NetworkPolicySpec {
                pod_selector: Some(selector),
                policy_types: Some(vec!["Egress".into()]),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(to),
                    ports: Some(ports),
                }]),
                ..Default::default()
            },
        )
    }

    fn peer_pods(s: LabelSelector) -> NetworkPolicyPeer {
        NetworkPolicyPeer {
            pod_selector: Some(s),
            ..Default::default()
        }
    }

    fn peer_ns(s: LabelSelector) -> NetworkPolicyPeer {
        NetworkPolicyPeer {
            namespace_selector: Some(s),
            ..Default::default()
        }
    }

    fn peer_cidr(cidr: &str, except: &[&str]) -> NetworkPolicyPeer {
        NetworkPolicyPeer {
            ip_block: Some(IPBlock {
                cidr: cidr.into(),
                except: (!except.is_empty())
                    .then(|| except.iter().map(|s| s.to_string()).collect()),
            }),
            ..Default::default()
        }
    }

    fn port(proto: Option<&str>, n: i32, end: Option<i32>) -> NetworkPolicyPort {
        NetworkPolicyPort {
            protocol: proto.map(String::from),
            port: Some(IntOrString::Int(n)),
            end_port: end,
        }
    }

    fn named(name: &str) -> NetworkPolicyPort {
        NetworkPolicyPort {
            protocol: None,
            port: Some(IntOrString::String(name.into())),
            end_port: None,
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> Ipv4Net {
        Ipv4Net::parse(s).unwrap()
    }

    fn allow(peer: &str, proto: Proto, lo: u16, hi: u16) -> Allow {
        Allow {
            peer: net(peer),
            proto,
            lo,
            hi,
        }
    }

    fn peers(rules: &Option<Vec<Allow>>) -> BTreeSet<Ipv4Net> {
        rules.as_ref().unwrap().iter().map(|r| r.peer).collect()
    }

    #[test]
    fn except_cut_from_cidr() {
        assert_eq!(
            subtract(net("10.0.0.0/24"), &[net("10.0.0.128/25")]),
            vec![net("10.0.0.0/25")]
        );
        assert_eq!(
            subtract(net("10.0.0.0/24"), &[net("10.0.0.5/32")]),
            vec![
                net("10.0.0.0/30"),
                net("10.0.0.4/32"),
                net("10.0.0.6/31"),
                net("10.0.0.8/29"),
                net("10.0.0.16/28"),
                net("10.0.0.32/27"),
                net("10.0.0.64/26"),
                net("10.0.0.128/25"),
            ]
        );
        assert_eq!(subtract(net("10.0.0.0/8"), &[]), vec![net("10.0.0.0/8")]);
        assert!(subtract(net("10.1.0.0/16"), &[net("10.0.0.0/8")]).is_empty());
        assert_eq!(
            subtract(net("10.1.0.0/16"), &[net("192.168.0.0/16")]),
            vec![net("10.1.0.0/16")],
            "an except elsewhere removes nothing"
        );
        assert_eq!(subtract(net("0.0.0.0/0"), &[]), vec![net("0.0.0.0/0")]);
        assert_eq!(
            subtract(net("0.0.0.0/0"), &[net("0.0.0.0/1")]),
            vec![net("128.0.0.0/1")]
        );
    }

    #[test]
    fn cover_is_exact() {
        let cidr = net("172.16.0.0/20");
        let except_sets: &[&[&str]] = &[
            &["172.16.3.0/24", "172.16.9.7/32", "172.16.15.240/28"],
            &["172.16.0.0/32", "172.16.15.255/32"],
            &["172.16.8.0/21", "172.16.4.0/22", "172.16.0.0/23"],
            &["172.14.0.0/16", "172.16.2.0/24", "172.18.0.0/16"],
            &["172.16.1.0/24", "172.16.1.0/24", "172.16.0.0/22"],
        ];
        for set in except_sets {
            let ex: Vec<Ipv4Net> = set.iter().map(|e| net(e)).collect();
            let cover = subtract(cidr, &ex);
            for offset in 0u32..(1 << 12) {
                let addr = Ipv4Addr::from(u32::from(ip("172.16.0.0")) + offset);
                let excepted = ex.iter().any(|e| e.contains(addr));
                let hits = cover.iter().filter(|n| n.contains(addr)).count();
                assert_eq!(hits, if excepted { 0 } else { 1 }, "{addr} {set:?}");
            }
            assert!(cover.iter().all(|n| cidr.contains(n.address())), "{set:?}");
        }
    }

    #[test]
    fn cidr_is_masked() {
        assert_eq!(net("10.1.2.3/8"), net("10.0.0.0/8"));
        assert_eq!(net("1.2.3.4"), net("1.2.3.4/32"));
        assert!(Ipv4Net::parse("10.0.0.0/33").is_none());
        assert!(Ipv4Net::parse("fd00::/8").is_none());
    }

    #[test]
    fn label_selectors() {
        let l = labels(&[("app", "web"), ("tier", "fe")]);
        assert!(selector_matches(&LabelSelector::default(), &l));
        assert!(selector_matches(&sel(&[("app", "web")]), &l));
        assert!(!selector_matches(&sel(&[("app", "db")]), &l));
        let expr = |op: &str, key: &str, vals: &[&str]| LabelSelector {
            match_expressions: Some(vec![LabelSelectorRequirement {
                key: key.into(),
                operator: op.into(),
                values: Some(vals.iter().map(|s| s.to_string()).collect()),
            }]),
            ..Default::default()
        };
        for (op, key, vals, want) in [
            ("In", "app", &["web", "api"][..], true),
            ("In", "app", &["api"], false),
            ("NotIn", "app", &["api"], true),
            ("NotIn", "absent", &["x"], true),
            ("NotIn", "app", &["web"], false),
            ("Exists", "tier", &[], true),
            ("Exists", "nope", &[], false),
            ("DoesNotExist", "nope", &[], true),
            ("DoesNotExist", "app", &[], false),
            ("Bogus", "app", &[], false),
        ] {
            assert_eq!(
                selector_matches(&expr(op, key, vals), &l),
                want,
                "{op} {key}"
            );
        }
    }

    #[test]
    fn only_selected_pods_isolated() {
        let got = compile_view(
            vec![
                pod("a", "web", "10.244.0.5", &[("app", "web")]),
                pod("a", "other", "10.244.0.6", &[]),
                pod("b", "web", "10.244.0.7", &[("app", "web")]),
            ],
            &[],
            vec![np(
                "deny",
                NetworkPolicySpec {
                    pod_selector: Some(sel(&[("app", "web")])),
                    ..Default::default()
                },
            )],
        );
        assert_eq!(
            got[&ip("10.244.0.5")],
            PodPolicy {
                ingress: Some(vec![]),
                egress: None,
            },
            "no rules: ingress deny-all, egress untouched"
        );
        assert!(got[&ip("10.244.0.5")].is_isolated());
        assert!(!got[&ip("10.244.0.6")].is_isolated());
        assert_eq!(got[&ip("10.244.0.6")], PodPolicy::default());
        assert_eq!(got[&ip("10.244.0.7")], PodPolicy::default());
    }

    #[test]
    fn policy_types_default() {
        let one = |types: Option<Vec<&str>>, with_egress: bool| {
            let spec = NetworkPolicySpec {
                pod_selector: Some(LabelSelector::default()),
                policy_types: types.map(|t| t.into_iter().map(String::from).collect()),
                egress: with_egress.then(|| vec![NetworkPolicyEgressRule::default()]),
                ..Default::default()
            };
            let got = compile_view(
                vec![pod("a", "p", "10.244.0.5", &[])],
                &[],
                vec![np("n", spec)],
            );
            let p = &got[&ip("10.244.0.5")];
            (p.ingress.is_some(), p.egress.clone().map(|e| e.is_empty()))
        };
        assert_eq!(one(None, false), (true, None));
        assert_eq!(one(None, true), (true, Some(false)));
        assert_eq!(one(Some(vec![]), true), (true, Some(false)));
        assert_eq!(one(Some(vec!["Egress"]), false), (false, Some(true)));
        assert_eq!(
            one(Some(vec!["Ingress", "Egress"]), false),
            (true, Some(true))
        );
    }

    #[test]
    fn no_from_allows_all_sources() {
        let only = |ports| {
            compile_view(
                vec![pod("a", "web", "10.244.0.5", &[])],
                &[],
                vec![ingress_policy(LabelSelector::default(), None, ports)],
            )[&ip("10.244.0.5")]
                .ingress
                .clone()
        };
        assert_eq!(
            only(Some(vec![port(Some("TCP"), 80, None)])),
            Some(vec![allow("0.0.0.0/0", Proto::Tcp, 80, 80)])
        );
        assert_eq!(
            only(None),
            Some(vec![
                allow("0.0.0.0/0", Proto::Tcp, 0, 65535),
                allow("0.0.0.0/0", Proto::Udp, 0, 65535),
                allow("0.0.0.0/0", Proto::Sctp, 0, 65535),
            ]),
            "`ingress: [{{}}]` allows everything"
        );
    }

    #[test]
    fn pod_selector_peer_same_namespace() {
        let got = compile_view(
            vec![
                pod("a", "web", "10.244.0.5", &[("app", "web")]),
                pod("a", "client", "10.244.0.6", &[("role", "client")]),
                pod("b", "client", "10.244.0.7", &[("role", "client")]),
            ],
            &[],
            vec![ingress_policy(
                sel(&[("app", "web")]),
                Some(vec![peer_pods(sel(&[("role", "client")]))]),
                Some(vec![port(Some("TCP"), 80, None)]),
            )],
        );
        assert_eq!(
            got[&ip("10.244.0.5")].ingress,
            Some(vec![allow("10.244.0.6/32", Proto::Tcp, 80, 80)])
        );
    }

    #[test]
    fn namespace_and_pod_selectors() {
        let pods = || {
            vec![
                pod("a", "web", "10.244.0.5", &[("app", "web")]),
                pod("mon", "prom", "10.244.0.8", &[("app", "prom")]),
                pod("mon", "other", "10.244.0.9", &[("app", "other")]),
                pod("dev", "prom", "10.244.0.10", &[("app", "prom")]),
            ]
        };
        let nss: &[(&str, Labels)] = &[
            ("a", &[]),
            ("mon", &[("team", "obs")]),
            ("dev", &[("team", "dev")]),
        ];
        let allowed = |from: Vec<NetworkPolicyPeer>| {
            peers(
                &compile_view(
                    pods(),
                    nss,
                    vec![ingress_policy(sel(&[("app", "web")]), Some(from), None)],
                )[&ip("10.244.0.5")]
                    .ingress,
            )
        };
        assert_eq!(
            allowed(vec![peer_ns(sel(&[("team", "obs")]))]),
            BTreeSet::from([net("10.244.0.8/32"), net("10.244.0.9/32")])
        );
        assert_eq!(
            allowed(vec![NetworkPolicyPeer {
                namespace_selector: Some(sel(&[("team", "obs")])),
                pod_selector: Some(sel(&[("app", "prom")])),
                ..Default::default()
            }]),
            BTreeSet::from([net("10.244.0.8/32")])
        );
        assert_eq!(
            allowed(vec![
                peer_ns(sel(&[("team", "obs")])),
                peer_pods(sel(&[("app", "prom")])),
            ]),
            BTreeSet::from([net("10.244.0.8/32"), net("10.244.0.9/32")]),
            "no prom pod in the policy's own namespace"
        );
    }

    #[test]
    fn ip_blocks_and_policies_union() {
        let mut second = ingress_policy(
            LabelSelector::default(),
            Some(vec![peer_cidr("10.0.0.0/8", &[])]),
            Some(vec![port(Some("TCP"), 80, None)]),
        );
        second.metadata.name = Some("second".into());
        let got = compile_view(
            vec![pod("a", "web", "10.244.0.5", &[])],
            &[],
            vec![
                ingress_policy(
                    LabelSelector::default(),
                    Some(vec![peer_cidr("192.168.0.0/24", &["192.168.0.128/25"])]),
                    Some(vec![port(Some("UDP"), 53, None)]),
                ),
                second,
            ],
        );
        assert_eq!(
            got[&ip("10.244.0.5")].ingress,
            Some(vec![
                allow("10.0.0.0/8", Proto::Tcp, 80, 80),
                allow("192.168.0.0/25", Proto::Udp, 53, 53),
            ])
        );
    }

    #[test]
    fn ports_default_tcp_end_port_range() {
        let got = compile_view(
            vec![pod("a", "web", "10.244.0.5", &[])],
            &[],
            vec![ingress_policy(
                LabelSelector::default(),
                None,
                Some(vec![
                    port(None, 8080, None),
                    port(Some("UDP"), 5000, Some(5010)),
                    port(Some("UDP"), 7000, Some(6000)),
                    port(Some("ICMP"), 1, None),
                    NetworkPolicyPort {
                        protocol: Some("SCTP".into()),
                        ..Default::default()
                    },
                ]),
            )],
        );
        assert_eq!(
            got[&ip("10.244.0.5")].ingress,
            Some(vec![
                allow("0.0.0.0/0", Proto::Tcp, 8080, 8080),
                allow("0.0.0.0/0", Proto::Udp, 5000, 5010),
                allow("0.0.0.0/0", Proto::Udp, 7000, 7000),
                allow("0.0.0.0/0", Proto::Sctp, 0, 65535),
            ])
        );
    }

    #[test]
    fn ingress_named_port_from_subject() {
        let got = compile_view(
            vec![{
                let mut p = with_port(pod("a", "web", "10.244.0.5", &[]), "http", 8080);
                p.ports.push(NamedPort {
                    name: "http".into(),
                    proto: Proto::Udp,
                    port: 8081,
                });
                p
            }],
            &[],
            vec![ingress_policy(
                LabelSelector::default(),
                None,
                Some(vec![named("http")]),
            )],
        );
        assert_eq!(
            got[&ip("10.244.0.5")].ingress,
            Some(vec![allow("0.0.0.0/0", Proto::Tcp, 8080, 8080)])
        );
    }

    #[test]
    fn egress_named_port_from_peer() {
        let got = compile_view(
            vec![
                pod("a", "client", "10.244.0.5", &[("role", "client")]),
                with_port(
                    pod("a", "s1", "10.244.0.6", &[("role", "srv")]),
                    "api",
                    9000,
                ),
                with_port(
                    pod("a", "s2", "10.244.0.7", &[("role", "srv")]),
                    "api",
                    9001,
                ),
                pod("a", "s3", "10.244.0.8", &[("role", "srv")]),
            ],
            &[],
            vec![egress_only_policy(
                sel(&[("role", "client")]),
                vec![
                    peer_pods(sel(&[("role", "srv")])),
                    peer_cidr("8.8.8.0/24", &[]),
                ],
                vec![named("api")],
            )],
        );
        assert_eq!(
            got[&ip("10.244.0.5")].egress,
            Some(vec![
                allow("10.244.0.6/32", Proto::Tcp, 9000, 9000),
                allow("10.244.0.7/32", Proto::Tcp, 9001, 9001)
            ])
        );
    }

    #[test]
    fn egress_named_port_to_anyone() {
        let mut host = with_port(pod("a", "host", "192.168.1.10", &[]), "serve-80-tcp", 80);
        host.host_network = true;
        let pods = || {
            vec![
                pod("a", "client", "10.244.0.5", &[("role", "client")]),
                with_port(pod("a", "s1", "10.244.0.6", &[]), "serve-80-tcp", 80),
                with_port(pod("b", "s2", "10.244.0.7", &[]), "serve-80-tcp", 8080),
                with_port(pod("b", "s3", "10.244.0.8", &[]), "other", 80),
                host.clone(),
            ]
        };
        let egress = |to, ports| {
            compile_view(
                pods(),
                &[("a", &[]), ("b", &[])],
                vec![egress_only_policy(sel(&[("role", "client")]), to, ports)],
            )[&ip("10.244.0.5")]
                .egress
                .clone()
        };
        let to_pods = Some(vec![
            allow("10.244.0.6/32", Proto::Tcp, 80, 80),
            allow("10.244.0.7/32", Proto::Tcp, 8080, 8080),
        ]);
        assert_eq!(egress(vec![], vec![named("serve-80-tcp")]), to_pods);
        assert_eq!(
            egress(
                vec![peer_ns(LabelSelector::default())],
                vec![named("serve-80-tcp")]
            ),
            to_pods
        );
        assert_eq!(
            egress(vec![], vec![port(None, 80, None)]),
            Some(vec![allow("0.0.0.0/0", Proto::Tcp, 80, 80)])
        );
        assert_eq!(
            egress(
                vec![],
                vec![named("serve-80-tcp"), port(Some("UDP"), 53, None)]
            ),
            Some(vec![
                allow("0.0.0.0/0", Proto::Udp, 53, 53),
                allow("10.244.0.6/32", Proto::Tcp, 80, 80),
                allow("10.244.0.7/32", Proto::Tcp, 8080, 8080),
            ])
        );
    }

    #[test]
    fn host_network_and_unaddressed_excluded() {
        let mut host = pod("a", "host", "192.168.1.10", &[("app", "web")]);
        host.host_network = true;
        let mut pending = pod("a", "pending", "10.244.0.9", &[("app", "web")]);
        pending.ip = None;
        let got = compile_view(
            vec![
                pod("a", "web", "10.244.0.5", &[("app", "web")]),
                host,
                pending,
            ],
            &[],
            vec![ingress_policy(
                sel(&[("app", "web")]),
                Some(vec![peer_pods(sel(&[("app", "web")]))]),
                None,
            )],
        );
        assert_eq!(got.keys().collect::<Vec<_>>(), [&ip("10.244.0.5")]);
        assert_eq!(
            peers(&got[&ip("10.244.0.5")].ingress),
            BTreeSet::from([net("10.244.0.5/32")])
        );
    }

    #[test]
    fn pod_info_from_pod() {
        let p = Pod {
            metadata: ObjectMeta {
                namespace: Some("a".into()),
                name: Some("web".into()),
                labels: Some(labels(&[("app", "web")])),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "c".into(),
                    ports: Some(vec![
                        ContainerPort {
                            name: Some("http".into()),
                            container_port: 8080,
                            ..Default::default()
                        },
                        ContainerPort {
                            name: None,
                            container_port: 9090,
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: Some("10.244.0.5".into()),
                phase: Some("Running".into()),
                ..Default::default()
            }),
        };
        let info = PodInfo::from_pod(&p).unwrap();
        assert_eq!(info.ip, Some(ip("10.244.0.5")));
        assert_eq!(info.labels, labels(&[("app", "web")]));
        assert_eq!(
            info.ports,
            vec![NamedPort {
                name: "http".into(),
                proto: Proto::Tcp,
                port: 8080
            }]
        );
        assert!(!info.host_network);
    }

    fn container_port(
        host_ip: Option<&str>,
        host_port: Option<i32>,
        protocol: &str,
    ) -> ContainerPort {
        ContainerPort {
            container_port: 8080,
            host_ip: host_ip.map(str::to_string),
            host_port,
            protocol: Some(protocol.into()),
            ..Default::default()
        }
    }

    #[test]
    fn host_ports_from_pod() {
        let mut p = kpod("a", "web", "10.244.0.5");
        p.spec = Some(PodSpec {
            containers: vec![Container {
                name: "c".into(),
                ports: Some(vec![
                    container_port(Some("127.0.0.1"), Some(54323), "TCP"),
                    container_port(Some("10.70.0.1"), Some(54323), "UDP"),
                    container_port(None, Some(80), "TCP"),
                    container_port(Some("0.0.0.0"), Some(81), "TCP"),
                    container_port(Some("::1"), Some(82), "TCP"),
                    container_port(None, None, "TCP"),
                    container_port(None, Some(0), "TCP"),
                    container_port(None, Some(70000), "TCP"),
                ]),
                ..Default::default()
            }],
            init_containers: Some(vec![Container {
                name: "init".into(),
                ports: Some(vec![container_port(None, Some(83), "TCP")]),
                ..Default::default()
            }]),
            ..Default::default()
        });
        let hp = |host_ip: Option<&str>, host_port, proto| HostPort {
            proto,
            host_ip: host_ip.map(|i| i.parse().unwrap()),
            host_port,
            container_port: 8080,
        };
        assert_eq!(
            PodInfo::from_pod(&p).unwrap().host_ports,
            [
                hp(Some("127.0.0.1"), 54323, Proto::Tcp),
                hp(Some("10.70.0.1"), 54323, Proto::Udp),
                hp(None, 80, Proto::Tcp),
                hp(None, 81, Proto::Tcp),
            ]
        );
        p.spec.as_mut().unwrap().host_network = Some(true);
        assert!(PodInfo::from_pod(&p).unwrap().host_ports.is_empty());
    }

    fn kpod(ns: &str, name: &str, ip: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            status: Some(PodStatus {
                pod_ip: Some(ip.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn finished_pod_releases_address() {
        for phase in ["Succeeded", "Failed"] {
            let mut p = kpod("a", "job", "10.244.0.5");
            p.status.as_mut().unwrap().phase = Some(phase.into());
            assert!(PodInfo::from_pod(&p).is_none(), "{phase}");
        }
    }

    #[test]
    fn relist_prunes_pod() {
        let mut v = PolicyView::default();
        let mut f = PolicyFold::default();
        f.pod(&mut v, Event::Init);
        f.pod(&mut v, Event::InitApply(kpod("a", "x", "10.244.0.5")));
        f.pod(&mut v, Event::InitApply(kpod("a", "y", "10.244.0.6")));
        f.pod(&mut v, Event::InitDone);
        assert_eq!(v.pods.len(), 2);
        f.pod(&mut v, Event::Init);
        f.pod(&mut v, Event::InitApply(kpod("a", "x", "10.244.0.5")));
        assert!(f.pod(&mut v, Event::InitDone), "the prune is a change");
        assert_eq!(v.pods.keys().collect::<Vec<_>>(), ["a/x"]);
    }

    #[test]
    fn irrelevant_update_is_no_change() {
        let mut v = PolicyView::default();
        let mut f = PolicyFold::default();
        assert!(f.pod(&mut v, Event::Apply(kpod("a", "x", "10.244.0.5"))));
        let mut again = kpod("a", "x", "10.244.0.5");
        again.metadata.resource_version = Some("999".into());
        assert!(!f.pod(&mut v, Event::Apply(again)));
        assert!(f.pod(&mut v, Event::Apply(kpod("a", "x", "10.244.0.6"))));
        let mut done = kpod("a", "x", "10.244.0.6");
        done.status.as_mut().unwrap().phase = Some("Succeeded".into());
        assert!(
            f.pod(&mut v, Event::Apply(done)),
            "finishing leaves the view"
        );
        assert!(v.pods.is_empty());
        assert!(!f.pod(&mut v, Event::Delete(kpod("a", "x", "10.244.0.6"))));
    }

    #[test]
    fn namespace_labels_survive_relist() {
        let mut v = PolicyView::default();
        let mut f = PolicyFold::default();
        let name_label = "kubernetes.io/metadata.name";
        for p in [
            pod("x", "a", "10.244.0.2", &[("pod", "a")]),
            pod("x", "b", "10.244.0.3", &[("pod", "b")]),
            pod("y", "b", "10.244.0.6", &[("pod", "b")]),
        ] {
            f.pod(&mut v, Event::Apply(to_pod(&p)));
        }
        for _ in 0..2 {
            f.namespace(&mut v, Event::Init);
            for n in ["x", "y"] {
                f.namespace(
                    &mut v,
                    Event::InitApply(kns(n, &[(name_label, n), ("ns", n)])),
                );
            }
            f.namespace(&mut v, Event::InitDone);
        }
        let expr = |op: &str| LabelSelector {
            match_expressions: Some(vec![LabelSelectorRequirement {
                key: "ns".into(),
                operator: op.into(),
                values: Some(vec!["x".into()]),
            }]),
            ..Default::default()
        };
        let allowed = |v: &PolicyView, from: NetworkPolicyPeer| {
            let mut v = v.clone();
            let mut p = ingress_policy(sel(&[("pod", "a")]), Some(vec![from]), None);
            p.metadata.namespace = Some("x".into());
            v.policies.insert("x/in".into(), p);
            peers(&compile(&v)[&ip("10.244.0.2")].ingress)
        };
        assert_eq!(
            allowed(&v, peer_ns(sel(&[(name_label, "y")]))),
            BTreeSet::from([net("10.244.0.6/32")])
        );
        assert_eq!(
            allowed(&v, peer_ns(expr("NotIn"))),
            BTreeSet::from([net("10.244.0.6/32")])
        );
        assert_eq!(
            allowed(&v, peer_ns(expr("In"))),
            BTreeSet::from([net("10.244.0.2/32"), net("10.244.0.3/32")])
        );
        assert!(f.namespace(&mut v, Event::Delete(kns("y", &[]))));
        assert!(allowed(&v, peer_ns(sel(&[(name_label, "y")]))).is_empty());
    }

    #[test]
    fn synced_after_three_lists() {
        let mut v = PolicyView::default();
        let mut f = PolicyFold::default();
        f.pod(&mut v, Event::InitDone);
        f.namespace(&mut v, Event::InitDone);
        assert!(!f.synced());
        f.policy(&mut v, Event::InitDone);
        assert!(f.synced());
    }
}
