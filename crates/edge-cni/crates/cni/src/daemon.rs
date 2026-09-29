//! Every part retries in place; nothing ends the process.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use aya::maps::{HashMap as BpfHashMap, MapData};
use edge_cni_common::{BackendKey, BackendVal, CtKey, ServiceKey, ServiceVal};
use edge_kube::policy::{HostPort, PodPolicy, PolicyView};
use k8s_openapi::api::core::v1::Node;
use kube::Client;

use crate::netpol::{self, AyaPolicyMaps, PolicyMaps};
use crate::nft::Forward;
use crate::pins::{self, SYNCED};
use crate::ports;
use crate::services::{AyaMaps, Programmer};

const ROOT_CGROUP: &str = "/sys/fs/cgroup";

const NAT_TICK: Duration = Duration::from_secs(5);

const POLICY_TICK: Duration = Duration::from_millis(250);

pub async fn run(node: &str) -> std::convert::Infallible {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let pod_cidr = &wait_for_pod_cidr(|| node_pod_cidr(node), Duration::from_secs(1)).await;
    tracing::info!(node, pod_cidr, "serving the Node's pod CIDR");
    // Before the dataplane: an ADD handed the floor's conflist reads this one.
    if let Err(e) = crate::install::install_cni(Some(pod_cidr)) {
        tracing::error!(error = %format!("{e:#}"), "cannot install the CNI files; retrying");
    }

    let cidr = pod_cidr.to_string();
    tokio::spawn(async move { crate::install::install_task(&cidr).await });
    let (nat, forwards) = tokio::sync::watch::channel(NatForwards::default());
    let cidr = pod_cidr.to_string();
    tokio::spawn(async move { nat_task(&cidr, forwards).await });

    let failures = &Cell::new(0u32);
    let nat = &nat;
    edge_common::forever(Duration::from_secs(1), Duration::from_secs(60), move || async move {
        if let Err(e) = dataplane(pod_cidr, failures, nat).await {
            tracing::error!(error = %format!("{e:#}"), "dataplane stopped; restarting it, pinned programs and maps stay in place");
        }
    })
    .await
}

async fn node_pod_cidr(node: &str) -> anyhow::Result<Option<String>> {
    let client = Client::try_default()
        .await
        .context("build the kube client")?;
    let node = kube::Api::<Node>::all(client)
        .get(node)
        .await
        .with_context(|| format!("get Node {node}"))?;
    Ok(pod_cidr_of(&node))
}

fn pod_cidr_of(node: &Node) -> Option<String> {
    let spec = node.spec.as_ref()?;
    spec.pod_cidrs
        .iter()
        .flatten()
        .chain(&spec.pod_cidr)
        .find(|c| crate::cni::parse_cidr(c).is_ok())
        .cloned()
}

async fn wait_for_pod_cidr<F, Fut>(mut fetch: F, first_retry: Duration) -> String
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<Option<String>>>,
{
    let mut outage = edge_common::Outage::default();
    let mut delay = first_retry;
    loop {
        let result = match fetch().await {
            Ok(Some(cidr)) => Ok(cidr),
            Ok(None) => Err("the Node has no IPv4 pod CIDR yet".to_string()),
            Err(e) => Err(format!("{e:#}")),
        };
        outage.observe("the Node's pod CIDR", &result);
        if let Ok(cidr) = result {
            return cidr;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

// Only a second consecutive failed set-up clears the pins, so a transient
// failure cannot detach a working dataplane.
async fn dataplane(pod_cidr: &str, failures: &Cell<u32>, nat: &NatSender) -> anyhow::Result<()> {
    let setup = (|| -> anyhow::Result<_> {
        let vdir = pins::version_dir();
        // Two loads of one object sharing the pinned maps: the socket and veth
        // hooks are taken over independently, each once its own maps are ready.
        let (mut sockets, programmer) = load_services(&vdir)?;
        let port_maps = load_port_maps(&mut sockets)?;
        let veths = pins::load(&vdir)?;
        Ok((sockets, veths, vdir, programmer, port_maps))
    })();
    let (sockets, veths, vdir, programmer, port_maps) = match setup {
        Ok(x) => {
            failures.set(0);
            x
        }
        Err(e) => {
            failures.set(failures.get() + 1);
            if failures.get() >= 2 {
                tracing::error!(
                    error = %format!("{e:#}"),
                    "dataplane set-up failed twice in a row; clearing this version's pins"
                );
                pins::purge_version_dir(std::path::Path::new(&pins::version_dir()));
            }
            return Err(e);
        }
    };
    let pods = Pods::default();
    let _watch = AbortOnDrop(tokio::spawn(watch_pods(pods.clone())));
    // A policy failure never ends the service sync: the pinned policy holds.
    tokio::select! {
        r = sync_loop(programmer, sockets, &vdir, nat) => r,
        r = policy_loop(veths, &vdir, pod_cidr, &pods) => r,
        r = ports_loop(port_maps, pod_cidr, &pods, nat) => r,
    }
}

pub fn load_services(vdir: &str) -> anyhow::Result<(aya::Ebpf, Programmer<AyaMaps>)> {
    let mut sockets = pins::load(vdir)?;
    pins::load_socket_programs(&mut sockets)?;
    let services: BpfHashMap<_, ServiceKey, ServiceVal> = BpfHashMap::try_from(
        sockets
            .take_map("SERVICES")
            .context("the object has no SERVICES map")?,
    )?;
    let backends: BpfHashMap<_, BackendKey, BackendVal> = BpfHashMap::try_from(
        sockets
            .take_map("BACKENDS")
            .context("the object has no BACKENDS map")?,
    )?;
    let programmer = Programmer::seed(AyaMaps { services, backends })
        .context("adopt the pinned service maps")?;
    Ok((sockets, programmer))
}

pub struct PortMaps {
    pub node_addrs: BpfHashMap<MapData, u32, u8>,
    pub host_ports: BpfHashMap<MapData, ServiceKey, BackendVal>,
}

pub fn load_port_maps(sockets: &mut aya::Ebpf) -> anyhow::Result<PortMaps> {
    Ok(PortMaps {
        node_addrs: BpfHashMap::try_from(sockets.take_map("NODE_ADDRS").context("no NODE_ADDRS")?)?,
        host_ports: BpfHashMap::try_from(sockets.take_map("HOSTPORTS").context("no HOSTPORTS")?)?,
    })
}

// `None` until its first full listing, so a restart keeps the installed forwarding.
#[derive(Debug, Default)]
pub struct NatForwards {
    node_ports: Option<Vec<Forward>>,
    host_ports: Option<Vec<Forward>>,
}

impl NatForwards {
    fn known(&self) -> Option<Vec<Forward>> {
        Some([self.host_ports.clone()?, self.node_ports.clone()?].concat())
    }
}

type NatSender = tokio::sync::watch::Sender<NatForwards>;

fn publish(slot: &mut Option<Vec<Forward>>, forwards: Vec<Forward>) -> bool {
    let changed = slot.as_ref() != Some(&forwards);
    *slot = Some(forwards);
    changed
}

fn nat_ensure(pod_cidr: &str, forwards: Option<&[Forward]>) -> bool {
    let Ok((net, prefix)) = crate::cni::parse_cidr(pod_cidr) else {
        return false;
    };
    match crate::nft::ensure(net, prefix, forwards) {
        Ok(crate::nft::Outcome::Present) => true,
        Ok(crate::nft::Outcome::Installed) => {
            tracing::info!(
                cidr = pod_cidr,
                forwards = forwards.map(<[Forward]>::len),
                "egress masquerade installed"
            );
            true
        }
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "cannot install the egress masquerade or port forwarding; pods cannot reach off-node addresses, or off-node clients node and host ports");
            false
        }
    }
}

// Re-checked while it holds: a flushed ruleset would otherwise cut pods off
// until a restart.
async fn nat_task(pod_cidr: &str, mut forwards: tokio::sync::watch::Receiver<NatForwards>) {
    let mut delay = Duration::from_secs(1);
    loop {
        let known = forwards.borrow_and_update().known();
        let cidr = pod_cidr.to_string();
        let ok = tokio::task::spawn_blocking(move || nat_ensure(&cidr, known.as_deref()))
            .await
            .unwrap_or(false);
        let wait = if ok {
            delay = Duration::from_secs(1);
            NAT_TICK
        } else {
            let d = delay;
            delay = (delay * 2).min(Duration::from_secs(30));
            d
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            changed = forwards.changed() => {
                if changed.is_err() {
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

async fn ports_loop(
    mut maps: PortMaps,
    pod_cidr: &str,
    pods: &Pods,
    nat: &NatSender,
) -> anyhow::Result<()> {
    let (network, prefix) = crate::cni::parse_cidr(pod_cidr)?;
    let pool = crate::ipam::Pool::new(network, prefix)?;
    let mut net = crate::netlink::Net::open()?;
    loop {
        if let Err(e) = program_ports(&mut maps, &pool, &net, pods, nat).await {
            tracing::error!(error = %format!("{e:#}"), "cannot program the node and host ports; retrying");
            if let Ok(fresh) = crate::netlink::Net::open() {
                net = fresh;
            }
        }
        tokio::time::sleep(POLICY_TICK).await;
    }
}

async fn program_ports(
    maps: &mut PortMaps,
    pool: &crate::ipam::Pool,
    net: &crate::netlink::Net,
    pods: &Pods,
    nat: &NatSender,
) -> anyhow::Result<()> {
    let addrs = net.local_addrs().await?;
    if ports::reconcile(&mut maps.node_addrs, &ports::node_addr_entries(&addrs))
        .context("program NODE_ADDRS")?
        > 0
    {
        tracing::info!(addresses = ?addrs, "node addresses programmed");
    }
    let host_ports = pods.lock().unwrap().as_ref().map(|p| p.host_ports.clone());
    let Some(host_ports) = host_ports else {
        return Ok(());
    };
    let live = net
        .pod_veths(pool)
        .await?
        .into_iter()
        .map(|(_, ip)| ip)
        .collect();
    let want = ports::host_port_entries(&host_ports, &live);
    if ports::reconcile(&mut maps.host_ports, &want).context("program HOSTPORTS")? > 0 {
        tracing::info!(entries = want.len(), "host ports programmed");
    }
    nat.send_if_modified(|f| publish(&mut f.host_ports, ports::forwards(&want)));
    Ok(())
}

// Returns only on error: after a failed map write the maps no longer match, and
// the next dataplane life adopts and reconciles them.
async fn sync_loop(
    programmer: Programmer<AyaMaps>,
    mut sockets: aya::Ebpf,
    vdir: &str,
    nat: &NatSender,
) -> anyhow::Result<()> {
    let client = Client::try_default()
        .await
        .context("build the kube client")?;
    let programmer = RefCell::new(programmer);
    tracing::info!(
        entries = programmer.borrow().service_count(),
        "adopted the pinned service maps"
    );

    let publish_node_ports = |p: &Programmer<AyaMaps>| {
        nat.send_if_modified(|f| publish(&mut f.node_ports, p.node_ports()));
    };
    let result = edge_kube::run(
        client,
        |view, key| {
            let mut p = programmer.borrow_mut();
            p.on_change(view, key)?;
            if p.is_synced() {
                publish_node_ports(&p);
            }
            Ok(())
        },
        |view| {
            programmer.borrow_mut().on_synced(view)?;
            publish_node_ports(&programmer.borrow());
            // Only after the reconcile: CNI ADD waits on this.
            std::fs::create_dir_all(format!("{vdir}/{SYNCED}"))
                .context("mark the dataplane synced")?;
            tracing::info!("initial service listing programmed; pods may start");
            pins::take_over_sockets(&mut sockets, vdir, Path::new(ROOT_CGROUP))
                .context("attach the socket programs")
        },
    )
    .await;
    if let Err(e) = &result {
        tracing::error!(error = %format!("{e:#}"), "service map sync stopped");
    }
    result
}

type Pods = Arc<Mutex<Option<PodView>>>;

struct PodView {
    policy: BTreeMap<Ipv4Addr, PodPolicy>,
    host_ports: Vec<(Ipv4Addr, HostPort)>,
}

impl PodView {
    fn of(view: &PolicyView) -> Self {
        let mut pods: Vec<(&String, &edge_kube::policy::PodInfo)> = view.pods.iter().collect();
        pods.sort_by_key(|(k, _)| *k);
        Self {
            policy: edge_kube::policy::compile(view),
            host_ports: pods
                .into_iter()
                .filter_map(|(_, p)| Some((p.ip?, &p.host_ports)))
                .flat_map(|(ip, host_ports)| host_ports.iter().map(move |hp| (ip, *hp)))
                .collect(),
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Nothing is written to the maps before the first full listing: a restart must
// not clear the isolation the previous run programmed.
async fn policy_loop(
    mut bpf: aya::Ebpf,
    vdir: &str,
    pod_cidr: &str,
    pods: &Pods,
) -> anyhow::Result<()> {
    let mut maps = match load_policy_datapath(&mut bpf) {
        Ok(m) => {
            // CNI ADD's signal that this daemon enforces policy.
            if let Err(e) = std::fs::create_dir_all(netpol::pin_dir(vdir)) {
                tracing::error!(error = %e, "cannot create the NetworkPolicy pin directory; hooks cannot be pinned");
            }
            m
        }
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "NetworkPolicy is NOT enforced: cannot set up the policy datapath");
            return std::future::pending().await;
        }
    };

    let (network, prefix) = crate::cni::parse_cidr(pod_cidr)?;
    let pool = crate::ipam::Pool::new(network, prefix)?;
    let mut net = loop {
        match crate::netlink::Net::open() {
            Ok(n) => break n,
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "cannot open a netlink socket for NetworkPolicy; retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    let mut state = PolicyState {
        programmed: None,
        logged_unsynced: false,
    };
    loop {
        tokio::time::sleep(POLICY_TICK).await;
        if let Err(e) = state
            .tick(&mut bpf, vdir, &pool, &net, pods, &mut maps)
            .await
        {
            tracing::error!(error = %format!("{e:#}"), "NetworkPolicy reconcile failed; retrying");
            // The netlink connection task can end, failing every later call.
            if let Ok(fresh) = crate::netlink::Net::open() {
                net = fresh;
            }
        }
    }
}

fn load_policy_datapath(bpf: &mut aya::Ebpf) -> anyhow::Result<AyaPolicyMaps> {
    netpol::load_programs(bpf)?;
    Ok(AyaPolicyMaps {
        pods: BpfHashMap::try_from(bpf.take_map("NP_PODS").context("no NP_PODS")?)?,
        pod_ips: BpfHashMap::try_from(bpf.take_map("NP_POD_IPS").context("no NP_POD_IPS")?)?,
        allow: aya::maps::lpm_trie::LpmTrie::try_from(
            bpf.take_map("NP_ALLOW").context("no NP_ALLOW")?,
        )?,
        armed: aya::maps::Array::try_from(bpf.take_map("NP_ARMED").context("no NP_ARMED")?)?,
    })
}

async fn watch_pods(pods: Pods) {
    loop {
        let publish = |view: &PolicyView| {
            *pods.lock().unwrap() = Some(PodView::of(view));
            Ok(())
        };
        let result = match Client::try_default().await {
            Ok(client) => edge_kube::policy::run(client, publish, publish).await,
            Err(e) => Err(e.into()),
        };
        if let Err(e) = result {
            tracing::error!(error = %format!("{e:#}"), "the NetworkPolicy watch stopped; policy stays as last programmed, retrying in 5s");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

struct PolicyState {
    programmed: Option<netpol::Desired>,
    logged_unsynced: bool,
}

struct HookedVeth {
    ifindex: u32,
    ip: Ipv4Addr,
    name: String,
    inherited: bool,
}

impl PolicyState {
    async fn tick(
        &mut self,
        bpf: &mut aya::Ebpf,
        vdir: &str,
        pool: &crate::ipam::Pool,
        net: &crate::netlink::Net,
        pods: &Mutex<Option<PodView>>,
        maps: &mut AyaPolicyMaps,
    ) -> anyhow::Result<()> {
        let veths = net.pod_veths(pool).await?;
        let mut hooked = Vec::new();
        let mut live: HashSet<String> = HashSet::new();
        for (ifindex, ip) in veths {
            let name = match net.link_name(ifindex).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(ifindex, error = %format!("{e:#}"), "cannot name a pod veth; skipping it this tick");
                    continue;
                }
            };
            if !name.starts_with("edge") {
                continue;
            }
            live.insert(name.clone());
            match netpol::hook_veth(bpf, vdir, &name, false) {
                Ok(h) => {
                    if h.attached {
                        tracing::info!(veth = %name, pod = %ip, "NetworkPolicy hooks attached");
                    }
                    hooked.push(HookedVeth {
                        ifindex,
                        ip,
                        name,
                        inherited: h.inherited,
                    });
                }
                Err(e) => {
                    tracing::error!(veth = %name, pod = %ip, error = %format!("{e:#}"), "cannot attach the NetworkPolicy hooks; the pod is unfiltered until this works");
                }
            }
        }
        netpol::prune_pins(vdir, &live);

        let policy = pods.lock().unwrap().as_ref().map(|p| p.policy.clone());
        let take_over = self.program(maps, &hooked, policy.as_ref())?;
        if !take_over.is_empty() {
            let carried = pins::carry_over::<CtKey, u8>(std::path::Path::new(vdir), "NP_CT");
            tracing::info!(
                veths = take_over.len(),
                carried,
                "taking the NetworkPolicy hooks over from the old version"
            );
        }
        for name in take_over {
            if let Err(e) = netpol::hook_veth(bpf, vdir, &name, true) {
                tracing::error!(veth = %name, error = %format!("{e:#}"), "cannot take the NetworkPolicy hooks over; the old version keeps filtering");
            }
        }
        let retired = pins::retire_old_versions(std::path::Path::new(vdir), &live);
        if retired > 0 {
            tracing::info!(retired, "removed the old dataplane versions");
        }
        Ok(())
    }

    // Returns the veths another version still filters: they are taken over only
    // once the maps hold their policy.
    fn program<M: PolicyMaps>(
        &mut self,
        maps: &mut M,
        hooked: &[HookedVeth],
        compiled: Option<&BTreeMap<Ipv4Addr, PodPolicy>>,
    ) -> anyhow::Result<Vec<String>> {
        let Some(policy) = compiled else {
            if !self.logged_unsynced {
                tracing::info!(
                    "waiting for the first full listing of pods, namespaces and policies before programming NetworkPolicy"
                );
                self.logged_unsynced = true;
            }
            return Ok(Vec::new());
        };
        let attached = hooked.iter().map(|v| (v.ifindex, v.ip)).collect();
        let want = netpol::lower(policy, &attached);
        if self.programmed.as_ref() != Some(&want) {
            if want.dropped_ranges > 0 {
                tracing::error!(
                    dropped = want.dropped_ranges,
                    "NetworkPolicy allows more port ranges towards one peer than the datapath holds ({}); the excess are REFUSED",
                    edge_cni_common::MAX_RANGES
                );
            }
            let writes = netpol::reconcile(maps, &want)?;
            tracing::info!(
                writes,
                pods = want.pods.len(),
                rules = want.allow.len(),
                armed = want.armed,
                "NetworkPolicy programmed"
            );
            self.programmed = Some(want);
        }
        Ok(hooked
            .iter()
            .filter(|v| v.inherited)
            .map(|v| v.name.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Mem;

    fn veth(ifindex: u32, ip: &str, inherited: bool) -> HookedVeth {
        HookedVeth {
            ifindex,
            ip: ip.parse().unwrap(),
            name: format!("edge{ifindex}"),
            inherited,
        }
    }

    fn isolating(ip: &str) -> BTreeMap<Ipv4Addr, PodPolicy> {
        BTreeMap::from([(
            ip.parse().unwrap(),
            PodPolicy {
                ingress: Some(Vec::new()),
                egress: None,
            },
        )])
    }

    fn node(pod_cidr: Option<&str>, pod_cidrs: &[&str]) -> Node {
        Node {
            spec: Some(k8s_openapi::api::core::v1::NodeSpec {
                pod_cidr: pod_cidr.map(str::to_string),
                pod_cidrs: Some(pod_cidrs.iter().map(|c| c.to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn node_pod_cidr_is_ipv4() {
        let v4 = Some("10.244.0.0/24".to_string());
        assert_eq!(
            pod_cidr_of(&node(Some("fd00::/64"), &["fd00::/64", "10.244.0.0/24"])),
            v4
        );
        assert_eq!(pod_cidr_of(&node(Some("10.244.0.0/24"), &[])), v4);
        assert_eq!(pod_cidr_of(&node(Some("fd00::/24"), &["junk"])), None);
        assert_eq!(pod_cidr_of(&node(None, &[])), None);
        assert_eq!(pod_cidr_of(&Node::default()), None);
    }

    #[tokio::test]
    async fn waits_for_node_pod_cidr() {
        let mut answers = [
            Err(anyhow::anyhow!("connection refused")),
            Ok(None),
            Ok(Some("10.244.0.0/24".to_string())),
        ]
        .into_iter();
        let calls = Cell::new(0);
        let fetch = || {
            calls.set(calls.get() + 1);
            let answer = answers.next().expect("asked again after an answer");
            async move { answer }
        };
        let cidr = wait_for_pod_cidr(fetch, Duration::from_millis(1)).await;
        assert_eq!(cidr, "10.244.0.0/24");
        assert_eq!(calls.get(), 3);
    }

    fn state() -> PolicyState {
        PolicyState {
            programmed: None,
            logged_unsynced: false,
        }
    }

    fn fwd(port: u16) -> Forward {
        Forward {
            proto: edge_cni_common::IPPROTO_TCP,
            addr: None,
            port,
            backends: vec!["10.244.0.5:8080".parse().unwrap()],
        }
    }

    #[test]
    fn forwards_known_once_both_listed() {
        let mut f = NatForwards::default();
        assert_eq!(f.known(), None);
        assert!(publish(&mut f.node_ports, vec![fwd(30080)]));
        assert_eq!(f.known(), None, "host ports not yet listed");
        assert!(publish(&mut f.host_ports, vec![]));
        assert_eq!(f.known(), Some(vec![fwd(30080)]));
        assert!(publish(&mut f.host_ports, vec![fwd(80)]));
        assert_eq!(f.known(), Some(vec![fwd(80), fwd(30080)]));
    }

    #[test]
    fn unchanged_forwards_not_republished() {
        let mut slot = None;
        assert!(publish(&mut slot, vec![]), "first listing");
        assert!(!publish(&mut slot, vec![]));
        assert!(publish(&mut slot, vec![fwd(1)]));
        assert!(!publish(&mut slot, vec![fwd(1)]));
    }

    #[test]
    fn pod_view_lists_host_ports_of_addressed_pods() {
        let hp = |port| HostPort {
            proto: edge_kube::policy::Proto::Tcp,
            host_ip: None,
            host_port: port,
            container_port: 8080,
        };
        let pod = |name: &str, ip: Option<&str>, ports: Vec<HostPort>| edge_kube::policy::PodInfo {
            namespace: "ns".into(),
            name: name.into(),
            ip: ip.map(|i| i.parse().unwrap()),
            host_ports: ports,
            ..Default::default()
        };
        let mut view = PolicyView::default();
        for p in [
            pod("b", Some("10.244.0.6"), vec![hp(81)]),
            pod("a", Some("10.244.0.5"), vec![hp(80), hp(82)]),
            pod("pending", None, vec![hp(83)]),
        ] {
            view.pods.insert(format!("ns/{}", p.name), p);
        }
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            PodView::of(&view).host_ports,
            [
                (ip("10.244.0.5"), hp(80)),
                (ip("10.244.0.5"), hp(82)),
                (ip("10.244.0.6"), hp(81)),
            ],
            "sorted by pod, so the first claim of a port is stable"
        );
    }

    #[test]
    fn inherited_hooks_wait_for_policy() {
        let mut maps = Mem::default();
        let hooked = [veth(11, "10.244.0.5", true)];
        let take_over = state().program(&mut maps, &hooked, None).unwrap();
        assert!(take_over.is_empty());
        assert!(maps.log.is_empty(), "{:?}", maps.log);
    }

    #[test]
    fn inherited_hooks_taken_over_once_programmed() {
        let mut maps = Mem::default();
        let hooked = [veth(11, "10.244.0.5", true), veth(12, "10.244.0.6", false)];
        let compiled = isolating("10.244.0.5");
        let take_over = state()
            .program(&mut maps, &hooked, Some(&compiled))
            .unwrap();
        assert_eq!(take_over, ["edge11"]);
        assert_eq!(maps.pods[&11].flags, edge_cni_common::FLAG_INGRESS_ISOLATED);
        assert!(maps.pods.contains_key(&12));
        assert!(maps.armed);
    }

    #[test]
    fn unchanged_policy_still_hands_over() {
        let mut maps = Mem::default();
        let mut state = state();
        let compiled = isolating("10.244.0.5");
        state
            .program(&mut maps, &[veth(11, "10.244.0.5", false)], Some(&compiled))
            .unwrap();
        maps.log.clear();
        let take_over = state
            .program(&mut maps, &[veth(11, "10.244.0.5", true)], Some(&compiled))
            .unwrap();
        assert_eq!(take_over, ["edge11"]);
        assert!(maps.log.is_empty(), "{:?}", maps.log);
    }

    #[test]
    fn failed_write_keeps_old_hooks() {
        let mut maps = Mem {
            fail_writes: true,
            ..Mem::default()
        };
        let hooked = [veth(11, "10.244.0.5", true)];
        let compiled = isolating("10.244.0.5");
        let mut state = state();
        assert!(state.program(&mut maps, &hooked, Some(&compiled)).is_err());
        assert!(state.programmed.is_none());
    }
}
