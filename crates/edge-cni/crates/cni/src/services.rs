//! The maps are pinned, so a restart adopts them and writes nothing before the
//! first full listing: a Service seen before its slices looks backend-less.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::Context;
use edge_cni_common::{
    ANY_NODE_ADDR, BackendKey, BackendVal, IPPROTO_TCP, IPPROTO_UDP, ServiceKey, ServiceVal,
};
use edge_kube::ServiceView;

use crate::nft::Forward;
use k8s_openapi::api::core::v1::{Service, ServiceSpec};
use k8s_openapi::api::discovery::v1::EndpointSlice;

// Deleting an absent key is Ok.
pub trait ServiceMaps {
    fn dump_services(&self) -> anyhow::Result<Vec<(ServiceKey, ServiceVal)>>;
    fn dump_backends(&self) -> anyhow::Result<Vec<(BackendKey, BackendVal)>>;
    fn put_service(&mut self, key: &ServiceKey, val: &ServiceVal) -> anyhow::Result<()>;
    fn put_backend(&mut self, key: &BackendKey, val: &BackendVal) -> anyhow::Result<()>;
    fn del_service(&mut self, key: &ServiceKey) -> anyhow::Result<()>;
    fn del_backend(&mut self, key: &BackendKey) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Desired {
    pub entries: Vec<(ServiceKey, Vec<BackendVal>)>,
    pub affinity_secs: u32,
}

const DEFAULT_AFFINITY_SECS: i32 = 10800;

fn affinity_secs(spec: &ServiceSpec) -> u32 {
    if spec.session_affinity.as_deref() != Some("ClientIP") {
        return 0;
    }
    let timeout = spec
        .session_affinity_config
        .as_ref()
        .and_then(|c| c.client_ip.as_ref())
        .and_then(|c| c.timeout_seconds)
        .unwrap_or(DEFAULT_AFFINITY_SECS);
    u32::try_from(timeout).unwrap_or(0).max(1)
}

// Slice ports are matched to service ports by name, which is how targetPort resolves.
pub fn desired_for(svc: Option<&Service>, slices: &[EndpointSlice]) -> Desired {
    let Some(svc) = svc else {
        return Desired::default();
    };
    let Some(spec) = &svc.spec else {
        return Desired::default();
    };
    let Some(ip) = spec
        .cluster_ip
        .as_deref()
        .filter(|ip| *ip != "None")
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
    else {
        return Desired::default();
    };

    let mut entries = Vec::new();
    for port in spec.ports.iter().flatten() {
        let proto = match port.protocol.as_deref() {
            Some("UDP") => IPPROTO_UDP,
            Some("SCTP") => continue,
            _ => IPPROTO_TCP,
        };
        // Readiness is selected over all slices at once: the terminating
        // fallback applies only when no endpoint of the service is ready.
        let mut candidates = Vec::new();
        for slice in slices {
            // An unnamed port is `None` on the Service and `Some("")` on a slice.
            let Some(slice_port) = slice
                .ports
                .iter()
                .flatten()
                .find(|p| p.name.as_deref().unwrap_or("") == port.name.as_deref().unwrap_or(""))
                .and_then(|p| p.port)
            else {
                continue;
            };
            for ep in slice.endpoints.iter().flatten() {
                candidates.push((ep, slice_port));
            }
        }
        let mut backs = Vec::new();
        for (ep, slice_port) in edge_kube::select_with(candidates, |c| c.0) {
            for addr in &ep.addresses {
                if let Ok(a) = addr.parse::<Ipv4Addr>() {
                    backs.push(BackendVal {
                        addr: u32::from(a).to_be(),
                        port: (slice_port as u16).to_be(),
                        _pad: 0,
                    });
                }
            }
        }
        backs.sort_by_key(|b| (b.addr, b.port));
        backs.dedup();
        let key = |addr: u32, port: i32| ServiceKey {
            addr,
            port: (port as u16).to_be(),
            proto,
            _pad: 0,
        };
        if let Some(node_port) = port.node_port.filter(|p| (1..=65535).contains(p)) {
            entries.push((key(ANY_NODE_ADDR, node_port), backs.clone()));
        }
        entries.push((key(u32::from(ip).to_be(), port.port), backs));
    }
    entries.sort_by_key(|(k, _)| (k.addr, k.port, k.proto));
    Desired {
        entries,
        affinity_secs: affinity_secs(spec),
    }
}

pub struct Programmer<M: ServiceMaps> {
    maps: M,
    svc: HashMap<ServiceKey, ServiceVal>,
    backends: HashMap<u32, BTreeMap<u32, BackendVal>>,
    // Includes BACKENDS' ids, so a new service never lands on one with leftovers.
    ids: BTreeSet<u32>,
    owned: HashMap<String, Vec<ServiceKey>>,
    synced: bool,
}

impl<M: ServiceMaps> Programmer<M> {
    pub fn seed(maps: M) -> anyhow::Result<Self> {
        let mut p = Self {
            svc: HashMap::new(),
            backends: HashMap::new(),
            ids: BTreeSet::new(),
            owned: HashMap::new(),
            synced: false,
            maps,
        };
        for (k, v) in p.maps.dump_services().context("read the SERVICES map")? {
            p.ids.insert(v.id);
            p.svc.insert(k, v);
        }
        for (k, v) in p.maps.dump_backends().context("read the BACKENDS map")? {
            p.ids.insert(k.id);
            p.backends.entry(k.id).or_default().insert(k.slot, v);
        }
        Ok(p)
    }

    pub fn service_count(&self) -> usize {
        self.svc.len()
    }

    pub fn is_synced(&self) -> bool {
        self.synced
    }

    pub fn node_ports(&self) -> Vec<Forward> {
        let mut out: Vec<Forward> = self
            .svc
            .iter()
            .filter(|(k, v)| k.addr == ANY_NODE_ADDR && v.backend_count > 0)
            .map(|(k, v)| Forward {
                proto: k.proto,
                addr: None,
                port: u16::from_be(k.port),
                backends: self
                    .backends
                    .get(&v.id)
                    .into_iter()
                    .flat_map(|slots| slots.range(..v.backend_count).map(|(_, b)| socket_addr(b)))
                    .collect(),
            })
            .collect();
        out.sort_by_key(|f| (f.proto, f.port));
        out
    }

    pub fn on_change(&mut self, view: &ServiceView, key: &str) -> anyhow::Result<()> {
        if !self.synced {
            return Ok(());
        }
        let desired = desired_for(view.services.get(key), view.slices_for(key));
        let mut changed = false;
        for (k, backs) in &desired.entries {
            changed |= self.set_entry(k, backs, desired.affinity_secs)?;
        }
        let keep: Vec<ServiceKey> = desired.entries.iter().map(|(k, _)| *k).collect();
        if let Some(prev) = self.owned.get(key).cloned() {
            for k in prev.iter().filter(|k| !keep.contains(k)) {
                changed |= self.remove_entry(k)?;
            }
        }
        if keep.is_empty() {
            self.owned.remove(key);
        } else {
            self.owned.insert(key.to_string(), keep);
        }
        if changed {
            tracing::info!(service = %key, entries = desired.entries.len(), "service programmed");
        }
        Ok(())
    }

    pub fn on_synced(&mut self, view: &ServiceView) -> anyhow::Result<()> {
        let adopted = self.svc.len();
        let mut target: BTreeSet<ServiceKey> = BTreeSet::new();
        let mut owned = HashMap::new();
        let mut keys: Vec<&String> = view.services.keys().collect();
        keys.sort();
        for key in keys {
            let desired = desired_for(view.services.get(key), view.slices_for(key));
            for (k, backs) in &desired.entries {
                self.set_entry(k, backs, desired.affinity_secs)?;
                target.insert(*k);
            }
            if !desired.entries.is_empty() {
                owned.insert(
                    key.clone(),
                    desired.entries.iter().map(|(k, _)| *k).collect(),
                );
            }
        }
        let stale: Vec<ServiceKey> = self
            .svc
            .keys()
            .filter(|k| !target.contains(k))
            .copied()
            .collect();
        for k in &stale {
            self.remove_entry(k)?;
        }
        let orphans = self.gc_backends()?;
        self.owned = owned;
        self.synced = true;
        tracing::info!(
            adopted,
            programmed = self.svc.len(),
            stale_removed = stale.len(),
            orphan_backends_removed = orphans,
            "reconciled the service maps to the first full listing"
        );
        Ok(())
    }

    // The lowest free id, so churn cannot walk towards u32::MAX.
    fn alloc_id(&self) -> u32 {
        let mut candidate = 1;
        for id in self.ids.range(1..) {
            if *id != candidate {
                break;
            }
            candidate += 1;
        }
        candidate
    }

    // Backends before the count and surplus slots after it, so a lookup never
    // follows the count to an unwritten slot.
    fn set_entry(
        &mut self,
        key: &ServiceKey,
        backs: &[BackendVal],
        affinity_secs: u32,
    ) -> anyhow::Result<bool> {
        let id = match self.svc.get(key) {
            Some(v) => v.id,
            None => self.alloc_id(),
        };
        self.ids.insert(id);
        let mut changed = false;
        for (slot, b) in backs.iter().enumerate() {
            let slot = slot as u32;
            if self.backends.get(&id).and_then(|m| m.get(&slot)) == Some(b) {
                continue;
            }
            self.maps
                .put_backend(&BackendKey { id, slot }, b)
                .context("write a BACKENDS entry")?;
            self.backends.entry(id).or_default().insert(slot, *b);
            changed = true;
        }
        let want = ServiceVal {
            id,
            backend_count: backs.len() as u32,
            affinity_secs,
        };
        if self.svc.get(key) != Some(&want) {
            self.maps
                .put_service(key, &want)
                .context("write a SERVICES entry")?;
            self.svc.insert(*key, want);
            changed = true;
        }
        let surplus: Vec<u32> = self
            .backends
            .get(&id)
            .map(|m| m.range(backs.len() as u32..).map(|(s, _)| *s).collect())
            .unwrap_or_default();
        for slot in surplus {
            self.maps
                .del_backend(&BackendKey { id, slot })
                .context("delete a BACKENDS entry")?;
            if let Some(m) = self.backends.get_mut(&id) {
                m.remove(&slot);
            }
            changed = true;
        }
        Ok(changed)
    }

    // The service first, so nothing points at the slots going away.
    fn remove_entry(&mut self, key: &ServiceKey) -> anyhow::Result<bool> {
        let Some(val) = self.svc.get(key).copied() else {
            return Ok(false);
        };
        self.maps
            .del_service(key)
            .context("delete a SERVICES entry")?;
        self.svc.remove(key);
        let slots: Vec<u32> = self
            .backends
            .get(&val.id)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for slot in slots {
            self.maps
                .del_backend(&BackendKey { id: val.id, slot })
                .context("delete a BACKENDS entry")?;
            if let Some(m) = self.backends.get_mut(&val.id) {
                m.remove(&slot);
            }
        }
        self.backends.remove(&val.id);
        self.ids.remove(&val.id);
        Ok(true)
    }

    fn gc_backends(&mut self) -> anyhow::Result<usize> {
        let counts: HashMap<u32, u32> =
            self.svc.values().map(|v| (v.id, v.backend_count)).collect();
        let dead: Vec<BackendKey> = self
            .backends
            .iter()
            .flat_map(|(id, slots)| {
                let count = counts.get(id).copied();
                slots.keys().filter_map(move |slot| match count {
                    Some(c) if *slot < c => None,
                    _ => Some(BackendKey {
                        id: *id,
                        slot: *slot,
                    }),
                })
            })
            .collect();
        for k in &dead {
            self.maps
                .del_backend(k)
                .context("delete an orphaned BACKENDS entry")?;
            if let Some(m) = self.backends.get_mut(&k.id) {
                m.remove(&k.slot);
            }
        }
        self.backends.retain(|_, m| !m.is_empty());
        self.ids = self
            .svc
            .values()
            .map(|v| v.id)
            .chain(self.backends.keys().copied())
            .collect();
        Ok(dead.len())
    }
}

pub fn socket_addr(b: &BackendVal) -> SocketAddrV4 {
    SocketAddrV4::new(u32::from_be(b.addr).into(), u16::from_be(b.port))
}

pub struct AyaMaps {
    pub services: aya::maps::HashMap<aya::maps::MapData, ServiceKey, ServiceVal>,
    pub backends: aya::maps::HashMap<aya::maps::MapData, BackendKey, BackendVal>,
}

impl ServiceMaps for AyaMaps {
    fn dump_services(&self) -> anyhow::Result<Vec<(ServiceKey, ServiceVal)>> {
        Ok(self.services.iter().collect::<Result<_, _>>()?)
    }
    fn dump_backends(&self) -> anyhow::Result<Vec<(BackendKey, BackendVal)>> {
        Ok(self.backends.iter().collect::<Result<_, _>>()?)
    }
    fn put_service(&mut self, key: &ServiceKey, val: &ServiceVal) -> anyhow::Result<()> {
        Ok(self.services.insert(key, val, 0)?)
    }
    fn put_backend(&mut self, key: &BackendKey, val: &BackendVal) -> anyhow::Result<()> {
        Ok(self.backends.insert(key, val, 0)?)
    }
    fn del_service(&mut self, key: &ServiceKey) -> anyhow::Result<()> {
        absent_is_fine(self.services.remove(key))
    }
    fn del_backend(&mut self, key: &BackendKey) -> anyhow::Result<()> {
        absent_is_fine(self.backends.remove(key))
    }
}

// aya reports deleting an absent key as a raw ENOENT syscall error.
pub(crate) fn absent_is_fine(r: Result<(), aya::maps::MapError>) -> anyhow::Result<()> {
    match r {
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        other => Ok(other?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ClientIPConfig, ServicePort, SessionAffinityConfig};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};

    fn svc_named(ns: &str, name: &str, ip: &str, ports: &[(Option<&str>, i32, &str)]) -> Service {
        let mut s = Service::default();
        s.metadata.name = Some(name.into());
        s.metadata.namespace = Some(ns.into());
        s.spec = Some(k8s_openapi::api::core::v1::ServiceSpec {
            cluster_ip: Some(ip.into()),
            ports: Some(
                ports
                    .iter()
                    .map(|(name, port, proto)| ServicePort {
                        name: name.map(|n| n.to_string()),
                        port: *port,
                        protocol: Some(proto.to_string()),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        });
        s
    }

    fn svc(ip: &str, ports: &[(Option<&str>, i32, &str)]) -> Service {
        svc_named("ns", "s", ip, ports)
    }

    fn slice_for(
        owner: &str,
        port_name: Option<&str>,
        port: i32,
        addrs: &[(&str, Option<bool>)],
    ) -> EndpointSlice {
        let mut e = EndpointSlice {
            address_type: "IPv4".into(),
            ..Default::default()
        };
        e.metadata.name = Some(format!("{owner}-sl"));
        e.metadata.namespace = Some("ns".into());
        e.metadata.labels =
            Some([("kubernetes.io/service-name".to_string(), owner.to_string())].into());
        e.ports = Some(vec![EndpointPort {
            name: port_name.map(|n| n.to_string()),
            port: Some(port),
            ..Default::default()
        }]);
        e.endpoints = Some(
            addrs
                .iter()
                .map(|(a, ready)| Endpoint {
                    addresses: vec![a.to_string()],
                    conditions: Some(EndpointConditions {
                        ready: *ready,
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
        );
        e
    }

    fn slice(port_name: Option<&str>, port: i32, addrs: &[(&str, bool)]) -> EndpointSlice {
        let addrs: Vec<(&str, Option<bool>)> = addrs.iter().map(|(a, r)| (*a, Some(*r))).collect();
        slice_for("s", port_name, port, &addrs)
    }

    fn ip(a: [u8; 4]) -> u32 {
        u32::from(Ipv4Addr::from(a)).to_be()
    }

    fn skey(a: [u8; 4], port: u16) -> ServiceKey {
        ServiceKey {
            addr: ip(a),
            port: port.to_be(),
            proto: IPPROTO_TCP,
            _pad: 0,
        }
    }

    fn back(a: [u8; 4], port: u16) -> BackendVal {
        BackendVal {
            addr: ip(a),
            port: port.to_be(),
            _pad: 0,
        }
    }

    #[derive(Default)]
    struct Mem {
        services: HashMap<ServiceKey, ServiceVal>,
        backends: HashMap<(u32, u32), BackendVal>,
        writes: usize,
        budget: Option<usize>,
        service_log: Vec<(ServiceKey, ServiceVal)>,
    }

    impl Mem {
        fn spend(&mut self) -> anyhow::Result<()> {
            if let Some(b) = self.budget.as_mut() {
                if *b == 0 {
                    anyhow::bail!("E2BIG");
                }
                *b -= 1;
            }
            self.writes += 1;
            Ok(())
        }
    }

    impl ServiceMaps for Mem {
        fn dump_services(&self) -> anyhow::Result<Vec<(ServiceKey, ServiceVal)>> {
            Ok(self.services.iter().map(|(k, v)| (*k, *v)).collect())
        }
        fn dump_backends(&self) -> anyhow::Result<Vec<(BackendKey, BackendVal)>> {
            Ok(self
                .backends
                .iter()
                .map(|((id, slot), v)| {
                    (
                        BackendKey {
                            id: *id,
                            slot: *slot,
                        },
                        *v,
                    )
                })
                .collect())
        }
        fn put_service(&mut self, k: &ServiceKey, v: &ServiceVal) -> anyhow::Result<()> {
            self.spend()?;
            self.service_log.push((*k, *v));
            self.services.insert(*k, *v);
            Ok(())
        }
        fn put_backend(&mut self, k: &BackendKey, v: &BackendVal) -> anyhow::Result<()> {
            self.spend()?;
            self.backends.insert((k.id, k.slot), *v);
            Ok(())
        }
        fn del_service(&mut self, k: &ServiceKey) -> anyhow::Result<()> {
            self.spend()?;
            self.services.remove(k);
            Ok(())
        }
        fn del_backend(&mut self, k: &BackendKey) -> anyhow::Result<()> {
            self.spend()?;
            self.backends.remove(&(k.id, k.slot));
            Ok(())
        }
    }

    fn view(services: Vec<Service>, slices: Vec<EndpointSlice>) -> ServiceView {
        let mut v = ServiceView::default();
        for s in services {
            v.apply_service(s);
        }
        for s in slices {
            v.apply_slice(s);
        }
        v
    }

    fn with_node_port(mut s: Service, node_port: i32) -> Service {
        let spec = s.spec.as_mut().unwrap();
        spec.type_ = Some("NodePort".into());
        spec.ports.as_mut().unwrap()[0].node_port = Some(node_port);
        s
    }

    fn with_affinity(mut s: Service, timeout: Option<i32>) -> Service {
        let spec = s.spec.as_mut().unwrap();
        spec.session_affinity = Some("ClientIP".into());
        spec.session_affinity_config = timeout.map(|t| SessionAffinityConfig {
            client_ip: Some(ClientIPConfig {
                timeout_seconds: Some(t),
            }),
        });
        s
    }

    #[test]
    fn node_port_answers_on_node_addresses() {
        let s = with_node_port(svc("10.96.0.7", &[(None, 80, "TCP")]), 30080);
        let d = desired_for(Some(&s), &[slice(None, 8080, &[("10.244.0.3", true)])]);
        let any = ServiceKey {
            addr: ANY_NODE_ADDR,
            port: 30080u16.to_be(),
            proto: IPPROTO_TCP,
            _pad: 0,
        };
        assert_eq!(
            d.entries,
            [
                (any, vec![back([10, 244, 0, 3], 8080)]),
                (skey([10, 96, 0, 7], 80), vec![back([10, 244, 0, 3], 8080)]),
            ]
        );
    }

    #[test]
    fn client_ip_affinity_timeout() {
        let s = svc("10.96.0.7", &[(None, 80, "TCP")]);
        assert_eq!(desired_for(Some(&s), &[]).affinity_secs, 0);
        let mut none = s.clone();
        none.spec.as_mut().unwrap().session_affinity = Some("None".into());
        assert_eq!(desired_for(Some(&none), &[]).affinity_secs, 0);
        assert_eq!(
            desired_for(Some(&with_affinity(s.clone(), None)), &[]).affinity_secs,
            10800
        );
        assert_eq!(
            desired_for(Some(&with_affinity(s, Some(10))), &[]).affinity_secs,
            10
        );
    }

    #[test]
    fn affinity_switch_rewrites_service() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        p.on_synced(&ServiceView::default()).unwrap();
        let backends = slice_for("a", None, 8080, &[("10.244.0.3", Some(true))]);
        let a = svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")]);
        let sticky = view(
            vec![with_affinity(a.clone(), Some(30))],
            vec![backends.clone()],
        );
        p.on_change(&sticky, "ns/a").unwrap();
        assert_eq!(p.maps.services[&skey([10, 96, 0, 1], 80)].affinity_secs, 30);
        p.on_change(&view(vec![a], vec![backends]), "ns/a").unwrap();
        assert_eq!(p.maps.services[&skey([10, 96, 0, 1], 80)].affinity_secs, 0);
    }

    #[test]
    fn node_ports_forward_to_backends() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        let v = view(
            vec![
                with_node_port(
                    svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")]),
                    30080,
                ),
                with_node_port(
                    svc_named("ns", "b", "10.96.0.2", &[(None, 53, "UDP")]),
                    30053,
                ),
                svc_named("ns", "c", "10.96.0.3", &[(None, 80, "TCP")]),
            ],
            vec![
                slice_for(
                    "a",
                    None,
                    8080,
                    &[("10.244.0.4", Some(true)), ("10.244.0.3", Some(true))],
                ),
                slice_for("c", None, 8080, &[("10.244.0.5", Some(true))]),
            ],
        );
        p.on_synced(&v).unwrap();
        let backend = |a: [u8; 4]| SocketAddrV4::new(Ipv4Addr::from(a), 8080);
        assert_eq!(
            p.node_ports(),
            [Forward {
                proto: IPPROTO_TCP,
                addr: None,
                port: 30080,
                backends: vec![backend([10, 244, 0, 3]), backend([10, 244, 0, 4])],
            }],
            "no rule for a node port without backends, none for a ClusterIP"
        );
    }

    #[test]
    fn headless_and_sctp_skipped() {
        let d = desired_for(Some(&svc("None", &[(None, 80, "TCP")])), &[]);
        assert!(d.entries.is_empty());
        let d = desired_for(Some(&svc("10.96.0.7", &[(None, 80, "SCTP")])), &[]);
        assert!(d.entries.is_empty());
    }

    #[test]
    fn unready_endpoint_skipped() {
        let s = svc("10.96.0.7", &[(None, 80, "TCP")]);
        let sl = slice(None, 8080, &[("10.244.0.3", true), ("10.244.0.4", false)]);
        let d = desired_for(Some(&s), &[sl]);
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].1.len(), 1);
        assert_eq!(
            d.entries[0].1[0].addr,
            u32::from(Ipv4Addr::new(10, 244, 0, 3)).to_be()
        );
        assert_eq!(d.entries[0].1[0].port, 8080u16.to_be());
    }

    #[test]
    fn unset_ready_is_backend() {
        let s = svc("10.96.0.7", &[(None, 80, "TCP")]);
        let sl = slice_for("s", None, 8080, &[("10.244.0.3", None)]);
        let d = desired_for(Some(&s), &[sl]);
        assert_eq!(d.entries[0].1.len(), 1);
    }

    #[test]
    fn serving_terminating_fallback() {
        let s = svc("10.96.0.7", &[(None, 80, "TCP")]);
        let mut sl = slice(None, 8080, &[("10.244.0.3", false)]);
        sl.endpoints.as_mut().unwrap()[0].conditions = Some(EndpointConditions {
            ready: Some(false),
            serving: Some(true),
            terminating: Some(true),
        });
        let d = desired_for(Some(&s), &[sl]);
        assert_eq!(d.entries[0].1.len(), 1, "kube-proxy's fallback");
    }

    #[test]
    fn unnamed_port_matches_empty_name() {
        let s = svc("10.109.0.5", &[(None, 80, "TCP")]);
        let d = desired_for(Some(&s), &[slice(Some(""), 8080, &[("10.244.0.3", true)])]);
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].1.len(), 1, "the backend is programmed");
        assert_eq!(d.entries[0].1[0].port, 8080u16.to_be());
        let s = svc("10.109.0.5", &[(Some("http"), 80, "TCP")]);
        let d = desired_for(Some(&s), &[slice(Some(""), 8080, &[("10.244.0.3", true)])]);
        assert!(d.entries[0].1.is_empty());
    }

    #[test]
    fn ports_match_by_name() {
        let s = svc(
            "10.96.0.10",
            &[(Some("dns"), 53, "UDP"), (Some("metrics"), 9153, "TCP")],
        );
        let d = desired_for(
            Some(&s),
            &[
                slice(Some("dns"), 5353, &[("10.244.0.5", true)]),
                slice(Some("metrics"), 9153, &[("10.244.0.5", true)]),
            ],
        );
        let udp = d
            .entries
            .iter()
            .find(|(k, _)| k.proto == IPPROTO_UDP)
            .unwrap();
        assert_eq!(udp.1[0].port, 5353u16.to_be());
    }

    #[test]
    fn keys_network_byte_order() {
        let s = svc("10.96.0.1", &[(None, 443, "TCP")]);
        let d = desired_for(Some(&s), &[slice(None, 6443, &[("10.70.0.1", true)])]);
        let (k, _) = &d.entries[0];
        assert_eq!(k.addr, u32::from_be_bytes([10, 96, 0, 1]).to_be());
        assert_eq!(k.port, 443u16.to_be());
    }

    fn pinned_a() -> Mem {
        let mut m = Mem::default();
        m.services.insert(
            skey([10, 96, 0, 1], 80),
            ServiceVal {
                id: 7,
                backend_count: 2,
                affinity_secs: 0,
            },
        );
        m.backends.insert((7, 0), back([10, 244, 0, 3], 8080));
        m.backends.insert((7, 1), back([10, 244, 0, 4], 8080));
        m
    }

    fn a_view() -> ServiceView {
        view(
            vec![svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")])],
            vec![slice_for(
                "a",
                None,
                8080,
                &[("10.244.0.3", Some(true)), ("10.244.0.4", Some(true))],
            )],
        )
    }

    #[test]
    fn restart_keeps_pinned_ids() {
        let mut p = Programmer::seed(pinned_a()).unwrap();
        let v = view(
            vec![
                svc_named("ns", "b", "10.96.0.2", &[(None, 80, "TCP")]),
                svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")]),
            ],
            vec![
                slice_for("b", None, 9090, &[("10.244.0.9", Some(true))]),
                slice_for(
                    "a",
                    None,
                    8080,
                    &[("10.244.0.3", Some(true)), ("10.244.0.4", Some(true))],
                ),
            ],
        );
        p.on_synced(&v).unwrap();
        let m = &p.maps;
        assert_eq!(
            m.services[&skey([10, 96, 0, 1], 80)].id,
            7,
            "A keeps its id"
        );
        let b = m.services[&skey([10, 96, 0, 2], 80)];
        assert_ne!(b.id, 7, "B must not collide with A's id");
        assert_eq!(m.backends[&(b.id, 0)], back([10, 244, 0, 9], 9090));
        assert_eq!(
            m.backends[&(7, 0)],
            back([10, 244, 0, 3], 8080),
            "A's backends untouched"
        );
    }

    #[test]
    fn clean_restart_writes_nothing() {
        let mut p = Programmer::seed(pinned_a()).unwrap();
        assert_eq!(p.service_count(), 1);
        assert!(!p.is_synced());
        p.on_synced(&a_view()).unwrap();
        assert!(p.is_synced());
        assert_eq!(p.maps.writes, 0);
    }

    #[test]
    fn no_writes_before_sync() {
        let mut p = Programmer::seed(pinned_a()).unwrap();
        let early = view(
            vec![svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")])],
            vec![],
        );
        p.on_change(&early, "ns/a").unwrap();
        assert_eq!(p.maps.writes, 0);
        assert_eq!(
            p.maps.services[&skey([10, 96, 0, 1], 80)].backend_count,
            2,
            "the healthy entry survives"
        );
        p.on_synced(&a_view()).unwrap();
        assert!(
            p.maps.service_log.is_empty(),
            "a count of 0 was never written"
        );
        assert_eq!(p.maps.services[&skey([10, 96, 0, 1], 80)].backend_count, 2);
    }

    #[test]
    fn service_deleted_while_down_removed() {
        let mut m = pinned_a();
        m.services.insert(
            skey([10, 96, 0, 9], 443),
            ServiceVal {
                id: 8,
                backend_count: 1,
                affinity_secs: 0,
            },
        );
        m.backends.insert((8, 0), back([10, 244, 0, 50], 6443));
        let mut p = Programmer::seed(m).unwrap();
        p.on_synced(&a_view()).unwrap();
        assert!(!p.maps.services.contains_key(&skey([10, 96, 0, 9], 443)));
        assert!(!p.maps.backends.contains_key(&(8, 0)));
        assert!(p.maps.services.contains_key(&skey([10, 96, 0, 1], 80)));
    }

    #[test]
    fn orphan_backends_collected() {
        let mut m = pinned_a();
        m.backends.insert((42, 0), back([10, 244, 0, 77], 1));
        m.backends.insert((7, 5), back([10, 244, 0, 78], 1)); // past A's count
        let mut p = Programmer::seed(m).unwrap();
        p.on_synced(&a_view()).unwrap();
        assert!(!p.maps.backends.contains_key(&(42, 0)));
        assert!(!p.maps.backends.contains_key(&(7, 5)));
        assert_eq!(p.maps.backends.len(), 2);
    }

    #[test]
    fn new_service_takes_lowest_clean_id() {
        let mut m = pinned_a();
        m.backends.insert((1, 0), back([10, 244, 0, 77], 1)); // orphan under id 1
        let mut p = Programmer::seed(m).unwrap();
        let v = view(
            vec![
                svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")]),
                svc_named("ns", "b", "10.96.0.2", &[(None, 80, "TCP")]),
            ],
            vec![
                slice_for(
                    "a",
                    None,
                    8080,
                    &[("10.244.0.3", Some(true)), ("10.244.0.4", Some(true))],
                ),
                slice_for("b", None, 9090, &[("10.244.0.9", Some(true))]),
            ],
        );
        p.on_synced(&v).unwrap();
        assert_eq!(
            p.maps.services[&skey([10, 96, 0, 2], 80)].id,
            2,
            "id 1 is dirty, 7 is A's"
        );
        let c = view(
            vec![svc_named("ns", "c", "10.96.0.3", &[(None, 80, "TCP")])],
            vec![slice_for("c", None, 1, &[("10.244.0.1", Some(true))])],
        );
        p.on_change(&c, "ns/c").unwrap();
        assert_eq!(
            p.maps.services[&skey([10, 96, 0, 3], 80)].id,
            1,
            "collected, id 1 is free again"
        );
    }

    #[test]
    fn service_after_sync_programmed() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        p.on_synced(&ServiceView::default()).unwrap();
        let v = a_view();
        p.on_change(&v, "ns/a").unwrap();
        let s = p.maps.services[&skey([10, 96, 0, 1], 80)];
        assert_eq!(s.backend_count, 2);
        assert_eq!(p.maps.backends.len(), 2);
    }

    #[test]
    fn deleted_service_frees_id() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        p.on_synced(&ServiceView::default()).unwrap();
        p.on_change(&a_view(), "ns/a").unwrap();
        let id = p.maps.services[&skey([10, 96, 0, 1], 80)].id;
        p.on_change(&ServiceView::default(), "ns/a").unwrap();
        assert!(p.maps.services.is_empty());
        assert!(p.maps.backends.is_empty());
        let v = view(
            vec![svc_named("ns", "c", "10.96.0.3", &[(None, 80, "TCP")])],
            vec![slice_for("c", None, 1, &[("10.244.0.1", Some(true))])],
        );
        p.on_change(&v, "ns/c").unwrap();
        assert_eq!(p.maps.services[&skey([10, 96, 0, 3], 80)].id, id);
    }

    #[test]
    fn shrink_drops_surplus_slots() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        p.on_synced(&ServiceView::default()).unwrap();
        p.on_change(&a_view(), "ns/a").unwrap();
        let v = view(
            vec![svc_named("ns", "a", "10.96.0.1", &[(None, 80, "TCP")])],
            vec![slice_for("a", None, 8080, &[("10.244.0.3", Some(true))])],
        );
        p.on_change(&v, "ns/a").unwrap();
        assert_eq!(p.maps.services[&skey([10, 96, 0, 1], 80)].backend_count, 1);
        assert_eq!(p.maps.backends.len(), 1);
    }

    #[test]
    fn removed_port_unprogrammed() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        let two = view(
            vec![svc_named(
                "ns",
                "a",
                "10.96.0.1",
                &[(Some("x"), 80, "TCP"), (Some("y"), 81, "TCP")],
            )],
            vec![slice_for(
                "a",
                Some("x"),
                8080,
                &[("10.244.0.3", Some(true))],
            )],
        );
        p.on_synced(&two).unwrap();
        assert_eq!(p.maps.services.len(), 2, "y has no backends: refused");
        let one = view(
            vec![svc_named("ns", "a", "10.96.0.1", &[(Some("x"), 80, "TCP")])],
            vec![slice_for(
                "a",
                Some("x"),
                8080,
                &[("10.244.0.3", Some(true))],
            )],
        );
        p.on_change(&one, "ns/a").unwrap();
        assert_eq!(p.maps.services.len(), 1);
    }

    #[test]
    fn map_write_failure_errors() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        p.on_synced(&ServiceView::default()).unwrap();
        p.maps.budget = Some(1);
        let e = p.on_change(&a_view(), "ns/a").unwrap_err();
        assert!(format!("{e:#}").contains("E2BIG"), "{e:#}");
    }

    #[test]
    fn half_write_converges_on_restart() {
        let mut p = Programmer::seed(Mem::default()).unwrap();
        p.on_synced(&ServiceView::default()).unwrap();
        p.maps.budget = Some(2); // both backends land, the service does not
        assert!(p.on_change(&a_view(), "ns/a").is_err());
        let mut mem = p.maps;
        mem.budget = None;
        assert!(mem.services.is_empty());
        assert_eq!(mem.backends.len(), 2, "orphans under an unreferenced id");

        let mut p2 = Programmer::seed(mem).unwrap();
        p2.on_synced(&a_view()).unwrap();
        let s = p2.maps.services[&skey([10, 96, 0, 1], 80)];
        assert_eq!(s.backend_count, 2);
        assert_eq!(p2.maps.backends.len(), 2);
    }

    #[test]
    fn reconcile_failure_errors() {
        let mut m = pinned_a();
        m.services.insert(
            skey([10, 96, 0, 9], 443),
            ServiceVal {
                id: 8,
                backend_count: 0,
                affinity_secs: 0,
            },
        );
        m.budget = Some(0);
        let mut p = Programmer::seed(m).unwrap();
        assert!(p.on_synced(&a_view()).is_err());
        assert!(
            !p.is_synced(),
            "a failed reconcile must not claim the maps are in step"
        );
    }
}
