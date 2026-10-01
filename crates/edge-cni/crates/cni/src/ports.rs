use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::Context;
use edge_cni_common::{ANY_NODE_ADDR, BackendVal, IPPROTO_TCP, IPPROTO_UDP, ServiceKey};
use edge_kube::policy::{HostPort, Proto};

use crate::nft::Forward;
use crate::services::{absent_is_fine, socket_addr};

// Only pods with a live veth: that is what CNI DEL removes.
pub fn host_port_entries(
    host_ports: &[(Ipv4Addr, HostPort)],
    live: &HashSet<Ipv4Addr>,
) -> BTreeMap<ServiceKey, BackendVal> {
    let mut out = BTreeMap::new();
    for (pod, hp) in host_ports {
        let proto = match hp.proto {
            Proto::Tcp => IPPROTO_TCP,
            Proto::Udp => IPPROTO_UDP,
            Proto::Sctp => continue,
        };
        if !live.contains(pod) {
            continue;
        }
        let key = ServiceKey {
            addr: hp.host_ip.map_or(ANY_NODE_ADDR, |ip| u32::from(ip).to_be()),
            port: hp.host_port.to_be(),
            proto,
            _pad: 0,
        };
        out.entry(key).or_insert(BackendVal {
            addr: u32::from(*pod).to_be(),
            port: hp.container_port.to_be(),
            _pad: 0,
        });
    }
    out
}

// Loopback cannot arrive from off the node, the only traffic netfilter forwards.
pub fn forwards(entries: &BTreeMap<ServiceKey, BackendVal>) -> Vec<Forward> {
    entries
        .iter()
        .filter_map(|(k, b)| {
            let addr = (k.addr != ANY_NODE_ADDR).then(|| Ipv4Addr::from(u32::from_be(k.addr)));
            if addr.is_some_and(|a| a.is_loopback()) {
                return None;
            }
            Some(Forward {
                proto: k.proto,
                addr,
                port: u16::from_be(k.port),
                backends: vec![socket_addr(b)],
                affinity: false,
            })
        })
        .collect()
}

pub fn node_addr_entries(addrs: &[Ipv4Addr]) -> BTreeMap<u32, u8> {
    addrs.iter().map(|a| (u32::from(*a).to_be(), 1)).collect()
}

pub trait KeyedMap<K, V> {
    fn dump(&self) -> anyhow::Result<Vec<(K, V)>>;
    fn put(&mut self, k: &K, v: &V) -> anyhow::Result<()>;
    fn del(&mut self, k: &K) -> anyhow::Result<()>;
}

impl<K: aya::Pod, V: aya::Pod> KeyedMap<K, V> for aya::maps::HashMap<aya::maps::MapData, K, V> {
    fn dump(&self) -> anyhow::Result<Vec<(K, V)>> {
        Ok(self.iter().collect::<Result<_, _>>()?)
    }
    fn put(&mut self, k: &K, v: &V) -> anyhow::Result<()> {
        Ok(self.insert(k, v, 0)?)
    }
    fn del(&mut self, k: &K) -> anyhow::Result<()> {
        absent_is_fine(self.remove(k))
    }
}

// Writes before deletes, so a moved entry is never missing in between.
pub fn reconcile<K: Ord + Copy, V: PartialEq + Copy>(
    map: &mut impl KeyedMap<K, V>,
    want: &BTreeMap<K, V>,
) -> anyhow::Result<usize> {
    let have: BTreeMap<K, V> = map.dump().context("read the map")?.into_iter().collect();
    let mut writes = 0;
    for (k, v) in want {
        if have.get(k) != Some(v) {
            map.put(k, v).context("write the map")?;
            writes += 1;
        }
    }
    for k in have.keys().filter(|k| !want.contains_key(k)) {
        map.del(k).context("delete from the map")?;
        writes += 1;
    }
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn hp(host_ip: Option<&str>, host_port: u16, proto: Proto) -> HostPort {
        HostPort {
            proto,
            host_ip: host_ip.map(ip),
            host_port,
            container_port: 8080,
        }
    }

    fn key(addr: u32, port: u16, proto: u8) -> ServiceKey {
        ServiceKey {
            addr,
            port: port.to_be(),
            proto,
            _pad: 0,
        }
    }

    fn be(s: &str) -> u32 {
        u32::from(ip(s)).to_be()
    }

    #[test]
    fn host_ports_by_ip_and_protocol() {
        let pods = [
            (ip("10.244.0.1"), hp(Some("127.0.0.1"), 54323, Proto::Tcp)),
            (ip("10.244.0.2"), hp(Some("10.70.0.1"), 54323, Proto::Tcp)),
            (ip("10.244.0.3"), hp(Some("10.70.0.1"), 54323, Proto::Udp)),
            (ip("10.244.0.4"), hp(None, 80, Proto::Tcp)),
            (ip("10.244.0.4"), hp(None, 81, Proto::Sctp)),
        ];
        let live = pods.iter().map(|(p, _)| *p).collect();
        let e = host_port_entries(&pods, &live);
        let backend = |pod: &str| BackendVal {
            addr: be(pod),
            port: 8080u16.to_be(),
            _pad: 0,
        };
        assert_eq!(
            e,
            BTreeMap::from([
                (
                    key(be("127.0.0.1"), 54323, IPPROTO_TCP),
                    backend("10.244.0.1")
                ),
                (
                    key(be("10.70.0.1"), 54323, IPPROTO_TCP),
                    backend("10.244.0.2")
                ),
                (
                    key(be("10.70.0.1"), 54323, IPPROTO_UDP),
                    backend("10.244.0.3")
                ),
                (key(ANY_NODE_ADDR, 80, IPPROTO_TCP), backend("10.244.0.4")),
            ])
        );
    }

    #[test]
    fn deleted_pod_host_port_dropped() {
        let pods = [
            (ip("10.244.0.1"), hp(None, 80, Proto::Tcp)),
            (ip("10.244.0.2"), hp(None, 81, Proto::Tcp)),
        ];
        let e = host_port_entries(&pods, &HashSet::from([ip("10.244.0.2")]));
        assert_eq!(
            e.keys().copied().collect::<Vec<_>>(),
            [key(0, 81, IPPROTO_TCP)]
        );
    }

    #[test]
    fn first_claim_wins() {
        let pods = [
            (ip("10.244.0.1"), hp(None, 80, Proto::Tcp)),
            (ip("10.244.0.2"), hp(None, 80, Proto::Tcp)),
        ];
        let live = pods.iter().map(|(p, _)| *p).collect();
        let e = host_port_entries(&pods, &live);
        assert_eq!(e.len(), 1);
        assert_eq!(e[&key(0, 80, IPPROTO_TCP)].addr, be("10.244.0.1"));
    }

    #[test]
    fn forwards_skip_loopback() {
        let pods = [
            (ip("10.244.0.1"), hp(Some("127.0.0.1"), 54323, Proto::Tcp)),
            (ip("10.244.0.2"), hp(Some("10.70.0.1"), 54323, Proto::Udp)),
            (ip("10.244.0.3"), hp(None, 80, Proto::Tcp)),
        ];
        let live = pods.iter().map(|(p, _)| *p).collect();
        let f = forwards(&host_port_entries(&pods, &live));
        assert_eq!(
            f,
            [
                Forward {
                    proto: IPPROTO_TCP,
                    addr: None,
                    port: 80,
                    backends: vec![SocketAddrV4::new(ip("10.244.0.3"), 8080)],
                    affinity: false,
                },
                Forward {
                    proto: IPPROTO_UDP,
                    addr: Some(ip("10.70.0.1")),
                    port: 54323,
                    backends: vec![SocketAddrV4::new(ip("10.244.0.2"), 8080)],
                    affinity: false,
                },
            ]
        );
    }

    #[test]
    fn node_addrs_network_order() {
        assert_eq!(
            node_addr_entries(&[ip("10.70.0.1"), ip("127.0.0.1")]),
            BTreeMap::from([(be("10.70.0.1"), 1), (be("127.0.0.1"), 1)])
        );
    }

    #[derive(Default)]
    struct Mem {
        map: BTreeMap<u32, u8>,
        log: Vec<String>,
    }

    impl KeyedMap<u32, u8> for Mem {
        fn dump(&self) -> anyhow::Result<Vec<(u32, u8)>> {
            Ok(self.map.iter().map(|(k, v)| (*k, *v)).collect())
        }
        fn put(&mut self, k: &u32, v: &u8) -> anyhow::Result<()> {
            self.log.push(format!("put {k}"));
            self.map.insert(*k, *v);
            Ok(())
        }
        fn del(&mut self, k: &u32) -> anyhow::Result<()> {
            self.log.push(format!("del {k}"));
            self.map.remove(k);
            Ok(())
        }
    }

    #[test]
    fn reconcile_writes_difference() {
        let mut m = Mem::default();
        m.map.extend([(1, 1), (2, 1), (3, 7)]);
        let want = BTreeMap::from([(2, 1), (3, 1), (4, 1)]);
        assert_eq!(reconcile(&mut m, &want).unwrap(), 3);
        assert_eq!(m.map, want);
        assert_eq!(m.log, ["put 3", "put 4", "del 1"], "writes before deletes");
        m.log.clear();
        assert_eq!(reconcile(&mut m, &want).unwrap(), 0);
        assert!(m.log.is_empty());
    }
}
