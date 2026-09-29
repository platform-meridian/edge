use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use k8s_openapi::api::core::v1::{Service, ServiceSpec};
use k8s_openapi::api::discovery::v1::EndpointSlice;

#[derive(Debug, Clone, PartialEq)]
pub enum Local {
    A(Vec<Ipv4Addr>),
    Aaaa(Vec<Ipv6Addr>),
    Srv(Vec<(u16, String)>),
    /// The name exists without records of this type; a resolver must not
    /// search past it.
    NoData,
    NxDomain,
    Cname(String, Option<Box<Local>>),
    Ptr(Vec<String>),
    Forward,
    Soa,
    Ns,
    NotSynced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    A,
    Aaaa,
    Srv,
    Ptr,
    Soa,
    Ns,
    Other,
}

/// `10-244-0-5` -> 10.244.0.5; only the address's own spelling, so no two
/// names answer for one pod.
fn dashed_to_ipv4(s: &str) -> Option<Ipv4Addr> {
    s.replace('-', ".").parse().ok()
}

#[derive(Debug, Default)]
pub struct Zone {
    domain: String,
    a: HashMap<String, Vec<Ipv4Addr>>,
    aaaa: HashMap<String, Vec<Ipv6Addr>>,
    srv: HashMap<String, Vec<(u16, String)>>,
    cname: HashMap<String, String>,
    ptr: HashMap<String, Vec<String>>,
    /// Every owner and every name between it and the apex (RFC 8020 empty
    /// non-terminals): what decides NODATA over NXDOMAIN.
    exists: HashSet<String>,
    synced: bool,
    serial: u32,
}

impl Zone {
    pub fn unsynced(domain: &str) -> Self {
        Self {
            domain: domain.trim_matches('.').to_ascii_lowercase(),
            ..Default::default()
        }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    #[cfg(test)]
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    fn mark(&mut self, name: &str) {
        let mut n = name;
        loop {
            if !self.exists.insert(n.to_string()) {
                return;
            }
            match n.split_once('.') {
                Some((_, rest))
                    if rest == self.domain || rest.ends_with(&format!(".{}", self.domain)) =>
                {
                    n = rest
                }
                _ => return,
            }
        }
    }

    /// `slices` is keyed by "<namespace>/<service-name>".
    pub fn build<'a>(
        domain: &str,
        services: impl IntoIterator<Item = &'a Service>,
        slices: &HashMap<String, Vec<EndpointSlice>>,
    ) -> Self {
        let domain = domain.trim_matches('.').to_ascii_lowercase();
        let serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_secs() as u32);
        let mut z = Zone {
            domain: domain.clone(),
            synced: true,
            serial,
            ..Default::default()
        };
        z.exists.insert(domain.clone());
        let no_spec = ServiceSpec::default();

        for svc in services {
            let Some(name) = svc.metadata.name.as_deref() else {
                continue;
            };
            let Some(ns) = svc.metadata.namespace.as_deref() else {
                continue;
            };
            let fqdn = format!("{name}.{ns}.svc.{domain}").to_ascii_lowercase();
            let spec = svc.spec.as_ref().unwrap_or(&no_spec);
            z.mark(&fqdn);

            if spec.type_.as_deref() == Some("ExternalName") {
                if let Some(t) = spec.external_name.as_deref().filter(|t| !t.is_empty()) {
                    z.cname
                        .insert(fqdn, t.trim_end_matches('.').to_ascii_lowercase());
                }
                continue;
            }

            let cluster_ip = spec.cluster_ip.as_deref().unwrap_or("None");
            let headless = cluster_ip == "None" || cluster_ip.is_empty();

            if headless {
                let key = format!("{ns}/{name}");
                z.add_endpoint_addrs(&fqdn, slices.get(&key).map(|v| v.as_slice()).unwrap_or(&[]));
            } else {
                z.add_addr(&fqdn, cluster_ip);
            }

            // Kubernetes publishes SRV for named ports only.
            for p in spec.ports.iter().flatten() {
                let Some(pname) = p.name.as_deref() else {
                    continue;
                };
                let proto = p.protocol.as_deref().unwrap_or("TCP").to_ascii_lowercase();
                let srv_name = format!("_{}._{}.{fqdn}", pname.to_ascii_lowercase(), proto);
                z.mark(&srv_name);
                z.srv
                    .entry(srv_name)
                    .or_default()
                    .push((p.port as u16, fqdn.clone()));
            }
        }
        z
    }

    fn add_addr(&mut self, fqdn: &str, ip: &str) {
        self.mark(fqdn);
        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
            self.a.entry(fqdn.to_string()).or_default().push(v4);
            let o = v4.octets();
            let rev = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
            self.ptr.entry(rev).or_default().push(fqdn.to_string());
        } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
            self.aaaa.entry(fqdn.to_string()).or_default().push(v6);
            let mut rev = String::new();
            for b in v6.octets().iter().rev() {
                rev.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            rev.push_str("ip6.arpa");
            self.ptr.entry(rev).or_default().push(fqdn.to_string());
        }
    }

    fn add_endpoint_addrs(&mut self, fqdn: &str, slices: &[EndpointSlice]) {
        // The same readiness rule as edge-cni's dataplane.
        for ep in edge_kube::service_endpoints(slices) {
            for addr in &ep.addresses {
                self.add_addr(fqdn, addr);
            }
            if let Some(h) = ep.hostname.as_deref().filter(|h| !h.is_empty()) {
                let hn = format!("{}.{fqdn}", h.to_ascii_lowercase());
                for addr in &ep.addresses {
                    self.add_addr(&hn, addr);
                }
            }
        }
    }

    pub fn resolve(&self, name: &str, qtype: QType) -> Local {
        let name = name.trim_matches('.').to_ascii_lowercase();

        if name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa") {
            return match self.ptr.get(&name) {
                Some(v) if !v.is_empty() => Local::Ptr(v.clone()),
                // Not ours to deny: the node's own subnets resolve upstream.
                _ => Local::Forward,
            };
        }

        if name != self.domain && !name.ends_with(&format!(".{}", self.domain)) {
            return Local::Forward;
        }

        if !self.synced {
            return Local::NotSynced;
        }

        if name == self.domain {
            return match qtype {
                QType::Soa => Local::Soa,
                QType::Ns => Local::Ns,
                _ => Local::NoData,
            };
        }

        // `<dashed-ip>.<namespace>.pod`, synthesised as CoreDNS "insecure" does.
        if let Some(rest) = name.strip_suffix(&format!(".pod.{}", self.domain)) {
            let ip = rest
                .split_once('.')
                .filter(|(_, ns)| !ns.contains('.'))
                .and_then(|(dashed, _)| dashed_to_ipv4(dashed));
            return match (ip, qtype) {
                (Some(ip), QType::A) => Local::A(vec![ip]),
                (Some(_), _) => Local::NoData,
                (None, _) => Local::NxDomain,
            };
        }

        // A CNAME answers every type.
        if let Some(target) = self.cname.get(&name) {
            return Local::Cname(target.clone(), self.chase(target, qtype, 0));
        }

        let known = self.exists.contains(&name);

        match qtype {
            QType::A => match self.a.get(&name) {
                Some(v) if !v.is_empty() => Local::A(v.clone()),
                _ if known => Local::NoData,
                _ => Local::NxDomain,
            },
            QType::Aaaa => match self.aaaa.get(&name) {
                Some(v) if !v.is_empty() => Local::Aaaa(v.clone()),
                _ if known => Local::NoData,
                _ => Local::NxDomain,
            },
            QType::Srv => match self.srv.get(&name) {
                Some(v) if !v.is_empty() => Local::Srv(v.clone()),
                _ if known => Local::NoData,
                _ => Local::NxDomain,
            },
            QType::Ptr if known => Local::NoData,
            QType::Ptr => Local::NxDomain,
            QType::Soa | QType::Ns | QType::Other if known => Local::NoData,
            QType::Soa | QType::Ns | QType::Other => Local::NxDomain,
        }
    }

    /// Bounded: `a -> b -> a` is user input.
    fn chase(&self, target: &str, qtype: QType, depth: u8) -> Option<Box<Local>> {
        const MAX_HOPS: u8 = 8;
        if depth >= MAX_HOPS {
            return None;
        }
        let t = target.trim_matches('.').to_ascii_lowercase();
        // Never put a foreign address behind our authoritative flag.
        if t != self.domain && !t.ends_with(&format!(".{}", self.domain)) {
            return None;
        }
        if let Some(next) = self.cname.get(&t) {
            return self.chase(next, qtype, depth + 1);
        }
        match qtype {
            QType::A => self
                .a
                .get(&t)
                .filter(|v| !v.is_empty())
                .map(|v| Box::new(Local::A(v.clone()))),
            QType::Aaaa => self
                .aaaa
                .get(&t)
                .filter(|v| !v.is_empty())
                .map(|v| Box::new(Local::Aaaa(v.clone()))),
            QType::Srv => self
                .srv
                .get(&t)
                .filter(|v| !v.is_empty())
                .map(|v| Box::new(Local::Srv(v.clone()))),
            QType::Ptr | QType::Soa | QType::Ns | QType::Other => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServicePort;
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions};

    fn svc(ns: &str, name: &str, spec: ServiceSpec) -> Service {
        let mut s = Service::default();
        s.metadata.name = Some(name.into());
        s.metadata.namespace = Some(ns.into());
        s.spec = Some(spec);
        s
    }

    fn cluster_ip(ns: &str, name: &str, ip: &str, ports: &[(&str, i32, &str)]) -> Service {
        let ports = ports
            .iter()
            .map(|(n, p, proto)| ServicePort {
                name: Some((*n).into()),
                port: *p,
                protocol: Some((*proto).into()),
                ..Default::default()
            })
            .collect();
        svc(
            ns,
            name,
            ServiceSpec {
                cluster_ip: Some(ip.into()),
                ports: Some(ports),
                ..Default::default()
            },
        )
    }

    fn external(ns: &str, name: &str, target: &str) -> Service {
        svc(
            ns,
            name,
            ServiceSpec {
                type_: Some("ExternalName".into()),
                external_name: Some(target.into()),
                ..Default::default()
            },
        )
    }

    /// (address, conditions (ready, serving, terminating), hostname)
    type Ep<'a> = (
        &'a str,
        (Option<bool>, Option<bool>, Option<bool>),
        Option<&'a str>,
    );

    fn slice(eps: &[Ep]) -> EndpointSlice {
        EndpointSlice {
            endpoints: Some(
                eps.iter()
                    .map(|(a, (ready, serving, terminating), host)| Endpoint {
                        addresses: vec![(*a).into()],
                        conditions: Some(EndpointConditions {
                            ready: *ready,
                            serving: *serving,
                            terminating: *terminating,
                        }),
                        hostname: host.map(Into::into),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn zone() -> Zone {
        let ready = (Some(true), None, None);
        let services = [
            cluster_ip(
                "default",
                "kubernetes",
                "10.96.0.1",
                &[("https", 443, "TCP")],
            ),
            cluster_ip(
                "kube-system",
                "kube-dns",
                "10.96.0.10",
                &[("dns", 53, "UDP")],
            ),
            cluster_ip("default", "v6", "fd00::1", &[]),
            cluster_ip("db", "fdb", "None", &[]),
            cluster_ip("db", "term", "None", &[]),
            cluster_ip("db", "gone", "None", &[]),
            cluster_ip("db", "empty", "None", &[]),
            external("apps", "flux", "adapter.apps-privileged.svc.cluster.local"),
            external("app", "db", "real.app.svc.cluster.local"),
            cluster_ip("app", "real", "10.96.5.5", &[]),
            external("d", "a", "b.d.svc.cluster.local"),
            external("d", "b", "a.d.svc.cluster.local"),
            external("app", "db6", "v6.default.svc.cluster.local"),
            external(
                "kube-system",
                "dns-alias",
                "_dns._udp.kube-dns.kube-system.svc.cluster.local",
            ),
        ];
        let slices = HashMap::from([
            (
                "db/fdb".to_string(),
                vec![slice(&[
                    ("10.244.1.5", ready, None),
                    ("10.244.1.6", (None, None, None), None),
                    ("10.244.1.7", (Some(false), None, None), None),
                    ("10.244.2.9", ready, Some("fdb-0")),
                ])],
            ),
            (
                "db/term".to_string(),
                vec![slice(&[(
                    "10.244.3.5",
                    (Some(false), Some(true), Some(true)),
                    None,
                )])],
            ),
            (
                "db/gone".to_string(),
                vec![slice(&[("10.244.4.5", (Some(false), None, None), None)])],
            ),
        ]);
        Zone::build("cluster.local", services.iter(), &slices)
    }

    fn a(ips: &[&str]) -> Local {
        Local::A(ips.iter().map(|i| i.parse().unwrap()).collect())
    }

    #[test]
    fn resolve() {
        use Local::{Forward, NoData, NxDomain};
        use QType::{A, Aaaa, Ns, Other, Ptr, Soa, Srv};
        let cname = |t: &str, chased: Option<Local>| Local::Cname(t.into(), chased.map(Box::new));
        let cases: Vec<(&str, QType, Local)> = vec![
            ("kubernetes.default.svc.cluster.local", A, a(&["10.96.0.1"])),
            (
                "Kubernetes.Default.SVC.Cluster.Local.",
                A,
                a(&["10.96.0.1"]),
            ),
            ("kubernetes.default.svc.cluster.local", Aaaa, NoData),
            ("kubernetes.default.svc.cluster.local", Other, NoData),
            ("nope.default.svc.cluster.local", A, NxDomain),
            ("nope.default.svc.cluster.local", Aaaa, NxDomain),
            ("nope.default.svc.cluster.local", Srv, NxDomain),
            ("nope.default.svc.cluster.local", Ptr, NxDomain),
            ("nope.default.svc.cluster.local", Other, NxDomain),
            ("kubernetes.default.svc.cluster.local", Ptr, NoData),
            (
                "v6.default.svc.cluster.local",
                Aaaa,
                Local::Aaaa(vec!["fd00::1".parse().unwrap()]),
            ),
            (
                "_dns._udp.kube-dns.kube-system.svc.cluster.local",
                Srv,
                Local::Srv(vec![(53, "kube-dns.kube-system.svc.cluster.local".into())]),
            ),
            ("default.svc.cluster.local", A, NoData),
            ("svc.cluster.local", A, NoData),
            ("_tcp.kubernetes.default.svc.cluster.local", Srv, NoData),
            ("other.svc.cluster.local", A, NxDomain),
            ("cluster.local", Soa, Local::Soa),
            ("cluster.local.", Ns, Local::Ns),
            ("cluster.local", A, NoData),
            (
                "fdb.db.svc.cluster.local",
                A,
                a(&["10.244.1.5", "10.244.1.6", "10.244.2.9"]),
            ),
            ("fdb-0.fdb.db.svc.cluster.local", A, a(&["10.244.2.9"])),
            ("term.db.svc.cluster.local", A, a(&["10.244.3.5"])),
            ("gone.db.svc.cluster.local", A, NoData),
            ("gone.db.svc.cluster.local", Aaaa, NoData),
            ("empty.db.svc.cluster.local", A, NoData),
            (
                "1.0.96.10.in-addr.arpa",
                Ptr,
                Local::Ptr(vec!["kubernetes.default.svc.cluster.local".into()]),
            ),
            (
                "5.1.244.10.in-addr.arpa",
                Ptr,
                Local::Ptr(vec!["fdb.db.svc.cluster.local".into()]),
            ),
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
                Ptr,
                Local::Ptr(vec!["v6.default.svc.cluster.local".into()]),
            ),
            ("1.0.0.10.in-addr.arpa", Ptr, Forward),
            (
                "10-244-0-5.default.pod.cluster.local",
                A,
                a(&["10.244.0.5"]),
            ),
            ("10-244-0-5.default.pod.cluster.local", Aaaa, NoData),
            ("not-an-ip.default.pod.cluster.local", A, NxDomain),
            ("a-b-c-d.default.pod.cluster.local", A, NxDomain),
            ("10-244-0.default.pod.cluster.local", A, NxDomain),
            ("010-244-0-5.default.pod.cluster.local", A, NxDomain),
            ("+10-244-0-5.default.pod.cluster.local", A, NxDomain),
            ("10-244-0-5.a.default.pod.cluster.local", A, NxDomain),
            (
                "flux.apps.svc.cluster.local",
                A,
                cname("adapter.apps-privileged.svc.cluster.local", None),
            ),
            (
                "flux.apps.svc.cluster.local",
                Srv,
                cname("adapter.apps-privileged.svc.cluster.local", None),
            ),
            (
                "db.app.svc.cluster.local",
                A,
                cname("real.app.svc.cluster.local", Some(a(&["10.96.5.5"]))),
            ),
            (
                "db.app.svc.cluster.local",
                Aaaa,
                cname("real.app.svc.cluster.local", None),
            ),
            (
                "db6.app.svc.cluster.local",
                Aaaa,
                cname(
                    "v6.default.svc.cluster.local",
                    Some(Local::Aaaa(vec!["fd00::1".parse().unwrap()])),
                ),
            ),
            (
                "dns-alias.kube-system.svc.cluster.local",
                Srv,
                cname(
                    "_dns._udp.kube-dns.kube-system.svc.cluster.local",
                    Some(Local::Srv(vec![(
                        53,
                        "kube-dns.kube-system.svc.cluster.local".into(),
                    )])),
                ),
            ),
            (
                "a.d.svc.cluster.local",
                A,
                cname("b.d.svc.cluster.local", None),
            ),
            ("example.com", A, Forward),
            ("example.org.", A, Forward),
        ];
        let z = zone();
        for (name, q, want) in cases {
            assert_eq!(z.resolve(name, q), want, "{name} {q:?}");
        }
    }

    proptest::proptest! {
        #[test]
        fn pod_name_is_canonical_ip(
            octets in proptest::array::uniform4(0u8..),
            pads in proptest::array::uniform4(proptest::sample::select(vec!["", "", "0", "+"])),
            ns in "[a-z]{1,3}(\\.[a-z]{1,3})?",
        ) {
            let z = Zone::build("cluster.local", [], &HashMap::new());
            let dashed: Vec<String> = octets.iter().zip(pads).map(|(o, p)| format!("{p}{o}")).collect();
            let name = format!("{}.{ns}.pod.cluster.local", dashed.join("-"));
            let ip = Ipv4Addr::from(octets);
            let canonical = format!("{}.{ns}.pod.cluster.local", ip.to_string().replace('.', "-"));
            let want = if name == canonical && !ns.contains('.') { Local::A(vec![ip]) } else { Local::NxDomain };
            proptest::prop_assert_eq!(z.resolve(&name, QType::A), want, "{}", name);
        }
    }

    #[test]
    fn built_zone_synced_with_serial() {
        let z = Zone::unsynced("cluster.local");
        assert_eq!(
            z.resolve("kubernetes.default.svc.cluster.local", QType::A),
            Local::NotSynced
        );
        assert_eq!(z.resolve("cluster.local", QType::Soa), Local::NotSynced);
        assert_eq!(z.resolve("example.com", QType::A), Local::Forward);
        assert!(!z.is_synced());
        let built = zone();
        assert!(built.is_synced());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(now - built.serial() < 60, "the serial is the build time");
    }
}
