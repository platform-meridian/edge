//! The unit's ingress firewall, in Talos's own documents.
//!
//! Ingress is denied by default (`NetworkDefaultActionConfig`): nothing
//! reaches the host from off the node but what a `NetworkRuleConfig` here
//! allows. The rules are derived from the unit's own config, at provisioning
//! and at every merge, so a patch never carries one and nothing is opened by
//! hand:
//!
//! | rule | ports | from |
//! | --- | --- | --- |
//! | `cluster-tcp`, `cluster-udp` | every port | the pod and service subnets |
//! | `console-tcp` | 443: edge-gateway | anywhere |
//! | `console-udp` | 443: core's WebTransport | anywhere |
//! | `operator-tcp` | 50000: the Talos API; the cluster endpoint's port: the Kubernetes API | the operator island, IPv6 link-local |
//! | `operator-udp` | 53: the island's name service (edge-dhcp) | the operator island |
//! | `operator-dhcp` | 67: the island's DHCP (edge-dhcp) | the operator island, and `0.0.0.0`, a client with no lease yet |
//! | `management` | the Talos and Kubernetes APIs | the networks the site manages the unit from |
//!
//! The pods reach every port of the host, and nothing else does: core's
//! component port (7600/UDP) among them, the kubelet and the apiserver.
//! The operator island is the port the unit is managed from: an interface
//! with addresses of its own (not DHCP, not a dummy link). Link-local is
//! where `appliance provision` and `appliance watch` find the unit
//! (`fe80::ed6e:1`); it is never routed, so only a neighbour on one of the
//! unit's links reaches it. trustd (50001) answers no one but the node: one
//! node, and no other ever joins.
//!
//! `management` alone is not derived: the management port takes a lease, so
//! its network is not in the config. It is the unit's own, rendered at
//! provisioning from the networks the site names ([`management`]) and kept by
//! every merge, as the unit's other identity is.
//!
//! Talos itself always admits loopback (the node's own traffic), replies to
//! what the node sent (a DHCP lease's renewal among them), and ICMP and
//! ICMPv6 at up to five packets a second.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::{Key, get};

/// The kinds this derives, and that nothing else may write.
pub(super) const KINDS: [&str; 2] = ["NetworkDefaultActionConfig", "NetworkRuleConfig"];

/// Talos's defaults, when the config names no subnets or endpoint.
const POD_SUBNET: &str = "10.244.0.0/16";
const SERVICE_SUBNET: &str = "10.96.0.0/12";
const APISERVER_PORT: u16 = 6443;

const TALOS_API: u16 = 50000;
const CONSOLE: u16 = 443;
const DNS: u16 = 53;
const DHCP_SERVER: u16 = 67;

/// The rule the unit keeps.
pub(super) const MANAGEMENT: &str = "management";

/// Whether `k` is one of the documents the firewall derives.
pub(super) fn is(k: &Key) -> bool {
    matches!(k, Key::Typed(kind, name)
        if KINDS.contains(&kind.as_str()) && !(kind == KINDS[1] && name == MANAGEMENT))
}

/// The unit's `management` rule: the Talos API and the Kubernetes API (on
/// `apiserver`) from `networks`, each an address with its prefix length.
pub fn management(networks: &[String], apiserver: u16) -> anyhow::Result<Value> {
    anyhow::ensure!(!networks.is_empty(), "a management rule from no network");
    let from = networks
        .iter()
        .map(|n| network(n).map(|s| json!({ "subnet": s })))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(json!({
        "apiVersion": "v1alpha1",
        "kind": KINDS[1],
        "name": MANAGEMENT,
        "portSelector": { "ports": [TALOS_API, apiserver], "protocol": "tcp" },
        "ingress": from,
    }))
}

/// The firewall `docs` imply, as documents.
pub(super) fn derive(docs: &[(Key, Value)]) -> anyhow::Result<Vec<(Key, Value)>> {
    let typed = |kind: &str| {
        docs.iter().find_map(|(k, d)| match k {
            Key::Typed(k, _) if k == kind => Some(d),
            _ => None,
        })
    };
    let subnets = |field: &str, default: &str| -> anyhow::Result<Vec<String>> {
        match typed("KubeNetworkConfig").and_then(|d| get(d, &[field])) {
            None => Ok(vec![default.into()]),
            Some(v) => v
                .as_array()
                .with_context(|| format!("KubeNetworkConfig.{field} is not a list"))?
                .iter()
                .map(|s| {
                    s.as_str()
                        .with_context(|| format!("KubeNetworkConfig.{field} holds a non-string"))
                        .and_then(network)
                })
                .collect(),
        }
    };
    let mut cluster = subnets("podSubnets", POD_SUBNET)?;
    cluster.extend(subnets("serviceSubnets", SERVICE_SUBNET)?);

    let apiserver = match typed("KubeClusterConfig").and_then(|d| get(d, &["endpoint"])) {
        None => APISERVER_PORT,
        Some(e) => port_of(
            e.as_str()
                .context("KubeClusterConfig.endpoint is not a string")?,
        )?,
    };

    let v1 = docs
        .iter()
        .find_map(|(k, d)| (*k == Key::V1alpha1).then_some(d))
        .context("the config has no v1alpha1 document")?;
    let mut island = Vec::new();
    for i in get(v1, &["machine", "network", "interfaces"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let on = |f: &str| i.get(f).and_then(Value::as_bool) == Some(true);
        if on("dummy") || on("dhcp") || on("ignore") {
            continue;
        }
        for a in i
            .get("addresses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let a = a
                .as_str()
                .context("an interface's address is not a string")?;
            let n = network(a)?;
            if !n.starts_with("fe80:") && !island.contains(&n) {
                island.push(n);
            }
        }
    }
    let mut operator = island.clone();
    operator.push("fe80::/10".into());
    let island4: Vec<String> = island
        .iter()
        .filter(|n| !n.contains(':'))
        .cloned()
        .collect();
    // No island, no edge-dhcp, and no DHCP to admit.
    let dhcp: Vec<String> = match island4.is_empty() {
        true => Vec::new(),
        false => std::iter::once("0.0.0.0/32".to_string())
            .chain(island4.iter().cloned())
            .collect(),
    };

    let anywhere = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    let all = || json!(["1-65535"]);
    let mut out = vec![(
        Key::Typed(KINDS[0].into(), String::new()),
        json!({ "apiVersion": "v1alpha1", "kind": KINDS[0], "ingress": "block" }),
    )];
    let mut rule = |name: &str, protocol: &str, ports: Value, from: &[String]| {
        if from.is_empty() {
            return;
        }
        out.push((
            Key::Typed(KINDS[1].into(), name.into()),
            json!({
                "apiVersion": "v1alpha1",
                "kind": KINDS[1],
                "name": name,
                "portSelector": { "ports": ports, "protocol": protocol },
                "ingress": from.iter().map(|s| json!({ "subnet": s })).collect::<Vec<_>>(),
            }),
        ));
    };
    rule("cluster-tcp", "tcp", all(), &cluster);
    rule("cluster-udp", "udp", all(), &cluster);
    rule("console-tcp", "tcp", json!([CONSOLE]), &anywhere);
    rule("console-udp", "udp", json!([CONSOLE]), &anywhere);
    rule(
        "operator-tcp",
        "tcp",
        json!([TALOS_API, apiserver]),
        &operator,
    );
    rule("operator-udp", "udp", json!([DNS]), &island4);
    rule("operator-dhcp", "udp", json!([DHCP_SERVER]), &dhcp);
    Ok(out)
}

/// The network an address with its prefix length is on, as Talos takes a
/// subnet: `10.50.0.1/24` is `10.50.0.0/24`.
fn network(cidr: &str) -> anyhow::Result<String> {
    let (addr, len) = cidr
        .split_once('/')
        .with_context(|| format!("{cidr} has no prefix length"))?;
    let addr: IpAddr = addr
        .parse()
        .with_context(|| format!("{cidr} is no address"))?;
    let len: u8 = len
        .parse()
        .with_context(|| format!("{cidr} has no prefix length"))?;
    let net = match addr {
        IpAddr::V4(a) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
        _ => bail!("{cidr} has a prefix longer than its address"),
    };
    Ok(format!("{net}/{len}"))
}

/// The port an `https://host:port` endpoint names, else HTTPS's.
fn port_of(endpoint: &str) -> anyhow::Result<u16> {
    let authority = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default();
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.contains(']') => port
            .parse()
            .with_context(|| format!("{endpoint} names no port")),
        _ => Ok(443),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_network_is_its_address_masked() {
        assert_eq!(network("10.50.0.1/24").unwrap(), "10.50.0.0/24");
        assert_eq!(network("10.70.0.1/32").unwrap(), "10.70.0.1/32");
        assert_eq!(
            network("fd00:ed6e:1:1::2/64").unwrap(),
            "fd00:ed6e:1:1::/64"
        );
        assert_eq!(network("0.0.0.0/0").unwrap(), "0.0.0.0/0");
        assert!(network("10.50.0.1/33").is_err());
        assert!(network("10.50.0.1").is_err());
    }

    #[test]
    fn an_endpoint_names_its_port() {
        assert_eq!(port_of("https://10.50.0.1:6443").unwrap(), 6443);
        assert_eq!(port_of("https://[fd00::1]:7443/").unwrap(), 7443);
        assert_eq!(port_of("https://unit.lan").unwrap(), 443);
        assert_eq!(port_of("https://[fd00::1]").unwrap(), 443);
    }
}
