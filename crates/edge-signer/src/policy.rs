//! What a pod may be issued. The node is single-tenant, so the rule is
//! about names, not pods: only the names this unit is reached by.
//!
//! A pod asks with its projection's `userAnnotations`:
//!   edge.meridian/dns-names     comma-separated: localhost, the unit's domain,
//!                               *.<domain> or <label>.<domain>
//!   edge.meridian/ip-addresses  comma-separated: loopback or this unit's own

use std::net::IpAddr;

use crate::api::Spec;

pub const SIGNER: &str = "edge.meridian/node";
const DNS_NAMES: &str = "edge.meridian/dns-names";
const IP_ADDRESSES: &str = "edge.meridian/ip-addresses";
/// kube-apiserver's default when the pod names none.
const DEFAULT_LIFETIME: i64 = 86_400;

#[derive(Debug, Default, PartialEq)]
pub struct Unit {
    pub domain: Option<String>,
    pub addresses: Vec<IpAddr>,
}

impl Unit {
    /// A bad entry is dropped, not fatal: requests naming it are denied and
    /// say why.
    pub fn new(domain: &str, addresses: &str) -> Self {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let domain = if domain.is_empty() {
            None
        } else if domain.len() <= 253 && domain.split('.').all(label_allowed) {
            Some(domain)
        } else {
            tracing::error!(domain, "EDGE_SIGNER_DOMAIN: not a domain name; ignored");
            None
        };
        let addresses = addresses
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                s.parse()
                    .inspect_err(|_| {
                        tracing::error!(
                            address = s,
                            "EDGE_SIGNER_ADDRESSES: not an address; ignored"
                        )
                    })
                    .ok()
            })
            .collect();
        Self { domain, addresses }
    }
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Issue {
        dns: Vec<String>,
        ips: Vec<IpAddr>,
        lifetime: i64,
    },
    Deny {
        reason: &'static str,
        message: String,
    },
}

fn invalid(message: String) -> Decision {
    Decision::Deny {
        reason: "InvalidUnverifiedUserAnnotations",
        message,
    }
}

pub fn decide(spec: &Spec, unit: &Unit) -> Decision {
    if let Some(key) = spec
        .unverified_user_annotations
        .keys()
        .find(|k| ![DNS_NAMES, IP_ADDRESSES].contains(&k.as_str()))
    {
        return invalid(format!(
            "unknown annotation {key}; this signer reads {DNS_NAMES} and {IP_ADDRESSES}"
        ));
    }
    let annotation_list = |key| {
        let mut out: Vec<String> = Vec::new();
        for item in spec
            .unverified_user_annotations
            .get(key)
            .map_or("", String::as_str)
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
        {
            if !out.contains(&item) {
                out.push(item);
            }
        }
        out
    };
    let dns = annotation_list(DNS_NAMES);
    let domain = unit.domain.as_deref();
    if let Some(bad) = dns.iter().find(|d| !dns_allowed(d, domain)) {
        return invalid(match domain {
            Some(domain) => {
                format!("{bad} is not a name of this node (localhost, {domain} or a name under it)")
            }
            None => format!("{bad} is not a name of this node (localhost; it has no domain)"),
        });
    }
    let mut ips = Vec::new();
    for raw in annotation_list(IP_ADDRESSES) {
        match raw.parse::<IpAddr>() {
            Ok(ip) if ip.is_loopback() || unit.addresses.contains(&ip) => ips.push(ip),
            _ => {
                return invalid(format!(
                    "{raw} is not a loopback address or one of this node's {:?}",
                    unit.addresses
                ));
            }
        }
    }
    if dns.is_empty() && ips.is_empty() {
        return invalid(format!("no names: set {DNS_NAMES} or {IP_ADDRESSES}"));
    }
    let lifetime = spec
        .max_expiration_seconds
        .map_or(DEFAULT_LIFETIME, i64::from);
    Decision::Issue { dns, ips, lifetime }
}

fn dns_allowed(name: &str, domain: Option<&str>) -> bool {
    if name == "localhost" {
        return true;
    }
    let Some(domain) = domain else {
        return false;
    };
    if name == domain {
        return true;
    }
    let Some(label) = name.strip_suffix(domain).and_then(|l| l.strip_suffix('.')) else {
        return false;
    };
    label == "*" || label_allowed(label)
}

fn label_allowed(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(annotations: &[(&str, &str)], max: Option<i32>) -> Spec {
        Spec {
            max_expiration_seconds: max,
            unverified_user_annotations: annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Spec::default()
        }
    }

    fn unit() -> Unit {
        Unit::new("example.lan", "10.42.0.1")
    }

    fn issue(annotations: &[(&str, &str)]) -> (Vec<String>, Vec<IpAddr>) {
        match decide(&spec(annotations, Some(864_000)), &unit()) {
            Decision::Issue { dns, ips, lifetime } => {
                assert_eq!(lifetime, 864_000);
                (dns, ips)
            }
            d => panic!("{annotations:?}: {d:?}"),
        }
    }

    fn denied(annotations: &[(&str, &str)]) -> &'static str {
        match decide(&spec(annotations, None), &unit()) {
            Decision::Deny { reason, .. } => reason,
            d => panic!("{annotations:?}: {d:?}"),
        }
    }

    #[test]
    fn shipped_requests_get_their_names() {
        let (dns, ips) = issue(&[
            (DNS_NAMES, "*.example.lan, example.lan,localhost"),
            (IP_ADDRESSES, "10.42.0.1,127.0.0.1"),
        ]);
        assert_eq!(dns, ["*.example.lan", "example.lan", "localhost"]);
        assert_eq!(
            ips,
            [
                "10.42.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.1".parse().unwrap()
            ]
        );

        let (dns, ips) = issue(&[
            (DNS_NAMES, "example.lan,localhost"),
            (IP_ADDRESSES, "10.42.0.1,127.0.0.1,::1"),
        ]);
        assert_eq!(dns, ["example.lan", "localhost"]);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn names_normalised_and_deduplicated() {
        let (dns, ips) = issue(&[
            (DNS_NAMES, " Example.LAN ,example.lan,,flux.example.lan"),
            (IP_ADDRESSES, "127.0.0.2"),
        ]);
        assert_eq!(dns, ["example.lan", "flux.example.lan"]);
        assert_eq!(ips, ["127.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(issue(&[(IP_ADDRESSES, "::1")]).0, Vec::<String>::new());
    }

    #[test]
    fn denies_foreign_name() {
        for bad in [
            "example.com",
            "example.lan.example.com",
            "evilexample.lan",
            ".example.lan",
            "a.b.example.lan",
            "*.*.example.lan",
            "-a.example.lan",
            "a-.example.lan",
            "a_b.example.lan",
            "*",
            "lan",
            &format!("{}.example.lan", "a".repeat(64)),
        ] {
            assert_eq!(
                denied(&[(DNS_NAMES, bad)]),
                "InvalidUnverifiedUserAnnotations",
                "{bad}"
            );
        }
        assert_eq!(
            issue(&[(DNS_NAMES, &format!("{}.example.lan", "a".repeat(63)))])
                .0
                .len(),
            1
        );
        assert_eq!(issue(&[(DNS_NAMES, "a-1.example.lan")]).0.len(), 1);
    }

    #[test]
    fn denies_foreign_address() {
        for bad in [
            "10.42.0.2",
            "0.0.0.0",
            "::",
            "192.168.1.1",
            "localhost",
            "10.42.0.1/24",
        ] {
            assert_eq!(
                denied(&[(IP_ADDRESSES, bad)]),
                "InvalidUnverifiedUserAnnotations",
                "{bad}"
            );
        }
    }

    #[test]
    fn denies_unknown_annotation_or_no_names() {
        assert_eq!(
            denied(&[(DNS_NAMES, "example.lan"), ("edge.meridian/lifetime", "1")]),
            "InvalidUnverifiedUserAnnotations"
        );
        assert_eq!(denied(&[]), "InvalidUnverifiedUserAnnotations");
        assert_eq!(
            denied(&[(DNS_NAMES, " , ")]),
            "InvalidUnverifiedUserAnnotations"
        );
    }

    #[test]
    fn lifetime_defaults_to_one_day() {
        let lifetime = |max| match decide(&spec(&[(DNS_NAMES, "localhost")], max), &unit()) {
            Decision::Issue { lifetime, .. } => lifetime,
            d => panic!("{d:?}"),
        };
        assert_eq!(lifetime(Some(3600)), 3600);
        assert_eq!(lifetime(None), 86_400);
    }

    #[test]
    fn names_follow_unit_domain() {
        let names = |unit: &Unit, dns: &str| match decide(&spec(&[(DNS_NAMES, dns)], None), unit) {
            Decision::Issue { dns, .. } => Ok(dns),
            Decision::Deny { reason, message } => Err((reason, message)),
        };
        let site = Unit::new(" Site.Example. ", "");
        assert_eq!(site.domain.as_deref(), Some("site.example"));
        assert_eq!(
            names(
                &site,
                "*.site.example,site.example,a.site.example,localhost"
            )
            .unwrap(),
            [
                "*.site.example",
                "site.example",
                "a.site.example",
                "localhost"
            ]
        );
        let (reason, message) = names(&site, "example.lan").unwrap_err();
        assert_eq!(reason, "InvalidUnverifiedUserAnnotations");
        assert!(message.contains("site.example"), "{message}");
        assert!(names(&site, "a.example.lan").is_err());

        for none in [
            Unit::new("", ""),
            Unit::new("bad_domain", ""),
            Unit::new("-a.lan", ""),
        ] {
            assert_eq!(none.domain, None);
            assert_eq!(names(&none, "localhost").unwrap(), ["localhost"]);
            assert!(names(&none, "example.lan").is_err());
            assert!(names(&none, "a.example.lan").is_err());
        }
        assert_eq!(
            Unit::new(&"a.".repeat(127), "").domain,
            Some("a.".repeat(126) + "a")
        );
        assert_eq!(Unit::new(&("a.".repeat(126) + "ab"), "").domain, None);
    }

    #[test]
    fn bad_addresses_are_dropped() {
        assert_eq!(
            Unit::new("", " 10.42.0.1, nope,,::1 ").addresses,
            [
                "10.42.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse().unwrap()
            ]
        );
        assert!(Unit::new("", "").addresses.is_empty());
    }
}
