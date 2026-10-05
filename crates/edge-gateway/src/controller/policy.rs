//! BackendTLSPolicy: which Services are dialled over TLS, and against what.
//! A policy this data plane cannot honour still claims its Service, whose
//! every request then fails: plaintext would be a silent downgrade.

use super::convert::Verdict;
use super::state::{Key, key};
use super::trust::{RefError, Sources};
use crate::config::{San, UpstreamTls};
use kube::ResourceExt;
use kube::api::DynamicObject;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Spec {
    target_refs: Vec<TargetRef>,
    validation: Validation,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct TargetRef {
    group: String,
    kind: String,
    name: String,
    section_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Validation {
    ca_certificate_refs: Vec<CaRef>,
    hostname: String,
    subject_alt_names: Vec<serde_json::Value>,
    #[serde(rename = "wellKnownCACertificates")]
    well_known_ca_certificates: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CaRef {
    group: String,
    kind: String,
    name: String,
}

pub(super) struct Outcome {
    /// The Services it claims, which its status is reported against.
    pub targets: Vec<Key>,
    pub accepted: Verdict,
    pub resolved: Verdict,
}

/// A whole Service, or one port of it (`sectionName`), which outranks it.
pub(super) type Target = (Key, Option<u16>);

pub(super) struct Policies {
    pub by_service: BTreeMap<Target, UpstreamTls>,
    pub outcomes: Vec<(DynamicObject, Outcome)>,
}

fn verdict(ok: bool, reason: &'static str, message: impl Into<String>) -> Verdict {
    Verdict {
        ok,
        reason,
        message: message.into(),
    }
}

/// Oldest first: on a shared target the older policy wins (the API's rule).
/// `services` carry their ports, for `sectionName`; `None` when unlisted.
pub(super) fn evaluate(
    policies: &[&DynamicObject],
    sources: &Sources,
    services: Option<&BTreeMap<Key, DynamicObject>>,
) -> Policies {
    let mut ordered = policies.to_vec();
    ordered.sort_by_key(|o| {
        let created = o.metadata.creation_timestamp.as_ref().map(|t| t.0);
        (created.is_none(), created, key(o))
    });
    let mut by_service = BTreeMap::new();
    let mut outcomes = Vec::new();
    for o in ordered {
        let ns = o.namespace().unwrap_or_default();
        let (targets, tls, accepted, resolved) =
            match serde_json::from_value::<Spec>(o.data["spec"].clone()) {
                Ok(spec) => {
                    let refs: Vec<&TargetRef> = spec
                        .target_refs
                        .iter()
                        .filter(|t| t.group.is_empty() && t.kind == "Service")
                        .collect();
                    let (tls, a, r) = judge(&spec.validation, &ns, sources);
                    (
                        refs.iter()
                            .map(|t| (t.name.clone(), t.section_name.clone()))
                            .collect(),
                        tls,
                        a,
                        r,
                    )
                }
                Err(e) => unparseable(&o.data["spec"], &e),
            };
        if targets.is_empty() {
            continue;
        }
        let mut accepted = accepted;
        let mut claimed = Vec::new();
        let mut conflicted = Vec::new();
        let mut missing = Vec::new();
        for (name, section) in &targets {
            let svc = (ns.clone(), name.clone());
            let (target, tls) = match section {
                None => ((svc.clone(), None), tls.clone()),
                Some(section) => match port_named(services, &svc, section) {
                    Ok(port) => ((svc.clone(), Some(port)), tls.clone()),
                    Err(None) => {
                        missing.push(format!("Service {name} has no port {section}"));
                        continue;
                    }
                    // Its port unknown, the whole Service is refused.
                    Err(Some(why)) => {
                        accepted =
                            verdict(false, "Invalid", format!("{why}; its Services are refused"));
                        ((svc.clone(), None), UpstreamTls::refused())
                    }
                },
            };
            match by_service.entry(target) {
                std::collections::btree_map::Entry::Occupied(_) => conflicted.push(name.as_str()),
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(tls);
                    if !claimed.contains(&svc) {
                        claimed.push(svc);
                    }
                }
            }
        }
        if !conflicted.is_empty() {
            accepted = verdict(
                false,
                "Conflicted",
                format!(
                    "an older policy already targets Service {}",
                    conflicted.join(", ")
                ),
            );
        } else if !missing.is_empty() && accepted.ok {
            accepted = verdict(false, "TargetNotFound", missing.join("; "));
        }
        outcomes.push((
            o.clone(),
            Outcome {
                targets: claimed,
                accepted,
                resolved,
            },
        ));
    }
    Policies {
        by_service,
        outcomes,
    }
}

/// `Err(None)`: no such port; `Err(Some(why))`: it cannot be known.
fn port_named(
    services: Option<&BTreeMap<Key, DynamicObject>>,
    svc: &Key,
    section: &str,
) -> Result<u16, Option<String>> {
    let Some(services) = services else {
        return Err(Some(format!(
            "sectionName {section}: Services cannot be listed"
        )));
    };
    services
        .get(svc)
        .and_then(|o| o.data["spec"]["ports"].as_array())
        .and_then(|ports| {
            ports
                .iter()
                .find(|p| p["name"].as_str() == Some(section))
                .and_then(|p| p["port"].as_u64())
                .and_then(|p| u16::try_from(p).ok())
        })
        .ok_or(None)
}

/// Its Services, read as leniently as they can be, are still claimed: refused.
#[allow(clippy::type_complexity)]
fn unparseable(
    spec: &serde_json::Value,
    e: &serde_json::Error,
) -> (Vec<(String, Option<String>)>, UpstreamTls, Verdict, Verdict) {
    let names = spec["targetRefs"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|t| {
            t["group"].as_str().unwrap_or_default().is_empty()
                && t["kind"].as_str() == Some("Service")
        })
        .filter_map(|t| t["name"].as_str().map(|n| (n.to_string(), None)))
        .collect();
    (
        names,
        UpstreamTls::refused(),
        verdict(
            false,
            "Invalid",
            format!("the spec does not parse ({e}); its Services are refused"),
        ),
        verdict(
            false,
            "InvalidCACertificateRef",
            "caCertificateRefs not evaluated: the spec does not parse",
        ),
    )
}

fn sans(v: &[serde_json::Value]) -> Result<Vec<San>, String> {
    v.iter()
        .map(|s| {
            match (
                s["type"].as_str(),
                s["hostname"].as_str(),
                s["uri"].as_str(),
            ) {
                (Some("Hostname"), Some(h), _) => Ok(San::Hostname(h.to_string())),
                (Some("URI"), _, Some(u)) => Ok(San::Uri(u.to_string())),
                _ => Err(format!("subjectAltName {s} is not supported")),
            }
        })
        .collect()
}

fn judge(v: &Validation, ns: &str, sources: &Sources) -> (UpstreamTls, Verdict, Verdict) {
    let mut pem = String::new();
    let mut bad_kind = Vec::new();
    let mut bad_ref = Vec::new();
    for r in &v.ca_certificate_refs {
        match sources.resolve(&r.group, &r.kind, ns, &r.name) {
            Ok(p) => {
                pem.push_str(&p);
                pem.push('\n');
            }
            Err(e @ RefError::Kind(_)) => bad_kind.push(e.message().to_string()),
            Err(e @ RefError::Invalid(_)) => bad_ref.push(e.message().to_string()),
        }
    }
    let resolved = match (bad_kind.is_empty(), bad_ref.is_empty()) {
        (true, true) => verdict(true, "ResolvedRefs", "all caCertificateRefs resolved"),
        (false, _) => verdict(
            false,
            "InvalidKind",
            [bad_kind.clone(), bad_ref.clone()].concat().join("; "),
        ),
        (true, false) => verdict(false, "InvalidCACertificateRef", bad_ref.join("; ")),
    };
    let system = match v.well_known_ca_certificates.as_deref() {
        None => Ok(false),
        Some("System") => Ok(true),
        Some(other) => Err(format!("wellKnownCACertificates {other} is not supported")),
    };
    let checked = system.and_then(|system| Ok((system, sans(&v.subject_alt_names)?)));
    let accepted = match &checked {
        Err(why) => verdict(false, "Invalid", format!("{why}; its Services are refused")),
        Ok(_) if v.hostname.is_empty() => verdict(
            false,
            "Invalid",
            "no validation.hostname; its Services are refused",
        ),
        Ok((false, _))
            if v.ca_certificate_refs.is_empty()
                || bad_kind.len() + bad_ref.len() == v.ca_certificate_refs.len() =>
        {
            verdict(
                false,
                "NoValidCACertificate",
                "no caCertificateRef is usable; its Services are refused",
            )
        }
        Ok(_) => verdict(true, "Accepted", "Services are dialled over TLS"),
    };
    // Any bad reference fails every connection, as the API requires.
    let tls = match checked {
        Ok((system, sans)) if accepted.ok && resolved.ok => UpstreamTls {
            hostname: v.hostname.clone(),
            ca_pem: pem,
            system,
            sans,
            ..UpstreamTls::default()
        },
        _ => UpstreamTls::refused(),
    };
    (tls, accepted, resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::trust::{RefKind, RefState, Refs};
    use serde_json::{Value, json};

    pub(crate) fn ca_pem() -> String {
        let mut p = rcgen::CertificateParams::default();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem()
    }

    fn obj(kind: &str, ns: Option<&str>, name: &str, created: &str, body: Value) -> DynamicObject {
        let mut v = json!({
            "apiVersion": "v1", "kind": kind,
            "metadata": { "name": name, "namespace": ns, "creationTimestamp": created },
        });
        v.as_object_mut()
            .unwrap()
            .extend(body.as_object().unwrap().clone());
        serde_json::from_value(v).unwrap()
    }

    fn policy(name: &str, created: &str, targets: Value, validation: Value) -> DynamicObject {
        obj(
            "BackendTLSPolicy",
            Some("apps"),
            name,
            created,
            json!({ "spec": { "targetRefs": targets, "validation": validation } }),
        )
    }

    fn svc(name: &str) -> Value {
        json!([{ "group": "", "kind": "Service", "name": name }])
    }

    fn cm_ref(name: &str) -> Value {
        json!({ "group": "", "kind": "ConfigMap", "name": name })
    }

    const T0: &str = "2026-01-01T00:00:00Z";
    const T1: &str = "2026-01-02T00:00:00Z";

    struct World {
        cms: Refs,
        bundles: BTreeMap<Key, DynamicObject>,
        pem: String,
    }

    impl World {
        fn new() -> Self {
            let pem = ca_pem();
            let mut cms = BTreeMap::new();
            for (name, data) in [
                ("ca", json!({ "ca.crt": pem })),
                ("empty", json!({ "other": "x" })),
                (
                    "junk",
                    json!({ "ca.crt": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }),
                ),
            ] {
                let mut o = obj("ConfigMap", Some("apps"), name, T0, json!({ "data": data }));
                RefKind::ConfigMap.thin(&mut o);
                cms.insert(
                    (RefKind::ConfigMap, ("apps".into(), name.into())),
                    RefState {
                        listed: Some(true),
                        object: Some(o),
                    },
                );
            }
            let mut bundles = BTreeMap::new();
            bundles.insert(
                (String::new(), "node:ca".into()),
                obj(
                    "ClusterTrustBundle",
                    None,
                    "node:ca",
                    T0,
                    json!({ "spec": { "trustBundle": pem } }),
                ),
            );
            World { cms, bundles, pem }
        }

        fn eval(&self, ps: &[DynamicObject]) -> Policies {
            let refs: Vec<&DynamicObject> = ps.iter().collect();
            evaluate(
                &refs,
                &Sources {
                    refs: &self.cms,
                    bundles: Some(&self.bundles),
                },
                None,
            )
        }
    }

    type Verdicts = (bool, &'static str);

    fn summary(p: &Policies) -> Vec<(String, Verdicts, Verdicts)> {
        p.outcomes
            .iter()
            .map(|(o, x)| {
                (
                    o.name_any(),
                    (x.accepted.ok, x.accepted.reason),
                    (x.resolved.ok, x.resolved.reason),
                )
            })
            .collect()
    }

    fn key(s: &str) -> Target {
        (svc_key(s), None)
    }

    fn svc_key(s: &str) -> Key {
        ("apps".into(), s.into())
    }

    #[test]
    fn configmap_and_trust_bundle_resolve() {
        let w = World::new();
        let p = w.eval(&[
            policy("a", T0, svc("a"), json!({ "hostname": "a.apps", "caCertificateRefs": [cm_ref("ca")] })),
            policy(
                "b",
                T0,
                svc("b"),
                json!({ "hostname": "b.apps", "caCertificateRefs": [
                    { "group": "certificates.k8s.io", "kind": "ClusterTrustBundle", "name": "node:ca" }] }),
            ),
        ]);
        assert_eq!(
            summary(&p),
            [
                ("a".into(), (true, "Accepted"), (true, "ResolvedRefs")),
                ("b".into(), (true, "Accepted"), (true, "ResolvedRefs")),
            ]
        );
        for s in ["a", "b"] {
            let t = &p.by_service[&key(s)];
            assert_eq!(t.hostname, format!("{s}.apps"));
            assert!(t.ca_pem.contains(w.pem.trim()), "{s}");
        }
    }

    #[test]
    fn problems_fail_closed_and_say_why() {
        let w = World::new();
        let bundle = |n: &str| json!({ "group": "certificates.k8s.io", "kind": "ClusterTrustBundle", "name": n });
        for (what, targets, validation, accepted, resolved) in [
            (
                "missing ConfigMap",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("absent")] }),
                (false, "NoValidCACertificate"),
                (false, "InvalidCACertificateRef"),
            ),
            (
                "no ca.crt",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("empty")] }),
                (false, "NoValidCACertificate"),
                (false, "InvalidCACertificateRef"),
            ),
            (
                "not a certificate",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("junk")] }),
                (false, "NoValidCACertificate"),
                (false, "InvalidCACertificateRef"),
            ),
            (
                "missing bundle",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [bundle("absent")] }),
                (false, "NoValidCACertificate"),
                (false, "InvalidCACertificateRef"),
            ),
            (
                "one bad of two",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca"), cm_ref("absent")] }),
                (true, "Accepted"),
                (false, "InvalidCACertificateRef"),
            ),
            (
                "a Secret",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca"), { "group": "", "kind": "Secret", "name": "x" }] }),
                (true, "Accepted"),
                (false, "InvalidKind"),
            ),
            (
                "an unknown well-known set",
                svc("s"),
                json!({ "hostname": "h", "wellKnownCACertificates": "example.com/mine" }),
                (false, "Invalid"),
                (true, "ResolvedRefs"),
            ),
            (
                "an unknown subjectAltName type",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca")],
                "subjectAltNames": [{ "type": "IP", "ip": "1.2.3.4" }] }),
                (false, "Invalid"),
                (true, "ResolvedRefs"),
            ),
            (
                "a sectionName while Services cannot be listed",
                json!([{ "group": "", "kind": "Service", "name": "s", "sectionName": "https" }]),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca")] }),
                (false, "Invalid"),
                (true, "ResolvedRefs"),
            ),
        ] {
            let p = w.eval(&[policy("p", T0, targets, validation)]);
            let s = summary(&p);
            assert_eq!((s[0].1, s[0].2), (accepted, resolved), "{what}");
            let t = &p.by_service[&key("s")];
            assert!(t.refused, "{what}: served");
            assert!(!p.outcomes[0].1.accepted.message.is_empty(), "{what}");
        }
    }

    #[test]
    fn oldest_policy_wins_a_service() {
        let w = World::new();
        let v = |h: &str| json!({ "hostname": h, "caCertificateRefs": [cm_ref("ca")] });
        let p = w.eval(&[
            policy("newer", T1, svc("s"), v("newer")),
            policy("older", T0, svc("s"), v("older")),
            policy("zz-same-age", T0, svc("s"), v("same")),
        ]);
        assert_eq!(p.by_service[&key("s")].hostname, "older");
        assert_eq!(
            summary(&p),
            [
                ("older".into(), (true, "Accepted"), (true, "ResolvedRefs")),
                (
                    "zz-same-age".into(),
                    (false, "Conflicted"),
                    (true, "ResolvedRefs")
                ),
                (
                    "newer".into(),
                    (false, "Conflicted"),
                    (true, "ResolvedRefs")
                ),
            ]
        );
        assert!(p.outcomes[1].1.targets.is_empty());
    }

    #[test]
    fn only_service_targets_count() {
        let w = World::new();
        let p = w.eval(&[policy(
            "p",
            T0,
            json!([{ "group": "example.com", "kind": "Backend", "name": "s" }]),
            json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca")] }),
        )]);
        assert!(p.by_service.is_empty() && p.outcomes.is_empty());
    }

    #[test]
    fn unlisted_configmaps_fail_closed() {
        let mut w = World::new();
        for r in w.cms.values_mut() {
            *r = RefState {
                listed: Some(false),
                object: None,
            };
        }
        let ps = [policy(
            "p",
            T0,
            svc("s"),
            json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca")] }),
        )];
        let refs: Vec<&DynamicObject> = ps.iter().collect();
        let p = evaluate(
            &refs,
            &Sources {
                refs: &w.cms,
                bundles: Some(&w.bundles),
            },
            None,
        );
        assert!(p.by_service[&key("s")].refused);
        let resolved = &p.outcomes[0].1.resolved;
        assert!(
            resolved.message.contains("cannot be listed"),
            "{}",
            resolved.message
        );
    }

    #[test]
    fn unparseable_policy_still_claims_its_service() {
        let w = World::new();
        let bad = policy(
            "bad",
            T0,
            json!([{ "kind": "Service", "name": "s" }, { "group": "x.io", "kind": "Service", "name": "other" }]),
            json!({ "hostname": 5, "caCertificateRefs": [cm_ref("ca")] }),
        );
        let p = w.eval(&[bad]);
        assert_eq!(
            summary(&p),
            [(
                "bad".into(),
                (false, "Invalid"),
                (false, "InvalidCACertificateRef")
            )]
        );
        assert!(p.outcomes[0].1.accepted.message.contains("does not parse"));
        assert_eq!(p.by_service.keys().collect::<Vec<_>>(), [&key("s")]);
        assert!(p.by_service[&key("s")].refused);
        assert_eq!(p.outcomes[0].1.targets, [svc_key("s")]);
    }

    #[test]
    fn standard_validation_fields() {
        let w = World::new();
        let p = w.eval(&[
            policy("sys", T0, svc("sys"), json!({ "hostname": "api.example.com", "wellKnownCACertificates": "System" })),
            policy(
                "sans",
                T0,
                svc("sans"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca")], "subjectAltNames": [
                    { "type": "Hostname", "hostname": "*.apps.svc" }, { "type": "URI", "uri": "spiffe://x/ns/apps/sa/jel" }] }),
            ),
        ]);
        assert_eq!(
            summary(&p),
            [
                ("sans".into(), (true, "Accepted"), (true, "ResolvedRefs")),
                ("sys".into(), (true, "Accepted"), (true, "ResolvedRefs")),
            ]
        );
        let sys = &p.by_service[&key("sys")];
        assert!(sys.system && !sys.refused && sys.ca_pem.is_empty());
        assert_eq!(
            p.by_service[&key("sans")].sans,
            [
                San::Hostname("*.apps.svc".into()),
                San::Uri("spiffe://x/ns/apps/sa/jel".into())
            ]
        );
    }

    /// `sectionName` names a Service port; that port's policy outranks one on
    /// the whole Service.
    #[test]
    fn section_name_is_a_service_port() {
        let w = World::new();
        let mut services = BTreeMap::new();
        services.insert(
            svc_key("s"),
            obj(
                "Service",
                Some("apps"),
                "s",
                T0,
                json!({ "spec": { "ports": [
                { "name": "https", "port": 8443 }, { "name": "http", "port": 80 }] } }),
            ),
        );
        let ps = [
            policy(
                "port",
                T1,
                json!([{ "group": "", "kind": "Service", "name": "s", "sectionName": "https" }]),
                json!({ "hostname": "port", "caCertificateRefs": [cm_ref("ca")] }),
            ),
            policy(
                "whole",
                T0,
                svc("s"),
                json!({ "hostname": "whole", "caCertificateRefs": [cm_ref("ca")] }),
            ),
            policy(
                "nowhere",
                T0,
                json!([{ "group": "", "kind": "Service", "name": "s", "sectionName": "grpc" }]),
                json!({ "hostname": "x", "caCertificateRefs": [cm_ref("ca")] }),
            ),
        ];
        let refs: Vec<&DynamicObject> = ps.iter().collect();
        let p = evaluate(
            &refs,
            &Sources {
                refs: &w.cms,
                bundles: Some(&w.bundles),
            },
            Some(&services),
        );
        assert_eq!(p.by_service[&(svc_key("s"), Some(8443))].hostname, "port");
        assert_eq!(p.by_service[&key("s")].hostname, "whole");
        assert_eq!(p.by_service.len(), 2);
        assert_eq!(
            summary(&p),
            [
                (
                    "nowhere".into(),
                    (false, "TargetNotFound"),
                    (true, "ResolvedRefs")
                ),
                ("whole".into(), (true, "Accepted"), (true, "ResolvedRefs")),
                ("port".into(), (true, "Accepted"), (true, "ResolvedRefs")),
            ]
        );
    }
}
