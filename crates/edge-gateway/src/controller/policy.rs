//! BackendTLSPolicy: which Services are dialled over TLS, and against what.
//! A policy this data plane cannot honour still claims its Service, whose
//! every request then fails: plaintext would be a silent downgrade.

use super::convert::Verdict;
use super::state::{Key, key};
use super::trust::{RefError, Sources};
use crate::config::UpstreamTls;
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

pub(super) struct Policies {
    pub by_service: BTreeMap<Key, UpstreamTls>,
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
pub(super) fn evaluate(policies: &[&DynamicObject], sources: &Sources) -> Policies {
    let mut ordered = policies.to_vec();
    ordered.sort_by_key(|o| {
        let created = o.metadata.creation_timestamp.as_ref().map(|t| t.0);
        (created.is_none(), created, key(o))
    });
    let mut by_service = BTreeMap::new();
    let mut outcomes = Vec::new();
    for o in ordered {
        let ns = o.namespace().unwrap_or_default();
        let spec: Spec = match serde_json::from_value(o.data["spec"].clone()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(policy = %o.name_any(), error = %e, "unparseable BackendTLSPolicy; ignored");
                continue;
            }
        };
        let services: Vec<&TargetRef> = spec
            .target_refs
            .iter()
            .filter(|t| t.group.is_empty() && t.kind == "Service")
            .collect();
        if services.is_empty() {
            continue;
        }
        let (tls, accepted, resolved) = judge(&spec.validation, &services, &ns, sources);
        let mut claimed = Vec::new();
        let mut conflicted = Vec::new();
        for t in &services {
            let k = (ns.clone(), t.name.clone());
            if by_service.contains_key(&k) {
                conflicted.push(t.name.as_str());
            } else {
                by_service.insert(k.clone(), tls.clone());
                claimed.push(k);
            }
        }
        let accepted = if conflicted.is_empty() {
            accepted
        } else {
            verdict(
                false,
                "Conflicted",
                format!(
                    "an older policy already targets Service {}",
                    conflicted.join(", ")
                ),
            )
        };
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

fn judge(
    v: &Validation,
    targets: &[&TargetRef],
    ns: &str,
    sources: &Sources,
) -> (UpstreamTls, Verdict, Verdict) {
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
    let unsupported = if targets.iter().any(|t| t.section_name.is_some()) {
        Some("a targetRef sectionName is not supported")
    } else if !v.subject_alt_names.is_empty() {
        Some("subjectAltNames is not supported")
    } else if v.well_known_ca_certificates.is_some() {
        Some("wellKnownCACertificates is not supported")
    } else if v.hostname.is_empty() {
        Some("no validation.hostname")
    } else {
        None
    };
    let accepted = match unsupported {
        Some(why) => verdict(false, "Invalid", format!("{why}; its Services are refused")),
        None if v.ca_certificate_refs.is_empty()
            || bad_kind.len() + bad_ref.len() == v.ca_certificate_refs.len() =>
        {
            verdict(
                false,
                "NoValidCACertificate",
                "no caCertificateRef is usable; its Services are refused",
            )
        }
        None => verdict(true, "Accepted", "Services are dialled over TLS"),
    };
    // Any bad reference fails every connection, as the API requires.
    let usable = accepted.ok && resolved.ok;
    (
        UpstreamTls {
            hostname: v.hostname.clone(),
            ca_pem: if usable { pem } else { String::new() },
        },
        accepted,
        resolved,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
        cms: BTreeMap<Key, DynamicObject>,
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
                super::super::trust::thin_configmap(&mut o);
                cms.insert(("apps".into(), name.into()), o);
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
                    configmaps: Some(&self.cms),
                    bundles: Some(&self.bundles),
                },
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

    fn key(s: &str) -> Key {
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
                "well-known CAs",
                svc("s"),
                json!({ "hostname": "h", "wellKnownCACertificates": "System" }),
                (false, "Invalid"),
                (true, "ResolvedRefs"),
            ),
            (
                "subjectAltNames",
                svc("s"),
                json!({ "hostname": "h", "caCertificateRefs": [cm_ref("ca")],
                "subjectAltNames": [{ "type": "Hostname", "hostname": "x" }] }),
                (false, "Invalid"),
                (true, "ResolvedRefs"),
            ),
            (
                "sectionName",
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
            assert!(t.ca_pem.is_empty(), "{what}: served with a CA");
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
        let w = World::new();
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
                configmaps: None,
                bundles: Some(&w.bundles),
            },
        );
        assert!(p.by_service[&key("s")].ca_pem.is_empty());
    }
}
