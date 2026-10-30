//! A leaf the signer keeps in a Secret (`kubernetes.io/tls`), for a workload
//! whose portable rendering reads its certificate from one, as cert-manager
//! would write it: platform-core's `meridian-tls`. Its names are asked for as
//! a pod certificate's are (`edge.meridian/dns-names`,
//! `edge.meridian/ip-addresses`) and decided by the same policy, so the
//! Secret's leaf names what the pod certificate would. It is issued again
//! halfway through its life, as a pod certificate is refreshed, or when the
//! node gains an address it lacks, or when the CA's root changes. The Secret
//! holds the root too (`ca.crt`), as cert-manager's do.
//!
//! Configured by the deployment, never defaulted:
//!
//!   EDGE_SIGNER_LEAF            <namespace>/<name>
//!   EDGE_SIGNER_LEAF_DNS        e.g. `meridian.lan,localhost`
//!   EDGE_SIGNER_LEAF_IPS        e.g. `node,127.0.0.1,::1`
//!   EDGE_SIGNER_LEAF_LIFETIME   seconds; what its holder's pin allows

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::Context;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, Patch, PatchParams};
use x509_parser::prelude::*;

use crate::api::Spec;
use crate::ca::Ca;
use crate::policy::{self, Decision, Unit};

const FIELD_MANAGER: &str = "edge-signer";

#[derive(Clone, Debug)]
pub struct Config {
    pub namespace: String,
    pub name: String,
    asked: Spec,
}

impl Config {
    /// From the environment; `None` when no leaf is configured.
    pub fn from_env(env: impl Fn(&str) -> String) -> anyhow::Result<Option<Self>> {
        let at = env("EDGE_SIGNER_LEAF");
        let at = at.trim();
        if at.is_empty() {
            return Ok(None);
        }
        let (namespace, name) = at
            .split_once('/')
            .context("EDGE_SIGNER_LEAF is <namespace>/<name>")?;
        let lifetime = env("EDGE_SIGNER_LEAF_LIFETIME");
        let lifetime: i32 = lifetime
            .trim()
            .parse()
            .with_context(|| format!("EDGE_SIGNER_LEAF_LIFETIME: {lifetime:?} is not seconds"))?;
        let asked = Spec {
            signer_name: policy::SIGNER.into(),
            pod_name: String::new(),
            pod_uid: String::new(),
            node_name: String::new(),
            max_expiration_seconds: Some(lifetime),
            stub_pkcs10_request: ByteString(Vec::new()),
            unverified_user_annotations: BTreeMap::from([
                (policy::DNS_NAMES.to_owned(), env("EDGE_SIGNER_LEAF_DNS")),
                (policy::IP_ADDRESSES.to_owned(), env("EDGE_SIGNER_LEAF_IPS")),
            ]),
        };
        Ok(Some(Self {
            namespace: namespace.into(),
            name: name.into(),
            asked,
        }))
    }
}

/// What the Secret's leaf is: its names, its life, and the root it chains to.
#[derive(Debug, PartialEq)]
struct Held {
    dns: Vec<String>,
    ips: Vec<IpAddr>,
    not_before: i64,
    not_after: i64,
    root: Vec<u8>,
}

fn held(secret: &Secret) -> Option<Held> {
    let crt = secret.data.as_ref()?.get("tls.crt")?;
    let (_, pem) = parse_x509_pem(&crt.0).ok()?;
    let (_, cert) = parse_x509_certificate(&pem.contents).ok()?;
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => dns.push(d.to_string()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => ips.push(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?)),
                    16 => ips.push(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?)),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let root = secret
        .data
        .as_ref()?
        .get("ca.crt")
        .map(|r| r.0.clone())
        .unwrap_or_default();
    Some(Held {
        dns,
        ips,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        root,
    })
}

/// Why the leaf must be issued now, if it must.
fn due(
    held: Option<&Held>,
    dns: &[String],
    ips: &[IpAddr],
    root: &[u8],
    now: i64,
) -> Option<&'static str> {
    let Some(h) = held else {
        return Some("no leaf yet");
    };
    if h.root != root {
        return Some("the CA changed");
    }
    if now >= (h.not_before + h.not_after) / 2 {
        return Some("halfway through its life");
    }
    if dns.iter().any(|d| !h.dns.contains(d)) || ips.iter().any(|ip| !h.ips.contains(ip)) {
        return Some("a name it lacks");
    }
    None
}

/// Issues the leaf again if it is due, with a new key. Returns why, if it did.
pub async fn keep(
    api: &Api<Secret>,
    c: &Config,
    ca: &Ca,
    unit: &Unit,
    now: i64,
) -> anyhow::Result<Option<&'static str>> {
    let (dns, ips, lifetime) = match policy::decide(&c.asked, unit) {
        Decision::Issue { dns, ips, lifetime } => (dns, ips, lifetime),
        Decision::Deny { message, .. } => anyhow::bail!("{}/{}: {message}", c.namespace, c.name),
    };
    let current = api.get_opt(&c.name).await?;
    let Some(why) = due(
        current.as_ref().and_then(held).as_ref(),
        &dns,
        &ips,
        ca.root().as_bytes(),
        now,
    ) else {
        return Ok(None);
    };
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let spki = rcgen::SubjectPublicKeyInfo::from_der(
        &rcgen::PublicKeyData::subject_public_key_info(&key),
    )?;
    let leaf = ca.issue(&spki, &dns, &ips, now, lifetime)?;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(c.name.clone()),
            namespace: Some(c.namespace.clone()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".into()),
        data: Some(BTreeMap::from([
            ("tls.crt".to_owned(), ByteString(leaf.chain.into_bytes())),
            (
                "tls.key".to_owned(),
                ByteString(key.serialize_pem().into_bytes()),
            ),
            (
                "ca.crt".to_owned(),
                ByteString(ca.root().as_bytes().to_vec()),
            ),
        ])),
        ..Default::default()
    };
    api.patch(
        &c.name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&secret),
    )
    .await?;
    Ok(Some(why))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(not_before: i64, not_after: i64) -> Held {
        Held {
            dns: vec!["meridian.lan".into(), "localhost".into()],
            ips: vec!["127.0.0.1".parse().unwrap()],
            not_before,
            not_after,
            root: vec![1],
        }
    }

    #[test]
    fn a_leaf_is_issued_again_halfway_for_a_new_name_or_a_new_ca() {
        let dns = vec!["meridian.lan".to_owned(), "localhost".to_owned()];
        let ips: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        assert_eq!(due(None, &dns, &ips, &[1], 0), Some("no leaf yet"));
        assert_eq!(due(Some(&h(0, 100)), &dns, &ips, &[1], 10), None);
        assert_eq!(
            due(Some(&h(0, 100)), &dns, &ips, &[1], 50),
            Some("halfway through its life")
        );
        assert_eq!(
            due(Some(&h(0, 100)), &dns, &ips, &[2], 10),
            Some("the CA changed")
        );
        let more: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "10.51.0.1".parse().unwrap()];
        assert_eq!(
            due(Some(&h(0, 100)), &dns, &more, &[1], 10),
            Some("a name it lacks")
        );
    }

    #[test]
    fn configured_by_the_deployment_or_not_at_all() {
        assert!(Config::from_env(|_| String::new()).unwrap().is_none());
        let env = |k: &str| match k {
            "EDGE_SIGNER_LEAF" => "meridian/meridian-tls".into(),
            "EDGE_SIGNER_LEAF_DNS" => "meridian.lan,localhost".into(),
            "EDGE_SIGNER_LEAF_IPS" => "node,127.0.0.1".into(),
            "EDGE_SIGNER_LEAF_LIFETIME" => "864000".into(),
            _ => String::new(),
        };
        let c = Config::from_env(env).unwrap().unwrap();
        assert_eq!(
            (c.namespace.as_str(), c.name.as_str()),
            ("meridian", "meridian-tls")
        );
        assert!(
            Config::from_env(|k| if k == "EDGE_SIGNER_LEAF" {
                "meridian/x".into()
            } else {
                String::new()
            })
            .is_err(),
            "a leaf names its lifetime"
        );
    }
}
