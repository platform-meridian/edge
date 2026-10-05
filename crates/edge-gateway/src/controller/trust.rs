//! CA bundles a reference names: a ConfigMap's `ca.crt`, or, so the node's own
//! CA needs no copy, a ClusterTrustBundle.

use super::state::Key;
use kube::api::DynamicObject;
use std::collections::BTreeMap;

pub(super) const BUNDLE_GROUP: &str = "certificates.k8s.io";

/// Objects watched one by one, while something references them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum RefKind {
    ConfigMap,
}

impl RefKind {
    pub fn api(self) -> (&'static str, &'static str, &'static str) {
        match self {
            RefKind::ConfigMap => ("", "v1", "ConfigMap"),
        }
    }

    pub fn thin(self, o: &mut DynamicObject) {
        match self {
            RefKind::ConfigMap => thin_configmap(o),
        }
        o.metadata.managed_fields = None;
        o.metadata.annotations = None;
    }
}

#[derive(Debug, Default)]
pub(super) struct RefState {
    pub listed: Option<bool>,
    pub object: Option<DynamicObject>,
}

pub(super) type Refs = BTreeMap<(RefKind, Key), RefState>;

pub(super) struct Sources<'a> {
    pub refs: &'a Refs,
    pub bundles: Option<&'a BTreeMap<Key, DynamicObject>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RefError {
    Kind(String),
    Invalid(String),
}

impl RefError {
    pub fn message(&self) -> &str {
        match self {
            RefError::Kind(m) | RefError::Invalid(m) => m,
        }
    }
}

impl Sources<'_> {
    pub fn resolve(
        &self,
        group: &str,
        kind: &str,
        ns: &str,
        name: &str,
    ) -> Result<String, RefError> {
        let invalid = |why: &str| RefError::Invalid(format!("{kind} {name}: {why}"));
        let key = (ns.to_string(), name.to_string());
        let (found, pem) = match (group, kind) {
            ("", "ConfigMap") => (
                match self.refs.get(&(RefKind::ConfigMap, key)) {
                    Some(RefState {
                        listed: Some(false),
                        ..
                    }) => None,
                    r => Some(r.and_then(|r| r.object.as_ref())),
                },
                (|o: &DynamicObject| o.data["data"]["ca.crt"].as_str().map(str::to_string))
                    as fn(&DynamicObject) -> Option<String>,
            ),
            (BUNDLE_GROUP, "ClusterTrustBundle") => (
                self.bundles
                    .map(|b| b.get(&(String::new(), name.to_string()))),
                (|o: &DynamicObject| o.data["spec"]["trustBundle"].as_str().map(str::to_string))
                    as fn(&DynamicObject) -> Option<String>,
            ),
            _ => {
                return Err(RefError::Kind(format!(
                    "{name} is a {group}/{kind}; only ConfigMap and ClusterTrustBundle are supported"
                )));
            }
        };
        let Some(found) = found else {
            return Err(invalid("cannot be listed"));
        };
        let Some(o) = found else {
            return Err(invalid("does not exist"));
        };
        let Some(pem) = pem(o) else {
            return Err(invalid("holds no CA bundle (ca.crt)"));
        };
        crate::tls::roots(&pem).map_err(|e| invalid(&e))?;
        Ok(pem)
    }
}

/// The ConfigMaps a Gateway's frontend validation or a BackendTLSPolicy names:
/// only these are watched.
pub(super) fn referenced(
    gateway: Option<&DynamicObject>,
    gw: &super::GatewayRef,
    policies: impl Iterator<Item = DynamicObject>,
) -> std::collections::BTreeSet<(RefKind, Key)> {
    let configmaps = |refs: &serde_json::Value, default_ns: &str| -> Vec<(RefKind, Key)> {
        refs.as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|r| {
                r["group"].as_str().unwrap_or_default().is_empty()
                    && r["kind"].as_str() == Some("ConfigMap")
            })
            .filter_map(|r| {
                let ns = r["namespace"].as_str().unwrap_or(default_ns);
                Some((
                    RefKind::ConfigMap,
                    (ns.to_string(), r["name"].as_str()?.to_string()),
                ))
            })
            .collect()
    };
    let mut out = std::collections::BTreeSet::new();
    if let Some(g) = gateway {
        out.extend(configmaps(
            &super::frontend::validation(g, gw)["caCertificateRefs"],
            &gw.namespace,
        ));
    }
    for p in policies {
        let ns = kube::ResourceExt::namespace(&p).unwrap_or_default();
        out.extend(configmaps(
            &p.data["spec"]["validation"]["caCertificateRefs"],
            &ns,
        ));
    }
    out
}

/// Only a ConfigMap's `ca.crt` is kept.
pub(super) fn thin_configmap(o: &mut DynamicObject) {
    let ca = o.data["data"]["ca.crt"].take();
    o.data = if ca.is_null() {
        serde_json::Value::Null
    } else {
        serde_json::json!({ "data": { "ca.crt": ca } })
    };
}
