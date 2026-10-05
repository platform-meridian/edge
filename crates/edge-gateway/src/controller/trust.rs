//! CA bundles a reference names: a ConfigMap's `ca.crt`, or, so the node's own
//! CA needs no copy, a ClusterTrustBundle.

use super::state::Key;
use kube::api::DynamicObject;
use std::collections::BTreeMap;

pub(super) const BUNDLE_GROUP: &str = "certificates.k8s.io";

pub(super) struct Sources<'a> {
    /// Thinned to `ca.crt`; `None` when ConfigMaps cannot be listed.
    pub configmaps: Option<&'a BTreeMap<Key, DynamicObject>>,
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
        let (store, key, pem) = match (group, kind) {
            ("", "ConfigMap") => (
                self.configmaps,
                (ns.to_string(), name.to_string()),
                (|o: &DynamicObject| o.data["data"]["ca.crt"].as_str().map(str::to_string))
                    as fn(&DynamicObject) -> Option<String>,
            ),
            (BUNDLE_GROUP, "ClusterTrustBundle") => (
                self.bundles,
                (String::new(), name.to_string()),
                (|o: &DynamicObject| o.data["spec"]["trustBundle"].as_str().map(str::to_string))
                    as fn(&DynamicObject) -> Option<String>,
            ),
            _ => {
                return Err(RefError::Kind(format!(
                    "{name} is a {group}/{kind}; only ConfigMap and ClusterTrustBundle are supported"
                )));
            }
        };
        let Some(store) = store else {
            return Err(invalid("cannot be listed"));
        };
        let Some(o) = store.get(&key) else {
            return Err(invalid("does not exist"));
        };
        let Some(pem) = pem(o) else {
            return Err(invalid("holds no CA bundle (ca.crt)"));
        };
        crate::tls::roots(&pem).map_err(|e| invalid(&e))?;
        Ok(pem)
    }
}

/// Only a ConfigMap's `ca.crt` is kept: every ConfigMap is watched.
pub(super) fn thin_configmap(o: &mut DynamicObject) {
    let ca = o.data["data"]["ca.crt"].take();
    o.data = if ca.is_null() {
        serde_json::Value::Null
    } else {
        serde_json::json!({ "data": { "ca.crt": ca } })
    };
}
