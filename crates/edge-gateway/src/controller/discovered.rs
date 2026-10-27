//! Routes an app declares in a ConfigMap of its own, labelled
//! [`LABEL`]: edge-gateway finds them, so no app patches another's objects.
//! Each holds a [`RouteSet`] under [`KEY`], served like the config file's
//! routes (loopback backends included), after them on a tie.

use crate::config::{Route, RouteSet};
use kube::ResourceExt;
use kube::api::DynamicObject;
use serde_json::Value;

/// The label that makes a ConfigMap a route declaration; its value is not read.
pub const LABEL: &str = "edge.meridian/routes";
/// The data key holding the routes.
pub const KEY: &str = "routes.yaml";

/// Its routes, or why it has none.
pub(super) fn routes(o: &DynamicObject) -> anyhow::Result<Vec<Route>> {
    let text = o.data["data"][KEY]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no {KEY} key"))?;
    Ok(RouteSet::parse(text)?.routes)
}

/// Keeps only [`KEY`].
pub(super) fn thin(o: &mut DynamicObject) {
    let kept = o.data["data"][KEY].clone();
    o.data = match kept {
        Value::Null => serde_json::json!({}),
        v => serde_json::json!({ "data": { KEY: v } }),
    };
}

/// Said once per change, as the object arrives.
pub(super) fn report(o: &DynamicObject) {
    let at = format!("{}/{}", o.namespace().unwrap_or_default(), o.name_any());
    match routes(o) {
        Ok(r) => tracing::info!(configmap = %at, routes = r.len(), "declared routes"),
        Err(e) => tracing::error!(configmap = %at, error = %e, "declared routes refused"),
    }
}
