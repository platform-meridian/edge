use super::convert::Outcome;
use super::policy;
use super::run::each_ok;
use super::{CONTROLLER, GATEWAY_GROUP, GatewayRef, api_resource};
use crate::status;
use futures::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, ApiResource, DynamicObject};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, ResourceExt};
use serde_json::{Value, json};

pub(super) async fn publish_route_status(
    client: &Client,
    ar: &ApiResource,
    o: &DynamicObject,
    outcome: &Outcome,
) -> anyhow::Result<()> {
    let generation = o.metadata.generation.unwrap_or(0);
    let conds = vec![
        outcome.accepted.condition("Accepted", generation),
        outcome.resolved.condition("ResolvedRefs", generation),
    ];
    let ours = status::route_parent(&outcome.parent, CONTROLLER, conds);
    let current = o.data.get("status").and_then(|s| s.get("parents"));
    let desired = status::merge_parents(current, ours, CONTROLLER);
    if status::parents_same(current, &desired) {
        return Ok(());
    }
    let ns = o.namespace().unwrap_or_else(|| "default".into());
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), &ns, ar);
    api.patch_status(
        &o.name_any(),
        &status::patch_params(),
        &kube::api::Patch::Merge(json!({ "status": { "parents": desired } })),
    )
    .await?;
    tracing::info!(route = %o.name_any(), accepted = outcome.accepted.ok, "status written");
    Ok(())
}

/// Our ancestor entry while one of our routes uses a Service it targets;
/// otherwise none, and a stale one is removed.
pub(super) async fn publish_policy_status(
    client: &Client,
    ar: &ApiResource,
    gateway: &GatewayRef,
    o: &DynamicObject,
    outcome: &policy::Outcome,
    ours: bool,
) -> anyhow::Result<()> {
    let generation = o.metadata.generation.unwrap_or(0);
    let current = o.data.get("status").and_then(|s| s.get("ancestors"));
    let desired = if ours {
        let ancestor = json!({
            "group": GATEWAY_GROUP, "kind": "Gateway",
            "namespace": gateway.namespace, "name": gateway.name,
        });
        let conds = vec![
            outcome.accepted.condition("Accepted", generation),
            outcome.resolved.condition("ResolvedRefs", generation),
        ];
        status::merge_parents(
            current,
            status::policy_ancestor(&ancestor, CONTROLLER, conds),
            CONTROLLER,
        )
    } else {
        status::others(current, CONTROLLER)
    };
    if status::parents_same(current, &desired) {
        return Ok(());
    }
    let ns = o.namespace().unwrap_or_default();
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), &ns, ar);
    api.patch_status(
        &o.name_any(),
        &status::patch_params(),
        &kube::api::Patch::Merge(json!({ "status": { "ancestors": desired } })),
    )
    .await?;
    tracing::info!(policy = %o.name_any(), accepted = outcome.accepted.ok, resolved = outcome.resolved.ok, "status written");
    Ok(())
}

/// Watched apart from HTTPRoutes so a Gateway created after its routes is
/// reported on without waiting for a route to change.
pub(super) async fn run_gateway_status(gateway: GatewayRef) -> anyhow::Result<()> {
    let client = Client::try_default().await?;
    let class_ar = api_resource(GATEWAY_GROUP, "v1", "GatewayClass");
    let gw_ar = api_resource(GATEWAY_GROUP, "v1", "Gateway");
    let classes: Api<DynamicObject> = Api::all_with(client.clone(), &class_ar);
    let gateways: Api<DynamicObject> = Api::all_with(client.clone(), &gw_ar);
    // Patching a namespaced object through an all-namespaces Api builds a URL
    // that does not exist, and the apiserver answers a bare 404.
    let gateway_ns: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), &gateway.namespace, &gw_ar);

    let applied = |api: &Api<DynamicObject>| {
        watcher(api.clone(), watcher::Config::default())
            .default_backoff()
            .applied_objects()
            .boxed()
    };

    let class_status = each_ok(applied(&classes), "gatewayclass", |o| {
        let classes = classes.clone();
        async move {
            if !is_our_class(&o) {
                return;
            }
            let generation = o.metadata.generation.unwrap_or(0);
            let cond = status::condition(
                "Accepted",
                true,
                "Accepted",
                "controller is running",
                generation,
            );
            let current = o.data.get("status").and_then(|s| s.get("conditions"));
            match status::publish_conditions(&classes, &o, current, vec![cond]).await {
                Ok(true) => tracing::info!(class = %o.name_any(), "gatewayclass status written"),
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(class = %o.name_any(), error = %e, "gatewayclass status not written")
                }
            }
        }
    });

    let gateway_status = each_ok(applied(&gateways), "gateway", |o| {
        let gateway = gateway.clone();
        let gateway_ns = gateway_ns.clone();
        async move {
            if !is_our_gateway(&o, &gateway) {
                return;
            }
            let generation = o.metadata.generation.unwrap_or(0);
            let (conds, programmed) = gateway_conditions(&o.data, gateway.bound_port, generation);
            let current = o.data.get("status").and_then(|s| s.get("conditions"));
            match status::publish_conditions(&gateway_ns, &o, current, conds).await {
                Ok(true) => {
                    tracing::info!(gateway = %o.name_any(), programmed, "gateway status written")
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(gateway = %o.name_any(), error = %e, "gateway status not written")
                }
            }
        }
    });

    futures::join!(class_status, gateway_status);
    anyhow::bail!("gateway status watches ended")
}

fn is_our_class(class: &DynamicObject) -> bool {
    class.data["spec"]["controllerName"] == json!(CONTROLLER)
}

fn is_our_gateway(o: &DynamicObject, gateway: &GatewayRef) -> bool {
    o.name_any() == gateway.name && o.namespace().as_deref() == Some(&gateway.namespace)
}

/// The listener comes from the config file, so Programmed means some declared
/// port is the bound one.
fn gateway_conditions(gateway: &Value, bound: u16, generation: i64) -> (Vec<Condition>, bool) {
    let declared: Vec<u64> = gateway["spec"]["listeners"]
        .as_array()
        .map(|ls| ls.iter().filter_map(|l| l["port"].as_u64()).collect())
        .unwrap_or_default();
    let programmed = declared.contains(&u64::from(bound));
    let programmed_cond = if programmed {
        status::condition(
            "Programmed",
            true,
            "Programmed",
            "listener bound",
            generation,
        )
    } else {
        status::condition(
            "Programmed",
            false,
            "Invalid",
            &format!(
                "serving :{bound}, which no listener declares (declared: {declared:?}); \
                 the listener is set in edge-gateway's config, not here"
            ),
            generation,
        )
    };
    let accepted = status::condition(
        "Accepted",
        true,
        "Accepted",
        "claimed by edge-gateway",
        generation,
    );
    (vec![accepted, programmed_cond], programmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(kind: &str, ns: Option<&str>, name: &str, spec: Value) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": kind,
            "metadata": { "name": name, "namespace": ns }, "spec": spec,
        }))
        .unwrap()
    }

    #[test]
    fn reports_only_on_ours() {
        let class = |c: &str| object("GatewayClass", None, "edge", json!({ "controllerName": c }));
        assert!(is_our_class(&class(CONTROLLER)));
        assert!(!is_our_class(&class("someone.else/gateway")));

        let gw = GatewayRef {
            name: "edge".into(),
            namespace: "edge".into(),
            bound_port: 443,
        };
        let gateway = |ns, name| object("Gateway", ns, name, json!({}));
        assert!(is_our_gateway(&gateway(Some("edge"), "edge"), &gw));
        assert!(!is_our_gateway(&gateway(Some("other"), "edge"), &gw));
        assert!(!is_our_gateway(&gateway(Some("edge"), "other"), &gw));
        assert!(!is_our_gateway(&gateway(None, "edge"), &gw));
    }

    #[test]
    fn programmed_needs_bound_port() {
        let spec = json!({ "spec": { "listeners": [{ "port": 80 }, { "port": 443 }] } });
        let summary = |(conds, programmed): (Vec<Condition>, bool)| {
            let c: Vec<(String, String, String, Option<i64>)> = conds
                .into_iter()
                .map(|c| (c.type_, c.status, c.reason, c.observed_generation))
                .collect();
            (c, programmed)
        };
        let row =
            |t: &str, s: &str, r: &str| (t.to_string(), s.to_string(), r.to_string(), Some(7));
        assert_eq!(
            summary(gateway_conditions(&spec, 443, 7)),
            (
                vec![
                    row("Accepted", "True", "Accepted"),
                    row("Programmed", "True", "Programmed")
                ],
                true
            )
        );
        assert_eq!(
            summary(gateway_conditions(&spec, 8443, 7)),
            (
                vec![
                    row("Accepted", "True", "Accepted"),
                    row("Programmed", "False", "Invalid")
                ],
                false
            )
        );
        assert!(!gateway_conditions(&json!({}), 443, 1).1);
    }
}
