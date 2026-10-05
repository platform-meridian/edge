use super::convert::{Outcome, Verdict};
use super::gateway_status::GatewayStatus;
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

pub(super) async fn publish_gateway_status(
    client: &Client,
    o: &DynamicObject,
    st: &GatewayStatus,
) -> anyhow::Result<()> {
    let generation = o.metadata.generation.unwrap_or(0);
    let conds = |c: &[(&str, Verdict)]| -> Vec<Condition> {
        c.iter().map(|(t, v)| v.condition(t, generation)).collect()
    };
    let conditions = json!(conds(&st.conditions));
    let listeners: Vec<Value> = st
        .listeners
        .iter()
        .map(|l| {
            json!({
                "name": l.name,
                "supportedKinds": l.supported_kinds,
                "attachedRoutes": l.attached,
                "conditions": conds(&l.conditions),
            })
        })
        .collect();
    let current = o.data.get("status");
    if current.is_some_and(|c| {
        status::conditions_equal(&c["conditions"], &conditions)
            && status::listeners_same(&c["listeners"], &listeners)
    }) {
        return Ok(());
    }
    let ns = o.namespace().unwrap_or_default();
    let api: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        &ns,
        &api_resource(GATEWAY_GROUP, "v1", "Gateway"),
    );
    api.patch_status(
        &o.name_any(),
        &status::patch_params(),
        &kube::api::Patch::Merge(
            json!({ "status": { "conditions": conditions, "listeners": listeners } }),
        ),
    )
    .await?;
    tracing::info!(gateway = %o.name_any(), "gateway status written");
    Ok(())
}

/// GatewayClasses are watched apart: one names this controller before any
/// Gateway or route exists.
pub(super) async fn run_class_status() -> anyhow::Result<()> {
    let client = Client::try_default().await?;
    let class_ar = api_resource(GATEWAY_GROUP, "v1", "GatewayClass");
    let classes: Api<DynamicObject> = Api::all_with(client.clone(), &class_ar);
    let applied = watcher(classes.clone(), watcher::Config::default())
        .default_backoff()
        .applied_objects()
        .boxed();
    each_ok(applied, "gatewayclass", |o| {
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
    })
    .await;
    anyhow::bail!("gatewayclass watch ended")
}

fn is_our_class(class: &DynamicObject) -> bool {
    class.data["spec"]["controllerName"] == json!(CONTROLLER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_on_our_class() {
        let class = |c: &str| -> DynamicObject {
            serde_json::from_value(json!({
                "apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
                "metadata": { "name": "edge" }, "spec": { "controllerName": c },
            }))
            .unwrap()
        };
        assert!(is_our_class(&class(CONTROLLER)));
        assert!(!is_our_class(&class("someone.else/gateway")));
    }
}
