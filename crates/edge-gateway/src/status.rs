//! Every write is guarded by a comparison: a status patch triggers a watch event
//! that rebuilds and republishes, so an unguarded write loops forever.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use serde_json::{Value, json};

const MANAGER: &str = "edge-gateway";

/// No `force`: it is apply-only and kube rejects it on a merge patch.
pub fn patch_params() -> PatchParams {
    PatchParams {
        field_manager: Some(MANAGER.to_string()),
        ..Default::default()
    }
}

pub fn condition(
    type_: &str,
    ok: bool,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> Condition {
    Condition {
        type_: type_.into(),
        status: if ok { "True".into() } else { "False".into() },
        reason: reason.into(),
        message: message.into(),
        observed_generation: Some(observed_generation),
        last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        ),
    }
}

fn conditions_same(current: Option<&Value>, desired: &[Condition]) -> bool {
    current.is_some_and(|have| conditions_equal(have, &json!(desired)))
}

pub async fn publish_conditions(
    api: &Api<kube::api::DynamicObject>,
    obj: &kube::api::DynamicObject,
    current: Option<&Value>,
    desired: Vec<Condition>,
) -> anyhow::Result<bool> {
    if conditions_same(current, &desired) {
        return Ok(false);
    }
    api.patch_status(
        &obj.name_any(),
        &patch_params(),
        &Patch::Merge(json!({ "status": { "conditions": desired } })),
    )
    .await?;
    Ok(true)
}

pub fn route_parent(parent: &Value, controller: &str, conditions: Vec<Condition>) -> Value {
    json!({
        "parentRef": parent,
        "controllerName": controller,
        "conditions": conditions,
    })
}

/// Other implementations report on the same route, so only our entry is replaced.
pub fn merge_parents(current: Option<&Value>, ours: Value, controller: &str) -> Vec<Value> {
    let mut out: Vec<Value> = match current {
        Some(Value::Array(a)) => a
            .iter()
            .filter(|p| p["controllerName"] != json!(controller))
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    out.push(ours);
    out
}

/// Ignores `lastTransitionTime`, which would otherwise never converge.
pub fn parents_same(current: Option<&Value>, desired: &[Value]) -> bool {
    let Some(Value::Array(have)) = current else {
        return false;
    };
    if have.len() != desired.len() {
        return false;
    }
    desired.iter().all(|d| {
        have.iter().any(|h| {
            h["parentRef"] == d["parentRef"]
                && h["controllerName"] == d["controllerName"]
                && conditions_equal(&h["conditions"], &d["conditions"])
        })
    })
}

fn conditions_equal(a: &Value, b: &Value) -> bool {
    let (Value::Array(a), Value::Array(b)) = (a, b) else {
        return false;
    };
    a.len() == b.len()
        && b.iter().all(|d| {
            a.iter().any(|h| {
                h["type"] == d["type"]
                    && h["status"] == d["status"]
                    && h["reason"] == d["reason"]
                    && h["message"] == d["message"]
                    && h["observedGeneration"] == d["observedGeneration"]
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "edge.meridian/gateway";

    fn cond(reason: &str, generation: i64) -> Condition {
        condition("Accepted", true, reason, "ok", generation)
    }

    #[test]
    fn conditions_ignore_timestamp() {
        let published = serde_json::to_value([cond("Accepted", 3)]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(conditions_same(Some(&published), &[cond("Accepted", 3)]));
        for differs in [
            vec![cond("SomethingElse", 3)],
            vec![cond("Accepted", 4)],
            vec![condition("Accepted", false, "Accepted", "ok", 3)],
            vec![condition("Accepted", true, "Accepted", "changed", 3)],
            vec![condition("Programmed", true, "Accepted", "ok", 3)],
            vec![cond("Accepted", 3), cond("Other", 3)],
            vec![],
        ] {
            assert!(!conditions_same(Some(&published), &differs), "{differs:?}");
        }
        assert!(!conditions_same(None, &[cond("Accepted", 3)]));
    }

    #[test]
    fn merge_replaces_only_our_parent() {
        let theirs = json!({ "parentRef": { "name": "other" }, "controllerName": "someone.else/gateway", "conditions": [] });
        let our_old = route_parent(&json!({ "name": "edge" }), OURS, vec![]);
        let ours = route_parent(&json!({ "name": "edge" }), OURS, vec![cond("Accepted", 1)]);
        let merged = merge_parents(Some(&json!([theirs, our_old])), ours.clone(), OURS);
        assert_eq!(merged, [theirs, ours.clone()]);
        assert_eq!(merge_parents(None, ours.clone(), OURS), [ours]);
    }

    #[test]
    fn parents_ignore_timestamp() {
        let entry = |reason: &str, controller: &str| {
            route_parent(
                &json!({ "name": "edge" }),
                controller,
                vec![cond(reason, 1)],
            )
        };
        let published = json!([entry("Accepted", OURS)]);
        assert!(parents_same(Some(&published), &[entry("Accepted", OURS)]));
        for differs in [
            vec![entry("Other", OURS)],
            vec![entry("Accepted", "someone.else/gateway")],
            vec![route_parent(
                &json!({ "name": "other" }),
                OURS,
                vec![cond("Accepted", 1)],
            )],
            vec![route_parent(&json!({ "name": "edge" }), OURS, vec![])],
            vec![
                entry("Accepted", OURS),
                entry("Accepted", "someone.else/gateway"),
            ],
        ] {
            assert!(!parents_same(Some(&published), &differs), "{differs:?}");
        }
        assert!(!parents_same(None, &[entry("Accepted", OURS)]));
    }
}
