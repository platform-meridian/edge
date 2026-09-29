//! Whatever this data plane cannot honour (a header match, a filter, a weighted
//! split) is dropped and reported, never served wider than asked.

use super::schema::{BackendRef, HttpRouteSpec, Listener, Match, ParentRef, ReferenceGrant, Rule};
use super::state::Key;
use super::{GATEWAY_GROUP, GatewayRef};
use crate::config::{Authz, Backend, Route, normalize_host};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::ResourceExt;
use kube::api::DynamicObject;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};

/// Absent means authz is required. Stands in for GEP-1494 `ExternalAuth`.
const AUTHZ_ANNOTATION: &str = "edge.meridian/authz";
const REWRITE_HOST_ANNOTATION: &str = "edge.meridian/rewrite-host";

pub(super) struct Ctx<'a> {
    pub gateway: &'a GatewayRef,
    pub listeners: Option<&'a [Listener]>,
    pub services: Option<&'a BTreeSet<Key>>,
    pub grants: &'a [ReferenceGrant],
    /// No HTTPRoute may claim the config file's hostnames.
    pub static_hosts: &'a HashSet<String>,
}

#[derive(Debug)]
pub(super) struct Verdict {
    pub ok: bool,
    pub reason: &'static str,
    pub message: String,
}

impl Verdict {
    pub fn condition(&self, type_: &str, generation: i64) -> Condition {
        crate::status::condition(type_, self.ok, self.reason, &self.message, generation)
    }
}

struct Problem {
    reason: &'static str,
    message: String,
}

fn problem(reason: &'static str, message: String) -> Problem {
    Problem { reason, message }
}

impl Problem {
    fn into_verdict(self) -> Verdict {
        Verdict {
            ok: false,
            reason: self.reason,
            message: self.message,
        }
    }
}

pub(super) struct Outcome {
    pub routes: Vec<Route>,
    pub parent: Value,
    pub accepted: Verdict,
    pub resolved: Verdict,
}

pub(super) fn convert(o: &DynamicObject, ctx: &Ctx) -> Option<Outcome> {
    let spec: HttpRouteSpec = match serde_json::from_value(o.data["spec"].clone()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(route = %o.name_any(), error = %e, "unparseable spec; ignored");
            return None;
        }
    };
    let ns = o.namespace().unwrap_or_else(|| "default".into());

    let ours: Vec<&ParentRef> = spec
        .parent_refs
        .iter()
        .filter(|p| is_ours(p, &ns, ctx.gateway))
        .collect();
    let parent = status_parent_ref(ours.first()?, ctx.gateway);

    if let Err(p) = attach_any(&ours, &ns, ctx) {
        return Some(Outcome {
            routes: vec![],
            parent,
            accepted: p.into_verdict(),
            resolved: Verdict {
                ok: true,
                reason: "ResolvedRefs",
                message: "not attached; backendRefs not evaluated".into(),
            },
        });
    }

    let annotation = |k: &str| o.annotations().get(k).cloned();
    let authz = match annotation(AUTHZ_ANNOTATION).as_deref() {
        Some("skip") => Authz::Skip,
        _ => Authz::Required,
    };
    let rewrite_host = annotation(REWRITE_HOST_ANNOTATION);

    let mut unsupported = Vec::new();
    let mut unresolved = Vec::new();
    let hostnames = hostnames(&spec.hostnames, ctx, &mut unsupported);
    let mut routes = Vec::new();
    for (i, rule) in spec.rules.iter().enumerate() {
        let backend = match rule_backend(i, rule, &ns, ctx) {
            Ok(b) => b,
            Err(Skipped::Unsupported(p)) => {
                unsupported.push(p);
                continue;
            }
            Err(Skipped::Unresolved(p)) => {
                unresolved.push(p);
                continue;
            }
        };
        let prefixes = rule_prefixes(i, rule, &mut unsupported);
        for host in &hostnames {
            for prefix in &prefixes {
                routes.push(Route {
                    hostname: host.clone(),
                    prefix: prefix.clone(),
                    authz,
                    rewrite_host: rewrite_host.clone(),
                    backend: backend.clone(),
                });
            }
        }
    }

    Some(Outcome {
        accepted: accepted(&unsupported, routes.len()),
        resolved: resolved(&unresolved),
        routes,
        parent,
    })
}

fn is_ours(p: &ParentRef, route_ns: &str, gw: &GatewayRef) -> bool {
    p.name == gw.name
        && p.namespace.as_deref().unwrap_or(route_ns) == gw.namespace
        && p.kind.as_deref().unwrap_or("Gateway") == "Gateway"
        && p.group.as_deref().unwrap_or(GATEWAY_GROUP) == GATEWAY_GROUP
}

fn status_parent_ref(p: &ParentRef, gw: &GatewayRef) -> Value {
    let mut v = json!({
        "name": p.name, "namespace": gw.namespace, "kind": "Gateway", "group": GATEWAY_GROUP,
    });
    if let Some(s) = &p.section_name {
        v["sectionName"] = json!(s);
    }
    if let Some(port) = p.port {
        v["port"] = json!(port);
    }
    v
}

fn attach_any(ours: &[&ParentRef], route_ns: &str, ctx: &Ctx) -> Result<(), Problem> {
    if ours.iter().any(|p| attach(p, route_ns, ctx).is_ok()) {
        return Ok(());
    }
    attach(ours[0], route_ns, ctx)
}

fn attach(p: &ParentRef, route_ns: &str, ctx: &Ctx) -> Result<(), Problem> {
    let gw = ctx.gateway;
    let Some(listeners) = ctx.listeners else {
        return Err(problem(
            "NoMatchingParent",
            format!("Gateway {}/{} does not exist", gw.namespace, gw.name),
        ));
    };
    let mut selected = listeners.iter().filter(|l| l.selected_by(p)).peekable();
    if selected.peek().is_none() {
        return Err(problem(
            "NoMatchingParent",
            format!(
                "no listener of {}/{} matches sectionName {:?} port {:?}",
                gw.namespace, gw.name, p.section_name, p.port
            ),
        ));
    }
    if selected.any(|l| l.admits(route_ns, &gw.namespace)) {
        Ok(())
    } else {
        Err(problem(
            "NotAllowedByListeners",
            format!("listener allowedRoutes does not admit namespace {route_ns}"),
        ))
    }
}

fn hostnames(
    declared: &[String],
    ctx: &Ctx,
    unsupported: &mut Vec<Problem>,
) -> Vec<Option<String>> {
    if declared.is_empty() {
        return vec![None];
    }
    let mut out = Vec::new();
    for h in declared {
        let Some(n) = normalize_host(h) else {
            unsupported.push(problem(
                "UnsupportedValue",
                format!("hostname {h} is a wildcard or not a host"),
            ));
            continue;
        };
        if ctx.static_hosts.contains(&n) {
            unsupported.push(problem(
                "NoMatchingListenerHostname",
                format!("hostname {h} belongs to the gateway's own configuration"),
            ));
        } else {
            out.push(Some(n));
        }
    }
    out
}

enum Skipped {
    Unsupported(Problem),
    Unresolved(Problem),
}

fn rule_backend(i: usize, rule: &Rule, route_ns: &str, ctx: &Ctx) -> Result<Backend, Skipped> {
    let unsupported = |what: String| {
        Skipped::Unsupported(problem("UnsupportedValue", format!("rule {i}: {what}")))
    };
    if !rule.filters.is_empty() {
        return Err(unsupported("filters".into()));
    }
    let receiving_traffic: Vec<&BackendRef> = rule
        .backend_refs
        .iter()
        .filter(|b| b.weight != Some(0))
        .collect();
    if receiving_traffic.iter().any(|b| !b.filters.is_empty()) {
        return Err(unsupported("backendRef filters".into()));
    }
    match receiving_traffic[..] {
        [] => Err(Skipped::Unresolved(problem(
            "BackendNotFound",
            format!("rule {i}: no backendRef that receives traffic"),
        ))),
        [b] => resolve_backend(b, route_ns, ctx).map_err(Skipped::Unresolved),
        _ => Err(unsupported(format!(
            "weighted split across {} backendRefs",
            receiving_traffic.len()
        ))),
    }
}

fn resolve_backend(b: &BackendRef, route_ns: &str, ctx: &Ctx) -> Result<Backend, Problem> {
    let group = b.group.as_deref().unwrap_or("");
    let kind = b.kind.as_deref().unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        return Err(problem(
            "InvalidKind",
            format!(
                "backendRef {} is a {group}/{kind}; only Service is supported",
                b.name
            ),
        ));
    }
    let Some(port) = b.port else {
        return Err(problem(
            "BackendNotFound",
            format!("backendRef {} has no port", b.name),
        ));
    };
    let ns = b.namespace.as_deref().unwrap_or(route_ns);
    // Checked before existence, so a route cannot probe another namespace's Services.
    if ns != route_ns && !ctx.grants.iter().any(|g| g.permits(route_ns, ns, &b.name)) {
        return Err(problem(
            "RefNotPermitted",
            format!("backendRef {ns}/{} needs a ReferenceGrant in {ns}", b.name),
        ));
    }
    if let Some(known) = ctx.services
        && !known.contains(&(ns.to_string(), b.name.clone()))
    {
        return Err(problem(
            "BackendNotFound",
            format!("Service {ns}/{} does not exist", b.name),
        ));
    }
    Ok(Backend {
        host: format!("{}.{ns}.svc.cluster.local", b.name),
        port,
    })
}

fn rule_prefixes(i: usize, rule: &Rule, unsupported: &mut Vec<Problem>) -> Vec<String> {
    let match_all = [Match::default()];
    let matches: &[Match] = if rule.matches.is_empty() {
        &match_all
    } else {
        &rule.matches
    };
    let mut prefixes = Vec::new();
    for m in matches {
        match path_prefix(m) {
            Ok(p) => prefixes.push(p),
            Err(what) => unsupported.push(problem("UnsupportedValue", format!("rule {i}: {what}"))),
        }
    }
    prefixes
}

/// Only PathPrefix: narrowing Exact to a prefix would also serve `/abc/d` for `/abc`.
fn path_prefix(m: &Match) -> Result<String, String> {
    if !m.headers.is_empty() {
        return Err("header matches".into());
    }
    if m.method.is_some() {
        return Err("method matches".into());
    }
    if !m.query_params.is_empty() {
        return Err("queryParam matches".into());
    }
    let (ty, value) = match &m.path {
        None => (None, None),
        Some(p) => (p.r#type.as_deref(), p.value.as_deref()),
    };
    let value = value.unwrap_or("/");
    match ty {
        Some("PathPrefix") | None => {
            crate::path::canonicalize(value).map_err(|e| format!("path prefix {value:?}: {e}"))
        }
        Some(other) => Err(format!("path match type {other}")),
    }
}

fn joined(problems: &[Problem], sep: &str) -> String {
    problems
        .iter()
        .map(|p| p.message.as_str())
        .collect::<Vec<_>>()
        .join(sep)
}

fn accepted(unsupported: &[Problem], served: usize) -> Verdict {
    match unsupported.first() {
        None => Verdict {
            ok: true,
            reason: "Accepted",
            message: format!("{served} route(s) served"),
        },
        Some(first) => Verdict {
            ok: false,
            reason: first.reason,
            message: format!(
                "{}; unsupported parts were dropped, the rest is served",
                joined(unsupported, ", ")
            ),
        },
    }
}

fn resolved(unresolved: &[Problem]) -> Verdict {
    let severity = |p: &&Problem| match p.reason {
        "InvalidKind" => 0,
        "RefNotPermitted" => 1,
        _ => 2,
    };
    match unresolved.iter().min_by_key(severity) {
        None => Verdict {
            ok: true,
            reason: "ResolvedRefs",
            message: "all backendRefs resolved".into(),
        },
        Some(worst) => Verdict {
            ok: false,
            reason: worst.reason,
            message: joined(unresolved, "; "),
        },
    }
}
