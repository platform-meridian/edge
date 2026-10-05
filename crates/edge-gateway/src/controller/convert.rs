//! Whatever this data plane cannot honour (a header match, an unknown filter, a
//! weighted split) is dropped and reported, never served wider than asked.

use super::schema::{
    BackendRef, Filter, HeaderFilter, HttpRouteSpec, Listener, Match, ParentRef, PathFilter,
    RedirectFilter, ReferenceGrant, RewriteFilter, Rule,
};
use super::state::Key;
use super::{GATEWAY_GROUP, GatewayRef};
use crate::config::{
    Authz, Backend, Filters, HeaderModifier, PathModifier, Redirect, Route, UpstreamTls,
    normalize_host,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::ResourceExt;
use kube::api::DynamicObject;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Absent means authz is required. Stands in for GEP-1494 `ExternalAuth`.
const AUTHZ_ANNOTATION: &str = "edge.meridian/authz";
const REWRITE_HOST_ANNOTATION: &str = "edge.meridian/rewrite-host";
/// `request`: the route's hostnames ask the client for a certificate. Ours: the
/// API sets validation per port, and a browser asked shows a picker.
pub(super) const CLIENT_CERT_ANNOTATION: &str = "edge.meridian/client-certificate";

pub(super) struct Ctx<'a> {
    pub gateway: &'a GatewayRef,
    pub listeners: Option<&'a [Listener]>,
    pub services: Option<&'a BTreeSet<Key>>,
    pub grants: &'a [ReferenceGrant],
    pub backend_tls: &'a BTreeMap<Key, UpstreamTls>,
    pub strip: &'a [String],
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
    /// The Services its served rules forward to.
    pub services: BTreeSet<Key>,
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
            services: BTreeSet::new(),
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
    let mut client_cert = annotation(CLIENT_CERT_ANNOTATION).as_deref() == Some("request");

    let mut unsupported = Vec::new();
    let mut unresolved = Vec::new();
    let hostnames = hostnames(&spec.hostnames, ctx, &mut unsupported);
    // Asked for by SNI, so only a named host can be.
    if client_cert && !hostnames.iter().any(Option::is_some) {
        unsupported.push(problem(
            "UnsupportedValue",
            format!("{CLIENT_CERT_ANNOTATION} needs a hostname; no certificate is asked for"),
        ));
        client_cert = false;
    }
    let mut routes = Vec::new();
    let mut services = BTreeSet::new();
    for (i, rule) in spec.rules.iter().enumerate() {
        let (filters, host_rewrite) = match rule_filters(i, rule, ctx) {
            Ok(f) => f,
            Err(p) => {
                unsupported.push(p);
                continue;
            }
        };
        // A redirect is answered here, whatever the rule's backends.
        let backend = if filters.redirect.is_some() {
            None
        } else {
            match rule_backend(i, rule, &ns, ctx) {
                Ok((b, service)) => {
                    services.insert(service);
                    Some(b)
                }
                Err(Skipped::Unsupported(p)) => {
                    unsupported.push(p);
                    continue;
                }
                Err(Skipped::Unresolved(p)) => {
                    unresolved.push(p);
                    continue;
                }
            }
        };
        let rewrite_host = host_rewrite.or_else(|| rewrite_host.clone());
        let prefixes = rule_prefixes(i, rule, &mut unsupported);
        for host in &hostnames {
            for prefix in &prefixes {
                routes.push(Route {
                    hostname: host.clone(),
                    prefix: prefix.clone(),
                    authz,
                    rewrite_host: rewrite_host.clone(),
                    backend: backend.clone(),
                    filters: filters.clone(),
                    client_cert,
                });
            }
        }
    }

    Some(Outcome {
        accepted: accepted(&unsupported, routes.len()),
        resolved: resolved(&unresolved),
        routes,
        services,
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

fn rule_backend(
    i: usize,
    rule: &Rule,
    route_ns: &str,
    ctx: &Ctx,
) -> Result<(Backend, Key), Skipped> {
    let unsupported = |what: String| {
        Skipped::Unsupported(problem("UnsupportedValue", format!("rule {i}: {what}")))
    };
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

fn resolve_backend(b: &BackendRef, route_ns: &str, ctx: &Ctx) -> Result<(Backend, Key), Problem> {
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
    if ns != route_ns
        && !ctx
            .grants
            .iter()
            .any(|g| g.permits("HTTPRoute", route_ns, "Service", ns, &b.name))
    {
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
    let service = (ns.to_string(), b.name.clone());
    Ok((
        Backend {
            host: format!("{}.{ns}.svc.cluster.local", b.name),
            port,
            tls: ctx.backend_tls.get(&service).cloned(),
        },
        service,
    ))
}

/// Each kind at most once, and never a redirect with a rewrite: the API's own
/// rules, checked again since nothing else here would notice.
fn rule_filters(i: usize, rule: &Rule, ctx: &Ctx) -> Result<(Filters, Option<String>), Problem> {
    let listener_port = ctx.gateway.bound_port;
    let bad = |what: String| problem("UnsupportedValue", format!("rule {i}: {what}"));
    let mut filters = Filters::default();
    let mut host_rewrite = None;
    let mut seen = HashSet::new();
    for raw in &rule.filters {
        let f: Filter = serde_json::from_value(raw.clone())
            .map_err(|_| bad("a filter without a type".into()))?;
        if !seen.insert(f.r#type.clone()) {
            return Err(bad(format!("filter {} twice", f.r#type)));
        }
        let missing = || bad(format!("filter {} without its settings", f.r#type));
        match f.r#type.as_str() {
            "RequestHeaderModifier" => {
                let h = f.request_header_modifier.as_ref().ok_or_else(missing)?;
                filters.request_headers = header_modifier(h, ctx.strip).map_err(bad)?;
            }
            "RequestRedirect" => {
                let r = f.request_redirect.as_ref().ok_or_else(missing)?;
                filters.redirect = Some(redirect(r, listener_port).map_err(bad)?);
            }
            "URLRewrite" => {
                let r = f.url_rewrite.as_ref().ok_or_else(missing)?;
                let RewriteFilter { hostname, path } = r;
                if let Some(h) = hostname {
                    host_rewrite = Some(precise_host(h).map_err(bad)?);
                }
                if let Some(p) = path {
                    filters.rewrite_path = Some(path_modifier(p).map_err(bad)?);
                }
            }
            other => return Err(bad(format!("filter {other}"))),
        }
    }
    if filters.redirect.is_some() && seen.contains("URLRewrite") {
        return Err(bad("a redirect and a rewrite together".into()));
    }
    Ok((filters, host_rewrite))
}

/// Never what sanitising settled: framing, hop-by-hop, routing and forwarding
/// headers (the upstream Host is URLRewrite's), nor an identity header backends
/// trust from authz or the gateway alone.
fn header_modifier(h: &HeaderFilter, strip: &[String]) -> Result<HeaderModifier, String> {
    let name = |n: &str| {
        let parsed = http::HeaderName::try_from(n).map_err(|_| format!("header name {n:?}"))?;
        let lower = parsed.as_str();
        if crate::authz::is_forbidden_for_authz(lower) {
            return Err(format!(
                "a header filter on {lower}, which the gateway sets"
            ));
        }
        if lower == crate::xfcc::HEADER || crate::config::strip_listed(strip, lower) {
            return Err(format!("a header filter on {lower}, an identity header"));
        }
        Ok(lower.to_string())
    };
    let pairs = |list: &[super::schema::NameValue]| {
        list.iter()
            .map(|nv| {
                http::HeaderValue::try_from(nv.value.as_str())
                    .map_err(|_| format!("header value for {}", nv.name))?;
                Ok((name(&nv.name)?, nv.value.clone()))
            })
            .collect::<Result<Vec<_>, String>>()
    };
    Ok(HeaderModifier {
        set: pairs(&h.set)?,
        add: pairs(&h.add)?,
        remove: h.remove.iter().map(|n| name(n)).collect::<Result<_, _>>()?,
    })
}

fn redirect(r: &RedirectFilter, listener_port: u16) -> Result<Redirect, String> {
    if let Some(s) = &r.scheme
        && s != "http"
        && s != "https"
    {
        return Err(format!("redirect scheme {s}"));
    }
    let status = r.status_code.unwrap_or(302);
    if ![301, 302, 303, 307, 308].contains(&status) {
        return Err(format!("redirect status {status}"));
    }
    if r.port == Some(0) {
        return Err("redirect port 0".into());
    }
    Ok(Redirect {
        scheme: r.scheme.clone(),
        hostname: r.hostname.as_deref().map(precise_host).transpose()?,
        path: r.path.as_ref().map(path_modifier).transpose()?,
        port: r.port,
        status,
        listener_port,
    })
}

fn precise_host(h: &str) -> Result<String, String> {
    match normalize_host(h) {
        Some(n) if !h.contains(':') => Ok(n),
        _ => Err(format!("hostname {h}")),
    }
}

fn path_modifier(p: &PathFilter) -> Result<PathModifier, String> {
    let canonical = |v: &str| crate::path::canonicalize(v).map_err(|e| format!("path {v:?}: {e}"));
    match (
        p.r#type.as_str(),
        &p.replace_full_path,
        &p.replace_prefix_match,
    ) {
        ("ReplaceFullPath", Some(v), _) => Ok(PathModifier::Full(canonical(v)?)),
        // Empty means strip the prefix.
        ("ReplacePrefixMatch", _, Some(v)) if v.is_empty() => {
            Ok(PathModifier::Prefix(String::new()))
        }
        ("ReplacePrefixMatch", _, Some(v)) => Ok(PathModifier::Prefix(canonical(v)?)),
        (t, ..) => Err(format!("path modifier {t}")),
    }
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
