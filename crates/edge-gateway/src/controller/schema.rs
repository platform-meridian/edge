//! Retyped rather than taken from generated bindings, which pin their own
//! kube/k8s-openapi pair.

use super::GATEWAY_GROUP;
use kube::ResourceExt;
use kube::api::DynamicObject;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct HttpRouteSpec {
    pub parent_refs: Vec<ParentRef>,
    pub hostnames: Vec<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ParentRef {
    pub name: String,
    pub namespace: Option<String>,
    pub kind: Option<String>,
    pub group: Option<String>,
    pub section_name: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct Rule {
    pub matches: Vec<Match>,
    pub backend_refs: Vec<BackendRef>,
    pub filters: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Filter {
    pub r#type: String,
    pub request_header_modifier: Option<HeaderFilter>,
    pub request_redirect: Option<RedirectFilter>,
    pub url_rewrite: Option<RewriteFilter>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct HeaderFilter {
    pub set: Vec<NameValue>,
    pub add: Vec<NameValue>,
    pub remove: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct NameValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct RedirectFilter {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub path: Option<PathFilter>,
    pub port: Option<u16>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct RewriteFilter {
    pub hostname: Option<String>,
    pub path: Option<PathFilter>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct PathFilter {
    pub r#type: String,
    pub replace_full_path: Option<String>,
    pub replace_prefix_match: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct Match {
    pub path: Option<PathMatch>,
    pub headers: Vec<Value>,
    pub method: Option<String>,
    pub query_params: Vec<Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct PathMatch {
    pub r#type: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct BackendRef {
    pub name: String,
    pub namespace: Option<String>,
    pub port: Option<u16>,
    pub group: Option<String>,
    pub kind: Option<String>,
    pub weight: Option<u32>,
    pub filters: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowedNamespaces {
    Same,
    All,
    /// Would need a Namespace watch; refused rather than guessed.
    Selector,
}

#[derive(Debug, Clone)]
pub(super) struct Listener {
    name: String,
    port: Option<u16>,
    namespaces: AllowedNamespaces,
    admits_httproute: bool,
}

impl Listener {
    pub fn all_of(gateway: &DynamicObject) -> Vec<Listener> {
        gateway.data["spec"]["listeners"]
            .as_array()
            .map(|ls| ls.iter().map(Listener::parse).collect())
            .unwrap_or_default()
    }

    fn parse(l: &Value) -> Listener {
        let allowed = &l["allowedRoutes"];
        let namespaces = match allowed["namespaces"]["from"].as_str() {
            None | Some("Same") => AllowedNamespaces::Same,
            Some("All") => AllowedNamespaces::All,
            Some(_) => AllowedNamespaces::Selector,
        };
        let admits_httproute = match allowed["kinds"].as_array() {
            None => true,
            Some(kinds) => kinds.iter().any(|k| {
                k["kind"].as_str() == Some("HTTPRoute")
                    && k["group"].as_str().unwrap_or(GATEWAY_GROUP) == GATEWAY_GROUP
            }),
        };
        Listener {
            name: l["name"].as_str().unwrap_or_default().to_string(),
            port: l["port"].as_u64().and_then(|p| u16::try_from(p).ok()),
            namespaces,
            admits_httproute,
        }
    }

    pub fn selected_by(&self, p: &ParentRef) -> bool {
        p.section_name.as_deref().is_none_or(|s| s == self.name)
            && p.port.is_none_or(|port| Some(port) == self.port)
    }

    pub fn admits(&self, route_ns: &str, gateway_ns: &str) -> bool {
        self.admits_httproute
            && match self.namespaces {
                AllowedNamespaces::All => true,
                AllowedNamespaces::Same => route_ns == gateway_ns,
                AllowedNamespaces::Selector => false,
            }
    }
}

#[derive(Debug)]
struct GrantFrom {
    group: String,
    kind: String,
    namespace: String,
}

#[derive(Debug)]
struct GrantTo {
    group: String,
    kind: String,
    name: Option<String>,
}

/// Lives in the namespace of the object it grants access to.
#[derive(Debug)]
pub(super) struct ReferenceGrant {
    namespace: String,
    from: Vec<GrantFrom>,
    to: Vec<GrantTo>,
}

impl ReferenceGrant {
    pub fn parse(o: &DynamicObject) -> Option<ReferenceGrant> {
        let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
        Some(ReferenceGrant {
            namespace: o.namespace()?,
            from: o.data["spec"]["from"]
                .as_array()?
                .iter()
                .map(|f| GrantFrom {
                    group: text(&f["group"]),
                    kind: text(&f["kind"]),
                    namespace: text(&f["namespace"]),
                })
                .collect(),
            to: o.data["spec"]["to"]
                .as_array()?
                .iter()
                .map(|t| GrantTo {
                    group: text(&t["group"]),
                    kind: text(&t["kind"]),
                    name: t["name"].as_str().map(str::to_string),
                })
                .collect(),
        })
    }

    pub fn permits(&self, route_ns: &str, service_ns: &str, service: &str) -> bool {
        self.namespace == service_ns
            && self.from.iter().any(|f| {
                f.group == GATEWAY_GROUP && f.kind == "HTTPRoute" && f.namespace == route_ns
            })
            && self.to.iter().any(|t| {
                t.group.is_empty()
                    && t.kind == "Service"
                    && t.name.as_deref().is_none_or(|n| n == service)
            })
    }
}
