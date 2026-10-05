//! Gateway API objects become the same route table the config file produces, so
//! matching and forwarding never see Gateway API types.

mod convert;
mod frontend;
mod gateway_status;
mod identity;
mod policy;
mod report;
mod run;
mod schema;
mod state;
mod trust;

use crate::config::Route;
use arc_swap::ArcSwap;
use kube::api::{ApiResource, GroupVersionKind};
use std::sync::Arc;

pub use run::spawn;

const CONTROLLER: &str = "edge.meridian/gateway";
const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

pub type Routes = Arc<ArcSwap<Vec<Route>>>;

/// What the config file gives the controller.
#[derive(Clone)]
pub struct Settings {
    /// Survive every republish: they reach loopback-bound backends, which no
    /// Service can name (Endpoints reject 127.0.0.1).
    pub statics: Vec<Route>,
    /// Identity headers no route filter may set.
    pub strip: Vec<String>,
    /// Dial the Services BackendTLSPolicies name.
    pub dialers: crate::proxy::Dialers,
}

#[derive(Clone)]
pub struct GatewayRef {
    pub name: String,
    pub namespace: String,
    pub bound_port: u16,
}

fn api_resource(group: &str, version: &str, kind: &str) -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind))
}
