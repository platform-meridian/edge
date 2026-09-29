//! Gateway API objects become the same route table the config file produces, so
//! matching and forwarding never see Gateway API types.

mod convert;
mod report;
mod run;
mod schema;
mod state;

use crate::config::Route;
use arc_swap::ArcSwap;
use kube::api::{ApiResource, GroupVersionKind};
use std::sync::Arc;

pub use run::spawn;

const CONTROLLER: &str = "edge.meridian/gateway";
const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

pub type Routes = Arc<ArcSwap<Vec<Route>>>;

#[derive(Clone)]
pub struct GatewayRef {
    pub name: String,
    pub namespace: String,
    pub bound_port: u16,
}

fn api_resource(group: &str, version: &str, kind: &str) -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind))
}
