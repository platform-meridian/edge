//! The cluster, through the apiserver: what its workloads run, and whether they
//! are ready.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{Pod, PodSpec};
use kube::api::ListParams;
use kube::{Api, Client};

const CALL: Duration = Duration::from_secs(30);

pub struct Kube {
    client: Client,
}

impl Kube {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

async fn timed<T>(f: impl std::future::Future<Output = kube::Result<T>>) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(CALL, f)
        .await
        .context("the apiserver did not answer")??)
}

pub fn workload(kind: &str, namespace: &str, name: &str) -> String {
    format!("{} {namespace}/{name}", kind.to_ascii_lowercase())
}

fn images(spec: &PodSpec) -> impl Iterator<Item = String> + '_ {
    spec.containers
        .iter()
        .chain(spec.init_containers.iter().flatten())
        .filter_map(|c| c.image.clone())
}

#[async_trait]
impl crate::unit::Cluster for Kube {
    async fn not_ready(&self) -> anyhow::Result<Vec<String>> {
        let mut waiting = Vec::new();
        let lp = ListParams::default();
        let deploys: Api<Deployment> = Api::all(self.client.clone());
        for d in timed(deploys.list(&lp)).await? {
            let want = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
            let ready = d.status.and_then(|s| s.ready_replicas).unwrap_or(0);
            if ready < want {
                waiting.push(named("Deployment", &d.metadata));
            }
        }
        let sets: Api<DaemonSet> = Api::all(self.client.clone());
        for d in timed(sets.list(&lp)).await? {
            let st = d.status.unwrap_or_default();
            if st.number_ready < st.desired_number_scheduled {
                waiting.push(named("DaemonSet", &d.metadata));
            }
        }
        Ok(waiting)
    }

    async fn workloads(&self) -> anyhow::Result<BTreeSet<String>> {
        let lp = ListParams::default();
        let deploys: Api<Deployment> = Api::all(self.client.clone());
        let sets: Api<DaemonSet> = Api::all(self.client.clone());
        let mut out: BTreeSet<String> = timed(deploys.list(&lp))
            .await?
            .iter()
            .map(|d| named("Deployment", &d.metadata))
            .collect();
        out.extend(
            timed(sets.list(&lp))
                .await?
                .iter()
                .map(|d| named("DaemonSet", &d.metadata)),
        );
        Ok(out)
    }

    async fn images_in_use(&self) -> anyhow::Result<BTreeSet<String>> {
        let lp = ListParams::default();
        let mut specs = Vec::new();
        let deploys: Api<Deployment> = Api::all(self.client.clone());
        for d in timed(deploys.list(&lp)).await? {
            specs.extend(d.spec.and_then(|s| s.template.spec));
        }
        let sets: Api<DaemonSet> = Api::all(self.client.clone());
        for d in timed(sets.list(&lp)).await? {
            specs.extend(d.spec.and_then(|s| s.template.spec));
        }
        let pods: Api<Pod> = Api::all(self.client.clone());
        for p in timed(pods.list(&lp)).await? {
            specs.extend(p.spec);
        }
        Ok(specs.iter().flat_map(images).collect())
    }
}

fn named(kind: &str, m: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta) -> String {
    let s = |o: &Option<String>| o.clone().unwrap_or_default();
    workload(kind, &s(&m.namespace), &s(&m.name))
}
