//! The cluster, through the apiserver: Flux's objects, the stack's records and
//! the bundle's seed.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{ConfigMap, Pod, PodSpec};
use kube::api::{ApiResource, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams};
use kube::{Api, Client};
use serde::Deserialize;

use crate::unit::Ref;

const MANAGER: &str = "edge-update";
const CALL: Duration = Duration::from_secs(30);

pub struct Kube {
    client: Client,
}

impl Kube {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn dynamic(&self, gvk: (&str, &str, &str), at: &Ref) -> Api<DynamicObject> {
        let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(gvk.0, gvk.1, gvk.2));
        Api::namespaced_with(self.client.clone(), &at.namespace, &ar)
    }
}

const FLUX_INSTANCE: (&str, &str, &str) = ("fluxcd.controlplane.io", "v1", "FluxInstance");
const OCI_REPOSITORY: (&str, &str, &str) = ("source.toolkit.fluxcd.io", "v1", "OCIRepository");
const KUSTOMIZATION: (&str, &str, &str) = ("kustomize.toolkit.fluxcd.io", "v1", "Kustomization");

async fn timed<T>(f: impl std::future::Future<Output = kube::Result<T>>) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(CALL, f)
        .await
        .context("the apiserver did not answer")??)
}

/// Objects in a manifest stream, empty documents skipped.
fn objects(manifests: &str) -> anyhow::Result<Vec<DynamicObject>> {
    let mut out = Vec::new();
    for de in serde_yaml::Deserializer::from_str(manifests) {
        let v = serde_yaml::Value::deserialize(de)?;
        if v.is_null() {
            continue;
        }
        out.push(serde_yaml::from_value(v).context("a seed document is not a Kubernetes object")?);
    }
    Ok(out)
}

pub fn workload(kind: &str, namespace: &str, name: &str) -> String {
    format!("{} {namespace}/{name}", kind.to_ascii_lowercase())
}

/// A manifest stream's namespaced objects, named as [`workload`] names them.
pub fn declared(manifests: &str) -> anyhow::Result<BTreeSet<String>> {
    Ok(objects(manifests)?
        .into_iter()
        .filter_map(|o| {
            let kind = &o.types.as_ref()?.kind;
            let m = &o.metadata;
            Some(workload(kind, m.namespace.as_deref()?, m.name.as_deref()?))
        })
        .collect())
}

fn images(spec: &PodSpec) -> impl Iterator<Item = String> + '_ {
    spec.containers
        .iter()
        .chain(spec.init_containers.iter().flatten())
        .filter_map(|c| c.image.clone())
}

#[async_trait]
impl crate::unit::Cluster for Kube {
    async fn config_map(&self, at: &Ref) -> anyhow::Result<Option<BTreeMap<String, String>>> {
        let api: Api<ConfigMap> = Api::namespaced(self.client.clone(), &at.namespace);
        Ok(timed(api.get_opt(&at.name))
            .await?
            .map(|c| c.data.unwrap_or_default()))
    }

    async fn sync(&self, instance: &Ref) -> anyhow::Result<(String, String)> {
        let fi = timed(self.dynamic(FLUX_INSTANCE, instance).get(&instance.name)).await?;
        let sync = &fi.data["spec"]["sync"];
        let s = |k: &str| sync[k].as_str().unwrap_or_default().to_string();
        Ok((s("url"), s("ref")))
    }

    async fn repoint(
        &self,
        instance: &Ref,
        url: &str,
        tag: &str,
        path: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut sync = serde_json::json!({ "url": url, "ref": tag });
        if let Some(p) = path {
            sync["path"] = p.into();
        }
        let patch = serde_json::json!({ "spec": { "sync": sync } });
        timed(self.dynamic(FLUX_INSTANCE, instance).patch(
            &instance.name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        ))
        .await?;
        Ok(())
    }

    async fn reconcile(&self, source: &Ref) -> anyhow::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .to_string();
        let patch = serde_json::json!({
            "metadata": { "annotations": { "reconcile.fluxcd.io/requestedAt": now } }
        });
        timed(self.dynamic(OCI_REPOSITORY, source).patch(
            &source.name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        ))
        .await?;
        Ok(())
    }

    async fn applied(&self, kustomization: &Ref) -> anyhow::Result<Option<String>> {
        let k = timed(
            self.dynamic(KUSTOMIZATION, kustomization)
                .get_opt(&kustomization.name),
        )
        .await?;
        Ok(k.and_then(|k| {
            k.data["status"]["lastAppliedRevision"]
                .as_str()
                .map(String::from)
        }))
    }

    async fn apply(&self, manifests: &str) -> anyhow::Result<()> {
        for obj in objects(manifests)? {
            let types = obj
                .types
                .clone()
                .context("a seed object has no apiVersion or kind")?;
            let gvk = GroupVersionKind::try_from(&types)?;
            let name = obj
                .metadata
                .name
                .clone()
                .context("a seed object has no name")?;
            let (ar, caps) = timed(kube::discovery::pinned_kind(&self.client, &gvk)).await?;
            let api: Api<DynamicObject> = match (&caps.scope, &obj.metadata.namespace) {
                (kube::discovery::Scope::Namespaced, Some(ns)) => {
                    Api::namespaced_with(self.client.clone(), ns, &ar)
                }
                (kube::discovery::Scope::Namespaced, None) => {
                    anyhow::bail!("the seed's {} {name} names no namespace", gvk.kind)
                }
                (kube::discovery::Scope::Cluster, _) => Api::all_with(self.client.clone(), &ar),
            };
            timed(api.patch(
                &name,
                &PatchParams::apply(MANAGER).force(),
                &Patch::Apply(&obj),
            ))
            .await
            .with_context(|| format!("apply {} {name}", gvk.kind))?;
        }
        Ok(())
    }

    async fn not_rolled_out(&self, manifests: &str) -> anyhow::Result<Vec<String>> {
        let mut waiting = Vec::new();
        for obj in objects(manifests)? {
            if !obj.types.as_ref().is_some_and(|t| t.kind == "Deployment") {
                continue;
            }
            let (Some(name), Some(ns)) = (obj.metadata.name, obj.metadata.namespace) else {
                continue;
            };
            let api: Api<Deployment> = Api::namespaced(self.client.clone(), &ns);
            let d = timed(api.get(&name)).await?;
            let want = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
            let st = d.status.unwrap_or_default();
            let current = st.observed_generation >= d.metadata.generation
                && st.updated_replicas.unwrap_or(0) >= want
                && st.available_replicas.unwrap_or(0) >= want
                && st.replicas.unwrap_or(0) == want;
            if !current {
                waiting.push(format!("{ns}/{name}"));
            }
        }
        Ok(waiting)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_objects_parse_and_empty_documents_are_skipped() {
        let objs = objects(
            "---\napiVersion: v1\nkind: ServiceAccount\nmetadata: {name: judge, namespace: flux}\n---\n\n---\n\
             apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: judge, namespace: flux}\nspec: {replicas: 1}\n",
        )
        .unwrap();
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[1].types.as_ref().unwrap().kind, "Deployment");
        assert!(objects("- not an object\n").is_err());
    }

    #[test]
    fn declared_named_like_not_ready() {
        let w = declared(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: judge, namespace: flux}\n---\n\
             apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: judge, namespace: flux}\n---\n\
             apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: judge}\n",
        )
        .unwrap();
        assert_eq!(
            w,
            ["deployment flux/judge", "serviceaccount flux/judge"]
                .map(String::from)
                .into()
        );
    }

    #[test]
    fn images_include_init_containers() {
        let spec: PodSpec = serde_json::from_value(serde_json::json!({
            "initContainers": [{"name": "i", "image": "reg/init:1"}],
            "containers": [{"name": "c", "image": "reg/app:1"}, {"name": "n"}],
        }))
        .unwrap();
        assert_eq!(
            images(&spec).collect::<Vec<_>>(),
            ["reg/app:1", "reg/init:1"]
        );
    }
}
