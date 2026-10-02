//! What the engine drives: the node's Talos API, its cluster and the image
//! registry. Real clients and test fakes both implement these.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait Talos: Send + Sync {
    /// The running Talos version tag.
    async fn version(&self) -> anyhow::Result<String>;
    /// A small file on the node; `None` if it does not exist.
    async fn read(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>>;
    /// A file's size on the node; `None` if it does not exist.
    async fn size(&self, path: &str) -> anyhow::Result<Option<u64>>;
    /// Streams a node file to a local one, returning the bytes copied.
    async fn copy(&self, path: &str, dest: &Path) -> anyhow::Result<u64>;
    /// The config the node boots next.
    async fn machine_config(&self) -> anyhow::Result<String>;
    /// The config the node runs.
    async fn running_config(&self) -> anyhow::Result<String>;
    /// Stages a config for the next boot, or only validates it.
    async fn stage_config(&self, config: &str, dry_run: bool) -> anyhow::Result<()>;
    /// Applies a config now and for every boot after, without a reboot.
    async fn apply_config(&self, config: &str) -> anyhow::Result<()>;
    /// Pulls the installer and writes the new OS beside the running one.
    async fn install(&self, image: &str) -> anyhow::Result<()>;
    /// A power cycle: sd-boot counts the new OS's boots, and a kexec would bypass it.
    async fn reboot(&self) -> anyhow::Result<()>;
    async fn shutdown(&self) -> anyhow::Result<()>;
}

#[async_trait]
pub trait Cluster: Send + Sync {
    async fn config_map(&self, at: &Ref) -> anyhow::Result<Option<BTreeMap<String, String>>>;
    /// The FluxInstance's `spec.sync` url and ref.
    async fn sync(&self, instance: &Ref) -> anyhow::Result<(String, String)>;
    async fn repoint(
        &self,
        instance: &Ref,
        url: &str,
        tag: &str,
        path: Option<&str>,
    ) -> anyhow::Result<()>;
    /// Asks Flux to fetch the source now.
    async fn reconcile(&self, source: &Ref) -> anyhow::Result<()>;
    /// The Kustomization's last applied revision.
    async fn applied(&self, kustomization: &Ref) -> anyhow::Result<Option<String>>;
    /// Server-side applies every object in a manifest stream.
    async fn apply(&self, manifests: &str) -> anyhow::Result<()>;
    /// Names of the stream's Deployments not yet rolled out.
    async fn not_rolled_out(&self, manifests: &str) -> anyhow::Result<Vec<String>>;
    /// Deployments and DaemonSets anywhere with fewer ready than wanted, as
    /// [`crate::cluster::workload`] names them.
    async fn not_ready(&self) -> anyhow::Result<Vec<String>>;
    /// Every image a pod, Deployment or DaemonSet names.
    async fn images_in_use(&self) -> anyhow::Result<BTreeSet<String>>;
}

/// The unit's image store: content-addressed, collected by what is kept.
pub trait Registry: Send + Sync {
    /// Imports every image an OCI image layout holds, under the names its index gives.
    fn import(&self, layout: &Path) -> anyhow::Result<()>;
    /// Drops every image `keep` does not name, and whatever only they held.
    fn retain(&self, keep: &BTreeSet<String>) -> anyhow::Result<()>;
    /// Whether the store holds the image a ref names.
    fn holds(&self, image: &str) -> bool;
}

/// `namespace/name`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ref {
    pub namespace: String,
    pub name: String,
}

impl TryFrom<String> for Ref {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        match s.split_once('/') {
            Some((ns, name)) if !ns.is_empty() && !name.is_empty() && !name.contains('/') => {
                Ok(Self {
                    namespace: ns.into(),
                    name: name.into(),
                })
            }
            _ => Err(format!("{s:?} is not namespace/name")),
        }
    }
}

impl From<Ref> for String {
    fn from(r: Ref) -> String {
        format!("{}/{}", r.namespace, r.name)
    }
}

impl std::fmt::Display for Ref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// What the consumer supplies: the key, the node's paths and the stack's names.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// OpenSSH public key that signs bundles.
    pub signing_key: String,
    /// The `ssh-keygen -Y sign -n` namespace.
    pub signature_namespace: String,
    /// The node path of the store log copied before an update.
    pub store: String,
    /// The node path of boot-commit's record of the boot it blessed.
    pub bless: String,
    pub stack: Stack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stack {
    /// The OCI repository, on the unit, that serves stack artifacts.
    pub url: String,
    pub flux_instance: Ref,
    pub kustomization: Ref,
    pub source: Ref,
    /// The stack's own record: `built_epoch`, and what `LOCK_*` lines check.
    pub lock: Ref,
    /// The judge's record: `good`, `previous`, `trial` and `rolled_back`.
    pub judge: Ref,
}
