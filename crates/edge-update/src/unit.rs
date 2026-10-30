//! What the engine drives: the node's Talos API, its cluster and the image
//! registry. Real clients and test fakes both implement these.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use edge_bundle::Policy;
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
    /// Pulls the installer and writes the new OS beside the running one. The
    /// installer's own failure is [`InstallerFailed`]; any other error is
    /// what it waits on.
    async fn install(&self, image: &str) -> anyhow::Result<()>;
    /// A power cycle: sd-boot counts the new OS's boots, and a kexec would bypass it.
    async fn reboot(&self) -> anyhow::Result<()>;
    /// Points sd-boot back at the previous OS and reboots into it.
    async fn rollback(&self) -> anyhow::Result<()>;
    async fn shutdown(&self) -> anyhow::Result<()>;
    /// The user volume `name`'s status; `None` while Talos has none.
    async fn volume(&self, name: &str) -> anyhow::Result<Option<Volume>>;
    /// Wipes the partition `device` (`/dev/sda7`), no volume using it, and
    /// drops it from its disk.
    async fn drop_partition(&self, device: &str) -> anyhow::Result<()>;
}

/// A user volume as Talos reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    pub phase: VolumePhase,
    /// Its raw partition, `/dev/<name>`.
    pub location: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VolumePhase {
    /// Located, provisioned or prepared, not yet mounted.
    Pending,
    /// Mounted at its path.
    Ready,
    /// Why Talos could not make it.
    Failed(String),
}

#[async_trait]
pub trait Cluster: Send + Sync {
    /// Deployments and DaemonSets anywhere with fewer ready than wanted, as
    /// [`crate::cluster::workload`] names them.
    async fn not_ready(&self) -> anyhow::Result<Vec<String>>;
    /// Every image a pod, Deployment or DaemonSet names.
    async fn images_in_use(&self) -> anyhow::Result<BTreeSet<String>>;
}

/// The unit's image store, content-addressed and shared: this engine's
/// releases are one of its writers, core's uploads another, so it collects only
/// what its own releases named.
pub trait Registry: Send + Sync {
    /// Imports every image an OCI image layout holds, under the names its index gives.
    fn import(&self, layout: &Path) -> anyhow::Result<()>;
    /// Imports an apps layout (`meridian-app export`), relocated under
    /// `host`, the store's own name, as core's uploads are.
    fn import_apps(&self, layout: &Path, host: &str) -> anyhow::Result<()>;
    /// Drops the images `drop` names, and whatever only they held; returns
    /// the bytes freed.
    fn forget(&self, drop: &BTreeSet<String>) -> anyhow::Result<u64>;
    /// The bytes [`Registry::forget`] would free.
    fn forgettable(&self, drop: &BTreeSet<String>) -> anyhow::Result<u64>;
    /// Bytes held, and free on its volume.
    fn usage(&self) -> anyhow::Result<(u64, u64)>;
    /// Bytes of a layout's blobs the store does not hold yet.
    fn missing(&self, layout: &Path) -> anyhow::Result<u64>;
    /// The digest the store holds a reference at.
    fn digest(&self, image: &str) -> Option<String>;
    /// A manifest or blob the store holds, by digest.
    fn read(&self, digest: &str) -> anyhow::Result<Vec<u8>>;
    /// A blob the store holds, by digest, to stream.
    fn open(&self, digest: &str) -> anyhow::Result<Box<dyn std::io::Read + Send>> {
        Ok(Box::new(std::io::Cursor::new(self.read(digest)?)))
    }
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

/// What the consumer supplies: who may sign, the node's paths and the store's name.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// Sigstore's `trusted_root.json`.
    pub trusted_root: PathBuf,
    pub trust_policy: Policy,
    /// The node path of the store log copied before an update.
    pub store: String,
    /// The node path of boot-commit's record of the boot it blessed.
    pub bless: String,
    /// The image store's own name, `host:port`: what an apps layout is
    /// relocated under.
    pub registry: String,
    /// The unit's own boot keys sign each new OS's boot files, at a boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_signing: Option<crate::boot::Settings>,
}

/// The installer ran and failed.
#[derive(Debug)]
pub struct InstallerFailed(pub String);

impl std::fmt::Display for InstallerFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the installer failed: {}", self.0)
    }
}

impl std::error::Error for InstallerFailed {}
