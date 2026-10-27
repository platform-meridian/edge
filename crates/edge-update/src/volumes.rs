//! The storage provisioner (ADR-0015, finding A): a PersistentVolumeClaim of a
//! StorageClass whose provisioner is [`PROVISIONER`] becomes a Talos user
//! volume, so an app only ever asks for a claim and never carries machine
//! config.
//!
//! A Kubernetes external provisioner, not a CSI driver: Talos itself
//! partitions, keys, formats and mounts a user volume at `/var/mnt/<name>`,
//! so there is nothing for a node plugin to do, and the kubelet mounts the
//! directory as a `local` PersistentVolume. The volume is named for the
//! claim's uid ([`Provisioned`]), and every merge of a new machine config
//! keeps it (`edge_bundle::machineconfig`), so an OS update never drops one.
//!
//! The machine config has one writer, the engine: this asks it, by
//! [`Command::Volume`], to add or remove a volume, and the engine refuses
//! while an update runs, so a claim then waits.
//!
//! For a claim on this node (the scheduler's `selected-node`, with
//! `WaitForFirstConsumer`; any, with `Immediate`):
//!
//! 1. the engine adds the volume, its size the request rounded up to MiB;
//! 2. once Talos reports it ready, the PersistentVolume is created, bound to
//!    the claim by `claimRef`, on this node alone.
//!
//! A volume released under `reclaimPolicy: Delete` (its PersistentVolume
//! holds [`FINALIZER`]) has its partition noted on the PersistentVolume, the
//! volume removed, then the partition wiped and dropped, then the
//! PersistentVolume deleted. Under `Retain` it stays, data and all.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use edge_bundle::machineconfig::Provisioned;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{
    LocalVolumeSource, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, ObjectReference,
    PersistentVolume, PersistentVolumeClaim, PersistentVolumeSpec, VolumeNodeAffinity,
};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, Resource, ResourceExt};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::api::Command;
use crate::engine::VolumeEdit;
use crate::unit::{Talos, VolumePhase};

/// The StorageClass `provisioner` this serves.
pub const PROVISIONER: &str = "edge.meridian/local";
/// Held by a PersistentVolume whose volume is deleted with it.
pub const FINALIZER: &str = "edge.meridian/local-volume";
/// The partition a released volume was on, noted before it is removed.
const PARTITION: &str = "edge.meridian/partition";
const STORAGE_PROVISIONER: &str = "volume.kubernetes.io/storage-provisioner";
const SELECTED_NODE: &str = "volume.kubernetes.io/selected-node";
const PROVISIONED_BY: &str = "pv.kubernetes.io/provisioned-by";
const MIB: u128 = 1 << 20;
const RESYNC: Duration = Duration::from_secs(30);

/// What a class of ours says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class {
    pub reclaim: Reclaim,
    /// `WaitForFirstConsumer`: only a claim the scheduler put on this node.
    pub wait_for_consumer: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reclaim {
    Retain,
    Delete,
}

impl Class {
    /// `None` for a class another provisioner serves.
    pub fn of(sc: &StorageClass) -> Option<Self> {
        (sc.provisioner == PROVISIONER).then(|| Self {
            reclaim: match sc.reclaim_policy.as_deref() {
                Some("Retain") => Reclaim::Retain,
                _ => Reclaim::Delete,
            },
            wait_for_consumer: sc.volume_binding_mode.as_deref() == Some("WaitForFirstConsumer"),
        })
    }
}

/// What a claim asks of this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// Not ours, not this node's, or bound already.
    Nothing,
    /// Ours, and one this provisioner cannot give: why.
    Refused(String),
    Volume {
        volume: Provisioned,
        mib: u64,
        class: String,
    },
}

/// What `claim` asks of the node `node`, given our classes.
pub fn wanted(
    claim: &PersistentVolumeClaim,
    classes: &BTreeMap<String, Class>,
    node: &str,
) -> Wanted {
    let (Some(spec), Some(uid)) = (&claim.spec, claim.metadata.uid.as_deref()) else {
        return Wanted::Nothing;
    };
    let Some((name, class)) = spec
        .storage_class_name
        .as_deref()
        .and_then(|n| classes.get(n).map(|c| (n, c)))
    else {
        return Wanted::Nothing;
    };
    let annotations = claim.annotations();
    let bound = spec.volume_name.as_deref().is_some_and(|v| !v.is_empty());
    let asked = annotations.get(STORAGE_PROVISIONER).map(String::as_str) == Some(PROVISIONER);
    let here = !class.wait_for_consumer
        || annotations.get(SELECTED_NODE).map(String::as_str) == Some(node);
    if bound || !asked || !here || claim.metadata.deletion_timestamp.is_some() {
        return Wanted::Nothing;
    }
    let refuse = |why: &str| Wanted::Refused(why.into());
    if spec
        .volume_mode
        .as_deref()
        .is_some_and(|m| m != "Filesystem")
    {
        return refuse("a raw block claim: only a filesystem is provisioned");
    }
    let modes = spec.access_modes.as_deref().unwrap_or_default();
    if modes.is_empty()
        || modes
            .iter()
            .any(|m| m != "ReadWriteOnce" && m != "ReadWriteOncePod")
    {
        return refuse("a volume on one node is ReadWriteOnce or ReadWriteOncePod alone");
    }
    if spec.data_source.is_some() || spec.data_source_ref.is_some() {
        return refuse("a claim from a data source: a volume is provisioned empty");
    }
    if spec.selector.is_some() {
        return refuse("a claim with a selector: a volume is provisioned, never chosen");
    }
    let Some(request) = spec
        .resources
        .as_ref()
        .and_then(|r| r.requests.as_ref())
        .and_then(|r| r.get("storage"))
    else {
        return refuse("no storage request");
    };
    match mib_of(request) {
        Ok(mib) => Wanted::Volume {
            volume: Provisioned::for_claim(uid),
            mib,
            class: name.into(),
        },
        Err(e) => Wanted::Refused(format!("{e:#}")),
    }
}

/// A quantity's bytes, rounded up to whole MiB.
pub fn mib_of(q: &Quantity) -> anyhow::Result<u64> {
    let s = q.0.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (number, suffix) = s.split_at(split);
    let unit: u128 = match suffix {
        "" => 1,
        "k" => 1000,
        "M" => 1000u128.pow(2),
        "G" => 1000u128.pow(3),
        "T" => 1000u128.pow(4),
        "P" => 1000u128.pow(5),
        "Ki" => 1 << 10,
        "Mi" => 1 << 20,
        "Gi" => 1 << 30,
        "Ti" => 1 << 40,
        "Pi" => 1 << 50,
        _ => bail!("{s:?} is not a size this reads"),
    };
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && frac.is_empty() {
        bail!("{s:?} is not a size");
    }
    let scale = 10u128.pow(u32::try_from(frac.len()).context("too many digits")?);
    let digits: u128 = format!("{whole}{frac}")
        .parse()
        .with_context(|| format!("{s:?} is not a size"))?;
    let bytes = (digits * unit).div_ceil(scale);
    let mib = u64::try_from(bytes.div_ceil(MIB)).context("too large")?;
    anyhow::ensure!(mib > 0, "{s:?} is no size");
    Ok(mib)
}

/// The PersistentVolume the claim binds: the volume's directory, on `node`.
pub fn persistent_volume(
    claim: &PersistentVolumeClaim,
    class_name: &str,
    class: Class,
    node: &str,
    volume: &Provisioned,
    mib: u64,
) -> PersistentVolume {
    let spec = claim.spec.clone().unwrap_or_default();
    PersistentVolume {
        metadata: ObjectMeta {
            name: Some(volume.name().into()),
            annotations: Some([(PROVISIONED_BY.to_string(), PROVISIONER.to_string())].into()),
            finalizers: (class.reclaim == Reclaim::Delete).then(|| vec![FINALIZER.to_string()]),
            ..ObjectMeta::default()
        },
        spec: Some(PersistentVolumeSpec {
            capacity: Some([("storage".to_string(), Quantity(format!("{mib}Mi")))].into()),
            access_modes: spec.access_modes,
            volume_mode: Some("Filesystem".into()),
            storage_class_name: Some(class_name.into()),
            persistent_volume_reclaim_policy: Some(
                match class.reclaim {
                    Reclaim::Retain => "Retain",
                    Reclaim::Delete => "Delete",
                }
                .into(),
            ),
            claim_ref: Some(ObjectReference {
                api_version: Some("v1".into()),
                kind: Some("PersistentVolumeClaim".into()),
                namespace: claim.namespace(),
                name: Some(claim.name_any()),
                uid: claim.metadata.uid.clone(),
                ..ObjectReference::default()
            }),
            local: Some(LocalVolumeSource {
                path: volume.path(),
                fs_type: None,
            }),
            node_affinity: Some(VolumeNodeAffinity {
                required: Some(NodeSelector {
                    node_selector_terms: vec![NodeSelectorTerm {
                        match_expressions: Some(vec![NodeSelectorRequirement {
                            key: "kubernetes.io/hostname".into(),
                            operator: "In".into(),
                            values: Some(vec![node.into()]),
                        }]),
                        match_fields: None,
                    }],
                }),
            }),
            ..PersistentVolumeSpec::default()
        }),
        status: None,
    }
}

/// What to do with a PersistentVolume of ours, as the cluster has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Release {
    Keep,
    /// Its volume goes: note its partition, then remove it.
    Remove(Provisioned),
    /// Its volume is gone: drop the noted partition, if any, then the object.
    Drop(Provisioned, Option<String>),
}

/// `present`: Talos still reports the volume.
pub fn release(pv: &PersistentVolume, present: bool) -> Release {
    let ours = pv.annotations().get(PROVISIONED_BY).map(String::as_str) == Some(PROVISIONER);
    let held = pv.finalizers().iter().any(|f| f == FINALIZER);
    let (Some(volume), true, true) = (Provisioned::parse(&pv.name_any()), ours, held) else {
        return Release::Keep;
    };
    let released = pv.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Released")
        || pv.metadata.deletion_timestamp.is_some();
    match (released, present) {
        (false, _) => Release::Keep,
        (true, true) => Release::Remove(volume),
        (true, false) => Release::Drop(volume, pv.annotations().get(PARTITION).cloned()),
    }
}

pub struct Provisioner {
    pub client: Client,
    pub node: String,
    pub talos: Arc<dyn Talos>,
    pub engine: mpsc::Sender<Command>,
}

impl Provisioner {
    /// Reconciles on every change to claims, volumes and classes, and every
    /// half-minute, for as long as the process runs.
    pub async fn run(self) {
        let changed = Arc::new(Notify::new());
        follow::<PersistentVolumeClaim>(&self.client, &changed);
        follow::<PersistentVolume>(&self.client, &changed);
        follow::<StorageClass>(&self.client, &changed);
        let recorder = Recorder::new(
            self.client.clone(),
            Reporter {
                controller: "edge-update".into(),
                instance: Some(self.node.clone()),
            },
        );
        loop {
            if let Err(e) = self.reconcile(&recorder).await {
                tracing::warn!(error = format!("{e:#}"), "provisioning");
            }
            let _ = tokio::time::timeout(RESYNC, changed.notified()).await;
        }
    }

    async fn reconcile(&self, recorder: &Recorder) -> anyhow::Result<()> {
        let lp = ListParams::default();
        let classes: BTreeMap<String, Class> = Api::<StorageClass>::all(self.client.clone())
            .list(&lp)
            .await?
            .into_iter()
            .filter_map(|sc| Class::of(&sc).map(|c| (sc.name_any(), c)))
            .collect();
        let pvs: Api<PersistentVolume> = Api::all(self.client.clone());
        let volumes = pvs.list(&lp).await?.items;
        let claims = Api::<PersistentVolumeClaim>::all(self.client.clone())
            .list(&lp)
            .await?;
        for claim in &claims {
            let r = match wanted(claim, &classes, &self.node) {
                Wanted::Nothing => continue,
                Wanted::Refused(why) => Err(anyhow::anyhow!(why)),
                Wanted::Volume { volume, mib, class } => {
                    if volumes.iter().any(|pv| pv.name_any() == volume.name()) {
                        continue;
                    }
                    self.provision(claim, &class, classes[&class], &volume, mib, &pvs)
                        .await
                }
            };
            if let Err(e) = r {
                let note = format!("{e:#}");
                tracing::warn!(claim = %at(claim), error = %note, "not provisioned");
                let ev = Event {
                    type_: EventType::Warning,
                    reason: "ProvisioningFailed".into(),
                    note: Some(note),
                    action: "Provision".into(),
                    secondary: None,
                };
                let _ = recorder.publish(&ev, &claim.object_ref(&())).await;
            }
        }
        for pv in &volumes {
            let present = match Provisioned::parse(&pv.name_any()) {
                Some(v) => self.talos.volume(v.name()).await?.is_some(),
                None => continue,
            };
            if let Err(e) = self.release(pv, present, &pvs).await {
                tracing::warn!(volume = %pv.name_any(), error = format!("{e:#}"), "not released");
            }
        }
        Ok(())
    }

    async fn provision(
        &self,
        claim: &PersistentVolumeClaim,
        class_name: &str,
        class: Class,
        volume: &Provisioned,
        mib: u64,
        pvs: &Api<PersistentVolume>,
    ) -> anyhow::Result<()> {
        self.edit(VolumeEdit::Add(volume.clone(), mib)).await?;
        match self.talos.volume(volume.name()).await?.map(|v| v.phase) {
            Some(VolumePhase::Ready) => {}
            Some(VolumePhase::Failed(why)) => {
                bail!("Talos could not make {}: {why}", volume.name())
            }
            Some(VolumePhase::Pending) | None => return Ok(()),
        }
        let pv = persistent_volume(claim, class_name, class, &self.node, volume, mib);
        pvs.create(&PostParams::default(), &pv).await?;
        tracing::info!(claim = %at(claim), volume = volume.name(), mib, "provisioned");
        Ok(())
    }

    async fn release(
        &self,
        pv: &PersistentVolume,
        present: bool,
        pvs: &Api<PersistentVolume>,
    ) -> anyhow::Result<()> {
        match release(pv, present) {
            Release::Keep => Ok(()),
            Release::Remove(v) => {
                if let Some(location) = self.talos.volume(v.name()).await?.map(|s| s.location)
                    && !location.is_empty()
                    && pv.annotations().get(PARTITION) != Some(&location)
                {
                    let note =
                        serde_json::json!({"metadata": {"annotations": {PARTITION: location}}});
                    pvs.patch(&pv.name_any(), &PatchParams::default(), &Patch::Merge(note))
                        .await?;
                }
                self.edit(VolumeEdit::Remove(v)).await
            }
            Release::Drop(v, partition) => {
                if let Some(p) = &partition {
                    self.talos.drop_partition(p).await?;
                }
                let finalizers: Vec<&String> =
                    pv.finalizers().iter().filter(|f| *f != FINALIZER).collect();
                let unheld = serde_json::json!({"metadata": {"finalizers": finalizers}});
                pvs.patch(
                    &pv.name_any(),
                    &PatchParams::default(),
                    &Patch::Merge(unheld),
                )
                .await?;
                if pv.metadata.deletion_timestamp.is_none() {
                    pvs.delete(&pv.name_any(), &DeleteParams::default()).await?;
                }
                tracing::info!(volume = v.name(), partition = ?partition, "released");
                Ok(())
            }
        }
    }

    async fn edit(&self, edit: VolumeEdit) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.engine
            .send(Command::Volume(edit, tx))
            .await
            .context("the engine has stopped")?;
        rx.await.context("the engine has stopped")?
    }
}

fn at(claim: &PersistentVolumeClaim) -> String {
    format!(
        "{}/{}",
        claim.namespace().unwrap_or_default(),
        claim.name_any()
    )
}

/// Notifies `changed` on every change to a `K`.
fn follow<K>(client: &Client, changed: &Arc<Notify>)
where
    K: Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + 'static,
{
    let api: Api<K> = Api::all(client.clone());
    let changed = changed.clone();
    tokio::spawn(async move {
        let mut events = watcher(api, watcher::Config::default())
            .default_backoff()
            .boxed();
        while let Some(e) = events.next().await {
            if e.is_ok() {
                changed.notify_one();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "unit-a";

    fn classes() -> BTreeMap<String, Class> {
        [(
            "edge-local".to_string(),
            Class {
                reclaim: Reclaim::Retain,
                wait_for_consumer: true,
            },
        )]
        .into()
    }

    fn claim(f: impl FnOnce(&mut serde_json::Value)) -> PersistentVolumeClaim {
        let mut v = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "fusion-data",
                "namespace": "meridian",
                "uid": "6a2f0c4e-8d5b-4f3a-9c1e-0b7d2e4f6a8c",
                "annotations": { STORAGE_PROVISIONER: PROVISIONER, SELECTED_NODE: NODE },
            },
            "spec": {
                "storageClassName": "edge-local",
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "4Gi" } },
            },
        });
        f(&mut v);
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn sizes_round_up_to_mib() {
        for (q, mib) in [
            ("4Gi", 4096),
            ("256Mi", 256),
            ("1", 1),
            ("1048577", 2),
            ("100M", 96),
            ("1.5Gi", 1536),
            ("2G", 1908),
            ("0.5Mi", 1),
        ] {
            assert_eq!(mib_of(&Quantity(q.into())).unwrap(), mib, "{q}");
        }
        for q in ["", "Gi", "1e9", "4GB", "0", "-1Gi"] {
            assert!(mib_of(&Quantity(q.into())).is_err(), "{q}");
        }
    }

    #[test]
    fn a_claim_on_this_node_of_our_class_is_a_volume_named_for_it() {
        let c = claim(|_| {});
        let Wanted::Volume { volume, mib, class } = wanted(&c, &classes(), NODE) else {
            panic!("{:?}", wanted(&c, &classes(), NODE));
        };
        assert_eq!(
            volume,
            Provisioned::for_claim("6a2f0c4e-8d5b-4f3a-9c1e-0b7d2e4f6a8c")
        );
        assert_eq!((mib, class.as_str()), (4096, "edge-local"));
    }

    #[test]
    fn a_claim_not_ours_or_not_here_or_bound_is_nothing() {
        for edit in [
            (|v: &mut serde_json::Value| v["spec"]["storageClassName"] = "other".into())
                as fn(&mut serde_json::Value),
            |v| {
                v["spec"]
                    .as_object_mut()
                    .unwrap()
                    .remove("storageClassName");
            },
            |v| v["metadata"]["annotations"][SELECTED_NODE] = "unit-b".into(),
            |v| {
                v["metadata"]["annotations"]
                    .as_object_mut()
                    .unwrap()
                    .remove(STORAGE_PROVISIONER);
            },
            |v| v["spec"]["volumeName"] = "pv-x".into(),
            |v| v["metadata"]["deletionTimestamp"] = "2026-10-27T00:00:00Z".into(),
        ] {
            assert_eq!(wanted(&claim(edit), &classes(), NODE), Wanted::Nothing);
        }
        let mut immediate = classes();
        immediate.get_mut("edge-local").unwrap().wait_for_consumer = false;
        let anywhere = claim(|v| {
            v["metadata"]["annotations"]
                .as_object_mut()
                .unwrap()
                .remove(SELECTED_NODE);
        });
        assert!(matches!(
            wanted(&anywhere, &immediate, NODE),
            Wanted::Volume { .. }
        ));
    }

    #[test]
    fn a_claim_a_local_volume_cannot_give_is_refused_by_name() {
        for (edit, why) in [
            (
                (|v: &mut serde_json::Value| v["spec"]["volumeMode"] = "Block".into())
                    as fn(&mut serde_json::Value),
                "raw block",
            ),
            (
                |v| v["spec"]["accessModes"] = serde_json::json!(["ReadWriteMany"]),
                "ReadWriteOnce",
            ),
            (
                |v| v["spec"]["accessModes"] = serde_json::json!([]),
                "ReadWriteOnce",
            ),
            (
                |v| {
                    v["spec"]["dataSource"] =
                        serde_json::json!({"kind": "PersistentVolumeClaim", "name": "x"})
                },
                "data source",
            ),
            (
                |v| v["spec"]["selector"] = serde_json::json!({}),
                "selector",
            ),
            (
                |v| v["spec"]["resources"] = serde_json::json!({}),
                "no storage request",
            ),
            (
                |v| v["spec"]["resources"]["requests"]["storage"] = "4GB".into(),
                "not a size",
            ),
        ] {
            match wanted(&claim(edit), &classes(), NODE) {
                Wanted::Refused(w) => assert!(w.contains(why), "{w}"),
                other => panic!("{why}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_persistent_volume_is_the_volumes_directory_on_this_node_bound_to_the_claim() {
        let c = claim(|_| {});
        let v = Provisioned::for_claim(c.metadata.uid.as_deref().unwrap());
        let class = classes()["edge-local"];
        let pv = persistent_volume(&c, "edge-local", class, NODE, &v, 4096);
        let j = serde_json::to_value(&pv).unwrap();
        assert_eq!(j["metadata"]["name"], v.name());
        assert_eq!(j["metadata"]["annotations"][PROVISIONED_BY], PROVISIONER);
        assert!(
            j["metadata"].get("finalizers").is_none(),
            "Retain holds nothing"
        );
        assert_eq!(j["spec"]["local"]["path"], v.path());
        assert_eq!(j["spec"]["capacity"]["storage"], "4096Mi");
        assert_eq!(j["spec"]["persistentVolumeReclaimPolicy"], "Retain");
        assert_eq!(
            j["spec"]["claimRef"]["uid"],
            c.metadata.uid.clone().unwrap()
        );
        assert_eq!(j["spec"]["claimRef"]["namespace"], "meridian");
        assert_eq!(
            j["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"]
                [0],
            NODE
        );
        let deleting = Class {
            reclaim: Reclaim::Delete,
            ..class
        };
        let pv = persistent_volume(&c, "edge-local", deleting, NODE, &v, 4096);
        assert_eq!(pv.finalizers(), [FINALIZER]);
        assert_eq!(release(&pv, true), Release::Keep, "bound");
    }

    #[test]
    fn a_released_volume_of_a_deleting_class_goes_then_its_partition() {
        let c = claim(|_| {});
        let v = Provisioned::for_claim(c.metadata.uid.as_deref().unwrap());
        let deleting = Class {
            reclaim: Reclaim::Delete,
            wait_for_consumer: true,
        };
        let mut pv = persistent_volume(&c, "edge-local", deleting, NODE, &v, 1);
        pv.status = Some(k8s_openapi::api::core::v1::PersistentVolumeStatus {
            phase: Some("Released".into()),
            ..Default::default()
        });
        assert_eq!(release(&pv, true), Release::Remove(v.clone()));
        assert_eq!(release(&pv, false), Release::Drop(v.clone(), None));
        pv.metadata
            .annotations
            .get_or_insert_default()
            .insert(PARTITION.into(), "/dev/sda7".into());
        assert_eq!(
            release(&pv, false),
            Release::Drop(v.clone(), Some("/dev/sda7".into()))
        );
        // Retained, or another's, it stays.
        pv.metadata.finalizers = None;
        assert_eq!(release(&pv, true), Release::Keep);
        let mut theirs = persistent_volume(&c, "edge-local", deleting, NODE, &v, 1);
        theirs.metadata.annotations = None;
        theirs.status = pv.status.clone();
        assert_eq!(release(&theirs, true), Release::Keep);
    }
}
