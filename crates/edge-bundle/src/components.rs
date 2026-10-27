//! What a bundle brings, and what a unit has installed.
//!
//! A bundle brings the base: the OS and the stack, nothing else. Apps are
//! `MeridianApp`s now. Until the appliance's switch-over (ADR-0015, phase 5)
//! a unit's stack still runs the modules it installed before, so its
//! installed set keeps them: a base update composes its stack with them,
//! as they are, `modules/` rewritten from the set, one file of Flux objects
//! per module, and their machine-config parts kept.
//!
//! Anti-rollback is the base's, by `BUILT_EPOCH`. The same base again is taken.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Manifest, machineconfig, oci};

pub const COMPONENTS: &str = "components.json";
/// The stack artifact's directory the unit's modules are written into.
pub const MODULES: &str = "modules";
/// The MANIFEST key naming the installed modules.
pub const MODULES_KEY: &str = "MODULES";

const FLUX_CONTENT: &str = "application/vnd.cncf.flux.content.v1.tar+gzip";

/// A module a unit installed before apps were `MeridianApp`s, as its
/// installed set records it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    #[serde(default)]
    pub version: String,
    pub epoch: i64,
    #[serde(default)]
    pub requires: Requires,
    /// MANIFEST lines it adds while installed.
    #[serde(default)]
    pub manifest: Manifest,
    /// Every ref it runs.
    #[serde(default)]
    pub refs: BTreeSet<String>,
    /// Its Flux objects, applied by the stack.
    pub flux: String,
    /// Machine-config documents it adds to the base's.
    #[serde(default)]
    pub machine: String,
}

/// What a module needs of the unit; empty needs nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requires {
    /// Minimum versions, `vX.Y.Z`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub talos: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kubernetes: String,
    /// As a FluxInstance's `spec.components` names them.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub flux: BTreeSet<String>,
}

/// A bundle's `components.json`: the base's refs, and nothing a bundle could
/// bring beside them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub base: BTreeSet<String>,
}

impl Components {
    /// Every ref the base runs.
    pub fn refs(&self) -> BTreeSet<String> {
        self.base.clone()
    }

    pub fn read(dir: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read(dir.join(COMPONENTS)).context("reading the components")?;
        serde_json::from_slice(&text)
            .context("the components are not a base's: a bundle brings the base alone")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    /// The MANIFEST of the bundle that brought it.
    pub manifest: Manifest,
    /// Its bundle's `BUILT_EPOCH`.
    pub epoch: i64,
    /// Its machine config.
    pub patch: String,
    pub refs: BTreeSet<String>,
}

/// A unit's installed set.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub base: Base,
    pub modules: BTreeMap<String, Module>,
}

impl Installed {
    /// `current` with the bundle's base installed, its modules kept as they are.
    pub fn after(
        current: Option<&Installed>,
        manifest: &Manifest,
        patch: &str,
        c: &Components,
    ) -> anyhow::Result<Self> {
        let epoch = manifest
            .get("BUILT_EPOCH")
            .and_then(|e| e.parse().ok())
            .context("the MANIFEST has no BUILT_EPOCH")?;
        let base = Base {
            epoch,
            manifest: manifest
                .iter()
                .filter(|(k, _)| k.as_str() != MODULES_KEY)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            patch: patch.to_string(),
            refs: c.base.clone(),
        };
        if let Some(cur) = current {
            not_older(
                "the unit's base",
                (cur.base.epoch, &cur.base),
                (base.epoch, &base),
            )?;
        }
        let modules = current.map(|c| c.modules.clone()).unwrap_or_default();
        let next = Self { base, modules };
        next.patch()?;
        Ok(next)
    }

    /// Every ref the set runs.
    pub fn refs(&self) -> BTreeSet<String> {
        self.base
            .refs
            .iter()
            .chain(self.modules.values().flat_map(|m| &m.refs))
            .cloned()
            .collect()
    }

    /// The machine config the set runs: the base's, then each module's.
    pub fn patch(&self) -> anyhow::Result<String> {
        let mut all = vec![self.base.patch.as_str()];
        all.extend(self.modules.values().map(|m| m.machine.as_str()));
        machineconfig::join(&all)
    }

    /// What the set says of itself, as a release MANIFEST: the base's, then
    /// the modules'.
    pub fn manifest(&self) -> Manifest {
        let mut m = self.base.manifest.clone();
        for module in self.modules.values() {
            m.extend(module.manifest.clone());
        }
        if !self.modules.is_empty() {
            let names: Vec<&str> = self.modules.keys().map(String::as_str).collect();
            m.insert(MODULES_KEY.into(), names.join(" "));
        }
        m
    }
}

/// A part is newer than the one installed, or that one again.
fn not_older<T: PartialEq>(
    what: &str,
    (was, old): (i64, &T),
    (now, new): (i64, &T),
) -> anyhow::Result<()> {
    ensure!(
        now > was || (now == was && old == new),
        "REFUSING A DOWNGRADE: {what} is version {was} and the bundle's is {now}"
    );
    Ok(())
}

/// The stack's `modules/`, a kustomize Component the stack includes: each
/// module's objects, and with `record` (namespace, name) a ConfigMap saying
/// what is installed.
pub fn modules_dir(
    modules: &BTreeMap<String, Module>,
    record: Option<(&str, &str)>,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    let mut resources = String::new();
    for (name, m) in modules {
        resources.push_str(&format!("  - {name}.yaml\n"));
        files.push((
            format!("{MODULES}/{name}.yaml"),
            m.flux.clone().into_bytes(),
        ));
    }
    if let Some((ns, cm)) = record {
        resources.push_str("  - installed.yaml\n");
        let mut data = serde_json::Map::new();
        let names: Vec<&str> = modules.keys().map(String::as_str).collect();
        data.insert(MODULES_KEY.into(), names.join(" ").into());
        for m in modules.values() {
            for (k, v) in &m.manifest {
                data.insert(k.as_str().into(), v.as_str().into());
            }
        }
        let flux: Vec<&str> = modules.values().map(|m| m.flux.trim_end()).collect();
        data.insert("modules.yaml".into(), (flux.join("\n---\n") + "\n").into());
        let doc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": cm, "namespace": ns},
            "data": data,
        });
        files.push((
            format!("{MODULES}/installed.yaml"),
            serde_saphyr::to_string(&doc)?.into_bytes(),
        ));
    }
    let resources = if resources.is_empty() {
        "resources: []\n".to_string()
    } else {
        format!("resources:\n{resources}")
    };
    let kustomization = format!(
        "# The modules the unit runs, one file of Flux objects each.\n\
         apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\n{resources}"
    );
    files.push((
        format!("{MODULES}/kustomization.yaml"),
        kustomization.into_bytes(),
    ));
    files.sort();
    Ok(files)
}

fn in_modules(path: &Path) -> bool {
    let rel = path.strip_prefix(".").unwrap_or(path);
    rel.starts_with(MODULES)
}

/// A Flux artifact's content (`tar+gzip`) with `modules/` replaced by `files`.
pub fn compose_layer(layer: &[u8], files: &[(String, Vec<u8>)]) -> anyhow::Result<Vec<u8>> {
    let gz = flate2::read::GzDecoder::new(layer);
    let mut archive = tar::Archive::new(gz);
    let out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut b = tar::Builder::new(out);
    for e in archive
        .entries()
        .context("the stack artifact is not a tar")?
    {
        let mut e = e?;
        let path = e.path()?.into_owned();
        if in_modules(&path) {
            continue;
        }
        let mut h = e.header().clone();
        let mut data = Vec::new();
        e.read_to_end(&mut data)?;
        b.append_data(&mut h, &path, data.as_slice())?;
    }
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_mode(0o755);
    dir.set_size(0);
    b.append_data(&mut dir, format!("{MODULES}/"), std::io::empty())?;
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o644);
        h.set_size(data.len() as u64);
        b.append_data(&mut h, name, data.as_slice())?;
    }
    let mut gz = b.into_inner()?;
    gz.flush()?;
    Ok(gz.finish()?)
}

/// The Flux artifact `base` (a manifest digest `read` finds, with its blobs)
/// with `modules/` replaced by `files`, laid out at `layout` as `name`; its digest.
pub fn compose(
    read: impl Fn(&str) -> anyhow::Result<Vec<u8>>,
    base: &str,
    files: &[(String, Vec<u8>)],
    layout: &Path,
    name: &str,
) -> anyhow::Result<String> {
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &read(base).with_context(|| format!("reading the stack artifact {base}"))?,
    )
    .context("the stack artifact's manifest is not JSON")?;
    let layers = manifest["layers"]
        .as_array_mut()
        .context("the stack artifact has no layers")?;
    ensure!(
        layers.len() == 1 && layers[0]["mediaType"] == FLUX_CONTENT,
        "the stack artifact is not one Flux content layer"
    );
    let from = layers[0]["digest"]
        .as_str()
        .context("the stack artifact's layer has no digest")?
        .to_string();
    let layer = compose_layer(&read(&from)?, files)?;
    let blobs = layout.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    let put = |data: &[u8]| -> anyhow::Result<String> {
        let h = hex::encode(Sha256::digest(data));
        std::fs::write(blobs.join(&h), data)?;
        Ok(format!("sha256:{h}"))
    };
    layers[0]["digest"] = put(&layer)?.into();
    layers[0]["size"] = layer.len().into();
    if let Some(config) = manifest["config"]["digest"].as_str() {
        put(&read(config)?)?;
    }
    let bytes = serde_json::to_vec(&manifest)?;
    let digest = put(&bytes)?;
    let index = serde_json::json!({"schemaVersion": 2, "manifests": [{
        "mediaType": manifest["mediaType"].as_str().unwrap_or("application/vnd.oci.image.manifest.v1+json"),
        "digest": digest,
        "size": bytes.len(),
        "annotations": {oci::NAME: name},
    }]});
    std::fs::write(layout.join("index.json"), serde_json::to_vec(&index)?)?;
    std::fs::write(
        layout.join("oci-layout"),
        "{\"imageLayoutVersion\":\"1.0.0\"}\n",
    )?;
    Ok(digest)
}

/// A blob or manifest an OCI image layout holds, by digest.
pub fn layout_blob(layout: &Path, digest: &str) -> anyhow::Result<Vec<u8>> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .with_context(|| format!("{digest} is not a sha256 digest"))?;
    std::fs::read(layout.join("blobs/sha256").join(hex))
        .with_context(|| format!("the layout holds no {digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATCH: &str = "version: v1alpha1\nmachine:\n  type: init\n";
    const VOLUME: &str = "apiVersion: v1alpha1\nkind: UserVolumeConfig\nname: a-data\n";

    fn module(name: &str, digest: &str) -> Module {
        Module {
            version: "v1".into(),
            epoch: 1,
            requires: Requires::default(),
            manifest: [(
                format!("MODULE_{}", name.to_uppercase()),
                format!("r/modules/{name}:1@{digest}"),
            )]
            .into(),
            refs: [format!("r/{name}:{digest}")].into(),
            flux: format!("kind: Kustomization\nmetadata: {{name: module-{name}}}\n"),
            machine: String::new(),
        }
    }

    fn bundle(epoch: i64) -> Manifest {
        [
            ("STACK_TAG".to_string(), format!("t{epoch}")),
            ("BUILT_EPOCH".to_string(), epoch.to_string()),
        ]
        .into()
    }

    fn base_bundle(epoch: i64) -> (Manifest, Components) {
        let mut m = bundle(epoch);
        m.insert("TALOS_VERSION".into(), "v1.14.1".into());
        m.insert("INSTALLER_REF".into(), "r/i:1@sha256:aa".into());
        let c = Components {
            base: [format!("r/base:{epoch}")].into(),
        };
        (m, c)
    }

    /// A set a unit installed before apps were MeridianApps: a base and the module `a`.
    fn installed() -> Installed {
        let (m, c) = base_bundle(1);
        let mut i = Installed::after(None, &m, PATCH, &c).unwrap();
        let mut a = module("a", "sha256:1");
        a.machine = VOLUME.into();
        i.modules.insert("a".into(), a);
        i
    }

    #[test]
    fn a_base_is_its_bundle() {
        let (mut m, c) = base_bundle(1);
        m.insert(MODULES_KEY.into(), "stale".into());
        let i = Installed::after(None, &m, PATCH, &c).unwrap();
        assert_eq!(i.base.patch, PATCH);
        assert!(i.base.manifest.contains_key("TALOS_VERSION"));
        assert!(!i.base.manifest.contains_key(MODULES_KEY));
        assert!(i.modules.is_empty());
        assert_eq!(i.refs(), c.base);
    }

    #[test]
    fn a_new_base_keeps_the_modules_the_unit_runs_as_they_are() {
        let i = installed();
        let (mut m, c) = base_bundle(2);
        m.insert("TALOS_VERSION".into(), "v1.15.0".into());
        let next = Installed::after(Some(&i), &m, PATCH, &c).unwrap();
        assert_eq!(next.base.refs, c.base);
        assert_eq!(next.base.manifest["TALOS_VERSION"], "v1.15.0");
        assert_eq!(next.modules, i.modules);
        assert!(next.refs().contains("r/a:sha256:1"));
        assert!(next.patch().unwrap().contains("name: a-data"));
        let mf = next.manifest();
        assert_eq!(mf[MODULES_KEY], "a");
        assert_eq!(mf["MODULE_A"], "r/modules/a:1@sha256:1");
        assert_eq!(mf["STACK_TAG"], "t2");
    }

    #[test]
    fn an_older_base_is_refused_and_the_same_one_taken() {
        let i = installed();
        let (m, c) = base_bundle(1);
        Installed::after(Some(&i), &m, PATCH, &c).unwrap();
        let (older, c0) = base_bundle(0);
        let e = Installed::after(Some(&i), &older, PATCH, &c0).unwrap_err();
        assert!(
            format!("{e:#}").contains("the unit's base is version 1"),
            "{e:#}"
        );
    }

    #[test]
    fn components_bringing_more_than_a_base_are_refused() {
        let d = tempfile::tempdir().unwrap();
        for json in [
            r#"{"base": [], "modules": {}}"#,
            r#"{"base": [], "remove": ["a"]}"#,
            r#"{"modules": {}}"#,
        ] {
            std::fs::write(d.path().join(COMPONENTS), json).unwrap();
            assert!(Components::read(d.path()).is_err(), "{json}");
        }
        std::fs::write(d.path().join(COMPONENTS), r#"{"base": ["r/a:1"]}"#).unwrap();
        assert_eq!(Components::read(d.path()).unwrap().refs().len(), 1);
    }

    fn tgz(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, name, body.as_bytes()).unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&b.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    }

    fn untgz(data: &[u8]) -> BTreeMap<String, String> {
        let mut a = tar::Archive::new(flate2::read::GzDecoder::new(data));
        let mut out = BTreeMap::new();
        for e in a.entries().unwrap() {
            let mut e = e.unwrap();
            if !e.header().entry_type().is_file() {
                continue;
            }
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            out.insert(e.path().unwrap().display().to_string(), s);
        }
        out
    }

    #[test]
    fn the_stack_is_its_base_with_the_sets_modules() {
        let d = tempfile::tempdir().unwrap();
        let layer = tgz(&[
            ("base/kustomization.yaml", "components:\n  - ../modules\n"),
            ("./modules/old.yaml", "old"),
            ("modules/kustomization.yaml", "old"),
        ]);
        let config = b"{}".to_vec();
        let h = |b: &[u8]| format!("sha256:{}", hex::encode(Sha256::digest(b)));
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.cncf.flux.config.v1+json", "digest": h(&config), "size": 2},
            "layers": [{"mediaType": FLUX_CONTENT, "digest": h(&layer), "size": layer.len()}],
        });
        let mbytes = serde_json::to_vec(&manifest).unwrap();
        let blobs: BTreeMap<String, Vec<u8>> = [
            (h(&layer), layer),
            (h(&config), config),
            (h(&mbytes), mbytes.clone()),
        ]
        .into();
        let read = |d: &str| blobs.get(d).cloned().context("no such blob");
        let i = installed();
        let files = modules_dir(&i.modules, Some(("flux-system", "installed"))).unwrap();
        let out = d.path().join("out");
        let digest = compose(read, &h(&mbytes), &files, &out, "r/stack:t2").unwrap();
        assert_eq!(oci::layout_images(&out).unwrap()["r/stack:t2"], digest);
        let m: serde_json::Value =
            serde_json::from_slice(&layout_blob(&out, &digest).unwrap()).unwrap();
        let tree = untgz(&layout_blob(&out, m["layers"][0]["digest"].as_str().unwrap()).unwrap());
        assert_eq!(
            tree.keys().collect::<Vec<_>>(),
            [
                "base/kustomization.yaml",
                "modules/a.yaml",
                "modules/installed.yaml",
                "modules/kustomization.yaml"
            ]
        );
        let k: serde_json::Value =
            serde_saphyr::from_str(&tree["modules/kustomization.yaml"]).unwrap();
        assert_eq!(k["kind"], "Component");
        assert_eq!(k["resources"][0], "a.yaml");
        assert!(
            k.get("patches").is_none(),
            "a module patches nothing of edge's"
        );
        let record: serde_json::Value =
            serde_saphyr::from_str(&tree["modules/installed.yaml"]).unwrap();
        assert_eq!(record["metadata"]["name"], "installed");
        assert_eq!(record["data"]["MODULE_A"], "r/modules/a:1@sha256:1");
        assert_eq!(record["data"][MODULES_KEY], "a");
        assert!(layout_blob(&out, manifest["config"]["digest"].as_str().unwrap()).is_ok());
        let again = compose(
            |d: &str| blobs.get(d).cloned().context("no such blob"),
            &h(&mbytes),
            &files,
            &d.path().join("again"),
            "r/stack:t2",
        )
        .unwrap();
        assert_eq!(again, digest, "the same set composes the same stack");
    }

    #[test]
    fn no_modules_is_an_empty_kustomization() {
        let files = modules_dir(&BTreeMap::new(), None).unwrap();
        assert_eq!(files.len(), 1);
        let k = String::from_utf8_lossy(&files[0].1);
        assert!(k.contains("resources: []") && !k.contains("patches"), "{k}");
    }
}
