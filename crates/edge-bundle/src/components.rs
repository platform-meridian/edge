//! What a bundle brings, and what a unit has installed: a base and modules.
//!
//! A bundle brings the base or not, and any modules; it removes a module only
//! by naming it in `remove`. Installing it merges it into the unit's set: a
//! module it does not mention stays as it is, and without a base the unit
//! keeps its own. The stack a unit runs is its base's artifact with `modules/`
//! rewritten from the set, one file of Flux objects per module.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Manifest, machineconfig, oci};

pub const COMPONENTS: &str = "components.json";
/// The stack artifact's directory the unit's modules are written into.
pub const MODULES: &str = "modules";
/// MANIFEST keys the merge owns: the installed modules, and what a bundle removes.
pub const MODULES_KEY: &str = "MODULES";
pub const REMOVE_KEY: &str = "REMOVE";

const FLUX_CONTENT: &str = "application/vnd.cncf.flux.content.v1.tar+gzip";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    /// MANIFEST lines it adds while installed, such as its version.
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

/// A bundle's `components.json`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    /// The base's refs; `None` keeps the unit's base, installer included.
    pub base: Option<BTreeSet<String>>,
    #[serde(default)]
    pub modules: BTreeMap<String, Module>,
    #[serde(default)]
    pub remove: BTreeSet<String>,
}

fn module_name(n: &str) -> bool {
    !n.is_empty()
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Components {
    pub fn check(&self) -> anyhow::Result<()> {
        let mut keys = BTreeSet::new();
        for (name, m) in &self.modules {
            ensure!(module_name(name), "{name:?} is not a module name");
            ensure!(
                !self.remove.contains(name),
                "the bundle both brings and removes {name}"
            );
            ensure!(
                !m.flux.trim().is_empty(),
                "the {name} module has no objects"
            );
            machineconfig::check_part(&m.machine)
                .with_context(|| format!("the {name} module's machine config"))?;
            for k in m.manifest.keys() {
                ensure!(
                    ![MODULES_KEY, REMOVE_KEY].contains(&k.as_str()) && keys.insert(k.clone()),
                    "the {name} module's MANIFEST line {k} is another's"
                );
            }
        }
        for name in &self.remove {
            ensure!(module_name(name), "{name:?} is not a module name");
        }
        Ok(())
    }

    /// Every ref the bundle's components run.
    pub fn refs(&self) -> BTreeSet<String> {
        self.base
            .iter()
            .flatten()
            .chain(self.modules.values().flat_map(|m| &m.refs))
            .cloned()
            .collect()
    }

    /// An unpacked bundle's, if it says what it brings.
    pub fn read(dir: &Path) -> anyhow::Result<Option<Self>> {
        let p = dir.join(COMPONENTS);
        let text = match std::fs::read(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading the components"),
        };
        let c: Self = serde_json::from_slice(&text).context("the components are not JSON")?;
        c.check()?;
        Ok(Some(c))
    }

    /// The MANIFEST keys the bundle's modules bring.
    fn module_keys(&self) -> BTreeSet<&str> {
        self.modules
            .values()
            .flat_map(|m| m.manifest.keys())
            .map(String::as_str)
            .collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    /// The MANIFEST of the bundle that brought it, less its modules'.
    pub manifest: Manifest,
    /// Its machine config, less its modules'.
    pub patch: String,
    pub refs: BTreeSet<String>,
}

/// A unit's installed set.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub base: Base,
    pub modules: BTreeMap<String, Module>,
    /// The last bundle's, which a later one must exceed.
    pub built_epoch: i64,
}

impl Installed {
    /// `current` with a bundle installed: its `manifest` and, with a base, its
    /// config `patch`. Without `current`, the bundle must bring a base.
    pub fn after(
        current: Option<&Installed>,
        manifest: &Manifest,
        patch: Option<&str>,
        c: &Components,
    ) -> anyhow::Result<Self> {
        c.check()?;
        let base = match (&c.base, current) {
            (Some(refs), _) => {
                let patch = patch.context("the bundle brings a base without its config patch")?;
                let parts: Vec<&str> = c.modules.values().map(|m| m.machine.as_str()).collect();
                let theirs = c.module_keys();
                Base {
                    manifest: manifest
                        .iter()
                        .filter(|(k, _)| {
                            ![MODULES_KEY, REMOVE_KEY].contains(&k.as_str())
                                && !theirs.contains(k.as_str())
                        })
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    patch: machineconfig::without(patch, &parts)?,
                    refs: refs.clone(),
                }
            }
            (None, Some(cur)) => cur.base.clone(),
            (None, None) => bail!(
                "the bundle brings no base, and the unit's installed set is unknown: install a bundle with a base first"
            ),
        };
        let mut modules = current.map(|c| c.modules.clone()).unwrap_or_default();
        for name in &c.remove {
            modules.remove(name);
        }
        modules.extend(c.modules.clone());
        let epoch = manifest
            .get("BUILT_EPOCH")
            .and_then(|e| e.parse().ok())
            .context("the MANIFEST has no BUILT_EPOCH")?;
        let next = Self {
            base,
            modules,
            built_epoch: epoch,
        };
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

    /// What the set says of itself, as a release MANIFEST: the base's, the
    /// bundle's own lines over it, then the modules'.
    pub fn manifest(&self, bundle: &Manifest, c: &Components) -> Manifest {
        let theirs = c.module_keys();
        let mut m = self.base.manifest.clone();
        for (k, v) in bundle {
            if ![MODULES_KEY, REMOVE_KEY].contains(&k.as_str()) && !theirs.contains(k.as_str()) {
                m.insert(k.clone(), v.clone());
            }
        }
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

/// The stack's `modules/`: a kustomization of each module's objects, and with
/// `record` (namespace, name) a ConfigMap saying what is installed.
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
        let mut data = serde_yaml::Mapping::new();
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
            serde_yaml::to_string(&doc)?.into_bytes(),
        ));
    }
    let resources = if resources.is_empty() {
        "resources: []\n".to_string()
    } else {
        format!("resources:\n{resources}")
    };
    files.push((
        format!("{MODULES}/kustomization.yaml"),
        format!(
            "# The modules the unit runs, one file of Flux objects each.\n\
             apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n{resources}"
        )
        .into_bytes(),
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

    fn base_bundle() -> (Manifest, Components) {
        let mut m = bundle(1);
        m.insert("TALOS_VERSION".into(), "v1.14.1".into());
        m.insert("INSTALLER_REF".into(), "r/i:1@sha256:aa".into());
        let mut a = module("a", "sha256:1");
        a.machine = VOLUME.into();
        m.extend(a.manifest.clone());
        m.insert(MODULES_KEY.into(), "a".into());
        let c = Components {
            base: Some(["r/base:1".to_string()].into()),
            modules: [("a".to_string(), a)].into(),
            remove: BTreeSet::new(),
        };
        (m, c)
    }

    fn installed() -> Installed {
        let (m, c) = base_bundle();
        let patch = format!("{PATCH}---\n{VOLUME}");
        Installed::after(None, &m, Some(&patch), &c).unwrap()
    }

    #[test]
    fn a_base_is_its_bundle_less_its_modules() {
        let i = installed();
        assert_eq!(i.base.patch, PATCH);
        assert!(i.base.manifest.contains_key("TALOS_VERSION"));
        assert!(!i.base.manifest.contains_key("MODULE_A"));
        assert!(!i.base.manifest.contains_key(MODULES_KEY));
        assert_eq!(
            i.refs(),
            ["r/a:sha256:1", "r/base:1"].map(String::from).into()
        );
        assert!(i.patch().unwrap().contains("name: a-data"));
    }

    #[test]
    fn a_bundle_without_a_module_keeps_it_and_without_a_base_keeps_the_base() {
        let i = installed();
        let c = Components {
            base: None,
            modules: [("b".to_string(), module("b", "sha256:2"))].into(),
            remove: BTreeSet::new(),
        };
        let mut m = bundle(2);
        m.extend(c.modules["b"].manifest.clone());
        let next = Installed::after(Some(&i), &m, None, &c).unwrap();
        assert_eq!(next.base, i.base);
        assert_eq!(next.modules["a"], i.modules["a"]);
        assert!(next.modules.contains_key("b"));
        assert_eq!(next.built_epoch, 2);
        let mf = next.manifest(&m, &c);
        assert_eq!(mf[MODULES_KEY], "a b");
        assert_eq!(mf["INSTALLER_REF"], "r/i:1@sha256:aa");
        assert_eq!(mf["STACK_TAG"], "t2");
        assert_eq!(mf["MODULE_A"], "r/modules/a:1@sha256:1");
        assert!(next.patch().unwrap().contains("name: a-data"));
    }

    #[test]
    fn a_module_goes_only_when_a_bundle_removes_it() {
        let i = installed();
        let c = Components {
            base: None,
            modules: BTreeMap::new(),
            remove: ["a".to_string()].into(),
        };
        let mut m = bundle(2);
        m.insert(REMOVE_KEY.into(), "a".into());
        let next = Installed::after(Some(&i), &m, None, &c).unwrap();
        assert!(next.modules.is_empty());
        assert!(!next.refs().contains("r/a:sha256:1"));
        assert!(!next.patch().unwrap().contains("a-data"));
        let mf = next.manifest(&m, &c);
        assert!(!mf.contains_key("MODULE_A") && !mf.contains_key(MODULES_KEY));
        assert!(!mf.contains_key(REMOVE_KEY));
    }

    #[test]
    fn a_bundle_with_a_base_replaces_the_base_and_keeps_the_modules() {
        let i = installed();
        let mut m = bundle(3);
        m.insert("TALOS_VERSION".into(), "v1.15.0".into());
        let c = Components {
            base: Some(["r/base:2".to_string()].into()),
            ..Components::default()
        };
        let next = Installed::after(Some(&i), &m, Some(PATCH), &c).unwrap();
        assert_eq!(next.base.refs, ["r/base:2".to_string()].into());
        assert_eq!(next.base.manifest["TALOS_VERSION"], "v1.15.0");
        assert!(!next.base.manifest.contains_key("INSTALLER_REF"));
        assert_eq!(next.modules, i.modules);
    }

    #[test]
    fn without_a_set_a_bundle_must_bring_a_base() {
        let c = Components::default();
        let e = Installed::after(None, &bundle(1), None, &c).unwrap_err();
        assert!(
            format!("{e:#}").contains("install a bundle with a base"),
            "{e:#}"
        );
    }

    #[test]
    fn components_are_refused_when_they_contradict_themselves() {
        let mut c = Components {
            modules: [("a".to_string(), module("a", "sha256:1"))].into(),
            remove: ["a".to_string()].into(),
            ..Components::default()
        };
        assert!(c.check().is_err());
        c.remove.clear();
        c.modules.get_mut("a").unwrap().machine = "version: v1alpha1\n".into();
        assert!(c.check().is_err());
        c.modules.get_mut("a").unwrap().machine = VOLUME.into();
        c.check().unwrap();
        let mut b = module("b", "sha256:2");
        b.manifest = c.modules["a"].manifest.clone();
        c.modules.insert("b".into(), b);
        assert!(c.check().is_err());
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
            ("base/kustomization.yaml", "resources:\n  - ../modules\n"),
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
        assert!(tree["modules/kustomization.yaml"].contains("  - a.yaml\n"));
        let record: serde_yaml::Value =
            serde_yaml::from_str(&tree["modules/installed.yaml"]).unwrap();
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
        assert!(String::from_utf8_lossy(&files[0].1).contains("resources: []"));
    }
}
