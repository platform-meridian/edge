//! Packs an app's `deploy/` and images into a bundle without a base that
//! brings one module (`edge-bundle`), staged for signing
//! ([`edge_bundle::stage`]). The manifests travel as a Flux OCI artifact,
//! their per-unit `${KEY}`s filled on the unit from:
//! - the node facts ([`NODE_FACTS`]), ConfigMap `flux-system/node-facts`;
//! - the declared `values`, ConfigMap `flux-system/module-<name>-values`;
//! - the declared `[secrets]`, Secret `flux-system/module-<name>`, which the
//!   [`SecretOwner`] generates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use edge_bundle::components::{Components, Module, Requires};
use edge_bundle::oci::NAME;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const FILE: &str = "module.toml";

/// What every unit's stack says of its node, as `${KEY}`.
pub const NODE_FACTS: [&str; 5] = [
    "OPERATOR_ADDR",
    "OPERATOR_DOMAIN",
    "CLUSTER_DNS",
    "APISERVER_HOST",
    "APISERVER_PORT",
];

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const FLUX_CONFIG: &str = "application/vnd.cncf.flux.config.v1+json";
const FLUX_CONTENT: &str = "application/vnd.cncf.flux.content.v1.tar+gzip";

/// `deploy/module.toml`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub name: String,
    #[serde(default)]
    pub requires: Requirements,
    /// Machine-config parts, relative to `deploy/`.
    #[serde(default)]
    pub machine: Vec<PathBuf>,
    /// `KEY = ref`, each pinned by digest when packed.
    #[serde(default)]
    pub images: BTreeMap<String, String>,
    /// `KEY = name`: the image name the manifests use.
    #[serde(default)]
    pub image_names: BTreeMap<String, String>,
    /// Per-unit secrets the manifests name as `${KEY}`, generated on the unit.
    #[serde(default)]
    pub secrets: BTreeMap<String, Mint>,
    /// Per-unit values the manifests name as `${KEY}`, set at install.
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirements {
    /// `>=vX.Y.Z`.
    pub talos: Option<String>,
    pub kubernetes: Option<String>,
    #[serde(default)]
    pub components: Vec<String>,
}

/// How a secret is generated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mint {
    /// 32 random bytes, hex.
    Hex32,
}

impl Mint {
    fn name(self) -> &'static str {
        match self {
            Self::Hex32 => "hex32",
        }
    }
}

/// What a pack takes besides `deploy/`.
pub struct Pack<'a> {
    pub deploy: &'a Path,
    /// OCI image layouts holding every image, by digest.
    pub layouts: &'a [PathBuf],
    /// `KEY = ref@digest` overriding `module.toml`'s.
    pub images: &'a BTreeMap<String, String>,
    pub version: &'a str,
    /// Anti-rollback: the unit refuses an older one.
    pub epoch: i64,
    /// The repository the module's manifests are published in, without a tag.
    pub artifact: &'a str,
    pub notes: Option<&'a str>,
    /// Required when the module declares secrets.
    pub secret_owner: Option<&'a SecretOwner>,
}

/// The ServiceAccount that generates declared secrets on the unit, from
/// ConfigMaps in its namespace that carry `label`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretOwner {
    pub namespace: String,
    pub service_account: String,
    pub label: (String, String),
}

fn env_key(k: &str) -> bool {
    !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl Spec {
    pub fn read(deploy: &Path) -> anyhow::Result<Self> {
        let p = deploy.join(FILE);
        let s: Self = toml::from_str(
            &std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?,
        )
        .with_context(|| format!("{} is not a module", p.display()))?;
        ensure!(
            !s.name.is_empty()
                && s.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "module name {:?} is not lower case, digits and dashes",
            s.name
        );
        for k in s.image_names.keys() {
            ensure!(
                s.images.contains_key(k),
                "image_names names {k}, which no image has"
            );
        }
        for k in s.secrets.keys().chain(&s.values) {
            ensure!(env_key(k), "{k} is not upper case, digits and underscores");
            ensure!(!NODE_FACTS.contains(&k.as_str()), "{k} is a node fact");
        }
        ensure!(
            s.values.iter().all(|v| !s.secrets.contains_key(v)),
            "a value is also a secret"
        );
        Ok(s)
    }

    fn requires(&self) -> anyhow::Result<Requires> {
        let r = &self.requires;
        Ok(Requires {
            talos: minimum(r.talos.as_deref())?,
            kubernetes: minimum(r.kubernetes.as_deref())?,
            flux: r.components.iter().cloned().collect(),
        })
    }
}

/// `>=vX.Y.Z` as the unit checks it.
fn minimum(bound: Option<&str>) -> anyhow::Result<String> {
    let Some(b) = bound else {
        return Ok(String::new());
    };
    let v = b
        .trim()
        .strip_prefix(">=")
        .map(str::trim)
        .filter(|v| !v.contains([',', '<', '>', ' ']))
        .with_context(|| format!("{b:?} is not one bound >=vX.Y.Z: a unit checks a minimum"))?;
    Ok(v.into())
}

/// Stages the app at `out`, which must not exist, for signing.
pub fn pack(p: &Pack, out: &Path) -> anyhow::Result<()> {
    let spec = Spec::read(p.deploy)?;
    ensure!(!p.version.is_empty(), "no version");
    ensure!(
        spec.secrets.is_empty() || p.secret_owner.is_some(),
        "the module declares secrets and no secret owner is given"
    );
    let mut images = spec.images.clone();
    for (k, r) in p.images {
        ensure!(
            images.insert(k.clone(), r.clone()).is_some(),
            "{k} is no image the module names"
        );
    }
    let scratch = tempfile::tempdir()?;
    let tree = scratch.path().join("module");
    stage_tree(p.deploy, &tree, &spec.machine)?;
    images_stanza(&images, &spec.image_names, &tree.join("kustomization.yaml"))?;
    placeholders(&tree, &spec)?;

    let layout = scratch.path().join("images");
    let blobs = layout.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    let mut index = Vec::new();
    let mut refs = BTreeSet::new();
    for r in images.values() {
        let (name, digest) = pinned(r)?;
        let desc = copy_image(p.layouts, digest, &blobs)
            .with_context(|| format!("{r} from the image layouts"))?;
        index.push(entry(desc, &name));
        refs.insert(name);
    }
    let artifact = format!("{}:{}", p.artifact, p.version);
    let (desc, digest) = flux_artifact(&tree, &blobs)?;
    index.push(entry(desc, &artifact));
    refs.insert(artifact.clone());
    std::fs::write(
        layout.join("index.json"),
        serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "manifests": index}))?,
    )?;
    std::fs::write(
        layout.join("oci-layout"),
        "{\"imageLayoutVersion\":\"1.0.0\"}\n",
    )?;

    let key = format!(
        "MODULE_{}",
        spec.name.to_ascii_uppercase().replace('-', "_")
    );
    let module = Module {
        version: p.version.into(),
        epoch: p.epoch,
        requires: spec.requires()?,
        manifest: [(key.clone(), format!("{artifact}@{digest}"))].into(),
        refs,
        flux: flux_objects(&spec, &artifact, &digest, p.secret_owner),
        machine: machine(p.deploy, &spec.machine)?,
    };
    let components = Components {
        modules: [(spec.name.clone(), module)].into(),
        ..Components::default()
    };
    let manifest = [
        (key, format!("{artifact}@{digest}")),
        (
            edge_bundle::components::MODULES_KEY.to_string(),
            spec.name.clone(),
        ),
    ]
    .into();
    edge_bundle::stage(
        &edge_bundle::Contents {
            manifest: &manifest,
            patch: None,
            seed: None,
            images: &layout,
            notes: p.notes,
            instance: None,
            components: &components,
        },
        out,
    )
}

/// `deploy/` without `module.toml` and its machine parts.
fn stage_tree(src: &Path, dst: &Path, machine: &[PathBuf]) -> anyhow::Result<()> {
    copy_tree(src, dst)?;
    std::fs::remove_file(dst.join(FILE))?;
    for part in machine {
        std::fs::remove_file(dst.join(part))
            .with_context(|| format!("the machine part {}", part.display()))?;
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let e = e?;
        let (from, to) = (e.path(), dst.join(e.file_name()));
        let kind = e.file_type()?;
        if kind.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            ensure!(kind.is_file(), "{} is not a regular file", from.display());
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            files(&p, out)?;
        } else {
            out.push(p);
        }
    }
    out.sort();
    Ok(())
}

/// The machine parts, one stream of documents.
fn machine(deploy: &Path, parts: &[PathBuf]) -> anyhow::Result<String> {
    let mut docs = Vec::new();
    for p in parts {
        let text = std::fs::read_to_string(deploy.join(p))
            .with_context(|| format!("the machine part {}", p.display()))?;
        docs.push(text.trim_end().to_string() + "\n");
    }
    Ok(docs.join("---\n"))
}

/// `repo:tag@sha256:…` as the layout names it, `repo:tag`, and its digest.
fn pinned(r: &str) -> anyhow::Result<(String, &str)> {
    let (name, digest) = r
        .split_once('@')
        .with_context(|| format!("{r} is not pinned by digest"))?;
    ensure!(
        digest
            .strip_prefix("sha256:")
            .is_some_and(|h| h.len() == 64),
        "{r} is not pinned by a sha256 digest"
    );
    let tagged = name.rsplit('/').next().is_some_and(|l| l.contains(':'));
    Ok((
        match tagged {
            true => name.to_string(),
            false => r.to_string(),
        },
        digest,
    ))
}

/// kustomize's `images:`, each named image pinned.
fn images_stanza(
    images: &BTreeMap<String, String>,
    names: &BTreeMap<String, String>,
    kfile: &Path,
) -> anyhow::Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    let mut text = std::fs::read_to_string(kfile).context("reading kustomization.yaml")?;
    ensure!(
        !text.lines().any(|l| l.starts_with("images:")),
        "{} has an images: stanza: the pack writes it",
        kfile.display()
    );
    text.push_str("images:\n");
    for (key, name) in names {
        let r = &images[key];
        let (named, digest) = pinned(r)?;
        let (repo, tag) = match named.rsplit_once(':') {
            Some((repo, tag)) if !tag.contains('/') && !named.contains('@') => (repo, Some(tag)),
            _ => (r.split('@').next().unwrap_or(r), None),
        };
        let _ = writeln!(text, "  - name: {name}\n    newName: {repo}");
        if let Some(t) = tag {
            let _ = writeln!(text, "    newTag: {t}");
        }
        let _ = writeln!(text, "    digest: {digest}");
    }
    std::fs::write(kfile, text)?;
    Ok(())
}

/// Every `${KEY}` is one the unit fills, every secret is used, and no build
/// token (`@KEY@`) is left.
fn placeholders(root: &Path, spec: &Spec) -> anyhow::Result<()> {
    let mut all = Vec::new();
    files(root, &mut all)?;
    let mut used = BTreeSet::new();
    for f in all
        .iter()
        .filter(|f| f.extension().is_some_and(|x| x == "yaml" || x == "in"))
    {
        for (i, line) in std::fs::read_to_string(f)?.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            let at = || format!("{}:{}", f.strip_prefix(root).unwrap_or(f).display(), i + 1);
            ensure!(
                !build_token(line),
                "{}: a build-time @KEY@: name it ${{KEY}}",
                at()
            );
            for key in line
                .split("${")
                .skip(1)
                .filter_map(|r| r.split_once('}').map(|(k, _)| k))
                .filter(|k| env_key(k))
            {
                ensure!(
                    NODE_FACTS.contains(&key)
                        || spec.values.iter().any(|v| v == key)
                        || spec.secrets.contains_key(key),
                    "{}: ${{{key}}} is no node fact, value or secret the module declares",
                    at()
                );
                used.insert(key.to_string());
            }
        }
    }
    let unused: Vec<&String> = spec
        .secrets
        .keys()
        .chain(&spec.values)
        .filter(|k| !used.contains(*k))
        .collect();
    ensure!(
        unused.is_empty(),
        "the module declares what its manifests never name: {unused:?}"
    );
    Ok(())
}

fn build_token(line: &str) -> bool {
    let b = line.as_bytes();
    (0..b.len()).any(|i| {
        b[i] == b'@' && {
            let n = b[i + 1..]
                .iter()
                .take_while(|&&x| x.is_ascii_uppercase() || x == b'_')
                .count();
            n > 0 && b.get(i + 1 + n) == Some(&b'@')
        }
    })
}

#[derive(Debug)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
}

fn entry(d: Descriptor, name: &str) -> serde_json::Value {
    serde_json::json!({
        "mediaType": d.media_type,
        "digest": d.digest,
        "size": d.size,
        "annotations": {NAME: name},
    })
}

fn blob_path(layout: &Path, digest: &str) -> anyhow::Result<PathBuf> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .with_context(|| format!("{digest} is not a sha256 digest"))?;
    Ok(layout.join("blobs/sha256").join(hex))
}

/// The image `digest` and everything it names, from whichever layout holds
/// it, into `blobs`.
fn copy_image(layouts: &[PathBuf], digest: &str, blobs: &Path) -> anyhow::Result<Descriptor> {
    let from = layouts
        .iter()
        .find(|l| blob_path(l, digest).is_ok_and(|p| p.exists()))
        .with_context(|| format!("no image layout holds {digest}"))?;
    let bytes = std::fs::read(blob_path(from, digest)?)?;
    ensure!(
        format!("sha256:{}", hex::encode(Sha256::digest(&bytes))) == digest,
        "the layout's {digest} does not hash to its name"
    );
    let m: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{digest} is not an image manifest or index"))?;
    let copy = |d: &str| -> anyhow::Result<()> {
        let src = blob_path(from, d)?;
        ensure!(src.exists(), "the layout lacks {d}");
        std::fs::copy(&src, blobs.join(d.trim_start_matches("sha256:")))?;
        Ok(())
    };
    for c in m["manifests"].as_array().into_iter().flatten() {
        let d = c["digest"]
            .as_str()
            .context("an index entry has no digest")?;
        copy_image(std::slice::from_ref(from), d, blobs)?;
    }
    for c in [&m["config"]]
        .into_iter()
        .chain(m["layers"].as_array().into_iter().flatten())
        .filter_map(|c| c["digest"].as_str())
    {
        copy(c)?;
    }
    std::fs::write(blobs.join(digest.trim_start_matches("sha256:")), &bytes)?;
    Ok(Descriptor {
        media_type: m["mediaType"].as_str().unwrap_or(OCI_MANIFEST).to_string(),
        digest: digest.into(),
        size: bytes.len() as u64,
    })
}

/// The staged tree as a Flux artifact, reproducibly.
fn flux_artifact(tree: &Path, blobs: &Path) -> anyhow::Result<(Descriptor, String)> {
    let mut all = Vec::new();
    files(tree, &mut all)?;
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for f in all {
        let data = std::fs::read(&f)?;
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        b.append_data(&mut h, f.strip_prefix(tree)?, data.as_slice())?;
    }
    let mut gz = b.into_inner()?;
    gz.flush()?;
    let layer = gz.finish()?;
    let put = |data: &[u8]| -> anyhow::Result<String> {
        let h = hex::encode(Sha256::digest(data));
        std::fs::write(blobs.join(&h), data)?;
        Ok(format!("sha256:{h}"))
    };
    let config = b"{}";
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": FLUX_CONFIG, "digest": put(config)?, "size": config.len()},
        "layers": [{"mediaType": FLUX_CONTENT, "digest": put(&layer)?, "size": layer.len()}],
    }))?;
    let digest = put(&manifest)?;
    Ok((
        Descriptor {
            media_type: OCI_MANIFEST.into(),
            digest: digest.clone(),
            size: manifest.len() as u64,
        },
        digest,
    ))
}

/// The module's OCIRepository on the unit's registry and the Kustomization
/// that applies it, retrying until its values and Secret exist.
pub fn flux_objects(
    spec: &Spec,
    artifact: &str,
    digest: &str,
    owner: Option<&SecretOwner>,
) -> String {
    let name = format!("module-{}", spec.name);
    let path = artifact.split_once('/').map_or(artifact, |(_, p)| p);
    let repo = path.rsplit_once(':').map_or(path, |(r, _)| r);
    let mut y = format!(
        "# The {module} module ({artifact}).\n\
         apiVersion: source.toolkit.fluxcd.io/v1\nkind: OCIRepository\n\
         metadata:\n  name: {name}\n  namespace: flux-system\n\
         spec:\n  interval: 10m\n  insecure: true\n  url: oci://127.0.0.1:5000/{repo}\n\
         \x20 ref:\n    digest: {digest}\n\
         ---\napiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n\
         metadata:\n  name: {name}\n  namespace: flux-system\n\
         spec:\n  interval: 10m\n  retryInterval: 2m\n  timeout: 5m\n  path: ./\n\
         \x20 prune: true\n  wait: true\n\
         \x20 sourceRef:\n    kind: OCIRepository\n    name: {name}\n\
         \x20 postBuild:\n    substituteFrom:\n      - kind: ConfigMap\n        name: node-facts\n",
        module = spec.name,
    );
    if !spec.values.is_empty() {
        let _ = writeln!(y, "      - kind: ConfigMap\n        name: {name}-values");
    }
    if let Some(owner) = owner.filter(|_| !spec.secrets.is_empty()) {
        let _ = writeln!(y, "      - kind: Secret\n        name: {name}");
        y.push_str(&generated_secret(&name, &spec.secrets, owner));
    }
    y
}

/// A declaration of Secret `flux-system/<name>` with `keys` for `owner`, and
/// its Role: create cannot be scoped by name, the rest is.
fn generated_secret(name: &str, keys: &BTreeMap<String, Mint>, owner: &SecretOwner) -> String {
    let declaration = format!("secrets-{name}");
    let SecretOwner {
        namespace,
        service_account,
        label: (lk, lv),
    } = owner;
    let mut by: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (k, m) in keys {
        by.entry(m.name()).or_default().push(k);
    }
    let lines: String = by
        .iter()
        .map(|(m, ks)| format!("  {m}: \"{}\"\n", ks.join(" ")))
        .collect();
    format!(
        "---\napiVersion: v1\nkind: ConfigMap\n\
         metadata:\n  name: {declaration}\n  namespace: {namespace}\n  \
         labels: {{ {lk}: \"{lv}\" }}\n\
         data:\n  namespace: flux-system\n  secret: {name}\n{lines}\
         ---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n\
         metadata:\n  name: {declaration}\n  namespace: flux-system\n\
         rules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    verbs: [\"create\"]\n\
         \x20 - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    resourceNames: [{name}]\n    \
         verbs: [\"get\", \"watch\", \"patch\"]\n\
         ---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n\
         metadata:\n  name: {declaration}\n  namespace: flux-system\n\
         roleRef: {{ apiGroup: rbac.authorization.k8s.io, kind: Role, name: {declaration} }}\n\
         subjects:\n  - {{ kind: ServiceAccount, name: {service_account}, namespace: {namespace} }}\n"
    )
}

#[cfg(test)]
mod tests;
