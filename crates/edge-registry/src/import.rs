use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::manifest::{Descriptor, Manifest};
use crate::{Digest, ImageRef, Store};

const NAME_ANNOTATIONS: [&str; 2] = [
    "io.containerd.image.name",
    "org.opencontainers.image.ref.name",
];

impl Store {
    /// Imports every image an OCI image layout holds and tags each from its
    /// index annotation, which must be a full reference such as
    /// `registry.k8s.io/pause:3.10`: a bare tag names no repository. An index
    /// may lack some of its platforms' manifests. Returns the images tagged.
    pub fn import_layout(&self, layout: &Path) -> anyhow::Result<Vec<ImageRef>> {
        let _lock = self.lock()?;
        let marker: serde_json::Value = serde_json::from_slice(
            &std::fs::read(layout.join("oci-layout")).context("reading oci-layout")?,
        )
        .context("parsing oci-layout")?;
        if !marker["imageLayoutVersion"].is_string() {
            bail!("oci-layout has no imageLayoutVersion");
        }
        let index = std::fs::read(layout.join("index.json")).context("reading index.json")?;
        let index = Manifest::parse(&index)
            .map_err(anyhow::Error::msg)
            .context("parsing index.json")?;
        let mut tagged = Vec::new();
        for desc in &index.children {
            self.import_manifest(layout, desc, true)?;
            let Some(name) = NAME_ANNOTATIONS
                .iter()
                .find_map(|a| desc.annotations.get(*a))
            else {
                continue;
            };
            let named = name
                .contains(['/', ':'])
                .then(|| name.parse::<ImageRef>().ok())
                .flatten();
            let Some(ImageRef {
                repo,
                tag: Some(tag),
                ..
            }) = named
            else {
                tracing::warn!(name, digest = %desc.digest, "not a tagged image reference; imported untagged");
                continue;
            };
            self.set_tag(&repo, &tag, &desc.digest)
                .with_context(|| format!("tagging {repo}:{tag}"))?;
            tagged.push(ImageRef {
                repo,
                tag: Some(tag),
                digest: Some(desc.digest.clone()),
            });
        }
        Ok(tagged)
    }

    fn import_manifest(
        &self,
        layout: &Path,
        desc: &Descriptor,
        required: bool,
    ) -> anyhow::Result<()> {
        let held = self.has_manifest(&desc.digest);
        let bytes = if held {
            self.manifest(&desc.digest)?
                .map(|(_, b)| b)
                .unwrap_or_default()
        } else {
            match std::fs::read(blob(layout, &desc.digest)) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("reading manifest {}", desc.digest));
                }
            }
        };
        let digest = Digest::of(&bytes);
        if digest != desc.digest || bytes.len() as u64 != desc.size {
            bail!(
                "manifest {} is {digest} ({} bytes), expected {} bytes",
                desc.digest,
                bytes.len(),
                desc.size
            );
        }
        let m = Manifest::parse(&bytes)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("parsing manifest {digest}"))?;
        for b in &m.blobs {
            if !self.has_blob(&b.digest) {
                let from = std::fs::File::open(blob(layout, &b.digest))
                    .with_context(|| format!("opening blob {}", b.digest))?;
                self.put_blob(b, from)
                    .with_context(|| format!("importing blob {}", b.digest))?;
            }
        }
        for child in &m.children {
            self.import_manifest(layout, child, false)?;
        }
        if !held {
            self.put_manifest(&digest, &bytes)
                .with_context(|| format!("importing manifest {digest}"))?;
        }
        Ok(())
    }
}

fn blob(layout: &Path, digest: &Digest) -> PathBuf {
    layout.join("blobs/sha256").join(digest.hex())
}
