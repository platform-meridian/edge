//! edge-registry's store, on the volume the registry serves from.

use std::collections::BTreeSet;
use std::path::Path;

use edge_registry::{ImageRef, Store};

pub struct Registry(Store);

impl Registry {
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        Ok(Self(Store::open(root)?))
    }
}

impl crate::unit::Registry for Registry {
    fn import(&self, layout: &Path) -> anyhow::Result<()> {
        let tagged = self.0.import_layout(layout)?;
        tracing::info!(images = tagged.len(), "imported the bundle's images");
        Ok(())
    }

    fn retain(&self, keep: &BTreeSet<String>) -> anyhow::Result<()> {
        let mut refs = Vec::new();
        for r in keep {
            // The import left a name it could not parse untagged: nothing to keep by it.
            match r.parse::<ImageRef>() {
                Ok(i) => refs.push(i),
                Err(e) => tracing::warn!(%r, error = %e, "not an image reference; not kept"),
            }
        }
        let swept = self.0.retain(&refs)?;
        tracing::info!(?swept, "collected what no kept release names");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::Registry as _;
    use sha2::{Digest, Sha256};

    /// A one-image layout named `name`, whose layer is `layer`.
    fn layout(dir: &Path, name: &str, layer: &[u8]) {
        let blobs = dir.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        let put = |b: &[u8]| {
            let h = hex::encode(Sha256::digest(b));
            std::fs::write(blobs.join(&h), b).unwrap();
            serde_json::json!({ "digest": format!("sha256:{h}"), "size": b.len() })
        };
        let mut config = put(b"{}");
        config["mediaType"] = "application/vnd.oci.image.config.v1+json".into();
        let mut l = put(layer);
        l["mediaType"] = "application/vnd.oci.image.layer.v1.tar+gzip".into();
        let m = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config,
            "layers": [l],
        })
        .to_string();
        let mut d = put(m.as_bytes());
        d["mediaType"] = "application/vnd.oci.image.manifest.v1+json".into();
        d["annotations"] = serde_json::json!({ "io.containerd.image.name": name });
        let index = serde_json::json!({ "schemaVersion": 2, "manifests": [d] });
        std::fs::write(dir.join("index.json"), index.to_string()).unwrap();
        std::fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    }

    fn held(root: &Path) -> Vec<String> {
        let mut v: Vec<_> = Store::open(root)
            .unwrap()
            .list()
            .unwrap()
            .images
            .iter()
            .map(|i| i.to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn releases_import_and_only_the_kept_ones_stay() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("store");
        let r = Registry::open(&root).unwrap();
        for (tag, layer) in [("t1", b"one".as_slice()), ("t2", b"two"), ("t3", b"three")] {
            let l = d.path().join(tag);
            layout(&l, &format!("127.0.0.1:5999/app:{tag}"), layer);
            r.import(&l).unwrap();
        }
        assert_eq!(held(&root).len(), 3);
        let keep = [
            "127.0.0.1:5999/app:t2",
            "127.0.0.1:5999/app:t3",
            "not a ref!",
        ]
        .map(String::from)
        .into();
        r.retain(&keep).unwrap();
        let held = held(&root);
        assert_eq!(held.len(), 2, "{held:?}");
        assert!(held.iter().all(|h| !h.contains(":t1")), "{held:?}");
        let blob = |b: &[u8]| {
            Store::open(&root)
                .unwrap()
                .blob_path(&edge_registry::Digest::of(b))
                .exists()
        };
        assert!(!blob(b"one") && blob(b"two"));
    }
}
