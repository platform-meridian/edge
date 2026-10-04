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

    fn retain(&self, keep: &BTreeSet<String>) -> anyhow::Result<u64> {
        let swept = self.0.retain(&refs(keep))?;
        tracing::info!(?swept, "collected what no kept release names");
        Ok(swept.bytes)
    }

    fn reclaimable(&self, keep: &BTreeSet<String>) -> anyhow::Result<u64> {
        Ok(self.0.reclaimable(&refs(keep))?.bytes)
    }

    fn usage(&self) -> anyhow::Result<(u64, u64)> {
        let held = self.0.list()?.bytes;
        let s = nix::sys::statvfs::statvfs(self.0.root())?;
        Ok((held, s.blocks_available() * s.fragment_size()))
    }

    fn missing(&self, layout: &Path) -> anyhow::Result<u64> {
        let mut bytes = 0;
        for e in std::fs::read_dir(layout.join("blobs/sha256"))? {
            let e = e?;
            // A manifest the store keeps apart from its blobs.
            let held = edge_registry::Digest::from_hex(&e.file_name().to_string_lossy())
                .is_some_and(|d| {
                    self.0.blob_path(&d).is_file() || matches!(self.0.manifest(&d), Ok(Some(_)))
                });
            if !held {
                bytes += e.metadata()?.len();
            }
        }
        Ok(bytes)
    }

    fn digest(&self, image: &str) -> Option<String> {
        let r = image.parse::<ImageRef>().ok()?;
        let reference = r.digest.map(|d| d.to_string()).or(r.tag)?;
        self.0.resolve(&r.repo, &reference).map(|d| d.to_string())
    }

    fn read(&self, digest: &str) -> anyhow::Result<Vec<u8>> {
        let d: edge_registry::Digest = digest
            .parse()
            .map_err(|e: String| anyhow::anyhow!("{digest}: {e}"))?;
        if let Some((_, bytes)) = self.0.manifest(&d)? {
            return Ok(bytes);
        }
        std::fs::read(self.0.blob_path(&d))
            .map_err(|e| anyhow::anyhow!("the store holds no {digest}: {e}"))
    }
}

/// The import left a name it could not parse untagged: nothing to keep by it.
fn refs(keep: &BTreeSet<String>) -> Vec<ImageRef> {
    keep.iter()
        .filter_map(|r| match r.parse::<ImageRef>() {
            Ok(i) => Some(i),
            Err(e) => {
                tracing::warn!(%r, error = %e, "not an image reference; not kept");
                None
            }
        })
        .collect()
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
        let (bytes, free) = r.usage().unwrap();
        assert!(bytes > 0 && free > 0);
        assert_eq!(
            r.digest("127.0.0.1:5999/app:t2")
                .as_deref()
                .map(|d| d.starts_with("sha256:")),
            Some(true)
        );
        assert_eq!(r.digest("127.0.0.1:5999/app:gone"), None);
        let again = d.path().join("t2");
        assert_eq!(r.missing(&again).unwrap(), 0);
        let fresh = d.path().join("t4");
        layout(&fresh, "127.0.0.1:5999/app:t4", b"four");
        let blobs: Vec<_> = std::fs::read_dir(fresh.join("blobs/sha256"))
            .unwrap()
            .flatten()
            .map(|e| e.metadata().unwrap().len())
            .collect();
        // Its empty config the store holds already.
        assert_eq!(r.missing(&fresh).unwrap(), blobs.iter().sum::<u64>() - 2);
        let keep = [
            "127.0.0.1:5999/app:t2",
            "127.0.0.1:5999/app:t3",
            "not a ref!",
        ]
        .map(String::from)
        .into();
        let would = r.reclaimable(&keep).unwrap();
        assert!(would > 0);
        assert_eq!(r.retain(&keep).unwrap(), would);
        let held = held(&root);
        assert_eq!(held.len(), 2, "{held:?}");
        assert!(held.iter().all(|h| !h.contains(":t1")), "{held:?}");
        assert!(r.digest("127.0.0.1:5999/app:t2").is_some());
        assert!(r.digest("127.0.0.1:5999/app:t1").is_none());
        assert!(r.digest("127.0.0.1:5999/other:t2").is_none());
        assert!(r.digest("not a ref!").is_none());
        let blob = |b: &[u8]| {
            Store::open(&root)
                .unwrap()
                .blob_path(&edge_registry::Digest::of(b))
                .exists()
        };
        assert!(!blob(b"one") && blob(b"two"));
    }
}
