//! Layer indexes kept between runs; a blob is content-addressed, so its index is valid
//! while the blob exists.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::blobs::Blobs;
use crate::layers::{Entry, Layer};

/// Bumped whenever indexing changes what it records.
const FORMAT: u64 = 2;
const SUFFIX: &str = ".json";

pub struct IndexCache {
    dir: PathBuf,
    write: bool,
}

impl IndexCache {
    pub fn new(dir: PathBuf, write: bool) -> Self {
        IndexCache { dir, write }
    }

    fn entry(&self, digest: &str) -> PathBuf {
        self.dir.join(format!("{digest}{SUFFIX}"))
    }

    pub fn load(&self, digest: &str) -> Option<Layer> {
        let v: Value = serde_json::from_slice(&std::fs::read(self.entry(digest)).ok()?).ok()?;
        if v.get("format")?.as_u64()? != FORMAT || v.get("digest")?.as_str()? != digest {
            return None;
        }
        let files = v
            .get("files")?
            .as_object()?
            .iter()
            .map(|(p, s)| Some((p.clone(), Entry { size: s.as_u64()? })))
            .collect::<Option<HashMap<_, _>>>()?;
        let links = v
            .get("links")?
            .as_object()?
            .iter()
            .map(|(p, t)| Some((p.clone(), t.as_str()?.to_string())))
            .collect::<Option<BTreeMap<_, _>>>()?;
        Some(Layer {
            digest: digest.to_string(),
            files,
            links,
        })
    }

    pub fn store(&self, l: &Layer) {
        if !self.write {
            return;
        }
        let files: Map<String, Value> = l
            .files
            .iter()
            .map(|(p, e)| (p.clone(), json!(e.size)))
            .collect();
        let v = json!({ "format": FORMAT, "digest": l.digest, "files": files, "links": l.links });
        let r = std::fs::create_dir_all(&self.dir).and_then(|()| {
            edge_common::durable_write(&self.entry(&l.digest), v.to_string().as_bytes())
        });
        if let Err(e) = r {
            tracing::warn!(dir = %self.dir.display(), error = %e, "could not cache a layer index; the next run rebuilds it");
        }
    }

    pub fn prune(&self, blobs: &Blobs) {
        if !self.write {
            return;
        }
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let live = name.strip_suffix(SUFFIX).is_some_and(|d| blobs.exists(d));
            if !live && let Err(err) = std::fs::remove_file(e.path()) {
                tracing::warn!(path = %e.path().display(), error = %err, "could not prune a cached layer index");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::layer_blob;

    /// (tempdir, cache dir, blob dir, the index of blob `aa11` plus a link).
    fn store_with_blob() -> (tempfile::TempDir, PathBuf, PathBuf, Layer) {
        let d = tempfile::tempdir().unwrap();
        let blobs = d.path().join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join("aa11"), layer_blob(&[("./bin/tool", b"12345")])).unwrap();
        let mut l = crate::layers::index_blob(&blobs.join("aa11"), "aa11").unwrap();
        l.links.insert("bin/alias".into(), "bin/tool".into());
        let dir = d.path().join("cache");
        (d, dir, blobs, l)
    }

    #[test]
    fn entry_round_trips_verify_never_writes() {
        let (_d, dir, _blobs, l) = store_with_blob();
        IndexCache::new(dir.clone(), false).store(&l);
        assert!(!dir.exists());

        let c = IndexCache::new(dir, true);
        c.store(&l);
        let back = c.load("aa11").unwrap();
        assert_eq!(back.digest, "aa11");
        assert_eq!(back.files, l.files);
        assert_eq!(back.links, l.links);
        assert_eq!(back.source_of("bin/alias"), Some(("bin/tool", 5)));
    }

    #[test]
    fn bad_entry_is_miss() {
        let (_d, dir, _blobs, l) = store_with_blob();
        let c = IndexCache::new(dir.clone(), true);
        c.store(&l);
        let entry = dir.join("aa11.json");
        let good = std::fs::read_to_string(&entry).unwrap();
        for bad in [
            good[..good.len() / 2].to_string(),
            good.replace("\"aa11\"", "\"bb22\""),
            good.replace(&format!("\"format\":{FORMAT}"), "\"format\":1"),
            good.replace(":5", ":\"5\""),
            String::new(),
        ] {
            assert_ne!(bad, good);
            std::fs::write(&entry, &bad).unwrap();
            assert!(c.load("aa11").is_none(), "{bad}");
        }
        assert!(c.load("absent").is_none());
    }

    #[test]
    fn prune_drops_gone_blobs() {
        let (_d, dir, blobs, l) = store_with_blob();
        let c = IndexCache::new(dir.clone(), true);
        c.store(&l);
        c.store(&Layer {
            digest: "gone".into(),
            ..Layer::default()
        });
        std::fs::write(dir.join("stray.edge-tmp"), b"x").unwrap();

        let blobs = Blobs::content_store(blobs);
        IndexCache::new(dir.clone(), false).prune(&blobs);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);
        c.prune(&blobs);
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, ["aa11.json"]);
    }
}
