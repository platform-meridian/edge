//! Where a layer's compressed blob is read from, first holder wins: edge-registry's
//! store, which keeps every release's images; containerd's content store, which
//! `discard_unpacked_layers` empties of layers; then Talos's image cache, where its
//! own images' blobs survive containerd's GC (it pulls them outside the GC references).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// edge-registry's store layout, under its root.
pub const REGISTRY_BLOBS: &str = "blobs/sha256";
pub const REGISTRY_MANIFESTS: &str = "manifests/sha256";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Registry,
    ContentStore,
    ImageCache,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Registry => "registry",
            Kind::ContentStore => "content store",
            Kind::ImageCache => "image cache",
        }
    }
}

pub struct Source {
    pub dir: PathBuf,
    prefix: &'static str,
    pub kind: Kind,
}

pub struct Blobs {
    sources: Vec<Source>,
}

impl Blobs {
    pub fn content_store(dir: PathBuf) -> Self {
        Blobs {
            sources: vec![Source {
                dir,
                prefix: "",
                kind: Kind::ContentStore,
            }],
        }
    }

    pub fn with_registry(mut self, root: &Path) -> Self {
        self.sources.insert(
            0,
            Source {
                dir: root.join(REGISTRY_BLOBS),
                prefix: "",
                kind: Kind::Registry,
            },
        );
        self
    }

    pub fn with_image_caches(mut self, roots: &[PathBuf]) -> Self {
        self.sources.extend(roots.iter().map(|r| Source {
            dir: r.join("blob"),
            prefix: "sha256-",
            kind: Kind::ImageCache,
        }));
        self
    }

    pub fn content_store_dir(&self) -> &Path {
        &self
            .sources
            .iter()
            .find(|s| s.kind == Kind::ContentStore)
            .expect("built with a content store")
            .dir
    }

    pub fn present(&self, kind: Kind) -> usize {
        self.sources
            .iter()
            .filter(|s| s.kind == kind && s.dir.is_dir())
            .count()
    }

    pub fn has(&self, kind: Kind) -> bool {
        self.sources.iter().any(|s| s.kind == kind)
    }

    pub fn find(&self, digest: &str) -> Option<(PathBuf, Kind)> {
        self.sources.iter().find_map(|s| {
            let p = s.dir.join(format!("{}{digest}", s.prefix));
            p.is_file().then_some((p, s.kind))
        })
    }

    pub fn exists(&self, digest: &str) -> bool {
        self.find(digest).is_some()
    }

    /// Only the content store must be readable: the others are optional mounts.
    pub fn list(&self) -> anyhow::Result<Vec<(String, PathBuf)>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for s in &self.sources {
            let rd = match std::fs::read_dir(&s.dir) {
                Ok(rd) => rd,
                Err(e) if s.kind == Kind::ContentStore => return Err(e.into()),
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(dir = %s.dir.display(), source = s.kind.as_str(), error = %e, "could not read a blob source; skipping it");
                    }
                    continue;
                }
            };
            for e in rd {
                let e = match e {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::warn!(dir = %s.dir.display(), error = %err, "could not read a blob entry; skipping it");
                        continue;
                    }
                };
                let name = e.file_name().to_string_lossy().into_owned();
                let Some(digest) = name.strip_prefix(s.prefix) else {
                    continue;
                };
                if seen.insert(digest.to_string()) {
                    out.push((digest.to_string(), e.path()));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_then_content_store_then_caches() {
        let d = tempfile::tempdir().unwrap();
        let cs = d.path().join("cs");
        let reg = d.path().join("registry");
        let cache = d.path().join("cache");
        std::fs::create_dir_all(&cs).unwrap();
        std::fs::create_dir_all(reg.join(REGISTRY_BLOBS)).unwrap();
        std::fs::create_dir_all(cache.join("blob")).unwrap();
        std::fs::write(reg.join(REGISTRY_BLOBS).join("aa"), b"registry").unwrap();
        std::fs::write(cs.join("aa"), b"cs").unwrap();
        std::fs::write(cs.join("bb"), b"cs").unwrap();
        std::fs::write(cache.join("blob/sha256-bb"), b"cache").unwrap();
        std::fs::write(cache.join("blob/sha256-cc"), b"cache").unwrap();
        std::fs::write(cache.join("blob/stray"), b"x").unwrap();

        let b = Blobs::content_store(cs.clone())
            .with_registry(&reg)
            .with_image_caches(&[d.path().join("absent"), cache.clone()]);
        assert_eq!(
            b.find("aa"),
            Some((reg.join(REGISTRY_BLOBS).join("aa"), Kind::Registry))
        );
        assert_eq!(b.find("bb"), Some((cs.join("bb"), Kind::ContentStore)));
        assert_eq!(
            b.find("cc"),
            Some((cache.join("blob/sha256-cc"), Kind::ImageCache))
        );
        assert_eq!(b.find("dd"), None);
        assert_eq!(b.content_store_dir(), cs);
        assert_eq!(b.present(Kind::ImageCache), 1);
        assert_eq!(b.present(Kind::Registry), 1);

        let mut l = b.list().unwrap();
        l.sort();
        assert_eq!(
            l,
            [
                ("aa".to_string(), reg.join(REGISTRY_BLOBS).join("aa")),
                ("bb".to_string(), cs.join("bb")),
                ("cc".to_string(), cache.join("blob/sha256-cc"))
            ]
        );

        std::fs::remove_dir_all(&reg).unwrap();
        assert_eq!(b.present(Kind::Registry), 0);
        assert!(b.list().is_ok(), "a missing registry is no error");
        std::fs::remove_dir_all(&cs).unwrap();
        assert!(b.list().is_err(), "a missing content store is an error");
    }
}
