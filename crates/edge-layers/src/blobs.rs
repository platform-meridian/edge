//! Talos pulls its own images into containerd's `system` namespace outside the GC
//! references, so after a GC their layer blobs exist only in the image cache.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct Source {
    pub dir: PathBuf,
    prefix: &'static str,
    pub kind: &'static str,
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
                kind: "content store",
            }],
        }
    }

    pub fn with_image_caches(mut self, roots: &[PathBuf]) -> Self {
        self.sources.extend(roots.iter().map(|r| Source {
            dir: r.join("blob"),
            prefix: "sha256-",
            kind: "image cache",
        }));
        self
    }

    pub fn content_store_dir(&self) -> &Path {
        &self.sources[0].dir
    }

    pub fn image_caches_present(&self) -> usize {
        self.sources[1..].iter().filter(|s| s.dir.is_dir()).count()
    }

    pub fn has_image_caches(&self) -> bool {
        self.sources.len() > 1
    }

    pub fn find(&self, digest: &str) -> Option<(PathBuf, &'static str)> {
        self.sources.iter().find_map(|s| {
            let p = s.dir.join(format!("{}{digest}", s.prefix));
            p.is_file().then_some((p, s.kind))
        })
    }

    pub fn exists(&self, digest: &str) -> bool {
        self.find(digest).is_some()
    }

    pub fn list(&self) -> anyhow::Result<Vec<(String, PathBuf)>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (i, s) in self.sources.iter().enumerate() {
            let rd = match std::fs::read_dir(&s.dir) {
                Ok(rd) => rd,
                Err(e) if i == 0 => return Err(e.into()),
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(dir = %s.dir.display(), error = %e, "could not read an image cache; skipping it");
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
    fn content_store_first_then_caches() {
        let d = tempfile::tempdir().unwrap();
        let cs = d.path().join("cs");
        let cache = d.path().join("cache");
        std::fs::create_dir_all(&cs).unwrap();
        std::fs::create_dir_all(cache.join("blob")).unwrap();
        std::fs::write(cs.join("aa"), b"cs").unwrap();
        std::fs::write(cache.join("blob/sha256-aa"), b"cache").unwrap();
        std::fs::write(cache.join("blob/sha256-bb"), b"cache").unwrap();
        std::fs::write(cache.join("blob/stray"), b"x").unwrap();

        let b = Blobs::content_store(cs.clone())
            .with_image_caches(&[d.path().join("absent"), cache.clone()]);
        assert_eq!(b.find("aa"), Some((cs.join("aa"), "content store")));
        assert_eq!(
            b.find("bb"),
            Some((cache.join("blob/sha256-bb"), "image cache"))
        );
        assert_eq!(b.find("cc"), None);
        assert_eq!(b.image_caches_present(), 1);

        let mut l = b.list().unwrap();
        l.sort();
        assert_eq!(
            l,
            [
                ("aa".to_string(), cs.join("aa")),
                ("bb".to_string(), cache.join("blob/sha256-bb"))
            ]
        );

        std::fs::remove_file(cs.join("aa")).unwrap();
        std::fs::remove_dir(&cs).unwrap();
        assert!(b.list().is_err(), "a missing content store is an error");
    }
}
