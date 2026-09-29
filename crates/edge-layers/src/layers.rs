//! containerd writes blobs through its ingest path (fsynced and digest-verified), so
//! they are the intact copy of anything a cut truncated in a snapshot.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

use crate::blobs::Blobs;
use crate::cache::IndexCache;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct Layer {
    pub digest: String,
    pub files: HashMap<String, Entry>,
    /// Hardlink alias -> target. On disk an alias is a regular file, so it
    /// belongs to the path set and is size-checked against its target.
    pub links: BTreeMap<String, String>,
}

impl Layer {
    pub fn paths(&self) -> BTreeSet<&str> {
        self.files
            .keys()
            .map(String::as_str)
            .chain(self.links.keys().map(String::as_str))
            .collect()
    }

    pub fn source_of(&self, path: &str) -> Option<(&str, u64)> {
        if let Some((k, e)) = self.files.get_key_value(path) {
            return Some((k.as_str(), e.size));
        }
        let mut cur = path;
        // Bounded: a link cycle in a corrupt layer must not hang boot.
        for _ in 0..16 {
            let next = self.links.get(cur)?;
            if let Some((k, e)) = self.files.get_key_value(next.as_str()) {
                return Some((k.as_str(), e.size));
            }
            cur = next;
        }
        None
    }
}

/// In the snapshot walk's form: `.` and empty components dropped, `..` resolved
/// and clamped at the root.
pub fn normalise(p: &str) -> Option<String> {
    let mut parts = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn is_whiteout(p: &str) -> bool {
    Path::new(p)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(".wh."))
}

fn open(blob: &Path) -> anyhow::Result<tar::Archive<Box<dyn Read>>> {
    let mut magic = [0u8; 2];
    std::fs::File::open(blob)?.read_exact(&mut magic)?;
    let f = std::fs::File::open(blob)?;
    let reader: Box<dyn Read> = if magic == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(f))
    } else {
        Box::new(f)
    };
    Ok(tar::Archive::new(reader))
}

/// A blob that fails mid-stream is discarded whole: a partial index would make real
/// files look absent.
pub fn index_blob(path: &Path, digest: &str) -> Option<Layer> {
    let mut layer = Layer {
        digest: digest.to_string(),
        ..Layer::default()
    };
    let mut ar = open(path).ok()?;
    for e in ar.entries().ok()? {
        let e = e.ok()?;
        let kind = e.header().entry_type();
        if kind != tar::EntryType::Regular && kind != tar::EntryType::Link {
            continue;
        }
        let Some(p) = normalise(&e.path().ok()?.to_string_lossy()) else {
            continue;
        };
        if is_whiteout(&p) {
            continue;
        }
        if kind == tar::EntryType::Link {
            let target = e.link_name().ok()??.to_string_lossy().to_string();
            // A target naming the root is no file: it stays unresolvable as written.
            layer.links.insert(p, normalise(&target).unwrap_or(target));
        } else {
            let size = e.header().size().ok()?;
            layer.files.insert(p, Entry { size });
        }
    }
    (!layer.files.is_empty() || !layer.links.is_empty()).then_some(layer)
}

/// Never returns a partial index: a deadline or stop request is an error.
pub fn index_store(
    blobs: &Blobs,
    until: std::time::Instant,
    only: Option<&HashSet<String>>,
    cache: Option<&IndexCache>,
) -> anyhow::Result<(Vec<Layer>, usize)> {
    let mut out = Vec::new();
    let mut hits = 0;
    for (digest, p) in blobs.list()? {
        crate::budget::check(until)?;
        if !only.is_none_or(|o| o.contains(&digest)) || !p.is_file() {
            continue;
        }
        if let Some(l) = cache.and_then(|c| c.load(&digest)) {
            hits += 1;
            out.push(l);
        } else if let Some(l) = index_blob(&p, &digest) {
            if let Some(c) = cache {
                c.store(&l);
            }
            out.push(l);
        }
    }
    Ok((out, hits))
}

/// Reads to EOF so the gzip trailer's CRC and length are checked, which
/// `extract_each` skips by stopping early.
pub fn verify_blob(blob: &Path) -> anyhow::Result<()> {
    let mut ar = open(blob)?;
    for e in ar.entries()? {
        std::io::copy(&mut e?, &mut std::io::sink())?;
    }
    std::io::copy(&mut ar.into_inner(), &mut std::io::sink())?;
    Ok(())
}

/// Does not verify the stream: call [`verify_blob`] first.
pub fn extract_each(
    blob: &Path,
    wanted: &BTreeSet<String>,
    mut sink: impl FnMut(&str, u64, &mut dyn Read) -> anyhow::Result<()>,
) -> anyhow::Result<usize> {
    let mut ar = open(blob)?;
    let mut done = 0usize;
    for e in ar.entries()? {
        let mut e = e?;
        // A Link entry carries no bytes.
        if e.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let Some(p) = normalise(&e.path()?.to_string_lossy()).filter(|p| wanted.contains(p)) else {
            continue;
        };
        let size = e.header().size()?;
        sink(&p, size, &mut e)?;
        done += 1;
        if done == wanted.len() {
            break;
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Item, layer_blob, tar, tar_gz};
    use std::path::PathBuf;

    fn put(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn extract(blob: &Path, want: &str) -> Option<Vec<u8>> {
        let mut got = None;
        extract_each(blob, &BTreeSet::from([want.to_string()]), |_, _, r| {
            let mut b = Vec::new();
            r.read_to_end(&mut b)?;
            got = Some(b);
            Ok(())
        })
        .unwrap();
        got
    }

    #[test]
    fn gzip_and_plain_tars() {
        let d = tempfile::tempdir().unwrap();
        let items = [
            Item::File("./a", b"first"),
            Item::File("./b/c", b"second"),
            Item::File("./marker", b""),
            Item::File("./a/.wh.gone", b""),
        ];
        for (name, bytes) in [("gz", tar_gz(&items)), ("plain", tar(&items))] {
            let p = put(d.path(), name, &bytes);
            let l = index_blob(&p, name).unwrap();
            assert_eq!(l.digest, name);
            assert_eq!(
                l.paths(),
                BTreeSet::from(["a", "b/c", "marker"]),
                "{name}: normalised, whiteouts excluded"
            );
            assert_eq!(l.files["b/c"].size, 6, "{name}");
            assert_eq!(l.files["marker"].size, 0, "{name}");
            verify_blob(&p).unwrap();
            assert_eq!(extract(&p, "b/c").unwrap(), b"second", "{name}");
            assert_eq!(extract(&p, "a").unwrap(), b"first", "{name}");
            assert_eq!(extract(&p, "nope"), None, "{name}");
        }
    }

    #[test]
    fn normalise_matches_containerd() {
        for (p, want) in [
            ("./a/b", Some("a/b")),
            ("/a/b", Some("a/b")),
            ("a/b", Some("a/b")),
            ("/./a", Some("a")),
            ("a//b/", Some("a/b")),
            ("a/./b", Some("a/b")),
            ("a/../b", Some("b")),
            ("../../etc/x", Some("etc/x")),
            ("./", None),
            ("a/..", None),
        ] {
            assert_eq!(normalise(p).as_deref(), want, "{p:?}");
        }
    }

    proptest::proptest! {
        #[test]
        fn normalised_path_is_fixed_point(p in "[./ab]{0,12}") {
            if let Some(n) = normalise(&p) {
                proptest::prop_assert_eq!(normalise(&n), Some(n.clone()), "{:?}", p);
                let root = Path::new("/snap");
                let walked = root.join(&n);
                let walked = walked.strip_prefix(root).unwrap().to_string_lossy();
                proptest::prop_assert_eq!(&walked, &n, "{:?}", p);
                proptest::prop_assert!(!n.split('/').any(|c| c == "." || c == ".."), "{:?}", p);
            }
        }
    }

    #[test]
    fn only_tars_with_entries_are_layers() {
        let d = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("manifest", &br#"{"schemaVersion":2}"#[..]),
            ("tiny", b"x"),
            ("empty-tar", &tar(&[])),
        ] {
            assert!(
                index_blob(&put(d.path(), name, bytes), name).is_none(),
                "{name}"
            );
        }
        let links_only = tar(&[Item::Link("./a", "../lower/a")]);
        assert!(index_blob(&put(d.path(), "links-only", &links_only), "l").is_some());
    }

    #[test]
    fn hardlinks_resolve_to_target() {
        let d = tempfile::tempdir().unwrap();
        let p = put(
            d.path(),
            "h",
            &tar_gz(&[
                Item::File("./bin/real", b"abcd"),
                Item::Link("./bin/alias", "./bin/real"),
            ]),
        );
        let l = index_blob(&p, "h").unwrap();
        assert_eq!(l.paths(), BTreeSet::from(["bin/alias", "bin/real"]));
        assert!(!l.files.contains_key("bin/alias"));
        assert_eq!(l.source_of("bin/alias"), Some(("bin/real", 4)));
        assert_eq!(l.source_of("bin/real"), Some(("bin/real", 4)));
        assert_eq!(l.source_of("bin/nope"), None);
        assert_eq!(extract(&p, "bin/alias"), None);
    }

    #[test]
    fn link_chains_resolve_cycles_do_not() {
        let mut l = Layer::default();
        l.files.insert("real".into(), Entry { size: 9 });
        for (from, to) in [("a", "b"), ("b", "real"), ("x", "y"), ("y", "x")] {
            l.links.insert(from.into(), to.into());
        }
        l.links.insert("lower".into(), "in/a/lower/layer".into());
        assert_eq!(l.source_of("a"), Some(("real", 9)));
        assert_eq!(l.source_of("x"), None);
        assert_eq!(l.source_of("lower"), None);
    }

    #[test]
    fn bad_crc_fails_verification() {
        // `extract_each` stops at the last wanted file, before the gzip trailer.
        let d = tempfile::tempdir().unwrap();
        let mut blob = layer_blob(&[("./first", b"wanted"), ("./second", &[b'z'; 200_000])]);
        let n = blob.len();
        blob[n - 8] ^= 0x01;
        let p = put(d.path(), "crc", &blob);
        assert_eq!(extract(&p, "first").unwrap(), b"wanted");
        assert!(verify_blob(&p).is_err());
    }

    #[test]
    fn truncated_blob_fails_verification() {
        let d = tempfile::tempdir().unwrap();
        let good = layer_blob(&[("./a", b"aaaa"), ("./b", b"bbbb")]);
        assert!(verify_blob(&put(d.path(), "cut", &good[..good.len() - 20])).is_err());
    }

    #[test]
    fn index_store_skips_non_layers() {
        let d = tempfile::tempdir().unwrap();
        put(d.path(), "layer", &layer_blob(&[("./a", b"x")]));
        put(d.path(), "config", b"{}");
        std::fs::create_dir(d.path().join("subdir")).unwrap();
        let far = std::time::Instant::now() + std::time::Duration::from_secs(60);
        put(d.path(), "other", &layer_blob(&[("./b", b"y")]));
        let blobs = Blobs::content_store(d.path().to_path_buf());
        let digests = |only: Option<&HashSet<String>>| {
            let mut v: Vec<_> = index_store(&blobs, far, only, None)
                .unwrap()
                .0
                .into_iter()
                .map(|l| l.digest)
                .collect();
            v.sort();
            v
        };
        assert_eq!(digests(None), ["layer", "other"]);
        let only = HashSet::from(["other".to_string(), "config".to_string()]);
        assert_eq!(digests(Some(&only)), ["other"]);
        let e = index_store(&blobs, std::time::Instant::now(), None, None).unwrap_err();
        assert_eq!(e.downcast_ref(), Some(&crate::budget::Halt::Deadline));
    }
}
