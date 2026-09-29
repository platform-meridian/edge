//! A snapshot's layer comes from containerd's metadata (its chainID); only when
//! that is unreadable is it inferred as the one layer whose path set equals the
//! snapshot's, since truncation never changes a path.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::layers::Layer;
use crate::meta::{Origin, Provenance};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnDisk {
    /// Relative to `<id>/fs`.
    pub path: String,
    pub size: u64,
}

#[derive(Debug)]
pub struct Snapshot {
    pub id: String,
    pub root: PathBuf,
    pub files: Vec<OnDisk>,
    /// Kept out of `files` so they cannot change the path set.
    pub stale_temps: Vec<PathBuf>,
    /// Part of it was unreadable. A partial path set can equal another
    /// layer's, so an incomplete snapshot is never matched.
    pub incomplete: bool,
}

/// Matched by suffix alone: older builds replaced the extension
/// (`libc.so.6` -> `libc.so.edge-layers-tmp`).
pub fn is_stale_temp(name: &str) -> bool {
    name.ends_with(".edge-layers-tmp") || name.ends_with(edge_common::TMP_SUFFIX)
}

impl Snapshot {
    pub fn paths(&self) -> BTreeSet<&str> {
        self.files.iter().map(|f| f.path.as_str()).collect()
    }
}

/// Symlinks are not followed: an absolute one would lead into the host.
pub fn walk(snapshots: &Path) -> anyhow::Result<Vec<Snapshot>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(snapshots)? {
        let dir = match e {
            Ok(e) => e.path(),
            Err(err) => {
                tracing::warn!(error = %err, "could not read a snapshots entry; skipping it");
                continue;
            }
        };
        let root = dir.join("fs");
        if !root.is_dir() {
            continue;
        }
        let mut snap = Snapshot {
            id: dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            root,
            files: Vec::new(),
            stale_temps: Vec::new(),
            incomplete: false,
        };
        let root = snap.root.clone();
        walk_into(&root, &mut snap);
        if snap.incomplete {
            tracing::warn!(snapshot = %snap.id, "part of this snapshot could not be read; it will not be matched or repaired");
        }
        out.push(snap);
    }
    Ok(out)
}

fn walk_into(dir: &Path, snap: &mut Snapshot) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "could not read a directory in a snapshot");
            snap.incomplete = true;
            return;
        }
    };
    for e in rd {
        let e = match e {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(dir = %dir.display(), error = %err, "could not read a directory entry");
                snap.incomplete = true;
                continue;
            }
        };
        let md = match e.metadata() {
            Ok(md) => md,
            Err(err) => {
                tracing::warn!(path = %e.path().display(), error = %err, "could not stat a file in a snapshot");
                snap.incomplete = true;
                continue;
            }
        };
        let p = e.path();
        if md.is_dir() {
            walk_into(&p, snap);
        } else if md.is_file() {
            if is_stale_temp(&e.file_name().to_string_lossy()) {
                snap.stale_temps.push(p);
            } else if let Ok(rel) = p.strip_prefix(&snap.root) {
                snap.files.push(OnDisk {
                    path: rel.to_string_lossy().to_string(),
                    size: md.len(),
                });
            }
        }
    }
}

pub fn remove_stale_temps(snaps: &[Snapshot]) -> usize {
    let mut n = 0;
    for p in snaps.iter().flat_map(|s| &s.stale_temps) {
        match std::fs::remove_file(p) {
            Ok(()) => {
                n += 1;
                tracing::info!(path = %p.display(), "removed a leftover repair temp file");
            }
            Err(e) => {
                tracing::warn!(path = %p.display(), error = %e, "could not remove a leftover repair temp file")
            }
        }
    }
    n
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Torn {
    pub snapshot: String,
    /// `?` when matched by path set.
    pub namespace: String,
    pub root: PathBuf,
    pub path: String,
    /// The tar entry holding the bytes: `path`, or a hardlink's target.
    pub source: String,
    pub on_disk: u64,
    pub expected: u64,
    pub layer_digest: String,
    pub matched_by: MatchedBy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    ChainId,
    PathSet,
}

impl std::fmt::Display for MatchedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MatchedBy::ChainId => "chainid",
            MatchedBy::PathSet => "path-set",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unverifiable {
    NotALayer,
    NoLayerBlob,
    Unrecorded,
    NoUniquePathSet,
    Incomplete,
}

/// The layer whose path set equals the snapshot's, if exactly one does:
/// repairing from a lookalike would write plausible wrong bytes.
pub fn match_layer<'a>(snap: &Snapshot, layers: &'a [Layer]) -> Option<&'a Layer> {
    let want = snap.paths();
    let mut hit = None;
    for l in layers {
        if l.paths() == want {
            if hit.is_some() {
                return None;
            }
            hit = Some(l);
        }
    }
    hit
}

/// Files a container runtime creates empty as bind-mount targets in every
/// read-write layer. Only used to quieten the unmatched-snapshot report.
fn is_runtime_placeholder(path: &str) -> bool {
    matches!(
        path,
        "etc/hostname" | "etc/hosts" | "etc/resolv.conf" | ".dockerenv" | "dev/console"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmatched {
    pub id: String,
    pub why: Unverifiable,
    pub files: usize,
    /// Empty files other than runtime placeholders.
    pub empty: usize,
}

#[derive(Debug, Default)]
pub struct Coverage {
    pub by_chain_id: usize,
    pub by_path_set: usize,
    pub empty: usize,
    pub unmatched: Vec<Unmatched>,
    pub layers_indexed: usize,
    pub layers_verified: usize,
}

impl Coverage {
    pub fn checked(&self) -> usize {
        self.by_chain_id + self.by_path_set
    }

    /// Unmatched snapshots holding empty files: possibly torn, not repairable.
    pub fn suspect(&self) -> impl Iterator<Item = &Unmatched> {
        self.unmatched.iter().filter(|u| u.empty > 0)
    }
}

/// With metadata (`prov`) the layer is a fact or nothing; path sets are
/// compared only when the metadata was unreadable.
fn layer_of<'a, 'p>(
    s: &Snapshot,
    layers: &'a [Layer],
    by_digest: &HashMap<&str, &'a Layer>,
    prov: Option<&'p Provenance>,
) -> Result<(&'a Layer, MatchedBy, &'p str), Unverifiable> {
    if s.incomplete {
        return Err(Unverifiable::Incomplete);
    }
    let Some(prov) = prov else {
        return match_layer(s, layers)
            .map(|l| (l, MatchedBy::PathSet, "?"))
            .ok_or(Unverifiable::NoUniquePathSet);
    };
    match prov.get(&s.id) {
        None => Err(Unverifiable::Unrecorded),
        Some(Origin::NotALayer) => Err(Unverifiable::NotALayer),
        Some(Origin::Layer {
            blobs, namespace, ..
        }) => blobs
            .iter()
            .find_map(|b| by_digest.get(b.as_str()).copied())
            .map(|l| (l, MatchedBy::ChainId, namespace.as_str()))
            .ok_or(Unverifiable::NoLayerBlob),
    }
}

pub fn find_torn(
    snaps: &[Snapshot],
    layers: &[Layer],
    prov: Option<&Provenance>,
) -> (Vec<Torn>, Coverage) {
    let mut torn = Vec::new();
    let mut cov = Coverage {
        layers_indexed: layers.len(),
        ..Coverage::default()
    };
    let by_digest: HashMap<&str, &Layer> = layers.iter().map(|l| (l.digest.as_str(), l)).collect();
    let mut verified: HashSet<&str> = HashSet::new();
    for s in snaps {
        if s.files.is_empty() {
            cov.empty += 1;
            continue;
        }
        let (l, matched_by, namespace) = match layer_of(s, layers, &by_digest, prov) {
            Ok(m) => m,
            Err(why) => {
                cov.unmatched.push(Unmatched {
                    id: s.id.clone(),
                    why,
                    files: s.files.len(),
                    empty: s
                        .files
                        .iter()
                        .filter(|f| f.size == 0 && !is_runtime_placeholder(&f.path))
                        .count(),
                });
                continue;
            }
        };
        match matched_by {
            MatchedBy::ChainId => cov.by_chain_id += 1,
            MatchedBy::PathSet => cov.by_path_set += 1,
        }
        verified.insert(&l.digest);
        for f in &s.files {
            let Some((source, want)) = l.source_of(&f.path) else {
                continue;
            };
            if want != f.size {
                torn.push(Torn {
                    snapshot: s.id.clone(),
                    namespace: namespace.to_string(),
                    root: s.root.clone(),
                    path: f.path.clone(),
                    source: source.to_string(),
                    on_disk: f.size,
                    expected: want,
                    layer_digest: l.digest.clone(),
                    matched_by,
                });
            }
        }
    }
    torn.sort_by(|a, b| (&a.snapshot, &a.path).cmp(&(&b.snapshot, &b.path)));
    cov.unmatched.sort_by(|a, b| a.id.cmp(&b.id));
    cov.layers_verified = verified.len();
    (torn, cov)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::Entry;
    use crate::testutil::{layer, snap};

    #[test]
    fn size_mismatch_is_torn() {
        for on_disk in [0, 40, 101] {
            let l = [layer("sha256:a", &[("bin/x", 100), (".dockerenv", 0)])];
            let s = [snap("164", &[("bin/x", on_disk), (".dockerenv", 0)])];
            let (torn, cov) = find_torn(&s, &l, None);
            assert_eq!(cov.checked(), 1);
            assert_eq!(
                torn,
                vec![Torn {
                    snapshot: "164".into(),
                    namespace: "?".into(),
                    root: PathBuf::from("/nowhere"),
                    path: "bin/x".into(),
                    source: "bin/x".into(),
                    on_disk,
                    expected: 100,
                    layer_digest: "sha256:a".into(),
                    matched_by: MatchedBy::PathSet,
                }],
                "{on_disk}"
            );
        }
        let (torn, _) = find_torn(
            &[snap("1", &[("bin/x", 100)])],
            &[layer("sha256:a", &[("bin/x", 100)])],
            None,
        );
        assert!(torn.is_empty());
    }

    #[test]
    fn matched_by_log_spelling() {
        // talos test/torn-shared-layer.sh greps for these.
        assert_eq!(MatchedBy::ChainId.to_string(), "chainid");
        assert_eq!(MatchedBy::PathSet.to_string(), "path-set");
    }

    #[test]
    fn ambiguous_path_set_matches_neither() {
        let l = [
            layer("sha256:a", &[("bin/x", 10)]),
            layer("sha256:b", &[("bin/x", 20)]),
        ];
        let (torn, cov) = find_torn(&[snap("1", &[("bin/x", 0)])], &l, None);
        assert!(torn.is_empty());
        assert_eq!(cov.unmatched[0].id, "1");
    }

    #[test]
    fn lower_layer_hardlink_unchecked() {
        let mut l = layer("sha256:a", &[("bin/x", 10)]);
        l.links
            .insert("bin/alias".into(), "usr/lib/elsewhere".into());
        let (torn, cov) = find_torn(&[snap("1", &[("bin/x", 10), ("bin/alias", 0)])], &[l], None);
        assert_eq!(cov.checked(), 1);
        assert!(torn.is_empty());
    }

    #[test]
    fn coverage_buckets() {
        let l = [
            layer("sha256:img", &[("bin/a", 10), ("bin/b", 20)]),
            layer("sha256:unpacked-later", &[("opt/x", 1)]),
        ];
        let s = [
            snap("1", &[("bin/a", 10), ("bin/b", 20)]),
            snap("2", &[("bin/a", 10), ("bin/b", 20)]),
            snap("3", &[]),
            snap("9", &[("tmp/session", 5)]),
            snap(
                "8",
                &[
                    ("etc/hosts", 0),
                    ("etc/resolv.conf", 0),
                    ("usr/bin/thing", 0),
                ],
            ),
            snap(
                "7",
                &[("etc/hostname", 0), (".dockerenv", 0), ("dev/console", 0)],
            ),
        ];
        let (torn, cov) = find_torn(&s, &l, None);
        assert!(torn.is_empty());
        assert_eq!((cov.checked(), cov.empty), (2, 1));
        assert_eq!((cov.layers_indexed, cov.layers_verified), (2, 1));
        assert_eq!(
            cov.unmatched,
            vec![
                Unmatched {
                    why: Unverifiable::NoUniquePathSet,
                    id: "7".into(),
                    files: 3,
                    empty: 0
                },
                Unmatched {
                    why: Unverifiable::NoUniquePathSet,
                    id: "8".into(),
                    files: 3,
                    empty: 1
                },
                Unmatched {
                    why: Unverifiable::NoUniquePathSet,
                    id: "9".into(),
                    files: 1,
                    empty: 0
                },
            ],
            "sorted, runtime placeholders not counted as empty"
        );
        assert_eq!(
            cov.suspect().map(|u| u.id.as_str()).collect::<Vec<_>>(),
            ["8"]
        );
    }

    #[test]
    fn hardlink_checked_against_target() {
        let mut l = layer("sha256:l", &[("bin/real", 100)]);
        l.links.insert("bin/alias".into(), "bin/real".into());
        let l = [l];
        let (torn, _) = find_torn(
            &[snap("1", &[("bin/real", 100), ("bin/alias", 100)])],
            &l,
            None,
        );
        assert!(torn.is_empty());
        let (torn, _) = find_torn(
            &[snap("1", &[("bin/real", 100), ("bin/alias", 0)])],
            &l,
            None,
        );
        assert_eq!(torn.len(), 1);
        assert_eq!(
            (torn[0].path.as_str(), torn[0].source.as_str()),
            ("bin/alias", "bin/real")
        );
        assert_eq!(torn[0].expected, 100);
    }

    #[test]
    fn unreadable_dir_marks_snapshot_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let snaps = d.path();
        for id in ["1", "2"] {
            std::fs::create_dir_all(snaps.join(id).join("fs/bin")).unwrap();
            std::fs::write(snaps.join(id).join("fs/bin/tool"), b"x").unwrap();
        }
        std::fs::create_dir_all(snaps.join("2/fs/lib")).unwrap();
        std::fs::write(snaps.join("2/fs/lib/a"), b"y").unwrap();
        std::fs::write(snaps.join("stray"), b"z").unwrap();
        std::os::unix::fs::symlink("/nonexistent", snaps.join("2/fs/dangling")).unwrap();
        let lib = snaps.join("2/fs/lib");
        std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = std::fs::read_dir(&lib).is_ok();
        let got = walk(snaps);
        std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o755)).unwrap();
        if readable_anyway {
            return; // root
        }
        let mut got = got.unwrap();
        got.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(got.len(), 2);
        assert!(!got[0].incomplete);
        assert!(got[1].incomplete);
        assert_eq!(got[1].paths(), BTreeSet::from(["bin/tool"]));

        let l = [layer("sha256:b", &[("bin/tool", 99)])];
        let (torn, cov) = find_torn(&got, &l, None);
        assert_eq!(torn.len(), 1);
        assert_eq!(torn[0].snapshot, "1");
        assert_eq!(cov.unmatched[0].id, "2");
    }

    #[test]
    fn stale_temps_excluded_and_removed() {
        let d = tempfile::tempdir().unwrap();
        let fs = d.path().join("164/fs/bin");
        std::fs::create_dir_all(&fs).unwrap();
        std::fs::write(fs.join("tool"), b"x").unwrap();
        for leftover in [
            "tool.edge-layers-tmp".to_string(),
            "libc.so.edge-layers-tmp".to_string(),
            format!("tool{}", edge_common::TMP_SUFFIX),
        ] {
            std::fs::write(fs.join(leftover), b"half").unwrap();
        }

        let snaps = walk(d.path()).unwrap();
        assert_eq!(
            snaps[0].files,
            vec![OnDisk {
                path: "bin/tool".into(),
                size: 1
            }]
        );
        assert_eq!(snaps[0].stale_temps.len(), 3);
        let l = crate::layers::Layer {
            digest: "sha256:t".into(),
            files: [("bin/tool".to_string(), Entry { size: 1 })].into(),
            links: Default::default(),
        };
        assert!(match_layer(&snaps[0], &[l]).is_some());

        assert_eq!(remove_stale_temps(&snaps), 3);
        assert_eq!(std::fs::read_dir(&fs).unwrap().count(), 1);
        assert!(fs.join("tool").exists());
    }
}
