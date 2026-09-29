//! Written in place, keeping the inode: a rename would drop owner and xattrs
//! (`security.capability`) and split hardlinks. Only a running binary (ETXTBSY) is
//! replaced by rename.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Instant;

use crate::blobs::Blobs;
use crate::budget::{self, Halt};
use crate::layers;
use crate::snapshots::Torn;

const ETXTBSY: i32 = 26;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Repaired {
    pub fixed: usize,
    pub failed: usize,
    pub bytes: u64,
    /// Why the run stopped early; everything not reached counts as failed.
    pub halted: Option<Halt>,
}

impl Repaired {
    fn fixed(&mut self, t: &Torn, n: u64, from: &str) {
        self.fixed += 1;
        self.bytes += n;
        tracing::info!(
            snapshot = %t.snapshot, namespace = %t.namespace, path = %t.path, bytes = n,
            matched_by = %t.matched_by, from, "repaired"
        );
    }

    fn failed(&mut self, t: &Torn, e: &anyhow::Error) {
        self.failed += 1;
        tracing::error!(
            snapshot = %t.snapshot, path = %t.path,
            error = %format!("{e:#}"), "could not repair"
        );
    }
}

/// One decompression pass per layer (a tar has no index). One unrepairable
/// file never abandons the rest.
pub fn repair_all(blobs: &Blobs, torn: &[Torn], until: Instant) -> Repaired {
    let mut out = Repaired::default();

    let mut by_layer: BTreeMap<&str, Vec<&Torn>> = BTreeMap::new();
    for t in torn {
        by_layer.entry(t.layer_digest.as_str()).or_default().push(t);
    }

    let mut layers_iter = by_layer.into_iter();
    while let Some((digest, items)) = layers_iter.next() {
        if let Err(h) = budget::check(until) {
            out.halted = Some(h);
            out.failed += items.len() + layers_iter.map(|(_, i)| i.len()).sum::<usize>();
            tracing::error!(reason = %h, "stopping the repair before layer {digest}");
            break;
        }
        let Some((blob, from)) = blobs.find(digest) else {
            out.failed += items.len();
            tracing::error!(
                layer = digest,
                files = items.len(),
                "the layer blob is gone"
            );
            continue;
        };

        if let Err(e) = layers::verify_blob(&blob) {
            out.failed += items.len();
            tracing::error!(
                layer = digest, files = items.len(), error = %format!("{e:#}"),
                "the layer blob failed verification; refusing to repair from it"
            );
            continue;
        }

        let wanted: BTreeSet<String> = items.iter().map(|t| t.source.clone()).collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();

        let r = layers::extract_each(&blob, &wanted, |source, size, data| {
            budget::check(until)?;
            let group: Vec<&Torn> = items
                .iter()
                .copied()
                .filter(|t| t.source == source)
                .collect();
            seen.insert(source.to_string());
            repair_group(&group, size, data, from, &mut out);
            Ok(())
        });

        match r {
            Err(e) => {
                let missed = items.iter().filter(|t| !seen.contains(&t.source)).count();
                out.failed += missed;
                if let Some(h) = e.downcast_ref::<Halt>().copied() {
                    out.halted = Some(h);
                    out.failed += layers_iter.map(|(_, i)| i.len()).sum::<usize>();
                    tracing::error!(reason = %h, missed, "stopping the repair mid-layer");
                    break;
                }
                tracing::error!(
                    layer = digest, missed,
                    error = %format!("{e:#}"), "could not read the layer"
                );
            }
            Ok(_) => {
                for t in items.iter().filter(|t| !seen.contains(&t.source)) {
                    out.failed += 1;
                    tracing::error!(
                        snapshot = %t.snapshot, path = %t.path, layer = digest,
                        "the layer does not contain this path"
                    );
                }
            }
        }
    }
    out
}

/// The entry streams once, so the first name is written from it and its
/// hardlink aliases are copied from that finished file.
fn repair_group(
    group: &[&Torn],
    declared: u64,
    data: &mut dyn Read,
    from: &str,
    out: &mut Repaired,
) {
    let Some(first) = group.first() else { return };

    if declared != first.expected {
        let e = anyhow::anyhow!(
            "{} is {} bytes in the layer but {} in the index; not writing",
            first.path,
            declared,
            first.expected
        );
        for t in group {
            out.failed(t, &e);
        }
        return;
    }

    match write_in_place(first, data) {
        Ok(n) => out.fixed(first, n, from),
        Err(e) => {
            for t in group {
                out.failed(t, &e);
            }
            return;
        }
    }

    let src = first.root.join(&first.path);
    for t in &group[1..] {
        if same_inode(&src, &t.root.join(&t.path)) {
            out.fixed(t, first.expected, from);
            continue;
        }
        let r = std::fs::File::open(&src)
            .map_err(anyhow::Error::from)
            .and_then(|mut f| write_in_place(t, &mut f));
        match r {
            Ok(n) => out.fixed(t, n, from),
            Err(e) => out.failed(t, &e),
        }
    }
}

fn same_inode(a: &Path, b: &Path) -> bool {
    match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

fn write_in_place(t: &Torn, data: &mut dyn Read) -> anyhow::Result<u64> {
    let dst = t.root.join(&t.path);
    // Never through a symlink, and never creating a file.
    let md = std::fs::symlink_metadata(&dst)?;
    anyhow::ensure!(md.is_file(), "{} is not a regular file", dst.display());

    let mut f = match std::fs::OpenOptions::new().write(true).open(&dst) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(ETXTBSY) => {
            return write_replacing(t, &dst, &md, data);
        }
        Err(e) => return Err(e.into()),
    };
    let n = std::io::copy(data, &mut f)?;
    anyhow::ensure!(
        n == t.expected,
        "{} extracted {} bytes but the layer declares {}",
        t.path,
        n,
        t.expected
    );
    f.set_len(n)?;
    f.sync_all()?;
    Ok(n)
}

/// Replaces the inode, keeping mode and owner: breaks hardlinks, drops xattrs.
fn write_replacing(
    t: &Torn,
    dst: &Path,
    md: &std::fs::Metadata,
    data: &mut dyn Read,
) -> anyhow::Result<u64> {
    tracing::warn!(
        path = %t.path,
        "file is executing (ETXTBSY); replacing by rename, which splits hardlinks and drops xattrs"
    );
    let mut written = 0u64;
    edge_common::durable_write_with(dst, |f| {
        written = std::io::copy(data, f)?;
        if written != t.expected {
            return Err(std::io::Error::other(format!(
                "{} extracted {} bytes but the layer declares {}",
                t.path, written, t.expected
            )));
        }
        f.set_permissions(std::fs::Permissions::from_mode(md.permissions().mode()))?;
        // Fails without privilege, which only tests lack.
        let _ = std::os::unix::fs::fchown(&*f, Some(md.uid()), Some(md.gid()));
        f.flush()
    })?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::layer_blob;
    use std::path::PathBuf;

    fn cs(p: &Path) -> Blobs {
        Blobs::content_store(p.to_path_buf())
    }

    fn far() -> Instant {
        Instant::now() + std::time::Duration::from_secs(3600)
    }

    fn fixture(content: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let blobs = d.path().join("blobs");
        let root = d.path().join("snaps/164/fs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(
            blobs.join("sha256:a"),
            layer_blob(&[("./bin/tool", content)]),
        )
        .unwrap();
        let f = root.join("bin/tool");
        std::fs::write(&f, b"").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        (d, blobs, root)
    }

    fn torn(root: &Path, path: &str, source: &str, expected: u64) -> Torn {
        Torn {
            snapshot: "164".into(),
            namespace: "k8s.io".into(),
            root: root.to_path_buf(),
            path: path.into(),
            source: source.into(),
            on_disk: 0,
            expected,
            layer_digest: "sha256:a".into(),
            matched_by: crate::snapshots::MatchedBy::ChainId,
        }
    }

    fn tool(root: &Path, expected: u64) -> Torn {
        torn(root, "bin/tool", "bin/tool", expected)
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn rewrites_in_place_keeping_inode() {
        let (_d, blobs, root) = fixture(b"real content here");
        let f = root.join("bin/tool");
        std::fs::hard_link(&f, root.join("bin/alias")).unwrap();
        let ino = std::fs::metadata(&f).unwrap().ino();

        let r = repair_all(&cs(&blobs), &[tool(&root, 17)], far());
        assert_eq!(
            r,
            Repaired {
                fixed: 1,
                failed: 0,
                bytes: 17,
                halted: None
            }
        );
        assert_eq!(std::fs::read(&f).unwrap(), b"real content here");
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!(md.ino(), ino);
        assert_eq!(md.permissions().mode() & 0o777, 0o755);
        assert_eq!(
            std::fs::read(root.join("bin/alias")).unwrap(),
            b"real content here"
        );
        assert_eq!(
            files_in(&root.join("bin")),
            ["alias", "tool"],
            "no temp left"
        );
    }

    #[test]
    fn one_pass_repairs_whole_layer() {
        let d = tempfile::tempdir().unwrap();
        let blobs = d.path().join("blobs");
        let root = d.path().join("snaps/7/fs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let entries: Vec<(String, Vec<u8>)> = (0..20)
            .map(|i| (format!("./f{i}"), vec![b'x'; 10 + i]))
            .collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        std::fs::write(blobs.join("sha256:a"), layer_blob(&refs)).unwrap();
        let torn: Vec<Torn> = (0..20)
            .map(|i| {
                let name = format!("f{i}");
                std::fs::write(root.join(&name), b"").unwrap();
                torn(&root, &name, &name, 10 + i as u64)
            })
            .collect();
        let r = repair_all(&cs(&blobs), &torn, far());
        assert_eq!((r.fixed, r.failed, r.bytes), (20, 0, (10..30).sum()));
        for i in 0..20 {
            assert_eq!(
                std::fs::read(root.join(format!("f{i}"))).unwrap().len(),
                10 + i
            );
        }
    }

    #[test]
    fn missing_path_fails_alone() {
        let (_d, blobs, root) = fixture(b"good");
        std::fs::write(root.join("bin/missing"), b"").unwrap();
        let r = repair_all(
            &cs(&blobs),
            &[torn(&root, "bin/missing", "bin/missing", 4), tool(&root, 4)],
            far(),
        );
        assert_eq!((r.fixed, r.failed), (1, 1));
        assert_eq!(std::fs::read(root.join("bin/tool")).unwrap(), b"good");
    }

    #[test]
    fn untrusted_source_writes_nothing() {
        type Spoil = fn(&Path, &Path);
        let cases: [(&str, Spoil); 3] = [
            ("size disagrees with the index", |_, _| {}),
            ("file is missing", |_, root| {
                std::fs::remove_file(root.join("bin/tool")).unwrap()
            }),
            ("blob CRC is bad", |blobs, _| {
                let bp = blobs.join("sha256:a");
                let mut b = std::fs::read(&bp).unwrap();
                let n = b.len();
                b[n - 8] ^= 0x01;
                std::fs::write(&bp, &b).unwrap();
            }),
        ];
        for (i, (why, break_it)) in cases.into_iter().enumerate() {
            let (_d, blobs, root) = fixture(b"real content here");
            break_it(&blobs, &root);
            let expected = if i == 0 { 999 } else { 17 };
            let r = repair_all(&cs(&blobs), &[tool(&root, expected)], far());
            assert_eq!((r.fixed, r.failed), (0, 1), "{why}");
            let f = root.join("bin/tool");
            if f.exists() {
                assert_eq!(std::fs::read(&f).unwrap(), b"", "{why}");
            } else {
                assert_eq!(i, 1, "{why}: created");
            }
        }
    }

    #[test]
    fn gone_blob_fails_alone() {
        let (_d, blobs, root) = fixture(b"good");
        std::fs::write(root.join("bin/other"), b"").unwrap();
        let mut gone = torn(&root, "bin/other", "bin/other", 4);
        gone.layer_digest = "sha256:gone".into();
        let r = repair_all(&cs(&blobs), &[gone, tool(&root, 4)], far());
        assert_eq!((r.fixed, r.failed), (1, 1));
        assert_eq!(std::fs::read(root.join("bin/tool")).unwrap(), b"good");
    }

    #[test]
    fn split_hardlink_repaired_from_target() {
        let (_d, blobs, root) = fixture(b"linked bytes");
        std::fs::write(root.join("bin/alias"), b"").unwrap();
        let r = repair_all(
            &cs(&blobs),
            &[tool(&root, 12), torn(&root, "bin/alias", "bin/tool", 12)],
            far(),
        );
        assert_eq!((r.fixed, r.failed, r.bytes), (2, 0, 24));
        for f in ["bin/alias", "bin/tool"] {
            assert_eq!(std::fs::read(root.join(f)).unwrap(), b"linked bytes", "{f}");
        }
    }

    #[test]
    fn longer_file_truncated_to_layer() {
        let (_d, blobs, root) = fixture(b"short");
        let f = root.join("bin/tool");
        std::fs::write(&f, b"way longer than the layer says it should be").unwrap();
        assert_eq!(repair_all(&cs(&blobs), &[tool(&root, 5)], far()).fixed, 1);
        assert_eq!(std::fs::read(&f).unwrap(), b"short");
    }

    #[test]
    fn expired_deadline_repairs_nothing() {
        let (_d, blobs, root) = fixture(b"abc");
        let mut other = tool(&root, 3);
        other.layer_digest = "sha256:b".into();
        let r = repair_all(&cs(&blobs), &[tool(&root, 3), other], Instant::now());
        assert_eq!(
            r,
            Repaired {
                fixed: 0,
                failed: 2,
                bytes: 0,
                halted: Some(Halt::Deadline)
            }
        );
        assert_eq!(std::fs::read(root.join("bin/tool")).unwrap(), b"");
    }

    #[test]
    fn cut_mid_repair_finished_next_run() {
        let content: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
        for cut in [0usize, 1, 4095, 4096, 10_000, 19_999] {
            let (_d, blobs, root) = fixture(&content);
            let snaps = root.parent().unwrap().parent().unwrap().to_path_buf();
            let target = root.join("bin/tool");
            std::fs::write(&target, &content[..cut]).unwrap();
            std::fs::write(root.join("bin/tool.edge-layers-tmp"), &content[..10]).unwrap();

            let run = || {
                let snapset = crate::snapshots::walk(&snaps).unwrap();
                let (index, _) = layers::index_store(&cs(&blobs), far(), None, None).unwrap();
                let (torn, _) = crate::snapshots::find_torn(&snapset, &index, None);
                (torn.len(), repair_all(&cs(&blobs), &torn, far()))
            };
            let (found, r) = run();
            assert_eq!((found, r.fixed, r.failed), (1, 1, 0), "cut at {cut}");
            assert_eq!(std::fs::read(&target).unwrap(), content, "cut at {cut}");
            let (found, r) = run();
            assert_eq!((found, r), (0, Repaired::default()), "cut at {cut}");
        }
    }

    #[test]
    fn running_binary_replaced() {
        let (_d, blobs, root) = fixture(b"NEW BYTES");
        let target = root.join("bin/tool");
        let Some(sleep) = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|p| Path::new(p).exists())
        else {
            eprintln!("skipped: no sleep binary");
            return;
        };
        std::fs::copy(sleep, &target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A concurrent fork holding our write fd open makes exec see ETXTBSY.
        let mut child = None;
        for _ in 0..40 {
            match std::process::Command::new(&target).arg("30").spawn() {
                Ok(c) => {
                    child = Some(c);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        let Some(mut child) = child else {
            eprintln!("skipped: could not exec the copy");
            return;
        };
        let raw = std::fs::OpenOptions::new().write(true).open(&target);
        assert_eq!(raw.err().and_then(|e| e.raw_os_error()), Some(ETXTBSY));

        let r = repair_all(&cs(&blobs), &[tool(&root, 9)], far());
        child.kill().ok();
        child.wait().ok();
        assert_eq!((r.fixed, r.failed), (1, 0));
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW BYTES");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(files_in(&root.join("bin")), ["tool"]);
    }
}
