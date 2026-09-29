use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::layers::{Entry, Layer};
use crate::snapshots::{OnDisk, Snapshot};

pub enum Item<'a> {
    File(&'a str, &'a [u8]),
    Link(&'a str, &'a str),
}

fn build<W: std::io::Write>(w: W, items: &[Item]) -> W {
    let mut ar = tar::Builder::new(w);
    for item in items {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o755);
        match item {
            Item::File(p, data) => {
                h.set_size(data.len() as u64);
                h.set_cksum();
                ar.append_data(&mut h, p, *data).unwrap();
            }
            Item::Link(p, target) => {
                h.set_size(0);
                h.set_entry_type(tar::EntryType::Link);
                h.set_link_name(target).unwrap();
                h.set_cksum();
                ar.append_data(&mut h, p, std::io::empty()).unwrap();
            }
        }
    }
    ar.into_inner().unwrap()
}

pub fn tar(items: &[Item]) -> Vec<u8> {
    build(Vec::new(), items)
}

pub fn tar_gz(items: &[Item]) -> Vec<u8> {
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    build(enc, items).finish().unwrap()
}

pub fn layer_blob(files: &[(&str, &[u8])]) -> Vec<u8> {
    let items: Vec<Item> = files.iter().map(|(p, d)| Item::File(p, d)).collect();
    tar_gz(&items)
}

pub fn layer(digest: &str, files: &[(&str, u64)]) -> Layer {
    Layer {
        digest: digest.into(),
        files: files
            .iter()
            .map(|(p, s)| ((*p).to_string(), Entry { size: *s }))
            .collect::<HashMap<_, _>>(),
        links: BTreeMap::new(),
    }
}

pub fn snap(id: &str, files: &[(&str, u64)]) -> Snapshot {
    Snapshot {
        id: id.into(),
        root: PathBuf::from("/nowhere"),
        files: files
            .iter()
            .map(|(p, s)| OnDisk {
                path: (*p).to_string(),
                size: *s,
            })
            .collect(),
        stale_temps: vec![],
        incomplete: false,
    }
}

pub const BLOBS: &str = "io.containerd.content.v1.content/blobs/sha256";
pub const SNAPSHOTTER: &str = "io.containerd.snapshotter.v1.overlayfs";
pub const IMAGECACHE: &str = "imagecache";
pub const SNAPS: &str = "io.containerd.snapshotter.v1.overlayfs/snapshots";

/// A containerd root written by containerd's own code (testdata/fixturegen): snapshots
/// 1/3/5 are base layers, 2/4/6 a ca-certificates layer above each (one path set,
/// three contents), 7 a container's rw layer; plus `bolt-large.db`.
pub fn fixture_root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let gz = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/containerd-root.tar.gz"
    ))
    .unwrap();
    tar::Archive::new(flate2::read::GzDecoder::new(&gz[..]))
        .unpack(d.path())
        .unwrap();
    d
}

pub const CA: &str = "etc/ssl/certs/ca-certificates.crt";
