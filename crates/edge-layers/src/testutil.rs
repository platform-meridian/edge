use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

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

fn json(p: &Path) -> Option<serde_json::Value> {
    let b = std::fs::read(p).ok()?;
    (b.first() == Some(&b'{')).then(|| serde_json::from_slice(&b).ok())?
}

/// The layer digests (hex) of each image manifest in the content store, by
/// manifest hex digest.
pub fn images(root: &Path) -> Vec<(String, Vec<String>)> {
    let cs = root.join(BLOBS);
    let mut out = Vec::new();
    for e in std::fs::read_dir(&cs).unwrap().flatten() {
        let Some(m) = json(&e.path()) else { continue };
        let Some(layers) = m.get("layers").and_then(|l| l.as_array()) else {
            continue;
        };
        let hex = |d: &serde_json::Value| d["digest"].as_str().unwrap()[7..].to_string();
        out.push((
            e.file_name().into_string().unwrap(),
            layers.iter().map(hex).collect(),
        ));
    }
    out.sort();
    out
}

/// Imports the content store's images that `keep` picks, by their layer digests,
/// into an edge-registry store at `registry`, through edge-registry itself.
pub fn registry_from(root: &Path, registry: &Path, keep: impl Fn(&[String]) -> bool) -> usize {
    let cs = root.join(BLOBS);
    let layout = root.join("layout");
    std::fs::create_dir_all(layout.join("blobs")).unwrap();
    std::os::unix::fs::symlink(&cs, layout.join("blobs/sha256")).unwrap();
    std::fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let picked: Vec<serde_json::Value> = images(root)
        .into_iter()
        .filter(|(_, layers)| keep(layers) && layers.iter().all(|l| cs.join(l).is_file()))
        .enumerate()
        .map(|(i, (m, _))| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{m}"),
                "size": std::fs::metadata(cs.join(&m)).unwrap().len(),
                "annotations": {"io.containerd.image.name": format!("example.test/img{i}:v1")},
            })
        })
        .collect();
    let n = picked.len();
    let index = serde_json::json!({"schemaVersion": 2, "manifests": picked});
    std::fs::write(layout.join("index.json"), index.to_string()).unwrap();
    edge_registry::Store::open(registry)
        .unwrap()
        .import_layout(&layout)
        .unwrap();
    std::fs::remove_dir_all(&layout).unwrap();
    n
}

/// What `discard_unpacked_layers` leaves of the content store: manifests and configs.
pub fn discard_layers(root: &Path) {
    for e in std::fs::read_dir(root.join(BLOBS)).unwrap().flatten() {
        if json(&e.path()).is_none() {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
}
