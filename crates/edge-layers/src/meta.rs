//! The snapshotter's metadata.db keeps each committed snapshot in `v1/snapshots` under
//! `<namespace>/<txid>/<chainID>`. A chainID names one layer at one position in one
//! stack, so snapshots whose layers share a path set stay distinct.

use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use sha2::{Digest, Sha256};

use crate::bolt::{Db, Value};

/// containerd's `snapshots.KindCommitted`.
const KIND_COMMITTED: u8 = 3;
/// Manifests and configs are small; anything larger is a layer.
const MAX_JSON: u64 = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Content-store blobs (hex digests) holding the layer; empty when no
    /// manifest in the store names this chainID.
    Layer {
        chain_id: String,
        namespace: String,
        blobs: Vec<String>,
    },
    /// Active or view: a container's read-write layer or a mount in progress.
    NotALayer,
}

pub type Provenance = HashMap<String, Origin>;

pub fn read(snapshotter_root: &Path, blobs: &Path) -> anyhow::Result<Provenance> {
    let db = Db::read(&snapshotter_root.join("metadata.db"))?;
    let chains = chain_ids_by_snapshot(&db)?;
    let layers = blobs_by_chain_id(blobs);
    Ok(chains
        .into_iter()
        .map(|(id, chain)| {
            let origin = match chain {
                Some((namespace, chain_id)) => Origin::Layer {
                    blobs: layers.get(&chain_id).cloned().unwrap_or_default(),
                    namespace,
                    chain_id,
                },
                None => Origin::NotALayer,
            };
            (id, origin)
        })
        .collect())
}

fn uvarint(b: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for (i, &byte) in b.iter().enumerate().take(10) {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

type Chain = Option<(String, String)>;

fn chain_ids_by_snapshot(db: &Db) -> anyhow::Result<HashMap<String, Chain>> {
    let snaps = db
        .path(&[b"v1", b"snapshots"])?
        .context("no v1/snapshots bucket")?;
    let mut out = HashMap::new();
    for (key, v) in db.entries(snaps)? {
        let Value::Bucket(b) = v else { continue };
        let (Some(id), Some(kind)) = (db.get(b, b"id")?.and_then(uvarint), db.get(b, b"kind")?)
        else {
            continue;
        };
        let name = String::from_utf8_lossy(key);
        let mut parts = name.splitn(3, '/');
        let (ns, chain) = (parts.next(), parts.nth(1));
        let chain = (kind == [KIND_COMMITTED])
            .then(|| Some((ns?.to_string(), chain?.to_string())))
            .flatten();
        out.insert(id.to_string(), chain);
    }
    Ok(out)
}

pub fn chain_ids(diff_ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(diff_ids.len());
    for d in diff_ids {
        let next = match out.last() {
            None => d.clone(),
            Some(parent) => Sha256::digest(format!("{parent} {d}"))
                .iter()
                .fold("sha256:".to_string(), |hex, b| hex + &format!("{b:02x}")),
        };
        out.push(next);
    }
    out
}

fn read_json(blobs: &Path, digest: &str) -> Option<serde_json::Value> {
    let hex = digest.strip_prefix("sha256:")?;
    let mut f = std::fs::File::open(blobs.join(hex)).ok()?;
    let mut buf = vec![0u8];
    f.read_exact(&mut buf).ok()?;
    if buf[0] != b'{' {
        return None;
    }
    // Anything longer is cut short and fails to parse.
    f.take(MAX_JSON).read_to_end(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// OCI and Docker schema 2 share the fields read here. A chainID can have
/// several blobs: one layer compressed two ways.
fn blobs_by_chain_id(blobs: &Path) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    let Ok(rd) = std::fs::read_dir(blobs) else {
        return HashMap::new();
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(manifest) = read_json(blobs, &format!("sha256:{name}")) else {
            continue;
        };
        let (Some(layers), Some(cfg)) = (
            manifest.get("layers").and_then(|l| l.as_array()),
            manifest.pointer("/config/digest").and_then(|d| d.as_str()),
        ) else {
            continue;
        };
        let Some(diff_ids) = read_json(blobs, cfg).and_then(|c| {
            c.pointer("/rootfs/diff_ids")?
                .as_array()?
                .iter()
                .map(|d| d.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
        }) else {
            continue;
        };
        if diff_ids.len() != layers.len() {
            continue;
        }
        for (chain, layer) in chain_ids(&diff_ids).into_iter().zip(layers) {
            let Some(hex) = layer
                .get("digest")
                .and_then(|d| d.as_str())
                .and_then(|d| d.strip_prefix("sha256:"))
            else {
                continue;
            };
            out.entry(chain).or_default().insert(hex.to_string());
        }
    }
    out.into_iter()
        .map(|(c, b)| (c, b.into_iter().collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{BLOBS, IMAGECACHE, SNAPSHOTTER, fixture_root};

    #[test]
    fn chain_ids_match_containerd() {
        // From containerd's `identity.ChainID`, printed by the fixture generator.
        let base = "sha256:3b6629ca18feec55ec96c7b3c5fedf343485f9ea99c92de2173d706bb11ef10d";
        let ca = "sha256:c6fb523ffc4b74a2cad1cb6c137c7b2b3d9e042fa29c86e5494a916cff7cb788";
        assert_eq!(
            chain_ids(&[base.into(), ca.into()]),
            [
                base,
                "sha256:5907c3830708dc105e69f8597dd518487b648a497d4401698cfcbf5d2c499d14"
            ]
        );
        assert!(chain_ids(&[]).is_empty());
    }

    fn layer<'a>(p: &'a Provenance, id: &str) -> (&'a str, &'a str, &'a [String]) {
        match &p[id] {
            Origin::Layer {
                chain_id,
                namespace,
                blobs,
            } => (chain_id, namespace, blobs),
            o => panic!("{id}: {o:?}"),
        }
    }

    #[test]
    fn traces_every_snapshot_to_layer() {
        let root = fixture_root();
        let store = root.path().join(BLOBS);
        let p = read(&root.path().join(SNAPSHOTTER), &store).unwrap();
        let mut ids: Vec<_> = p.keys().map(|k| k.parse::<u32>().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, (1..=11).collect::<Vec<_>>());
        assert_eq!(p["7"], Origin::NotALayer);

        let mut seen = std::collections::HashSet::new();
        for id in ["1", "2", "3", "4", "5", "6"] {
            let (chain_id, namespace, blobs) = layer(&p, id);
            assert!(chain_id.starts_with("sha256:"), "{id}");
            assert_eq!(namespace, "k8s.io", "{id}");
            assert_eq!(blobs.len(), 1, "{id}");
            assert!(store.join(&blobs[0]).is_file());
            assert!(
                seen.insert(blobs[0].clone()),
                "{id}: two snapshots share a blob"
            );
        }
        assert_eq!(
            p["2"],
            Origin::Layer {
                chain_id: "sha256:5907c3830708dc105e69f8597dd518487b648a497d4401698cfcbf5d2c499d14"
                    .into(),
                namespace: "k8s.io".into(),
                blobs: vec![
                    "3cff7b92da8658db032d9477ecf4204ae9e4b5ec58979449eb721e7232b6e4a9".into()
                ],
            }
        );

        // The system namespace: a second snapshot of img1's chain, sharing its blobs.
        for (k8s, system) in [("1", "8"), ("2", "9")] {
            let (chain, ns, blobs) = layer(&p, system);
            assert_eq!(ns, "system");
            assert_eq!((chain, blobs), (layer(&p, k8s).0, layer(&p, k8s).2));
        }
        // Its own image: containerd's GC took the layer blobs, the manifest
        // still names them.
        for id in ["10", "11"] {
            let (_, ns, blobs) = layer(&p, id);
            assert_eq!(ns, "system");
            assert_eq!(blobs.len(), 1, "{id}");
            assert!(!store.join(&blobs[0]).exists(), "{id}");
            let cached = root.path().join(IMAGECACHE).join("blob");
            assert!(
                cached.join(format!("sha256-{}", blobs[0])).is_file(),
                "{id}"
            );
        }
    }

    #[test]
    fn missing_manifest_means_no_blobs() {
        let root = fixture_root();
        let blobs = root.path().join(BLOBS);
        for e in std::fs::read_dir(&blobs).unwrap().flatten() {
            if std::fs::read(e.path()).unwrap().first() == Some(&b'{') {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        let p = read(&root.path().join(SNAPSHOTTER), &blobs).unwrap();
        assert!(matches!(&p["2"], Origin::Layer { blobs, .. } if blobs.is_empty()));
    }

    #[test]
    fn uvarint_decodes_go_encoding() {
        assert_eq!(uvarint(&[0x07]), Some(7));
        assert_eq!(uvarint(&[0x80, 0x01]), Some(128));
        assert_eq!(uvarint(&[0xac, 0x02]), Some(300));
        assert_eq!(uvarint(&[0x80]), None);
        assert_eq!(uvarint(&[]), None);
    }
}
