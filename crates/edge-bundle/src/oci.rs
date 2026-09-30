//! A bundle's images: one OCI image layout, every image named in its index by
//! `io.containerd.image.name`, as the unit's registry imports it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};

pub const NAME: &str = "io.containerd.image.name";
const INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// The refs an OCI image layout names, from its index.
pub fn layout_refs(layout: &Path) -> anyhow::Result<BTreeSet<String>> {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(layout.join("index.json")).context("the image layout's index")?,
    )?;
    let mut refs = BTreeSet::new();
    for m in index["manifests"]
        .as_array()
        .context("the index lists no manifests")?
    {
        let a = &m["annotations"];
        let name = a[NAME]
            .as_str()
            .or_else(|| a["org.opencontainers.image.ref.name"].as_str())
            .context("an index entry names no image")?;
        refs.insert(name.to_string());
    }
    Ok(refs)
}

/// Lays a Talos flat image cache (`talosctl images cache-create --layout
/// flat`) out at `layout`, which must not exist, with one index entry per ref.
/// Blobs are moved, not copied: the cache is spent afterwards.
pub fn from_flat_cache(flat: &Path, layout: &Path, refs: &[String]) -> anyhow::Result<()> {
    ensure!(!layout.exists(), "{} already exists", layout.display());
    let blobs = layout.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;

    let mut cached: Vec<_> = std::fs::read_dir(flat.join("blob"))
        .context("the flat cache has no blobs")?
        .collect::<Result<_, _>>()?;
    cached.sort_by_key(|e| e.file_name());
    for b in cached {
        let name = b.file_name();
        let name = name.to_string_lossy();
        let hex = name
            .strip_prefix("sha256-")
            .filter(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))
            .with_context(|| format!("{name}: not a sha256 blob"))?;
        std::fs::rename(b.path(), blobs.join(hex))?;
    }

    let put = |data: &[u8]| -> anyhow::Result<String> {
        let h = hex::encode(Sha256::digest(data));
        let p = blobs.join(&h);
        if !p.exists() {
            std::fs::write(p, data)?;
        }
        Ok(h)
    };
    // Manifests an index names are kept too: the platform's, at least.
    for f in files(&flat.join("manifests"))? {
        let parent = f.parent().and_then(Path::file_name);
        if parent.is_some_and(|p| p == "digest" || p == "reference") {
            put(&std::fs::read(&f)?)?;
        }
    }

    let mut entries = Vec::new();
    for r in refs {
        let f = flat.join("manifests").join(cache_path(r)?);
        let data =
            std::fs::read(&f).with_context(|| format!("{r}: the cache has no {}", f.display()))?;
        let h = put(&data)?;
        if let Some((_, d)) = r.split_once('@') {
            ensure!(
                d.strip_prefix("sha256:") == Some(h.as_str()),
                "{r}: its manifest hashes to sha256:{h}"
            );
        }
        let m: serde_json::Value =
            serde_json::from_slice(&data).with_context(|| format!("{r}: its manifest"))?;
        let media = m["mediaType"]
            .as_str()
            .unwrap_or(if m.get("manifests").is_some() {
                INDEX
            } else {
                MANIFEST
            });
        entries.push(serde_json::json!({
            "mediaType": media,
            "digest": format!("sha256:{h}"),
            "size": data.len(),
            "annotations": {NAME: r},
        }));
    }
    let index = serde_json::json!({"schemaVersion": 2, "manifests": entries});
    std::fs::write(
        layout.join("index.json"),
        serde_json::to_string_pretty(&index)? + "\n",
    )?;
    std::fs::write(
        layout.join("oci-layout"),
        "{\"imageLayoutVersion\":\"1.0.0\"}\n",
    )?;
    Ok(())
}

/// Where Talos's flat cache holds `r`'s manifest, under `manifests/`.
fn cache_path(r: &str) -> anyhow::Result<PathBuf> {
    let (name, digest) = match r.split_once('@') {
        Some((n, d)) => (n, Some(d.strip_prefix("sha256:").unwrap_or(d))),
        None => (r, None),
    };
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    let (last, tag) = match name[slash..].split_once(':') {
        Some((l, t)) => (l, Some(t)),
        None => (&name[slash..], None),
    };
    let name = format!("{}{last}", &name[..slash]);
    let (reg, repo) = match name.split_once('/') {
        Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => {
            (first.to_string(), rest.to_string())
        }
        _ => ("docker.io".to_string(), name.clone()),
    };
    let reg = match reg.as_str() {
        "index.docker.io" => "docker.io".to_string(),
        r => r.replace(':', "_") + if r.contains(':') { "_" } else { "" },
    };
    let repo = if reg == "docker.io" && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo
    };
    let base = Path::new(&reg).join(repo);
    Ok(match (digest, tag) {
        (Some(d), _) => base.join("digest").join(format!("sha256-{d}")),
        (None, Some(t)) => base.join("reference").join(t),
        (None, None) => bail!("{r} names neither a tag nor a digest"),
    })
}

fn files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in read {
        let e = e?;
        if e.file_type()?.is_dir() {
            out.extend(files(&e.path())?);
        } else {
            out.push(e.path());
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_land_where_talos_caches_them() {
        for (r, want) in [
            ("nginx:1", "docker.io/library/nginx/reference/1"),
            (
                "index.docker.io/nginx:1",
                "docker.io/library/nginx/reference/1",
            ),
            ("org/app:v2", "docker.io/org/app/reference/v2"),
            ("ghcr.io/org/app:v2", "ghcr.io/org/app/reference/v2"),
            ("localhost/app:v2", "localhost/app/reference/v2"),
            (
                "reg.example:5000/a/b:t",
                "reg.example_5000_/a/b/reference/t",
            ),
            ("10.0.0.1:5000/app:t", "10.0.0.1_5000_/app/reference/t"),
            (
                "ghcr.io/org/app:v2@sha256:abc",
                "ghcr.io/org/app/digest/sha256-abc",
            ),
            (
                "ghcr.io/org/app@sha256:abc",
                "ghcr.io/org/app/digest/sha256-abc",
            ),
        ] {
            assert_eq!(cache_path(r).unwrap(), Path::new(want), "{r}");
        }
        assert!(cache_path("ghcr.io/org/app").is_err());
    }
}
