//! A new OS's boot files, signed by the unit for its own firmware. Its keys
//! unseal only early in a boot, before anything else runs: the update stages
//! the verified release for the next boot to sign, then lays the signed files
//! over the installer image as one more layer.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use edge_bundle::{MANIFEST, SIGNATURE, SUMS};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::unit::Registry;

/// Where the boot signs, and where in an installer image its files go.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// The host directory the boot reads `staged/` from and writes `signed/`
    /// or `refused` into; it holds `keys` while the unit has them.
    pub dir: PathBuf,
    /// The UKI's path in the installer image.
    pub uki: String,
    /// The boot loader's path in the installer image.
    pub bootloader: String,
}

impl Settings {
    pub fn has_keys(&self) -> bool {
        self.dir.join("keys").exists()
    }
}

/// Writes a file, hashing what it writes.
struct Hashed {
    file: std::fs::File,
    hash: Sha256,
    len: u64,
}

impl std::io::Write for Hashed {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(b)?;
        self.hash.update(&b[..n]);
        self.len += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn digest_of(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "amd64",
    }
}

/// The image's manifest, this machine's of an index, and its digest.
fn image_manifest(registry: &dyn Registry, digest: &str) -> anyhow::Result<(String, Value)> {
    let manifest: Value = serde_json::from_slice(&registry.read(digest)?)?;
    let Some(children) = manifest.get("manifests").and_then(Value::as_array) else {
        return Ok((digest.into(), manifest));
    };
    let d = children
        .iter()
        .find(|c| c["platform"]["architecture"] == arch())
        .and_then(|c| c["digest"].as_str())
        .with_context(|| format!("no {} image", arch()))?;
    Ok((d.into(), serde_json::from_slice(&registry.read(d)?)?))
}

/// Stages a release (its signed sums, any signature and its MANIFEST, in
/// `release`) and the installer it pins, for the next boot to sign.
pub fn stage(
    registry: &dyn Registry,
    s: &Settings,
    release: &Path,
    installer: &str,
) -> anyhow::Result<()> {
    let (_, digest) = installer
        .split_once('@')
        .with_context(|| format!("{installer} is not pinned by digest"))?;
    let next = s.dir.join("staged.new");
    let _ = std::fs::remove_dir_all(&next);
    for old in ["staged", "signed"] {
        let _ = std::fs::remove_dir_all(s.dir.join(old));
    }
    let _ = std::fs::remove_file(s.dir.join("refused"));
    let blobs = next.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    for f in [SUMS, SIGNATURE, MANIFEST] {
        match std::fs::copy(release.join(f), next.join(f)) {
            Err(e) if f == SIGNATURE && e.kind() == std::io::ErrorKind::NotFound => {}
            r => {
                r.with_context(|| format!("the release's {f}"))?;
            }
        }
    }
    let put = |d: &str| -> anyhow::Result<()> {
        let mut out = std::fs::File::create(blobs.join(d.trim_start_matches("sha256:")))?;
        std::io::copy(&mut registry.open(d)?, &mut out)?;
        Ok(out.sync_all()?)
    };
    let (d, manifest) =
        image_manifest(registry, digest).with_context(|| format!("the installer {installer}"))?;
    for m in [digest, d.as_str()] {
        std::fs::write(
            blobs.join(m.trim_start_matches("sha256:")),
            registry.read(m)?,
        )?;
    }
    for layer in manifest["layers"]
        .as_array()
        .context("the installer has no layers")?
    {
        put(layer["digest"]
            .as_str()
            .context("a layer without a digest")?)?;
    }
    std::fs::rename(&next, s.dir.join("staged"))?;
    Ok(())
}

/// The installer the boot signed; or why it did not.
pub fn signed(s: &Settings) -> anyhow::Result<String> {
    match std::fs::read_to_string(s.dir.join("signed/INSTALLER_REF")) {
        Ok(r) => Ok(r.trim().to_string()),
        Err(_) => match std::fs::read_to_string(s.dir.join("refused")) {
            Ok(why) => bail!("{}", why.trim()),
            Err(_) => bail!("the boot left no signed files"),
        },
    }
}

/// `image` (by digest, held by `registry`) with the boot's signed files over
/// it: the derived image, imported and named by digest.
pub fn derive(
    registry: &dyn Registry,
    s: &Settings,
    image: &str,
    scratch: &Path,
) -> anyhow::Result<String> {
    let (repo, digest) = image
        .split_once('@')
        .with_context(|| format!("{image} is not pinned by digest"))?;
    let signed = signed(s)?;
    anyhow::ensure!(
        signed.ends_with(&format!("@{digest}")),
        "the boot signed {signed}, not {image}"
    );
    let (_, mut manifest) =
        image_manifest(registry, digest).with_context(|| format!("the installer {image}"))?;

    let _ = std::fs::remove_dir_all(scratch);
    let blobs = scratch.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    // Streamed to a file: a UKI is large.
    let mut layer = tar::Builder::new(Hashed {
        file: std::fs::File::create(scratch.join("layer"))?,
        hash: Sha256::new(),
        len: 0,
    });
    for path in [&s.uki, &s.bootloader] {
        let name = Path::new(path).file_name().context("a boot file path")?;
        let mut f = std::fs::File::open(s.dir.join("signed").join(name))?;
        let mut h = tar::Header::new_gnu();
        h.set_size(f.metadata()?.len());
        h.set_mode(0o644);
        h.set_cksum();
        layer.append_data(&mut h, path.trim_start_matches('/'), &mut f)?;
    }
    let layer = layer.into_inner()?;
    let layer_digest = format!("sha256:{}", hex::encode(layer.hash.finalize()));
    let layer_size = layer.len;
    layer.file.sync_all()?;
    std::fs::rename(scratch.join("layer"), blobs.join(&layer_digest[7..]))?;

    let mut config: Value = serde_json::from_slice(
        &registry.read(
            manifest["config"]["digest"]
                .as_str()
                .context("no config digest")?,
        )?,
    )?;
    config["rootfs"]["diff_ids"]
        .as_array_mut()
        .context("the config has no diff_ids")?
        .push(json!(layer_digest));
    if let Some(h) = config.get_mut("history").and_then(Value::as_array_mut) {
        h.push(json!({"created_by": "edge-update: boot files signed by the unit"}));
    }
    let config = serde_json::to_vec(&config)?;
    let docker = manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json";
    manifest["config"]["digest"] = json!(digest_of(&config));
    manifest["config"]["size"] = json!(config.len());
    manifest["layers"]
        .as_array_mut()
        .context("no layers")?
        .push(json!({
            "mediaType": if docker {
                "application/vnd.docker.image.rootfs.diff.tar"
            } else {
                "application/vnd.oci.image.layer.v1.tar"
            },
            "digest": layer_digest,
            "size": layer_size,
        }));
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_digest = digest_of(&manifest_bytes);

    for b in [&config, &manifest_bytes] {
        std::fs::write(blobs.join(&digest_of(b)[7..]), b)?;
    }
    std::fs::write(
        scratch.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )?;
    let media_type = manifest["mediaType"]
        .as_str()
        .unwrap_or("application/vnd.oci.image.manifest.v1+json");
    std::fs::write(
        scratch.join("index.json"),
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": media_type, "digest": manifest_digest, "size": manifest_bytes.len(),
                "annotations": {"io.containerd.image.name": format!("{repo}:unit-signed")},
            }],
        }))?,
    )?;
    registry.import(scratch)?;
    let _ = std::fs::remove_dir_all(scratch);
    Ok(format!("{repo}@{manifest_digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry as Store;
    use std::io::Read;

    fn targz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, contents) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(contents.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, path, *contents).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn a_release_is_staged_then_its_signed_files_laid_over_the_installer() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store")).unwrap();
        let layout = dir.path().join("layout");
        let blobs = layout.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        let put = |b: &[u8]| {
            std::fs::write(blobs.join(&digest_of(b)[7..]), b).unwrap();
            json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest_of(b), "size": b.len()})
        };
        let layers = [
            put(&targz(&[("usr/bin/installer", b"#!")])),
            put(&targz(&[
                ("usr/install/amd64/vmlinuz.efi", b"uki"),
                ("usr/install/amd64/systemd-boot.efi", b"boot"),
            ])),
        ];
        let config = put(
            br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:aa","sha256:bb"]},"history":[]}"#,
        );
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config, "layers": layers,
        }))
        .unwrap();
        put(&manifest);
        std::fs::write(
            layout.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            layout.join("index.json"),
            serde_json::to_vec(&json!({"schemaVersion": 2, "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest_of(&manifest),
                "size": manifest.len(), "annotations": {"io.containerd.image.name": "127.0.0.1:5000/installer:v1"}}]}))
            .unwrap(),
        )
        .unwrap();
        store.import(&layout).unwrap();

        let release = dir.path().join("release");
        std::fs::create_dir_all(&release).unwrap();
        for f in [SUMS, MANIFEST] {
            std::fs::write(release.join(f), f).unwrap();
        }
        let s = Settings {
            dir: dir.path().join("boot-signing"),
            uki: "/usr/install/amd64/vmlinuz.efi".into(),
            bootloader: "/usr/install/amd64/systemd-boot.efi".into(),
        };
        std::fs::create_dir_all(&s.dir).unwrap();
        let image = format!("127.0.0.1:5000/installer@{}", digest_of(&manifest));
        stage(&store, &s, &release, &image).unwrap();
        let staged = s.dir.join("staged");
        assert!(!staged.join(SIGNATURE).exists());
        assert_eq!(
            std::fs::read(staged.join(MANIFEST)).unwrap(),
            MANIFEST.as_bytes()
        );
        for d in [
            digest_of(&manifest).as_str(),
            layers[0]["digest"].as_str().unwrap(),
            layers[1]["digest"].as_str().unwrap(),
        ] {
            assert!(staged.join("blobs/sha256").join(&d[7..]).exists(), "{d}");
        }

        let scratch = dir.path().join("scratch");
        assert!(derive(&store, &s, &image, &scratch).is_err());
        std::fs::write(s.dir.join("refused"), "the release is unsigned\n").unwrap();
        let e = derive(&store, &s, &image, &scratch).unwrap_err();
        assert_eq!(e.to_string(), "the release is unsigned");

        let signed = s.dir.join("signed");
        std::fs::create_dir_all(&signed).unwrap();
        std::fs::write(signed.join("vmlinuz.efi"), b"signed uki").unwrap();
        std::fs::write(signed.join("systemd-boot.efi"), b"signed boot").unwrap();
        std::fs::write(
            signed.join("INSTALLER_REF"),
            "127.0.0.1:5000/installer@sha256:00\n",
        )
        .unwrap();
        assert!(derive(&store, &s, &image, &scratch).is_err());

        std::fs::write(signed.join("INSTALLER_REF"), format!("{image}\n")).unwrap();
        let derived = derive(&store, &s, &image, &scratch).unwrap();
        assert!(derived.starts_with("127.0.0.1:5000/installer@sha256:"));
        let d = store.digest(&derived).unwrap();
        let m: Value = serde_json::from_slice(&store.read(&d).unwrap()).unwrap();
        let layers = m["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 3);
        let top = store.read(layers[2]["digest"].as_str().unwrap()).unwrap();
        let mut files = Vec::new();
        for e in tar::Archive::new(top.as_slice()).entries().unwrap() {
            let mut e = e.unwrap();
            let mut b = String::new();
            e.read_to_string(&mut b).unwrap();
            files.push((e.path().unwrap().to_string_lossy().to_string(), b));
        }
        assert_eq!(
            files,
            [
                ("usr/install/amd64/vmlinuz.efi".into(), "signed uki".into()),
                (
                    "usr/install/amd64/systemd-boot.efi".into(),
                    "signed boot".into()
                )
            ]
        );
        let c: Value =
            serde_json::from_slice(&store.read(m["config"]["digest"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(c["rootfs"]["diff_ids"][2], layers[2]["digest"]);
    }
}
