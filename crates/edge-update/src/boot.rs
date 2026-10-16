//! A new OS's boot files, signed by the unit for its own firmware: the
//! installer image a verified release names, with its UKI and boot loader
//! re-signed by the unit's keys laid over it as one more layer.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use edge_boot::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::unit::Registry;

/// Where the unit's boot signing keys are, and what in an installer image they sign.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// The TPM holding the keys ([`edge_boot::tpm`]).
    pub tpm: PathBuf,
    pub phases: edge_boot::Phases,
    /// The UKI's path in the installer image.
    pub uki: String,
    /// The boot loader's path in the installer image.
    pub bootloader: String,
}

/// The unit's boot signing keys, unlocked for one signing; `None` if it has none.
pub trait Keys: Send + Sync {
    fn unlock(&self) -> anyhow::Result<Option<Box<dyn Signer>>>;
}

pub struct Tpm(pub PathBuf);

impl Keys for Tpm {
    fn unlock(&self) -> anyhow::Result<Option<Box<dyn Signer>>> {
        Ok(edge_boot::tpm::TpmKeys::open(&self.0)?.map(|k| Box::new(k) as Box<dyn Signer>))
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

/// `image` (by digest, held by `registry`) with its boot files signed: the
/// derived image, imported and named by digest.
pub fn derive(
    registry: &dyn Registry,
    signer: &dyn Signer,
    s: &Settings,
    image: &str,
    scratch: &Path,
) -> anyhow::Result<String> {
    let (repo, _) = image
        .split_once('@')
        .with_context(|| format!("{image} is not pinned by digest"))?;
    let mut digest = registry
        .digest(image)
        .with_context(|| format!("the unit holds no {image}"))?;
    let mut manifest: Value = serde_json::from_slice(&registry.read(&digest)?)?;
    if let Some(children) = manifest.get("manifests").and_then(Value::as_array) {
        digest = children
            .iter()
            .find(|c| c["platform"]["architecture"] == arch())
            .and_then(|c| c["digest"].as_str())
            .with_context(|| format!("{image} has no {} image", arch()))?
            .to_string();
        manifest = serde_json::from_slice(&registry.read(&digest)?)?;
    }

    let mut files: [Option<Vec<u8>>; 2] = [None, None];
    let wanted = [
        s.uki.trim_start_matches('/'),
        s.bootloader.trim_start_matches('/'),
    ];
    for layer in manifest["layers"]
        .as_array()
        .context("the installer has no layers")?
    {
        let d = layer["digest"]
            .as_str()
            .context("a layer without a digest")?;
        let mut blob = registry.open(d)?;
        let mut magic = [0u8; 2];
        blob.read_exact(&mut magic)?;
        let blob = std::io::Cursor::new(magic).chain(blob);
        let tar: Box<dyn Read> = match magic {
            [0x1f, 0x8b] => Box::new(flate2::read::GzDecoder::new(blob)),
            _ => Box::new(blob),
        };
        let mut tar = tar::Archive::new(tar);
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry
                .path()?
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string();
            if let Some(i) = wanted.iter().position(|w| *w == path) {
                let mut b = Vec::new();
                entry.read_to_end(&mut b)?;
                files[i] = Some(b);
            }
        }
    }
    let [Some(uki), Some(bootloader)] = files else {
        bail!("{image} has no {} or {}", s.uki, s.bootloader);
    };
    let _ = std::fs::remove_dir_all(scratch);
    let blobs = scratch.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    // The layer streams to a file: a UKI is large, and signing it holds it twice already.
    let mut layer = tar::Builder::new(Hashed {
        file: std::fs::File::create(scratch.join("layer"))?,
        hash: Sha256::new(),
        len: 0,
    });
    let signed = [
        edge_boot::sign_uki(signer, uki, &s.phases).context("signing the UKI")?,
        edge_boot::sign_image(signer, bootloader).context("signing the boot loader")?,
    ];
    for (path, contents) in wanted.iter().zip(signed) {
        let mut h = tar::Header::new_gnu();
        h.set_size(contents.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        layer.append_data(&mut h, path, contents.as_slice())?;
    }
    let layer = layer.into_inner()?;
    let layer_digest = format!("sha256:{}", hex::encode(layer.hash.finalize()));
    let layer_size = layer.len;
    layer.file.sync_all()?;
    std::fs::rename(scratch.join("layer"), blobs.join(&layer_digest[7..]))?;

    let config_desc = &manifest["config"];
    let mut config: Value = serde_json::from_slice(
        &registry.read(config_desc["digest"].as_str().context("no config digest")?)?,
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
            "manifests": [{"mediaType": media_type, "digest": manifest_digest, "size": manifest_bytes.len()}],
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
    use edge_boot::testkit::{Soft, image, uki};

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
    fn the_installer_gets_a_layer_of_its_boot_files_signed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store")).unwrap();
        let layout = dir.path().join("layout");
        let blobs = layout.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        let put = |b: &[u8]| {
            std::fs::write(blobs.join(&digest_of(b)[7..]), b).unwrap();
            json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest_of(b), "size": b.len()})
        };
        let boot = image(&[(".text", &[0xc3; 600]), (".sbat", b"sbat,1\n")]);
        let layers = [
            put(&targz(&[("usr/bin/installer", b"#!")])),
            put(&targz(&[
                ("usr/install/amd64/vmlinuz.efi", &uki()),
                ("usr/install/amd64/systemd-boot.efi", &boot),
            ])),
        ];
        let config = put(br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:aa","sha256:bb"]},"history":[]}"#);
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

        let soft = Soft::default();
        let settings = Settings {
            tpm: "/dev/null".into(),
            phases: edge_boot::Phases {
                signed: vec!["a:b".into()],
                running: "a:b:c".into(),
            },
            uki: "/usr/install/amd64/vmlinuz.efi".into(),
            bootloader: "/usr/install/amd64/systemd-boot.efi".into(),
        };
        let image = format!("127.0.0.1:5000/installer@{}", digest_of(&manifest));
        let derived = derive(
            &store,
            &soft,
            &settings,
            &image,
            &dir.path().join("scratch"),
        )
        .unwrap();
        assert!(derived.starts_with("127.0.0.1:5000/installer@sha256:"));
        assert_eq!(soft.granted.lock().unwrap().len(), 1);

        let d = store.digest(&derived).unwrap();
        let m: Value = serde_json::from_slice(&store.read(&d).unwrap()).unwrap();
        let layers = m["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 3);
        let top = store.read(layers[2]["digest"].as_str().unwrap()).unwrap();
        let mut names = Vec::new();
        for e in tar::Archive::new(top.as_slice()).entries().unwrap() {
            let mut e = e.unwrap();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            let pe = edge_boot::pe::Pe::parse(&b).unwrap();
            assert!(pe.sections.len() > 1);
            names.push(e.path().unwrap().to_string_lossy().to_string());
        }
        assert_eq!(
            names,
            [
                "usr/install/amd64/vmlinuz.efi",
                "usr/install/amd64/systemd-boot.efi"
            ]
        );
        let c: Value =
            serde_json::from_slice(&store.read(m["config"]["digest"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(c["rootfs"]["diff_ids"][2], layers[2]["digest"]);
    }
}
