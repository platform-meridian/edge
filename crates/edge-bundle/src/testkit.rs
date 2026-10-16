//! Bundles packed by hand, independent of [`crate::write`], and signed for
//! [`Trusted`]: a signature is `<signer> <sha256 of the sums>`.

use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use sha2::Digest;

use crate::{SIGNATURE, SUMS, Trust};

/// The signer [`trust`] takes.
pub const SIGNER: &str = "https://github.com/test/app/.github/workflows/release.yml@refs/tags/v1";

pub struct Trusted(pub Vec<String>);

/// A trust that takes [`SIGNER`].
pub fn trust() -> Trusted {
    Trusted(vec![SIGNER.into()])
}

impl Trust for Trusted {
    fn verify(&self, sums: &[u8], signature: &[u8]) -> anyhow::Result<String> {
        let (who, sha) = std::str::from_utf8(signature)
            .ok()
            .and_then(|s| s.trim().rsplit_once(' '))
            .context("the signature is not a Sigstore bundle")?;
        ensure!(
            sha == hex::encode(sha2::Sha256::digest(sums)),
            "the signature does not verify"
        );
        ensure!(
            self.0.iter().any(|s| s == who),
            "{who} is not a signer this unit trusts"
        );
        Ok(who.into())
    }
}

/// `sums` signed as `signer`.
pub fn sign(signer: &str, sums: &[u8]) -> Vec<u8> {
    format!("{signer} {}\n", hex::encode(sha2::Sha256::digest(sums))).into_bytes()
}

const LAYOUT_INDEX: &str = r#"{"schemaVersion":2,"manifests":[
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aa","size":1,
 "annotations":{"io.containerd.image.name":"registry.example/app:v2","org.opencontainers.image.ref.name":"v2"}},
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bb","size":1,
 "annotations":{"io.containerd.image.name":"registry.example/installer@sha256:bb"}}]}"#;

/// The components of [`tree`]: a base running what its layout carries.
pub const COMPONENTS: &str =
    r#"{"base":["registry.example/app:v2","registry.example/installer@sha256:bb"]}"#;

/// A source tree of a base as a build lays it out; `seal` sums and signs it.
pub fn tree(dir: &Path, manifest: &str) {
    std::fs::create_dir_all(dir.join("images/blobs/sha256")).unwrap();
    std::fs::write(dir.join("MANIFEST"), manifest).unwrap();
    std::fs::write(dir.join("config-patch.yaml"), "version: v1alpha1\n").unwrap();
    std::fs::write(dir.join("seed.yaml"), "").unwrap();
    std::fs::write(dir.join(crate::components::COMPONENTS), COMPONENTS).unwrap();
    std::fs::write(
        dir.join("images/oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("images/index.json"), LAYOUT_INDEX).unwrap();
    std::fs::write(dir.join("images/blobs/sha256/aa"), "layer").unwrap();
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in walk(dir) {
        let rel = e.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
        if rel != SUMS && rel != SIGNATURE {
            out.push(rel);
        }
    }
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Sums every file and signs the sums as `signer`.
pub fn seal(dir: &Path, signer: &str) {
    let mut sums = String::new();
    for f in files(dir) {
        let h = sha2::Sha256::digest(std::fs::read(dir.join(&f)).unwrap());
        sums.push_str(&format!("{}  {f}\n", hex::encode(h)));
    }
    std::fs::write(dir.join(SUMS), &sums).unwrap();
    resign(dir, signer);
}

/// Signs the sums as they stand.
pub fn resign(dir: &Path, signer: &str) {
    let sums = std::fs::read(dir.join(SUMS)).unwrap();
    std::fs::write(dir.join(SIGNATURE), sign(signer, &sums)).unwrap();
}

/// The tar, `head` first, then every other file.
pub fn pack(dir: &Path, out: &Path, head: &[&str]) {
    let mut b = tar::Builder::new(std::fs::File::create(out).unwrap());
    let mut names: Vec<String> = head.iter().map(|s| s.to_string()).collect();
    for f in files(dir) {
        if !names.contains(&f) {
            names.push(f);
        }
    }
    for n in names {
        if dir.join(&n).exists() {
            b.append_path_with_name(dir.join(&n), &n).unwrap();
        }
    }
    b.finish().unwrap();
}

pub const HEAD: &[&str] = &[SUMS, SIGNATURE];
