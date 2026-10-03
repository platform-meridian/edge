//! Bundles sealed with ssh-keygen and packed by hand, as a build shell does:
//! a producer independent of [`crate::write`], and one that can misbehave.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const NAMESPACE: &str = "test-update";

pub fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
    let key = dir.join(name);
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
        .arg(&key)
        .status()
        .expect("ssh-keygen");
    assert!(st.success());
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    (key, public)
}

pub fn sign(key: &Path, file: &Path, namespace: &str) {
    let _ = std::fs::remove_file(file.with_extension("sig"));
    let st = Command::new("ssh-keygen")
        .args(["-q", "-Y", "sign", "-n", namespace, "-f"])
        .arg(key)
        .arg(file)
        .status()
        .expect("ssh-keygen");
    assert!(st.success());
}

const LAYOUT_INDEX: &str = r#"{"schemaVersion":2,"manifests":[
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aa","size":1,
 "annotations":{"io.containerd.image.name":"registry.example/app:v2","org.opencontainers.image.ref.name":"v2"}},
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bb","size":1,
 "annotations":{"io.containerd.image.name":"registry.example/installer@sha256:bb"}}]}"#;

/// A source tree as a build lays it out; `seal` sums and signs it.
pub fn tree(dir: &Path, manifest: &str) {
    std::fs::create_dir_all(dir.join("images/blobs/sha256")).unwrap();
    std::fs::write(dir.join("MANIFEST"), manifest).unwrap();
    std::fs::write(dir.join("config-patch.yaml"), "version: v1alpha1\n").unwrap();
    std::fs::write(dir.join("seed.yaml"), "").unwrap();
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
        if rel != "SHA256SUMS" && rel != "SHA256SUMS.sig" {
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

pub fn seal(dir: &Path, key: &Path, namespace: &str) {
    use sha2::Digest;
    let mut sums = String::new();
    for f in files(dir) {
        let h = sha2::Sha256::digest(std::fs::read(dir.join(&f)).unwrap());
        sums.push_str(&format!("{}  {f}\n", hex::encode(h)));
    }
    std::fs::write(dir.join("SHA256SUMS"), sums).unwrap();
    sign(key, &dir.join("SHA256SUMS"), namespace);
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

pub const HEAD: &[&str] = &["SHA256SUMS", "SHA256SUMS.sig"];
