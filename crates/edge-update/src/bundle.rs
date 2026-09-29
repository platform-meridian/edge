//! A bundle is one tar: `SHA256SUMS`, then its SSH signature, then every file
//! the sums name. Nothing past the first two entries is written anywhere until
//! the signature has verified against the pinned key.
//!
//! - `MANIFEST`: `KEY=value` lines. `FORMAT=2`, `STACK_TAG`, `STACK_DIGEST`,
//!   `INSTALLER_REF` (by digest), `TALOS_VERSION`, `BUILT_EPOCH` (the version
//!   anti-rollback compares), `SECUREBOOT`; optionally `STACK_PATH`, and
//!   `LOCK_<KEY>=v`, which the unit's stack lock must match.
//! - `config-patch.yaml`: the machine config without what the unit keeps
//!   (`machineconfig`).
//! - `seed.yaml`: objects applied server-side before the stack moves.
//! - `images/`: an OCI image layout holding every image, the installer and the
//!   stack artifact, each named in its index by `io.containerd.image.name`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};
use ssh_key::{PublicKey, SshSig};

pub const SUMS: &str = "SHA256SUMS";
pub const SIG: &str = "SHA256SUMS.sig";
pub const MANIFEST: &str = "MANIFEST";
pub const PATCH: &str = "config-patch.yaml";
pub const SEED: &str = "seed.yaml";
pub const IMAGES: &str = "images";

const MAX_SUMS: u64 = 64 << 20;
const MAX_SIG: u64 = 64 << 10;

#[derive(Clone)]
pub struct Signer {
    key: PublicKey,
    namespace: String,
}

impl Signer {
    pub fn new(openssh: &str, namespace: &str) -> anyhow::Result<Self> {
        let key = PublicKey::from_openssh(openssh.trim()).context("the pinned update key")?;
        ensure!(!namespace.is_empty(), "no signature namespace");
        Ok(Self {
            key,
            namespace: namespace.into(),
        })
    }

    pub fn verify(&self, msg: &[u8], armored: &[u8]) -> anyhow::Result<()> {
        let sig = SshSig::from_pem(armored).context("the signature is not an SSH signature")?;
        self.key.verify(&self.namespace, msg, &sig).map_err(|e| {
            anyhow::anyhow!("the signature does not verify against the pinned update key: {e}")
        })
    }
}

pub type Manifest = BTreeMap<String, String>;

pub fn parse_manifest(text: &str) -> anyhow::Result<Manifest> {
    let mut m = Manifest::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("MANIFEST line {line:?} is not KEY=value"))?;
        ensure!(
            !k.is_empty()
                && k.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            "MANIFEST key {k:?} is not KEY"
        );
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "MANIFEST names {k} twice"
        );
    }
    Ok(m)
}

fn parse_sums(text: &str) -> anyhow::Result<BTreeMap<PathBuf, [u8; 32]>> {
    let mut sums = BTreeMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (hash, path) = line
            .split_once("  ")
            .with_context(|| format!("{SUMS} line {line:?} is not `<sha256>  <path>`"))?;
        let mut h = [0u8; 32];
        hex::decode_to_slice(hash, &mut h)
            .with_context(|| format!("{SUMS}: {hash:?} is not a sha256"))?;
        let path = safe(Path::new(path))?;
        ensure!(
            path != Path::new(SUMS) && path != Path::new(SIG),
            "{SUMS} names itself or its signature"
        );
        ensure!(
            sums.insert(path.clone(), h).is_none(),
            "{SUMS} names {} twice",
            path.display()
        );
    }
    Ok(sums)
}

fn safe(path: &Path) -> anyhow::Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(p) => out.push(p),
            _ => bail!("{} is not a plain relative path", path.display()),
        }
    }
    ensure!(!out.as_os_str().is_empty(), "an empty path");
    Ok(out)
}

fn read_small(entry: &mut impl Read, size: u64, max: u64, what: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(size <= max, "{what} is {size} bytes, more than {max}");
    let mut buf = Vec::with_capacity(size as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Verifies `tar` against `signer` and unpacks it into `dest`, which must not
/// exist. On any failure `dest` is removed.
pub fn unpack(tar: &Path, dest: &Path, signer: &Signer) -> anyhow::Result<Manifest> {
    ensure!(!dest.exists(), "{} already exists", dest.display());
    let r = unpack_into(tar, dest, signer);
    if r.is_err() {
        let _ = std::fs::remove_dir_all(dest);
    }
    r
}

fn unpack_into(tar: &Path, dest: &Path, signer: &Signer) -> anyhow::Result<Manifest> {
    let mut archive = tar::Archive::new(File::open(tar).context("open the bundle")?);
    let mut entries = archive.entries().context("the bundle is not a tar")?;

    let mut next = |want: &str, max: u64| -> anyhow::Result<Vec<u8>> {
        let mut e = entries
            .next()
            .with_context(|| format!("the bundle ends before {want}"))??;
        let path = e.path()?.into_owned();
        ensure!(
            path == Path::new(want) && e.header().entry_type().is_file(),
            "the bundle must start with {SUMS} then {SIG}, not {}",
            path.display()
        );
        let size = e.size();
        read_small(&mut e, size, max, want)
    };
    let sums_bytes = next(SUMS, MAX_SUMS)?;
    let sig = next(SIG, MAX_SIG)?;
    signer.verify(&sums_bytes, &sig)?;
    let sums = parse_sums(std::str::from_utf8(&sums_bytes).context("the sums are not text")?)?;
    for need in [MANIFEST, PATCH, SEED] {
        ensure!(
            sums.contains_key(Path::new(need)),
            "the signed sums do not cover {need}"
        );
    }

    std::fs::create_dir_all(dest)?;
    let mut seen = BTreeSet::new();
    for e in entries {
        let mut e = e?;
        let path = safe(&e.path()?)?;
        let kind = e.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        ensure!(kind.is_file(), "{} is not a regular file", path.display());
        let want = sums
            .get(&path)
            .with_context(|| format!("{} is not in the signed sums", path.display()))?;
        ensure!(
            seen.insert(path.clone()),
            "{} appears twice",
            path.display()
        );
        let out = dest.join(&path);
        if let Some(dir) = out.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = File::create(&out)?;
        let mut hash = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = e.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
            f.write_all(&buf[..n])?;
        }
        ensure!(
            hash.finalize().as_slice() == want,
            "{} does not match the signed sums",
            path.display()
        );
    }
    if let Some(missing) = sums.keys().find(|p| !seen.contains(*p)) {
        bail!(
            "the bundle lacks {}, which the signed sums name",
            missing.display()
        );
    }
    sync_fs(dest)?;
    parse_manifest(&std::fs::read_to_string(dest.join(MANIFEST))?)
}

/// One syncfs for the whole unpack rather than an fsync per blob.
pub fn sync_fs(dir: &Path) -> anyhow::Result<()> {
    let d = File::open(dir)?;
    nix::unistd::syncfs(&d).context("syncfs")?;
    Ok(())
}

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
        let name = a["io.containerd.image.name"]
            .as_str()
            .or_else(|| a["org.opencontainers.image.ref.name"].as_str())
            .context("an index entry names no image")?;
        refs.insert(name.to_string());
    }
    Ok(refs)
}

#[cfg(test)]
pub mod testkit {
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

    pub const LAYOUT_INDEX: &str = r#"{"schemaVersion":2,"manifests":[
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

    pub fn files(dir: &Path) -> Vec<String> {
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

    /// The tar, in the order a build writes it; `order` overrides the head.
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
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    const MF: &str = "FORMAT=2\nSTACK_TAG=t2\n";

    struct Case {
        dir: tempfile::TempDir,
        public: String,
        key: PathBuf,
    }

    impl Case {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (key, public) = keygen(dir.path(), "good");
            tree(&dir.path().join("src"), MF);
            seal(&dir.path().join("src"), &key, NAMESPACE);
            Self { dir, public, key }
        }
        fn src(&self) -> PathBuf {
            self.dir.path().join("src")
        }
        fn open(&self, head: &[&str]) -> anyhow::Result<Manifest> {
            self.open_with(head, &self.public, NAMESPACE)
        }
        fn open_with(&self, head: &[&str], public: &str, ns: &str) -> anyhow::Result<Manifest> {
            let t = self.dir.path().join("b.tar");
            pack(&self.src(), &t, head);
            let _ = std::fs::remove_dir_all(self.out());
            unpack(&t, &self.out(), &Signer::new(public, ns)?)
        }
        fn out(&self) -> PathBuf {
            self.dir.path().join("out")
        }
    }

    fn refused(c: &Case, r: anyhow::Result<Manifest>, why: &str) {
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains(why), "want {why:?}, got {e:?}");
        assert!(!c.out().exists(), "a refused bundle left files behind");
    }

    #[test]
    fn a_signed_bundle_unpacks() {
        let c = Case::new();
        let m = c.open(HEAD).unwrap();
        assert_eq!(m["STACK_TAG"], "t2");
        assert_eq!(
            std::fs::read(c.out().join("images/blobs/sha256/aa")).unwrap(),
            b"layer"
        );
        let refs = layout_refs(&c.out().join(IMAGES)).unwrap();
        assert_eq!(
            refs.into_iter().collect::<Vec<_>>(),
            [
                "registry.example/app:v2",
                "registry.example/installer@sha256:bb"
            ]
        );
    }

    #[test]
    fn another_key_is_refused() {
        let c = Case::new();
        let (_, other) = keygen(c.dir.path(), "other");
        refused(
            &c,
            c.open_with(HEAD, &other, NAMESPACE),
            "pinned update key",
        );
    }

    #[test]
    fn another_namespace_is_refused() {
        let c = Case::new();
        refused(
            &c,
            c.open_with(HEAD, &c.public, "another"),
            "pinned update key",
        );
    }

    #[test]
    fn unsigned_is_refused() {
        let c = Case::new();
        std::fs::remove_file(c.src().join(SIG)).unwrap();
        refused(&c, c.open(HEAD), "must start with");
    }

    #[test]
    fn signature_first_is_refused() {
        let c = Case::new();
        refused(&c, c.open(&[SIG, SUMS]), "must start with");
    }

    #[test]
    fn an_edited_file_is_refused() {
        let c = Case::new();
        std::fs::write(c.src().join("images/blobs/sha256/aa"), "evil!").unwrap();
        refused(&c, c.open(HEAD), "does not match the signed sums");
    }

    #[test]
    fn resealed_sums_are_refused() {
        let c = Case::new();
        std::fs::write(c.src().join(MANIFEST), "FORMAT=2\nSTACK_TAG=t9\n").unwrap();
        let (other, _) = keygen(c.dir.path(), "attacker");
        seal(&c.src(), &other, NAMESPACE);
        refused(&c, c.open(HEAD), "pinned update key");
    }

    #[test]
    fn a_file_outside_the_sums_is_refused() {
        let c = Case::new();
        std::fs::write(c.src().join("extra"), "x").unwrap();
        refused(&c, c.open(HEAD), "not in the signed sums");
    }

    #[test]
    fn a_missing_file_is_refused() {
        let c = Case::new();
        std::fs::remove_file(c.src().join("images/blobs/sha256/aa")).unwrap();
        refused(&c, c.open(HEAD), "lacks images/blobs/sha256/aa");
    }

    #[test]
    fn sums_without_the_manifest_are_refused() {
        let c = Case::new();
        let sums = std::fs::read_to_string(c.src().join(SUMS)).unwrap();
        let kept: String = sums
            .lines()
            .filter(|l| !l.ends_with("  MANIFEST"))
            .map(|l| format!("{l}\n"))
            .collect();
        std::fs::write(c.src().join(SUMS), kept).unwrap();
        sign(&c.key, &c.src().join(SUMS), NAMESPACE);
        refused(&c, c.open(HEAD), "do not cover MANIFEST");
    }

    #[test]
    fn traversal_and_links_are_refused() {
        assert!(safe(Path::new("../x")).is_err());
        assert!(safe(Path::new("/etc/x")).is_err());
        assert!(safe(Path::new("./x")).is_err());
        assert!(parse_sums(&format!("{}  ../../etc/passwd\n", "0".repeat(64))).is_err());

        let c = Case::new();
        let t = c.dir.path().join("link.tar");
        let mut b = tar::Builder::new(File::create(&t).unwrap());
        b.append_path_with_name(c.src().join(SUMS), SUMS).unwrap();
        b.append_path_with_name(c.src().join(SIG), SIG).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, MANIFEST, "/etc/shadow").unwrap();
        b.finish().unwrap();
        drop(b);
        let r = unpack(&t, &c.out(), &Signer::new(&c.public, NAMESPACE).unwrap());
        refused(&c, r, "not a regular file");
    }

    #[test]
    fn manifest_lines_are_strict() {
        assert!(parse_manifest("A=1\nA=2\n").is_err());
        assert!(parse_manifest("lower=1\n").is_err());
        assert!(parse_manifest("NOEQUALS\n").is_err());
        assert_eq!(parse_manifest("A_1=x=y\n").unwrap()["A_1"], "x=y");
    }
}
