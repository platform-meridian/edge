//! A bundle is one tar: `SHA256SUMS`, then its SSH signature, then every file
//! the sums name. Nothing past the first two entries is written anywhere until
//! the signature has verified against the pinned key.
//!
//! - `MANIFEST`: `KEY=value` lines. `FORMAT=2` (`3` with `refs`), `STACK_TAG`, `STACK_DIGEST`,
//!   `INSTALLER_REF` (by digest), `TALOS_VERSION`, `BUILT_EPOCH` (the version
//!   anti-rollback compares), `SECUREBOOT`; optionally `STACK_PATH`, and
//!   `LOCK_<KEY>=v`, which the unit's stack lock must match.
//! - `config-patch.yaml`: the machine config without what the unit keeps
//!   (`machineconfig`).
//! - `seed.yaml`: objects applied server-side before the stack moves.
//! - `images/`: an OCI image layout holding every image, the installer and the
//!   stack artifact, each named in its index by `io.containerd.image.name`
//!   (`oci`).
//! - optionally `refs`: every ref the release runs, one per line, when the
//!   layout carries only those the unit lacks (a partial bundle).
//! - `NOTES.md`, optional: release notes for a person, at most 64 KiB.
//!
//! `MANIFEST` may also name the images a person cares about, one
//! `COMPONENT_<NAME>=<ref> <digest> <version> dirty=<bool>` line each
//! ([`components`]).
//!
//! A build writes one with [`write`]; a unit reads one with [`unpack`] and
//! [`check`], or its signed head alone, as it arrives, with [`read_head`].

pub mod machineconfig;
pub mod oci;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

pub use oci::{layout_images, layout_refs};

pub const SUMS: &str = "SHA256SUMS";
pub const SIG: &str = "SHA256SUMS.sig";
pub const MANIFEST: &str = "MANIFEST";
pub const PATCH: &str = "config-patch.yaml";
pub const SEED: &str = "seed.yaml";
pub const IMAGES: &str = "images";
pub const REFS: &str = "refs";
pub const NOTES: &str = "NOTES.md";

const MAX_SUMS: u64 = 64 << 20;
const MAX_SIG: u64 = 64 << 10;
const MAX_MANIFEST: u64 = 1 << 20;
const MAX_NOTES: u64 = 64 << 10;

/// The pinned key a unit checks a bundle's signature against.
#[derive(Clone)]
pub struct Verifier {
    key: PublicKey,
    namespace: String,
}

impl Verifier {
    pub fn new(openssh: &str, namespace: &str) -> anyhow::Result<Self> {
        let key = PublicKey::from_openssh(openssh.trim()).context("the pinned update key")?;
        ensure!(!namespace.is_empty(), "no signature namespace");
        Ok(Self {
            key,
            namespace: namespace.into(),
        })
    }

    /// The pinned key as a person checks it: `SHA256:<fingerprint> <comment>`.
    pub fn signer(&self) -> String {
        let fp = self.key.fingerprint(HashAlg::Sha256).to_string();
        match self.key.comment() {
            "" => fp,
            c => format!("{fp} {c}"),
        }
    }

    pub fn verify(&self, msg: &[u8], armored: &[u8]) -> anyhow::Result<()> {
        let sig = SshSig::from_pem(armored).context("the signature is not an SSH signature")?;
        self.key.verify(&self.namespace, msg, &sig).map_err(|e| {
            anyhow::anyhow!("the signature does not verify against the pinned update key: {e}")
        })
    }
}

/// The build's private key: signs as `ssh-keygen -Y sign` does.
pub struct SigningKey {
    key: PrivateKey,
    namespace: String,
}

impl SigningKey {
    /// An unencrypted OpenSSH private key.
    pub fn from_openssh(pem: &str, namespace: &str) -> anyhow::Result<Self> {
        let key = PrivateKey::from_openssh(pem.trim()).context("the update signing key")?;
        ensure!(
            !key.is_encrypted(),
            "the update signing key is encrypted; sign with an unencrypted copy"
        );
        ensure!(!namespace.is_empty(), "no signature namespace");
        Ok(Self {
            key,
            namespace: namespace.into(),
        })
    }

    /// The public half, as a unit pins it.
    pub fn public_key(&self) -> anyhow::Result<String> {
        Ok(self.key.public_key().to_openssh()?)
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let sig = self
            .key
            .sign(&self.namespace, HashAlg::Sha512, msg)
            .map_err(|e| anyhow::anyhow!("signing: {e}"))?;
        Ok(sig.to_pem(LineEnding::LF)?.into_bytes())
    }
}

pub type Manifest = BTreeMap<String, String>;

fn manifest_key(k: &str) -> bool {
    !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

pub fn parse_manifest(text: &str) -> anyhow::Result<Manifest> {
    let mut m = Manifest::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("MANIFEST line {line:?} is not KEY=value"))?;
        ensure!(manifest_key(k), "MANIFEST key {k:?} is not KEY");
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "MANIFEST names {k} twice"
        );
    }
    Ok(m)
}

pub fn render_manifest(m: &Manifest) -> anyhow::Result<String> {
    let mut out = String::new();
    for (k, v) in m {
        ensure!(manifest_key(k), "MANIFEST key {k:?} is not KEY");
        ensure!(
            !v.contains(['\n', '\r']),
            "MANIFEST value of {k} is not one line"
        );
        out.push_str(&format!("{k}={v}\n"));
    }
    Ok(out)
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
            std::path::Component::Normal(p) => out.push(p),
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

/// Verifies `tar` against `verifier` and unpacks it into `dest`, which must
/// not exist. On any failure `dest` is removed.
pub fn unpack(tar: &Path, dest: &Path, verifier: &Verifier) -> anyhow::Result<Manifest> {
    unpack_counting(tar, dest, verifier, &AtomicU64::new(0))
}

/// [`unpack`], adding to `read` each byte of the bundle as it is read.
pub fn unpack_counting(
    tar: &Path,
    dest: &Path,
    verifier: &Verifier,
    read: &AtomicU64,
) -> anyhow::Result<Manifest> {
    ensure!(!dest.exists(), "{} already exists", dest.display());
    let file = File::open(tar).context("open the bundle")?;
    let r = unpack_into(Counting { inner: file, read }, dest, verifier);
    if r.is_err() {
        let _ = std::fs::remove_dir_all(dest);
    }
    r
}

type Sums = BTreeMap<PathBuf, [u8; 32]>;

/// The first two entries, the sums and their signature, verified.
fn signed_sums<R: Read>(
    entries: &mut tar::Entries<'_, R>,
    verifier: &Verifier,
) -> anyhow::Result<Sums> {
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
    verifier.verify(&sums_bytes, &sig)?;
    let sums = parse_sums(std::str::from_utf8(&sums_bytes).context("the sums are not text")?)?;
    for need in [MANIFEST, PATCH, SEED] {
        ensure!(
            sums.contains_key(Path::new(need)),
            "the signed sums do not cover {need}"
        );
    }
    Ok(sums)
}

/// What a bundle says of itself, signed: readable before the rest has arrived.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Head {
    pub manifest: Manifest,
    pub notes: Option<String>,
    /// [`Verifier::signer`] of the key it verified against.
    pub signer: String,
}

/// The signed head of a bundle from as much of its start as is at hand:
/// `Ok(None)` until enough has arrived, an error as soon as what has arrived
/// is not a bundle signed by the pinned key.
pub fn read_head(start: impl Read, verifier: &Verifier) -> anyhow::Result<Option<Head>> {
    let mut start = Start {
        inner: start,
        ended: false,
    };
    let r = head_of(&mut start, verifier);
    match r {
        Err(_) if start.ended => Ok(None),
        r => r.map(Some),
    }
}

/// Notes whether a read ran out: what failed then may only be unfinished.
struct Start<R> {
    inner: R,
    ended: bool,
}

impl<R: Read> Read for Start<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() {
            self.ended = true;
        }
        Ok(n)
    }
}

fn head_of(start: &mut impl Read, verifier: &Verifier) -> anyhow::Result<Head> {
    let mut archive = tar::Archive::new(start);
    let mut entries = archive.entries().context("the bundle is not a tar")?;
    let sums = signed_sums(&mut entries, verifier)?;
    let mut head = Head {
        signer: verifier.signer(),
        ..Head::default()
    };
    let (mut manifest, want_notes) = (None, sums.contains_key(Path::new(NOTES)));
    while manifest.is_none() || (want_notes && head.notes.is_none()) {
        let mut e = entries
            .next()
            .with_context(|| format!("the bundle ends before {MANIFEST}"))??;
        let path = safe(&e.path()?)?;
        let max = match path.to_str() {
            Some(MANIFEST) => MAX_MANIFEST,
            Some(NOTES) => MAX_NOTES,
            _ => continue,
        };
        let size = e.size();
        let body = read_small(&mut e, size, max, &path.to_string_lossy())?;
        ensure!(
            sums.get(&path).map(|h| h.as_slice()) == Some(Sha256::digest(&body).as_slice()),
            "{} does not match the signed sums",
            path.display()
        );
        let text =
            String::from_utf8(body).with_context(|| format!("{} is not text", path.display()))?;
        if path == Path::new(MANIFEST) {
            manifest = Some(parse_manifest(&text)?);
        } else {
            head.notes = Some(text);
        }
    }
    head.manifest = manifest.unwrap_or_default();
    Ok(head)
}

struct Counting<'a, R> {
    inner: R,
    read: &'a AtomicU64,
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

fn unpack_into(tar: impl Read, dest: &Path, verifier: &Verifier) -> anyhow::Result<Manifest> {
    let mut archive = tar::Archive::new(tar);
    let mut entries = archive.entries().context("the bundle is not a tar")?;
    let sums = signed_sums(&mut entries, verifier)?;

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

/// An unpacked bundle's notes, if it carries any.
pub fn notes(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(NOTES)).ok()
}

/// An image a person cares about, as a `COMPONENT_<NAME>` line names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// `<NAME>`, lower-cased with dashes: `EDGE_CNI` is `edge-cni`.
    pub name: String,
    pub image: String,
    pub digest: String,
    /// What the build calls it, often `git describe`.
    pub version: String,
    /// Built from a tree with uncommitted changes, if the line says.
    pub dirty: Option<bool>,
}

/// Every `COMPONENT_<NAME>=<ref> <digest> <version> dirty=<bool>` line. Any
/// field may be empty; a line too short to read is skipped.
pub fn components(m: &Manifest) -> Vec<Component> {
    m.iter()
        .filter_map(|(k, v)| {
            let name = k.strip_prefix("COMPONENT_")?;
            let mut f = v.split(' ');
            let (image, digest, version) = (f.next()?, f.next()?, f.next()?);
            let dirty = f
                .next()
                .and_then(|d| d.strip_prefix("dirty="))
                .and_then(|d| d.parse().ok());
            Some(Component {
                name: name.to_ascii_lowercase().replace('_', "-"),
                image: image.into(),
                digest: digest.into(),
                version: version.into(),
                dirty,
            })
        })
        .collect()
}

/// One syncfs for the whole unpack rather than an fsync per blob.
fn sync_fs(dir: &Path) -> anyhow::Result<()> {
    let d = File::open(dir)?;
    nix::unistd::syncfs(&d).context("syncfs")?;
    Ok(())
}

/// What a unit checks of an unpacked bundle before it moves: a patch that
/// carries nothing the unit keeps, and a layout naming at least one image.
/// Returns the layout's refs.
pub fn check(dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    machineconfig::check_patch(&std::fs::read_to_string(dir.join(PATCH))?)?;
    let refs = layout_refs(&dir.join(IMAGES))?;
    ensure!(!refs.is_empty(), "the image layout names no image");
    if let Some(listed) = listed_refs(dir)? {
        unlisted(&refs, &listed)?;
    }
    Ok(refs)
}

/// Every ref the release runs: its `refs`, else its layout's.
pub fn release_refs(dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    match listed_refs(dir)? {
        Some(r) => Ok(r),
        None => layout_refs(&dir.join(IMAGES)),
    }
}

/// An unpacked bundle's `refs`, if it has one.
pub fn listed_refs(dir: &Path) -> anyhow::Result<Option<BTreeSet<String>>> {
    match std::fs::read_to_string(dir.join(REFS)) {
        Ok(t) => parse_refs(&t).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading the refs"),
    }
}

fn parse_refs(text: &str) -> anyhow::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for r in text.lines() {
        ensure!(
            !r.is_empty() && !r.contains(char::is_whitespace),
            "{REFS} line {r:?} is not one ref"
        );
        ensure!(out.insert(r.to_string()), "{REFS} names {r} twice");
    }
    ensure!(!out.is_empty(), "{REFS} names no image");
    Ok(out)
}

/// A carried image the list leaves out would be imported and then collected.
fn unlisted(carried: &BTreeSet<String>, listed: &BTreeSet<String>) -> anyhow::Result<()> {
    let missing: Vec<&str> = carried.difference(listed).map(String::as_str).collect();
    ensure!(
        missing.is_empty(),
        "{REFS} leaves out images the layout carries: {}",
        missing.join(", ")
    );
    Ok(())
}

/// What a build puts in a bundle.
pub struct Contents<'a> {
    pub manifest: &'a Manifest,
    /// From [`machineconfig::strip`].
    pub patch: &'a str,
    pub seed: &'a str,
    /// An OCI image layout ([`oci::from_flat_cache`]).
    pub images: &'a Path,
    /// Every ref the release runs, when `images` carries only some of them.
    pub refs: Option<&'a BTreeSet<String>>,
    /// Release notes for a person: [`NOTES`].
    pub notes: Option<&'a str>,
}

enum Source {
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl Source {
    fn open(&self) -> std::io::Result<Box<dyn Read + '_>> {
        Ok(match self {
            Source::Bytes(b) => Box::new(b.as_slice()),
            Source::File(p) => Box::new(File::open(p)?),
        })
    }

    fn len(&self) -> std::io::Result<u64> {
        Ok(match self {
            Source::Bytes(b) => b.len() as u64,
            Source::File(p) => std::fs::metadata(p)?.len(),
        })
    }
}

/// Writes `contents` as a bundle to `out`, signed with `key`, every entry
/// root's and dated `mtime` so the same inputs make the same tar. Refuses
/// what a unit would refuse.
pub fn write(contents: &Contents, key: &SigningKey, mtime: u64, out: &Path) -> anyhow::Result<()> {
    machineconfig::check_patch(contents.patch)?;
    if let Some(n) = contents.notes {
        ensure!(
            n.len() as u64 <= MAX_NOTES,
            "the notes are {} bytes, more than {MAX_NOTES}",
            n.len()
        );
    }
    let carried = layout_refs(contents.images)?;
    ensure!(!carried.is_empty(), "the image layout names no image");
    if let Some(refs) = contents.refs {
        let text: String = refs.iter().map(|r| format!("{r}\n")).collect();
        unlisted(&carried, &parse_refs(&text)?)?;
    }
    let mut files = BTreeMap::new();
    files.insert(
        MANIFEST.to_string(),
        Source::Bytes(render_manifest(contents.manifest)?.into_bytes()),
    );
    files.insert(
        PATCH.into(),
        Source::Bytes(contents.patch.as_bytes().into()),
    );
    files.insert(SEED.into(), Source::Bytes(contents.seed.as_bytes().into()));
    if let Some(refs) = contents.refs {
        let text: String = refs.iter().map(|r| format!("{r}\n")).collect();
        files.insert(REFS.into(), Source::Bytes(text.into_bytes()));
    }
    if let Some(n) = contents.notes {
        files.insert(NOTES.into(), Source::Bytes(n.as_bytes().into()));
    }
    for p in walk(contents.images)? {
        let name = Path::new(IMAGES).join(p.strip_prefix(contents.images)?);
        let name = name.to_str().context("an image layout path is not UTF-8")?;
        files.insert(name.into(), Source::File(p));
    }

    let mut sums = String::new();
    for (name, src) in &files {
        let mut hash = Sha256::new();
        std::io::copy(&mut src.open()?, &mut hash)?;
        sums.push_str(&format!("{}  {name}\n", hex::encode(hash.finalize())));
    }
    let sig = key.sign(sums.as_bytes())?;

    let r = (|| {
        let mut tar = tar::Builder::new(std::io::BufWriter::new(File::create(out)?));
        let mut append = |name: &str, size: u64, data: &mut dyn Read| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(size);
            h.set_mode(0o644);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(mtime);
            tar.append_data(&mut h, name, data)
        };
        append(SUMS, sums.len() as u64, &mut sums.as_bytes())?;
        append(SIG, sig.len() as u64, &mut sig.as_slice())?;
        for (name, src) in &files {
            append(name, src.len()?, &mut src.open()?)?;
        }
        tar.into_inner()?.into_inner()?.sync_all()?;
        anyhow::Ok(())
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(out);
    }
    r.with_context(|| format!("writing {}", out.display()))
}

/// Every regular file under `dir`, refusing anything a unit would.
fn walk(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let e = e?;
        let kind = e.file_type()?;
        if kind.is_dir() {
            out.extend(walk(&e.path())?);
        } else {
            ensure!(
                kind.is_file(),
                "{} is not a regular file",
                e.path().display()
            );
            out.push(e.path());
        }
    }
    Ok(out)
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
            unpack(&t, &self.out(), &Verifier::new(public, ns)?)
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
        let r = unpack(&t, &c.out(), &Verifier::new(&c.public, NAMESPACE).unwrap());
        refused(&c, r, "not a regular file");
    }

    #[test]
    fn a_units_list_must_name_what_the_layout_carries() {
        let c = Case::new();
        std::fs::write(c.src().join(REFS), "registry.example/base:v1\n").unwrap();
        seal(&c.src(), &c.key, NAMESPACE);
        c.open(HEAD).unwrap();
        let e = format!("{:#}", check(&c.out()).unwrap_err());
        assert!(e.contains("registry.example/app:v2"), "{e}");

        std::fs::write(
            c.src().join(REFS),
            "registry.example/app:v2\nregistry.example/installer@sha256:bb\nregistry.example/base:v1\n",
        )
        .unwrap();
        seal(&c.src(), &c.key, NAMESPACE);
        c.open(HEAD).unwrap();
        assert_eq!(check(&c.out()).unwrap().len(), 2);
        assert_eq!(release_refs(&c.out()).unwrap().len(), 3);
    }

    #[test]
    fn an_unreadable_list_is_no_full_bundle() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(listed_refs(d.path()).unwrap(), None);
        std::fs::write(d.path().join(REFS), b"\xff\xfe\n").unwrap();
        assert!(listed_refs(d.path()).is_err());
        assert!(release_refs(d.path()).is_err());
    }

    #[test]
    fn a_refs_line_is_one_ref() {
        assert!(parse_refs("a:1\na:1\n").is_err());
        assert!(parse_refs("a:1\n\nb:2\n").is_err());
        assert!(parse_refs("a:1 b:2\n").is_err());
        assert!(parse_refs("").is_err());
        assert_eq!(parse_refs("b:2\na:1\n").unwrap().len(), 2);
    }

    #[test]
    fn manifest_lines_are_strict() {
        assert!(parse_manifest("A=1\nA=2\n").is_err());
        assert!(parse_manifest("lower=1\n").is_err());
        assert!(parse_manifest("NOEQUALS\n").is_err());
        assert_eq!(parse_manifest("A_1=x=y\n").unwrap()["A_1"], "x=y");
    }

    #[test]
    fn components_are_read_from_their_lines() {
        let m = parse_manifest(
            "COMPONENT_EDGE_CNI=reg/edge-cni:t2 sha256:aa v1.2-3-gabc dirty=false\n\
             COMPONENT_APP= sha256:bb  dirty=\n\
             COMPONENT_SHORT=reg/x:1 sha256:cc\n\
             STACK_TAG=t2\n",
        )
        .unwrap();
        assert_eq!(
            components(&m),
            [
                Component {
                    name: "app".into(),
                    image: "".into(),
                    digest: "sha256:bb".into(),
                    version: "".into(),
                    dirty: None,
                },
                Component {
                    name: "edge-cni".into(),
                    image: "reg/edge-cni:t2".into(),
                    digest: "sha256:aa".into(),
                    version: "v1.2-3-gabc".into(),
                    dirty: Some(false),
                },
            ]
        );
    }

    #[test]
    fn a_manifest_renders_back_to_itself() {
        let m =
            parse_manifest("FORMAT=2\nLOCK_A=x=y\nCOMPONENT_B=img:1 sha256:aa dirty=0\nEMPTY=\n")
                .unwrap();
        assert_eq!(parse_manifest(&render_manifest(&m).unwrap()).unwrap(), m);
        for (k, v) in [
            ("lower", "x"),
            ("", "x"),
            ("A-B", "x"),
            ("A", "x\nB=y"),
            ("A", "x\r"),
        ] {
            let m = Manifest::from([(k.into(), v.into())]);
            assert!(render_manifest(&m).is_err(), "{k:?}={v:?}");
        }
    }
}
