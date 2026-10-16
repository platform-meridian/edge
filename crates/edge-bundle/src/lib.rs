//! A bundle is one tar: `SHA256SUMS`, then its Sigstore signature
//! (`SHA256SUMS.sigstore.json`), then every file the sums name. Nothing past
//! the first two entries is written anywhere until the signature has verified
//! against the unit's [`Trust`].
//!
//! - `MANIFEST`: `KEY=value` lines. `FORMAT=5` ([`FORMAT`]); with a base,
//!   `STACK_DIGEST`, `INSTALLER_REF` (by digest), `TALOS_VERSION`,
//!   `BUILT_EPOCH` (the version the base's anti-rollback compares),
//!   `SECUREBOOT`, optionally `STACK_PATH`, and `LOCK_<KEY>=v`, which the
//!   unit's stack lock must match. A bundle without a base names neither.
//! - `components.json`: what the bundle brings and removes ([`components`]).
//! - `config-patch.yaml`, with a base: the machine config without what the
//!   unit keeps (`machineconfig`).
//! - `seed.yaml`, with a base: objects applied server-side before the stack moves.
//! - `images/`: an OCI image layout holding images the components run, the
//!   installer and the stack artifact, each named in its index by
//!   `io.containerd.image.name` (`oci`). The unit must already hold any ref
//!   it leaves out.
//! - `NOTES.md`, optional: release notes for a person, at most 64 KiB.
//! - `fluxinstance.yaml`, optional: the FluxInstance the release runs on,
//!   applied once the stack has brought the operator that knows it.
//!
//! `MANIFEST` may also name the images a person cares about, one
//! `COMPONENT_<NAME>=<ref> <digest> <version> dirty=<bool>` line each
//! ([`components`]).
//!
//! An app is a bundle without a base that brings one module, also published
//! as an OCI artifact whose one layer is the tar ([`APP_ARTIFACT`]).
//!
//! A build writes one with [`write`]; a unit reads one with [`unpack`] and
//! [`check`], or its signed head alone, as it arrives, with [`read_head`].

pub mod components;
pub mod machineconfig;
pub mod oci;
pub mod sigstore;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};

pub use oci::{layout_images, layout_refs};
pub use sigstore::{Signer, Sigstore, Trust};

pub const SUMS: &str = "SHA256SUMS";
pub const SIGNATURE: &str = "SHA256SUMS.sigstore.json";
pub const MANIFEST: &str = "MANIFEST";
pub const PATCH: &str = "config-patch.yaml";
pub const SEED: &str = "seed.yaml";
pub const IMAGES: &str = "images";
pub const NOTES: &str = "NOTES.md";
pub const INSTANCE: &str = "fluxinstance.yaml";

/// An app's OCI `artifactType`, and the media type of its one layer, the tar.
pub const APP_ARTIFACT: &str = "application/vnd.meridian.app.v1";
pub const APP_LAYER: &str = "application/vnd.meridian.bundle.v1.tar";

/// The one layout read and written: any other `FORMAT` is refused.
pub const FORMAT: &str = "5";

/// The bundle brings a base: its MANIFEST names the stack.
pub fn has_base(m: &Manifest) -> bool {
    m.contains_key("STACK_DIGEST")
}

const MAX_SUMS: u64 = 64 << 20;
const MAX_SIGNATURE: u64 = 64 << 10;
const MAX_MANIFEST: u64 = 1 << 20;
const MAX_NOTES: u64 = 64 << 10;

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
            path != Path::new(SUMS) && path != Path::new(SIGNATURE),
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

/// Verifies `tar` against `trust` and unpacks it into `dest`, which must
/// not exist. On any failure `dest` is removed.
pub fn unpack(tar: &Path, dest: &Path, trust: &dyn Trust) -> anyhow::Result<Unpacked> {
    unpack_counting(tar, dest, trust, &AtomicU64::new(0))
}

/// A bundle verified and unpacked: its MANIFEST, and who signed it.
#[derive(Clone, Debug, PartialEq)]
pub struct Unpacked {
    pub manifest: Manifest,
    /// [`Trust::verify`]'s signer.
    pub signer: String,
}

/// [`unpack`], adding to `read` each byte of the bundle as it is read.
pub fn unpack_counting(
    tar: &Path,
    dest: &Path,
    trust: &dyn Trust,
    read: &AtomicU64,
) -> anyhow::Result<Unpacked> {
    ensure!(!dest.exists(), "{} already exists", dest.display());
    let file = File::open(tar).context("open the bundle")?;
    let r = unpack_into(Counting { inner: file, read }, dest, trust);
    if r.is_err() {
        let _ = std::fs::remove_dir_all(dest);
    }
    r
}

type Sums = BTreeMap<PathBuf, [u8; 32]>;

/// The first two entries, the sums and their signature, verified; and the signer.
fn signed_sums<R: Read>(
    entries: &mut tar::Entries<'_, R>,
    trust: &dyn Trust,
) -> anyhow::Result<(Sums, String)> {
    let mut next = |want: &str, max: u64| -> anyhow::Result<Vec<u8>> {
        let mut e = entries
            .next()
            .with_context(|| format!("the bundle ends before {want}"))??;
        let path = e.path()?.into_owned();
        ensure!(
            path == Path::new(want) && e.header().entry_type().is_file(),
            "the bundle must start with {SUMS} then {SIGNATURE}, not {}",
            path.display()
        );
        let size = e.size();
        read_small(&mut e, size, max, want)
    };
    let sums_bytes = next(SUMS, MAX_SUMS)?;
    let sig = next(SIGNATURE, MAX_SIGNATURE)?;
    let signer = trust.verify(&sums_bytes, &sig)?;
    let sums = parse_sums(std::str::from_utf8(&sums_bytes).context("the sums are not text")?)?;
    ensure!(
        sums.contains_key(Path::new(MANIFEST)),
        "the signed sums do not cover {MANIFEST}"
    );
    Ok((sums, signer))
}

/// What a bundle says of itself, signed: readable before the rest has arrived.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Head {
    pub manifest: Manifest,
    pub notes: Option<String>,
    /// [`Trust::verify`]'s signer.
    pub signer: String,
}

/// The signed head of a bundle from as much of its start as is at hand:
/// `Ok(None)` until enough has arrived.
pub fn read_head(start: impl Read, trust: &dyn Trust) -> anyhow::Result<Option<Head>> {
    let mut start = Start {
        inner: start,
        ended: false,
    };
    let r = head_of(&mut start, trust);
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

fn head_of(start: &mut impl Read, trust: &dyn Trust) -> anyhow::Result<Head> {
    let mut archive = tar::Archive::new(start);
    let mut entries = archive.entries().context("the bundle is not a tar")?;
    let (sums, signer) = signed_sums(&mut entries, trust)?;
    let mut head = Head {
        signer,
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
    signed_format(&sums, &head.manifest)?;
    Ok(head)
}

fn format_check(m: &Manifest) -> anyhow::Result<&'static [&'static str]> {
    match m.get("FORMAT").map(String::as_str) {
        Some(FORMAT) => {}
        Some(f) => bail!("the bundle is format {f}, and only format {FORMAT} is read: rebuild it"),
        None => bail!("the bundle names no FORMAT, and only format {FORMAT} is read: rebuild it"),
    }
    ensure!(
        !m.contains_key("STACK_TAG"),
        "the MANIFEST names a STACK_TAG: the unit names its releases"
    );
    if has_base(m) {
        return Ok(&[components::COMPONENTS, PATCH, SEED]);
    }
    if let Some(k) = m
        .keys()
        .find(|k| *k == "BUILT_EPOCH" || k.starts_with("LOCK_"))
    {
        bail!("a bundle without a base names {k}: only a base does");
    }
    Ok(&[components::COMPONENTS])
}

/// A bundle of another format is refused as that, before what it lacks for this one.
fn signed_format(sums: &Sums, m: &Manifest) -> anyhow::Result<()> {
    for need in format_check(m)? {
        ensure!(
            sums.contains_key(Path::new(need)),
            "the signed sums do not cover {need}"
        );
    }
    ensure!(
        has_base(m) || !sums.contains_key(Path::new(PATCH)),
        "the bundle carries a config patch, and its MANIFEST names no STACK_DIGEST"
    );
    Ok(())
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

fn unpack_into(tar: impl Read, dest: &Path, trust: &dyn Trust) -> anyhow::Result<Unpacked> {
    let mut archive = tar::Archive::new(tar);
    let mut entries = archive.entries().context("the bundle is not a tar")?;
    let (sums, signer) = signed_sums(&mut entries, trust)?;

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
    let manifest = parse_manifest(&std::fs::read_to_string(dest.join(MANIFEST))?)?;
    signed_format(&sums, &manifest)?;
    Ok(Unpacked { manifest, signer })
}

/// An unpacked bundle's FluxInstance, if it carries one.
pub fn instance(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(INSTANCE)).ok()
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

/// What a unit checks of an unpacked bundle before it moves. Returns the
/// components and the layout's refs.
pub fn check(dir: &Path) -> anyhow::Result<(components::Components, BTreeSet<String>)> {
    let c = components::Components::read(dir)?;
    let manifest = parse_manifest(&std::fs::read_to_string(dir.join(MANIFEST))?)?;
    ensure!(
        has_base(&manifest) == c.base.is_some(),
        "a bundle's MANIFEST names a STACK_DIGEST exactly when it brings a base"
    );
    if c.base.is_some() {
        machineconfig::check_patch(&std::fs::read_to_string(dir.join(PATCH))?)?;
    }
    let carried = layout_refs(&dir.join(IMAGES))?;
    carries(&c, &carried)?;
    Ok((c, carried))
}

/// A carried image the components leave out would be imported, then collected.
fn carries(c: &components::Components, carried: &BTreeSet<String>) -> anyhow::Result<()> {
    ensure!(
        c.base.is_none() || !carried.is_empty(),
        "the image layout names no image"
    );
    let runs = c.refs();
    let missing: Vec<&str> = carried.difference(&runs).map(String::as_str).collect();
    ensure!(
        missing.is_empty(),
        "the components leave out images the layout carries: {}",
        missing.join(", ")
    );
    Ok(())
}

/// What a build puts in a bundle.
pub struct Contents<'a> {
    pub manifest: &'a Manifest,
    /// From [`machineconfig::strip`]; a bundle without a base has none.
    pub patch: Option<&'a str>,
    pub seed: Option<&'a str>,
    /// An OCI image layout ([`oci::from_flat_cache`]).
    pub images: &'a Path,
    /// Release notes for a person: [`NOTES`].
    pub notes: Option<&'a str>,
    /// The FluxInstance the release runs on: [`INSTANCE`].
    pub instance: Option<&'a str>,
    /// What the bundle brings: [`components::COMPONENTS`].
    pub components: &'a components::Components,
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

/// Writes `contents` as a bundle to `out`, reproducibly, every entry dated
/// `mtime`. `sign` returns the sums' Sigstore bundle.
pub fn write(
    contents: &Contents,
    sign: impl FnOnce(&[u8]) -> anyhow::Result<Vec<u8>>,
    mtime: u64,
    out: &Path,
) -> anyhow::Result<()> {
    let c = contents.components;
    c.check()?;
    let base = c.base.is_some();
    match (contents.patch, contents.seed) {
        (Some(p), Some(_)) if base => machineconfig::check_patch(p)?,
        (None, None) if !base => {}
        _ if base => bail!("a bundle with a base carries its config patch and seed"),
        _ => bail!("a bundle without a base carries no config patch or seed"),
    }
    if let Some(n) = contents.notes {
        ensure!(
            n.len() as u64 <= MAX_NOTES,
            "the notes are {} bytes, more than {MAX_NOTES}",
            n.len()
        );
    }
    carries(c, &layout_refs(contents.images)?)?;
    ensure!(
        has_base(contents.manifest) == base,
        "a bundle's MANIFEST names a STACK_DIGEST exactly when it brings a base"
    );
    let mut manifest = contents.manifest.clone();
    if let Some(f) = manifest.insert("FORMAT".into(), FORMAT.into()) {
        ensure!(
            f == FORMAT,
            "the MANIFEST says FORMAT={f}; this writes {FORMAT}"
        );
    }
    format_check(&manifest)?;
    let mut files = BTreeMap::new();
    files.insert(
        MANIFEST.to_string(),
        Source::Bytes(render_manifest(&manifest)?.into_bytes()),
    );
    if let Some(p) = contents.patch {
        files.insert(PATCH.into(), Source::Bytes(p.as_bytes().into()));
    }
    if let Some(s) = contents.seed {
        files.insert(SEED.into(), Source::Bytes(s.as_bytes().into()));
    }
    files.insert(
        components::COMPONENTS.into(),
        Source::Bytes(serde_json::to_vec_pretty(c)?),
    );
    if let Some(i) = contents.instance {
        files.insert(INSTANCE.into(), Source::Bytes(i.as_bytes().into()));
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
    let sig = sign(sums.as_bytes()).context("signing the sums")?;

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
        append(SIGNATURE, sig.len() as u64, &mut sig.as_slice())?;
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

    const MF: &str = "FORMAT=5\nSTACK_DIGEST=sha256:00\nBUILT_EPOCH=2\n";

    struct Case {
        dir: tempfile::TempDir,
    }

    impl Case {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            tree(&dir.path().join("src"), MF);
            seal(&dir.path().join("src"), SIGNER);
            Self { dir }
        }
        fn src(&self) -> PathBuf {
            self.dir.path().join("src")
        }
        fn tar(&self, head: &[&str]) -> PathBuf {
            let t = self.dir.path().join("b.tar");
            pack(&self.src(), &t, head);
            t
        }
        fn open(&self, head: &[&str]) -> anyhow::Result<Manifest> {
            self.open_with(head, &trust())
        }
        fn open_with(&self, head: &[&str], trust: &dyn Trust) -> anyhow::Result<Manifest> {
            let t = self.tar(head);
            let _ = std::fs::remove_dir_all(self.out());
            unpack(&t, &self.out(), trust).map(|u| u.manifest)
        }
        fn head(&self) -> anyhow::Result<Option<Head>> {
            read_head(File::open(self.tar(HEAD)).unwrap(), &trust())
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
        let u = unpack(&c.tar(HEAD), &c.out(), &trust()).unwrap();
        assert_eq!(u.signer, SIGNER);
        assert_eq!(u.manifest["BUILT_EPOCH"], "2");
        assert_eq!(
            std::fs::read(c.out().join("images/blobs/sha256/aa")).unwrap(),
            b"layer"
        );
        let (components, carried) = check(&c.out()).unwrap();
        assert_eq!(carried, components.refs());
        assert_eq!(
            carried.into_iter().collect::<Vec<_>>(),
            [
                "registry.example/app:v2",
                "registry.example/installer@sha256:bb"
            ]
        );
    }

    #[test]
    fn another_signer_is_refused() {
        let c = Case::new();
        let other = Trusted(vec!["someone else".into()]);
        refused(
            &c,
            c.open_with(HEAD, &other),
            "not a signer this unit trusts",
        );
    }

    #[test]
    fn unsigned_is_refused() {
        let c = Case::new();
        std::fs::remove_file(c.src().join(SIGNATURE)).unwrap();
        refused(&c, c.open(HEAD), "must start with");
    }

    #[test]
    fn signature_first_is_refused() {
        let c = Case::new();
        refused(&c, c.open(&[SIGNATURE, SUMS]), "must start with");
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
        std::fs::write(
            c.src().join(MANIFEST),
            "FORMAT=5\nSTACK_DIGEST=sha256:00\nBUILT_EPOCH=9\n",
        )
        .unwrap();
        seal(&c.src(), "an attacker");
        refused(&c, c.open(HEAD), "not a signer this unit trusts");
    }

    #[test]
    fn edited_sums_under_the_old_signature_are_refused() {
        let c = Case::new();
        let sums = std::fs::read_to_string(c.src().join(SUMS)).unwrap();
        std::fs::write(c.src().join(SUMS), sums.replace("  MANIFEST", "  MANIFESX")).unwrap();
        refused(&c, c.open(HEAD), "does not verify");
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
        resign(&c.src(), SIGNER);
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
        b.append_path_with_name(c.src().join(SIGNATURE), SIGNATURE)
            .unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, MANIFEST, "/etc/shadow").unwrap();
        b.finish().unwrap();
        drop(b);
        let r = unpack(&t, &c.out(), &trust()).map(|u| u.manifest);
        refused(&c, r, "not a regular file");
    }

    #[test]
    fn the_components_must_name_what_the_layout_carries() {
        let c = Case::new();
        std::fs::write(
            c.src().join(components::COMPONENTS),
            r#"{"base":["registry.example/app:v2"]}"#,
        )
        .unwrap();
        seal(&c.src(), SIGNER);
        c.open(HEAD).unwrap();
        let e = format!("{:#}", check(&c.out()).unwrap_err());
        assert!(e.contains("registry.example/installer@sha256:bb"), "{e}");

        std::fs::write(
            c.src().join(components::COMPONENTS),
            r#"{"base":["registry.example/app:v2","registry.example/installer@sha256:bb","registry.example/base:v1"]}"#,
        )
        .unwrap();
        seal(&c.src(), SIGNER);
        c.open(HEAD).unwrap();
        let (components, carried) = check(&c.out()).unwrap();
        assert_eq!((carried.len(), components.refs().len()), (2, 3));
    }

    fn empty_layout(dir: &Path) -> PathBuf {
        let images = dir.join("images");
        std::fs::create_dir_all(images.join("blobs/sha256")).unwrap();
        std::fs::write(
            images.join("index.json"),
            r#"{"schemaVersion":2,"manifests":[]}"#,
        )
        .unwrap();
        std::fs::write(images.join("oci-layout"), "{}").unwrap();
        images
    }

    fn module() -> components::Module {
        components::Module {
            version: "v1.2.0".into(),
            epoch: 7,
            flux: "kind: Kustomization\n".into(),
            ..Default::default()
        }
    }

    #[test]
    fn an_app_carries_no_patch_seed_or_base_facts() {
        let d = tempfile::tempdir().unwrap();
        let images = empty_layout(d.path());
        let c = components::Components {
            modules: [("app".to_string(), module())].into(),
            ..Default::default()
        };
        let m = Manifest::new();
        let contents = Contents {
            manifest: &m,
            patch: None,
            seed: None,
            images: &images,
            notes: None,
            instance: None,
            components: &c,
        };
        let out = d.path().join("b.tar");
        let signer = |s: &[u8]| Ok(sign(SIGNER, s));
        write(&contents, signer, 1, &out).unwrap();
        let dest = d.path().join("out");
        let got = unpack(&out, &dest, &trust()).unwrap();
        assert_eq!(got.manifest["FORMAT"], FORMAT);
        assert!(!has_base(&got.manifest));
        let (read, carried) = check(&dest).unwrap();
        assert_eq!(read, c);
        assert!(carried.is_empty());
        assert!(!dest.join(PATCH).exists() && !dest.join(SEED).exists());

        let patched = Contents {
            patch: Some("version: v1alpha1\n"),
            seed: Some(""),
            ..contents
        };
        assert!(write(&patched, signer, 1, &out).is_err());
        let based = components::Components {
            base: Some(BTreeSet::new()),
            ..c.clone()
        };
        let unpatched = Contents {
            components: &based,
            ..contents
        };
        assert!(write(&unpatched, signer, 1, &out).is_err());
        for (k, v) in [
            ("BUILT_EPOCH", "3"),
            ("LOCK_PROFILE", "edge"),
            ("STACK_TAG", "t"),
        ] {
            let named = Manifest::from([(k.into(), v.into())]);
            let e = write(
                &Contents {
                    manifest: &named,
                    ..contents
                },
                signer,
                1,
                &out,
            )
            .unwrap_err();
            assert!(format!("{e:#}").contains(k), "{e:#}");
        }
    }

    #[test]
    fn another_format_is_refused_by_name() {
        for (mf, why) in [
            (
                "FORMAT=4\nSTACK_DIGEST=sha256:00\n",
                "the bundle is format 4, and only format 5 is read",
            ),
            ("STACK_DIGEST=sha256:00\n", "names no FORMAT"),
            (
                "FORMAT=5\nSTACK_TAG=t2\nSTACK_DIGEST=sha256:00\n",
                "the unit names its releases",
            ),
            ("FORMAT=5\nLOCK_PROFILE=edge\n", "names LOCK_PROFILE"),
        ] {
            let c = Case::new();
            std::fs::write(c.src().join(MANIFEST), mf).unwrap();
            seal(&c.src(), SIGNER);
            refused(&c, c.open(HEAD), why);
            let e = format!("{:#}", c.head().unwrap_err());
            assert!(e.contains(why), "{e}");
        }
    }

    #[test]
    fn a_bundle_without_components_is_refused() {
        let c = Case::new();
        std::fs::remove_file(c.src().join(components::COMPONENTS)).unwrap();
        seal(&c.src(), SIGNER);
        refused(&c, c.open(HEAD), "do not cover components.json");
        let e = format!("{:#}", c.head().unwrap_err());
        assert!(e.contains("do not cover components.json"), "{e}");
    }

    #[test]
    fn the_head_is_signed() {
        let c = Case::new();
        let h = c.head().unwrap().unwrap();
        assert_eq!(
            (h.signer.as_str(), h.manifest["BUILT_EPOCH"].as_str()),
            (SIGNER, "2")
        );
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
            parse_manifest("FORMAT=4\nLOCK_A=x=y\nCOMPONENT_B=img:1 sha256:aa dirty=0\nEMPTY=\n")
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
