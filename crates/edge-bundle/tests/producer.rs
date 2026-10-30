//! What a build writes, read back as a unit reads it.

use std::path::{Path, PathBuf};

use edge_bundle::components::Components;
use edge_bundle::{Contents, Manifest, Trust, check, machineconfig, oci, read_head, unpack, write};
use sha2::{Digest, Sha256};

const UNIT: &str = include_str!("fixtures/controlplane.yaml");
const SIGNER: &str = "https://github.com/test/talos/.github/workflows/release.yml@refs/tags/v2";

/// A stand-in trust that takes `<signer> <sha256 of the sums>`.
struct Signed;

impl Trust for Signed {
    fn verify(&self, sums: &[u8], signature: Option<&[u8]>) -> anyhow::Result<String> {
        let signature = signature.ok_or_else(|| anyhow::anyhow!("the bundle is unsigned"))?;
        let (who, sha) = std::str::from_utf8(signature)?
            .trim()
            .rsplit_once(' ')
            .ok_or_else(|| anyhow::anyhow!("the signature is not a Sigstore bundle"))?;
        anyhow::ensure!(sha == self::sha(sums), "the signature does not verify");
        anyhow::ensure!(who == SIGNER, "{who} is not a signer this unit trusts");
        Ok(who.into())
    }
}

fn signed_as(who: &'static str) -> impl Fn(&[u8]) -> anyhow::Result<Vec<u8>> + Copy {
    move |sums| Ok(format!("{who} {}", sha(sums)).into_bytes())
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// A flat image cache as Talos writes it, holding `refs`.
fn flat_cache(dir: &Path, refs: &[(&str, &str)]) -> Vec<String> {
    let mut named = Vec::new();
    std::fs::create_dir_all(dir.join("blob")).unwrap();
    for (i, (repo, tag)) in refs.iter().enumerate() {
        let config = format!("{{\"n\":{i}}}");
        let layer = format!("layer {i}");
        for b in [&config, &layer] {
            std::fs::write(dir.join(format!("blob/sha256-{}", sha(b.as_bytes()))), b).unwrap();
        }
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": format!("sha256:{}", sha(config.as_bytes())), "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "digest": format!("sha256:{}", sha(layer.as_bytes())), "size": layer.len()}],
        })
        .to_string();
        let (host, path) = repo.split_once('/').unwrap();
        let base = dir.join("manifests").join(host).join(path);
        let r = if tag.starts_with("sha256:") {
            let d = sha(manifest.as_bytes());
            std::fs::create_dir_all(base.join("digest")).unwrap();
            std::fs::write(base.join(format!("digest/sha256-{d}")), &manifest).unwrap();
            format!("{repo}@sha256:{d}")
        } else {
            std::fs::create_dir_all(base.join("reference")).unwrap();
            std::fs::write(base.join("reference").join(tag), &manifest).unwrap();
            format!("{repo}:{tag}")
        };
        named.push(r);
    }
    named
}

struct Build {
    dir: tempfile::TempDir,
    manifest: Manifest,
    patch: String,
    refs: Vec<String>,
    /// A base running what its layout carries.
    components: Components,
    images: PathBuf,
}

impl Build {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let refs = flat_cache(
            &dir.path().join("flat"),
            &[
                ("registry.example/app", "v2"),
                ("registry.example/installer", "sha256:"),
            ],
        );
        oci::from_flat_cache(&dir.path().join("flat"), &dir.path().join("images"), &refs).unwrap();
        let manifest = edge_bundle::parse_manifest("FORMAT=6\nBUILT_EPOCH=2000\n").unwrap();
        Self {
            manifest,
            patch: machineconfig::strip(&build_config()).unwrap(),
            components: Components {
                base: refs.iter().cloned().collect(),
            },
            refs,
            images: dir.path().join("images"),
            dir,
        }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    fn contents(&self) -> Contents<'_> {
        Contents {
            manifest: &self.manifest,
            patch: &self.patch,
            images: &self.images,
            apps: None,
            notes: None,
            components: &self.components,
        }
    }

    fn write(&self, out: &str) -> PathBuf {
        let out = self.path(out);
        write(&self.contents(), signed_as(SIGNER), 2000, &out).unwrap();
        out
    }

    fn open(&self, tar: &Path) -> anyhow::Result<Manifest> {
        let dest = self.path("unpacked");
        let _ = std::fs::remove_dir_all(&dest);
        unpack(tar, &dest, &Signed).map(|u| u.manifest)
    }
}

/// The build's own config: its secrets and identity, and newer images.
fn build_config() -> String {
    UNIT.replace("unit-", "build-")
        .replace(":t1", ":t2")
        .replace("v1.35.2", "v1.35.3")
}

fn err<T>(r: anyhow::Result<T>) -> String {
    match r {
        Ok(_) => panic!("accepted"),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn a_written_bundle_unpacks_as_a_unit_reads_it() {
    let b = Build::new();
    let tar = b.write("b.tar");
    let read = std::sync::atomic::AtomicU64::new(0);
    edge_bundle::unpack_counting(&tar, &b.path("counted"), &Signed, &read).unwrap();
    // All but the tar's closing padding.
    let (read, len) = (read.into_inner(), std::fs::metadata(&tar).unwrap().len());
    assert!(read <= len && read + 10240 >= len, "{read} of {len}");
    assert_eq!(b.open(&tar).unwrap(), b.manifest);
    let dest = b.path("unpacked");
    let (components, refs) = check(&dest).unwrap();
    assert_eq!(components, b.components);
    assert_eq!(refs.into_iter().collect::<Vec<_>>(), b.refs);
    assert_eq!(
        std::fs::read_to_string(dest.join(edge_bundle::PATCH)).unwrap(),
        b.patch
    );

    let store = edge_registry::Store::open(b.path("store")).unwrap();
    let tagged = store
        .import_layout(&dest.join(edge_bundle::IMAGES))
        .unwrap();
    assert_eq!(tagged.len(), 1);
    assert!(store.resolve("registry.example/app", "v2").is_some());
    let (_, digest) = b.refs[1].split_once('@').unwrap();
    assert!(
        store
            .resolve("registry.example/installer", digest)
            .is_some()
    );
}

#[test]
fn notes_ride_signed_and_the_head_reads_from_the_start_alone() {
    let b = Build::new();
    let mut c = b.contents();
    c.notes = Some("# 2.1\n\nFaster boots.\n");
    let tar = b.path("n.tar");
    write(&c, signed_as(SIGNER), 2000, &tar).unwrap();
    b.open(&tar).unwrap();
    assert_eq!(edge_bundle::notes(&b.path("unpacked")).as_deref(), c.notes);
    assert_eq!(edge_bundle::notes(&b.path("nowhere")), None);

    let bytes = std::fs::read(&tar).unwrap();
    let v = Signed;
    let head = read_head(bytes.as_slice(), &v).unwrap().unwrap();
    assert_eq!(head.manifest, b.manifest);
    assert_eq!(head.notes.as_deref(), c.notes);
    assert_eq!(head.signer, SIGNER);
    // The head is whole well before the images.
    let whole = (0..bytes.len())
        .step_by(512)
        .find(|&n| read_head(&bytes[..n], &v).unwrap().is_some())
        .unwrap();
    let images = bytes.windows(7).position(|w| w == b"layer 0").unwrap();
    assert!(whole < images, "{whole} >= {images}");
    for n in [0, 100, 512, 1024, whole - 512] {
        assert_eq!(read_head(&bytes[..n], &v).unwrap(), None, "{n}");
    }

    // Without notes, the manifest alone completes it.
    let plain = std::fs::read(b.write("p.tar")).unwrap();
    assert_eq!(
        read_head(plain.as_slice(), &v).unwrap().unwrap().notes,
        None
    );

    // A stranger's bundle fails as soon as its signature has arrived.
    write(&c, signed_as("a stranger"), 2000, &b.path("o.tar")).unwrap();
    let o = std::fs::read(b.path("o.tar")).unwrap();
    assert!(err(read_head(&o[..whole], &v)).contains("not a signer this unit trusts"));
    assert!(read_head(&b"not a tar at all".repeat(64)[..], &v).is_err());

    let mut bad = bytes.clone();
    let at = bad.windows(6).position(|w| w == b"Faster").unwrap();
    bad[at] = b'f';
    assert!(err(read_head(bad.as_slice(), &v)).contains("NOTES.md does not match"));

    let mut c = b.contents();
    let long = "x".repeat(65 << 10);
    c.notes = Some(&long);
    assert!(err(write(&c, signed_as(SIGNER), 0, &b.path("l.tar"))).contains("notes"));
}

#[test]
fn the_same_inputs_make_the_same_tar() {
    let b = Build::new();
    let one = std::fs::read(b.write("one.tar")).unwrap();
    let two = std::fs::read(b.write("two.tar")).unwrap();
    assert_eq!(one, two);
    let mut entries = tar::Archive::new(one.as_slice());
    for e in entries.entries().unwrap() {
        let h = e.unwrap().header().clone();
        assert_eq!(
            (h.mtime().unwrap(), h.uid().unwrap(), h.mode().unwrap()),
            (2000, 0, 0o644)
        );
    }
}

#[test]
fn a_tampered_bundle_is_refused() {
    let b = Build::new();
    let tar = b.write("b.tar");
    let mut bad = std::fs::read(&tar).unwrap();
    let at = bad.windows(7).position(|w| w == b"layer 0").unwrap();
    bad[at] = b'L';
    std::fs::write(&tar, &bad).unwrap();
    assert!(err(b.open(&tar)).contains("does not match the signed sums"));
    assert!(!b.path("unpacked").exists());
}

#[test]
fn a_build_refuses_what_a_unit_would() {
    let b = Build::new();
    let out = b.path("b.tar");
    let full = build_config();
    let mut c = b.contents();
    c.patch = &full;
    assert!(err(write(&c, signed_as(SIGNER), 0, &out)).contains("which the unit keeps"));

    let bad = Manifest::from([
        ("lower".into(), "x".into()),
        ("BUILT_EPOCH".into(), "2".into()),
    ]);
    let mut c = b.contents();
    c.manifest = &bad;
    assert!(err(write(&c, signed_as(SIGNER), 0, &out)).contains("is not KEY"));

    let empty = b.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::write(empty.join("index.json"), r#"{"manifests":[]}"#).unwrap();
    let mut c = b.contents();
    c.images = &empty;
    assert!(err(write(&c, signed_as(SIGNER), 0, &out)).contains("names no image"));

    std::os::unix::fs::symlink("/etc/passwd", b.path("images/link")).unwrap();
    assert!(err(write(&b.contents(), signed_as(SIGNER), 0, &out)).contains("not a regular file"));
    assert!(!out.exists());
}

#[test]
fn full_and_partial_bundles_round_trip_in_the_one_format() {
    let b = Build::new();
    let mut partial = b.components.clone();
    partial.base.insert("registry.example/base:v1".into());
    let unformatted: Manifest = b
        .manifest
        .iter()
        .filter(|(k, _)| *k != "FORMAT")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let dest = b.path("unpacked");
    for (name, components) in [("full.tar", &b.components), ("partial.tar", &partial)] {
        let mut c = b.contents();
        c.components = components;
        c.manifest = &unformatted;
        let out = b.path(name);
        write(&c, signed_as(SIGNER), 0, &out).unwrap();
        let m = b.open(&out).unwrap();
        assert_eq!(m["FORMAT"], edge_bundle::FORMAT, "{name}");
        assert_eq!(m, b.manifest, "{name}");
        let (read, carried) = check(&dest).unwrap();
        assert_eq!(carried.into_iter().collect::<Vec<_>>(), b.refs, "{name}");
        assert_eq!(&read, components, "{name}");
    }
}

#[test]
fn a_build_writes_no_other_format() {
    let b = Build::new();
    let out = b.path("b.tar");
    for f in ["4", "5", ""] {
        let mut m = b.manifest.clone();
        m.insert("FORMAT".into(), f.into());
        let mut c = b.contents();
        c.manifest = &m;
        assert!(
            err(write(&c, signed_as(SIGNER), 0, &out)).contains("this writes 6"),
            "{f}"
        );
    }
    assert!(!out.exists());
}

#[test]
fn the_components_must_name_every_carried_image() {
    let b = Build::new();
    let out = b.path("b.tar");
    let some = Components {
        base: ["registry.example/base:v1".to_string()].into(),
    };
    let mut c = b.contents();
    c.components = &some;
    assert!(
        err(write(&c, signed_as(SIGNER), 0, &out)).contains("leave out images the layout carries")
    );
    assert!(!out.exists());
}

#[test]
fn a_flat_cache_missing_an_image_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let flat = dir.path().join("flat");
    let mut refs = flat_cache(&flat, &[("registry.example/app", "v2")]);
    refs.push("registry.example/gone:v1".into());
    let e = err(oci::from_flat_cache(&flat, &dir.path().join("l"), &refs));
    assert!(e.contains("registry.example/gone:v1"), "{e}");

    let flat = dir.path().join("flat2");
    flat_cache(&flat, &[("registry.example/app", "v2")]);
    let zeros = "0".repeat(64);
    let digests = flat.join("manifests/registry.example/app/digest");
    std::fs::create_dir_all(&digests).unwrap();
    std::fs::write(digests.join(format!("sha256-{zeros}")), "{}").unwrap();
    let wrong = format!("registry.example/app@sha256:{zeros}");
    let e = err(oci::from_flat_cache(
        &flat,
        &dir.path().join("l2"),
        &[wrong],
    ));
    assert!(e.contains("hashes to"), "{e}");

    let flat = dir.path().join("flat3");
    let refs = flat_cache(&flat, &[("registry.example/app", "v2")]);
    for (i, bad) in [
        "not-a-blob".into(),
        format!("sha256-{}", "z".repeat(64)),
        "sha256-ab".into(),
    ]
    .iter()
    .enumerate()
    {
        let _ = std::fs::remove_dir_all(dir.path().join("l3"));
        std::fs::write(flat.join("blob").join(bad), "x").unwrap();
        let e = err(oci::from_flat_cache(&flat, &dir.path().join("l3"), &refs));
        assert!(e.contains("not a sha256 blob"), "{i} {e}");
        std::fs::remove_file(flat.join("blob").join(bad)).unwrap();
    }
}

#[test]
fn manifests_the_refs_do_not_name_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let flat = dir.path().join("flat");
    let refs = flat_cache(&flat, &[("registry.example/app", "v2")]);
    let base = flat.join("manifests/registry.example/app");
    std::fs::create_dir_all(base.join("digest")).unwrap();
    std::fs::create_dir_all(base.join("other")).unwrap();
    std::fs::write(base.join("digest/sha256-platform"), "platform").unwrap();
    std::fs::write(base.join("reference/v1"), "older").unwrap();
    std::fs::write(base.join("other/x"), "stray").unwrap();
    let layout = dir.path().join("layout");
    oci::from_flat_cache(&flat, &layout, &refs).unwrap();
    let blob = |b: &str| layout.join("blobs/sha256").join(sha(b.as_bytes())).exists();
    assert!(blob("platform") && blob("older"));
    assert!(!blob("stray"));
}

/// The same documents, in any order, their keys in any order.
fn same_docs(a: &str, b: &str) {
    let docs = |y: &str| edge_bundle::yaml::documents(y).unwrap();
    let (a, b) = (docs(a), docs(b));
    assert_eq!(a.len(), b.len());
    for d in &a {
        assert!(
            b.contains(d),
            "{} has no match",
            serde_saphyr::to_string(d).unwrap()
        );
    }
}

#[test]
fn a_build_patch_carries_none_of_the_builds_secrets() {
    let patch = machineconfig::strip(&build_config()).unwrap();
    assert!(!patch.contains("build-"), "{patch}");
    machineconfig::check_patch(&patch).unwrap();
    for owned in [
        "registry.example/store:t2",
        "kube-apiserver:v1.35.3",
        "installer:t2",
        "EDGE_WATCH_TIMEOUT",
        "operator-root-crt",
        "maxPods",
    ] {
        assert!(patch.contains(owned), "{owned} missing:\n{patch}");
    }
}

#[test]
fn a_build_patch_merges_onto_a_unit() {
    let patch = machineconfig::strip(&build_config()).unwrap();
    let next = machineconfig::merge(UNIT, &patch).unwrap();
    assert!(!next.contains("build-"), "{next}");
    for kept in [
        "unit-mtoken",
        "unit-etcd-ca-key",
        "unit-service-account-key",
        "unit-recovery-key",
        "unit-ephemeral-key",
        "unit-signing-ca-key",
        "unit-a-link",
        "unit-a-resolver",
        "unit-a-mac",
        "unit-a-seed",
        "unit-a-ssh-host-key",
    ] {
        assert!(next.contains(kept), "{kept} lost:\n{next}");
    }
    assert!(next.contains("registry.example/store:t2") && !next.contains(":t1"));
    assert_eq!(machineconfig::merge(&next, &patch).unwrap(), next);
    // The unit's next config is the build's, but for the unit's own, with the
    // firewall a config derives.
    same_docs(
        &next.replace("unit-", "build-"),
        &machineconfig::with_firewall(&build_config()).unwrap(),
    );
}

#[test]
fn a_units_own_patch_gives_it_back() {
    let patch = machineconfig::strip(UNIT).unwrap();
    same_docs(
        &machineconfig::merge(UNIT, &patch).unwrap(),
        &machineconfig::with_firewall(UNIT).unwrap(),
    );
}
