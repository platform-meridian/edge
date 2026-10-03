//! What a build writes, read back as a unit reads it.

use std::path::{Path, PathBuf};
use std::process::Command;

use edge_bundle::{
    Contents, Manifest, SigningKey, Verifier, check, machineconfig, oci, unpack, write,
};
use sha2::{Digest, Sha256};

const NS: &str = "test-update";
const UNIT: &str = include_str!("fixtures/controlplane.yaml");

fn keygen(dir: &Path, name: &str, pass: &str) -> (String, String) {
    let key = dir.join(name);
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", pass, "-C", "test", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(st.success());
    let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();
    (read(key.clone()), read(key.with_extension("pub")))
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
    key: SigningKey,
    public: String,
    manifest: Manifest,
    patch: String,
    refs: Vec<String>,
    images: PathBuf,
}

impl Build {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = keygen(dir.path(), "update", "");
        let refs = flat_cache(
            &dir.path().join("flat"),
            &[
                ("registry.example/app", "v2"),
                ("registry.example/installer", "sha256:"),
            ],
        );
        oci::from_flat_cache(&dir.path().join("flat"), &dir.path().join("images"), &refs).unwrap();
        let manifest =
            edge_bundle::parse_manifest("FORMAT=2\nSTACK_TAG=t2\nBUILT_EPOCH=2000\n").unwrap();
        Self {
            key: SigningKey::from_openssh(&private, NS).unwrap(),
            public,
            manifest,
            patch: machineconfig::strip(&build_config()).unwrap(),
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
            seed: "kind: ConfigMap\n",
            images: &self.images,
        }
    }

    fn write(&self, out: &str) -> PathBuf {
        let out = self.path(out);
        write(&self.contents(), &self.key, 2000, &out).unwrap();
        out
    }

    fn open(&self, tar: &Path) -> anyhow::Result<Manifest> {
        let dest = self.path("unpacked");
        let _ = std::fs::remove_dir_all(&dest);
        unpack(tar, &dest, &Verifier::new(&self.public, NS)?)
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
    assert_eq!(b.open(&tar).unwrap(), b.manifest);
    let dest = b.path("unpacked");
    let refs = check(&dest).unwrap();
    assert_eq!(refs.into_iter().collect::<Vec<_>>(), b.refs);
    assert_eq!(
        std::fs::read_to_string(dest.join(edge_bundle::PATCH)).unwrap(),
        b.patch
    );
    assert_eq!(
        std::fs::read_to_string(dest.join(edge_bundle::SEED)).unwrap(),
        "kind: ConfigMap\n"
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
fn ssh_keygen_verifies_what_the_key_signs() {
    let b = Build::new();
    let msg = b.path("msg");
    std::fs::write(&msg, "sums\n").unwrap();
    std::fs::write(b.path("msg.sig"), b.key.sign(b"sums\n").unwrap()).unwrap();
    let allowed = b.path("allowed");
    std::fs::write(&allowed, format!("test {}", b.public)).unwrap();
    let verify = |ns: &str| {
        Command::new("ssh-keygen")
            .args(["-Y", "verify", "-I", "test", "-n", ns, "-f"])
            .arg(&allowed)
            .arg("-s")
            .arg(b.path("msg.sig"))
            .stdin(std::fs::File::open(&msg).unwrap())
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(verify(NS));
    assert!(!verify("another"));
    assert_eq!(b.key.public_key().unwrap(), b.public.trim_end());
}

#[test]
fn a_key_needs_a_namespace_and_no_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (locked, _) = keygen(dir.path(), "locked", "hunter22");
    assert!(err(SigningKey::from_openssh(&locked, NS)).contains("encrypted"));
    let (open, _) = keygen(dir.path(), "open", "");
    assert!(err(SigningKey::from_openssh(&open, "")).contains("namespace"));
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
    assert!(err(write(&c, &b.key, 0, &out)).contains("which the unit keeps"));

    let bad = Manifest::from([("lower".into(), "x".into())]);
    let mut c = b.contents();
    c.manifest = &bad;
    assert!(err(write(&c, &b.key, 0, &out)).contains("is not KEY"));

    let empty = b.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::write(empty.join("index.json"), r#"{"manifests":[]}"#).unwrap();
    let mut c = b.contents();
    c.images = &empty;
    assert!(err(write(&c, &b.key, 0, &out)).contains("names no image"));

    std::os::unix::fs::symlink("/etc/passwd", b.path("images/link")).unwrap();
    assert!(err(write(&b.contents(), &b.key, 0, &out)).contains("not a regular file"));
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
    use serde::Deserialize;
    let docs = |y: &str| -> Vec<serde_yaml::Value> {
        serde_yaml::Deserializer::from_str(y)
            .map(|d| serde_yaml::Value::deserialize(d).unwrap())
            .collect()
    };
    let (a, b) = (docs(a), docs(b));
    assert_eq!(a.len(), b.len());
    for d in &a {
        assert!(
            b.contains(d),
            "{} has no match",
            serde_yaml::to_string(d).unwrap()
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
    // The unit's next config is the build's, but for the unit's own.
    same_docs(&next.replace("unit-", "build-"), &build_config());
}

#[test]
fn a_units_own_patch_gives_it_back() {
    let patch = machineconfig::strip(UNIT).unwrap();
    same_docs(&machineconfig::merge(UNIT, &patch).unwrap(), UNIT);
}
