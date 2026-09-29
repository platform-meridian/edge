mod common;

use common::{INDEX, Layout, tempdir};
use edge_registry::{Digest, ImageRef, Store, Swept};

fn r(s: &str) -> ImageRef {
    s.parse().unwrap()
}

fn tags(store: &Store) -> Vec<String> {
    store
        .list()
        .unwrap()
        .images
        .iter()
        .map(|i| format!("{}:{}", i.repo, i.tag.as_deref().unwrap()))
        .collect()
}

#[test]
fn imports_layout() {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 2);
    let pause = layout.image("pause", 1);
    layout.tag(&app, "ghcr.io/o/app:v1");
    layout.add(
        &pause.manifest,
        common::MANIFEST,
        &[
            ("io.containerd.image.name", "registry.k8s.io/pause:3.10"),
            ("org.opencontainers.image.ref.name", "3.10"),
        ],
    );
    layout.tag(&app, "busybox:1");
    layout.tag(&pause, "latest");
    layout.tag(&pause, "ghcr.io/o/pause@sha256:0");
    let store = Store::open(d.path().join("store")).unwrap();

    let got = store.import_layout(layout.write()).unwrap();

    assert_eq!(
        got,
        [
            r(&format!("ghcr.io/o/app:v1@{}", app.manifest.digest)),
            r(&format!(
                "registry.k8s.io/pause:3.10@{}",
                pause.manifest.digest
            )),
            r(&format!("busybox:1@{}", app.manifest.digest)),
        ]
    );
    let listing = store.list().unwrap();
    assert_eq!(
        tags(&store),
        [
            "docker.io/library/busybox:1",
            "ghcr.io/o/app:v1",
            "registry.k8s.io/pause:3.10"
        ]
    );
    assert_eq!((listing.manifests, listing.blobs), (2, 5));
    let bytes: usize = [&app, &pause]
        .iter()
        .flat_map(|i| [&i.manifest, &i.config].into_iter().chain(&i.layers))
        .map(|b| b.bytes.len())
        .sum();
    assert_eq!(listing.bytes, bytes as u64);

    assert_eq!(
        store.resolve("ghcr.io/o/app", "v1"),
        Some(app.manifest.digest.clone())
    );
    let (media_type, bytes) = store.manifest(&app.manifest.digest).unwrap().unwrap();
    assert_eq!(
        (media_type.as_str(), bytes),
        (common::MANIFEST, app.manifest.bytes.clone())
    );
    for layer in &app.layers {
        assert_eq!(
            std::fs::read(store.blob_path(&layer.digest)).unwrap(),
            layer.bytes
        );
    }

    assert_eq!(store.import_layout(&layout.dir).unwrap(), got);
    assert_eq!(store.list().unwrap(), listing);
}

#[test]
fn corrupt_blob_never_visible() {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 2);
    layout.tag(&app, "ghcr.io/o/app:v1");
    let bad = &app.layers[1];
    let mut flipped = bad.bytes.clone();
    flipped[7] ^= 1;
    std::fs::write(layout.path(&bad.digest), flipped).unwrap();
    let store = Store::open(d.path().join("store")).unwrap();

    let e = store.import_layout(layout.write()).unwrap_err();

    assert!(format!("{e:#}").contains(&bad.digest.to_string()), "{e:#}");
    assert!(!store.blob_path(&bad.digest).exists());
    assert!(store.blob_path(&app.layers[0].digest).exists());
    assert_eq!(store.resolve("ghcr.io/o/app", "v1"), None);
    assert_eq!(store.manifest(&app.manifest.digest).unwrap(), None);
    let mut names: Vec<_> = std::fs::read_dir(store.blob_path(&bad.digest).parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut want = [app.config.digest.hex(), app.layers[0].digest.hex()];
    want.sort();
    assert_eq!(names, want);
}

#[test]
fn truncated_blob_rejected() {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 1);
    layout.tag(&app, "ghcr.io/o/app:v1");
    let layer = &app.layers[0];
    std::fs::write(layout.path(&layer.digest), &layer.bytes[..100]).unwrap();
    let store = Store::open(d.path().join("store")).unwrap();
    assert!(store.import_layout(layout.write()).is_err());
    assert!(!store.blob_path(&layer.digest).exists());
}

#[test]
fn partial_index_imports() {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let amd64 = layout.image("amd64", 1);
    let arm64 = layout.image("arm64", 1);
    let index = layout.index(&[&amd64, &arm64], 1);
    std::fs::remove_file(layout.path(&arm64.config.digest)).unwrap();
    std::fs::remove_file(layout.path(&arm64.layers[0].digest)).unwrap();
    layout.add(
        &index,
        INDEX,
        &[("org.opencontainers.image.ref.name", "ghcr.io/o/multi:1")],
    );
    let store = Store::open(d.path().join("store")).unwrap();

    store.import_layout(layout.write()).unwrap();

    assert_eq!(
        store.resolve("ghcr.io/o/multi", "1"),
        Some(index.digest.clone())
    );
    let (media_type, _) = store.manifest(&index.digest).unwrap().unwrap();
    assert_eq!(media_type, INDEX);
    assert!(store.manifest(&amd64.manifest.digest).unwrap().is_some());
    assert!(store.manifest(&arm64.manifest.digest).unwrap().is_none());
    assert_eq!(store.repair().unwrap(), 0);
}

#[test]
fn missing_top_level_manifest_fails() {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 1);
    layout.tag(&app, "ghcr.io/o/app:v1");
    std::fs::remove_file(layout.path(&app.manifest.digest)).unwrap();
    let store = Store::open(d.path().join("store")).unwrap();
    assert!(store.import_layout(layout.write()).is_err());
    assert!(store.list().unwrap().images.is_empty());
}

#[test]
fn not_a_layout() {
    let d = tempdir();
    let store = Store::open(d.path().join("store")).unwrap();
    assert!(store.import_layout(d.path()).is_err());
    let mut layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 1);
    layout.tag(&app, "ghcr.io/o/app:v1");
    layout.write();
    std::fs::write(layout.dir.join("oci-layout"), b"{}").unwrap();
    assert!(store.import_layout(&layout.dir).is_err());
}

struct Three {
    store: Store,
    old: common::Image,
    prev: common::Image,
    cur: common::Image,
    shared: Digest,
    _d: tempfile::TempDir,
}

/// Three releases of one app plus a helper, the oldest sharing a layer with
/// the current one.
fn three_releases() -> Three {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let old = layout.image("old", 2);
    let prev = layout.image("prev", 1);
    let mut cur = layout.image("cur", 1);
    let shared = &old.layers[0];
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": common::MANIFEST,
        "config": cur.config.descriptor("application/vnd.oci.image.config.v1+json"),
        "layers": [
            shared.descriptor("application/vnd.oci.image.layer.v1.tar+gzip"),
            cur.layers[0].descriptor("application/vnd.oci.image.layer.v1.tar+gzip"),
        ],
    });
    cur.manifest = layout.blob(serde_json::to_vec(&manifest).unwrap());
    let helper = layout.image("helper", 1);
    layout.tag(&old, "ghcr.io/o/app:1");
    layout.tag(&prev, "ghcr.io/o/app:2");
    layout.tag(&cur, "ghcr.io/o/app:3");
    layout.tag(&cur, "ghcr.io/o/app:latest");
    layout.tag(&helper, "ghcr.io/o/helper:1");
    let store = Store::open(d.path().join("store")).unwrap();
    store.import_layout(layout.write()).unwrap();
    Three {
        store,
        shared: shared.digest.clone(),
        old,
        prev,
        cur,
        _d: d,
    }
}

#[test]
fn retain_keeps_exactly_the_keep_set() {
    let t = three_releases();
    let before = t.store.list().unwrap();
    assert_eq!((before.manifests, before.blobs), (4, 9));

    let swept = t
        .store
        .retain(&[
            r("ghcr.io/o/app:3"),
            r(&format!(
                "ghcr.io/o/helper@{}",
                t.store.resolve("ghcr.io/o/helper", "1").unwrap()
            )),
        ])
        .unwrap();

    assert_eq!(tags(&t.store), ["ghcr.io/o/app:3", "ghcr.io/o/helper:1"]);
    let after = t.store.list().unwrap();
    assert_eq!((after.manifests, after.blobs), (2, 5));
    assert_eq!(
        swept,
        Swept {
            tags: 3,
            manifests: 2,
            blobs: 4,
            bytes: before.bytes - after.bytes,
        }
    );
    assert!(
        t.store.blob_path(&t.shared).exists(),
        "a kept image's layer went"
    );
    assert!(!t.store.blob_path(&t.old.layers[1].digest).exists());
    assert!(!t.store.blob_path(&t.old.config.digest).exists());
    assert!(t.store.blob_path(&t.cur.config.digest).exists());
    assert_eq!(t.store.resolve("ghcr.io/o/app", "latest"), None);
    assert_eq!(t.store.manifest(&t.old.manifest.digest).unwrap(), None);
    assert_eq!(t.store.repair().unwrap(), 0);

    assert_eq!(
        t.store
            .retain(&[r("ghcr.io/o/app:3"), r("ghcr.io/o/helper:1")])
            .unwrap(),
        Swept::default()
    );
}

#[test]
fn retain_by_digest_keeps_its_tags() {
    let t = three_releases();
    let keep = r(&format!("ghcr.io/o/app@{}", t.cur.manifest.digest));
    t.store.retain(&[keep]).unwrap();
    assert_eq!(tags(&t.store), ["ghcr.io/o/app:3", "ghcr.io/o/app:latest"]);
    assert_eq!(t.store.list().unwrap().blobs, 3);
}

#[test]
fn retain_nothing_empties() {
    let t = three_releases();
    t.store.retain(&[r("ghcr.io/o/other:3")]).unwrap();
    let l = t.store.list().unwrap();
    assert_eq!(
        (l.images.len(), l.manifests, l.blobs, l.bytes),
        (0, 0, 0, 0)
    );
    let tag_dirs = std::fs::read_dir(t.store.root().join("tags"))
        .unwrap()
        .count();
    assert_eq!(tag_dirs, 0);
}

#[test]
fn repair_removes_torn() {
    let t = three_releases();
    let root = t.store.root();
    let blobs = root.join("blobs/sha256");
    let manifests = root.join("manifests/sha256");
    std::fs::write(blobs.join(format!("{}.edge-tmp", "0".repeat(64))), b"torn").unwrap();
    std::fs::write(manifests.join("junk"), b"x").unwrap();
    std::fs::create_dir(blobs.join("a".repeat(64))).unwrap();
    std::fs::write(
        root.join("tags/ghcr.io%o%app/bad tag"),
        t.cur.manifest.digest.to_string(),
    )
    .unwrap();
    std::fs::write(root.join("tags/ghcr.io%o%app/torn"), b"sha256:12").unwrap();
    std::fs::write(root.join("tags/NotARepo"), b"").unwrap();
    // A missing layer takes the previous release's manifest and tag with it.
    std::fs::remove_file(blobs.join(t.prev.layers[0].digest.hex())).unwrap();
    let flipped = flip_a_byte(&blobs.join(t.old.layers[1].digest.hex()));
    let before = tags(&t.store);

    assert_eq!(t.store.repair().unwrap(), 8);

    assert_eq!(t.store.manifest(&t.prev.manifest.digest).unwrap(), None);
    let after: Vec<_> = before
        .into_iter()
        .filter(|t| t != "ghcr.io/o/app:2")
        .collect();
    assert_eq!(tags(&t.store), after);
    assert!(flipped.exists(), "repair hashes nothing");
    for dir in [&blobs, &manifests] {
        for e in std::fs::read_dir(dir).unwrap() {
            let name = e.unwrap().file_name().into_string().unwrap();
            assert!(
                Digest::from_hex(&name).is_some(),
                "{name} left in {}",
                dir.display()
            );
        }
    }
    assert_eq!(t.store.repair().unwrap(), 0);
}

fn flip_a_byte(path: &std::path::Path) -> std::path::PathBuf {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(path, bytes).unwrap();
    path.to_path_buf()
}

#[test]
fn verify_removes_rot() {
    let t = three_releases();
    let root = t.store.root();
    let old_layer = flip_a_byte(&root.join("blobs/sha256").join(t.old.layers[1].digest.hex()));
    let helper = t.store.resolve("ghcr.io/o/helper", "1").unwrap();
    let manifest = root.join("manifests/sha256").join(helper.hex());
    let mut bytes = std::fs::read(&manifest).unwrap();
    bytes.push(b' ');
    std::fs::write(&manifest, bytes).unwrap();
    let before = tags(&t.store);

    assert_eq!(t.store.verify().unwrap(), 5);

    assert!(!old_layer.exists() && !manifest.exists());
    assert_eq!(t.store.manifest(&t.old.manifest.digest).unwrap(), None);
    let gone = ["ghcr.io/o/app:1", "ghcr.io/o/helper:1"];
    let after: Vec<_> = before
        .into_iter()
        .filter(|t| !gone.contains(&t.as_str()))
        .collect();
    assert_eq!(tags(&t.store), after);
    assert!(t.store.blob_path(&t.shared).exists());
    assert_eq!(t.store.verify().unwrap(), 0);
    assert_eq!(t.store.repair().unwrap(), 0);
}

#[test]
fn repair_waits_for_no_writer() {
    let t = three_releases();
    let torn = t.store.root().join("blobs/sha256/x.edge-tmp");
    std::fs::write(&torn, b"being written").unwrap();
    let lock = std::fs::File::open(t.store.root().join("lock")).unwrap();
    let held = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusive).unwrap();
    assert_eq!(t.store.repair().unwrap(), 0);
    assert!(torn.exists());
    drop(held);
    assert_eq!(t.store.repair().unwrap(), 1);
    assert!(!torn.exists());
}

#[test]
fn wrong_size_rejected() {
    let d = tempdir();
    let layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 1);
    let mut desc = app.manifest.descriptor(common::MANIFEST);
    desc["size"] = (app.manifest.bytes.len() + 1).into();
    std::fs::write(
        layout.dir.join("index.json"),
        serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "manifests": [desc]})).unwrap(),
    )
    .unwrap();
    std::fs::write(
        layout.dir.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let store = Store::open(d.path().join("store")).unwrap();
    assert!(store.import_layout(&layout.dir).is_err());
    assert_eq!(store.manifest(&app.manifest.digest).unwrap(), None);
}

#[test]
fn resolve_stays_in_tags() {
    let t = three_releases();
    let digest = t.cur.manifest.digest.to_string();
    std::fs::write(t.store.root().join("x"), &digest).unwrap();
    assert_eq!(t.store.resolve("..", "x"), None);
    assert_eq!(t.store.resolve("ghcr.io/o/app", "../../x"), None);
    assert_eq!(
        t.store.resolve("ghcr.io/o/app", &digest),
        Some(t.cur.manifest.digest.clone())
    );
}

#[test]
fn unreadable_manifest_is_an_error() {
    let t = three_releases();
    let path = t
        .store
        .root()
        .join("manifests/sha256")
        .join(t.cur.manifest.digest.hex());
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(t.store.manifest(&t.cur.manifest.digest).is_err());
}
