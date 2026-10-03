mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::{Canned, MANIFEST, Registry, Stub, import, tempdir};
use edge_registry::{Digest, Store};

struct Fixture {
    registry: Registry,
    stub: Stub,
    root: std::path::PathBuf,
    held: common::Image,
    _d: tempfile::TempDir,
}

const BAKED: &[u8] = b"{\"schemaVersion\":2,\"config\":{}}";
const BLOB: &[u8] = b"0123456789abcdef";

fn digest(b: &[u8]) -> String {
    Digest::of(b).to_string()
}

fn fixture() -> Fixture {
    let d = tempdir();
    let root = d.path().join("store");
    let [held] = import(
        &root,
        &d.path().join("layout"),
        [("held", "ghcr.io/o/app:v2")],
    );
    let mut answers = HashMap::new();
    let manifest = || Canned {
        status: "200 OK",
        headers: vec![
            ("Content-Type", MANIFEST.into()),
            ("Docker-Content-Digest", digest(BAKED)),
        ],
        body: BAKED.to_vec(),
    };
    answers.insert("/v2/o/app/manifests/v1?ns=ghcr.io".into(), manifest());
    answers.insert("/v2/stack/manifests/baked".into(), manifest());
    answers.insert(
        format!("/v2/o/app/blobs/{}?ns=ghcr.io", digest(BLOB)),
        Canned {
            status: "206 Partial Content",
            headers: vec![
                ("Content-Range", format!("bytes 4-7/{}", BLOB.len())),
                ("Docker-Content-Digest", digest(BLOB)),
            ],
            body: BLOB[4..8].to_vec(),
        },
    );
    answers.insert(
        "/v2/o/app/manifests/broken?ns=ghcr.io".into(),
        Canned {
            status: "500 Internal Server Error",
            headers: vec![],
            body: b"boom".to_vec(),
        },
    );
    let stub = Stub::start(answers);
    Fixture {
        registry: Registry::launch(&root, stub.port, None),
        stub,
        root,
        held,
        _d: d,
    }
}

#[test]
fn passes_a_miss_through() {
    let f = fixture();
    let resp = f.registry.get("/v2/o/app/manifests/v1?ns=ghcr.io");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, BAKED);
    assert_eq!(resp.header("content-type"), Some(MANIFEST));
    assert_eq!(
        resp.header("docker-content-digest"),
        Some(digest(BAKED).as_str())
    );
    let direct = f.registry.get("/v2/stack/manifests/baked");
    assert_eq!(direct.body, BAKED);
    let asked = f.stub.requests();
    assert!(
        asked[0].starts_with("GET /v2/o/app/manifests/v1?ns=ghcr.io HTTP/1.1"),
        "{asked:?}"
    );
    assert!(
        asked[1].starts_with("GET /v2/stack/manifests/baked HTTP/1.1"),
        "{asked:?}"
    );
}

#[test]
fn held_content_stays_local() {
    let f = fixture();
    let resp = f.registry.get("/v2/o/app/manifests/v2?ns=ghcr.io");
    assert_eq!(resp.body, f.held.manifest.bytes);
    let blob = f.registry.get(&format!(
        "/v2/o/app/blobs/{}?ns=ghcr.io",
        f.held.layers[0].digest
    ));
    assert_eq!(blob.body, f.held.layers[0].bytes);
    assert!(f.stub.requests().is_empty(), "{:?}", f.stub.requests());
}

#[test]
fn passes_range_through() {
    let f = fixture();
    let path = format!("/v2/o/app/blobs/{}?ns=ghcr.io", digest(BLOB));
    let resp = f
        .registry
        .request("GET", &path, &[("Range", "bytes=4-7"), ("Accept", "*/*")]);
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body, &BLOB[4..8]);
    assert_eq!(resp.header("content-range"), Some("bytes 4-7/16"));
    assert_eq!(resp.header("content-length"), Some("4"));
    let asked = f.stub.requests().join("").to_ascii_lowercase();
    assert!(
        asked.contains("range: bytes=4-7\r\n") && asked.contains("accept: */*\r\n"),
        "{asked}"
    );
}

#[test]
fn head_passes_through() {
    let f = fixture();
    let resp = f
        .registry
        .request("HEAD", "/v2/o/app/manifests/v1?ns=ghcr.io", &[]);
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty());
    assert_eq!(
        resp.header("content-length"),
        Some(BAKED.len().to_string().as_str())
    );
    assert!(f.stub.requests()[0].starts_with("HEAD "));
}

#[test]
fn upstream_miss_or_failure_is_404() {
    let f = fixture();
    for path in [
        "/v2/o/app/manifests/v9?ns=ghcr.io".to_string(),
        "/v2/o/app/manifests/broken?ns=ghcr.io".to_string(),
        format!("/v2/o/app/blobs/sha256:{}", "0".repeat(64)),
    ] {
        let resp = f.registry.get(&path);
        assert_eq!(resp.status, 404, "{path}");
        assert_eq!(
            resp.header("content-type"),
            Some("application/json"),
            "{path}"
        );
    }
    assert_eq!(f.stub.requests().len(), 3);
}

#[test]
fn nothing_passed_through_is_kept() {
    let f = fixture();
    let before = Store::open(&f.root).unwrap().list().unwrap();
    f.registry.get("/v2/o/app/manifests/v1?ns=ghcr.io");
    f.registry.request(
        "GET",
        &format!("/v2/o/app/blobs/{}?ns=ghcr.io", digest(BLOB)),
        &[("Range", "bytes=4-7")],
    );
    assert_eq!(Store::open(&f.root).unwrap().list().unwrap(), before);
    assert!(
        !Store::open(&f.root)
            .unwrap()
            .blob_path(&Digest::of(BLOB))
            .exists()
    );
}

#[test]
fn writes_never_reach_upstream() {
    let f = fixture();
    assert_eq!(
        f.registry
            .request("PUT", "/v2/o/app/manifests/v1?ns=ghcr.io", &[])
            .status,
        405
    );
    assert!(f.stub.requests().is_empty());
}

#[test]
fn unmounted_volume_passes_through_until_mounted() {
    let f = fixture();
    let vol = f.root.with_file_name("vol");
    let plain = f.root.with_file_name("plain");
    std::fs::create_dir(&plain).unwrap();
    std::os::unix::fs::symlink(&plain, &vol).unwrap();
    let held = "/v2/o/app/manifests/v2?ns=ghcr.io";

    let mut r = Registry::launch(&f.root, f.stub.port, Some(&vol));
    assert_eq!(r.get(held).status, 404, "served a store before its volume");
    assert_eq!(r.get("/v2/o/app/manifests/v1?ns=ghcr.io").body, BAKED);
    assert!(!r.exits_within(Duration::from_secs(2)));

    // A link to / stands in for the mount.
    let next = f.root.with_file_name("vol.next");
    std::os::unix::fs::symlink("/", &next).unwrap();
    std::fs::rename(&next, &vol).unwrap();
    assert!(
        r.exits_within(Duration::from_secs(10)),
        "never restarted to serve the mounted volume"
    );

    let r = Registry::launch(&f.root, f.stub.port, Some(&vol));
    assert_eq!(r.get(held).body, f.held.manifest.bytes);
}
