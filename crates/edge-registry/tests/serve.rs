mod common;

use common::{INDEX, Image, Layout, MANIFEST, Registry, import, tempdir};
use edge_registry::Store;

struct Fixture {
    registry: Registry,
    app: Image,
    multi: common::Blob,
    _d: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let d = tempdir();
    let mut layout = Layout::new(&d.path().join("layout"));
    let app = layout.image("app", 2);
    let arm = layout.image("arm", 1);
    let multi = layout.multi(&[&app, &arm], 2);
    layout.tag(&app, "ghcr.io/o/app:v1");
    layout.tag(&app, "nginx:1.27");
    layout.add(
        &multi,
        INDEX,
        &[(
            "org.opencontainers.image.ref.name",
            "registry.k8s.io/pause:3.10",
        )],
    );
    let root = d.path().join("store");
    Store::open(&root)
        .unwrap()
        .import_layout(layout.write())
        .unwrap();
    Fixture {
        registry: Registry::start(&root),
        app,
        multi,
        _d: d,
    }
}

#[test]
fn api_base() {
    let f = fixture();
    for method in ["GET", "HEAD"] {
        let resp = f.registry.request(method, "/v2/", &[]);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.header("docker-distribution-api-version"),
            Some("registry/2.0")
        );
    }
}

#[test]
fn pulls_by_tag() {
    let f = fixture();
    let resp = f.registry.get("/v2/o/app/manifests/v1?ns=ghcr.io");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, f.app.manifest.bytes);
    assert_eq!(resp.header("content-type"), Some(MANIFEST));
    let digest = f.app.manifest.digest.to_string();
    assert_eq!(resp.header("docker-content-digest"), Some(digest.as_str()));

    for blob in f.app.layers.iter().chain([&f.app.config]) {
        let resp = f
            .registry
            .get(&format!("/v2/o/app/blobs/{}?ns=ghcr.io", blob.digest));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, blob.bytes);
        assert_eq!(
            resp.header("content-length"),
            Some(blob.bytes.len().to_string().as_str())
        );
        assert_eq!(
            resp.header("docker-content-digest"),
            Some(blob.digest.to_string().as_str())
        );
    }

    let unqualified = f.registry.get("/v2/o/app/manifests/v1");
    assert_eq!(unqualified.body, f.app.manifest.bytes);
    let direct = f.registry.get("/v2/ghcr.io/o/app/manifests/v1");
    assert_eq!(direct.body, f.app.manifest.bytes);
    let docker = f
        .registry
        .get("/v2/library/nginx/manifests/1.27?ns=docker.io");
    assert_eq!(docker.body, f.app.manifest.bytes);
}

#[test]
fn pulls_by_digest() {
    let f = fixture();
    let resp = f.registry.get(&format!(
        "/v2/pause/manifests/{}?ns=registry.k8s.io",
        f.multi.digest
    ));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, f.multi.bytes);
    assert_eq!(resp.header("content-type"), Some(INDEX));

    let tagged = f
        .registry
        .get("/v2/pause/manifests/3.10?ns=registry.k8s.io");
    assert_eq!(tagged.body, f.multi.bytes);
    assert_eq!(
        tagged.header("docker-content-digest"),
        Some(f.multi.digest.to_string().as_str())
    );

    let child = f.registry.get(&format!(
        "/v2/pause/manifests/{}?ns=registry.k8s.io",
        f.app.manifest.digest
    ));
    assert_eq!(child.status, 200);
    assert_eq!(child.body, f.app.manifest.bytes);
}

#[test]
fn head_matches_get() {
    let f = fixture();
    for path in [
        "/v2/o/app/manifests/v1?ns=ghcr.io".to_string(),
        format!("/v2/o/app/blobs/{}?ns=ghcr.io", f.app.layers[0].digest),
    ] {
        let get = f.registry.get(&path);
        let head = f.registry.request("HEAD", &path, &[]);
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty());
        for h in ["content-type", "content-length", "docker-content-digest"] {
            assert_eq!(head.header(h), get.header(h), "{h}");
        }
    }
}

#[test]
fn blob_ranges() {
    let f = fixture();
    let blob = &f.app.layers[1];
    let len = blob.bytes.len();
    let path = format!("/v2/o/app/blobs/{}", blob.digest);
    let range = |r: &str| f.registry.request("GET", &path, &[("Range", r)]);

    let resp = range("bytes=10-19");
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body, &blob.bytes[10..20]);
    assert_eq!(
        resp.header("content-range"),
        Some(format!("bytes 10-19/{len}").as_str())
    );
    assert_eq!(resp.header("content-length"), Some("10"));
    assert_eq!(resp.header("accept-ranges"), Some("bytes"));

    let resp = range(&format!("bytes={}-", len - 5));
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body, &blob.bytes[len - 5..]);

    let resp = range("bytes=-7");
    assert_eq!(resp.body, &blob.bytes[len - 7..]);
    assert_eq!(
        resp.header("content-range"),
        Some(format!("bytes {}-{}/{len}", len - 7, len - 1).as_str())
    );

    let resp = range(&format!("bytes={len}-"));
    assert_eq!(resp.status, 416);
    assert_eq!(
        resp.header("content-range"),
        Some(format!("bytes */{len}").as_str())
    );

    let resp = range("bytes=0-1,5-6");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, blob.bytes);
}

#[test]
fn unknown_is_404() {
    let f = fixture();
    let absent = format!("sha256:{}", "0".repeat(64));
    for path in [
        "/v2/o/app/manifests/v2?ns=ghcr.io".to_string(),
        "/v2/o/app/manifests/v1?ns=docker.io".to_string(),
        format!("/v2/o/app/manifests/{absent}"),
        format!("/v2/o/app/blobs/{absent}"),
        "/v2/o/app/blobs/sha256:00".to_string(),
        "/v2/o/app/manifests/..%2F..%2Flock".to_string(),
        "/v2/o/../../lock/manifests/v1".to_string(),
        "/v2/o/app/tags/list".to_string(),
        "/v1/".to_string(),
    ] {
        let resp = f.registry.get(&path);
        assert_eq!(resp.status, 404, "{path}");
        assert_eq!(
            resp.header("content-type"),
            Some("application/json"),
            "{path}"
        );
    }
}

#[test]
fn read_only() {
    let f = fixture();
    for (method, path) in [
        ("POST", "/v2/o/app/blobs/uploads/"),
        ("PUT", "/v2/o/app/manifests/v1"),
        ("DELETE", "/v2/o/app/manifests/v1"),
        ("PATCH", "/v2/o/app/blobs/uploads/x"),
    ] {
        assert_eq!(
            f.registry.request(method, path, &[]).status,
            405,
            "{method}"
        );
    }
    assert_eq!(
        f.registry.get("/v2/o/app/manifests/v1?ns=ghcr.io").status,
        200
    );
}

#[test]
fn serves_what_is_imported_later() {
    let f = fixture();
    let d = tempdir();
    let root = f._d.path().join("store");
    let [next] = import(&root, d.path(), [("next", "ghcr.io/o/app:v2")]);
    let resp = f.registry.get("/v2/o/app/manifests/v2?ns=ghcr.io");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, next.manifest.bytes);

    Store::open(&root)
        .unwrap()
        .retain(&["ghcr.io/o/app:v2".parse().unwrap()])
        .unwrap();
    assert_eq!(
        f.registry.get("/v2/o/app/manifests/v1?ns=ghcr.io").status,
        404
    );
    assert_eq!(
        f.registry.get("/v2/o/app/manifests/v2?ns=ghcr.io").status,
        200
    );
}

#[test]
fn repairs_at_start_and_verifies_after() {
    let d = tempdir();
    let root = d.path().join("store");
    let [app, gone] = import(
        &root,
        &d.path().join("layout"),
        [("app", "ghcr.io/o/app:v1"), ("gone", "ghcr.io/o/gone:v1")],
    );
    let store = Store::open(&root).unwrap();
    let rotted = store.blob_path(&app.layers[0].digest);
    std::fs::write(&rotted, b"rot").unwrap();
    let temp = rotted.with_extension("edge-tmp");
    std::fs::write(&temp, b"half").unwrap();
    std::fs::remove_file(store.blob_path(&gone.layers[0].digest)).unwrap();

    let registry = Registry::start(&root);

    assert!(!temp.exists());
    assert_eq!(
        registry.get("/v2/o/gone/manifests/v1?ns=ghcr.io").status,
        404
    );
    let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while registry.get("/v2/o/app/manifests/v1?ns=ghcr.io").status != 404 {
        assert!(
            std::time::Instant::now() < until,
            "the verify pass never removed the rotted blob's image"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!rotted.exists());
}

#[test]
fn finds_a_repository_without_its_registry() {
    let d = tempdir();
    let root = d.path().join("store");
    let [stack] = import(
        &root,
        &d.path().join("layout"),
        [("stack", "127.0.0.1:5999/stack:t1")],
    );
    let registry = Registry::start(&root);
    let resp = registry.get("/v2/stack/manifests/t1");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, stack.manifest.bytes);
    assert_eq!(registry.get("/v2/other-stack/manifests/t1").status, 404);
}

#[test]
fn decodes_percent_encoding() {
    let d = tempdir();
    let root = d.path().join("store");
    let [installer] = import(
        &root,
        &d.path().join("layout"),
        [("installer", "127.0.0.1:5999/installer:v1")],
    );
    let registry = Registry::start(&root);
    let encoded = installer.manifest.digest.to_string().replace(':', "%3A");
    for path in [
        "/v2/installer/manifests/v1?ns=127.0.0.1%3A5999".to_string(),
        "/v2/install%65r/manifests/v1?ns=127.0.0.1%3A5999".to_string(),
        format!("/v2/installer/manifests/{encoded}?ns=127.0.0.1%3A5999"),
        format!("/v2/installer/blobs/{}", installer.layers[0].digest).replace(':', "%3A"),
    ] {
        assert_eq!(registry.get(&path).status, 200, "{path}");
    }
}
