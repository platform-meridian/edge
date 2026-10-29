//! The write side over HTTP: core pushes, the controller deletes, nobody else
//! writes, and what is pushed is pulled like anything held.

mod common;

use common::{Registry, tempdir};
use edge_registry::Digest;
use jsonwebtoken::{Algorithm, EncodingKey, Header};

const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDK331EumFEcyY/Kp
DFarwEZgsBaO7lvVZUP/DrVEDl+hRANCAASajR7Pu+b0+jKpDws8nNwjs0O3ULbv
fQFUbupG9+wIul6vIcLW84AWpP7HSp30rZY38vcnoobbgL24T1v1v0RL
-----END PRIVATE KEY-----
";
const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmo0ez7vm9PoyqQ8LPJzcI7NDt1C2
730BVG7qRvfsCLperyHC1vOAFqT+x0qd9K2WN/L3J6KG24C9uE9b9b9ESw==
-----END PUBLIC KEY-----
";

fn bearer(sub: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({"sub": sub, "aud": ["edge-registry"], "exp": now + 600});
    let key = EncodingKey::from_ec_pem(KEY.as_bytes()).unwrap();
    let t = jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap();
    format!("Bearer {t}")
}

const CORE: &str = "system:serviceaccount:meridian:platform-core";
const CONTROLLER: &str = "system:serviceaccount:meridian-system:platform-operator";

fn push_blob(r: &Registry, auth: &str, bytes: &[u8]) -> Digest {
    let d = Digest::of(bytes);
    let begun = r.send(
        "POST",
        "/v2/platform-meridian/app/blobs/uploads/",
        &[("Authorization", auth)],
        &[],
    );
    assert_eq!(
        begun.status,
        202,
        "{}",
        String::from_utf8_lossy(&begun.body)
    );
    let at = begun.header("location").unwrap().to_string();
    let done = r.send(
        "PUT",
        &format!("{at}?digest={d}"),
        &[("Authorization", auth)],
        bytes,
    );
    assert_eq!(done.status, 201, "{}", String::from_utf8_lossy(&done.body));
    assert_eq!(
        done.header("docker-content-digest"),
        Some(d.to_string().as_str())
    );
    d
}

#[test]
fn core_pushes_an_artifact_that_pulls_back_and_the_controller_deletes_it() {
    let d = tempdir();
    let keys = d.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("sa.pub"), PUBLIC).unwrap();
    let root = d.path().join("store");
    edge_registry::Store::open(&root).unwrap();
    let r = Registry::pushing(&root, &keys.join("sa.pub"));
    let (core, controller) = (bearer(CORE), bearer(CONTROLLER));

    let config = push_blob(&r, &core, b"{}");
    let layer = push_blob(&r, &core, b"[{\"kind\":\"ConfigMap\"}]");
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.meridian.app.v1",
        "config": {"mediaType": "application/vnd.meridian.app.config.v1+json", "digest": config.to_string(), "size": 2},
        "layers": [{"mediaType": "application/vnd.meridian.app.manifests.v1+json", "digest": layer.to_string(), "size": 22}],
    }))
    .unwrap();
    let ct = ("Content-Type", "application/vnd.oci.image.manifest.v1+json");
    let put = r.send(
        "PUT",
        "/v2/platform-meridian/app/manifests/1.5.0",
        &[("Authorization", &core), ct],
        &manifest,
    );
    assert_eq!(put.status, 201, "{}", String::from_utf8_lossy(&put.body));
    let digest = put.header("docker-content-digest").unwrap().to_string();
    assert_eq!(digest, Digest::of(&manifest).to_string());

    // Pulled as any image is: by tag and by digest, with its blobs.
    for reference in ["1.5.0", digest.as_str()] {
        let got = r.get(&format!("/v2/platform-meridian/app/manifests/{reference}"));
        assert_eq!(got.status, 200, "{reference}");
        assert_eq!(got.body, manifest);
    }
    assert_eq!(
        r.get(&format!("/v2/platform-meridian/app/blobs/{layer}"))
            .status,
        200
    );

    // Nobody else writes; core does not delete; the controller does not push.
    let anon = r.send("PUT", "/v2/x/manifests/t", &[ct], &manifest);
    assert_eq!(anon.status, 401);
    assert!(
        anon.header("www-authenticate")
            .is_some_and(|h| h.starts_with("Bearer"))
    );
    let app = bearer("system:serviceaccount:meridian:app-fusion");
    assert_eq!(
        r.send(
            "PUT",
            "/v2/x/manifests/t",
            &[("Authorization", &app), ct],
            &manifest
        )
        .status,
        401
    );
    let del = format!("/v2/platform-meridian/app/manifests/{digest}");
    assert_eq!(
        r.request("DELETE", &del, &[("Authorization", &core)])
            .status,
        403
    );
    assert_eq!(
        r.send(
            "POST",
            "/v2/x/blobs/uploads/",
            &[("Authorization", &controller)],
            &[]
        )
        .status,
        403
    );

    assert_eq!(
        r.request("DELETE", &del, &[("Authorization", &controller)])
            .status,
        202
    );
    assert_eq!(
        r.get("/v2/platform-meridian/app/manifests/1.5.0").status,
        404
    );
    assert_eq!(
        r.request("DELETE", &del, &[("Authorization", &controller)])
            .status,
        404
    );
}

#[test]
fn without_push_keys_the_registry_is_read_only() {
    let d = tempdir();
    let root = d.path().join("store");
    edge_registry::Store::open(&root).unwrap();
    let r = Registry::start(&root);
    let resp = r.send(
        "POST",
        "/v2/x/blobs/uploads/",
        &[("Authorization", &bearer(CORE))],
        &[],
    );
    assert_eq!(resp.status, 405);
}

#[test]
fn before_the_keys_are_there_nothing_is_pushed_and_their_arrival_restarts_it() {
    let d = tempdir();
    let root = d.path().join("store");
    edge_registry::Store::open(&root).unwrap();
    let keys = d.path().join("later");
    let mut r = Registry::pushing(&root, &keys.join("sa.pub"));
    let resp = r.send(
        "POST",
        "/v2/x/blobs/uploads/",
        &[("Authorization", &bearer(CORE))],
        &[],
    );
    assert_eq!(resp.status, 405);
    std::fs::create_dir_all(&keys).unwrap();
    assert!(
        r.exits_within(std::time::Duration::from_secs(10)),
        "not restarted"
    );
}
