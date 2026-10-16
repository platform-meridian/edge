use std::io::Read;

use edge_bundle::testkit::{SIGNER, sign, trust};

use super::*;

const MODULE: &str = r#"
name = "web"
machine = ["machine.yaml"]
values = ["HUB"]

[requires]
talos = ">=v1.14.0"
kubernetes = ">=v1.35.0"
components = ["helm-controller"]

[images]
WEB_IMAGE = "ghcr.io/o/app-web:old@sha256:0000000000000000000000000000000000000000000000000000000000000000"

[image_names]
WEB_IMAGE = "app-web"

[secrets]
WEB_KEY = "hex32"
"#;

const DEPLOYMENT: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\n\
    spec:\n  template:\n    spec:\n      containers:\n        - image: app-web\n          \
    env:\n            - {name: DOMAIN, value: \"${OPERATOR_DOMAIN}\"}\n            \
    - {name: HUB, value: \"${HUB}\"}\n            - {name: KEY, value: \"${WEB_KEY}\"}\n";

fn sha(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

/// `deploy/`, and a layout holding one image as `skopeo copy` leaves it; its digest.
fn app(d: &Path) -> (PathBuf, PathBuf, String) {
    let deploy = d.join("deploy");
    std::fs::create_dir_all(deploy.join("manifests")).unwrap();
    std::fs::write(deploy.join(FILE), MODULE).unwrap();
    std::fs::write(
        deploy.join("kustomization.yaml"),
        "resources:\n  - manifests/web.yaml\n",
    )
    .unwrap();
    std::fs::write(deploy.join("manifests/web.yaml"), DEPLOYMENT).unwrap();
    std::fs::write(
        deploy.join("machine.yaml"),
        "apiVersion: v1alpha1\nkind: UserVolumeConfig\nname: web-data\n",
    )
    .unwrap();

    let layout = d.join("layout");
    let blobs = layout.join("blobs/sha256");
    std::fs::create_dir_all(&blobs).unwrap();
    let put = |b: &[u8]| {
        let h = sha(b);
        std::fs::write(blobs.join(&h[7..]), b).unwrap();
        h
    };
    let (config, layer) = (b"{\"os\":\"linux\"}".to_vec(), b"a layer".to_vec());
    let m = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": put(&config), "size": config.len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": put(&layer), "size": layer.len()}],
    }))
    .unwrap();
    let digest = put(&m);
    let index = serde_json::json!({"schemaVersion": 2, "manifests": [{
        "mediaType": OCI_MANIFEST, "digest": digest, "size": m.len(),
        "annotations": {"org.opencontainers.image.ref.name": "ghcr.io/o/app-web:v1.2.0"},
    }]});
    std::fs::write(layout.join("index.json"), index.to_string()).unwrap();
    (deploy, layout, digest)
}

fn packed(d: &Path, deploy: &Path, layout: &Path, image: &str) -> anyhow::Result<PathBuf> {
    let out = d.join("staged");
    let _ = std::fs::remove_dir_all(&out);
    let images = BTreeMap::from([("WEB_IMAGE".to_string(), image.to_string())]);
    pack(
        &Pack {
            deploy,
            layouts: &[layout.to_path_buf()],
            images: &images,
            version: "v1.2.0",
            epoch: 1_760_000_000,
            artifact: "ghcr.io/o/app-web/module",
            notes: Some("# v1.2.0\n"),
            secret_owner: Some(&SecretOwner {
                namespace: "platform".into(),
                service_account: "generator".into(),
                label: ("example.com/generated-secret".into(), "true".into()),
            }),
        },
        &out,
    )?;
    Ok(out)
}

#[test]
fn an_app_packs_signs_and_unpacks_as_a_unit_reads_it() {
    let d = tempfile::tempdir().unwrap();
    let (deploy, layout, digest) = app(d.path());
    let image = format!("ghcr.io/o/app-web:v1.2.0@{digest}");
    let staged = packed(d.path(), &deploy, &layout, &image).unwrap();
    let sums = std::fs::read(staged.join(edge_bundle::SUMS)).unwrap();
    let tar = d.path().join("app.tar");
    edge_bundle::seal(&staged, Some(&sign(SIGNER, &sums)), 0, &tar).unwrap();

    let dest = d.path().join("unpacked");
    let u = edge_bundle::unpack(&tar, &dest, &trust()).unwrap();
    assert_eq!(u.signer, SIGNER);
    assert!(!edge_bundle::has_base(&u.manifest));
    assert_eq!(u.manifest["MODULES"], "web");
    let (c, carried) = edge_bundle::check(&dest).unwrap();
    let m = &c.modules["web"];
    assert_eq!((m.version.as_str(), m.epoch), ("v1.2.0", 1_760_000_000));
    assert_eq!(
        m.requires,
        Requires {
            talos: "v1.14.0".into(),
            kubernetes: "v1.35.0".into(),
            flux: ["helm-controller".to_string()].into(),
        }
    );
    assert!(m.machine.contains("name: web-data"));
    assert_eq!(
        carried.into_iter().collect::<Vec<_>>(),
        [
            "ghcr.io/o/app-web/module:v1.2.0",
            "ghcr.io/o/app-web:v1.2.0"
        ]
    );
    let images = edge_bundle::layout_images(&dest.join(edge_bundle::IMAGES)).unwrap();
    assert_eq!(images["ghcr.io/o/app-web:v1.2.0"], digest);
    let artifact = &images["ghcr.io/o/app-web/module:v1.2.0"];
    assert_eq!(
        u.manifest["MODULE_WEB"],
        format!("ghcr.io/o/app-web/module:v1.2.0@{artifact}")
    );
    for want in [
        "url: oci://127.0.0.1:5000/o/app-web/module",
        &format!("digest: {artifact}"),
        "name: node-facts",
        "name: module-web-values",
        "name: module-web\n",
        "hex32: \"WEB_KEY\"",
        "namespace: platform\n  labels: { example.com/generated-secret: \"true\" }",
        "{ kind: ServiceAccount, name: generator, namespace: platform }",
    ] {
        assert!(m.flux.contains(want), "{want} not in\n{}", m.flux);
    }

    // The manifests, as Flux unpacks the artifact: no build inputs, images pinned.
    let blob =
        |d: &str| edge_bundle::components::layout_blob(&dest.join(edge_bundle::IMAGES), d).unwrap();
    let man: serde_json::Value = serde_json::from_slice(&blob(artifact)).unwrap();
    assert_eq!(man["layers"][0]["mediaType"], FLUX_CONTENT);
    let layer = blob(man["layers"][0]["digest"].as_str().unwrap());
    let mut a = tar::Archive::new(flate2::read::GzDecoder::new(layer.as_slice()));
    let mut tree = BTreeMap::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        let mut t = String::new();
        e.read_to_string(&mut t).unwrap();
        tree.insert(e.path().unwrap().display().to_string(), t);
    }
    assert_eq!(
        tree.keys().collect::<Vec<_>>(),
        ["kustomization.yaml", "manifests/web.yaml"]
    );
    assert!(tree["kustomization.yaml"].contains(&format!(
        "  - name: app-web\n    newName: ghcr.io/o/app-web\n    newTag: v1.2.0\n    digest: {digest}\n"
    )));

    let again = packed(d.path(), &deploy, &layout, &image).unwrap();
    assert_eq!(
        std::fs::read(again.join(edge_bundle::SUMS)).unwrap(),
        sums,
        "the same inputs pack the same app"
    );
}

#[test]
fn a_pack_refuses_what_a_unit_could_not_fill() {
    let d = tempfile::tempdir().unwrap();
    let (deploy, layout, digest) = app(d.path());
    let image = format!("ghcr.io/o/app-web:v1.2.0@{digest}");
    let err = |image: &str| {
        format!(
            "{:#}",
            packed(d.path(), &deploy, &layout, image).unwrap_err()
        )
    };
    let edit = |from: &str, to: &str| {
        let p = deploy.join("manifests/web.yaml");
        let t = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, t.replace(from, to)).unwrap();
    };

    assert!(err("ghcr.io/o/app-web:v1.2.0").contains("not pinned by digest"));
    let gone = format!("ghcr.io/o/app-web@sha256:{}", "1".repeat(64));
    assert!(err(&gone).contains("no image layout holds"));

    edit("${HUB}", "${ELSEWHERE}");
    let e = err(&image);
    assert!(
        e.contains("manifests/web.yaml:") && e.contains("ELSEWHERE"),
        "{e}"
    );
    edit("${ELSEWHERE}", "@HUB@");
    assert!(err(&image).contains("a build-time @KEY@"));
    edit("@HUB@", "plain");
    let e = err(&image);
    assert!(e.contains("never name") && e.contains("HUB"), "{e}");
    edit("plain", "${HUB}");

    let toml = std::fs::read_to_string(deploy.join(FILE)).unwrap();
    std::fs::write(
        deploy.join(FILE),
        toml.replace(">=v1.14.0", ">=v1.14.0, <v1.15.0"),
    )
    .unwrap();
    assert!(err(&image).contains("a unit checks a minimum"));
    std::fs::write(
        deploy.join(FILE),
        toml.replace("values = [\"HUB\"]", "site = [\"HUB\"]"),
    )
    .unwrap();
    assert!(err(&image).contains("not a module"));
    std::fs::write(deploy.join(FILE), toml).unwrap();
    packed(d.path(), &deploy, &layout, &image).unwrap();
}
