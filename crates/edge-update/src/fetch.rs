//! Copies the running stack's artifact into the unit's registry before the
//! stack moves there, so a rollback to it resolves at the new address too.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use sha2::{Digest, Sha256};

#[async_trait]
pub trait Fetch: Send + Sync {
    /// Writes the artifact `url`:`tag` as an OCI image layout at `layout`, named `name`.
    async fn artifact(&self, url: &str, tag: &str, name: &str, layout: &Path)
    -> anyhow::Result<()>;
}

const ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
const MAX: usize = 256 << 20;

pub struct Http {
    client: Client<HttpConnector, Empty<Bytes>>,
}

impl Http {
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    async fn get(&self, uri: &str, accept: Option<&str>) -> anyhow::Result<Bytes> {
        let mut req = http::Request::get(uri);
        if let Some(a) = accept {
            req = req.header(http::header::ACCEPT, a);
        }
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.client.request(req.body(Empty::new())?),
        )
        .await
        .context("the registry did not answer")??;
        ensure!(resp.status().is_success(), "{uri}: {}", resp.status());
        let body = http_body_util::Limited::new(resp.into_body(), MAX)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("{uri}: {e}"))?;
        Ok(body.to_bytes())
    }
}

/// `oci://host/path` as (host, path).
pub fn split(url: &str) -> anyhow::Result<(&str, &str)> {
    url.strip_prefix("oci://")
        .and_then(|r| r.split_once('/'))
        .filter(|(h, p)| !h.is_empty() && !p.is_empty())
        .with_context(|| format!("{url} is not oci://host/repository"))
}

fn sha(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

pub fn write_layout(
    layout: &Path,
    name: &str,
    manifest: &[u8],
    blobs: &[Bytes],
) -> anyhow::Result<()> {
    let tmp = layout.with_extension("part");
    let _ = std::fs::remove_dir_all(&tmp);
    let dir = tmp.join("blobs/sha256");
    std::fs::create_dir_all(&dir)?;
    for b in blobs.iter().map(|b| b.as_ref()).chain([manifest]) {
        std::fs::write(dir.join(&sha(b)["sha256:".len()..]), b)?;
    }
    let media: serde_json::Value = serde_json::from_slice(manifest)?;
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": media["mediaType"].as_str().unwrap_or("application/vnd.oci.image.manifest.v1+json"),
            "digest": sha(manifest),
            "size": manifest.len(),
            "annotations": { "io.containerd.image.name": name },
        }],
    });
    std::fs::write(tmp.join("index.json"), index.to_string())?;
    std::fs::write(tmp.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)?;
    let _ = std::fs::remove_dir_all(layout);
    std::fs::rename(&tmp, layout)?;
    Ok(())
}

#[async_trait]
impl Fetch for Http {
    async fn artifact(
        &self,
        url: &str,
        tag: &str,
        name: &str,
        layout: &Path,
    ) -> anyhow::Result<()> {
        let (host, repo) = split(url)?;
        let base = format!("http://{host}/v2/{repo}");
        let manifest = self
            .get(&format!("{base}/manifests/{tag}"), Some(ACCEPT))
            .await?;
        let m: serde_json::Value =
            serde_json::from_slice(&manifest).context("the artifact's manifest")?;
        if m["manifests"].is_array() {
            bail!("{url}:{tag} is an index, not an artifact");
        }
        let mut blobs = Vec::new();
        let layers = m["layers"].as_array().cloned().unwrap_or_default();
        for d in std::iter::once(&m["config"]).chain(&layers) {
            let digest = d["digest"]
                .as_str()
                .context("a descriptor with no digest")?;
            let b = self.get(&format!("{base}/blobs/{digest}"), None).await?;
            ensure!(sha(&b) == digest, "{digest} arrived as {}", sha(&b));
            blobs.push(b);
        }
        let layout = layout.to_path_buf();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || write_layout(&layout, &name, &manifest, &blobs)).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_host_and_repository() {
        assert_eq!(
            split("oci://127.0.0.1:3172/stack").unwrap(),
            ("127.0.0.1:3172", "stack")
        );
        assert_eq!(split("oci://h/a/b").unwrap(), ("h", "a/b"));
        assert!(split("https://h/a").is_err());
        assert!(split("oci://h").is_err());
    }

    #[tokio::test]
    async fn an_artifact_is_copied_as_a_layout() {
        use hyper::service::service_fn;
        let config = Bytes::from_static(b"{}");
        let layer = Bytes::from_static(b"manifests.tar.gz");
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": sha(&config), "size": 2 },
            "layers": [{ "digest": sha(&layer), "size": layer.len() }],
        })
        .to_string();
        let files: std::collections::HashMap<String, Bytes> = [
            (
                "/v2/stack/manifests/t1".to_string(),
                Bytes::from(manifest.clone()),
            ),
            (format!("/v2/stack/blobs/{}", sha(&config)), config.clone()),
            (format!("/v2/stack/blobs/{}", sha(&layer)), layer.clone()),
        ]
        .into_iter()
        .collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let files = files.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |r: http::Request<hyper::body::Incoming>| {
                        let body = files.get(r.uri().path()).cloned();
                        async move {
                            let mut resp = http::Response::new(http_body_util::Full::new(
                                body.clone().unwrap_or_default(),
                            ));
                            if body.is_none() {
                                *resp.status_mut() = http::StatusCode::NOT_FOUND;
                            }
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        let d = tempfile::tempdir().unwrap();
        let layout = d.path().join("layout");
        let url = format!("oci://{addr}/stack");
        Http::new()
            .artifact(&url, "t1", "stack:t1", &layout)
            .await
            .unwrap();
        let refs = crate::bundle::layout_refs(&layout).unwrap();
        assert_eq!(refs.into_iter().collect::<Vec<_>>(), ["stack:t1"]);
        let hex = |b: &[u8]| sha(b)["sha256:".len()..].to_string();
        assert_eq!(
            std::fs::read(layout.join("blobs/sha256").join(hex(&layer))).unwrap(),
            layer
        );
        assert_eq!(
            std::fs::read(layout.join("blobs/sha256").join(hex(manifest.as_bytes()))).unwrap(),
            manifest.as_bytes()
        );
        assert!(
            Http::new()
                .artifact(&url, "missing", "stack:x", &d.path().join("x"))
                .await
                .is_err()
        );
    }
}
