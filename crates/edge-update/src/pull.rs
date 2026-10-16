//! Pulls an app by OCI reference into the upload, chunk by chunk, so the
//! upload's checks apply. HTTPS, but HTTP for a loopback registry.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use bytes::Bytes;
use edge_registry::ImageRef;
use http::{Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::bundle;
use crate::upload::{CHUNK, Uploads};

const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

type Https = hyper_rustls::HttpsConnector<HttpConnector>;

pub struct Puller {
    client: Client<Https, Empty<Bytes>>,
    /// `user:password` by registry host.
    logins: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct DockerConfig {
    #[serde(default)]
    auths: BTreeMap<String, DockerAuth>,
}

#[derive(Deserialize)]
struct DockerAuth {
    #[serde(default)]
    auth: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    #[serde(default)]
    artifact_type: String,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
}

impl Puller {
    pub fn new(docker_config: Option<&Path>) -> anyhow::Result<Self> {
        let mut logins = BTreeMap::new();
        if let Some(p) = docker_config {
            let c: DockerConfig = serde_json::from_slice(
                &std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
            )
            .with_context(|| format!("{} is not a Docker config", p.display()))?;
            for (host, a) in c.auths {
                let login = base64::engine::general_purpose::STANDARD
                    .decode(a.auth.trim())
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .with_context(|| format!("the login for {host} is not base64 user:password"))?;
                logins.insert(host, login);
            }
        }
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(https),
            logins,
        })
    }

    /// Pulls the app `reference` into `uploads` as `by`; returns its bundle's sha256.
    pub async fn pull(
        &self,
        reference: &str,
        uploads: &Arc<Mutex<Uploads>>,
        by: &str,
    ) -> anyhow::Result<String> {
        let r: ImageRef = reference.parse().map_err(anyhow::Error::msg)?;
        let (host, path) = r.repo.split_once('/').context("no registry host")?;
        let host = match host {
            "docker.io" => "registry-1.docker.io",
            h => h,
        };
        let pinned = r.digest.as_ref().map(|d| d.to_string());
        let at = pinned.clone().or(r.tag.clone()).unwrap_or_default();
        let base = format!("{}://{host}/v2/{path}", scheme(host));
        let mut token = None;
        let body = self
            .get(
                &format!("{base}/manifests/{at}"),
                MANIFEST,
                None,
                &mut token,
            )
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        if let Some(d) = &pinned {
            ensure!(
                format!("sha256:{}", hex::encode(Sha256::digest(&body))) == *d,
                "{reference}'s manifest does not match its digest"
            );
        }
        let m: Manifest = serde_json::from_slice(&body)
            .with_context(|| format!("{reference}'s manifest is not an OCI image manifest"))?;
        let layer = match m.layers.as_slice() {
            [l] if m.artifact_type == bundle::APP_ARTIFACT && l.media_type == bundle::APP_LAYER => {
                l
            }
            _ => bail!(
                "{reference} is not an app: no {} artifact",
                bundle::APP_ARTIFACT
            ),
        };
        let sha = layer
            .digest
            .strip_prefix("sha256:")
            .context("the app's layer is not named by sha256")?
            .to_string();
        let (size, s, by) = (layer.size, sha.clone(), by.to_string());
        let held = blocking(uploads, move |u| {
            let up = u.begin(size, &s, &by)?;
            Ok((up.complete, up.start()))
        })
        .await?;
        if held.0 {
            return Ok(sha);
        }
        let from = held.1;
        let mut res = self
            .get(
                &format!("{base}/blobs/{}", layer.digest),
                "*/*",
                Some(from),
                &mut token,
            )
            .await?;
        // A registry that ignores the range sends it all.
        let mut skip = match res.status() {
            StatusCode::PARTIAL_CONTENT => 0,
            _ => from,
        };
        let (mut index, mut chunk) = ((from / CHUNK as u64) as u32, Vec::new());
        while let Some(frame) = res.body_mut().frame().await {
            let Ok(mut data) = frame?.into_data() else {
                continue;
            };
            let drop = (skip as usize).min(data.len());
            data = data.slice(drop..);
            skip -= drop as u64;
            chunk.extend_from_slice(&data);
            while chunk.len() >= CHUNK as usize {
                let rest = chunk.split_off(CHUNK as usize);
                put(uploads, &sha, index, std::mem::replace(&mut chunk, rest)).await?;
                index += 1;
            }
        }
        if !chunk.is_empty() {
            put(uploads, &sha, index, chunk).await?;
        }
        let s = sha.clone();
        let complete = blocking(uploads, move |u| {
            Ok(u.current().is_some_and(|c| c.sha256 == s && c.complete))
        })
        .await?;
        ensure!(complete, "{reference}'s app ended before its size");
        Ok(sha)
    }

    /// Downloads the bundle at `url` into `uploads` as `by`, resuming a
    /// download of the same url cut short; returns its sha256.
    pub async fn download(
        &self,
        url: &str,
        uploads: &Arc<Mutex<Uploads>>,
        by: &str,
    ) -> anyhow::Result<String> {
        let u: Uri = url
            .parse()
            .with_context(|| format!("{url:?} is not a URL"))?;
        let host = u.authority().map(|a| a.as_str()).unwrap_or_default();
        ensure!(u.scheme_str() == Some(scheme(host)), "{url} is not https");
        let (part, from) = blocking(uploads, |u| Ok(u.download())).await?;
        if std::fs::read_to_string(&from).ok().as_deref() != Some(url) {
            let _ = std::fs::remove_file(&part);
            std::fs::create_dir_all(from.parent().context("no upload directory")?)?;
            std::fs::write(&from, url)?;
        }
        let held = std::fs::metadata(&part).map_or(0, |m| m.len());
        let mut res = self.get(url, "*/*", Some(held), &mut None).await?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&part)?;
        // A server that ignores the range sends it all.
        if res.status() != StatusCode::PARTIAL_CONTENT {
            f.set_len(0)?;
        }
        while let Some(frame) = res.body_mut().frame().await {
            if let Ok(data) = frame?.into_data() {
                std::io::Write::write_all(&mut f, &data)?;
            }
        }
        f.sync_all()?;
        let by = by.to_string();
        Ok(blocking(uploads, move |u| u.adopt(&by)).await?.sha256)
    }

    /// GET `url`, past the registry's bearer challenge and its redirects.
    async fn get(
        &self,
        url: &str,
        accept: &str,
        from: Option<u64>,
        token: &mut Option<String>,
    ) -> anyhow::Result<Response<hyper::body::Incoming>> {
        let mut url: Uri = url.parse()?;
        let origin = url.authority().map(|a| a.to_string());
        for _ in 0..8 {
            let mut req = Request::get(url.clone()).header(header::ACCEPT, accept);
            if let Some(f) = from.filter(|f| *f > 0) {
                req = req.header(header::RANGE, format!("bytes={f}-"));
            }
            // The token stays with the registry.
            let home = url.authority().map(|a| a.to_string()) == origin;
            if let Some(t) = token.as_ref().filter(|_| home) {
                req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
            }
            let res = self.client.request(req.body(Empty::new())?).await?;
            match res.status() {
                StatusCode::UNAUTHORIZED if token.is_none() && home => {
                    let challenge = res
                        .headers()
                        .get(header::WWW_AUTHENTICATE)
                        .and_then(|v| v.to_str().ok())
                        .context("the registry refuses without saying how to log in")?;
                    *token = Some(self.token(challenge, origin.as_deref()).await?);
                }
                s if s.is_redirection() => {
                    let to = res
                        .headers()
                        .get(header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .context("a redirect without a location")?;
                    url = join(&url, to)?;
                }
                s if s.is_success() => return Ok(res),
                s => bail!("{url}: {s}"),
            }
        }
        bail!("{url}: too many redirects")
    }

    /// A bearer token for a challenge `Bearer realm="…",service="…",scope="…"`.
    async fn token(&self, challenge: &str, host: Option<&str>) -> anyhow::Result<String> {
        let params = challenge
            .strip_prefix("Bearer ")
            .context("the registry asks for a login other than a bearer token")?;
        let (realm, query) = realm_and_query(params)?;
        let mut req = Request::get(format!("{realm}?{query}"));
        if let Some(login) = host.and_then(|h| self.logins.get(h)) {
            let basic = base64::engine::general_purpose::STANDARD.encode(login);
            req = req.header(header::AUTHORIZATION, format!("Basic {basic}"));
        }
        let res = self.client.request(req.body(Empty::new())?).await?;
        ensure!(
            res.status().is_success(),
            "the registry's token: {}",
            res.status()
        );
        #[derive(Deserialize)]
        struct Token {
            #[serde(alias = "access_token")]
            token: String,
        }
        let body = res.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice::<Token>(&body)
            .context("the registry's token is not JSON")?
            .token)
    }
}

/// A challenge's realm, and its other parameters as a query.
fn realm_and_query(params: &str) -> anyhow::Result<(String, String)> {
    let (mut realm, mut query) = (None, form_urlencoded::Serializer::new(String::new()));
    for p in params.split(',') {
        let Some((k, v)) = p.trim().split_once('=') else {
            continue;
        };
        let v = v.trim_matches('"');
        match k {
            "realm" => realm = Some(v.to_string()),
            _ => {
                query.append_pair(k, v);
            }
        }
    }
    let realm = realm.context("the registry's challenge names no realm")?;
    Ok((realm, query.finish()))
}

/// HTTPS, but for a registry on loopback.
fn scheme(host: &str) -> &'static str {
    let name = host.rsplit_once(':').map_or(host, |(n, _)| n);
    match name {
        "localhost" | "127.0.0.1" | "[::1]" => "http",
        _ => "https",
    }
}

fn join(base: &Uri, to: &str) -> anyhow::Result<Uri> {
    if to.starts_with('/') {
        let mut parts = base.clone().into_parts();
        parts.path_and_query = Some(to.parse()?);
        return Ok(Uri::from_parts(parts)?);
    }
    Ok(to.parse()?)
}

async fn blocking<T: Send + 'static>(
    uploads: &Arc<Mutex<Uploads>>,
    f: impl FnOnce(&Uploads) -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    let uploads = uploads.clone();
    tokio::task::spawn_blocking(move || f(&uploads.lock().unwrap_or_else(|e| e.into_inner())))
        .await?
}

async fn put(
    uploads: &Arc<Mutex<Uploads>>,
    sha: &str,
    index: u32,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    let sha = sha.to_string();
    blocking(uploads, move |u| {
        u.put(&sha, index, &data, &Sha256::digest(&data))?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A registry wanting a bearer token, redirecting blobs and serving
    /// ranges; returns the first byte each blob read began at.
    async fn registry(manifest: Vec<u8>, blob: Vec<u8>) -> (String, Arc<AtomicU64>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let from = Arc::new(AtomicU64::new(u64::MAX));
        let (a, f) = (addr.clone(), from.clone());
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&blob)));
        tokio::spawn(async move {
            loop {
                let (conn, _) = listener.accept().await.unwrap();
                let (a, f, m, b, d) = (
                    a.clone(),
                    f.clone(),
                    manifest.clone(),
                    blob.clone(),
                    digest.clone(),
                );
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let (a, f, m, b, d) = (a.clone(), f.clone(), m.clone(), b.clone(), d.clone());
                    async move {
                        let authed = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .is_some_and(|v| v == "Bearer t");
                        let path = req.uri().path().to_string();
                        let res = Response::builder();
                        let res = match path.as_str() {
                            "/token" => {
                                assert!(req.uri().query().unwrap().contains("scope=repository"));
                                res.body(Full::<Bytes>::from(r#"{"token":"t"}"#))
                            }
                            p if p.starts_with("/v2/") && !authed => res
                                .status(StatusCode::UNAUTHORIZED)
                                .header(
                                    header::WWW_AUTHENTICATE,
                                    format!(r#"Bearer realm="http://{a}/token",service="reg",scope="repository:test/app:pull""#),
                                )
                                .body(Full::default()),
                            "/v2/test/app/manifests/v1" => res.body(Full::from(m)),
                            p if p == format!("/v2/test/app/blobs/{d}") => res
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .header(header::LOCATION, "/storage/blob")
                                .body(Full::default()),
                            "/release/app.tar" => res
                                .status(StatusCode::FOUND)
                                .header(header::LOCATION, "/storage/blob")
                                .body(Full::default()),
                            "/storage/blob" => {
                                let start = req.headers().get(header::RANGE)
                                    .and_then(|r| r.to_str().ok()?.strip_prefix("bytes=")?.strip_suffix('-')?.parse().ok())
                                    .unwrap_or(0u64);
                                f.store(start, Ordering::SeqCst);
                                res.status(match start { 0 => StatusCode::OK, _ => StatusCode::PARTIAL_CONTENT })
                                    .body(Full::from(b[start as usize..].to_vec()))
                            }
                            _ => res.status(StatusCode::NOT_FOUND).body(Full::default()),
                        };
                        Ok::<_, std::convert::Infallible>(res.unwrap())
                    }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(conn), svc),
                );
            }
        });
        (addr, from)
    }

    fn app(blob: &[u8], artifact: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "artifactType": artifact,
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
            "layers": [{"mediaType": bundle::APP_LAYER, "digest": format!("sha256:{}", hex::encode(Sha256::digest(blob))), "size": blob.len()}],
        }))
        .unwrap()
    }

    fn uploads(d: &Path) -> Arc<Mutex<Uploads>> {
        Arc::new(Mutex::new(Uploads::new(d)))
    }

    #[tokio::test]
    async fn an_app_is_pulled_past_a_token_and_a_redirect_and_resumed() {
        let blob: Vec<u8> = (0..CHUNK as usize * 2 + 5)
            .map(|i| (i % 251) as u8)
            .collect();
        let (addr, from) = registry(app(&blob, bundle::APP_ARTIFACT), blob.clone()).await;
        let d = tempfile::tempdir().unwrap();
        let up = uploads(d.path());
        let sha = hex::encode(Sha256::digest(&blob));
        {
            let u = up.lock().unwrap();
            u.begin(blob.len() as u64, &sha, "ann").unwrap();
            let c = &blob[..CHUNK as usize];
            u.put(&sha, 0, c, &Sha256::digest(c)).unwrap();
        }
        let p = Puller::new(None).unwrap();
        let got = p
            .pull(&format!("{addr}/test/app:v1"), &up, "ann")
            .await
            .unwrap();
        assert_eq!(got, sha);
        assert_eq!(
            from.load(Ordering::SeqCst),
            CHUNK as u64,
            "resumed where it stopped"
        );
        let u = up.lock().unwrap();
        assert!(u.current().unwrap().complete);
        assert_eq!(std::fs::read(u.bundle()).unwrap(), blob);
    }

    #[tokio::test]
    async fn a_bundle_is_downloaded_past_a_redirect_and_resumed() {
        let blob: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let (addr, from) = registry(app(&blob, bundle::APP_ARTIFACT), blob.clone()).await;
        let d = tempfile::tempdir().unwrap();
        let up = uploads(d.path());
        let url = format!("http://{addr}/release/app.tar");
        let (part, of) = up.lock().unwrap().download();
        std::fs::write(&part, &blob[..1000]).unwrap();
        std::fs::write(&of, &url).unwrap();
        let p = Puller::new(None).unwrap();
        let sha = p.download(&url, &up, "ann").await.unwrap();
        assert_eq!(sha, hex::encode(Sha256::digest(&blob)));
        assert_eq!(
            from.load(Ordering::SeqCst),
            1000,
            "resumed where it stopped"
        );
        {
            let u = up.lock().unwrap();
            let c = u.current().unwrap();
            assert!(c.complete && c.by == "ann");
            assert_eq!(std::fs::read(u.bundle()).unwrap(), blob);
            assert!(!part.exists());
        }
        let e = p
            .download("http://example.com/app.tar", &up, "")
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("not https"), "{e:#}");
    }

    #[tokio::test]
    async fn only_an_app_is_pulled() {
        let blob = b"not an app".to_vec();
        let (addr, _) =
            registry(app(&blob, "application/vnd.oci.image.config.v1+json"), blob).await;
        let d = tempfile::tempdir().unwrap();
        let e = Puller::new(None)
            .unwrap()
            .pull(&format!("{addr}/test/app:v1"), &uploads(d.path()), "")
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("is not an app"), "{e:#}");
        let pinned = format!("{addr}/test/app@sha256:{}", "0".repeat(64));
        assert!(
            Puller::new(None)
                .unwrap()
                .pull(&pinned, &uploads(d.path()), "")
                .await
                .is_err()
        );
    }

    #[test]
    fn logins_are_read_from_a_docker_config() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        std::fs::write(&p, r#"{"auths":{"ghcr.io":{"auth":"dTpw"}}}"#).unwrap();
        assert_eq!(Puller::new(Some(&p)).unwrap().logins["ghcr.io"], "u:p");
        std::fs::write(&p, r#"{"auths":{"ghcr.io":{"auth":"!!"}}}"#).unwrap();
        assert!(Puller::new(Some(&p)).is_err());
        assert_eq!(
            (scheme("127.0.0.1:5000"), scheme("ghcr.io")),
            ("http", "https")
        );
    }
}
