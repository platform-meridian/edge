//! The read side of the OCI Distribution API: what containerd needs to pull.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use edge_registry::{Digest, Store, normalize_repo};
use futures::TryStreamExt;
use http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;

type Body = UnsyncBoxBody<Bytes, io::Error>;

const DOCKER_CONTENT_DIGEST: &str = "docker-content-digest";

pub async fn serve(store: Store, listen: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(addr = %listener.local_addr()?, root = %store.root().display(), "serving images");
    let store = Arc::new(store);
    let mut term = edge_common::Terminator::new();
    loop {
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(e) => {
                    // EMFILE and the like: back off rather than spin.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = term.wait() => return Ok(()),
        };
        let store = store.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let store = store.clone();
                async move { Ok::<_, Infallible>(respond(&store, &req).await) }
            });
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

enum Route {
    Base,
    Manifest { repo: String, reference: String },
    Blob(Digest),
}

/// containerd names the upstream registry in `ns` when it pulls through a mirror.
fn route(path: &str, query: Option<&str>) -> Option<Route> {
    let rest = path.strip_prefix("/v2")?;
    if rest.is_empty() || rest == "/" {
        return Some(Route::Base);
    }
    let mut parts = rest.strip_prefix('/')?.rsplitn(3, '/');
    let (reference, kind, name) = (parts.next()?, parts.next()?, parts.next()?);
    let ns = query.and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("ns=")));
    let repo = normalize_repo(&match ns {
        Some(host) => format!("{host}/{name}"),
        None => name.to_owned(),
    })?;
    match kind {
        "manifests" => Some(Route::Manifest {
            repo,
            reference: reference.to_owned(),
        }),
        "blobs" => reference.parse().ok().map(Route::Blob),
        _ => None,
    }
}

async fn respond<B>(store: &Store, req: &Request<B>) -> Response<Body> {
    let head = match *req.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => return error(StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", "read-only"),
    };
    let range = req.headers().get(RANGE).and_then(|v| v.to_str().ok());
    let mut resp = match route(req.uri().path(), req.uri().query()) {
        Some(Route::Base) => json(StatusCode::OK, Bytes::from_static(b"{}")),
        Some(Route::Manifest { repo, reference }) => manifest(store, &repo, &reference),
        Some(Route::Blob(digest)) => blob(store, &digest, range).await,
        None => error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "not found"),
    };
    if head {
        *resp.body_mut() = Body::default();
    }
    resp.headers_mut().insert(
        "docker-distribution-api-version",
        HeaderValue::from_static("registry/2.0"),
    );
    resp
}

fn manifest(store: &Store, repo: &str, reference: &str) -> Response<Body> {
    let unknown = || {
        error(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            "manifest unknown",
        )
    };
    let Some(digest) = store.resolve(repo, reference) else {
        return unknown();
    };
    match store.manifest(&digest) {
        Ok(Some((media_type, bytes))) => Response::builder()
            .header(CONTENT_TYPE, media_type)
            .header(CONTENT_LENGTH, bytes.len())
            .header(DOCKER_CONTENT_DIGEST, digest.to_string())
            .body(full(bytes.into()))
            .unwrap_or_else(|_| unknown()),
        Ok(None) => unknown(),
        Err(e) => {
            tracing::warn!(%digest, error = %e, "cannot read a manifest");
            unknown()
        }
    }
}

async fn blob(store: &Store, digest: &Digest, range: Option<&str>) -> Response<Body> {
    let unknown = || error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob unknown");
    let opened = match tokio::fs::File::open(store.blob_path(digest)).await {
        Ok(f) => f.metadata().await.map(|m| (f, m.len())),
        Err(e) => Err(e),
    };
    // Unreadable is unknown too: containerd then tries the next mirror.
    let (mut file, len) = match opened {
        Ok(o) => o,
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!(%digest, error = %e, "cannot read a blob");
            }
            return unknown();
        }
    };
    let (status, start, end) = match range.map(|r| byte_range(r, len)) {
        None | Some(Range::Whole) => (StatusCode::OK, 0, len),
        Some(Range::Part(start, end)) => (StatusCode::PARTIAL_CONTENT, start, end),
        Some(Range::Unsatisfiable) => {
            let mut resp = error(StatusCode::RANGE_NOT_SATISFIABLE, "UNKNOWN", "bad range");
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{len}")) {
                resp.headers_mut().insert(CONTENT_RANGE, v);
            }
            return resp;
        }
    };
    if let Err(e) = file.seek(io::SeekFrom::Start(start)).await {
        tracing::warn!(%digest, error = %e, "cannot seek a blob");
        return unknown();
    }
    let size = end - start;
    let body = StreamBody::new(ReaderStream::new(file.take(size)).map_ok(Frame::data));
    let mut resp = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, size)
        .header(ACCEPT_RANGES, "bytes")
        .header(DOCKER_CONTENT_DIGEST, digest.to_string());
    if status == StatusCode::PARTIAL_CONTENT {
        resp = resp.header(CONTENT_RANGE, format!("bytes {start}-{}/{len}", end - 1));
    }
    resp.body(BodyExt::boxed_unsync(body))
        .unwrap_or_else(|_| unknown())
}

#[derive(Debug, PartialEq)]
enum Range {
    Whole,
    /// Start inclusive, end exclusive.
    Part(u64, u64),
    Unsatisfiable,
}

/// A single `bytes=` range. Anything else is ignored and the whole blob sent,
/// as RFC 9110 allows.
fn byte_range(header: &str, len: u64) -> Range {
    let Some((first, last)) = header
        .strip_prefix("bytes=")
        .filter(|r| !r.contains(','))
        .and_then(|r| r.trim().split_once('-'))
    else {
        return Range::Whole;
    };
    let num = |s: &str| s.parse::<u64>().ok();
    let (start, end) = match (first, last) {
        ("", n) => match num(n) {
            Some(n) => (len.saturating_sub(n), len),
            None => return Range::Whole,
        },
        (a, "") => match num(a) {
            Some(a) => (a, len),
            None => return Range::Whole,
        },
        (a, b) => match (num(a), num(b)) {
            (Some(a), Some(b)) if a <= b => (a, b.saturating_add(1).min(len)),
            _ => return Range::Whole,
        },
    };
    if start >= len {
        return Range::Unsatisfiable;
    }
    Range::Part(start, end)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    let body = serde_json::json!({ "errors": [{ "code": code, "message": message }] });
    json(status, Bytes::from(body.to_string()))
}

fn json(status: StatusCode, body: Bytes) -> Response<Body> {
    let mut resp = Response::new(full(body));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn full(b: Bytes) -> Body {
    BodyExt::boxed_unsync(Full::new(b).map_err(|never| match never {}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        use Range::*;
        let r = |h| byte_range(h, 10);
        assert_eq!(r("bytes=0-0"), Part(0, 1));
        assert_eq!(r("bytes=2-5"), Part(2, 6));
        assert_eq!(r("bytes=2-"), Part(2, 10));
        assert_eq!(r("bytes=9-"), Part(9, 10));
        assert_eq!(r("bytes=3-99"), Part(3, 10));
        assert_eq!(r("bytes=-3"), Part(7, 10));
        assert_eq!(r("bytes=-99"), Part(0, 10));
        assert_eq!(r("bytes=10-"), Unsatisfiable);
        assert_eq!(r("bytes=10-12"), Unsatisfiable);
        assert_eq!(r("bytes=-0"), Unsatisfiable);
        assert_eq!(byte_range("bytes=-1", 0), Unsatisfiable);
        assert_eq!(byte_range("bytes=0-", 0), Unsatisfiable);
        for ignored in [
            "bytes=5-2",
            "bytes=0-1,3-4",
            "items=0-1",
            "bytes=x-1",
            "bytes=1",
            "",
        ] {
            assert_eq!(r(ignored), Whole, "{ignored}");
        }
    }

    fn manifest_route(path: &str, query: Option<&str>) -> Option<(String, String)> {
        match route(path, query)? {
            Route::Manifest { repo, reference } => Some((repo, reference)),
            _ => None,
        }
    }

    #[test]
    fn routes() {
        assert!(matches!(route("/v2/", None), Some(Route::Base)));
        assert!(matches!(route("/v2", None), Some(Route::Base)));
        let m = |repo: &str, reference: &str| Some((repo.into(), reference.into()));
        assert_eq!(
            manifest_route("/v2/library/nginx/manifests/1.27", Some("ns=docker.io")),
            m("docker.io/library/nginx", "1.27")
        );
        assert_eq!(
            manifest_route("/v2/pause/manifests/3.10", Some("x=1&ns=registry.k8s.io")),
            m("registry.k8s.io/pause", "3.10")
        );
        assert_eq!(
            manifest_route("/v2/ghcr.io/o/app/manifests/v1", None),
            m("ghcr.io/o/app", "v1")
        );
        assert_eq!(
            manifest_route("/v2/nginx/manifests/latest", None),
            m("docker.io/library/nginx", "latest")
        );
        let d = format!("sha256:{}", "a".repeat(64));
        assert!(
            matches!(route(&format!("/v2/o/app/blobs/{d}"), None), Some(Route::Blob(b)) if b.to_string() == d)
        );
        for missing in [
            "/v2/o/app/blobs/sha256:00",
            "/v2/o/app/tags/list",
            "/v2/manifests/x",
            "/v2/../x/manifests/y",
            "/v3/o/app/manifests/v1",
            "/v2x/o/manifests/v1",
        ] {
            assert!(route(missing, None).is_none(), "{missing}");
        }
    }
}
