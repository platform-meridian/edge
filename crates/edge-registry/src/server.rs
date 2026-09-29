//! The read side of the OCI Distribution API: what containerd needs to pull.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use edge_registry::{Digest, Store, normalize_repo};
use futures::TryStreamExt;
use http::header::{
    ACCEPT, ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HOST, RANGE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::io::ReaderStream;

type Body = UnsyncBoxBody<Bytes, io::Error>;

const DOCKER_CONTENT_DIGEST: &str = "docker-content-digest";

pub async fn serve(store: Store, listen: SocketAddr, upstream: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(addr = %listener.local_addr()?, root = %store.root().display(), %upstream, "serving images");
    let verifier = store.clone();
    tokio::task::spawn_blocking(move || {
        lower_priority();
        match verifier.verify() {
            Ok(0) => tracing::info!("every blob and manifest matches its digest"),
            Ok(n) => tracing::warn!(
                removed = n,
                "removed content that no longer matches its digest"
            ),
            Err(e) => tracing::error!(error = %e, "could not finish verifying the store"),
        }
    });
    let state = Arc::new((store, Upstream(upstream)));
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
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(respond(&state.0, &state.1, &req).await) }
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

/// Idle CPU and disk class for this thread: the verify pass must not slow a pull.
fn lower_priority() {
    use nix::libc;
    const IOPRIO_WHO_PROCESS: libc::c_long = 1;
    const IOPRIO_CLASS_IDLE: libc::c_long = 3;
    let param = libc::sched_param { sched_priority: 0 };
    // SAFETY: both act on the calling thread (0) and take no pointers but `param`.
    unsafe {
        libc::sched_setscheduler(0, libc::SCHED_IDLE, &param);
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0,
            IOPRIO_CLASS_IDLE << 13,
        );
    }
}

enum Route {
    Base,
    Manifest {
        name: String,
        ns: Option<String>,
        reference: String,
    },
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
    match kind {
        "manifests" => Some(Route::Manifest {
            name: name.to_owned(),
            ns: ns.map(str::to_owned),
            reference: reference.to_owned(),
        }),
        "blobs" => reference.parse().ok().map(Route::Blob),
        _ => None,
    }
}

async fn respond<B>(store: &Store, upstream: &Upstream, req: &Request<B>) -> Response<Body> {
    let head = match *req.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => return error(StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", "read-only"),
    };
    let range = req.headers().get(RANGE).and_then(|v| v.to_str().ok());
    let held = match route(req.uri().path(), req.uri().query()) {
        Some(Route::Base) => Some(json(StatusCode::OK, Bytes::from_static(b"{}"))),
        Some(Route::Manifest {
            name,
            ns,
            reference,
        }) => manifest(store, &name, ns.as_deref(), &reference),
        Some(Route::Blob(digest)) => blob(store, &digest, range).await,
        None => None,
    };
    let mut resp = match held {
        Some(r) => r,
        None => match upstream.fetch(req).await {
            Some(r) => r,
            None => error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "not found"),
        },
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

/// Without `ns`, the name may lack its registry: any held one matches.
fn manifest(
    store: &Store,
    name: &str,
    ns: Option<&str>,
    reference: &str,
) -> Option<Response<Body>> {
    let repos = match ns {
        Some(host) => normalize_repo(&format!("{host}/{name}"))
            .into_iter()
            .collect(),
        None => {
            let mut repos: Vec<String> = normalize_repo(name).into_iter().collect();
            repos.extend(store.repos_at_path(name));
            repos
        }
    };
    let digest = repos.iter().find_map(|r| store.resolve(r, reference))?;
    match store.manifest(&digest) {
        Ok(Some((media_type, bytes))) => Response::builder()
            .header(CONTENT_TYPE, media_type)
            .header(CONTENT_LENGTH, bytes.len())
            .header(DOCKER_CONTENT_DIGEST, digest.to_string())
            .body(full(bytes.into()))
            .ok(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(%digest, error = %e, "cannot read a manifest");
            None
        }
    }
}

async fn blob(store: &Store, digest: &Digest, range: Option<&str>) -> Option<Response<Body>> {
    let opened = match tokio::fs::File::open(store.blob_path(digest)).await {
        Ok(f) => f.metadata().await.map(|m| (f, m.len())),
        Err(e) => Err(e),
    };
    let (mut file, len) = match opened {
        Ok(o) => o,
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!(%digest, error = %e, "cannot read a blob");
            }
            return None;
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
            return Some(resp);
        }
    };
    if let Err(e) = file.seek(io::SeekFrom::Start(start)).await {
        tracing::warn!(%digest, error = %e, "cannot seek a blob");
        return None;
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
    resp.body(BodyExt::boxed_unsync(body)).ok()
}

/// A read-only pass-through to another registry, Talos's registryd by default,
/// for what the store does not hold. Nothing it serves is kept.
struct Upstream(SocketAddr);

/// Covers the answer's head only: a blob then streams as long as it takes.
const UPSTREAM_PATIENCE: Duration = Duration::from_secs(10);

impl Upstream {
    async fn fetch<B>(&self, req: &Request<B>) -> Option<Response<Body>> {
        match tokio::time::timeout(UPSTREAM_PATIENCE, self.send(req)).await {
            Ok(Ok(resp)) => Some(resp),
            Ok(Err(e)) => {
                tracing::debug!(uri = %req.uri(), error = %e, "not upstream either");
                None
            }
            Err(_) => {
                tracing::warn!(uri = %req.uri(), upstream = %self.0, "upstream did not answer in time");
                None
            }
        }
    }

    async fn send<B>(&self, req: &Request<B>) -> anyhow::Result<Response<Body>> {
        let stream = TcpStream::connect(self.0).await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
        let mut up = Request::builder()
            .method(req.method())
            .uri(path)
            .header(HOST, self.0.to_string());
        for name in [ACCEPT, RANGE] {
            for v in req.headers().get_all(&name) {
                up = up.header(&name, v);
            }
        }
        let resp = sender.send_request(up.body(Empty::<Bytes>::new())?).await?;
        let status = resp.status();
        // A 416 is the upstream's answer to a range, not a miss.
        if !status.is_success() && status != StatusCode::RANGE_NOT_SATISFIABLE {
            anyhow::bail!("upstream answered {status}");
        }
        let (parts, body) = resp.into_parts();
        let mut out = Response::builder().status(status);
        for name in [CONTENT_TYPE, CONTENT_LENGTH, CONTENT_RANGE, ACCEPT_RANGES] {
            if let Some(v) = parts.headers.get(&name) {
                out = out.header(&name, v);
            }
        }
        if let Some(v) = parts.headers.get(DOCKER_CONTENT_DIGEST) {
            out = out.header(DOCKER_CONTENT_DIGEST, v);
        }
        Ok(out.body(BodyExt::boxed_unsync(body.map_err(io::Error::other)))?)
    }
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

    #[test]
    fn verify_thread_runs_idle() {
        use nix::libc;
        let (policy, ioprio) = std::thread::spawn(|| {
            lower_priority();
            // SAFETY: queries for the calling thread only.
            unsafe {
                (
                    libc::sched_getscheduler(0),
                    libc::syscall(libc::SYS_ioprio_get, 1, 0),
                )
            }
        })
        .join()
        .unwrap();
        assert_eq!(policy, libc::SCHED_IDLE);
        assert_eq!(ioprio >> 13, 3, "ioprio {ioprio:#x}");
    }

    fn manifest_route(path: &str, query: Option<&str>) -> Option<(String, Option<String>, String)> {
        match route(path, query)? {
            Route::Manifest {
                name,
                ns,
                reference,
            } => Some((name, ns, reference)),
            _ => None,
        }
    }

    #[test]
    fn routes() {
        assert!(matches!(route("/v2/", None), Some(Route::Base)));
        assert!(matches!(route("/v2", None), Some(Route::Base)));
        let m = |name: &str, ns: Option<&str>, reference: &str| {
            Some((name.into(), ns.map(Into::into), reference.into()))
        };
        assert_eq!(
            manifest_route("/v2/library/nginx/manifests/1.27", Some("ns=docker.io")),
            m("library/nginx", Some("docker.io"), "1.27")
        );
        assert_eq!(
            manifest_route("/v2/pause/manifests/3.10", Some("x=1&ns=registry.k8s.io")),
            m("pause", Some("registry.k8s.io"), "3.10")
        );
        assert_eq!(
            manifest_route("/v2/ghcr.io/o/app/manifests/v1", None),
            m("ghcr.io/o/app", None, "v1")
        );
        let d = format!("sha256:{}", "a".repeat(64));
        assert!(
            matches!(route(&format!("/v2/o/app/blobs/{d}"), None), Some(Route::Blob(b)) if b.to_string() == d)
        );
        for missing in [
            "/v2/o/app/blobs/sha256:00",
            "/v2/o/app/tags/list",
            "/v2/manifests/x",
            "/v3/o/app/manifests/v1",
            "/v2x/o/manifests/v1",
        ] {
            assert!(route(missing, None).is_none(), "{missing}");
        }
    }
}
