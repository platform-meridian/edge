//! Canonicalise, route, sanitise, authorise, forward: in that order.

mod filters;
mod headers;
mod tunnel;
mod upstream;

use crate::authz::{self, Allowed, Authorizer, CheckInput, Decision};
use crate::config::{Authz, Backend, Config, Route};
use crate::controller::Routes;
use crate::path;
use bytes::Bytes;
use filters::{modify_headers, redirect};
use headers::{StripSet, request_host, sanitize, set_forwarded, upgrade_protocol};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::Duration;
use tunnel::tunnel;
use upstream::Upstreams;

pub use headers::ConnInfo;

pub type Body = BoxBody<Bytes, hyper::Error>;
pub type HttpClient = Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct Gateway {
    pub cfg: Arc<Config>,
    routes: Routes,
    client: HttpClient,
    authorizer: Option<Authorizer>,
    strip: Arc<StripSet>,
    frontend: Option<crate::tls::Acceptor>,
    upstreams: Upstreams,
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

pub(super) struct Target {
    path: String,
    query: Option<String>,
}

impl Target {
    fn request_target(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }
}

impl Gateway {
    pub fn new(cfg: Arc<Config>, routes: Routes) -> anyhow::Result<Self> {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(Duration::from_millis(
            cfg.limits.upstream_connect_timeout_ms,
        )));
        let authorizer = Authorizer::from_config(&cfg)?;
        let strip = Arc::new(StripSet::new(&cfg.strip_request_headers));
        let connect = Duration::from_millis(cfg.limits.upstream_connect_timeout_ms);
        Ok(Self {
            upstreams: Upstreams::new(None, connect),
            cfg,
            routes,
            client: Client::builder(TokioExecutor::new()).build(connector),
            authorizer,
            strip,
            frontend: None,
        })
    }

    /// The pod certificate it serves is also the client's to TLS backends.
    pub fn with_tls(mut self, acceptor: crate::tls::Acceptor) -> Self {
        let connect = Duration::from_millis(self.cfg.limits.upstream_connect_timeout_ms);
        self.upstreams = Upstreams::new(Some(acceptor.identity()), connect);
        self.frontend = Some(acceptor);
        self
    }

    /// A route that wants the client's certificate, on an h2 connection the
    /// browser coalesced from a name never asked for one: 421 makes it retry on
    /// a connection of its own, which is asked.
    fn misdirected(&self, route: &Route, host: Option<&str>, conn: &ConnInfo) -> bool {
        let Some(frontend) = &self.frontend else {
            return false;
        };
        route.client_cert
            && !conn.handshake.requested
            && host
                .and_then(crate::config::normalize_host)
                .is_some_and(|h| frontend.requests_certificate(&h))
    }

    pub async fn handle(
        &self,
        mut req: Request<Incoming>,
        conn: &ConnInfo,
    ) -> Result<Response<Body>, hyper::Error> {
        // Two Hosts, or two Authorizations, are requests two parties read differently.
        if req.headers().get_all(hyper::header::HOST).iter().count() > 1 {
            return Ok(status(StatusCode::BAD_REQUEST, "multiple Host headers"));
        }
        let host = request_host(&req);
        let target = match path::canonicalize(req.uri().path()) {
            Ok(path) => Target {
                path,
                query: req.uri().query().map(str::to_owned),
            },
            Err(e) => {
                tracing::debug!(error = %e, path = req.uri().path(), peer = %conn.peer, "bad path");
                return Ok(status(StatusCode::BAD_REQUEST, "bad request path"));
            }
        };

        let table = self.routes.load();
        let Some(route) = table
            .iter()
            .find(|r| r.matches(host.as_deref(), &target.path))
        else {
            return Ok(status(StatusCode::NOT_FOUND, "no route"));
        };
        if self.misdirected(route, host.as_deref(), conn) {
            return Ok(status(
                StatusCode::MISDIRECTED_REQUEST,
                "this connection was not asked for a client certificate",
            ));
        }

        // Read before sanitising, which removes Connection and Upgrade.
        let upgrade = upgrade_protocol(req.headers()).map(|p| (p, hyper::upgrade::on(&mut req)));

        if req
            .headers()
            .get_all(hyper::header::AUTHORIZATION)
            .iter()
            .count()
            > 1
        {
            return Ok(status(
                StatusCode::BAD_REQUEST,
                "multiple Authorization headers",
            ));
        }
        sanitize(req.headers_mut(), &self.strip);

        let allowed = match self
            .authorize(&req, route, host.as_deref(), &target, conn)
            .await
        {
            Ok(a) => a,
            Err(why) => return Ok(status(StatusCode::FORBIDDEN, why)),
        };

        if let Some(r) = &route.filters.redirect {
            return Ok(redirect(r, route, &target, host.as_deref(), conn));
        }
        let Some(backend) = &route.backend else {
            return Ok(status(
                StatusCode::INTERNAL_SERVER_ERROR,
                "route has no backend",
            ));
        };

        let (mut parts, body) = req.into_parts();
        if !rewrite_for_upstream(
            &mut parts,
            route,
            backend,
            &target,
            allowed.ops,
            &allowed.remove,
            host,
            conn,
        ) {
            return Ok(status(StatusCode::INTERNAL_SERVER_ERROR, "bad backend uri"));
        }
        let req = Request::from_parts(parts, body.boxed());
        let mut resp = match upgrade {
            Some((protocol, downstream)) => {
                self.forward_upgrade(req, protocol, downstream, backend)
                    .await
            }
            None => self.forward(req, backend).await,
        };
        for (k, v) in allowed.response_headers {
            if let (Ok(n), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
                resp.headers_mut().append(n, v);
            }
        }
        Ok(resp)
    }

    /// Fails closed: a missing, unreachable, slow or nonsensical authz service
    /// denies.
    async fn authorize(
        &self,
        req: &Request<Incoming>,
        route: &Route,
        host: Option<&str>,
        target: &Target,
        conn: &ConnInfo,
    ) -> Result<Allowed, &'static str> {
        if route.authz == Authz::Skip {
            return Ok(Allowed::default());
        }
        let Some(authorizer) = &self.authorizer else {
            return Err("no authorization service");
        };
        let request_target = target.request_target();
        let input = CheckInput {
            method: req.method(),
            version: req.version(),
            scheme: conn.scheme(),
            host,
            path: &request_target,
            query: target.query.as_deref(),
            peer: conn.peer,
            headers: req.headers(),
        };
        match authorizer.check(&self.client, &input).await {
            Ok(Decision::Allow(a)) => Ok(a),
            Ok(Decision::Deny) => Err("denied"),
            Err(e) => {
                tracing::warn!(error = %e, "authz unavailable; failing closed");
                Err("authorization unavailable")
            }
        }
    }

    async fn forward(&self, req: Request<Body>, backend: &Backend) -> Response<Body> {
        let limit = Duration::from_millis(self.cfg.limits.upstream_response_timeout_ms);
        let sent = match &backend.tls {
            None => self.client.request(req),
            Some(t) => match self.upstreams.client(t) {
                Some(c) => c.request(req),
                None => return status(StatusCode::BAD_GATEWAY, "upstream TLS unusable"),
            },
        };
        match tokio::time::timeout(limit, sent).await {
            Ok(Ok(resp)) => resp.map(|b| b.boxed()),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, backend = %backend.host, "upstream failed");
                status(StatusCode::BAD_GATEWAY, "upstream unavailable")
            }
            Err(_) => {
                tracing::warn!(backend = %backend.host, "upstream response timed out");
                status(StatusCode::GATEWAY_TIMEOUT, "upstream timed out")
            }
        }
    }

    /// A dedicated connection, never the pool: after the 101 it is no longer HTTP.
    async fn forward_upgrade(
        &self,
        mut req: Request<Body>,
        protocol: HeaderValue,
        downstream: OnUpgrade,
        backend: &Backend,
    ) -> Response<Body> {
        let limits = &self.cfg.limits;
        let connect = Duration::from_millis(limits.upstream_connect_timeout_ms);
        let respond = Duration::from_millis(limits.upstream_response_timeout_ms);
        let idle = Duration::from_millis(limits.tunnel_idle_timeout_ms);

        // RFC 9110 7.8: each hop renegotiates. Put back only these two, never
        // the client's Connection list, which may name headers already dropped.
        req.headers_mut().insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
        req.headers_mut().insert(hyper::header::UPGRADE, protocol);

        let addr = format!("{}:{}", backend.host, backend.port);
        let dialled: std::io::Result<Box<dyn Io>> = match &backend.tls {
            None => tokio::time::timeout(connect, tokio::net::TcpStream::connect(&addr))
                .await
                .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
                .map(|s| {
                    let _ = s.set_nodelay(true);
                    Box::new(s) as Box<dyn Io>
                }),
            Some(t) => match self.upstreams.connector(t) {
                Some(c) => c.dial(&addr).await.map(|s| Box::new(s) as Box<dyn Io>),
                None => return status(StatusCode::BAD_GATEWAY, "upstream TLS unusable"),
            },
        };
        let stream = match dialled {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                tracing::warn!(backend = %addr, "upgrade dial timed out");
                return status(StatusCode::GATEWAY_TIMEOUT, "upstream timed out");
            }
            Err(e) => {
                tracing::warn!(error = %e, backend = %addr, "upgrade dial failed");
                return status(StatusCode::BAD_GATEWAY, "upstream unavailable");
            }
        };

        let handshake = hyper::client::conn::http1::handshake(TokioIo::new(stream));
        let (mut sender, conn) = match tokio::time::timeout(respond, handshake).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, backend = %addr, "upgrade handshake failed");
                return status(StatusCode::BAD_GATEWAY, "upstream unavailable");
            }
            Err(_) => return status(StatusCode::GATEWAY_TIMEOUT, "upstream timed out"),
        };
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!(error = %e, "upgrade connection closed");
            }
        });

        let mut resp = match tokio::time::timeout(respond, sender.send_request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, backend = %addr, "upgrade request failed");
                return status(StatusCode::BAD_GATEWAY, "upstream unavailable");
            }
            Err(_) => return status(StatusCode::GATEWAY_TIMEOUT, "upstream timed out"),
        };
        // A declined upgrade is a real answer and goes back unchanged.
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return resp.map(|b| b.boxed());
        }

        let upstream = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            match tokio::try_join!(downstream, upstream) {
                Ok((d, u)) => {
                    if let Err(e) = tunnel(TokioIo::new(d), TokioIo::new(u), idle).await {
                        tracing::debug!(error = %e, "tunnel closed");
                    }
                }
                Err(e) => tracing::debug!(error = %e, "upgrade never completed"),
            }
        });
        resp.map(|b| b.boxed())
    }
}

#[allow(clippy::too_many_arguments)]
fn rewrite_for_upstream(
    parts: &mut Parts,
    route: &Route,
    backend: &Backend,
    target: &Target,
    ops: Vec<authz::HeaderOp>,
    remove: &[String],
    client_host: Option<String>,
    conn: &ConnInfo,
) -> bool {
    let rewritten;
    let target = match &route.filters.rewrite_path {
        Some(m) => {
            rewritten = Target {
                path: m.apply(&target.path, &route.prefix),
                query: target.query.clone(),
            };
            &rewritten
        }
        None => target,
    };
    let uri = format!(
        "http://{}:{}{}",
        backend.host,
        backend.port,
        target.request_target()
    );
    let Ok(uri) = uri.parse() else {
        return false;
    };
    parts.uri = uri;
    // The route's edits first: authz's, which decided the request, win.
    modify_headers(&mut parts.headers, &route.filters.request_headers);
    authz::apply_request_edits(&mut parts.headers, remove, ops);
    // The upstream Host is the route's, never the client's: otherwise it would
    // differ between h1 (Host forwarded) and h2 (Host synthesised).
    let upstream_host = route
        .rewrite_host
        .clone()
        .unwrap_or_else(|| format!("{}:{}", backend.host, backend.port));
    if let Ok(val) = HeaderValue::try_from(upstream_host) {
        parts.headers.insert(hyper::header::HOST, val);
    }
    // Last, so neither the client nor authz can override it.
    set_forwarded(&mut parts.headers, conn, client_host.as_deref());
    // Whatever the strip list says: only the route that asked gets one.
    parts.headers.remove(crate::xfcc::HEADER);
    if route.client_cert
        && let Some(v) = conn
            .handshake
            .client_cert
            .as_deref()
            .and_then(|v| HeaderValue::try_from(v).ok())
    {
        parts.headers.insert(crate::xfcc::HEADER, v);
    }
    // Upstream is HTTP/1.1; an h2 downstream version would be rejected by the client.
    parts.version = hyper::Version::HTTP_11;
    true
}

pub fn status(code: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(
            Full::new(Bytes::from(format!("{msg}\n")))
                .map_err(|e| match e {})
                .boxed(),
        )
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use hyper::header::{CONNECTION, UPGRADE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn authz_path(c: &envoy_types::pb::envoy::service::auth::v3::CheckRequest) -> String {
        c.attributes
            .as_ref()
            .unwrap()
            .request
            .as_ref()
            .unwrap()
            .http
            .as_ref()
            .unwrap()
            .path
            .clone()
    }

    async fn echo_backend() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|mut req: Request<Incoming>| async move {
                        if headers::upgrade_protocol(req.headers()).is_none() {
                            return Ok::<_, hyper::Error>(status(StatusCode::OK, "not an upgrade"));
                        }
                        let on = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            if let Ok(io) = on.await {
                                let mut io = TokioIo::new(io);
                                let mut buf = [0u8; 64];
                                while let Ok(n) = io.read(&mut buf).await {
                                    if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        });
                        Ok(Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(CONNECTION, "upgrade")
                            .header(UPGRADE, "echo")
                            .body(Body::default())
                            .unwrap())
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn upgrade_tunnels_bytes() {
        let gw = gateway(
            insecure_cfg(),
            vec![route("/", Authz::Skip, echo_backend().await)],
        )
        .await;
        let mut client = TcpStream::connect(gw.addr).await.unwrap();
        client
            .write_all(
                b"GET /watch HTTP/1.1\r\nHost: example.test\r\n\
                  Connection: keep-alive, Upgrade\r\nUpgrade: echo\r\n\r\n",
            )
            .await
            .unwrap();

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(
                client.read(&mut byte).await.unwrap(),
                1,
                "connection closed"
            );
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "expected a 101, got: {head}"
        );

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    }

    #[tokio::test]
    async fn declined_upgrade_passes_through() {
        let b = recorder("b").await;
        let gw = gateway(insecure_cfg(), vec![route("/", Authz::Skip, b.addr)]).await;
        let resp = raw(
            gw.addr,
            "GET /watch HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade, close\r\nUpgrade: echo\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert_eq!(b.last().header("upgrade"), Some("echo"));
        assert_eq!(b.last().header("connection"), Some("upgrade"));
    }

    #[tokio::test]
    async fn upstream_host_is_the_routes() {
        let b = recorder("b").await;
        for (rewrite, want_host) in [
            (None, b.addr.to_string()),
            (Some("mesh.example"), "mesh.example".to_string()),
        ] {
            let mut r = route("/", Authz::Skip, b.addr);
            r.rewrite_host = rewrite.map(str::to_owned);
            let gw = gateway(insecure_cfg(), vec![r]).await;
            raw(
                gw.addr,
                "GET / HTTP/1.1\r\nHost: headlamp.example.lan:8443\r\nConnection: close\r\n\r\n",
            )
            .await;
            let seen = b.last();
            assert_eq!(seen.headers_named("host"), [want_host.as_str()]);
            assert_eq!(
                seen.header("x-forwarded-host"),
                Some("headlamp.example.lan:8443")
            );
        }
    }

    #[tokio::test]
    async fn traversal_cannot_escape_skip_prefix() {
        let authz = fake_authz().await;
        authz.set(AuthzMode::Deny);
        let public = recorder("public").await;
        let admin = recorder("admin").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![
                route("/public", Authz::Skip, public.addr),
                route("/admin", Authz::Required, admin.addr),
            ],
        )
        .await;
        let spellings = [
            "/public/../admin",
            "/public/%2e%2e/admin",
            "/public/%2E%2E/admin",
            "/public/.%2e/admin",
            "/public/./../admin",
            "//admin",
            "/./admin",
            "/admin;x=1",
            "/public;a/../admin",
            "/%61dmin",
            "/admin/../admin",
        ];
        for p in spellings {
            assert_eq!(get(gw.addr, p, "").await.0, 403, "{p}");
        }
        assert_eq!(public.count() + admin.count(), 0, "{:?}", public.all());
        let asked: Vec<String> = authz.calls().iter().map(authz_path).collect();
        assert_eq!(asked, vec!["/admin"; spellings.len()]);
    }

    #[tokio::test]
    async fn required_denied_without_authz() {
        let open = recorder("open").await;
        let guarded = recorder("guarded").await;
        let gw = gateway(
            insecure_cfg(),
            vec![
                route("/open", Authz::Skip, open.addr),
                route("/", Authz::Required, guarded.addr),
            ],
        )
        .await;
        assert_eq!(get(gw.addr, "/", "").await.0, 403);
        assert_eq!(get(gw.addr, "/open", "").await.0, 200);
        assert_eq!(guarded.count(), 0);
    }

    #[tokio::test]
    async fn backend_gets_canonical_path() {
        let public = recorder("public").await;
        let gw = gateway(
            insecure_cfg(),
            vec![route("/public", Authz::Skip, public.addr)],
        )
        .await;
        let (code, _) = get(gw.addr, "/public/a/../b//c/?x=1%2f&y=/../", "").await;
        assert_eq!(code, 200);
        assert_eq!(public.last().target, "/public/b/c/?x=1%2f&y=/../");
    }

    #[tokio::test]
    async fn authz_and_backend_agree_on_path() {
        use proptest::strategy::{Strategy, ValueTree};
        use proptest::test_runner::{Config as PtConfig, TestRunner};

        let authz = fake_authz().await;
        let public = recorder("public").await;
        let admin = recorder("admin").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![
                route("/public", Authz::Skip, public.addr),
                route("/admin", Authz::Required, admin.addr),
            ],
        )
        .await;

        let mut runner = TestRunner::new(PtConfig::default());
        let strat = crate::path::tests::spelling();
        for _ in 0..120 {
            let raw = strat.new_tree(&mut runner).unwrap().current();
            let before = (public.count(), admin.count(), authz.calls().len());
            let (code, _) = get(gw.addr, &raw, "").await;
            let after = (public.count(), admin.count(), authz.calls().len());
            let Ok(canon) = crate::path::canonicalize(&raw) else {
                assert_eq!(code, 400, "{raw}");
                assert_eq!(before, after, "{raw}: a rejected path reached something");
                continue;
            };
            let landed = crate::path::tests::aggressive_backend_segments(&canon);
            assert_eq!(
                landed,
                crate::path::tests::aggressive_backend_segments(&raw),
                "{raw}"
            );
            match landed.first().map(String::as_str) {
                Some("public") => {
                    assert_eq!(
                        public.last().target.split('?').next().unwrap(),
                        canon,
                        "{raw}"
                    );
                    assert_eq!(after, (before.0 + 1, before.1, before.2), "{raw}");
                }
                Some("admin") => {
                    assert_eq!(after.2, before.2 + 1, "{raw}: admin must ask authz");
                    assert_eq!(authz_path(&authz.calls().pop().unwrap()), canon, "{raw}");
                    assert_eq!(admin.last().target, canon, "{raw}");
                }
                _ => assert_eq!(code, 404, "{raw} -> {landed:?}"),
            }
        }
    }

    #[tokio::test]
    async fn rejects_ambiguous_requests() {
        let authz = fake_authz().await;
        let b = recorder("b").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        let get_path =
            |p: &str| format!("GET {p} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        let mut requests: Vec<String> = [
            "/a%2fb",
            "/a%2Fb",
            "/public/..%2fadmin",
            "/a%5cb",
            "/a%00b",
            "/a%zz",
            "/a%0d%0ab",
            "/a\\b",
        ]
        .iter()
        .map(|p| get_path(p))
        .collect();
        requests.extend(
            [
                "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer a\r\nAuthorization: Bearer b\r\nConnection: close\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\nContent-Length: 30\r\nConnection: close\r\n\r\nabc",
                "GET / HTTP/1.1\r\nHost: t\r\nX-Folded: a\r\n b\r\nConnection: close\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: t\r\nContent-Length : 4\r\nConnection: close\r\n\r\nabcd",
            ]
            .map(String::from),
        );
        for req in &requests {
            let resp = raw(gw.addr, req).await;
            assert!(resp.starts_with("HTTP/1.1 400"), "{req:?}\n-> {resp}");
        }
        assert_eq!(b.count(), 0);
        assert!(authz.calls().is_empty());
    }

    #[tokio::test]
    async fn silent_backend_504_dead_502() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = l.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let cfg = Config::parse_plaintext(
            "listen: '127.0.0.1:0'\nlimits: { upstream_response_timeout_ms: 300 }\nroutes: []\n",
        )
        .unwrap();
        let gw = gateway(
            cfg,
            vec![
                route("/silent", Authz::Skip, silent),
                route("/dead", Authz::Skip, dead),
            ],
        )
        .await;
        let t = std::time::Instant::now();
        assert_eq!(get(gw.addr, "/silent", "").await.0, 504);
        assert!(t.elapsed() < Duration::from_secs(3));
        assert_eq!(get(gw.addr, "/dead", "").await.0, 502);
        let upgrade = "Connection: Upgrade\r\nUpgrade: echo\r\n";
        assert_eq!(get(gw.addr, "/dead", upgrade).await.0, 502);
    }

    async fn through(req: &str) -> (String, Vec<Seen>) {
        let b = recorder("b").await;
        let gw = gateway(insecure_cfg(), vec![route("/", Authz::Skip, b.addr)]).await;
        let resp = raw(gw.addr, req).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        (resp, b.all())
    }

    fn framing_headers(s: &Seen) -> usize {
        s.headers_named("content-length").len() + s.headers_named("transfer-encoding").len()
    }

    #[tokio::test]
    async fn cl_te_smuggles_nothing() {
        let (resp, seen) = through(
            "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
             0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .await;
        assert!(
            seen.iter().all(|s| s.target != "/smuggled"),
            "smuggled: {seen:?}\n{resp}"
        );
        assert!(seen.len() <= 1);
        assert!(seen.iter().all(|s| framing_headers(s) <= 1), "{seen:?}");
    }

    #[tokio::test]
    async fn duplicate_content_length_once() {
        let (resp, seen) = through(
            "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
        )
        .await;
        // RFC 9110 8.6 allows rejecting or coalescing identical values.
        if resp.starts_with("HTTP/1.1 400") {
            assert!(seen.is_empty());
        } else {
            assert_eq!(seen.len(), 1, "{resp}");
            assert_eq!(framing_headers(&seen[0]), 1);
            assert_eq!(seen[0].body, b"abcd");
        }
    }

    #[tokio::test]
    async fn chunked_body_reframed() {
        let (_, seen) = through(
            "POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
             5\r\nhello\r\n0\r\n\r\n",
        )
        .await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, b"hello");
    }

    #[tokio::test]
    async fn host_match_end_to_end() {
        let named = recorder("named").await;
        let other = recorder("other").await;
        let gw = gateway(
            insecure_cfg(),
            vec![
                host_route("app.test", "/", Authz::Skip, named.addr),
                route("/", Authz::Skip, other.addr),
            ],
        )
        .await;
        for host in ["APP.test", "app.test:8443", "app.test.", "App.Test.:1"] {
            raw(
                gw.addr,
                &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
            )
            .await;
        }
        raw(
            gw.addr,
            "GET / HTTP/1.1\r\nHost: app.test.evil\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!((named.count(), other.count()), (4, 1));
    }

    #[tokio::test]
    async fn table_swap_applies_next_request() {
        let (a, b) = (recorder("a").await, recorder("b").await);
        let gw = gateway(insecure_cfg(), vec![route("/", Authz::Skip, a.addr)]).await;
        get(gw.addr, "/", "").await;
        gw.routes
            .store(Arc::new(vec![route("/", Authz::Skip, b.addr)]));
        get(gw.addr, "/", "").await;
        assert_eq!((a.count(), b.count()), (1, 1));
        gw.routes.store(Arc::new(vec![]));
        assert_eq!(get(gw.addr, "/", "").await.0, 404);
    }
}
