//! Envoy `ext_authz` gRPC, or plain HTTP where 2xx allows. Every failure to get
//! a clear allow is a deny.

use crate::config::{AuthzProtocol, Config};
use crate::proxy::HttpClient;
use envoy_types::pb::envoy::config::core::v3::{
    Address, HeaderValueOption, SocketAddress, address, socket_address,
};
use envoy_types::pb::envoy::service::auth::v3::attribute_context::Peer;
use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
use envoy_types::pb::envoy::service::auth::v3::{
    AttributeContext, CheckRequest, OkHttpResponse, attribute_context::HttpRequest,
    attribute_context::Request as AttrRequest,
};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Version};
use std::net::SocketAddr;
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderOp {
    Append(String, String),
    Set(String, String),
    AddIfAbsent(String, String),
    OverwriteIfExists(String, String),
}

impl HeaderOp {
    fn into_pair(self) -> (String, String) {
        match self {
            HeaderOp::Append(k, v)
            | HeaderOp::Set(k, v)
            | HeaderOp::AddIfAbsent(k, v)
            | HeaderOp::OverwriteIfExists(k, v) => (k, v),
        }
    }
}

#[derive(Debug, Default)]
pub struct Allowed {
    pub ops: Vec<HeaderOp>,
    pub remove: Vec<String>,
    pub response_headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum Decision {
    Allow(Allowed),
    Deny,
}

/// Built from the sanitised request.
pub struct CheckInput<'a> {
    pub method: &'a Method,
    pub version: Version,
    pub scheme: &'a str,
    pub host: Option<&'a str>,
    /// Canonical, as the backend will be sent it.
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub peer: SocketAddr,
    pub headers: &'a HeaderMap,
}

#[derive(Clone)]
pub struct Authorizer {
    grpc: Option<AuthorizationClient<Channel>>,
    protocol: AuthzProtocol,
    base: String,
    timeout: Duration,
}

impl Authorizer {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Option<Self>> {
        let Some(b) = &cfg.authz_backend else {
            return Ok(None);
        };
        let timeout = Duration::from_millis(cfg.limits.authz_timeout_ms);
        let base = format!("http://{}:{}", b.host, b.port);
        let grpc = match cfg.authz_protocol {
            AuthzProtocol::Grpc => {
                let channel = Endpoint::from_shared(base.clone())?
                    .connect_timeout(timeout)
                    .timeout(timeout)
                    .tcp_nodelay(true)
                    .http2_keep_alive_interval(Duration::from_secs(30))
                    .keep_alive_while_idle(true)
                    .connect_lazy();
                Some(
                    AuthorizationClient::new(channel)
                        .max_decoding_message_size(cfg.limits.authz_max_response_bytes),
                )
            }
            AuthzProtocol::Http => None,
        };
        Ok(Some(Self {
            grpc,
            protocol: cfg.authz_protocol,
            base,
            timeout,
        }))
    }

    pub async fn check(
        &self,
        http: &HttpClient,
        input: &CheckInput<'_>,
    ) -> anyhow::Result<Decision> {
        let call = async {
            match self.protocol {
                AuthzProtocol::Grpc => self.grpc_check(input).await,
                AuthzProtocol::Http => self.http_check(http, input).await,
            }
        };
        // Over and above the channel's own timeouts: nothing here may block forever.
        tokio::time::timeout(self.timeout + Duration::from_millis(250), call)
            .await
            .map_err(|_| anyhow::anyhow!("authorization timed out"))?
    }

    async fn grpc_check(&self, input: &CheckInput<'_>) -> anyhow::Result<Decision> {
        let mut client = self.grpc.clone().expect("grpc protocol has a client");
        let resp = client.check(check_request(input)).await?.into_inner();
        // Allowed iff status.code == 0; an ok_response alone does not allow.
        if resp.status.as_ref().map(|s| s.code) != Some(0) {
            return Ok(Decision::Deny);
        }
        Ok(Decision::Allow(match resp.http_response {
            Some(HttpResponse::OkResponse(ok)) => allowed_from(ok),
            _ => Allowed::default(),
        }))
    }

    async fn http_check(
        &self,
        http: &HttpClient,
        input: &CheckInput<'_>,
    ) -> anyhow::Result<Decision> {
        let uri: hyper::Uri = format!("{}{}", self.base, input.path).parse()?;
        let mut check = hyper::Request::builder().method(input.method).uri(uri);
        for name in [hyper::header::AUTHORIZATION, hyper::header::COOKIE] {
            for v in input.headers.get_all(&name) {
                check = check.header(&name, v);
            }
        }
        if let Some(h) = input.host {
            check = check.header("x-forwarded-host", h);
        }
        check = check
            .header("x-forwarded-method", input.method.as_str())
            .header("x-forwarded-proto", input.scheme)
            .header("x-forwarded-for", input.peer.ip().to_string())
            .header("x-forwarded-uri", input.path);

        use http_body_util::BodyExt as _;
        let body = http_body_util::Empty::<bytes::Bytes>::new()
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed();
        let resp = http
            .request(check.body(body)?)
            .await
            .map_err(|e| anyhow::anyhow!("authz request failed: {e}"))?;
        Ok(if resp.status().is_success() {
            Decision::Allow(Allowed::default())
        } else {
            Decision::Deny
        })
    }
}

fn allowed_from(ok: OkHttpResponse) -> Allowed {
    Allowed {
        ops: ok.headers.into_iter().filter_map(header_op).collect(),
        remove: ok
            .headers_to_remove
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .filter(|h| h != "host" && !h.starts_with(':'))
            .collect(),
        response_headers: ok
            .response_headers_to_add
            .into_iter()
            .filter_map(header_op)
            .map(HeaderOp::into_pair)
            .collect(),
    }
}

/// Every value of a header joined into one string: judging only the first while
/// the backend receives them all would be a differential.
fn joined(headers: &HeaderMap, name: &HeaderName, sep: &str) -> Option<String> {
    let mut it = headers.get_all(name).iter().peekable();
    it.peek()?;
    Some(
        it.map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(sep),
    )
}

/// Only the headers a decision can legitimately rest on are sent.
fn check_request(input: &CheckInput<'_>) -> CheckRequest {
    let mut headers = std::collections::HashMap::new();
    if let Some(v) = joined(input.headers, &hyper::header::AUTHORIZATION, ", ") {
        headers.insert("authorization".to_string(), v);
    }
    // RFC 9113 8.2.3: cookie crumbs rejoin with "; ".
    if let Some(v) = joined(input.headers, &hyper::header::COOKIE, "; ") {
        headers.insert("cookie".to_string(), v);
    }

    CheckRequest {
        attributes: Some(AttributeContext {
            source: Some(Peer {
                address: Some(Address {
                    address: Some(address::Address::SocketAddress(SocketAddress {
                        address: input.peer.ip().to_string(),
                        port_specifier: Some(socket_address::PortSpecifier::PortValue(
                            input.peer.port() as u32,
                        )),
                        ..Default::default()
                    })),
                }),
                ..Default::default()
            }),
            request: Some(AttrRequest {
                http: Some(HttpRequest {
                    method: input.method.to_string(),
                    path: input.path.to_string(),
                    query: input.query.unwrap_or_default().to_string(),
                    host: input.host.unwrap_or_default().to_string(),
                    scheme: input.scheme.to_string(),
                    protocol: format!("{:?}", input.version),
                    headers,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

/// Routing, framing, forwarding and hop-by-hop headers: letting authz set these
/// after sanitising would reopen the ambiguity sanitising closed.
pub(crate) fn is_forbidden_for_authz(lower: &str) -> bool {
    lower.starts_with(':')
        || matches!(
            lower,
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "upgrade"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-proto"
                | "x-forwarded-host"
        )
}

#[allow(deprecated)] // `append` is deprecated but older services still set it, and it wins.
fn header_op(h: HeaderValueOption) -> Option<HeaderOp> {
    let hv = h.header?;
    let key = hv.key.to_ascii_lowercase();
    if is_forbidden_for_authz(&key) {
        return None;
    }
    let value = if hv.value.is_empty() && !hv.raw_value.is_empty() {
        String::from_utf8(hv.raw_value).ok()?
    } else {
        hv.value
    };
    if value.is_empty() && !h.keep_empty_value {
        return None;
    }
    Some(match (h.append.map(|b| b.value), h.append_action) {
        (Some(true), _) => HeaderOp::Append(key, value),
        (Some(false), _) => HeaderOp::Set(key, value),
        (None, 0) => HeaderOp::Append(key, value),
        (None, 1) => HeaderOp::AddIfAbsent(key, value),
        (None, 2) => HeaderOp::Set(key, value),
        (None, 3) => HeaderOp::OverwriteIfExists(key, value),
        (None, _) => return None,
    })
}

pub fn apply_request_edits(headers: &mut HeaderMap, remove: &[String], ops: Vec<HeaderOp>) {
    for name in remove {
        if let Ok(n) = HeaderName::try_from(name.as_str()) {
            headers.remove(&n);
        }
    }
    for op in ops {
        let (k, v) = op.clone().into_pair();
        let (Ok(name), Ok(val)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) else {
            continue;
        };
        match op {
            HeaderOp::Append(..) => {
                headers.append(name, val);
            }
            HeaderOp::Set(..) => {
                headers.insert(name, val);
            }
            HeaderOp::AddIfAbsent(..) => {
                if !headers.contains_key(&name) {
                    headers.insert(name, val);
                }
            }
            HeaderOp::OverwriteIfExists(..) => {
                if headers.contains_key(&name) {
                    headers.insert(name, val);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Authz;
    use crate::testutil::*;
    use envoy_types::pb::envoy::config::core::v3::HeaderValue as PbHeader;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[allow(deprecated)]
    fn header_option(
        key: &str,
        value: &str,
        raw: &[u8],
        append: Option<bool>,
        action: i32,
        keep_empty: bool,
    ) -> HeaderValueOption {
        HeaderValueOption {
            header: Some(PbHeader {
                key: key.into(),
                value: value.into(),
                raw_value: raw.to_vec(),
            }),
            append: append.map(|value| envoy_types::pb::google::protobuf::BoolValue { value }),
            append_action: action,
            keep_empty_value: keep_empty,
        }
    }

    #[test]
    fn header_op_mapping() {
        let op = |k: &str, v: &str| (k.to_string(), v.to_string());
        let (k, v) = op("x-id", "alice");
        for (what, h, want) in [
            (
                "append_action 0",
                header_option("X-Id", "alice", b"", None, 0, false),
                Some(HeaderOp::Append(k.clone(), v.clone())),
            ),
            (
                "append_action 1",
                header_option("x-id", "alice", b"", None, 1, false),
                Some(HeaderOp::AddIfAbsent(k.clone(), v.clone())),
            ),
            (
                "append_action 2",
                header_option("x-id", "alice", b"", None, 2, false),
                Some(HeaderOp::Set(k.clone(), v.clone())),
            ),
            (
                "append_action 3",
                header_option("x-id", "alice", b"", None, 3, false),
                Some(HeaderOp::OverwriteIfExists(k.clone(), v.clone())),
            ),
            (
                "unknown append_action",
                header_option("x-id", "alice", b"", None, 4, false),
                None,
            ),
            (
                "deprecated append wins",
                header_option("x-id", "alice", b"", Some(true), 2, false),
                Some(HeaderOp::Append(k.clone(), v.clone())),
            ),
            (
                "deprecated append=false",
                header_option("x-id", "alice", b"", Some(false), 0, false),
                Some(HeaderOp::Set(k.clone(), v.clone())),
            ),
            (
                "raw_value when value is empty",
                header_option("x-id", "", b"alice", None, 2, false),
                Some(HeaderOp::Set(k.clone(), v.clone())),
            ),
            (
                "value wins over raw_value",
                header_option("x-id", "alice", b"bob", None, 2, false),
                Some(HeaderOp::Set(k.clone(), v.clone())),
            ),
            (
                "non-UTF-8 raw_value",
                header_option("x-id", "", b"\xff", None, 2, false),
                None,
            ),
            (
                "empty value dropped",
                header_option("x-id", "", b"", None, 2, false),
                None,
            ),
            (
                "empty value kept on request",
                header_option("x-id", "", b"", None, 2, true),
                Some(HeaderOp::Set(k.clone(), String::new())),
            ),
            (
                "forbidden, any case",
                header_option("Transfer-Encoding", "chunked", b"", None, 2, false),
                None,
            ),
            (
                "pseudo-header",
                header_option(":path", "/admin", b"", None, 2, false),
                None,
            ),
        ] {
            assert_eq!(header_op(h), want, "{what}");
        }
    }

    #[tokio::test]
    async fn authz_cannot_set_framing_headers() {
        let authz = fake_authz().await;
        let forbidden = [
            "transfer-encoding",
            "content-length",
            "host",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "forwarded",
            "connection",
            "te",
            "upgrade",
        ];
        let mut ops: Vec<HeaderOp> = forbidden
            .iter()
            .map(|h| HeaderOp::Set(h.to_string(), "evil".into()))
            .collect();
        ops.push(HeaderOp::Set("X-OK".into(), "1".into()));
        authz.set(AuthzMode::AllowWith {
            ops,
            remove: vec!["host".into(), "x-forwarded-for".into()],
            response: vec![],
        });
        let b = recorder("b").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        get(gw.addr, "/", "").await;
        let s = b.last();
        assert_eq!(s.header("x-ok"), Some("1"));
        for h in forbidden {
            assert!(
                !s.headers_named(h).contains(&"evil"),
                "{h}: {:?}",
                s.headers
            );
        }
        assert_eq!(s.headers_named("x-forwarded-for"), ["127.0.0.1"]);
        assert_eq!(
            s.headers_named("host"),
            ["t.test"],
            "the client's, not authz's"
        );
    }

    #[tokio::test]
    async fn header_ops_applied() {
        let authz = fake_authz().await;
        authz.set(AuthzMode::AllowWith {
            ops: vec![
                HeaderOp::Append("x-a".into(), "authz".into()),
                HeaderOp::Set("x-b".into(), "authz".into()),
                HeaderOp::AddIfAbsent("x-c".into(), "authz".into()),
                HeaderOp::AddIfAbsent("x-d".into(), "authz".into()),
                HeaderOp::OverwriteIfExists("x-e".into(), "authz".into()),
                HeaderOp::OverwriteIfExists("x-f".into(), "authz".into()),
            ],
            remove: vec!["Authorization".into()],
            response: vec![("set-cookie".into(), "session=1".into())],
        });
        let b = recorder("b").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        let resp = raw(
            gw.addr,
            "GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer t\r\nX-A: client\r\nX-B: client\r\nX-C: client\r\nX-E: client\r\nConnection: close\r\n\r\n",
        )
        .await;
        let s = b.last();
        assert_eq!(s.headers_named("x-a"), ["client", "authz"]);
        assert_eq!(s.headers_named("x-b"), ["authz"]);
        assert_eq!(s.headers_named("x-c"), ["client"]);
        assert_eq!(s.headers_named("x-d"), ["authz"]);
        assert_eq!(s.headers_named("x-e"), ["authz"]);
        assert!(s.header("x-f").is_none());
        assert!(
            s.header("authorization").is_none(),
            "headers_to_remove not honoured"
        );
        assert!(
            resp.to_ascii_lowercase().contains("set-cookie: session=1"),
            "{resp}"
        );
    }

    #[tokio::test]
    async fn check_request_contents() {
        let authz = fake_authz().await;
        let b = recorder("b").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        raw(
            gw.addr,
            "GET /p?a=1&b=2 HTTP/1.1\r\nHost: Front.test\r\nCookie: a=1\r\nCookie: b=2\r\nCookie: c=3\r\n\
             Authorization: Bearer tok\r\nX-Other: no\r\nConnection: close\r\n\r\n",
        )
        .await;
        let call = authz.calls().pop().unwrap().attributes.unwrap();
        let http = call.request.unwrap().http.unwrap();
        assert_eq!(
            (
                http.method.as_str(),
                http.scheme.as_str(),
                http.path.as_str(),
                http.query.as_str()
            ),
            ("GET", "http", "/p?a=1&b=2", "a=1&b=2")
        );
        assert_eq!(
            (http.host.as_str(), http.protocol.as_str()),
            ("Front.test", "HTTP/1.1")
        );
        assert_eq!(
            http.headers,
            [
                ("cookie".to_string(), "a=1; b=2; c=3".to_string()),
                ("authorization".to_string(), "Bearer tok".to_string()),
            ]
            .into()
        );
        let peer = call.source.unwrap().address.unwrap().address.unwrap();
        let envoy_types::pb::envoy::config::core::v3::address::Address::SocketAddress(sa) = peer
        else {
            panic!("no socket address")
        };
        assert_eq!(sa.address, "127.0.0.1");
        assert!(matches!(
            sa.port_specifier,
            Some(envoy_types::pb::envoy::config::core::v3::socket_address::PortSpecifier::PortValue(p)) if p > 0
        ));
    }

    fn cfg_with(authz: std::net::SocketAddr, limits: &str) -> Config {
        Config::parse_plaintext(&format!(
            "listen: '127.0.0.1:0'\nauthz_backend: {{ host: '{}', port: {} }}\nlimits: {{ {limits} }}\nroutes: []\n",
            authz.ip(),
            authz.port()
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn deny_error_unreachable_fail_closed() {
        let authz = fake_authz().await;
        let b = recorder("b").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        authz.set(AuthzMode::Deny);
        assert_eq!(get(gw.addr, "/", "").await.0, 403);
        authz.set(AuthzMode::Fail);
        assert_eq!(get(gw.addr, "/", "").await.0, 403);
        assert_eq!(b.count(), 0);
        authz.set(AuthzMode::Allow);
        assert_eq!(get(gw.addr, "/", "").await.0, 200);

        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let gw2 = gateway(authz_cfg(dead), vec![route("/", Authz::Required, b.addr)]).await;
        assert_eq!(get(gw2.addr, "/", "").await.0, 403);
    }

    #[tokio::test]
    async fn slow_authz_denies() {
        let authz = fake_authz().await;
        authz.set(AuthzMode::SlowAllow(Duration::from_secs(5)));
        let b = recorder("b").await;
        let gw = gateway(
            cfg_with(authz.addr, "authz_timeout_ms: 200"),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        let t = std::time::Instant::now();
        let (code, body) = get(gw.addr, "/", "").await;
        assert_eq!(code, 403, "{body}");
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "took {:?}",
            t.elapsed()
        );
        assert_eq!(b.count(), 0);
    }

    #[tokio::test]
    async fn oversized_response_denies() {
        let authz = fake_authz().await;
        authz.set(AuthzMode::AllowWithHugeHeader(200_000));
        let b = recorder("b").await;
        let gw = gateway(
            cfg_with(authz.addr, "authz_max_response_bytes: 4096"),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        assert_eq!(get(gw.addr, "/", "").await.0, 403);
        assert_eq!(b.count(), 0);
        authz.set(AuthzMode::Allow);
        assert_eq!(get(gw.addr, "/", "").await.0, 200);
    }

    #[tokio::test]
    async fn channel_reused() {
        use futures::StreamExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = conns.clone();
        let svc =
            envoy_types::pb::envoy::service::auth::v3::authorization_server::AuthorizationServer::new(
                fake_service(
                    Arc::new(Mutex::new(AuthzMode::Allow)),
                    Arc::new(Mutex::new(Vec::new())),
                ),
            );
        tokio::spawn(async move {
            let incoming =
                tokio_stream::wrappers::TcpListenerStream::new(listener).inspect(move |r| {
                    if r.is_ok() {
                        c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            let _ = tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await;
        });
        let b = recorder("b").await;
        let gw = gateway(authz_cfg(addr), vec![route("/", Authz::Required, b.addr)]).await;
        for _ in 0..25 {
            assert_eq!(get(gw.addr, "/", "").await.0, 200);
        }
        assert_eq!(conns.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
