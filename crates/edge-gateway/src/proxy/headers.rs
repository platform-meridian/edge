use hyper::Request;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use std::net::SocketAddr;

pub(super) const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    /// Decides the forwarded scheme; nothing the client sends does.
    pub tls: bool,
    pub handshake: crate::tls::Handshake,
}

impl ConnInfo {
    pub fn plain(peer: SocketAddr) -> Self {
        Self {
            peer,
            tls: false,
            handshake: Default::default(),
        }
    }

    pub fn tls(peer: SocketAddr, handshake: crate::tls::Handshake) -> Self {
        Self {
            peer,
            tls: true,
            handshake,
        }
    }

    pub(super) fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct StripSet {
    exact: Vec<HeaderName>,
    prefixes: Vec<String>,
}

impl StripSet {
    pub fn new(patterns: &[String]) -> Self {
        let mut s = Self::default();
        for p in patterns {
            let p = p.to_ascii_lowercase();
            match p.strip_suffix('*') {
                Some(prefix) => s.prefixes.push(prefix.to_string()),
                None => s.exact.extend(HeaderName::try_from(p.as_str())),
            }
        }
        s
    }

    fn matches(&self, name: &HeaderName) -> bool {
        self.exact.contains(name) || self.prefixes.iter().any(|p| name.as_str().starts_with(p))
    }
}

/// RFC 9110 7.6.1, plus `Keep-Alive` and `Proxy-Connection` (the classic
/// smuggling carrier), which every implementation treats as hop-by-hop.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
];

/// Runs before authz, so authz judges exactly what the backend gets.
pub(super) fn sanitize(headers: &mut HeaderMap, strip: &StripSet) {
    let named: Vec<HeaderName> = connection_tokens(headers)
        .filter_map(|t| HeaderName::try_from(t.to_ascii_lowercase()).ok())
        .collect();
    for n in &named {
        headers.remove(n);
    }
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    let identity: Vec<HeaderName> = headers
        .keys()
        .filter(|k| strip.matches(k))
        .cloned()
        .collect();
    for n in identity {
        headers.remove(&n);
    }
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
}

/// RFC 9110 7.8: `Upgrade` alone is an offer; the `upgrade` token must also be
/// in `Connection`.
pub(super) fn upgrade_protocol(headers: &HeaderMap) -> Option<HeaderValue> {
    let protocol = headers.get(hyper::header::UPGRADE)?;
    connection_tokens(headers)
        .any(|t| t.eq_ignore_ascii_case("upgrade"))
        .then(|| protocol.clone())
}

/// RFC 7239: a token, or else a quoted-string.
pub(super) fn fwd_value(v: &str) -> String {
    let tchar = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if !v.is_empty() && v.chars().all(tchar) {
        v.to_string()
    } else {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Replace, never append to, the client's forwarding headers: nothing trusted
/// sits in front of the gateway, so any incoming value is forged.
pub(super) fn set_forwarded(headers: &mut HeaderMap, conn: &ConnInfo, client_host: Option<&str>) {
    for n in [
        &X_FORWARDED_FOR,
        &X_FORWARDED_PROTO,
        &X_FORWARDED_HOST,
        &FORWARDED,
    ] {
        headers.remove(n);
    }
    let ip = conn.peer.ip().to_string();
    if let Ok(v) = HeaderValue::try_from(ip.as_str()) {
        headers.insert(X_FORWARDED_FOR, v);
    }
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(conn.scheme()));
    let node = if conn.peer.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip
    };
    let mut fwd = format!("for={};proto={}", fwd_value(&node), conn.scheme());
    if let Some(h) = client_host {
        if let Ok(v) = HeaderValue::try_from(h) {
            headers.insert(X_FORWARDED_HOST, v);
        }
        fwd.push_str(&format!(";host={}", fwd_value(h)));
    }
    if let Ok(v) = HeaderValue::try_from(fwd) {
        headers.insert(FORWARDED, v);
    }
}

/// The URI authority (h2 `:authority`, h1 absolute-form) outranks `Host`
/// (RFC 9113 8.3.1, RFC 9112 3.2.2), so routing cannot depend on the version.
pub(super) fn request_host(req: &Request<Incoming>) -> Option<String> {
    if let Some(a) = req.uri().authority() {
        let without_userinfo = a.as_str().rsplit('@').next().unwrap_or(a.as_str());
        return Some(without_userinfo.to_string());
    }
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::HeaderOp;
    use crate::config::Authz;
    use crate::proxy::Body;
    use crate::testutil::*;
    use http_body_util::BodyExt;
    use hyper::Response;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::net::TcpStream;

    #[test]
    fn upgrade_needs_connection_token() {
        for (connection, upgrade, want) in [
            (&["Upgrade"][..], Some("websocket"), true),
            (&["keep-alive, upgrade"], Some("websocket"), true),
            (&["KEEP-ALIVE", "UPGRADE"], Some("websocket"), true),
            (&[], Some("websocket"), false),
            (&["Upgrade"], None, false),
            (&["upgrade-insecure-requests"], Some("websocket"), false),
        ] {
            let mut h = HeaderMap::new();
            for c in connection {
                h.append(hyper::header::CONNECTION, HeaderValue::from_static(c));
            }
            if let Some(u) = upgrade {
                h.insert(hyper::header::UPGRADE, HeaderValue::from_static(u));
            }
            let got = upgrade_protocol(&h);
            assert_eq!(got.is_some(), want, "{connection:?} {upgrade:?}");
            if want {
                assert_eq!(got.unwrap(), "websocket");
            }
        }
    }

    #[test]
    fn forwarded_quotes_non_tokens() {
        assert_eq!(fwd_value("192.0.2.1"), "192.0.2.1");
        assert_eq!(fwd_value("[2001:db8::1]"), "\"[2001:db8::1]\"");
        assert_eq!(fwd_value("h:8443"), "\"h:8443\"");
        assert_eq!(fwd_value("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(fwd_value(""), "\"\"");
    }

    #[test]
    fn ipv6_peer_bracketed() {
        let mut h = HeaderMap::new();
        let conn = ConnInfo::tls("[2001:db8::1]:443".parse().unwrap(), Default::default());
        set_forwarded(&mut h, &conn, None);
        assert_eq!(h["forwarded"], "for=\"[2001:db8::1]\";proto=https");
        assert_eq!(h["x-forwarded-for"], "2001:db8::1");
        assert!(h.get("x-forwarded-host").is_none());
    }

    async fn h2_get(gw: std::net::SocketAddr, req: Request<Body>) -> Response<Incoming> {
        let stream = TcpStream::connect(gw).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(conn);
        sender.send_request(req).await.unwrap()
    }

    #[tokio::test]
    async fn h2_authority_forwarded_as_host() {
        let b = recorder("b").await;
        let gw = gateway(insecure_cfg(), vec![route("/", Authz::Skip, b.addr)]).await;
        let req = Request::builder()
            .uri("http://headlamp.example.lan:8443/")
            .body(Body::default())
            .unwrap();
        assert_eq!(h2_get(gw.addr, req).await.status(), 200);
        let seen = b.last();
        assert_eq!(seen.header("host"), Some(b.addr.to_string().as_str()));
        assert_eq!(
            seen.header("x-forwarded-host"),
            Some("headlamp.example.lan:8443")
        );
    }

    #[tokio::test]
    async fn client_forwarding_headers_replaced() {
        let b = recorder("b").await;
        let gw = gateway(insecure_cfg(), vec![route("/", Authz::Skip, b.addr)]).await;
        raw(
            gw.addr,
            "GET /?q=1 HTTP/1.1\r\nHost: Front.Test:8443\r\nX-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: https\r\n\
             X-Forwarded-Host: evil\r\nForwarded: for=6.6.6.6\r\nX-Auth-Request-User: admin\r\nX-Forwarded-User: admin\r\n\
             X-Real-IP: 6.6.6.6\r\nConnection: close\r\n\r\n",
        )
        .await;
        let s = b.last();
        assert_eq!(s.headers_named("x-forwarded-for"), ["127.0.0.1"]);
        assert_eq!(s.headers_named("x-forwarded-proto"), ["http"]);
        assert_eq!(s.headers_named("x-forwarded-host"), ["Front.Test:8443"]);
        assert_eq!(
            s.headers_named("forwarded"),
            ["for=127.0.0.1;proto=http;host=\"Front.Test:8443\""]
        );
        for h in ["x-auth-request-user", "x-forwarded-user", "x-real-ip"] {
            assert!(s.header(h).is_none(), "{h} reached the backend");
        }
    }

    #[tokio::test]
    async fn identity_headers_stripped_before_authz() {
        let authz = fake_authz().await;
        authz.set(AuthzMode::AllowWith {
            ops: vec![HeaderOp::Set("x-auth-request-user".into(), "alice".into())],
            remove: vec![],
            response: vec![],
        });
        let b = recorder("b").await;
        let gw = gateway(
            authz_cfg(authz.addr),
            vec![route("/", Authz::Required, b.addr)],
        )
        .await;
        get(
            gw.addr,
            "/",
            "X-Auth-Request-User: mallory\r\nX-Auth-Other: y\r\n",
        )
        .await;
        let s = b.last();
        assert_eq!(s.headers_named("x-auth-request-user"), ["alice"]);
        assert!(s.header("x-auth-other").is_none());
    }

    #[tokio::test]
    async fn hop_by_hop_headers_dropped() {
        let b = recorder("b").await;
        let gw = gateway(insecure_cfg(), vec![route("/", Authz::Skip, b.addr)]).await;
        raw(
            gw.addr,
            "GET / HTTP/1.1\r\nHost: t\r\nConnection: close, X-Hop, keep-alive\r\nX-Hop: secret\r\n\
             X-Keep: yes\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\nTE: trailers\r\n\r\n",
        )
        .await;
        let s = b.last();
        for h in ["x-hop", "keep-alive", "proxy-connection", "te"] {
            assert!(
                s.header(h).is_none(),
                "{h} crossed the hop: {:?}",
                s.headers
            );
        }
        assert_eq!(s.header("x-keep"), Some("yes"));
    }

    #[tokio::test]
    async fn authority_outranks_host() {
        let a = recorder("a").await;
        let other = recorder("other").await;
        let gw = gateway(
            insecure_cfg(),
            vec![
                host_route("a.test", "/", Authz::Skip, a.addr),
                route("/", Authz::Skip, other.addr),
            ],
        )
        .await;
        raw(
            gw.addr,
            "GET http://user@a.test/ HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let req = Request::builder()
            .uri("http://a.test/")
            .header("host", "b.test")
            .body(Body::default())
            .unwrap();
        h2_get(gw.addr, req)
            .await
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!((a.count(), other.count()), (2, 0));
    }
}
