//! HTTPRoute's core filters, applied after authz: it judges what the client sent.

use super::{Body, ConnInfo, Target, status};
use crate::config::{HeaderModifier, Redirect, Route};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

pub(super) fn modify_headers(headers: &mut hyper::HeaderMap, m: &HeaderModifier) {
    let pair = |(k, v): &(String, String)| {
        Some((
            HeaderName::try_from(k.as_str()).ok()?,
            HeaderValue::try_from(v.as_str()).ok()?,
        ))
    };
    for (k, v) in m.set.iter().filter_map(pair) {
        headers.insert(k, v);
    }
    for (k, v) in m.add.iter().filter_map(pair) {
        headers.append(k, v);
    }
    for k in &m.remove {
        headers.remove(k.as_str());
    }
}

/// Gateway API: without a port or scheme the listener's port is kept, a named
/// scheme brings its own, and a scheme's default port is left out.
pub(super) fn redirect(
    r: &Redirect,
    route: &Route,
    target: &Target,
    client_host: Option<&str>,
    conn: ConnInfo,
) -> Response<Body> {
    let Some(host) = r
        .hostname
        .as_deref()
        .or_else(|| client_host.map(without_port))
    else {
        return status(StatusCode::BAD_REQUEST, "no host to redirect to");
    };
    let scheme = r.scheme.as_deref().unwrap_or(conn.scheme());
    let port = match (r.port, r.scheme.as_deref()) {
        (Some(p), _) => p,
        (None, Some("http")) => 80,
        (None, Some("https")) => 443,
        (None, _) => r.listener_port,
    };
    let authority = match (scheme, port) {
        ("http", 80) | ("https", 443) => host.to_string(),
        _ => format!("{host}:{port}"),
    };
    let path = match &r.path {
        Some(m) => m.apply(&target.path, &route.prefix),
        None => target.path.clone(),
    };
    let location = Target {
        path,
        query: target.query.clone(),
    }
    .request_target();
    let code = StatusCode::from_u16(r.status).unwrap_or(StatusCode::FOUND);
    Response::builder()
        .status(code)
        .header(
            hyper::header::LOCATION,
            format!("{scheme}://{authority}{location}"),
        )
        .body(Body::default())
        .unwrap_or_else(|_| status(StatusCode::BAD_REQUEST, "bad redirect target"))
}

fn without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.split_inclusive(']').next().unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// Gateway API's conformance cases (HTTPRouteRequestHeaderModifier,
/// HTTPRouteRewritePath, HTTPRouteRewriteHost, HTTPRouteRedirect*), on a
/// plaintext listener whose port is 8080.
#[cfg(test)]
mod tests {
    use crate::config::{Authz, Filters, HeaderModifier, PathModifier, Redirect, Route};
    use crate::testutil::*;

    const LISTENER: u16 = 8080;

    fn with(prefix: &str, filters: Filters, backend: &Recorder) -> Route {
        Route {
            filters,
            ..route(prefix, Authz::Skip, backend.addr)
        }
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn headers(set: &[(&str, &str)], add: &[(&str, &str)], remove: &[&str]) -> Filters {
        Filters {
            request_headers: HeaderModifier {
                set: pairs(set),
                add: pairs(add),
                remove: remove.iter().map(|s| s.to_string()).collect(),
            },
            ..Filters::default()
        }
    }

    fn rewrite(m: PathModifier) -> Filters {
        Filters {
            rewrite_path: Some(m),
            ..Filters::default()
        }
    }

    fn redirect(r: Redirect) -> Filters {
        Filters {
            redirect: Some(r),
            ..Filters::default()
        }
    }

    fn to() -> Redirect {
        Redirect {
            scheme: None,
            hostname: None,
            path: None,
            port: None,
            status: 302,
            listener_port: LISTENER,
        }
    }

    async fn request(gw: std::net::SocketAddr, target: &str, host: &str, extra: &str) -> String {
        raw(
            gw,
            &format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"),
        )
        .await
    }

    fn location(resp: &str) -> Option<&str> {
        resp.lines().find_map(|l| {
            l.strip_prefix("location: ")
                .or_else(|| l.strip_prefix("Location: "))
        })
    }

    #[tokio::test]
    async fn request_header_modifier() {
        let b = recorder("b").await;
        let gw = gateway(
            insecure_cfg(),
            vec![
                with(
                    "/set",
                    headers(&[("x-header-set", "set-overwrites-values")], &[], &[]),
                    &b,
                ),
                with(
                    "/add",
                    headers(&[], &[("x-header-add", "add-appends-values")], &[]),
                    &b,
                ),
                with("/remove", headers(&[], &[], &["x-header-remove"]), &b),
                with(
                    "/multiple",
                    headers(
                        &[
                            ("x-header-set-1", "header-set-1"),
                            ("x-header-set-2", "header-set-2"),
                        ],
                        &[
                            ("x-header-add-1", "header-add-1"),
                            ("x-header-add-2", "header-add-2"),
                        ],
                        &["x-header-remove-1", "x-header-remove-2"],
                    ),
                    &b,
                ),
            ],
        )
        .await;
        let seen = |target: &'static str, extra: &'static str| {
            let (gw, b) = (gw.addr, &b);
            async move {
                request(gw, target, "example.org", extra).await;
                b.last()
            }
        };

        let s = seen("/set", "Some-Other-Header: val\r\n").await;
        assert_eq!(s.headers_named("x-header-set"), ["set-overwrites-values"]);
        assert_eq!(s.header("some-other-header"), Some("val"));
        let s = seen("/set", "X-Header-Set: some-other-value\r\n").await;
        assert_eq!(s.headers_named("x-header-set"), ["set-overwrites-values"]);

        let s = seen("/add", "Some-Other-Header: val\r\n").await;
        assert_eq!(s.headers_named("x-header-add"), ["add-appends-values"]);
        let s = seen("/add", "X-Header-Add: some-other-value\r\n").await;
        assert_eq!(
            s.headers_named("x-header-add"),
            ["some-other-value", "add-appends-values"]
        );

        let s = seen("/remove", "X-Header-Remove: val\r\nX-Keep: k\r\n").await;
        assert_eq!(s.header("x-header-remove"), None);
        assert_eq!(s.header("x-keep"), Some("k"));

        let s = seen(
            "/multiple",
            "X-Header-Set-2: other\r\nX-Header-Add-2: other\r\nX-Header-Remove-1: a\r\nX-Header-Remove-2: b\r\n",
        )
        .await;
        assert_eq!(s.headers_named("x-header-set-1"), ["header-set-1"]);
        assert_eq!(s.headers_named("x-header-set-2"), ["header-set-2"]);
        assert_eq!(s.headers_named("x-header-add-1"), ["header-add-1"]);
        assert_eq!(s.headers_named("x-header-add-2"), ["other", "header-add-2"]);
        assert_eq!(s.header("x-header-remove-1"), None);
        assert_eq!(s.header("x-header-remove-2"), None);
    }

    #[tokio::test]
    async fn rewrite_path_and_host() {
        let b = recorder("b").await;
        let mut host = with("/host", Filters::default(), &b);
        host.rewrite_host = Some("one.example.org".into());
        let gw = gateway(
            insecure_cfg(),
            vec![
                with(
                    "/prefix/one",
                    rewrite(PathModifier::Prefix("/one".into())),
                    &b,
                ),
                with("/full/path", rewrite(PathModifier::Full("/one".into())), &b),
                with(
                    "/strip-prefix",
                    rewrite(PathModifier::Prefix("/".into())),
                    &b,
                ),
                host,
            ],
        )
        .await;
        for (sent, want) in [
            ("/prefix/one/two", "/one/two"),
            ("/prefix/one", "/one"),
            ("/prefix/one/two?a=b&c=d", "/one/two?a=b&c=d"),
            ("/full/path/original", "/one"),
            ("/full/path?q=1", "/one?q=1"),
            ("/strip-prefix/three", "/three"),
            ("/strip-prefix", "/"),
            ("/strip-prefix/", "/"),
        ] {
            request(gw.addr, sent, "example.org", "").await;
            assert_eq!(b.last().target, want, "{sent}");
        }
        request(gw.addr, "/host/x", "example.org", "").await;
        assert_eq!(b.last().headers_named("host"), ["one.example.org"]);
        assert_eq!(b.last().target, "/host/x");
    }

    #[tokio::test]
    async fn redirects() {
        let b = recorder("b").await;
        let r = |f: fn(&mut Redirect)| {
            let mut x = to();
            f(&mut x);
            redirect(x)
        };
        let gw = gateway(
            insecure_cfg(),
            vec![
                with(
                    "/original-prefix",
                    r(|x| x.path = Some(PathModifier::Prefix("/replacement-prefix".into()))),
                    &b,
                ),
                with(
                    "/full",
                    r(|x| x.path = Some(PathModifier::Full("/full-path-replacement".into()))),
                    &b,
                ),
                with(
                    "/path-and-host",
                    r(|x| {
                        x.hostname = Some("example.org".into());
                        x.path = Some(PathModifier::Prefix("/replacement-prefix".into()));
                    }),
                    &b,
                ),
                with(
                    "/path-and-status",
                    r(|x| {
                        x.path = Some(PathModifier::Full("/replacement-full".into()));
                        x.status = 301;
                    }),
                    &b,
                ),
                with("/scheme", r(|x| x.scheme = Some("https".into())), &b),
                with(
                    "/scheme-and-host",
                    r(|x| {
                        x.scheme = Some("https".into());
                        x.hostname = Some("example.org".into());
                    }),
                    &b,
                ),
                with(
                    "/scheme-and-status",
                    r(|x| {
                        x.scheme = Some("https".into());
                        x.status = 301;
                    }),
                    &b,
                ),
                with(
                    "/hostname-redirect",
                    r(|x| x.hostname = Some("example.org".into())),
                    &b,
                ),
                with("/port", r(|x| x.port = Some(8083)), &b),
                with(
                    "/port-and-scheme",
                    r(|x| {
                        x.scheme = Some("https".into());
                        x.port = Some(8443);
                    }),
                    &b,
                ),
                with(
                    "/http-80",
                    r(|x| {
                        x.scheme = Some("http".into());
                        x.port = Some(80);
                    }),
                    &b,
                ),
                with(
                    "/https-443",
                    r(|x| {
                        x.scheme = Some("https".into());
                        x.port = Some(443);
                    }),
                    &b,
                ),
                with("/status-303", r(|x| x.status = 303), &b),
            ],
        )
        .await;
        for (sent, host, code, want) in [
            (
                "/original-prefix/lemon",
                "redirect.example",
                302,
                "http://redirect.example:8080/replacement-prefix/lemon",
            ),
            (
                "/full/path/original?q=1",
                "redirect.example",
                302,
                "http://redirect.example:8080/full-path-replacement?q=1",
            ),
            (
                "/path-and-host",
                "redirect.example",
                302,
                "http://example.org:8080/replacement-prefix",
            ),
            (
                "/path-and-status",
                "redirect.example:8080",
                301,
                "http://redirect.example:8080/replacement-full",
            ),
            ("/scheme", "example.org", 302, "https://example.org/scheme"),
            (
                "/scheme-and-host",
                "redirect.example",
                302,
                "https://example.org/scheme-and-host",
            ),
            (
                "/scheme-and-status",
                "example.org",
                301,
                "https://example.org/scheme-and-status",
            ),
            (
                "/hostname-redirect",
                "redirect.example:8080",
                302,
                "http://example.org:8080/hostname-redirect",
            ),
            ("/port", "example.org", 302, "http://example.org:8083/port"),
            (
                "/port-and-scheme",
                "[::1]:9",
                302,
                "https://[::1]:8443/port-and-scheme",
            ),
            ("/http-80", "example.org", 302, "http://example.org/http-80"),
            (
                "/https-443",
                "example.org",
                302,
                "https://example.org/https-443",
            ),
            (
                "/status-303",
                "example.org",
                303,
                "http://example.org:8080/status-303",
            ),
        ] {
            let resp = request(gw.addr, sent, host, "").await;
            let (got, _) = parse_status(&resp);
            assert_eq!((got, location(&resp)), (code, Some(want)), "{sent}\n{resp}");
        }
        assert_eq!(b.count(), 0, "a redirect reached the backend");
    }

    /// The first users: `/` to the application's own root, and nothing under
    /// it redirected.
    #[tokio::test]
    async fn root_redirects_to_application() {
        let b = recorder("b").await;
        let mut to_ews = to();
        to_ews.path = Some(PathModifier::Prefix("/ews".into()));
        let gw = gateway(
            insecure_cfg(),
            vec![
                with("/ews", Filters::default(), &b),
                with("/", redirect(to_ews), &b),
            ],
        )
        .await;
        let resp = request(gw.addr, "/", "elf.example", "").await;
        assert_eq!(location(&resp), Some("http://elf.example:8080/ews/"));
        let resp = request(gw.addr, "/ews/app", "elf.example", "").await;
        assert_eq!(parse_status(&resp).0, 200);
        assert_eq!(b.last().target, "/ews/app");
    }

    #[test]
    fn port_stripped_from_client_host() {
        for (h, want) in [
            ("a.test:8080", "a.test"),
            ("a.test", "a.test"),
            ("[::1]:443", "[::1]"),
            ("[::1]", "[::1]"),
            ("a:b", "a:b"),
        ] {
            assert_eq!(super::without_port(h), want, "{h}");
        }
    }
}
