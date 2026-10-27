pub use crate::path::{normalize_host, segment_prefix};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Authz {
    #[default]
    Required,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthzProtocol {
    #[default]
    Grpc,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub host: String,
    pub port: u16,
    /// From a BackendTLSPolicy; the config file has none.
    #[serde(skip)]
    pub tls: Option<UpstreamTls>,
}

/// How a BackendTLSPolicy's Service is dialled. Compared by what it says; the
/// dialer is built from it once per table, and without one every request is
/// refused: the policy could not be honoured.
#[derive(Clone, Default)]
pub struct UpstreamTls {
    /// The SNI, and the name verified unless `sans` are given.
    pub hostname: String,
    pub ca_pem: String,
    /// The compiled-in Mozilla roots (`wellKnownCACertificates: System`).
    pub system: bool,
    pub sans: Vec<San>,
    pub refused: bool,
    /// What the gateway presents as the client, by fingerprint.
    pub identity: String,
    pub dialer: Option<std::sync::Arc<crate::proxy::Dialer>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San {
    Hostname(String),
    Uri(String),
}

impl UpstreamTls {
    pub fn refused() -> Self {
        Self {
            refused: true,
            ..Self::default()
        }
    }

    fn said(&self) -> impl PartialEq + '_ {
        (
            &self.hostname,
            &self.ca_pem,
            self.system,
            &self.sans,
            self.refused,
            &self.identity,
            self.dialer.is_some(),
        )
    }
}

impl PartialEq for UpstreamTls {
    fn eq(&self, o: &Self) -> bool {
        self.said() == o.said()
    }
}

impl Eq for UpstreamTls {}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("hostname", &self.hostname)
            .field("system", &self.system)
            .field("sans", &self.sans)
            .field("refused", &self.refused)
            .field("identity", &self.identity)
            .field("usable", &self.dialer.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default = "root")]
    pub prefix: String,
    #[serde(default)]
    pub authz: Authz,
    /// The upstream Host in place of the client's: URLRewrite's `hostname`.
    #[serde(default)]
    pub rewrite_host: Option<String>,
    /// Absent only on a redirect, which is answered here.
    pub backend: Option<Backend>,
    /// HTTPRoute filters; the config file has none.
    #[serde(skip)]
    pub filters: Filters,
    /// Its hostname asks the client for a certificate.
    #[serde(skip)]
    pub client_cert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filters {
    pub redirect: Option<Redirect>,
    pub rewrite_path: Option<PathModifier>,
    pub request_headers: HeaderModifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathModifier {
    Full(String),
    /// Replaces the route's matched prefix.
    Prefix(String),
}

impl PathModifier {
    /// `path` and the replacement are canonical, and `path` is under `prefix`.
    pub fn apply(&self, path: &str, prefix: &str) -> String {
        match self {
            PathModifier::Full(p) => p.clone(),
            PathModifier::Prefix(with) => {
                let rest = &path[prefix.trim_end_matches('/').len().min(path.len())..];
                let joined = format!("{}{rest}", with.trim_end_matches('/'));
                if joined.is_empty() {
                    "/".into()
                } else {
                    joined
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub path: Option<PathModifier>,
    pub port: Option<u16>,
    pub status: u16,
    /// Stands in for a port when neither it nor a scheme is named.
    pub listener_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderModifier {
    pub set: Vec<(String, String)>,
    pub add: Vec<(String, String)>,
    pub remove: Vec<String>,
}

fn root() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub tls_handshake_timeout_ms: u64,
    pub header_read_timeout_ms: u64,
    pub h2_keepalive_interval_ms: u64,
    pub h2_keepalive_timeout_ms: u64,
    pub max_connections: usize,
    pub upstream_connect_timeout_ms: u64,
    /// Until response headers only: bodies (downloads, event streams) are unbounded.
    pub upstream_response_timeout_ms: u64,
    pub tunnel_idle_timeout_ms: u64,
    /// Expiry denies.
    pub authz_timeout_ms: u64,
    /// A larger response denies.
    pub authz_max_response_bytes: usize,
    /// Only where inotify is unavailable.
    pub tls_reload_interval_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            tls_handshake_timeout_ms: 10_000,
            header_read_timeout_ms: 30_000,
            h2_keepalive_interval_ms: 30_000,
            h2_keepalive_timeout_ms: 20_000,
            max_connections: 256,
            upstream_connect_timeout_ms: 5_000,
            upstream_response_timeout_ms: 120_000,
            tunnel_idle_timeout_ms: 3_600_000,
            authz_timeout_ms: 3_000,
            authz_max_response_bytes: 64 * 1024,
            tls_reload_interval_ms: 30_000,
        }
    }
}

/// Backends trust these identity headers from authz alone, so every client copy
/// is stripped. A trailing `*` matches a prefix.
pub const DEFAULT_STRIP_HEADERS: &[&str] = &[
    "x-auth-*",
    "x-authx-*",
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-groups",
    "x-forwarded-preferred-username",
    "x-forwarded-access-token",
    "remote-user",
    "x-remote-user",
    "x-remote-group",
    "x-remote-email",
    "x-user",
    "x-email",
    "x-real-ip",
    "x-forwarded-client-cert",
];

/// Whether `lower` (a lowercase header name) is in a strip list.
pub fn strip_listed(patterns: &[String], lower: &str) -> bool {
    patterns.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        match p.strip_suffix('*') {
            Some(prefix) => lower.starts_with(prefix),
            None => p == lower,
        }
    })
}

fn default_strip() -> Vec<String> {
    DEFAULT_STRIP_HEADERS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    #[serde(default)]
    pub authz_backend: Option<Backend>,
    #[serde(default)]
    pub authz_protocol: AuthzProtocol,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default = "default_strip")]
    pub strip_request_headers: Vec<String>,
    pub routes: Vec<Route>,
}

/// The routes one labelled ConfigMap declares (`controller::discovered`):
/// routes alone, so no app sets what the whole gateway does.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSet {
    pub routes: Vec<Route>,
}

impl RouteSet {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut f: RouteSet =
            serde_saphyr::from_str(text).map_err(|e| anyhow::anyhow!("parsing: {e}"))?;
        canonicalize_routes(&mut f.routes)?;
        Ok(f)
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let shown = path.display();
        let text =
            std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {shown}: {e}"))?;
        Self::parse(&text).map_err(|e| anyhow::anyhow!("{shown}: {e}"))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Self::parse_checked(text, true)
    }

    #[cfg(test)]
    pub fn parse_plaintext(text: &str) -> anyhow::Result<Self> {
        Self::parse_checked(text, false)
    }

    fn parse_checked(text: &str, require_tls: bool) -> anyhow::Result<Self> {
        let mut cfg: Config =
            serde_saphyr::from_str(text).map_err(|e| anyhow::anyhow!("parsing: {e}"))?;
        cfg.validate(require_tls)?;
        cfg.routes.sort_by(Route::precedence);
        Ok(cfg)
    }

    fn validate(&mut self, require_tls: bool) -> anyhow::Result<()> {
        if require_tls {
            anyhow::ensure!(
                self.tls.is_some(),
                "no tls block: the shipped config must name a certificate and key"
            );
        }
        anyhow::ensure!(
            self.listen.contains(':'),
            "listen must be host:port, got {:?}",
            self.listen
        );
        let l = &self.limits;
        for (name, v) in [
            ("tls_handshake_timeout_ms", l.tls_handshake_timeout_ms),
            ("header_read_timeout_ms", l.header_read_timeout_ms),
            ("h2_keepalive_interval_ms", l.h2_keepalive_interval_ms),
            ("h2_keepalive_timeout_ms", l.h2_keepalive_timeout_ms),
            ("max_connections", l.max_connections as u64),
            ("upstream_connect_timeout_ms", l.upstream_connect_timeout_ms),
            (
                "upstream_response_timeout_ms",
                l.upstream_response_timeout_ms,
            ),
            ("tunnel_idle_timeout_ms", l.tunnel_idle_timeout_ms),
            ("authz_timeout_ms", l.authz_timeout_ms),
            (
                "authz_max_response_bytes",
                l.authz_max_response_bytes as u64,
            ),
            ("tls_reload_interval_ms", l.tls_reload_interval_ms),
        ] {
            anyhow::ensure!(v > 0, "limits.{name} must be > 0");
        }
        for h in &self.strip_request_headers {
            let name = h.strip_suffix('*').unwrap_or(h);
            anyhow::ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "strip_request_headers: bad header pattern {h:?}"
            );
        }
        canonicalize_routes(&mut self.routes)
    }
}

fn canonicalize_routes(routes: &mut [Route]) -> anyhow::Result<()> {
    for r in routes {
        r.prefix = crate::path::canonicalize(&r.prefix)
            .map_err(|e| anyhow::anyhow!("route prefix {:?}: {e}", r.prefix))?;
        if let Some(h) = &r.hostname {
            let n = normalize_host(h)
                .ok_or_else(|| anyhow::anyhow!("route hostname {h:?}: must be a plain name"))?;
            r.hostname = Some(n);
        }
        anyhow::ensure!(
            r.backend
                .as_ref()
                .is_some_and(|b| !b.host.is_empty() && b.port != 0),
            "route backend must have host and port"
        );
    }
    Ok(())
}

impl Route {
    pub fn precedence(a: &Route, b: &Route) -> std::cmp::Ordering {
        b.hostname
            .is_some()
            .cmp(&a.hostname.is_some())
            .then_with(|| b.prefix.len().cmp(&a.prefix.len()))
    }

    /// `path` must already be canonical.
    pub fn matches(&self, host: Option<&str>, path: &str) -> bool {
        if let Some(want) = &self.hostname {
            match host {
                Some(got) if normalize_host(got).as_ref() == Some(want) => {}
                _ => return false,
            }
        }
        segment_prefix(path, &self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "listen: '0.0.0.0:443'\nauthz_backend: { host: a, port: 1 }\ntls: { cert: /c, key: /k }\nroutes: []\n";

    #[test]
    fn rejects_unknown_fields() {
        for bad in [
            "listen: 'x:1'\nauthz_backnd: { host: a, port: 1 }\ntls: { cert: c, key: k }\nroutes: []\n",
            "listen: 'x:1'\nauthz_backend: { host: a, port: 1 }\ntsl: { cert: c, key: k }\nroutes: []\n",
            "listen: 'x:1'\nauthz_backend: { host: a, port: 1 }\ntls: { cert: c, ky: k }\nroutes: []\n",
            "listen: 'x:1'\nauthz_backend: { host: a, prot: 1 }\ntls: { cert: c, key: k }\nroutes: []\n",
            "listen: 'x:1'\nauthz_backend: { host: a, port: 1 }\ntls: { cert: c, key: k }\nroutes: [ { prefix: /, backend: { host: a, port: 1 }, authz_: skip } ]\n",
            "listen: 'x:1'\nauthz_backend: { host: a, port: 1 }\ntls: { cert: c, key: k }\nlimits: { authz_timeout: 5 }\nroutes: []\n",
        ] {
            let e = Config::parse(bad).unwrap_err().to_string();
            assert!(e.contains("unknown field"), "{bad}\n-> {e}");
        }
    }

    #[test]
    fn requires_tls_only() {
        assert!(Config::parse(MINIMAL).is_ok());
        let no_authz = "listen: 'x:1'\ntls: { cert: c, key: k }\nroutes: []\n";
        assert!(Config::parse(no_authz).unwrap().authz_backend.is_none());
        let no_tls = "listen: 'x:1'\nauthz_backend: { host: a, port: 1 }\nroutes: []\n";
        let neither = "listen: 'x:1'\nroutes: []\n";
        for c in [no_tls, neither] {
            assert!(Config::parse(c).is_err(), "{c}");
            let e = Config::parse(&format!("{c}insecure: true\n"))
                .unwrap_err()
                .to_string();
            assert!(e.contains("unknown field"), "{c}\n-> {e}");
        }
    }

    #[test]
    fn limits_override_individually() {
        let c = Config::parse(&format!("{MINIMAL}limits: {{ authz_timeout_ms: 1234 }}\n")).unwrap();
        assert_eq!(c.limits.authz_timeout_ms, 1234);
        assert_eq!(
            c.limits.tunnel_idle_timeout_ms,
            Limits::default().tunnel_idle_timeout_ms
        );
    }

    #[test]
    fn rejects_invalid_values() {
        let with_routes = |r: &str| MINIMAL.replace("routes: []", &format!("routes: [ {r} ]"));
        let mut bad: Vec<String> = [
            "tls_handshake_timeout_ms",
            "header_read_timeout_ms",
            "h2_keepalive_interval_ms",
            "h2_keepalive_timeout_ms",
            "max_connections",
            "upstream_connect_timeout_ms",
            "upstream_response_timeout_ms",
            "tunnel_idle_timeout_ms",
            "authz_timeout_ms",
            "authz_max_response_bytes",
            "tls_reload_interval_ms",
        ]
        .iter()
        .map(|l| format!("{MINIMAL}limits: {{ {l}: 0 }}\n"))
        .collect();
        bad.extend([
            MINIMAL.replace("'0.0.0.0:443'", "'0.0.0.0'"),
            format!("{MINIMAL}strip_request_headers: ['*']\n"),
            format!("{MINIMAL}strip_request_headers: ['x-a b']\n"),
            with_routes("{ prefix: 'a', backend: { host: h, port: 1 } }"),
            with_routes("{ prefix: '/a%2fb', backend: { host: h, port: 1 } }"),
            with_routes("{ hostname: '*.example', backend: { host: h, port: 1 } }"),
            with_routes("{ hostname: '.', backend: { host: h, port: 1 } }"),
            with_routes("{ backend: { host: '', port: 1 } }"),
            with_routes("{ backend: { host: h, port: 0 } }"),
            with_routes("{ prefix: '/' }"),
        ]);
        for c in &bad {
            assert!(Config::parse(c).is_err(), "{c}");
        }
        let ok = format!("{MINIMAL}strip_request_headers: ['x-a_b*', 'X-Y']\n");
        assert_eq!(
            Config::parse(&ok).unwrap().strip_request_headers,
            ["x-a_b*", "X-Y"]
        );
    }

    #[test]
    fn routes_canonicalised_and_sorted() {
        let c = Config::parse(&MINIMAL.replace(
            "routes: []",
            "routes: [ { backend: { host: h, port: 1 } }, { prefix: '/a', backend: { host: h, port: 1 } }, \
               { hostname: 'Foo.Example.', prefix: '/a/../b//', backend: { host: h, port: 1 } } ]",
        ))
        .unwrap();
        assert_eq!(c.routes[0].hostname.as_deref(), Some("foo.example"));
        let prefixes: Vec<&str> = c.routes.iter().map(|r| r.prefix.as_str()).collect();
        assert_eq!(prefixes, ["/b/", "/a", "/"]);
    }

    #[test]
    fn representative_config_parses() {
        let yaml = r#"
listen: "0.0.0.0:443"
authz_backend: { host: "authz.example.svc.cluster.local", port: 2080 }
authz_protocol: grpc
tls:
  cert: /tls/tls.crt
  key: /tls/tls.key
routes:
  - hostname: "app.example"
    prefix: "/"
    authz: skip
    backend: { host: "127.0.0.1", port: 8444 }
  - prefix: "/"
    authz: skip
    backend: { host: "127.0.0.1", port: 8444 }
  - hostname: "console.app.example"
    prefix: "/"
    backend: { host: "127.0.0.1", port: 4466 }
  - hostname: "flux.app.example"
    prefix: "/"
    authz: skip
    backend: { host: "127.0.0.1", port: 9080 }
"#;
        let c = Config::parse(yaml).unwrap();
        assert_eq!(c.routes.len(), 4);
    }

    #[test]
    fn deployed_config_parses() {
        let manifests = include_str!("../../../deploy/edge-gateway.yaml");
        let config = serde_saphyr::from_multiple::<serde_json::Value>(manifests)
            .unwrap()
            .into_iter()
            .find_map(|doc| doc["data"]["edge-gateway.yaml"].as_str().map(str::to_owned))
            .expect("the edge-gateway ConfigMap");
        let c = Config::parse(&config).unwrap();
        assert!(c.routes.is_empty());
    }

    fn named(h: &str) -> Route {
        Route {
            hostname: normalize_host(h),
            prefix: "/".into(),
            authz: Authz::Required,
            rewrite_host: None,
            backend: Some(Backend {
                host: "b".into(),
                port: 1,
                tls: None,
            }),
            filters: Filters::default(),
            client_cert: false,
        }
    }

    /// Gateway API's `ReplacePrefixMatch` table, then a full replacement.
    #[test]
    fn path_modifier_table() {
        for (path, prefix, with, want) in [
            ("/foo/bar", "/foo", "/xyz", "/xyz/bar"),
            ("/foo/bar", "/foo", "/xyz/", "/xyz/bar"),
            ("/foo/bar", "/foo/", "/xyz", "/xyz/bar"),
            ("/foo/bar", "/foo/", "/xyz/", "/xyz/bar"),
            ("/foo", "/foo", "/xyz", "/xyz"),
            ("/foo/", "/foo", "/xyz", "/xyz/"),
            ("/foo/bar", "/foo", "", "/bar"),
            ("/foo/", "/foo", "", "/"),
            ("/foo", "/foo", "", "/"),
            ("/foo/", "/foo", "/", "/"),
            ("/foo", "/foo", "/", "/"),
            ("/", "/", "/ews", "/ews/"),
            ("/a/b", "/", "/ews", "/ews/a/b"),
        ] {
            let got = PathModifier::Prefix(with.into()).apply(path, prefix);
            assert_eq!(got, want, "{path} {prefix} -> {with}");
        }
        assert_eq!(
            PathModifier::Full("/one".into()).apply("/a/b", "/a"),
            "/one"
        );
    }

    #[test]
    fn host_match_ignores_case_port_dot() {
        let r = |h: &str| named(h);
        assert!(r("example.com").matches(Some("Example.COM:8443"), "/"));
        assert!(r("example.com").matches(Some("example.com."), "/"));
        assert!(r("EXAMPLE.com").matches(Some("example.com"), "/"));
        assert!(r("::1").matches(Some("[::1]:8443"), "/"));
        assert!(r("[::1]").matches(Some("[::1]"), "/"));
        assert!(r("2001:db8::1").matches(Some("[2001:DB8::1]:443"), "/"));
        assert!(!r("example.com").matches(Some("example.com.evil"), "/"));
        assert!(!r("example.com").matches(Some("evilexample.com"), "/"));
        assert!(!r("example.com").matches(Some("example.com@evil.test"), "/"));
        assert!(!r("example.com").matches(None, "/"));
        let mut any = named("x");
        any.hostname = None;
        assert!(any.matches(None, "/"));
    }

    #[test]
    fn normalize_host_table() {
        for (raw, want) in [
            ("Example.COM", Some("example.com")),
            ("example.com:443", Some("example.com")),
            ("example.com.:443", Some("example.com")),
            ("example.com:", Some("example.com")),
            ("[::1]", Some("[::1]")),
            ("[0:0::1]:8443", Some("[::1]")),
            ("[FE80::1%25eth0]:1", None),
            ("::1", None),
            ("localhost", Some("localhost")),
            ("127.0.0.1:80", Some("127.0.0.1")),
            ("a..", None),
            ("x:1.", None),
            ("a:b", None),
            ("*.example", None),
            (".", None),
            ("", None),
        ] {
            assert_eq!(normalize_host(raw).as_deref(), want, "{raw:?}");
        }
    }

    fn routes_yaml(routes: &[(Option<&str>, &str, u16)]) -> String {
        let mut s = "routes:\n".to_string();
        for (host, prefix, port) in routes {
            s += "  - { ";
            if let Some(h) = host {
                s += &format!("hostname: '{h}', ");
            }
            s += &format!("prefix: '{prefix}', backend: {{ host: b, port: {port} }} }}\n");
        }
        s
    }

    #[test]
    fn route_set_is_routes_alone_canonicalised() {
        let set = RouteSet::parse(&routes_yaml(&[(Some("H.test."), "/a/", 2)])).unwrap();
        assert_eq!(set.routes[0].hostname.as_deref(), Some("h.test"));
        assert_eq!(
            set.routes[0].prefix,
            crate::path::canonicalize("/a/").unwrap()
        );
        for bad in [
            "routes: [".to_string(),
            String::new(),
            format!("listen: 'x:2'\n{}", routes_yaml(&[(None, "/b", 2)])),
            format!(
                "authz_backend: {{ host: a, port: 1 }}\n{}",
                routes_yaml(&[])
            ),
            routes_yaml(&[(None, "c", 3)]),
            routes_yaml(&[(Some("*.d"), "/", 4)]),
        ] {
            assert!(RouteSet::parse(&bad).is_err(), "taken: {bad:?}");
        }
    }

    #[test]
    fn bad_config_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edge-gateway.yaml");
        std::fs::write(&path, "listen: 'x:1'\nroutes: []\n").unwrap();
        assert!(Config::load(&path).is_err(), "no tls block");
        assert!(Config::load(&dir.path().join("absent.yaml")).is_err());
    }

    use proptest::prelude::*;

    fn segment_prefix_model(path: &str, prefix: &str) -> bool {
        let segs = |s: &str| {
            s.split('/')
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let (p, q) = (segs(path), segs(prefix));
        p.len() >= q.len() && p.iter().zip(&q).all(|(a, b)| a == b)
    }

    fn canon_path() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![Just("a"), Just("ab"), Just("abc"), Just("b"), Just("Ab")],
            0..5,
        )
        .prop_flat_map(|v| (Just(v), any::<bool>()))
        .prop_map(|(v, slash)| {
            let mut s = format!("/{}", v.join("/"));
            if slash && !v.is_empty() {
                s.push('/');
            }
            s
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3000))]

        #[test]
        fn segment_prefix_matches_model(path in canon_path(), prefix in canon_path()) {
            prop_assert_eq!(segment_prefix(&path, &prefix), segment_prefix_model(&path, &prefix), "{} {}", path, prefix);
        }

        #[test]
        fn prefix_never_matches_longer_segment(p in canon_path(), extra in "[a-z]{1,3}") {
            let prefix = p.trim_end_matches('/');
            prop_assume!(!prefix.is_empty());
            let path = format!("{prefix}{extra}");
            prop_assert!(!segment_prefix(&path, prefix), "{} matched {}", prefix, path);
        }

        #[test]
        fn route_matches_only_its_host(
            host in "[a-zA-Z]{1,6}(\\.[a-z]{1,3}){0,2}",
            other in "[a-zA-Z]{1,6}(\\.[a-z]{1,3}){0,2}",
            port in prop::option::of(1u16..),
            dot in any::<bool>(),
            path in canon_path(),
        ) {
            let r = named(&host);
            let mut presented = other.clone();
            if dot { presented.push('.'); }
            if let Some(p) = port { presented.push_str(&format!(":{p}")); }
            let same = normalize_host(&other) == normalize_host(&host);
            prop_assert_eq!(r.matches(Some(&presented), &path), same, "{} vs {}", host, presented);
            prop_assert!(r.matches(Some(&host.to_ascii_uppercase()), &path));
        }

        #[test]
        fn normalized_host_is_fixed_point(raw in "[\\[\\]:.a-zA-Z0-9%*]{0,12}") {
            if let Some(h) = normalize_host(&raw) {
                let again = normalize_host(&h);
                prop_assert_eq!(again.as_ref(), Some(&h), "{:?}", raw);
            }
        }

        #[test]
        fn precedence_orders_by_specificity(
            ha in any::<bool>(), hb in any::<bool>(), pa in canon_path(), pb in canon_path()
        ) {
            let mk = |h: bool, p: &str| { let mut r = named("x.test"); if !h { r.hostname = None; } r.prefix = p.into(); r };
            let (a, b) = (mk(ha, &pa), mk(hb, &pb));
            let ord = Route::precedence(&a, &b);
            prop_assert_eq!(ord.reverse(), Route::precedence(&b, &a));
            if ha && !hb { prop_assert_eq!(ord, std::cmp::Ordering::Less); }
            if ha == hb && pa.len() > pb.len() { prop_assert_eq!(ord, std::cmp::Ordering::Less); }
        }
    }
}
