//! The kubelet rotates the projected certificate in place, so it is resolved per
//! handshake from a slot reloaded when its directory changes. `cert` and `key`
//! may name one credential bundle.

use arc_swap::ArcSwapOption;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(rustls::crypto::ring::default_provider())
}

/// `metadata` follows symlinks, so the kubelet's `..data` swap changes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Stamp(Vec<(Option<std::time::SystemTime>, u64, u64)>);

fn stamp(paths: &[&str]) -> std::io::Result<Stamp> {
    use std::os::unix::fs::MetadataExt;
    paths
        .iter()
        .map(|p| {
            let m = std::fs::metadata(p)?;
            Ok((m.modified().ok(), m.len(), m.ino()))
        })
        .collect::<std::io::Result<Vec<_>>>()
        .map(Stamp)
}

/// A key that does not match the leaf fails here, not at handshake.
fn load(cert_path: &str, key_path: &str) -> anyhow::Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| anyhow::anyhow!("reading {cert_path}: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("parsing {cert_path}: {e}"))?;
    anyhow::ensure!(!certs.is_empty(), "{cert_path} contains no certificate");
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| anyhow::anyhow!("reading private key {key_path}: {e}"))?;
    Ok(CertifiedKey::from_der(certs, key, &provider())?)
}

/// Cannot fail to construct: missing or garbage files at boot are normal.
pub struct Reloading {
    current: ArcSwapOption<CertifiedKey>,
    cert_path: String,
    key_path: String,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    loaded: Option<Stamp>,
    last_logged: Option<String>,
}

impl std::fmt::Debug for Reloading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloading")
            .field("cert", &self.cert_path)
            .finish()
    }
}

impl Reloading {
    pub fn new(cert_path: &str, key_path: &str) -> Arc<Self> {
        let me = Arc::new(Self {
            current: ArcSwapOption::empty(),
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            state: Mutex::new(State::default()),
        });
        me.check();
        me
    }

    pub fn has_certificate(&self) -> bool {
        self.current.load().is_some()
    }

    /// True when a new certificate is now served.
    pub fn check(&self) -> bool {
        let paths = [self.cert_path.as_str(), self.key_path.as_str()];
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = match stamp(&paths) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("tls files unreadable: {e}");
                if st.last_logged.as_deref() != Some(&msg) {
                    if self.has_certificate() {
                        tracing::warn!(error = %e, "tls files unreadable; keeping the current certificate");
                    } else {
                        tracing::warn!(error = %e, "no tls certificate yet; refusing handshakes");
                    }
                    st.last_logged = Some(msg);
                }
                return false;
            }
        };
        if st.loaded.as_ref() == Some(&now) {
            return false;
        }
        match load(&self.cert_path, &self.key_path) {
            Ok(key) => {
                self.current.store(Some(Arc::new(key)));
                *st = State {
                    loaded: Some(now),
                    last_logged: None,
                };
                tracing::info!(cert = %self.cert_path, "tls certificate loaded");
                true
            }
            Err(e) => {
                // `loaded` stays put so the next poll retries a half-written file.
                let msg = format!("{e} @ {now:?}");
                if st.last_logged.as_deref() != Some(&msg) {
                    if self.has_certificate() {
                        tracing::error!(error = %e, "tls reload failed; keeping the last good certificate");
                    } else {
                        tracing::error!(error = %e, "tls certificate unusable; refusing handshakes");
                    }
                    st.last_logged = Some(msg);
                }
                false
            }
        }
    }

    /// Polls every `fallback` only where inotify is unavailable.
    pub fn spawn_reloader(self: &Arc<Self>, fallback: Duration) {
        let me = self.clone();
        let changed = Arc::new(tokio::sync::Notify::new());
        let watcher = me.watch(changed.clone());
        tokio::spawn(async move {
            // Anything changed before the watch began.
            me.check();
            let _watcher = match watcher {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!(error = %e, ?fallback, "tls: no inotify; polling");
                    loop {
                        tokio::time::sleep(fallback).await;
                        me.check();
                    }
                }
            };
            loop {
                changed.notified().await;
                me.check();
            }
        });
    }

    /// The directories, not the files: the kubelet swaps a projected volume's
    /// files by renaming its `..data` symlink.
    fn watch(
        &self,
        changed: Arc<tokio::sync::Notify>,
    ) -> notify::Result<notify::RecommendedWatcher> {
        use notify::Watcher;
        let mut w = notify::recommended_watcher(move |_: notify::Result<notify::Event>| {
            changed.notify_one();
        })?;
        let mut dirs: Vec<&std::path::Path> = [&self.cert_path, &self.key_path]
            .iter()
            .map(|p| {
                std::path::Path::new(p.as_str())
                    .parent()
                    .filter(|d| !d.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."))
            })
            .collect();
        dirs.dedup();
        for d in dirs {
            w.watch(d, notify::RecursiveMode::NonRecursive)?;
        }
        Ok(w)
    }

    #[cfg(test)]
    pub fn leaf(&self) -> Vec<u8> {
        self.current.load().as_ref().expect("a certificate").cert[0]
            .as_ref()
            .to_vec()
    }
}

impl ResolvesServerCert for Reloading {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.load_full()
    }
}

/// The served certificate, as the client's to a TLS backend.
impl rustls::client::ResolvesClientCert for Reloading {
    fn resolve(
        &self,
        _root_hints: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.current
            .load_full()
            .filter(|k| k.key.choose_scheme(schemes).is_some())
    }

    fn has_certs(&self) -> bool {
        self.has_certificate()
    }
}

/// Every certificate in `pem` as a trust anchor; none, or any unusable, fails.
pub fn roots(pem: &str) -> Result<rustls::RootCertStore, String> {
    let mut store = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let c = c.map_err(|e| format!("not PEM: {e}"))?;
        store
            .add(c)
            .map_err(|e| format!("not a CA certificate: {e}"))?;
    }
    if store.is_empty() {
        return Err("no certificate".into());
    }
    Ok(store)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Every handshake must present a certificate that verifies.
    AllowValidOnly,
    /// Asked for only on `names`; one that is presented must still verify.
    AllowInsecureFallback,
}

/// Client-certificate validation as the controller derives it from the Gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontend {
    pub mode: Mode,
    /// Empty when no CA reference resolved.
    pub ca_pem: String,
    pub names: std::collections::BTreeSet<String>,
}

#[derive(Default)]
struct Active {
    spec: Option<Frontend>,
    /// `None` with a spec: no usable CA.
    verifying: Option<Arc<rustls::ServerConfig>>,
    verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    /// Moves when the mode or CAs do; a handshake under another one is
    /// verified again before its identity is used.
    generation: u64,
}

impl Active {
    /// The config for this SNI, and whether it asks for a certificate. `None`
    /// refuses the handshake.
    fn choose(
        &self,
        plain: &Arc<rustls::ServerConfig>,
        sni: Option<&str>,
    ) -> Option<(Arc<rustls::ServerConfig>, bool)> {
        let Some(spec) = &self.spec else {
            return Some((plain.clone(), false));
        };
        match spec.mode {
            Mode::AllowValidOnly => self.verifying.clone().map(|c| (c, true)),
            Mode::AllowInsecureFallback => match &self.verifying {
                Some(c) if sni.is_some_and(|s| spec.names.contains(s)) => Some((c.clone(), true)),
                _ => Some((plain.clone(), false)),
            },
        }
    }

    fn requests(&self, plain: &Arc<rustls::ServerConfig>, host: &str) -> bool {
        matches!(self.choose(plain, Some(host)), Some((_, true)))
    }
}

/// What the handshake established.
#[derive(Debug, Clone, Default)]
pub struct Handshake {
    pub sni: Option<String>,
    pub requested: bool,
    /// The verified client certificate as `X-Forwarded-Client-Cert`; read it
    /// through `Acceptor::verified`, which checks it is still trusted.
    pub client_cert: Option<Arc<str>>,
    chain: Arc<[CertificateDer<'static>]>,
    generation: u64,
}

/// Picks the server config per handshake from the client's SNI, so only the
/// names that use a client certificate make a browser offer one.
#[derive(Clone)]
pub struct Acceptor {
    resolver: Arc<Reloading>,
    plain: Arc<rustls::ServerConfig>,
    active: Arc<arc_swap::ArcSwap<Active>>,
}

fn server_config(
    resolver: Arc<Reloading>,
    verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> Arc<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions");
    let mut cfg = match verifier {
        Some(v) => builder.with_client_cert_verifier(v),
        None => builder.with_no_client_auth(),
    }
    .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

pub fn acceptor(resolver: Arc<Reloading>) -> Acceptor {
    Acceptor {
        plain: server_config(resolver.clone(), None),
        resolver,
        active: Arc::default(),
    }
}

impl Acceptor {
    pub fn identity(&self) -> Arc<Reloading> {
        self.resolver.clone()
    }

    /// False when `spec` names no usable CA, which the result then refuses or
    /// stops asking for.
    pub fn set_frontend(&self, spec: Option<Frontend>) -> bool {
        let old = self.active.load();
        let trust = |s: &Option<Frontend>| s.as_ref().map(|f| (f.mode, f.ca_pem.clone()));
        let (verifier, verifying, generation) = if trust(&old.spec) == trust(&spec) {
            (old.verifier.clone(), old.verifying.clone(), old.generation)
        } else {
            let verifier = spec.as_ref().and_then(|s| {
                let roots = Arc::new(roots(&s.ca_pem).ok()?);
                let b =
                    rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider());
                let b = match s.mode {
                    Mode::AllowValidOnly => b,
                    Mode::AllowInsecureFallback => b.allow_unauthenticated(),
                };
                b.build().ok()
            });
            let verifying = verifier
                .clone()
                .map(|v| server_config(self.resolver.clone(), Some(v)));
            (verifier, verifying, old.generation + 1)
        };
        let usable = spec.is_none() || verifying.is_some();
        self.active.store(Arc::new(Active {
            spec,
            verifying,
            verifier,
            generation,
        }));
        usable
    }

    /// Whether a connection whose SNI is `host` would be asked for a certificate.
    pub fn requests_certificate(&self, host: &str) -> bool {
        self.active.load().requests(&self.plain, host)
    }

    /// The connection's verified certificate, if the CAs it was verified
    /// against, or the current ones, still trust it.
    pub fn verified(&self, h: &Handshake) -> Option<Arc<str>> {
        let cert = h.client_cert.clone()?;
        let active = self.active.load();
        active.spec.as_ref()?;
        if active.generation == h.generation {
            return Some(cert);
        }
        let (leaf, intermediates) = h.chain.split_first()?;
        active
            .verifier
            .as_ref()?
            .verify_client_cert(leaf, intermediates, rustls_pki_types::UnixTime::now())
            .ok()
            .map(|_| cert)
    }

    pub async fn accept(
        &self,
        stream: tokio::net::TcpStream,
    ) -> std::io::Result<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        Handshake,
    )> {
        let start =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await?;
        let sni = start
            .client_hello()
            .server_name()
            .and_then(crate::config::normalize_host);
        let active = self.active.load();
        let Some((cfg, requested)) = active.choose(&self.plain, sni.as_deref()) else {
            return Err(std::io::Error::other("no usable client CA"));
        };
        let generation = active.generation;
        drop(active);
        let tls = start.into_stream(cfg).await?;
        let chain: Arc<[CertificateDer<'static>]> = tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
            .unwrap_or_default();
        let client_cert = chain
            .first()
            .and_then(|c| crate::xfcc::value(c.as_ref()))
            .map(Arc::from);
        Ok((
            tls,
            Handshake {
                sni,
                requested,
                client_cert,
                chain,
                generation,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Authz;
    use crate::testutil::*;

    fn tls_cfg(cert: &str, key: &str, extra: &str) -> crate::config::Config {
        crate::config::Config::parse_plaintext(&format!(
            "listen: '127.0.0.1:0'\ntls: {{ cert: {cert}, key: {key} }}\n{extra}routes: []\n"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn starts_without_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let c = issue();
        let cert = dir.path().join("tls.crt").to_string_lossy().into_owned();
        let key = dir.path().join("tls.key").to_string_lossy().into_owned();
        let other = issue();

        let backend = recorder("b").await;
        let resolver = Reloading::new(&cert, &key);
        assert!(!resolver.has_certificate());
        let gw = start(
            tls_cfg(&cert, &key, ""),
            vec![route("/", Authz::Skip, backend.addr)],
            Some(acceptor(resolver.clone())),
        )
        .await;
        assert!(
            tls_connect(gw.addr, &["http/1.1"]).await.is_err(),
            "handshake succeeded with no certificate"
        );

        std::fs::write(&cert, "not a certificate").unwrap();
        std::fs::write(&key, "not a key").unwrap();
        assert!(!resolver.check());
        assert!(tls_connect(gw.addr, &["http/1.1"]).await.is_err());

        std::fs::remove_file(&cert).unwrap();
        std::fs::create_dir(&cert).unwrap();
        assert!(!resolver.check());
        std::fs::remove_dir(&cert).unwrap();

        std::fs::write(&cert, &c.cert_pem).unwrap();
        std::fs::write(&key, &other.key_pem).unwrap();
        assert!(!resolver.check());
        assert!(!resolver.has_certificate());

        install(dir.path(), &c);
        assert!(resolver.check());
        let (code, body, leaf) = tls_get(gw.addr, "/").await;
        assert_eq!((code, body.trim()), (200, "b"));
        assert_eq!(leaf, c.der);
    }

    /// Reloaded on change: the fallback poll is an hour.
    const NEVER: Duration = Duration::from_secs(3600);

    async fn eventually(what: &str, f: impl Fn() -> bool) {
        for _ in 0..100 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{what} not within 2 s");
    }

    #[tokio::test]
    async fn first_certificate_picked_up_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls.crt").to_string_lossy().into_owned();
        let key = dir.path().join("tls.key").to_string_lossy().into_owned();
        let resolver = Reloading::new(&cert, &key);
        resolver.spawn_reloader(NEVER);
        tokio::time::sleep(Duration::from_millis(100)).await;
        install(dir.path(), &issue());
        eventually("the first certificate", || resolver.has_certificate()).await;
    }

    #[tokio::test]
    async fn change_before_the_watch_is_not_missed() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls.crt").to_string_lossy().into_owned();
        let key = dir.path().join("tls.key").to_string_lossy().into_owned();
        let resolver = Reloading::new(&cert, &key);
        install(dir.path(), &issue());
        resolver.spawn_reloader(NEVER);
        eventually("the certificate", || resolver.has_certificate()).await;
    }

    #[tokio::test]
    async fn polls_without_inotify() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone");
        let cert = missing.join("tls.crt").to_string_lossy().into_owned();
        let key = missing.join("tls.key").to_string_lossy().into_owned();
        let resolver = Reloading::new(&cert, &key);
        resolver.spawn_reloader(Duration::from_millis(50));
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::create_dir(&missing).unwrap();
        install(&missing, &issue());
        eventually("the polled certificate", || resolver.has_certificate()).await;
    }

    #[tokio::test]
    async fn rotation_served_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (issue(), issue());
        assert_ne!(first.der, second.der);
        let (cert, key) = install(dir.path(), &first);

        let resolver = Reloading::new(&cert, &key);
        resolver.spawn_reloader(NEVER);
        let backend = recorder("b").await;
        let gw = start(
            tls_cfg(&cert, &key, ""),
            vec![route("/", Authz::Skip, backend.addr)],
            Some(acceptor(resolver.clone())),
        )
        .await;

        let (code, body, leaf) = tls_get(gw.addr, "/").await;
        assert_eq!((code, body.trim()), (200, "b"));
        assert_eq!(leaf, first.der, "serving the initial certificate");

        install(dir.path(), &second);
        let mut served = leaf;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            served = tls_get(gw.addr, "/").await.2;
            if served == second.der {
                break;
            }
        }
        assert_eq!(
            served, second.der,
            "still serving the old certificate after rotation"
        );
    }

    #[tokio::test]
    async fn bad_reload_keeps_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let (good, next) = (issue(), issue());
        let (cert, key) = install(dir.path(), &good);
        let r = Reloading::new(&cert, &key);
        assert!(!r.check(), "nothing changed");

        std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\ngarbage").unwrap();
        assert!(!r.check());
        assert_eq!(r.leaf(), good.der);
        std::fs::write(&cert, &next.cert_pem).unwrap();
        std::fs::write(&key, &good.key_pem).unwrap();
        assert!(!r.check());
        assert_eq!(r.leaf(), good.der);
        std::fs::remove_file(&cert).unwrap();
        assert!(!r.check());
        assert_eq!(r.leaf(), good.der);
        install(dir.path(), &next);
        assert!(r.check());
        assert_eq!(r.leaf(), next.der);
        assert!(!r.check(), "and only once");
    }

    #[test]
    fn symlink_swap_noticed() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (a, b) = (issue(), issue());
        let v1 = root.join("..v1");
        let v2 = root.join("..v2");
        for (d, c) in [(&v1, &a), (&v2, &b)] {
            std::fs::create_dir(d).unwrap();
            std::fs::write(d.join("tls.crt"), &c.cert_pem).unwrap();
            std::fs::write(d.join("tls.key"), &c.key_pem).unwrap();
        }
        symlink("..v1", root.join("..data")).unwrap();
        symlink("..data/tls.crt", root.join("tls.crt")).unwrap();
        symlink("..data/tls.key", root.join("tls.key")).unwrap();

        let r = Reloading::new(
            root.join("tls.crt").to_str().unwrap(),
            root.join("tls.key").to_str().unwrap(),
        );
        assert_eq!(r.leaf(), a.der);
        assert!(!r.check());

        symlink("..v2", root.join("..data_tmp")).unwrap();
        std::fs::rename(root.join("..data_tmp"), root.join("..data")).unwrap();
        assert!(r.check(), "the swap was not noticed");
        assert_eq!(r.leaf(), b.der);
    }

    #[test]
    fn credential_bundle_rotates() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (a, b) = (issue(), issue());
        for (v, c) in [("..v1", &a), ("..v2", &b)] {
            std::fs::create_dir(root.join(v)).unwrap();
            let bundle = format!("{}{}", c.key_pem, c.cert_pem);
            std::fs::write(root.join(v).join("credentialbundle.pem"), bundle).unwrap();
        }
        symlink("..v1", root.join("..data")).unwrap();
        symlink(
            "..data/credentialbundle.pem",
            root.join("credentialbundle.pem"),
        )
        .unwrap();

        let bundle = root.join("credentialbundle.pem");
        let r = Reloading::new(bundle.to_str().unwrap(), bundle.to_str().unwrap());
        assert_eq!(r.leaf(), a.der);

        symlink("..v2", root.join("..data_tmp")).unwrap();
        std::fs::rename(root.join("..data_tmp"), root.join("..data")).unwrap();
        assert!(r.check());
        assert_eq!(r.leaf(), b.der);
    }

    #[tokio::test]
    async fn tls_forwards_https_and_serves_h2() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = install(dir.path(), &issue());
        let authz = fake_authz().await;
        let backend = recorder("b").await;
        let cfg = crate::config::Config::parse_plaintext(&format!(
            "listen: '127.0.0.1:0'\ntls: {{ cert: {cert}, key: {key} }}\nauthz_backend: {{ host: '{}', port: {} }}\nroutes: []\n",
            authz.addr.ip(),
            authz.addr.port()
        ))
        .unwrap();
        let gw = start(
            cfg,
            vec![route("/", Authz::Required, backend.addr)],
            Some(acceptor(Reloading::new(&cert, &key))),
        )
        .await;

        let (code, _, _) = tls_get(gw.addr, "/x?y=1").await;
        assert_eq!(code, 200);
        let seen = backend.last();
        assert_eq!(seen.header("x-forwarded-proto"), Some("https"));
        assert!(seen.header("forwarded").unwrap().contains("proto=https"));
        let http = authz
            .calls()
            .pop()
            .unwrap()
            .attributes
            .unwrap()
            .request
            .unwrap()
            .http
            .unwrap();
        assert_eq!(http.scheme, "https");
        assert_eq!(http.path, "/x?y=1");

        let (s, _, alpn) = tls_connect(gw.addr, &["h2", "http/1.1"]).await.unwrap();
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]));
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(s),
        )
        .await
        .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .uri("https://localhost/h2?z=1")
            .body(crate::proxy::Body::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(backend.last().target, "/h2?z=1");
        assert_eq!(backend.last().header("x-forwarded-proto"), Some("https"));
        let http = authz
            .calls()
            .pop()
            .unwrap()
            .attributes
            .unwrap()
            .request
            .unwrap()
            .http
            .unwrap();
        assert_eq!(http.scheme, "https");
        assert_eq!(http.protocol, "HTTP/2.0");

        let (code, _) = get(gw.addr, "/", "").await;
        assert_eq!(code, 0);
    }

    struct Front {
        gw: RunningGateway,
        tls: Acceptor,
        marked: Recorder,
        open: Recorder,
        _dir: tempfile::TempDir,
    }

    /// `elf.test` wants the client's certificate; `ui.test` does not.
    async fn front() -> Front {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = install(dir.path(), &issue());
        let (marked, open) = (recorder("marked").await, recorder("open").await);
        let mut elf = host_route("elf.test", "/", Authz::Skip, marked.addr);
        elf.client_cert = true;
        let tls = acceptor(Reloading::new(&cert, &key));
        let gw = start(
            tls_cfg(&cert, &key, ""),
            vec![elf, host_route("ui.test", "/", Authz::Skip, open.addr)],
            Some(tls.clone()),
        )
        .await;
        Front {
            gw,
            tls,
            marked,
            open,
            _dir: dir,
        }
    }

    fn validation(mode: Mode, ca: &ClientCa) -> Option<Frontend> {
        Some(Frontend {
            mode,
            ca_pem: ca.pem.clone(),
            names: ["elf.test".to_string()].into(),
        })
    }

    #[tokio::test]
    async fn no_validation_asks_nobody() {
        let f = front().await;
        let ca = ClientCa::new("operators");
        for sni in ["elf.test", "ui.test"] {
            let got = tls_get_as(f.gw.addr, sni, sni, Some(ca.issue("op")), "").await;
            assert_eq!(got.unwrap(), (200, false), "{sni}");
        }
        assert!(f.tls.set_frontend(None));
        assert!(!f.tls.requests_certificate("elf.test"));
    }

    #[tokio::test]
    async fn insecure_fallback_asks_only_marked_names() {
        let f = front().await;
        let (ca, other) = (ClientCa::new("operators"), ClientCa::new("strangers"));
        assert!(
            f.tls
                .set_frontend(validation(Mode::AllowInsecureFallback, &ca))
        );
        assert!(f.tls.requests_certificate("elf.test"));
        assert!(!f.tls.requests_certificate("ui.test"));

        let ui = tls_get_as(f.gw.addr, "ui.test", "ui.test", Some(ca.issue("op")), "").await;
        assert_eq!(ui.unwrap(), (200, false), "an unmarked name is never asked");
        let none = tls_get_as(f.gw.addr, "elf.test", "elf.test", None, "").await;
        assert_eq!(none.unwrap(), (200, true), "asked, and served without one");
        let good = tls_get_as(f.gw.addr, "ELF.test.", "elf.test", Some(ca.issue("op")), "").await;
        assert_eq!(good.unwrap(), (200, true));
        let bad = tls_get_as(
            f.gw.addr,
            "elf.test",
            "elf.test",
            Some(other.issue("op")),
            "",
        )
        .await;
        assert!(
            !matches!(bad, Ok((200, _))),
            "a certificate that does not verify was accepted: {bad:?}"
        );
        assert_eq!(f.marked.count(), 2);
        assert_eq!(f.open.count(), 1);
    }

    #[tokio::test]
    async fn valid_only_asks_everyone_and_refuses_without() {
        let f = front().await;
        let (ca, other) = (ClientCa::new("operators"), ClientCa::new("strangers"));
        assert!(f.tls.set_frontend(validation(Mode::AllowValidOnly, &ca)));
        assert!(f.tls.requests_certificate("ui.test"));
        for sni in ["elf.test", "ui.test"] {
            let good = tls_get_as(f.gw.addr, sni, sni, Some(ca.issue("op")), "").await;
            assert_eq!(good.unwrap(), (200, true), "{sni}");
            for client in [None, Some(other.issue("op"))] {
                let refused = tls_get_as(f.gw.addr, sni, sni, client, "").await;
                assert!(!matches!(refused, Ok((200, _))), "{sni}: {refused:?}");
            }
        }
        assert_eq!(f.marked.count() + f.open.count(), 2);
    }

    #[tokio::test]
    async fn unusable_ca_fails_closed_only_where_required() {
        let f = front().await;
        let broken = |mode| {
            Some(Frontend {
                mode,
                ca_pem: String::new(),
                names: ["elf.test".to_string()].into(),
            })
        };
        assert!(!f.tls.set_frontend(broken(Mode::AllowInsecureFallback)));
        let got = tls_get_as(f.gw.addr, "elf.test", "elf.test", None, "").await;
        assert_eq!(got.unwrap(), (200, false), "fallback: nothing to ask with");
        assert!(!f.tls.set_frontend(broken(Mode::AllowValidOnly)));
        let got = tls_get_as(f.gw.addr, "ui.test", "ui.test", None, "").await;
        assert!(got.is_err() || got.unwrap().0 == 0, "required, yet served");
    }

    /// Envoy's header reaches the route that asked, whatever the client sent;
    /// any other route, or a request with no certificate, gets none.
    #[tokio::test]
    async fn verified_certificate_forwarded_as_xfcc() {
        let f = front().await;
        let ca = ClientCa::new("operators");
        f.tls
            .set_frontend(validation(Mode::AllowInsecureFallback, &ca));
        let forged = "X-Forwarded-Client-Cert: Hash=00;Subject=\"CN=admin\"\r\n";
        let op = ca.issue("DOE.JOHN.1234");

        let got = tls_get_as(f.gw.addr, "elf.test", "elf.test", Some(op.clone()), forged).await;
        assert_eq!(got.unwrap().0, 200);
        let seen = f.marked.last();
        let xfcc = seen.headers_named("x-forwarded-client-cert");
        assert_eq!(xfcc, [crate::xfcc::value(&op.der).unwrap().as_str()]);
        assert!(
            xfcc[0].contains(";Subject=\"CN=DOE.JOHN.1234\""),
            "{}",
            xfcc[0]
        );

        tls_get_as(f.gw.addr, "elf.test", "elf.test", None, forged)
            .await
            .unwrap();
        assert!(f.marked.last().header("x-forwarded-client-cert").is_none());
        tls_get_as(f.gw.addr, "ui.test", "ui.test", None, forged)
            .await
            .unwrap();
        assert!(f.open.last().header("x-forwarded-client-cert").is_none());
        tls_get_as(f.gw.addr, "elf.test", "ui.test", Some(op), forged)
            .await
            .unwrap();
        assert!(
            f.open.last().header("x-forwarded-client-cert").is_none(),
            "an unmarked route got the identity"
        );
    }

    /// A connection opened for `ui.test` was never asked for a certificate, so a
    /// browser that reuses it for `elf.test` is sent to open its own.
    #[tokio::test]
    async fn coalesced_request_is_misdirected() {
        let f = front().await;
        let ca = ClientCa::new("operators");
        f.tls
            .set_frontend(validation(Mode::AllowInsecureFallback, &ca));
        let got = tls_get_as(f.gw.addr, "ui.test", "elf.test", None, "").await;
        assert_eq!(got.unwrap(), (421, false));
        assert_eq!(f.marked.count(), 0);
        f.tls.set_frontend(None);
        let got = tls_get_as(f.gw.addr, "ui.test", "elf.test", None, "").await;
        assert_eq!(got.unwrap().0, 200, "nothing would ask: no 421 loop");
    }

    /// A client sending no SNI was never asked, and no connection would be:
    /// it is served without an identity, not sent round a 421 loop.
    #[tokio::test]
    async fn no_sni_gets_the_fallback() {
        let f = front().await;
        let ca = ClientCa::new("operators");
        f.tls
            .set_frontend(validation(Mode::AllowInsecureFallback, &ca));
        let forged = "X-Forwarded-Client-Cert: Hash=00\r\n";
        let got = tls_get_as(f.gw.addr, "127.0.0.1", "elf.test", None, forged).await;
        assert_eq!(got.unwrap(), (200, false));
        assert!(f.marked.last().header("x-forwarded-client-cert").is_none());
    }

    async fn keep_alive(
        f: &Front,
        client: ClientCert,
    ) -> hyper::client::conn::http1::SendRequest<crate::proxy::Body> {
        let (s, asked) = tls_connect_as(f.gw.addr, "elf.test", Some(client))
            .await
            .unwrap();
        assert!(asked);
        let (sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s))
            .await
            .unwrap();
        tokio::spawn(conn);
        sender
    }

    async fn send(sender: &mut hyper::client::conn::http1::SendRequest<crate::proxy::Body>) -> u16 {
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "elf.test")
            .body(crate::proxy::Body::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let code = resp.status().as_u16();
        http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap();
        code
    }

    /// The identity of an open connection follows the CAs now trusted: a
    /// removed CA or validation stops it on the next request.
    #[tokio::test]
    async fn identity_rechecked_per_request() {
        let f = front().await;
        let (ca, other) = (ClientCa::new("operators"), ClientCa::new("others"));
        let xfcc = || f.marked.last().header("x-forwarded-client-cert").is_some();
        f.tls
            .set_frontend(validation(Mode::AllowInsecureFallback, &ca));
        let mut c = keep_alive(&f, ca.issue("op")).await;
        assert_eq!(send(&mut c).await, 200);
        assert!(xfcc());

        let both = Frontend {
            mode: Mode::AllowInsecureFallback,
            ca_pem: format!("{}{}", ca.pem, other.pem),
            names: ["elf.test".to_string(), "more.test".to_string()].into(),
        };
        f.tls.set_frontend(Some(both));
        assert_eq!(send(&mut c).await, 200);
        assert!(xfcc(), "its CA is still trusted");

        f.tls
            .set_frontend(validation(Mode::AllowInsecureFallback, &other));
        assert_eq!(send(&mut c).await, 200);
        assert!(!xfcc(), "its CA was removed");

        let mut c = keep_alive(&f, other.issue("op")).await;
        assert_eq!(send(&mut c).await, 200);
        assert!(xfcc());
        f.tls.set_frontend(None);
        assert_eq!(send(&mut c).await, 200);
        assert!(!xfcc(), "validation was removed");
    }

    #[test]
    fn roots_need_every_certificate_usable() {
        let ca = ClientCa::new("a");
        assert_eq!(roots(&ca.pem).unwrap().len(), 1);
        let two = format!("{}{}", ca.pem, ClientCa::new("b").pem);
        assert_eq!(roots(&two).unwrap().len(), 2);
        assert!(roots("").is_err());
        assert!(roots("no pem here").is_err());
        let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(roots(&format!("{}{junk}", ca.pem)).is_err());
    }
}
