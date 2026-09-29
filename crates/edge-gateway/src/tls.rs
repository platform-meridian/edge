//! The kubelet rotates the projected certificate in place, so it is resolved per
//! handshake from a polled slot. `cert` and `key` may name one credential bundle.

use arc_swap::ArcSwapOption;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_rustls::TlsAcceptor;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
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

const NO_CERT_POLL: Duration = Duration::from_secs(1);

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

    pub fn spawn_reloader(self: &Arc<Self>, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let wait = if me.has_certificate() {
                    every
                } else {
                    every.min(NO_CERT_POLL)
                };
                tokio::time::sleep(wait).await;
                me.check();
            }
        });
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

pub fn acceptor(resolver: Arc<Reloading>) -> TlsAcceptor {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
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

    #[tokio::test]
    async fn polls_fast_without_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls.crt").to_string_lossy().into_owned();
        let key = dir.path().join("tls.key").to_string_lossy().into_owned();
        let resolver = Reloading::new(&cert, &key);
        resolver.spawn_reloader(Duration::from_secs(3600));
        install(dir.path(), &issue());
        let mut waited = 0;
        while !resolver.has_certificate() && waited < 40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            waited += 1;
        }
        assert!(
            resolver.has_certificate(),
            "no certificate picked up within 4 s"
        );
    }

    #[tokio::test]
    async fn rotation_served_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (issue(), issue());
        assert_ne!(first.der, second.der);
        let (cert, key) = install(dir.path(), &first);

        let resolver = Reloading::new(&cert, &key);
        resolver.spawn_reloader(Duration::from_millis(40));
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
}
