//! TLS to a backend a BackendTLSPolicy names: its CA and hostname verify the
//! server, and the gateway's identity is the client's.

use super::Body;
use crate::config::UpstreamTls;
use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub type TlsClient = Client<Connector, Body>;

/// A policy's dialer: its own pool, so a changed CA or name never reuses a
/// connection verified under the old one.
pub struct Dialer {
    pub connector: Connector,
    pub pool: TlsClient,
}

/// Builds dialers; the identity is what the gateway presents as the client.
#[derive(Clone)]
pub struct Dialers {
    pub identity: Option<Arc<dyn rustls::client::ResolvesClientCert>>,
    pub connect_timeout: Duration,
}

impl Dialers {
    /// `None` fails every request closed: no usable CA or hostname.
    pub fn build(&self, t: &UpstreamTls) -> Option<Arc<Dialer>> {
        let connector = self.connector(t);
        if connector.is_none() {
            tracing::warn!(hostname = %t.hostname, "backend TLS unusable; refusing its requests");
        }
        let connector = connector?;
        Some(Arc::new(Dialer {
            pool: Client::builder(TokioExecutor::new()).build(connector.clone()),
            connector,
        }))
    }

    fn connector(&self, t: &UpstreamTls) -> Option<Connector> {
        let roots = crate::tls::roots(&t.ca_pem).ok()?;
        let name = ServerName::try_from(t.hostname.clone()).ok()?;
        let builder = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots);
        let mut cfg = match &self.identity {
            Some(id) => builder.with_client_cert_resolver(id.clone()),
            None => builder.with_no_client_auth(),
        };
        // Upstream is HTTP/1.1.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(Connector {
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            name,
            timeout: self.connect_timeout,
        })
    }
}

#[derive(Clone)]
pub struct Connector {
    tls: tokio_rustls::TlsConnector,
    name: ServerName<'static>,
    timeout: Duration,
}

impl Connector {
    pub async fn dial(&self, addr: &str) -> std::io::Result<TlsStream<TcpStream>> {
        let attempt = async {
            let tcp = TcpStream::connect(addr).await?;
            let _ = tcp.set_nodelay(true);
            self.tls.connect(self.name.clone(), tcp).await
        };
        tokio::time::timeout(self.timeout, attempt)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))?
    }
}

impl tower_service::Service<Uri> for Connector {
    type Response = TlsIo;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<TlsIo>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let me = self.clone();
        Box::pin(async move {
            let host = uri.host().unwrap_or_default();
            let port = uri.port_u16().unwrap_or(443);
            let s = me.dial(&format!("{host}:{port}")).await?;
            Ok(TlsIo(TokioIo::new(s)))
        })
    }
}

pub struct TlsIo(TokioIo<TlsStream<TcpStream>>);

impl Connection for TlsIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{Authz, UpstreamTls};
    use crate::testutil::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Setup {
        gw: RunningGateway,
        backend: TlsBackend,
        pod_leaf: Vec<u8>,
        backend_ca: ClientCa,
        dialers: super::Dialers,
        _dir: tempfile::TempDir,
    }

    /// The gateway's pod certificate and the backend's come from one node CA,
    /// which the backend requires its clients to hold.
    async fn setup() -> Setup {
        let node = ClientCa::new("node");
        let backend_ca = ClientCa::new("backend");
        let (pod, _) = node.issue_for("gw.example");
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = install(dir.path(), &pod);
        let backend = tls_backend(&backend_ca, "jel.apps.svc", &node).await;
        let cfg = crate::config::Config::parse_plaintext(&format!(
            "listen: '127.0.0.1:0'\ntls: {{ cert: {cert}, key: {key} }}\nroutes: []\n"
        ))
        .unwrap();
        let pod_cert = crate::tls::Reloading::new(&cert, &key);
        let tls = crate::tls::acceptor(pod_cert.clone());
        let gw = start(cfg, vec![], Some(tls)).await;
        Setup {
            gw,
            backend,
            pod_leaf: pod.der,
            backend_ca,
            dialers: super::Dialers {
                identity: Some(pod_cert),
                connect_timeout: std::time::Duration::from_secs(2),
            },
            _dir: dir,
        }
    }

    fn to(s: &Setup, hostname: &str, ca_pem: &str) -> crate::config::Route {
        let mut r = route("/", Authz::Skip, s.backend.addr);
        let mut t = UpstreamTls {
            hostname: hostname.into(),
            ca_pem: ca_pem.into(),
            ..UpstreamTls::default()
        };
        t.dialer = s.dialers.build(&t);
        r.backend.as_mut().unwrap().tls = Some(t);
        r
    }

    #[tokio::test]
    async fn dialled_over_tls_with_the_pod_certificate() {
        let s = setup().await;
        s.gw.routes.store(std::sync::Arc::new(vec![to(
            &s,
            "jel.apps.svc",
            &s.backend_ca.pem,
        )]));
        for _ in 0..2 {
            let (code, body, _) = tls_get(s.gw.addr, "/x?q=1").await;
            assert_eq!((code, body.trim()), (200, "tls"));
        }
        assert_eq!(s.backend.seen.last().target, "/x");
        let peers = s.backend.peers.lock().unwrap().clone();
        assert_eq!(peers, [s.pod_leaf.clone(), s.pod_leaf.clone()]);
    }

    #[tokio::test]
    async fn wrong_name_or_ca_fails_closed() {
        let s = setup().await;
        let stranger = ClientCa::new("stranger");
        for (what, r) in [
            ("another name", to(&s, "other.apps.svc", &s.backend_ca.pem)),
            ("another CA", to(&s, "jel.apps.svc", &stranger.pem)),
            ("no usable CA", to(&s, "jel.apps.svc", "")),
            ("not a name", to(&s, "", &s.backend_ca.pem)),
        ] {
            s.gw.routes.store(std::sync::Arc::new(vec![r]));
            let (code, ..) = tls_get(s.gw.addr, "/").await;
            assert_eq!(code, 502, "{what}");
            let upgrade = "Connection: Upgrade\r\nUpgrade: echo\r\n";
            let mut c = tls_connect(s.gw.addr, &["http/1.1"]).await.unwrap().0;
            c.write_all(format!("GET / HTTP/1.1\r\nHost: localhost\r\n{upgrade}\r\n").as_bytes())
                .await
                .unwrap();
            let mut buf = vec![0u8; 512];
            let n = c.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 502"),
                "{what}: upgrade"
            );
        }
        assert_eq!(s.backend.seen.count(), 0, "a request reached the backend");
    }

    #[tokio::test]
    async fn upgrade_tunnels_over_tls() {
        let s = setup().await;
        s.gw.routes.store(std::sync::Arc::new(vec![to(
            &s,
            "jel.apps.svc",
            &s.backend_ca.pem,
        )]));
        let mut c = tls_connect(s.gw.addr, &["http/1.1"]).await.unwrap().0;
        c.write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(c.read(&mut byte).await.unwrap(), 1);
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        c.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        c.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        assert_eq!(s.backend.peers.lock().unwrap()[0], s.pod_leaf);
    }
}
