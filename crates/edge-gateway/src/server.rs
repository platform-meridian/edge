use crate::config::Limits;
use crate::proxy::{ConnInfo, Gateway};
use crate::tls::Acceptor as TlsAcceptor;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Lets a test make `accept` fail the way EMFILE does.
pub trait Accept {
    fn accept(&self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send;
}

impl Accept for TcpListener {
    async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
    }
}

const BACKOFF_MIN: Duration = Duration::from_millis(5);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Serve until `shutdown` resolves, without draining: clients retry, and a
/// long-lived websocket would turn a prompt stop into a wait for the kill.
pub async fn serve<L: Accept>(
    listener: L,
    gw: Gateway,
    acceptor: Option<TlsAcceptor>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let limits = gw.cfg.limits.clone();
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let mut backoff = BACKOFF_MIN;
    loop {
        // Slot before accept: at the cap the kernel backlog holds the excess, not our fds.
        let permit = tokio::select! {
            p = slots.clone().acquire_owned() => p.expect("semaphore is never closed"),
            _ = &mut shutdown => return,
        };
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = &mut shutdown => return,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => {
                backoff = BACKOFF_MIN;
                pair
            }
            Err(e) => {
                // EMFILE/ENFILE persist until something closes: back off, never exit.
                tracing::warn!(error = %e, retry_in = ?backoff, "accept failed");
                drop(permit);
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = &mut shutdown => return,
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        let gw = gw.clone();
        let acceptor = acceptor.clone();
        let limits = limits.clone();
        tokio::spawn(async move {
            connection(stream, peer, gw, acceptor, limits, permit).await;
        });
    }
}

async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    gw: Gateway,
    acceptor: Option<TlsAcceptor>,
    limits: Limits,
    _slot: OwnedSemaphorePermit,
) {
    let _ = stream.set_nodelay(true);
    let service = |conn: ConnInfo| {
        let gw = gw.clone();
        service_fn(move |req| {
            let (gw, conn) = (gw.clone(), conn.clone());
            async move { gw.handle(req, &conn).await }
        })
    };
    let header_read = Duration::from_millis(limits.header_read_timeout_ms);
    let ka_interval = Duration::from_millis(limits.h2_keepalive_interval_ms);
    let ka_timeout = Duration::from_millis(limits.h2_keepalive_timeout_ms);

    let served = match acceptor {
        Some(a) => {
            let handshake = Duration::from_millis(limits.tls_handshake_timeout_ms);
            let (tls, shook) = match tokio::time::timeout(handshake, a.accept(stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, %peer, "tls handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "tls handshake timed out");
                    return;
                }
            };
            let svc = service(ConnInfo::tls(peer, shook));
            // ALPN, not `auto`'s preface sniffing, which has no timeout.
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            let io = TokioIo::new(tls);
            if h2 {
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .timer(TokioTimer::new())
                    .keep_alive_interval(Some(ka_interval))
                    .keep_alive_timeout(ka_timeout)
                    .serve_connection(io, svc)
                    .await
                    .map_err(|e| e.to_string())
            } else {
                hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(header_read)
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await
                    .map_err(|e| e.to_string())
            }
        }
        None => {
            let svc = service(ConnInfo::plain(peer));
            // `auto` sniffs the preface without a timeout: bound the first byte here.
            let mut first = [0u8; 1];
            match tokio::time::timeout(header_read, stream.peek(&mut first)).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => return,
            }
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read);
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(Some(ka_interval))
                .keep_alive_timeout(ka_timeout);
            builder
                .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                .await
                .map_err(|e| e.to_string())
        }
    };
    if let Err(e) = served {
        tracing::debug!(error = %e, %peer, "connection closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Authz, Config};
    use crate::testutil::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg(limits: &str) -> Config {
        Config::parse_plaintext(&format!(
            "listen: '127.0.0.1:0'\nlimits: {{ {limits} }}\nroutes: []\n"
        ))
        .unwrap()
    }

    const EMFILE: i32 = 24;

    struct Flaky {
        inner: TcpListener,
        fail: AtomicUsize,
        failed: Arc<AtomicUsize>,
    }

    impl Accept for Flaky {
        async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
            if self.fail.load(Ordering::SeqCst) > 0 {
                self.fail.fetch_sub(1, Ordering::SeqCst);
                self.failed.fetch_add(1, Ordering::SeqCst);
                return Err(std::io::Error::from_raw_os_error(EMFILE));
            }
            self.inner.accept().await
        }
    }

    #[tokio::test]
    async fn accept_error_backs_off() {
        let backend = recorder("ok").await;
        let table: crate::controller::Routes =
            Arc::new(arc_swap::ArcSwap::from_pointee(vec![route(
                "/",
                Authz::Skip,
                backend.addr,
            )]));
        let gw = Gateway::new(Arc::new(cfg("max_connections: 10")), table).unwrap();
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inner.local_addr().unwrap();
        let failed = Arc::new(AtomicUsize::new(0));
        let flaky = Flaky {
            inner,
            fail: AtomicUsize::new(4),
            failed: failed.clone(),
        };
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(flaky, gw, None, async move {
            let _ = rx.await;
        }));

        let t = std::time::Instant::now();
        let (code, body) = get(addr, "/", "").await;
        assert_eq!((code, body.trim()), (200, "ok"));
        assert_eq!(failed.load(Ordering::SeqCst), 4);
        assert!(
            t.elapsed() >= Duration::from_millis(60),
            "no backoff: {:?}",
            t.elapsed()
        );
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(!task.is_finished(), "the accept loop exited");

        let _ = tx.send(());
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("did not stop")
            .unwrap();
    }

    #[tokio::test]
    async fn connection_cap_queues_excess() {
        let backend = recorder("ok").await;
        let gw = gateway(
            cfg("max_connections: 2"),
            vec![route("/", Authz::Skip, backend.addr)],
        )
        .await;

        let mut a = TcpStream::connect(gw.addr).await.unwrap();
        let b = TcpStream::connect(gw.addr).await.unwrap();
        a.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            a.read(&mut buf).await.unwrap() > 0,
            "first connection is served (keep-alive, still open)"
        );

        let mut c = TcpStream::connect(gw.addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let waited = tokio::time::timeout(Duration::from_millis(300), c.read(&mut buf)).await;
        assert!(waited.is_err(), "served beyond the cap");

        drop(b);
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("still not served after a slot freed")
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn stalled_handshake_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = install(dir.path(), &issue());
        let backend = recorder("ok").await;
        let cfg = Config::parse_plaintext(&format!(
            "listen: '127.0.0.1:0'\ntls: {{ cert: {cert}, key: {key} }}\n\
             limits: {{ tls_handshake_timeout_ms: 200, max_connections: 1 }}\nroutes: []\n"
        ))
        .unwrap();
        let gw = start(
            cfg,
            vec![route("/", Authz::Skip, backend.addr)],
            Some(crate::tls::acceptor(crate::tls::Reloading::new(
                &cert, &key,
            ))),
        )
        .await;

        let mut stalled = TcpStream::connect(gw.addr).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut buf))
            .await
            .expect("stalled handshake was never cut off")
            .unwrap_or(0);
        assert_eq!(n, 0, "server should have closed the connection");

        let (code, ..) = tls_get(gw.addr, "/").await;
        assert_eq!(code, 200);
    }

    #[tokio::test]
    async fn slow_headers_cut_off() {
        let backend = recorder("ok").await;
        let gw = gateway(
            cfg("header_read_timeout_ms: 250"),
            vec![route("/", Authz::Skip, backend.addr)],
        )
        .await;
        let mut c = TcpStream::connect(gw.addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nX-Slow: ")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut buf)).await;
        assert!(r.is_ok(), "connection held open past the header timeout");
        assert_eq!(backend.count(), 0);
    }

    #[tokio::test]
    async fn silent_plaintext_client_cut_off() {
        let backend = recorder("ok").await;
        let gw = gateway(
            cfg("header_read_timeout_ms: 200"),
            vec![route("/", Authz::Skip, backend.addr)],
        )
        .await;
        let mut c = TcpStream::connect(gw.addr).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("silent connection held open")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn unanswered_h2_ping_drops_peer() {
        let backend = recorder("ok").await;
        let gw = gateway(
            cfg("h2_keepalive_interval_ms: 100, h2_keepalive_timeout_ms: 150"),
            vec![route("/", Authz::Skip, backend.addr)],
        )
        .await;
        let mut c = TcpStream::connect(gw.addr).await.unwrap();
        // Preface and empty SETTINGS, then never ack a PING.
        c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let closed = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                match c.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "unresponsive h2 peer kept its connection");
    }
}
