//! Liveness for a daemon with no server of its own: its loop beats each time
//! round, and `GET /healthz` answers 503 once the last beat is too old.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Monotonic: a wall-clock step is neither a stall nor a beat.
#[derive(Clone, Debug)]
pub struct Heartbeat {
    start: Instant,
    last_ms: Arc<AtomicU64>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            last_ms: Arc::default(),
        }
    }
}

impl Heartbeat {
    pub fn beat(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    pub fn age(&self) -> Duration {
        self.start
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last_ms.load(Ordering::Relaxed)))
    }
}

const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Never returns. The bind is retried: a predecessor on the host's network may
/// still hold the port.
pub async fn serve(listen: String, heartbeat: Heartbeat, stale_after: Duration) {
    let listener = bind(&listen).await;
    tracing::info!(listen, "healthz: serving");
    loop {
        match listener.accept().await {
            Ok((mut s, _)) => {
                let hb = heartbeat.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(ANSWER_TIMEOUT, answer(&mut s, &hb, stale_after))
                        .await;
                });
            }
            // Out of descriptors, most likely: a probe that fails says so.
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn bind(listen: &str) -> TcpListener {
    let mut outage = crate::Outage::default();
    let mut delay = Duration::from_millis(250);
    loop {
        let r = TcpListener::bind(listen).await;
        outage.observe("healthz bind", &r);
        if let Ok(l) = r {
            return l;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}

async fn answer(s: &mut TcpStream, hb: &Heartbeat, stale_after: Duration) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let mut n = 0;
    while n < buf.len() && !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut buf[n..]).await? {
            0 => break,
            r => n += r,
        }
    }
    let (status, body) = respond(&buf[..n], hb.age(), stale_after);
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body.as_bytes()).await?;
    s.shutdown().await
}

fn respond(request: &[u8], age: Duration, stale_after: Duration) -> (&'static str, String) {
    let line = request.split(|&b| b == b'\r').next().unwrap_or_default();
    let mut words = line.split(|&b| b == b' ');
    let (method, target) = (words.next(), words.next().unwrap_or_default());
    let path = target.split(|&b| b == b'?').next().unwrap_or_default();
    if method != Some(b"GET") || path != b"/healthz" {
        return ("404 Not Found", String::new());
    }
    if age <= stale_after {
        ("200 OK", "ok\n".into())
    } else {
        (
            "503 Service Unavailable",
            format!("stalled for {}s\n", age.as_secs()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(addr: &str, target: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    fn free_addr() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    }

    async fn serving(stale_after: Duration) -> (String, Heartbeat) {
        let addr = free_addr();
        let hb = Heartbeat::default();
        tokio::spawn({
            let (addr, hb) = (addr.clone(), hb.clone());
            async move { serve(addr, hb, stale_after).await }
        });
        for _ in 0..100 {
            if TcpStream::connect(&addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (addr, hb)
    }

    #[tokio::test]
    async fn fresh_beat_is_healthy_stale_is_not() {
        let (addr, hb) = serving(Duration::from_millis(300)).await;
        hb.beat();
        let ok = get(&addr, "/healthz").await;
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.ends_with("\r\n\r\nok\n"), "{ok}");
        assert!(
            get(&addr, "/healthz?verbose")
                .await
                .starts_with("HTTP/1.1 200 ")
        );

        tokio::time::sleep(Duration::from_millis(400)).await;
        let stale = get(&addr, "/healthz").await;
        assert!(stale.starts_with("HTTP/1.1 503 "), "{stale}");
        assert!(stale.contains("stalled for 0s"), "{stale}");

        hb.beat();
        assert!(get(&addr, "/healthz").await.starts_with("HTTP/1.1 200 "));
    }

    #[tokio::test]
    async fn only_get_healthz_is_answered() {
        let (addr, _hb) = serving(Duration::from_secs(3600)).await;
        for target in ["/", "/healthzz", "/x/healthz"] {
            assert!(
                get(&addr, target).await.starts_with("HTTP/1.1 404 "),
                "{target}"
            );
        }
        let mut s = TcpStream::connect(&addr).await.unwrap();
        s.write_all(b"POST /healthz HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
    }

    #[tokio::test]
    async fn waits_for_a_held_port() {
        let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = holder.local_addr().unwrap().to_string();
        let hb = Heartbeat::default();
        tokio::spawn({
            let (addr, hb) = (addr.clone(), hb.clone());
            async move { serve(addr, hb, Duration::from_secs(3600)).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(holder);
        let up = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(mut s) = TcpStream::connect(&addr).await {
                    s.write_all(b"GET /healthz HTTP/1.1\r\n\r\n").await.unwrap();
                    let mut out = String::new();
                    s.read_to_string(&mut out).await.unwrap();
                    return out;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("never bound once the port was free");
        assert!(up.starts_with("HTTP/1.1 200 "), "{up}");
    }

    #[test]
    fn age_counts_from_the_last_beat() {
        let hb = Heartbeat::default();
        std::thread::sleep(Duration::from_millis(30));
        assert!(hb.age() >= Duration::from_millis(30));
        hb.beat();
        assert!(hb.age() < Duration::from_millis(30));
    }
}
