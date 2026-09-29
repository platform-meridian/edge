use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// Closes after `idle` with no byte moving either way: a peer that vanishes
/// without a FIN would otherwise hold its slot until TCP keepalive notices.
pub(super) async fn tunnel<A, B>(a: A, b: B, idle: Duration) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let clock = Arc::new(ActivityClock {
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
    });
    let mut a = Activity {
        io: a,
        clock: clock.clone(),
    };
    let mut b = Activity {
        io: b,
        clock: clock.clone(),
    };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    let watchdog = async {
        loop {
            tokio::time::sleep_until(clock.last() + idle).await;
            if clock.last() + idle <= Instant::now() {
                return;
            }
        }
    };
    tokio::select! {
        r = copy => r.map(|_| ()),
        _ = watchdog => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel idle")),
    }
}

struct ActivityClock {
    start: Instant,
    last_ms: AtomicU64,
}

impl ActivityClock {
    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

struct Activity<T> {
    io: T,
    clock: Arc<ActivityClock>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Activity<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.clock.touch();
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Activity<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            self.clock.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn tunnel_closes_when_idle() {
        let (a, mut a_peer) = tokio::io::duplex(64);
        let (b, mut b_peer) = tokio::io::duplex(64);
        let t = tokio::spawn(tunnel(a, b, Duration::from_millis(150)));
        for i in 0..4 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let mut byte = [0u8; 1];
            if i % 2 == 0 {
                a_peer.write_all(b"x").await.unwrap();
                b_peer.read_exact(&mut byte).await.unwrap();
            } else {
                b_peer.write_all(b"y").await.unwrap();
                a_peer.read_exact(&mut byte).await.unwrap();
            }
        }
        assert!(!t.is_finished(), "closed while active");
        let r = tokio::time::timeout(Duration::from_secs(2), t)
            .await
            .expect("tunnel never timed out")
            .unwrap();
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }
}
