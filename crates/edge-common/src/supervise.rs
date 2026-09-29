use std::future::Future;
use std::time::Duration;

pub async fn forever<F, Fut>(min: Duration, max: Duration, mut f: F) -> std::convert::Infallible
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut delay = min;
    loop {
        let began = tokio::time::Instant::now();
        f().await;
        if began.elapsed() > max {
            delay = min;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test(start_paused = true)]
    async fn delay_doubles_then_resets() {
        let start = tokio::time::Instant::now();
        let calls = Mutex::new(Vec::new());
        let r = tokio::time::timeout(
            Duration::from_secs(100),
            forever(Duration::from_secs(1), Duration::from_secs(8), || async {
                let n = {
                    let mut c = calls.lock().unwrap();
                    c.push(start.elapsed().as_secs());
                    c.len()
                };
                if n == 5 {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }),
        )
        .await;
        assert!(r.is_err(), "it must not return");
        let got = calls.lock().unwrap().clone();
        assert_eq!(got[..10], [0, 1, 3, 7, 15, 46, 48, 52, 60, 68]);
    }
}
