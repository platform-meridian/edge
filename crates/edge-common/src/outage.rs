use std::fmt::Display;

#[derive(Debug, Default)]
pub struct Outage {
    down: bool,
}

impl Outage {
    pub fn observe<T, E: Display>(&mut self, what: &str, result: &Result<T, E>) {
        match result {
            Ok(_) if std::mem::take(&mut self.down) => tracing::info!(what, "recovered"),
            Ok(_) => {}
            Err(error) if std::mem::replace(&mut self.down, true) => {
                tracing::debug!(what, %error, "still failing")
            }
            Err(error) => tracing::warn!(what, %error, "failing; retrying with backoff"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl Write for Lines {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn warns_once_then_recovers() {
        let lines = Lines::default();
        let sink = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut o = Outage::default();
            for r in [
                Ok(()),
                Err("a"),
                Err("b"),
                Err("c"),
                Ok(()),
                Ok(()),
                Err("d"),
            ] {
                o.observe("pods", &r);
            }
        });
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        let levels: Vec<&str> = text
            .lines()
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(levels, ["WARN", "DEBUG", "DEBUG", "INFO", "WARN"], "{text}");
    }
}
