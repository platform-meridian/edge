use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

// kube-client logs every failed request at ERROR; callers report outages once.
const DEFAULT_FILTER: &str = "info,kube_client=off";

pub fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .try_init();
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
    fn default_drops_kube_client_errors() {
        let lines = Lines::default();
        let sink = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(DEFAULT_FILTER))
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "kube_client::client::builder", "failed with error client error (Connect)");
            tracing::warn!(target: "edge_kube", "failing; retrying with backoff");
            tracing::debug!(target: "edge_kube", "still failing");
        });
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("client error"), "{text}");
        assert!(text.contains("failing; retrying"), "{text}");
        assert!(!text.contains("still failing"), "{text}");
    }
}
