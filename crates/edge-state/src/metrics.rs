//! Prometheus text served at `/metrics` on the client port, as etcd serves it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// A request this slow is logged; etcd warns at 100ms, a power-cut-safe single disk
/// is allowed more.
pub const SLOW_REQUEST: Duration = Duration::from_millis(500);
/// A watch this far behind the durable head is logged.
pub const SLOW_WATCH: Duration = Duration::from_secs(1);

const BUCKETS: [f64; 15] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0,
];

#[derive(Default)]
pub struct Histogram {
    counts: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl Histogram {
    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        if let Some(i) = BUCKETS.iter().position(|b| secs <= *b) {
            self.counts[i].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let sep = if labels.is_empty() { "" } else { "," };
        let mut cumulative = 0;
        for (b, c) in BUCKETS.iter().zip(&self.counts) {
            cumulative += c.load(Ordering::Relaxed);
            let _ = writeln!(out, "{name}_bucket{{{labels}{sep}le=\"{b}\"}} {cumulative}");
        }
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{{labels}{sep}le=\"+Inf\"}} {count}");
        let sum = self.sum_us.load(Ordering::Relaxed) as f64 / 1e6;
        let braces = |s: &str| {
            if s.is_empty() {
                String::new()
            } else {
                format!("{{{s}}}")
            }
        };
        let _ = writeln!(out, "{name}_sum{} {sum}", braces(labels));
        let _ = writeln!(out, "{name}_count{} {count}", braces(labels));
    }
}

#[derive(Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<&'static str, Histogram>>,
    slow_requests: Mutex<BTreeMap<&'static str, u64>>,
    pub lock_wait: Histogram,
    pub fsync: Histogram,
    pub watch_lag: Histogram,
    pub slow_watch_deliveries: AtomicU64,
    pub watch_send_blocked_us: AtomicU64,
    pub watch_streams: AtomicI64,
    pub watchers: AtomicI64,
}

pub static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::default);

impl Metrics {
    pub fn request(&self, method: &'static str, took: Duration) {
        crate::server::lock(&self.requests)
            .entry(method)
            .or_default()
            .observe(took);
        if took >= SLOW_REQUEST {
            *crate::server::lock(&self.slow_requests)
                .entry(method)
                .or_default() += 1;
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let header = |out: &mut String, name: &str, kind: &str, help: &str| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
        };
        header(
            &mut out,
            "grpc_server_handling_seconds",
            "histogram",
            "Time to answer a unary request, from its arrival to its response.",
        );
        for (method, h) in crate::server::lock(&self.requests).iter() {
            h.render(
                &mut out,
                "grpc_server_handling_seconds",
                &format!("grpc_method=\"{method}\""),
            );
        }
        header(
            &mut out,
            "edge_state_slow_requests_total",
            "counter",
            "Unary requests that took longer than the slow-request threshold.",
        );
        for (method, n) in crate::server::lock(&self.slow_requests).iter() {
            let _ = writeln!(
                out,
                "edge_state_slow_requests_total{{grpc_method=\"{method}\"}} {n}"
            );
        }
        header(
            &mut out,
            "edge_state_store_lock_wait_seconds",
            "histogram",
            "Time a request waited for the store lock.",
        );
        self.lock_wait
            .render(&mut out, "edge_state_store_lock_wait_seconds", "");
        header(
            &mut out,
            "etcd_disk_wal_fsync_duration_seconds",
            "histogram",
            "Duration of the log's fsyncs.",
        );
        self.fsync
            .render(&mut out, "etcd_disk_wal_fsync_duration_seconds", "");
        header(
            &mut out,
            "edge_state_watch_delivery_lag_seconds",
            "histogram",
            "Time from a revision becoming durable to its events reaching a watch stream.",
        );
        self.watch_lag
            .render(&mut out, "edge_state_watch_delivery_lag_seconds", "");
        let counters = [
            (
                "edge_state_slow_watch_deliveries_total",
                "counter",
                "Watch deliveries later than the slow-watch threshold.",
                self.slow_watch_deliveries.load(Ordering::Relaxed) as f64,
            ),
            (
                "edge_state_watch_send_blocked_seconds_total",
                "counter",
                "Time watch streams spent waiting for their client to read.",
                self.watch_send_blocked_us.load(Ordering::Relaxed) as f64 / 1e6,
            ),
            (
                "edge_state_watch_streams",
                "gauge",
                "Open watch streams.",
                self.watch_streams.load(Ordering::Relaxed) as f64,
            ),
            (
                "etcd_debugging_mvcc_watcher_total",
                "gauge",
                "Watches open across all streams.",
                self.watchers.load(Ordering::Relaxed) as f64,
            ),
        ];
        for (name, kind, help, v) in counters {
            header(&mut out, name, kind, help);
            let _ = writeln!(out, "{name} {v}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_is_cumulative() {
        let h = Histogram::default();
        for ms in [2, 2, 40, 7000] {
            h.observe(Duration::from_millis(ms));
        }
        let mut out = String::new();
        h.render(&mut out, "x", "m=\"a\"");
        for want in [
            "x_bucket{m=\"a\",le=\"0.001\"} 0",
            "x_bucket{m=\"a\",le=\"0.005\"} 2",
            "x_bucket{m=\"a\",le=\"0.05\"} 3",
            "x_bucket{m=\"a\",le=\"5\"} 3",
            "x_bucket{m=\"a\",le=\"10\"} 4",
            "x_bucket{m=\"a\",le=\"+Inf\"} 4",
            "x_sum{m=\"a\"} 7.044",
            "x_count{m=\"a\"} 4",
        ] {
            assert!(out.lines().any(|l| l == want), "{want} missing from\n{out}");
        }
    }

    #[test]
    fn slow_requests_counted_by_method() {
        let m = Metrics::default();
        m.request("Range", Duration::from_millis(3));
        m.request("Range", SLOW_REQUEST);
        m.request("Txn", Duration::from_millis(3));
        let out = m.render();
        assert!(out.contains("edge_state_slow_requests_total{grpc_method=\"Range\"} 1"));
        assert!(!out.contains("edge_state_slow_requests_total{grpc_method=\"Txn\"}"));
        assert!(out.contains("grpc_server_handling_seconds_count{grpc_method=\"Txn\"} 1"));
    }
}
