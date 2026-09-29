//! Mission-path probes. Local sockets only: they must answer when the
//! apiserver, kubelet or DNS cannot.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Probe {
    Tcp {
        addr: String,
    },
    /// Any status line counts, 5xx included: this is liveness, not correctness.
    Http {
        addr: String,
        path: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub name: String,
    #[serde(flatten)]
    pub probe: Probe,
    #[serde(default = "default_grace")]
    pub grace_secs: u64,
}

fn default_grace() -> u64 {
    60
}

#[derive(Debug, Clone)]
pub struct Config {
    pub timeout_secs: u32,
    pub interval_secs: u64,
    /// Zero disables the boot-loop breaker.
    pub max_consecutive_resets: u32,
    pub unrecorded_reset_after_secs: u64,
    pub recovery_secs: u64,
    /// The least grace a check gets until it first passes: the boot runs from before the
    /// kubelet.
    pub startup_grace_secs: u64,
    pub checks: Vec<Check>,
}

#[derive(Debug, Default, Deserialize)]
struct Fragment {
    timeout_secs: Option<u32>,
    interval_secs: Option<u64>,
    max_consecutive_resets: Option<u32>,
    unrecorded_reset_after_secs: Option<u64>,
    recovery_secs: Option<u64>,
    startup_grace_secs: Option<u64>,
    #[serde(default)]
    checks: Vec<Check>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_secs: 60,
            interval_secs: 10,
            max_consecutive_resets: 3,
            unrecorded_reset_after_secs: 900,
            recovery_secs: 600,
            startup_grace_secs: 1200,
            checks: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("read {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        files.sort();
        let mut cfg = Self::default();
        for f in files {
            match std::fs::read_to_string(&f)
                .map_err(anyhow::Error::from)
                .and_then(|t| cfg.with(&t))
            {
                Ok(merged) => cfg = merged,
                Err(e) => tracing::error!(
                    fragment = %f.display(), error = %format!("{e:#}"),
                    "skipping a bad config fragment"
                ),
            }
        }
        anyhow::ensure!(!cfg.checks.is_empty(), "no checks in {}", dir.display());
        Ok(cfg)
    }

    /// The bool is true when the fallback is in use.
    pub fn load_or_fallback(dir: &Path) -> (Self, bool) {
        match Self::load(dir) {
            Ok(c) => (c, false),
            Err(e) => {
                tracing::error!(
                    error = %format!("{e:#}"),
                    "cannot load the config; running with no checks and retrying every round"
                );
                (Self::default(), true)
            }
        }
    }

    #[cfg(test)]
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg = Self::default().with(text)?;
        anyhow::ensure!(!cfg.checks.is_empty(), "no checks declared");
        Ok(cfg)
    }

    fn with(&self, text: &str) -> anyhow::Result<Self> {
        // An empty or comment-only file is an empty fragment.
        let f: Fragment = match serde_yaml::from_str(text)? {
            serde_yaml::Value::Null => Fragment::default(),
            v => serde_yaml::from_value(v)?,
        };
        let mut cfg = self.clone();
        cfg.timeout_secs = f.timeout_secs.unwrap_or(cfg.timeout_secs);
        cfg.interval_secs = f.interval_secs.unwrap_or(cfg.interval_secs);
        cfg.max_consecutive_resets = f
            .max_consecutive_resets
            .unwrap_or(cfg.max_consecutive_resets);
        cfg.unrecorded_reset_after_secs = f
            .unrecorded_reset_after_secs
            .unwrap_or(cfg.unrecorded_reset_after_secs);
        cfg.recovery_secs = f.recovery_secs.unwrap_or(cfg.recovery_secs);
        cfg.startup_grace_secs = f.startup_grace_secs.unwrap_or(cfg.startup_grace_secs);
        cfg.checks.extend(f.checks);
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        // tokio::time::interval panics on a zero period.
        anyhow::ensure!(self.interval_secs >= 1, "interval_secs must be at least 1");
        anyhow::ensure!(self.timeout_secs >= 2, "timeout_secs must be at least 2");
        anyhow::ensure!(
            self.timeout_secs <= i32::MAX as u32,
            "timeout_secs {} does not fit the driver's int",
            self.timeout_secs
        );
        let need = self.interval_secs.checked_mul(2);
        anyhow::ensure!(
            need.is_some_and(|n| n <= self.timeout_secs as u64),
            "interval_secs {} leaves no margin under timeout_secs {}",
            self.interval_secs,
            self.timeout_secs
        );
        let mut seen = std::collections::HashSet::new();
        for c in &self.checks {
            anyhow::ensure!(!c.name.trim().is_empty(), "a check has an empty name");
            // Failure clocks are keyed by name.
            anyhow::ensure!(
                seen.insert(c.name.as_str()),
                "duplicate check name {:?}",
                c.name
            );
        }
        Ok(())
    }
}

/// Unanswered by `round_deadline` counts as failed. Results are (name, healthy,
/// grace) in `checks` order.
pub async fn run_round(
    checks: &[Check],
    probe_timeout: Duration,
    round_deadline: Duration,
) -> Vec<(String, bool, Duration)> {
    let mut set = tokio::task::JoinSet::new();
    for (i, c) in checks.iter().cloned().enumerate() {
        set.spawn(async move { (i, c.run(probe_timeout).await) });
    }
    let mut ok = vec![false; checks.len()];
    let mut answered = vec![false; checks.len()];
    let deadline = tokio::time::Instant::now() + round_deadline;
    loop {
        match tokio::time::timeout_at(deadline, set.join_next()).await {
            Ok(Some(Ok((i, r)))) => {
                ok[i] = r;
                answered[i] = true;
            }
            Ok(Some(Err(e))) => tracing::error!(error = %e, "a probe task died"),
            Ok(None) => break,
            Err(_) => {
                let hung: Vec<&str> = checks
                    .iter()
                    .zip(&answered)
                    .filter(|(_, a)| !**a)
                    .map(|(c, _)| c.name.as_str())
                    .collect();
                tracing::warn!(hung = ?hung, ?round_deadline, "probe round deadline hit; unanswered checks failed");
                break;
            }
        }
    }
    checks
        .iter()
        .zip(ok)
        .map(|(c, ok)| (c.name.clone(), ok, Duration::from_secs(c.grace_secs)))
        .collect()
}

impl Check {
    pub async fn run(&self, timeout: Duration) -> bool {
        let r = tokio::time::timeout(timeout, self.probe.run()).await;
        match r {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::debug!(check = %self.name, error = %e, "probe failed");
                false
            }
            Err(_) => {
                tracing::debug!(check = %self.name, "probe timed out");
                false
            }
        }
    }
}

impl Probe {
    async fn run(&self) -> anyhow::Result<()> {
        match self {
            Probe::Tcp { addr } => {
                TcpStream::connect(addr).await?;
                Ok(())
            }
            Probe::Http { addr, path } => {
                let mut s = TcpStream::connect(addr).await?;
                let req =
                    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
                s.write_all(req.as_bytes()).await?;
                let mut buf = [0u8; 16];
                let n = s.read(&mut buf).await?;
                anyhow::ensure!(n > 0, "closed without answering");
                anyhow::ensure!(buf.starts_with(b"HTTP/"), "not an HTTP response");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK: &str = "checks:\n  - name: a\n    kind: tcp\n    addr: 127.0.0.1:1\n";

    #[test]
    fn parse_rejects_unsafe_config() {
        let dup = "checks:\n  - {name: a, kind: tcp, addr: '127.0.0.1:1'}\n  - {name: a, kind: tcp, addr: '127.0.0.1:2'}\n";
        let blank = "checks:\n  - {name: ' ', kind: tcp, addr: '127.0.0.1:1'}\n";
        let with = |head: &str| format!("{head}\n{CHECK}");
        let cases = [
            ("checks: []".to_string(), "no checks"),
            (with("timeout_secs: 10\ninterval_secs: 6"), "no margin"),
            (with("interval_secs: 0"), "at least 1"),
            (with("interval_secs: 18446744073709551615"), "no margin"),
            (with("timeout_secs: 4294967295"), "fit"),
            (with("timeout_secs: 0"), "at least 2"),
            (with("timeout_secs: 1\ninterval_secs: 1"), "at least 2"),
            (dup.to_string(), "duplicate"),
            (blank.to_string(), "empty name"),
        ];
        for (text, why) in cases {
            let e = format!("{:#}", Config::parse(&text).expect_err(&text));
            assert!(e.contains(why), "{text}: {e}");
        }
        let edge = Config::parse(&with("timeout_secs: 10\ninterval_secs: 5")).unwrap();
        assert_eq!((edge.timeout_secs, edge.interval_secs), (10, 5));
        let c = Config::parse(CHECK).unwrap();
        assert_eq!(
            (
                c.timeout_secs,
                c.interval_secs,
                c.max_consecutive_resets,
                c.unrecorded_reset_after_secs,
                c.recovery_secs,
                c.startup_grace_secs,
                c.checks[0].grace_secs
            ),
            (60, 10, 3, 900, 600, 1200, 60)
        );
    }

    fn config_dir(name: &str, fragments: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("edge-watch-cfg-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        for (f, text) in fragments {
            std::fs::write(d.join(f), text).unwrap();
        }
        d
    }

    fn names(c: &Config) -> Vec<&str> {
        c.checks.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn fragments_merge_in_name_order() {
        let d = config_dir(
            "merge",
            &[
                (
                    "50-payload.yaml",
                    "checks: [ { name: meridian, kind: tcp, addr: '127.0.0.1:8444' } ]",
                ),
                (
                    "10-platform.yaml",
                    "timeout_secs: 30\ninterval_secs: 10\nchecks:\n  - { name: store, kind: tcp, addr: '127.0.0.1:2379' }\n  - { name: apiserver, kind: tcp, addr: '127.0.0.1:6443' }\n",
                ),
                ("20-recovery.yaml", "recovery_secs: 60\n"),
                ("60-later.yaml", "timeout_secs: 40\n"),
                ("notes.txt", "{{{ not a fragment"),
            ],
        );
        let (c, degraded) = Config::load_or_fallback(&d);
        assert!(!degraded);
        assert_eq!(names(&c), ["store", "apiserver", "meridian"]);
        assert_eq!(
            (
                c.timeout_secs,
                c.interval_secs,
                c.recovery_secs,
                c.startup_grace_secs
            ),
            (40, 10, 60, 1200)
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn bad_fragment_skipped() {
        let d = config_dir(
            "skip",
            &[
                ("10-good.yaml", CHECK),
                ("20-garbage.yaml", "{{{ not yaml"),
                ("30-duplicate.yaml", CHECK),
                (
                    "40-margin.yaml",
                    "interval_secs: 60\ntimeout_secs: 60\nchecks: [ { name: b, kind: tcp, addr: 'x:1' } ]\n",
                ),
                ("60-empty.yaml", ""),
                ("65-comment.yaml", "# disarmed\n"),
                (
                    "70-good.yaml",
                    "checks: [ { name: c, kind: tcp, addr: '127.0.0.1:2' } ]",
                ),
            ],
        );
        std::fs::create_dir(d.join("50-dir.yaml")).unwrap();
        let c = Config::load(&d).unwrap();
        assert_eq!(names(&c), ["a", "c"]);
        for blank in ["", "# disarmed\n"] {
            assert!(
                Config::default().with(blank).is_ok(),
                "{blank:?} is an empty fragment"
            );
        }
        assert_eq!((c.timeout_secs, c.interval_secs), (60, 10));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn no_checks_falls_back() {
        let empty = config_dir("empty", &[]);
        let bad = config_dir(
            "allbad",
            &[("10.yaml", "{{{"), ("20.yaml", "timeout_secs: 30\n")],
        );
        let file = empty.with_extension("file");
        std::fs::write(&file, CHECK).unwrap();
        for dir in [
            empty.join("missing"),
            empty.clone(),
            bad.clone(),
            file.clone(),
        ] {
            let e = format!("{:#}", Config::load(&dir).unwrap_err());
            assert!(e.contains(&*dir.to_string_lossy()), "{e}");
            let (c, degraded) = Config::load_or_fallback(&dir);
            assert!(degraded, "{}", dir.display());
            assert!(c.checks.is_empty() && c.validate().is_ok());
        }
        std::fs::remove_dir_all(&empty).ok();
        std::fs::remove_dir_all(&bad).ok();
        std::fs::remove_file(&file).ok();
    }

    async fn wedged() -> Check {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        Check {
            name: format!("wedged-{addr}"),
            probe: Probe::Http {
                addr,
                path: "/".into(),
            },
            grace_secs: 0,
        }
    }

    #[tokio::test]
    async fn hung_probes_run_concurrently() {
        let mut checks = Vec::new();
        for _ in 0..5 {
            checks.push(wedged().await);
        }
        let t = std::time::Instant::now();
        let r = run_round(&checks, Duration::from_millis(400), Duration::from_secs(5)).await;
        let took = t.elapsed();
        assert!(r.iter().all(|(_, ok, _)| !ok));
        assert!(
            took < Duration::from_millis(1000),
            "round took {took:?}; sequential would be ~2s"
        );
    }

    #[tokio::test]
    async fn round_keeps_order_and_grace() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move { while l.accept().await.is_ok() {} });
        let checks = vec![
            Check {
                name: "up".into(),
                probe: Probe::Tcp { addr },
                grace_secs: 7,
            },
            Check {
                name: "down".into(),
                probe: Probe::Tcp {
                    addr: "127.0.0.1:1".into(),
                },
                grace_secs: 9,
            },
        ];
        let r = run_round(&checks, Duration::from_secs(1), Duration::from_secs(3)).await;
        assert_eq!(
            r,
            vec![
                ("up".to_string(), true, Duration::from_secs(7)),
                ("down".to_string(), false, Duration::from_secs(9))
            ]
        );
    }

    #[tokio::test]
    async fn round_deadline_is_hard() {
        let checks = vec![wedged().await];
        let t = std::time::Instant::now();
        let r = run_round(&checks, Duration::from_secs(30), Duration::from_millis(300)).await;
        assert!(!r[0].1);
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "took {:?}",
            t.elapsed()
        );
    }

    #[tokio::test]
    async fn http_probe_accepts_any_status() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 512];
            let _ = s.read(&mut b).await;
            let _ = s
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                .await;
        });
        let c = Check {
            name: "erroring".into(),
            probe: Probe::Http {
                addr,
                path: "/health".into(),
            },
            grace_secs: 0,
        };
        assert!(c.run(Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn http_probe_rejects_silence() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (_s, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let c = Check {
            name: "wedged".into(),
            probe: Probe::Http {
                addr,
                path: "/".into(),
            },
            grace_secs: 0,
        };
        assert!(!c.run(Duration::from_millis(300)).await);
    }
}
