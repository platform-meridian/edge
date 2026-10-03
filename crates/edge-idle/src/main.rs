//! Throttling the scheduler and controller-manager is safe only because both run
//! with `leader-elect=false`: a starved leader would lose its lease, and client-go
//! exits on losing one.

mod throttle;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher;
use kube::{Api, Client, ResourceExt};

const TARGETS: [&str; 2] = ["kube-scheduler", "kube-controller-manager"];
const TARGET_NS: &str = "kube-system";

const STEP: Duration = Duration::from_secs(5);

/// Throttling a target slows its probes, and kubelet's resulting status update
/// on its static pod must not count as the activity that releases it.
fn is_suppression_target(ns: Option<&str>, name: &str) -> bool {
    ns == Some(TARGET_NS) && TARGETS.iter().any(|t| name.starts_with(t))
}

/// A relist (`Init*`) is activity: changes made while the watch was down
/// arrive only as `InitApply`, and deletions not at all.
fn is_activity<K>(ev: &watcher::Event<K>, guard_self_wake: bool) -> bool
where
    K: kube::Resource,
{
    use watcher::Event::*;
    match ev {
        Apply(o) | Delete(o) | InitApply(o) => {
            !(guard_self_wake && is_suppression_target(o.namespace().as_deref(), &o.name_any()))
        }
        Init | InitDone => true,
    }
}

fn secs_or_default(name: &str, raw: Option<&str>, default: u64, min: u64) -> u64 {
    let Some(raw) = raw else { return default };
    match raw.trim().parse::<u64>() {
        Ok(n) if n >= min => n,
        _ => {
            tracing::error!(
                name,
                value = raw,
                default,
                min,
                "invalid seconds; using the default"
            );
            default
        }
    }
}

async fn retry_until<T, E, Fut>(
    term: &mut edge_common::Terminator,
    what: &str,
    min: Duration,
    max: Duration,
    mut f: impl FnMut() -> Fut,
) -> Option<T>
where
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = min;
    loop {
        match f().await {
            Ok(v) => return Some(v),
            Err(e) => {
                tracing::error!(what, error = %e, retry_in = ?delay, "not available yet; retrying")
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = term.wait() => return None,
        }
        delay = (delay * 2).min(max);
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    acted: usize,
    failed: usize,
}

struct Governor {
    idle_after: Duration,
    step: Duration,
    quiet: Duration,
    /// Cleared only once a release succeeded on every target.
    throttled: bool,
    wake_pending: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Tick {
    Nothing,
    Released(usize),
    ReleaseFailed { failed: usize },
    Throttled(usize),
    NothingToThrottle { failed: usize },
}

impl Governor {
    fn new(idle_after: Duration, step: Duration) -> Self {
        Self {
            idle_after,
            step,
            quiet: Duration::ZERO,
            throttled: false,
            wake_pending: false,
        }
    }

    fn tick(&mut self, changed: bool, apply: &mut dyn FnMut(bool) -> Outcome) -> Tick {
        if changed {
            self.quiet = Duration::ZERO;
            if self.throttled {
                self.wake_pending = true;
            }
        }
        if self.wake_pending {
            let o = apply(false);
            if o.failed == 0 {
                self.throttled = false;
                self.wake_pending = false;
                return Tick::Released(o.acted);
            }
            return Tick::ReleaseFailed { failed: o.failed };
        }
        if changed || self.throttled {
            return Tick::Nothing;
        }
        self.quiet += self.step;
        if self.quiet < self.idle_after {
            return Tick::Nothing;
        }
        let o = apply(true);
        self.throttled = o.acted > 0;
        if self.throttled {
            Tick::Throttled(o.acted)
        } else {
            self.quiet = Duration::ZERO;
            Tick::NothingToThrottle { failed: o.failed }
        }
    }
}

/// A throttle outlives the process that set it, so every start first releases
/// whatever a predecessor left, including an older build's `cgroup.freeze`.
fn release_stale(proc_dir: &Path, cgroup_root: &Path) {
    for t in TARGETS {
        let Some(dir) = throttle::cgroup_dir_for(proc_dir, cgroup_root, t) else {
            continue;
        };
        if throttle::is_throttled(&dir) {
            tracing::warn!(
                target = t,
                "throttled at startup by a previous instance; releasing"
            );
        }
        match throttle::clear_stale_freeze(&dir) {
            Some(Ok(())) => tracing::warn!(target = t, "thawed a freeze left by an older build"),
            Some(Err(e)) => {
                tracing::error!(target = t, error = %e, "could not thaw a stale freeze")
            }
            None => {}
        }
    }
    if set_all(proc_dir, cgroup_root, false).failed > 0 {
        tracing::error!("could not release every target at startup; a stale throttle may remain");
    }
}

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();
    let proc_dir: PathBuf = std::env::var("EDGE_IDLE_PROC")
        .unwrap_or_else(|_| "/proc".into())
        .into();
    let cgroup_root: PathBuf = std::env::var("EDGE_IDLE_CGROUP")
        .unwrap_or_else(|_| "/sys/fs/cgroup".into())
        .into();
    edge_common::sandbox::restrict(&edge_common::sandbox::idle(&proc_dir, &cgroup_root));
    run(proc_dir, cgroup_root)
}

#[tokio::main]
async fn run(proc_dir: PathBuf, cgroup_root: PathBuf) -> anyhow::Result<()> {
    let mut term = edge_common::Terminator::new();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let idle_after = Duration::from_secs(secs_or_default(
        "EDGE_IDLE_AFTER",
        std::env::var("EDGE_IDLE_AFTER").ok().as_deref(),
        120,
        1,
    ));

    // Before the API client, which may never come up.
    release_stale(&proc_dir, &cgroup_root);

    let ticks = Arc::new(AtomicU64::new(0));
    let Some(client) = retry_until(
        &mut term,
        "kubernetes client",
        Duration::from_secs(1),
        Duration::from_secs(30),
        Client::try_default,
    )
    .await
    else {
        tracing::info!("SIGTERM before the API client came up; nothing is throttled");
        return Ok(());
    };

    // Nodes are not watched: kubelet's heartbeat updates the Node every few
    // seconds and would keep the cluster from ever looking quiet.
    let mut watches = tokio::task::JoinSet::new();
    spawn_watch::<Pod>(&mut watches, client.clone(), ticks.clone(), "pods", true);
    spawn_watch::<Deployment>(
        &mut watches,
        client.clone(),
        ticks.clone(),
        "deployments",
        false,
    );
    spawn_watch::<StatefulSet>(
        &mut watches,
        client.clone(),
        ticks.clone(),
        "statefulsets",
        false,
    );
    spawn_watch::<DaemonSet>(
        &mut watches,
        client.clone(),
        ticks.clone(),
        "daemonsets",
        false,
    );

    tracing::info!(
        idle_after_secs = idle_after.as_secs(),
        targets = ?TARGETS,
        "edge-idle started"
    );

    let mut last_seen = ticks.load(Ordering::Relaxed);
    let mut gov = Governor::new(idle_after, STEP);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(STEP) => {}
            _ = term.wait() => {
                tracing::info!("SIGTERM: releasing before exit");
                release_for_exit(&proc_dir, &cgroup_root).await;
                return Ok(());
            }
            ended = watches.join_next() => {
                let what = match ended {
                    Some(Ok(what)) => what.to_string(),
                    Some(Err(e)) => format!("a watch task died: {e}"),
                    None => "no watches remain".to_string(),
                };
                tracing::error!(what, "watch ended; releasing and exiting");
                release_for_exit(&proc_dir, &cgroup_root).await;
                anyhow::bail!("watch ended: {what}");
            }
        }
        let now = ticks.load(Ordering::Relaxed);
        let changed = now != last_seen;
        last_seen = now;

        let quiet_secs = gov.quiet.as_secs() + STEP.as_secs();
        match gov.tick(changed, &mut |t| set_all(&proc_dir, &cgroup_root, t)) {
            Tick::Nothing => {}
            Tick::Released(n) => {
                tracing::info!(released = n, "cluster changed; control loops released")
            }
            Tick::ReleaseFailed { failed } => {
                tracing::error!(failed, "release failed on some targets; retrying")
            }
            Tick::Throttled(n) => {
                tracing::info!(
                    quiet_secs,
                    throttled = n,
                    "cluster quiet; control loops throttled"
                )
            }
            Tick::NothingToThrottle { failed } => tracing::warn!(
                quiet_secs,
                failed,
                targets = ?TARGETS,
                "cluster quiet but nothing could be throttled; check hostPID and the cgroup mount"
            ),
        }
    }
}

/// The last chance to undo a throttle, so a failed write is retried.
async fn release_for_exit(proc_dir: &Path, cgroup_root: &Path) {
    for attempt in 1..=4 {
        let o = set_all(proc_dir, cgroup_root, false);
        if o.failed == 0 {
            return;
        }
        tracing::error!(
            attempt,
            failed = o.failed,
            "could not release the control loops on exit"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    tracing::error!("exiting while throttled; control loops stay slow until edge-idle restarts");
}

fn set_all(proc_dir: &Path, cgroup_root: &Path, throttle_them: bool) -> Outcome {
    let mut out = Outcome::default();
    for t in TARGETS {
        let Some(dir) = throttle::cgroup_dir_for(proc_dir, cgroup_root, t) else {
            tracing::debug!(target = t, "not running; skipping");
            continue;
        };
        match throttle::set_throttled(&dir, throttle_them) {
            Ok(true) => {
                tracing::debug!(target = t, throttle_them, "set");
                out.acted += 1;
            }
            Ok(false) => tracing::debug!(target = t, throttle_them, "nothing to do"),
            Err(e) => {
                tracing::warn!(target = t, error = %e, "could not set the CPU quota");
                out.failed += 1;
            }
        }
    }
    out
}

fn spawn_watch<K>(
    set: &mut tokio::task::JoinSet<&'static str>,
    client: Client,
    ticks: Arc<AtomicU64>,
    what: &'static str,
    guard_self_wake: bool,
) where
    K: kube::Resource
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + 'static,
    K::DynamicType: Default + Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync,
{
    set.spawn(async move {
        loop {
            let api: Api<K> = Api::all(client.clone());
            let mut s = edge_kube::watch(api, what).boxed();
            while let Some(ev) = s.next().await {
                if let Ok(ev) = ev
                    && is_activity(&ev, guard_self_wake)
                {
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            }
            tracing::error!(what, "watch stream ended; starting a new one");
            // The gap is unknown, so it counts as activity.
            ticks.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn pod(ns: &str, name: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn suppression_targets() {
        for (ns, name, want) in [
            (Some("kube-system"), "kube-scheduler-meridian-01", true),
            (
                Some("kube-system"),
                "kube-controller-manager-meridian-01",
                true,
            ),
            (Some("kube-system"), "kube-apiserver-meridian-01", false),
            (Some("kube-system"), "edge-dns-7d849f5bdb-nrzl4", false),
            (Some("meridian"), "kube-scheduler-lookalike", false),
            (None, "kube-scheduler-meridian-01", false),
        ] {
            assert_eq!(is_suppression_target(ns, name), want, "{ns:?}/{name}");
        }
    }

    #[test]
    fn own_pods_not_activity_under_guard() {
        use watcher::Event::*;
        let app = pod("meridian", "app-1");
        let sched = pod("kube-system", "kube-scheduler-meridian-01");
        for guard in [true, false] {
            assert!(is_activity::<Pod>(&Init, guard));
            assert!(is_activity::<Pod>(&InitDone, guard));
            for ev in [
                Apply(app.clone()),
                InitApply(app.clone()),
                Delete(app.clone()),
            ] {
                assert!(is_activity(&ev, guard));
            }
            for ev in [
                Apply(sched.clone()),
                InitApply(sched.clone()),
                Delete(sched.clone()),
            ] {
                assert_eq!(is_activity(&ev, guard), !guard);
            }
        }
    }

    fn gov(idle_secs: u64) -> Governor {
        Governor::new(Duration::from_secs(idle_secs), STEP)
    }

    fn acted(n: usize) -> Outcome {
        Outcome {
            acted: n,
            failed: 0,
        }
    }

    fn drive(
        g: &mut Governor,
        changed: bool,
        throttle: Outcome,
        release: Outcome,
    ) -> (Tick, Vec<bool>) {
        let mut asked = Vec::new();
        let (mut t, mut r) = (Some(throttle), Some(release));
        let tick = g.tick(changed, &mut |on| {
            asked.push(on);
            if on { t.take() } else { r.take() }.unwrap()
        });
        (tick, asked)
    }

    #[test]
    fn quiet_throttles_activity_releases() {
        let mut g = gov(10);
        assert_eq!(
            drive(&mut g, false, acted(2), acted(0)),
            (Tick::Nothing, vec![])
        );
        assert_eq!(
            drive(&mut g, false, acted(2), acted(0)),
            (Tick::Throttled(2), vec![true])
        );
        assert_eq!(
            drive(&mut g, false, acted(2), acted(0)),
            (Tick::Nothing, vec![])
        );
        assert_eq!(
            drive(&mut g, true, acted(0), acted(2)),
            (Tick::Released(2), vec![false])
        );
        assert!(!g.throttled);
        assert_eq!(g.quiet, Duration::ZERO);
        assert_eq!(
            drive(&mut g, false, acted(2), acted(0)),
            (Tick::Nothing, vec![])
        );
    }

    #[test]
    fn failed_release_retried() {
        let mut g = gov(5);
        drive(&mut g, false, acted(2), acted(0));
        let partial = Outcome {
            acted: 1,
            failed: 1,
        };
        assert_eq!(
            drive(&mut g, true, acted(0), partial),
            (Tick::ReleaseFailed { failed: 1 }, vec![false])
        );
        assert!(g.throttled);
        assert_eq!(
            drive(&mut g, false, acted(0), acted(1)),
            (Tick::Released(1), vec![false])
        );
        assert!(!g.throttled && !g.wake_pending);
    }

    #[test]
    fn activity_resets_quiet_clock() {
        let mut g = gov(10);
        drive(&mut g, false, acted(0), acted(0));
        assert_eq!(g.quiet, STEP);
        assert_eq!(
            drive(&mut g, true, acted(0), acted(0)),
            (Tick::Nothing, vec![])
        );
        assert_eq!(g.quiet, Duration::ZERO);
    }

    #[test]
    fn empty_throttle_not_claimed() {
        let mut g = gov(5);
        let none = Outcome {
            acted: 0,
            failed: 2,
        };
        assert_eq!(
            drive(&mut g, false, none, acted(0)),
            (Tick::NothingToThrottle { failed: 2 }, vec![true])
        );
        assert!(!g.throttled);
        assert_eq!(g.quiet, Duration::ZERO);
        assert_eq!(
            drive(&mut g, true, acted(0), acted(0)),
            (Tick::Nothing, vec![]),
            "nothing to release"
        );
    }

    #[test]
    fn bad_idle_after_uses_default() {
        let parse = |v| secs_or_default("EDGE_IDLE_AFTER", v, 120, 1);
        assert_eq!(parse(None), 120);
        assert_eq!(parse(Some(" 30 ")), 30);
        assert_eq!(parse(Some("1")), 1);
        for bad in ["2m", "", "-1", "0", "1.5"] {
            assert_eq!(parse(Some(bad)), 120, "{bad}");
        }
    }

    #[tokio::test]
    async fn retry_until_backs_off() {
        let mut term = edge_common::Terminator::new();
        let mut calls = 0;
        let started = std::time::Instant::now();
        let got = retry_until(
            &mut term,
            "x",
            Duration::from_millis(10),
            Duration::from_millis(40),
            || {
                calls += 1;
                let n = calls;
                async move { if n < 4 { Err("not yet") } else { Ok(n) } }
            },
        )
        .await;
        assert_eq!(got, Some(4));
        // 10 + 20 + 40 ms, doubling to the cap.
        assert!(started.elapsed() >= Duration::from_millis(70));
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let base = tempfile::tempdir().unwrap();
        let (proc_dir, cg) = (base.path().join("proc"), base.path().join("cg"));
        for (pid, comm) in [(101, "kube-scheduler"), (102, "kube-controller")] {
            let d = proc_dir.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
            let c = cg.join(format!("pod/{comm}"));
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("cgroup.procs"), format!("{pid}\n")).unwrap();
            std::fs::write(c.join("cpu.max"), "max 100000\n").unwrap();
        }
        (base, proc_dir, cg)
    }

    #[test]
    fn set_all_and_release_stale() {
        let (_tmp, proc_dir, cg) = fixture();
        assert_eq!(set_all(&proc_dir, &cg, true), acted(2));
        assert_eq!(set_all(&proc_dir, &cg, true), acted(0));

        use std::os::unix::fs::PermissionsExt;
        let f = cg.join("pod/kube-scheduler/cpu.max");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        if unsafe { nix::libc::geteuid() } != 0 {
            assert_eq!(
                set_all(&proc_dir, &cg, false),
                Outcome {
                    acted: 1,
                    failed: 1
                }
            );
        }
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();

        std::fs::write(&f, throttle::quota_for(true)).unwrap();
        std::fs::write(cg.join("pod/kube-controller/cpu.max"), "1\n").unwrap();
        std::fs::write(cg.join("pod/kube-scheduler/cgroup.freeze"), "1\n").unwrap();
        release_stale(&proc_dir, &cg);
        assert!(!throttle::is_throttled(&cg.join("pod/kube-scheduler")));
        assert_eq!(
            std::fs::read_to_string(cg.join("pod/kube-scheduler/cgroup.freeze")).unwrap(),
            "0"
        );
    }

    #[tokio::test]
    async fn exit_releases_throttle() {
        let (_tmp, proc_dir, cg) = fixture();
        assert_eq!(set_all(&proc_dir, &cg, true), acted(2));
        release_for_exit(&proc_dir, &cg).await;
        assert_eq!(set_all(&proc_dir, &cg, false), acted(0));
        assert_eq!(
            set_all(&proc_dir, &cg, true),
            acted(2),
            "both unlimited again"
        );
    }
}
