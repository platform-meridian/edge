//! Every ladder step is written durably before it is taken, so a power cut can
//! skip a rung but never repeat one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use edge_common::watch_state::{HealthySince, State};

/// Padding (trailing spaces are valid JSON) so a later record can be
/// overwritten in place when there is no room for a temp file.
const MIN_RECORD_BYTES: usize = 512;

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::error!(
                dir = %dir.display(), error = %e,
                "cannot create the state directory; arming anyway"
            );
        }
        Self {
            path: dir.join("state.json"),
        }
    }

    pub fn load(&self) -> State {
        match std::fs::read_to_string(&self.path) {
            // Unparseable means a reset landed mid-write: count it, failing
            // toward stopping the loop.
            Ok(t) => State::parse(&t).unwrap_or_else(|e| {
                tracing::error!(
                    error = %e,
                    kept_as = %self.corrupt_path().display(),
                    "state record damaged; counting it as a reset"
                );
                self.keep_evidence();
                State {
                    reset_pending: true,
                    ..State::default()
                }
            }),
            // The only read failure that means a first boot.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                tracing::error!(
                    path = %self.path.display(), error = %e,
                    "state record unreadable; counting it as a reset"
                );
                State {
                    reset_pending: true,
                    ..State::default()
                }
            }
        }
    }

    fn corrupt_path(&self) -> PathBuf {
        let mut n = self.path.as_os_str().to_os_string();
        n.push(".corrupt");
        PathBuf::from(n)
    }

    fn keep_evidence(&self) {
        let _ = std::fs::copy(&self.path, self.corrupt_path());
    }

    pub fn save(&self, s: &State) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(s)?;
        pad(&mut bytes, MIN_RECORD_BYTES);
        match edge_common::durable_write(&self.path, &bytes) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Likely a full disk: overwrite the file's own blocks. A torn
                // result is read back as a pending reset, which is safe.
                match self.save_in_place(&bytes) {
                    Ok(()) => {
                        tracing::warn!(error = %e, "could not replace the state record; overwrote it in place");
                        Ok(())
                    }
                    Err(e2) => Err(anyhow::anyhow!("{e}; in-place fallback also failed: {e2}")),
                }
            }
        }
    }

    fn save_in_place(&self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).open(&self.path)?;
        let mut out = bytes.to_vec();
        pad(&mut out, f.metadata()?.len() as usize);
        f.write_all(&out)?;
        f.sync_all()
    }
}

fn pad(bytes: &mut Vec<u8>, to: usize) {
    if bytes.len() < to {
        bytes.resize(to, b' ');
    }
}

/// A pending reset counts; any other restart neither counts nor clears the
/// count. Health is not carried: this process has seen none yet.
pub fn fold_boot(prev: State) -> State {
    let prev = State {
        healthy_since: None,
        ..prev
    };
    if prev.reset_pending {
        let n = prev.consecutive_resets.saturating_add(1);
        tracing::warn!(
            consecutive_resets = n,
            failed = ?prev.last_failure,
            at = ?prev.last_failure_at,
            "last boot ended in a watchdog reset we caused"
        );
        State {
            consecutive_resets: n,
            reset_pending: false,
            ..prev
        }
    } else {
        prev
    }
}

/// Persist "about to stop petting". On failure the state is left not pending,
/// so a later save cannot persist a claim never made.
pub fn arm_reset(
    store: &Store,
    st: &mut State,
    names: Vec<String>,
    at: String,
) -> anyhow::Result<()> {
    st.reset_pending = true;
    st.last_failure = names;
    st.last_failure_at = Some(at);
    let r = store.save(st);
    if r.is_err() {
        st.reset_pending = false;
    }
    r
}

pub fn set_healthy(
    store: &Store,
    st: &mut State,
    since: Option<HealthySince>,
) -> anyhow::Result<()> {
    if st.healthy_since == since {
        return Ok(());
    }
    let next = State {
        healthy_since: since,
        ..st.clone()
    };
    store.save(&next)?;
    *st = next;
    Ok(())
}

/// Repairs between rungs: one fresh bootstrap. A second from the same image
/// cache and config would fail the same way.
pub const MAX_REPAIRS: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    Arm,
    Repair,
    Exhausted,
}

pub fn rung(st: &State, max_resets: u32) -> Rung {
    if max_resets == 0 || st.consecutive_resets < max_resets {
        Rung::Arm
    } else if st.repairs < MAX_REPAIRS {
        Rung::Repair
    } else {
        Rung::Exhausted
    }
}

pub fn begin_repair(
    store: &Store,
    st: &mut State,
    names: Vec<String>,
    at: String,
) -> anyhow::Result<()> {
    let next = State {
        consecutive_resets: 0,
        reset_pending: false,
        repairs: st.repairs.saturating_add(1),
        last_failure: names,
        last_failure_at: Some(at.clone()),
        last_repair_at: Some(at),
        exhausted: false,
        healthy_since: None,
    };
    store.save(&next)?;
    *st = next;
    Ok(())
}

pub fn mark_exhausted(store: &Store, st: &mut State) -> anyhow::Result<()> {
    st.exhausted = true;
    store.save(st)
}

pub fn on_ladder(st: &State) -> bool {
    st.consecutive_resets != 0 || st.repairs != 0 || st.exhausted
}

pub fn recovered(store: &Store, st: &mut State) -> anyhow::Result<()> {
    let cleared = State {
        consecutive_resets: 0,
        repairs: 0,
        exhausted: false,
        ..st.clone()
    };
    store.save(&cleared)?;
    *st = cleared;
    Ok(())
}

/// A due reset whose record cannot be written is deferred (still petting,
/// retrying the write) for up to `patience`, then taken unrecorded: never
/// disabled, and an uncounted loop costs a boot plus `patience` per cycle.
pub struct ResetGate {
    patience: Duration,
    unrecorded_since: Option<Instant>,
    last_logged: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    Proceed,
    ProceedUnrecorded,
    Defer { log: bool, remaining: Duration },
}

impl ResetGate {
    pub fn new(patience: Duration) -> Self {
        Self {
            patience,
            unrecorded_since: None,
            last_logged: None,
        }
    }

    pub fn decide(&mut self, now: Instant, recorded: bool) -> Gate {
        if recorded {
            self.clear();
            return Gate::Proceed;
        }
        let since = *self.unrecorded_since.get_or_insert(now);
        let waited = now.saturating_duration_since(since);
        if waited >= self.patience {
            return Gate::ProceedUnrecorded;
        }
        let log = self
            .last_logged
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(60));
        if log {
            self.last_logged = Some(now);
        }
        Gate::Defer {
            log,
            remaining: self.patience - waited,
        }
    }

    pub fn clear(&mut self) {
        self.unrecorded_since = None;
        self.last_logged = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notdir_store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("file");
        std::fs::write(&f, b"x").unwrap();
        let store = Store::new(&f.join("sub/deeper"));
        (tmp, store)
    }

    /// A store in an empty directory it may not write.
    fn readonly_store() -> Option<(tempfile::TempDir, Store)> {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { nix::libc::geteuid() } == 0 {
            eprintln!("skipped: running as root");
            return None;
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let store = Store::new(tmp.path());
        Some((tmp, store))
    }

    fn record(n: u32, pending: bool) -> State {
        State {
            consecutive_resets: n,
            reset_pending: pending,
            last_failure: vec!["meridian".into()],
            last_failure_at: Some("epoch:1".into()),
            ..State::default()
        }
    }

    #[test]
    fn fold_boot_counts_pending_only() {
        for n in [0u32, 1, 2, 5, u32::MAX] {
            assert_eq!(
                fold_boot(record(n, true)),
                State {
                    consecutive_resets: n.saturating_add(1),
                    ..record(n, false)
                }
            );
            assert_eq!(fold_boot(record(n, false)), record(n, false));
        }
    }

    #[test]
    fn record_round_trips_padded() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        store.save(&record(4, true)).unwrap();
        assert_eq!(store.load(), record(4, true));
        assert!(std::fs::metadata(d.join("state.json")).unwrap().len() >= MIN_RECORD_BYTES as u64);
        assert!(!d.join("state.json.edge-tmp").exists());
    }

    #[test]
    fn unusable_record_counts_as_reset() {
        enum Rec {
            Absent,
            Bytes(&'static [u8]),
            Dir,
        }
        let cases = [
            ("absent", Rec::Absent, false),
            ("empty", Rec::Bytes(b""), true),
            (
                "torn",
                Rec::Bytes(b"{\"consecutive_resets\": 2, \"reset_p"),
                true,
            ),
            ("unreadable", Rec::Dir, true),
        ];
        for (name, rec, counts) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let d = tmp.path();
            let store = Store::new(d);
            match rec {
                Rec::Absent => {}
                Rec::Bytes(b) => std::fs::write(d.join("state.json"), b).unwrap(),
                Rec::Dir => std::fs::create_dir(d.join("state.json")).unwrap(),
            }
            let loaded = store.load();
            assert_eq!(loaded.reset_pending, counts, "{name}");
            assert_eq!(
                fold_boot(loaded).consecutive_resets,
                counts as u32,
                "{name}"
            );
        }
    }

    #[test]
    fn damaged_record_kept_as_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        let torn = b"{\"consecutive_resets\": 2, \"reset_p";
        std::fs::write(d.join("state.json"), torn).unwrap();
        assert!(store.load().reset_pending);
        assert_eq!(std::fs::read(d.join("state.json.corrupt")).unwrap(), torn);
        store.save(&fold_boot(store.load())).unwrap();
        let after = store.load();
        assert!(
            !after.reset_pending && after.consecutive_resets == 1,
            "{after:?}"
        );
    }

    #[test]
    fn record_writes_past_blockers() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        std::fs::create_dir(d.join("state.json")).unwrap();
        store.save(&record(1, false)).unwrap();
        assert_eq!(store.load().consecutive_resets, 1);

        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("state");
        std::fs::write(&f, b"not a directory").unwrap();
        let store = Store::new(&f);
        store.save(&record(2, false)).unwrap();
        assert_eq!(store.load().consecutive_resets, 2);
    }

    #[test]
    fn unrelated_restart_keeps_count() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        let mut st = fold_boot(store.load());
        for _ in 0..2 {
            arm_reset(&store, &mut st, vec!["meridian".into()], "epoch:1".into()).unwrap();
            st = fold_boot(store.load());
            store.save(&st).unwrap();
        }
        st = fold_boot(store.load());
        store.save(&st).unwrap();
        assert_eq!(st.consecutive_resets, 2);
        arm_reset(&store, &mut st, vec!["meridian".into()], "epoch:2".into()).unwrap();
        assert_eq!(fold_boot(store.load()).consecutive_resets, 3);
    }

    #[test]
    fn recovered_persists_or_keeps() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        let mut st = State {
            repairs: 1,
            exhausted: true,
            last_repair_at: Some("epoch:5".into()),
            ..record(2, false)
        };
        recovered(&store, &mut st).unwrap();
        let want = State {
            last_repair_at: Some("epoch:5".into()),
            ..record(0, false)
        };
        assert_eq!((&st, store.load()), (&want, want.clone()));
        assert!(!on_ladder(&st));
        std::fs::remove_dir_all(d).ok();

        let Some((_tmp, store)) = readonly_store() else {
            return;
        };
        let mut st = State {
            repairs: 1,
            ..record(2, false)
        };
        assert!(recovered(&store, &mut st).is_err());
        assert_eq!(
            (st.consecutive_resets, st.repairs),
            (2, 1),
            "a ladder we could not clear is kept"
        );
    }

    #[test]
    fn health_written_on_change_only() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        let mut st = State::default();
        let since = HealthySince {
            boot_id: "b1".into(),
            boottime_secs: 42,
        };
        set_healthy(&store, &mut st, Some(since.clone())).unwrap();
        assert_eq!(store.load().healthy_since, Some(since.clone()));
        std::fs::remove_file(d.join("state.json")).unwrap();
        set_healthy(&store, &mut st, Some(since.clone())).unwrap();
        assert!(
            !d.join("state.json").exists(),
            "unchanged health is not rewritten"
        );
        set_healthy(&store, &mut st, None).unwrap();
        assert_eq!(store.load().healthy_since, None);
        assert_eq!(
            fold_boot(State {
                healthy_since: Some(since),
                ..record(1, false)
            }),
            record(1, false),
            "a new process starts with no health"
        );
        std::fs::remove_dir_all(d).ok();

        let Some((_tmp, store)) = readonly_store() else {
            return;
        };
        let mut st = State::default();
        let since = HealthySince {
            boot_id: "b1".into(),
            boottime_secs: 1,
        };
        assert!(set_healthy(&store, &mut st, Some(since)).is_err());
        assert_eq!(st.healthy_since, None, "an unwritten change is retried");
    }

    #[test]
    fn rung_by_counts() {
        let at = |resets, repairs| State {
            consecutive_resets: resets,
            repairs,
            ..State::default()
        };
        assert_eq!(rung(&at(0, 0), 3), Rung::Arm);
        assert_eq!(rung(&at(2, 0), 3), Rung::Arm);
        assert_eq!(rung(&at(3, 0), 3), Rung::Repair);
        assert_eq!(rung(&at(9, 0), 3), Rung::Repair);
        assert_eq!(rung(&at(2, 1), 3), Rung::Arm);
        assert_eq!(rung(&at(3, 1), 3), Rung::Exhausted);
        assert_eq!(rung(&at(3, 9), 3), Rung::Exhausted);
        assert_eq!(rung(&at(9, 9), 0), Rung::Arm, "zero disables the breaker");
        for s in [
            at(1, 0),
            at(0, 1),
            State {
                exhausted: true,
                ..at(0, 0)
            },
        ] {
            assert!(on_ladder(&s), "{s:?}");
        }
        assert!(!on_ladder(&record(0, true)));
    }

    fn failed_boot(store: &Store, boot: u32) -> Rung {
        let mut st = fold_boot(Store::load(store));
        store.save(&st).unwrap();
        let r = rung(&st, 3);
        let at = format!("epoch:{boot}");
        match r {
            Rung::Arm => arm_reset(store, &mut st, vec!["meridian".into()], at).unwrap(),
            Rung::Repair => begin_repair(store, &mut st, vec!["meridian".into()], at).unwrap(),
            Rung::Exhausted => mark_exhausted(store, &mut st).unwrap(),
        }
        r
    }

    #[test]
    fn ladder_ends_disarmed() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        let steps: Vec<Rung> = (0..20).map(|b| failed_boot(&store, b)).collect();
        let mut want = vec![Rung::Arm; 3];
        want.push(Rung::Repair);
        want.extend([Rung::Arm; 3]);
        want.extend([Rung::Exhausted; 13]);
        assert_eq!(steps, want);
        let end = store.load();
        assert!(end.exhausted && end.repairs == MAX_REPAIRS, "{end:?}");
        assert_eq!(end.last_repair_at.as_deref(), Some("epoch:3"));
    }

    #[test]
    fn recovery_restarts_ladder() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        for b in 0..8 {
            failed_boot(&store, b);
        }
        let mut st = fold_boot(store.load());
        recovered(&store, &mut st).unwrap();
        let steps: Vec<Rung> = (0..4).map(|b| failed_boot(&store, b)).collect();
        assert_eq!(steps, [Rung::Arm, Rung::Arm, Rung::Arm, Rung::Repair]);
    }

    #[test]
    fn cut_after_repair_record_skips_rung() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        let mut st = State {
            consecutive_resets: 3,
            ..State::default()
        };
        begin_repair(&store, &mut st, vec!["store".into()], "epoch:7".into()).unwrap();
        let next = fold_boot(Store::new(d).load());
        assert_eq!((next.consecutive_resets, next.repairs), (0, 1));
        assert_eq!(rung(&next, 3), Rung::Arm);
        assert_eq!(
            rung(
                &State {
                    consecutive_resets: 3,
                    ..next
                },
                3
            ),
            Rung::Exhausted
        );
    }

    #[test]
    fn unwritable_repair_not_taken() {
        let Some((_tmp, store)) = readonly_store() else {
            return;
        };
        let mut st = State {
            consecutive_resets: 3,
            ..State::default()
        };
        assert!(begin_repair(&store, &mut st, vec!["a".into()], "epoch:1".into()).is_err());
        assert_eq!((st.consecutive_resets, st.repairs), (3, 0));
    }

    #[test]
    fn failed_arm_claims_nothing() {
        let (_tmp, store) = notdir_store();
        assert!(store.load().reset_pending, "ENOTDIR is not a first boot");

        let Some((_tmp, store)) = readonly_store() else {
            return;
        };
        let mut st = State::default();
        assert!(arm_reset(&store, &mut st, vec!["a".into()], "epoch:1".into()).is_err());
        assert!(!st.reset_pending);
    }

    #[test]
    fn full_dir_saves_in_place() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { nix::libc::geteuid() } == 0 {
            eprintln!("skipped: running as root");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let store = Store::new(d);
        store
            .save(&State {
                last_failure: (0..40).map(|i| format!("check-number-{i}")).collect(),
                ..State::default()
            })
            .unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut st = State::default();
        let r = arm_reset(&store, &mut st, vec!["meridian".into()], "epoch:9".into());
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        r.expect("the in-place fallback must succeed");
        let back = store.load();
        assert!(back.reset_pending);
        assert_eq!(back.last_failure, vec!["meridian".to_string()]);
    }

    const P: Duration = Duration::from_secs(900);

    #[test]
    fn unrecorded_reset_deferred_then_taken() {
        let mut g = ResetGate::new(P);
        let t = Instant::now();
        let defer = |g: &mut ResetGate, s| match g.decide(t + Duration::from_secs(s), false) {
            Gate::Defer { log, remaining } => (log, remaining.as_secs()),
            other => panic!("{other:?}"),
        };
        assert_eq!(defer(&mut g, 0), (true, 900));
        assert_eq!(defer(&mut g, 10), (false, 890));
        assert_eq!(defer(&mut g, 61), (true, 839));
        assert_eq!(g.decide(t + P, false), Gate::ProceedUnrecorded);
    }

    #[test]
    fn recorded_reset_restarts_patience() {
        let t = Instant::now();
        let mut g = ResetGate::new(P);
        g.decide(t, false);
        assert_eq!(g.decide(t + Duration::from_secs(300), true), Gate::Proceed);
        assert!(matches!(
            g.decide(t + Duration::from_secs(400), false),
            Gate::Defer { log: true, remaining } if remaining == P
        ));
        g.clear();
        assert!(matches!(
            g.decide(t + P + P, false),
            Gate::Defer { log: true, remaining } if remaining == P
        ));
    }
}
