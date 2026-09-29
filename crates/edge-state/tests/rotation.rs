mod common;

use common::{Dump, Op, apply, dump, script};
use edge_state::log::RotationStep;
use edge_state::store::Store;
use std::path::{Path, PathBuf};

fn build(path: &Path, ops: &[Op]) -> Store {
    let mut s = Store::open(path).unwrap();
    for op in ops {
        apply(&mut s, op);
    }
    s
}

fn temp_of(path: &Path) -> PathBuf {
    let mut t = path.as_os_str().to_owned();
    t.push(".rot");
    PathBuf::from(t)
}

#[test]
fn rotated_log_replays_identically() {
    for seed in [1u64, 2, 3, 0xBEEF] {
        let dir = tempfile::tempdir().unwrap();
        let (pa, pb) = (dir.path().join("a.log"), dir.path().join("b.log"));
        let first = script(seed, 260);
        let mut rotated = build(&pa, &first);
        let mut unrotated = build(&pb, &first);
        assert!(
            rotated.compact_revision() > 0,
            "the script must compact for this to mean anything"
        );

        let before = rotated.log_len();
        let report = rotated.rotate().unwrap();
        assert_eq!(report.before, before);
        assert!(
            report.after < before,
            "seed {seed}: rotation did not shrink the log ({} -> {})",
            report.before,
            report.after
        );
        assert_eq!(rotated.log_len(), report.after);
        assert_eq!(
            dump(&rotated),
            dump(&unrotated),
            "seed {seed}: state changed by rotating"
        );

        drop(rotated);
        let mut rotated = Store::open(&pa).unwrap();
        assert_eq!(
            dump(&rotated),
            dump(&unrotated),
            "seed {seed}: the rotated log replays differently"
        );

        for op in script(seed + 1000, 120)
            .iter()
            .filter(|o| !matches!(o, Op::Grant(..)))
        {
            // Lease ids would collide between the two scripts.
            let lease_ok =
                !matches!(op, Op::Put(_, _, l) if *l != 0) && !matches!(op, Op::Revoke(_));
            if lease_ok {
                apply(&mut rotated, op);
                apply(&mut unrotated, op);
            }
        }
        assert_eq!(
            dump(&rotated),
            dump(&unrotated),
            "seed {seed}: divergence after rotating"
        );
        drop(rotated);
        let rotated = Store::open(&pa).unwrap();
        assert_eq!(
            dump(&rotated),
            dump(&unrotated),
            "seed {seed}: divergence after reopening the rotated-then-extended log"
        );
    }
}

#[test]
fn rotation_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.log");
    let mut s = build(&p, &script(11, 200));
    let want = dump(&s);
    s.rotate().unwrap();
    let once = s.log_len();
    s.rotate().unwrap();
    assert_eq!(dump(&s), want);
    assert!(
        s.log_len() <= once + 16,
        "a second rotation should not grow the log"
    );
    drop(s);
    assert_eq!(dump(&Store::open(&p).unwrap()), want);
}

#[test]
fn derived_metadata_survives() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.log");
    let mut s = Store::open(&p).unwrap();
    for i in 0..6 {
        s.put(b"/k", format!("v{i}").as_bytes(), 0).unwrap();
    }
    s.put(b"/dead", b"x", 0).unwrap();
    s.delete(b"/dead").unwrap();
    let head = s.revision();
    s.compact(head).unwrap();
    let want = s.get(b"/k", 0).unwrap();
    assert_eq!((want.create_revision, want.version), (2, 6));
    s.rotate().unwrap();
    drop(s);
    let s = Store::open(&p).unwrap();
    assert_eq!(s.get(b"/k", 0).unwrap(), want);
    assert!(s.get(b"/dead", 0).is_none());
    assert_eq!(s.revision(), head);
    assert_eq!(s.compact_revision(), head);
}

#[test]
fn lease_counter_survives_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.log");
    let mut s = Store::open(&p).unwrap();
    let a = s.grant_lease(0, 30).unwrap();
    let b = s.grant_lease(0, 30).unwrap();
    s.revoke_lease(b).unwrap();
    s.rotate().unwrap();
    drop(s);
    let mut s = Store::open(&p).unwrap();
    let c = s.grant_lease(0, 30).unwrap();
    assert!(c > b && c != a, "lease id {c} was reused (a={a}, b={b})");
}

#[test]
fn concurrent_writes_carried_over() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.log");
    let ops = script(21, 150);
    let mut s = build(&p, &ops);
    let mut twin = build(&dir.path().join("twin.log"), &ops);

    let plan = s.begin_rotation().unwrap();
    for op in script(22, 40).iter().filter(|o| {
        !matches!(o, Op::Grant(..) | Op::Revoke(_)) && !matches!(o, Op::Put(_, _, l) if *l != 0)
    }) {
        apply(&mut s, op);
        apply(&mut twin, op);
    }
    let rotated = plan.write().unwrap();
    s.finish_rotation(rotated).unwrap();
    assert_eq!(dump(&s), dump(&twin));
    s.put(b"/after-swap", b"1", 0).unwrap();
    twin.put(b"/after-swap", b"1", 0).unwrap();
    drop(s);
    assert_eq!(dump(&Store::open(&p).unwrap()), dump(&twin));
}

#[test]
fn crash_at_every_step_recovers() {
    for with_delta in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("state.log");
        let temp = temp_of(&live);
        let mut s = build(&live, &script(31, 120));

        let plan = s.begin_rotation().unwrap();
        if with_delta {
            for op in script(32, 30).iter().filter(|o| {
                !matches!(o, Op::Grant(..) | Op::Revoke(_))
                    && !matches!(o, Op::Put(_, _, l) if *l != 0)
            }) {
                apply(&mut s, op);
            }
        }
        let expected: Dump = dump(&s);

        // (step, live bytes then, temp bytes then)
        let snaps =
            std::cell::RefCell::new(Vec::<(RotationStep, Option<Vec<u8>>, Option<Vec<u8>>)>::new());
        let mut hook = |step: RotationStep| {
            snaps
                .borrow_mut()
                .push((step, std::fs::read(&live).ok(), std::fs::read(&temp).ok()));
        };
        let rotated = plan.write_observed(&mut hook).unwrap();
        s.finish_rotation_observed(rotated, &mut hook).unwrap();
        let snaps = snaps.into_inner();
        let steps: Vec<_> = snaps.iter().map(|(s, ..)| *s).collect();
        assert_eq!(
            steps,
            [
                RotationStep::TempWritten,
                RotationStep::DeltaCopied,
                RotationStep::TempSynced,
                RotationStep::Renamed,
                RotationStep::DirSynced
            ]
        );
        assert_eq!(
            dump(&s),
            expected,
            "the live store must be unchanged by rotating"
        );

        let recover = |name: &str, live_bytes: &[u8], temp_bytes: Option<&[u8]>| {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("state.log");
            std::fs::write(&p, live_bytes).unwrap();
            if let Some(t) = temp_bytes {
                std::fs::write(temp_of(&p), t).unwrap();
            }
            let store = Store::open(&p)
                .unwrap_or_else(|e| panic!("with_delta={with_delta}: {name}: open failed: {e:#}"));
            assert_eq!(
                dump(&store),
                expected,
                "with_delta={with_delta}: {name}: recovered the wrong state"
            );
            assert!(
                !temp_of(&p).exists(),
                "{name}: the stale temp was not cleaned up"
            );
            drop(store);
            assert_eq!(
                dump(&Store::open(&p).unwrap()),
                expected,
                "{name}: second boot"
            );
        };

        let live_before_rename = snaps[2].1.clone().unwrap();
        let synced_temp = snaps[2].2.clone().unwrap();
        for (step, live_bytes, temp_bytes) in &snaps {
            match step {
                // Temp partial or unsynced: the old live log is complete; any prefix of the
                // temp may exist, with or without a zero-filled tail.
                RotationStep::TempWritten | RotationStep::DeltaCopied => {
                    let t = temp_bytes.as_ref().unwrap();
                    let stride = (t.len() / 200).max(1);
                    let mut cuts: Vec<usize> = (0..=t.len()).step_by(stride).collect();
                    cuts.extend([t.len(), t.len().saturating_sub(1), 1]);
                    for cut in cuts {
                        recover(
                            &format!("{step:?} temp cut at {cut}"),
                            live_bytes.as_ref().unwrap(),
                            Some(&t[..cut]),
                        );
                        let mut z = t[..cut].to_vec();
                        z.extend([0u8; 300]);
                        recover(
                            &format!("{step:?} temp cut at {cut} + zeros"),
                            live_bytes.as_ref().unwrap(),
                            Some(&z),
                        );
                    }
                }
                RotationStep::TempSynced => {
                    recover(
                        "temp complete, not yet renamed",
                        &live_before_rename,
                        Some(&synced_temp),
                    );
                }
                RotationStep::Renamed => {
                    // Renamed but the directory not fsynced: the old log with the temp beside it...
                    recover(
                        "renamed, old file resurrected",
                        &live_before_rename,
                        Some(&synced_temp),
                    );
                    // ...or the new log alone.
                    recover(
                        "renamed, new file visible",
                        live_bytes.as_ref().unwrap(),
                        None,
                    );
                }
                RotationStep::DirSynced => {
                    recover("dir synced", live_bytes.as_ref().unwrap(), None)
                }
            }
        }
        assert_eq!(std::fs::read(&live).unwrap(), synced_temp);
        assert!(!temp.exists());
    }
}

#[test]
fn failed_rotation_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.log");
    let mut s = build(&p, &script(41, 100));
    let want = dump(&s);
    let before = std::fs::read(&p).unwrap();

    std::fs::create_dir(temp_of(&p)).unwrap();
    assert!(s.rotate().is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    assert_eq!(dump(&s), want);
    std::fs::remove_dir(temp_of(&p)).unwrap();
    s.put(b"/still-alive", b"1", 0).unwrap();
    s.rotate().unwrap();
    assert!(s.get(b"/still-alive", 0).is_some());

    let plan = s.begin_rotation().unwrap();
    assert!(s.begin_rotation().is_err());
    s.abort_rotation(None);
    drop(plan);
    let plan = s.begin_rotation().unwrap();
    s.abort_rotation(Some(plan.write().unwrap()));
    assert!(!temp_of(&p).exists(), "an abandoned temp is removed");
    assert!(s.begin_rotation().is_ok());
}

#[test]
fn rotated_log_stays_locked() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.log");
    let mut s = build(&p, &script(51, 60));
    s.rotate().unwrap();
    let err = Store::open(&p)
        .err()
        .expect("a second writer must be refused after rotation too");
    assert!(format!("{err:#}").contains("locked"), "{err:#}");
    assert_eq!(dump(&Store::open_readonly(&p).unwrap()), dump(&s));
}

#[test]
fn history_after_rotation() {
    use edge_state::history;
    let dir = tempfile::tempdir().unwrap();
    let (pa, pb) = (dir.path().join("a.log"), dir.path().join("b.log"));
    let ops = script(61, 200);
    let mut a = build(&pa, &ops);
    drop(build(&pb, &ops));
    let floor = a.compact_revision();
    assert!(floor > 2);
    a.rotate().unwrap();
    drop(a);
    let a = Store::open_readonly(&pa).unwrap();
    let b = Store::open_readonly(&pb).unwrap();
    assert_eq!(
        history::changes(&a, floor).unwrap(),
        history::changes(&b, floor).unwrap()
    );
    let head = a.revision();
    assert_eq!(
        history::diff(&a, floor, head).unwrap(),
        history::diff(&b, floor, head).unwrap()
    );
    assert_eq!(history::changes(&a, floor - 1), Err(floor));
    assert_eq!(history::diff(&a, floor - 1, head), Err(floor));
}

#[test]
fn large_values_rotate() {
    let dir = common::tempdir();
    let p = dir.path().join("s.log");
    let mut s = Store::open(&p).unwrap();
    for round in 0..4u8 {
        for k in 0..6 {
            s.put(
                format!("/big/{k}").as_bytes(),
                &vec![round + k as u8; 400_000 + k * 1234],
                0,
            )
            .unwrap();
        }
    }
    let head = s.revision();
    s.compact(head - 3).unwrap();
    let want = dump(&s);
    let before = s.log_len();
    s.rotate().unwrap();
    assert!(s.log_len() < before / 2, "{} vs {before}", s.log_len());
    drop(s);
    assert_eq!(dump(&Store::open(&p).unwrap()), want);
}

#[test]
fn rotation_due_when_mostly_dead() {
    let dir = common::tempdir();
    let mut s = Store::open(dir.path().join("s.log")).unwrap();
    s.set_rotation_policy(256 * 1024, 2);
    assert!(!s.rotation_due());
    let chunk = vec![7u8; 16 * 1024];
    for _ in 0..4 {
        s.put(b"/churn", &chunk, 0).unwrap();
    }
    let head = s.revision();
    s.compact(head).unwrap();
    assert!(s.log_len() < 256 * 1024 && !s.rotation_due());
    for i in 0..20 {
        s.put(format!("/live/{i}").as_bytes(), &chunk, 0).unwrap();
    }
    assert!(s.log_len() >= 256 * 1024);
    assert!(
        !s.rotation_due(),
        "a log that is nearly all live data has nothing to reclaim"
    );
    for _ in 0..40 {
        s.put(b"/churn", &chunk, 0).unwrap();
    }
    let head = s.revision();
    s.compact(head).unwrap();
    assert!(
        s.rotation_due(),
        "log {} live {}",
        s.log_len(),
        s.live_bytes()
    );
    s.rotate().unwrap();
    assert!(!s.rotation_due());
    assert!(s.log_len() < s.live_bytes() * 2 && s.live_bytes() > 0);
}
