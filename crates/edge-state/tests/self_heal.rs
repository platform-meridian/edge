mod common;

use common::{Dump, Rng, apply, dump, script};
use edge_state::entry::Entry;
use edge_state::log::{self, Log};
use edge_state::store::Store;
use std::path::Path;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn build(path: &Path, seed: u64, n: usize) -> Vec<(u64, Dump)> {
    let mut s = Store::open(path).unwrap();
    let mut cps = vec![(0, dump(&s))];
    for op in script(seed, n) {
        let before = s.log_len();
        apply(&mut s, &op);
        if s.log_len() > before {
            cps.push((s.log_len(), dump(&s)));
        }
    }
    cps
}

fn assert_usable(path: &Path) {
    let mut s = Store::open(path).unwrap();
    assert!(!s.is_degraded());
    s.put(b"/usable-after-recovery", b"yes", 0).unwrap();
    drop(s);
    let s = Store::open(path).unwrap();
    assert_eq!(s.get(b"/usable-after-recovery", 0).unwrap().value, b"yes");
}

#[test]
fn corrupt_first_record_boots_empty() {
    let d = tmp();
    let p = d.path().join("state.log");
    build(&p, 3, 40);
    common::fill_past_a_batch(&p);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[9] ^= 0xff;
    std::fs::write(&p, &bytes).unwrap();

    let s = Store::open(&p).unwrap();
    assert_eq!((s.revision(), s.log_len()), (1, 0));
    let dmg = s.recovery().damage.as_ref().unwrap();
    assert_eq!(dmg.offset, 0);
    assert!(dmg.dropped_records_at_least > 5);
    assert_eq!(
        std::fs::read(dmg.preserved.as_ref().unwrap()).unwrap(),
        bytes
    );
    let note = std::fs::read_to_string(d.path().join("recovery.json")).unwrap();
    assert!(
        note.contains("\"kind\": \"corrupt_tail\"") && note.contains("\"dropped_bytes\""),
        "{note}"
    );
    drop(s);
    assert_usable(&p);
}

#[test]
fn random_garbage_boots() {
    let mut rng = Rng(0xFEED_FACE_CAFE_BEEF);
    for len in (0..120).step_by(7).chain([500, 4096, 30_000]) {
        let d = tmp();
        let p = d.path().join("state.log");
        let junk: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        std::fs::write(&p, &junk).unwrap();
        let s = Store::open(&p).unwrap_or_else(|e| panic!("{len} random bytes: {e:#}"));
        assert_eq!(s.revision(), 1);
        drop(s);
        assert_usable(&p);
    }
}

#[test]
fn garbage_after_valid_history() {
    let d = tmp();
    let p = d.path().join("state.log");
    let cps = build(&p, 5, 50);
    let bytes = std::fs::read(&p).unwrap();
    let mut rng = Rng(77);
    for junk_len in [1usize, 5, 8, 9, 100, 4000] {
        let junk: Vec<u8> = (0..junk_len).map(|_| rng.next() as u8).collect();
        let mut tail = bytes.clone();
        tail.extend(&junk);
        let q = d.path().join("tail.log");
        std::fs::write(&q, &tail).unwrap();
        assert_eq!(
            dump(&Store::open(&q).unwrap()),
            cps.last().unwrap().1,
            "junk tail {junk_len}"
        );
        let _ = std::fs::remove_file(&q);

        let mid = cps[cps.len() / 2].0 as usize;
        let mut spliced = bytes[..mid].to_vec();
        spliced.extend(&junk);
        spliced.extend(&bytes[mid..]);
        std::fs::write(&q, &spliced).unwrap();
        let s = Store::open(&q).unwrap();
        assert_eq!(
            dump(&s),
            cps[cps.len() / 2].1,
            "junk spliced at {mid}, {junk_len} bytes"
        );
    }
}

#[test]
fn truncated_rotated_log_boots() {
    let d = tmp();
    let p = d.path().join("state.log");
    {
        let mut s = Store::open(&p).unwrap();
        for op in script(11, 60) {
            apply(&mut s, &op);
        }
        s.rotate().unwrap();
    }
    let bytes = std::fs::read(&p).unwrap();
    let stride = (bytes.len() / 300).max(1);
    for cut in (0..=bytes.len()).step_by(stride).chain([bytes.len() - 1]) {
        let q = d.path().join("cut.log");
        std::fs::write(&q, &bytes[..cut]).unwrap();
        Store::open(&q).unwrap_or_else(|e| panic!("rotated log cut at {cut}: {e:#}"));
        let _ = std::fs::remove_file(&q);
    }
}

#[test]
fn leftover_temps_are_discarded() {
    let d = tmp();
    let p = d.path().join("state.log");
    let cps = build(&p, 13, 30);
    let temps = [log::rotation_temp_path(&p)];
    for junk in [
        &b""[..],
        b"\0\0\0\0\0\0\0\0",
        b"not a log at all",
        &std::fs::read(&p).unwrap()[..40],
    ] {
        for t in &temps {
            std::fs::write(t, junk).unwrap();
        }
        let s = Store::open(&p).unwrap();
        assert_eq!(dump(&s), cps.last().unwrap().1);
        assert!(temps.iter().all(|t| !t.exists()));
    }
    for t in &temps {
        std::fs::create_dir(t).unwrap();
        std::fs::write(t.join("x"), b"y").unwrap();
    }
    drop(Store::open(&p).unwrap());
    assert!(temps.iter().all(|t| !t.exists()));
}

#[test]
fn newer_records_are_skipped() {
    let d = tmp();
    let p = d.path().join("state.log");
    let (mut lg, _) = Log::open(&p).unwrap();
    let put = |rev: u64, k: &str, v: &str| {
        Entry::Put {
            revision: rev,
            key: k.into(),
            value: v.into(),
            lease: 0,
        }
        .encode()
    };
    lg.append(&put(2, "/a", "1"), true).unwrap();
    lg.append(&put(3, "/b", "1"), true).unwrap();
    let newer = |tag: u8, rev: u64| {
        let mut rec = vec![tag];
        rec.extend(rev.to_le_bytes());
        rec.extend(b"a payload in a format from the future");
        rec
    };
    lg.append(&newer(200, 4), true).unwrap();
    lg.append(&newer(200, 5), true).unwrap();
    lg.append(&put(6, "/a", "2"), true).unwrap();
    lg.append(&newer(201, 9), true).unwrap();
    lg.append(&newer(201, 1), true).unwrap();
    lg.append(&newer(201, 1 << 40), true).unwrap();
    drop(lg);
    let before = std::fs::read(&p).unwrap();

    let mut s = Store::open(&p).unwrap();
    assert_eq!(
        s.get(b"/a", 0).unwrap().value,
        b"2",
        "the known record AFTER the unknown ones was kept"
    );
    assert_eq!(s.get(b"/b", 0).unwrap().value, b"1");
    let r = s.recovery();
    assert_eq!((r.skipped_records, r.first_skipped_at), (5, Some(64)));
    assert_eq!(
        s.revision(),
        9,
        "skipped records' revisions are not reused; implausible hints are ignored"
    );
    assert_eq!(std::fs::read(&p).unwrap(), before);
    assert!(
        d.path()
            .read_dir()
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".undecodable-"))
    );
    assert!(
        std::fs::read_to_string(d.path().join("recovery.json"))
            .unwrap()
            .contains("undecodable_records")
    );

    let (rev, _) = s.put(b"/c", b"new", 0).unwrap();
    assert_eq!(rev, 10);
    drop(s);
    let s = Store::open(&p).unwrap();
    assert_eq!(s.get(b"/c", 0).unwrap().mod_revision, rev);
    assert_eq!(s.get(b"/a", 0).unwrap().value, b"2");
}

#[test]
fn rotation_after_rollback_keeps_evidence() {
    let d = tmp();
    let p = d.path().join("state.log");
    {
        let (mut lg, _) = Log::open(&p).unwrap();
        lg.append(
            &Entry::Put {
                revision: 2,
                key: b"/a".to_vec(),
                value: b"1".to_vec(),
                lease: 0,
            }
            .encode(),
            true,
        )
        .unwrap();
        lg.append(&[222, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3], true)
            .unwrap();
    }
    let mut s = Store::open(&p).unwrap();
    s.rotate().unwrap();
    assert_eq!(s.get(b"/a", 0).unwrap().value, b"1");
    drop(s);
    let s = Store::open(&p).unwrap();
    assert_eq!(
        s.recovery().skipped_records,
        0,
        "the rewritten log holds only what can be read"
    );
    assert!(s.revision() >= 3);
    assert!(
        d.path()
            .read_dir()
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".undecodable-"))
    );
}

#[test]
fn inconsistent_records_are_ignored() {
    let d = tmp();
    let p = d.path().join("state.log");
    {
        let (mut lg, _) = Log::open(&p).unwrap();
        let mut w = |e: Entry| lg.append(&e.encode(), true).unwrap();
        w(Entry::Put {
            revision: 5,
            key: b"/k".to_vec(),
            value: b"v5".to_vec(),
            lease: 0,
        });
        w(Entry::Put {
            revision: 3,
            key: b"/k".to_vec(),
            value: b"went-backwards".to_vec(),
            lease: 0,
        });
        w(Entry::Put {
            revision: 5,
            key: b"/k".to_vec(),
            value: b"same-revision".to_vec(),
            lease: 0,
        });
        w(Entry::Put {
            revision: u64::MAX,
            key: b"/huge".to_vec(),
            value: b"x".to_vec(),
            lease: 0,
        });
        w(Entry::Compaction {
            compact_revision: u64::MAX,
        });
        w(Entry::Compaction {
            compact_revision: 900,
        });
        w(Entry::Base {
            revision: 4,
            compact_revision: 1 << 40,
            next_lease: i64::MAX,
        });
        w(Entry::Delete {
            revision: 2,
            key: b"/k".to_vec(),
        });
        w(Entry::LeaseGrant {
            id: 7,
            ttl: i64::MIN,
        });
        w(Entry::LeaseRevoke { id: 12345 });
        w(Entry::Revoke {
            id: 999,
            revision: u64::MAX,
            keys: vec![b"/k".to_vec()],
        });
        w(Entry::PutWithMeta {
            revision: 6,
            key: b"/abs".to_vec(),
            value: b"a".to_vec(),
            lease: 0,
            create_revision: 2,
            version: i64::MAX,
        });
        w(Entry::Put {
            revision: 7,
            key: b"/abs".to_vec(),
            value: b"b".to_vec(),
            lease: 0,
        }); // version would overflow
    }
    let mut s = Store::open(&p).unwrap();
    assert_eq!(s.get(b"/k", 0).unwrap().value, b"v5");
    assert!(s.get(b"/huge", 0).is_none());
    assert!(
        s.recovery().contradictory_records >= 5,
        "{:?}",
        s.recovery()
    );
    let note = std::fs::read_to_string(d.path().join("recovery.json")).unwrap();
    assert!(
        note.contains("\"kind\": \"inconsistent_records\""),
        "{note}"
    );
    assert!(s.compact_revision() <= s.revision());
    assert!(s.check_revision(0).is_ok());
    s.put(b"/next", b"1", 0).unwrap();
    s.grant_lease(0, 10).unwrap();
    s.compact(s.revision()).unwrap();
    drop(s);
    Store::open(&p).unwrap();
}

#[test]
fn directory_at_log_path_moved_aside() {
    let d = tmp();
    let p = d.path().join("state.log");
    std::fs::create_dir(&p).unwrap();
    std::fs::write(p.join("junk"), b"x").unwrap();
    assert_usable(&p);
    let aside: Vec<_> = d
        .path()
        .read_dir()
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("state.log.notafile-")
        })
        .collect();
    assert_eq!(aside.len(), 1);
    assert_eq!(std::fs::read(aside[0].path().join("junk")).unwrap(), b"x");
}

#[test]
fn missing_data_dir_is_created() {
    let d = tmp();
    let p = d.path().join("does/not/exist/yet/state.log");
    assert_usable(&p);
}

#[test]
fn unwritable_log_degrades_and_recovers() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp();
    let p = d.path().join("state.log");
    let cps = build(&p, 21, 30);
    let want = cps.last().unwrap().1.clone();

    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let running_as_root = std::fs::OpenOptions::new().write(true).open(&p).is_ok();
    let mut s = Store::open(&p).unwrap();
    if !running_as_root {
        assert!(s.is_degraded(), "an unwritable log must come up degraded");
        assert_eq!(dump(&s), want, "and still serve everything it holds");
        let err = s.put(b"/x", b"1", 0).unwrap_err();
        assert!(
            matches!(
                err,
                edge_state::store::StoreError::Log(edge_state::log::LogError::Degraded(_))
            ),
            "{err}"
        );
        assert!(
            !s.try_recover().unwrap(),
            "still unwritable: recovery must say so, not fail"
        );

        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(s.try_recover().unwrap());
        assert!(!s.is_degraded());
        assert_eq!(dump(&s), want);
        s.put(b"/x", b"1", 0).unwrap();
    }
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn uncreatable_data_dir_recovers() {
    let d = tmp();
    let blocker = d.path().join("data");
    std::fs::write(&blocker, b"a FILE where the data directory belongs").unwrap();
    let p = blocker.join("state.log");
    let mut s = Store::open(&p).unwrap();
    assert!(s.is_degraded());
    assert!(s.put(b"/x", b"1", 0).is_err());
    assert!(!s.try_recover().unwrap());
    std::fs::remove_file(&blocker).unwrap();
    assert!(s.try_recover().unwrap());
    s.put(b"/x", b"1", 0).unwrap();
}

#[test]
fn full_disk_at_boot_recovers() {
    let d = tmp();
    let p = d.path().join("state.log");
    let mut s = Store::degraded(&p, true, "No space left on device");
    assert!(s.is_degraded() && s.put(b"/x", b"1", 0).unwrap_err().is_disk_full());
    for name in [
        "state.log.corrupt-1",
        "state.log.undecodable-9",
        "state.log.notafile-3",
    ] {
        std::fs::write(d.path().join(name), vec![0u8; 1000]).unwrap();
    }
    assert!(s.try_recover().unwrap());
    assert!(!d.path().join("state.log.corrupt-1").exists());
    s.put(b"/x", b"1", 0).unwrap();
}

#[test]
fn reclaim_drops_evidence_and_rotates() {
    let d = tmp();
    let p = d.path().join("state.log");
    let mut s = Store::open(&p).unwrap();
    for i in 0..40u8 {
        s.put(b"/churn", &[i; 2000], 0).unwrap();
    }
    let head = s.revision();
    s.compact(head).unwrap();
    std::fs::write(d.path().join("state.log.corrupt-1"), vec![0u8; 5000]).unwrap();
    let before = s.log_len();
    let freed = s.reclaim_space();
    assert!(freed >= 5000 + before / 2, "freed {freed} of {before}");
    assert!(!d.path().join("state.log.corrupt-1").exists());
    assert!(s.log_len() < before / 4);
    s.put(b"/still-works", b"1", 0).unwrap();
}

#[test]
fn held_lock_is_waited_for() {
    let d = tmp();
    let p = d.path().join("state.log");
    let holder = Store::open(&p).unwrap();
    assert!(
        Store::open(&p).is_err(),
        "the primitive still reports the lock"
    );

    let p2 = p.clone();
    let waiter = std::thread::spawn(move || {
        Store::open_patiently_for(&p2, Some(std::time::Duration::from_secs(20)))
    });
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(
        !waiter.is_finished(),
        "must still be waiting while the lock is held"
    );
    drop(holder);
    let s = waiter
        .join()
        .unwrap()
        .expect("must take over once the lock is released");
    assert!(!s.is_degraded());
}

#[test]
fn restart_after_failed_fsync_boots() {
    use edge_state::log::fault::Faults;
    use std::sync::{Arc, Mutex};
    for partial in [None, Some(3usize), Some(8), Some(15), Some(40)] {
        let d = tmp();
        let p = d.path().join("state.log");
        let mut s = Store::open(&p).unwrap();
        s.put(b"/before", b"1", 0).unwrap();
        let faults = Arc::new(Mutex::new(Faults::default()));
        s.inject_faults(faults.clone());
        {
            let mut f = faults.lock().unwrap();
            match partial {
                None => f.fail_sync = true,
                Some(n) => {
                    f.bytes_before_enospc = Some(n);
                    f.fail_set_len = true;
                }
            }
        }
        let err = s.put(b"/lost-or-not", b"2", 0).unwrap_err();
        assert!(err.is_fatal() && s.is_failed(), "{err}");
        assert!(
            s.put(b"/after", b"3", 0).is_err(),
            "a failed log stays failed"
        );
        drop(s);

        let s = Store::open(&p)
            .unwrap_or_else(|e| panic!("restart after failed fsync ({partial:?}) refused: {e:#}"));
        assert_eq!(s.get(b"/before", 0).unwrap().value, b"1");
        assert!(s.get(b"/after", 0).is_none());
        drop(s);
        assert_usable(&p);
    }
}

#[tokio::test]
async fn degraded_store_codes_and_heals() {
    use edge_state::pb::etcdserverpb::{PutRequest, RangeRequest, kv_client::KvClient};
    use edge_state::server::EtcdServer;
    let put = |k: &str| PutRequest {
        key: k.into(),
        value: b"v".to_vec(),
        ..Default::default()
    };

    for (disk_full, want) in [
        (true, tonic::Code::ResourceExhausted),
        (false, tonic::Code::Unavailable),
    ] {
        let d = tmp();
        let blocker = d.path().join("data");
        std::fs::write(&blocker, b"in the way").unwrap();
        let store = Store::degraded(blocker.join("state.log"), disk_full, "injected");
        let server = EtcdServer::new(store);
        server.spawn_log_recovery();
        let url = common::serve(server).await;
        let mut kv = KvClient::connect(url.clone()).await.unwrap();
        let mut watch = common::Watcher::open(&url, b"/y", b"", 0).await;

        assert!(
            kv.range(RangeRequest {
                key: b"/x".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .kvs
            .is_empty()
        );
        let e = kv.put(put("/x")).await.unwrap_err();
        assert_eq!(e.code(), want, "{e}");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            kv.put(put("/x")).await.is_err(),
            "the fault is still there; writes must still be refused"
        );

        std::fs::remove_file(&blocker).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
        loop {
            match kv.put(put("/x")).await {
                Ok(_) => break,
                Err(e) => {
                    assert!(std::time::Instant::now() < deadline, "never recovered: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        }
        assert_eq!(
            kv.range(RangeRequest {
                key: b"/x".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .kvs
            .len(),
            1
        );
        // Watches still hear of writes as they become durable, not at the next progress tick.
        kv.put(put("/y")).await.unwrap();
        let m = watch
            .next_within(1.0)
            .await
            .expect("no event after healing");
        assert_eq!(m.events[0].kv.as_ref().unwrap().key, b"/y");
    }
}
