mod common;

use common::{Watcher, serve, spawn};
use edge_state::pb::etcdserverpb::{
    CompactionRequest, LeaseGrantRequest, LeaseKeepAliveRequest, PutRequest, RangeRequest,
    WatchRequest, kv_client::KvClient, lease_client::LeaseClient, watch_client::WatchClient,
    watch_request,
};
use edge_state::server::EtcdServer;
use edge_state::store::Store;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn put(key: &str, value: &str) -> PutRequest {
    PutRequest {
        key: key.into(),
        value: value.into(),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progress_never_overtakes_events() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let base = kv
        .put(put("/base", "x"))
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    let mut w = Watcher::open(&url, b"/p/", b"/p0", 0).await;

    let mut writers = Vec::new();
    for t in 0..4 {
        let url = url.clone();
        writers.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            for i in 0..150 {
                kv.put(put(&format!("/p/{t}/{i}"), "v")).await.unwrap();
            }
        }));
    }

    let mut seen: std::collections::BTreeSet<i64> = Default::default();
    let mut progress_checked = 0;
    let mut next_request = 0;
    while seen.len() < 600 {
        if next_request == 0 {
            w.tx.send(WatchRequest {
                request_union: Some(watch_request::RequestUnion::ProgressRequest(
                    Default::default(),
                )),
            })
            .await
            .unwrap();
            next_request = 3;
        }
        next_request -= 1;
        let Some(m) = w.next_within(3.0).await else {
            break;
        };
        for e in &m.events {
            seen.insert(e.kv.as_ref().unwrap().mod_revision);
        }
        if m.watch_id == -1 {
            let claimed = m.header.unwrap().revision;
            let missing: Vec<i64> = (base + 1..=claimed).filter(|r| !seen.contains(r)).collect();
            assert!(
                missing.is_empty(),
                "a progress response claimed revision {claimed} while events {missing:?} had not been delivered"
            );
            progress_checked += 1;
        }
    }
    for h in writers {
        h.await.unwrap();
    }
    assert!(
        progress_checked > 5,
        "the test did not exercise progress responses ({progress_checked})"
    );
}

#[tokio::test]
async fn compacted_watch_is_canceled() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    for i in 0..5 {
        kv.put(put("/k", &format!("v{i}"))).await.unwrap();
    }
    let head = kv
        .range(RangeRequest {
            key: b"/k".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    kv.compact(CompactionRequest {
        revision: head,
        physical: false,
    })
    .await
    .unwrap();

    let mut w = Watcher::open_raw(&url, b"/k", b"", 2).await;
    let created = w.next().await.unwrap();
    assert!(created.created && !created.canceled);
    let cancel = w
        .next_event()
        .await
        .expect("the watch was neither served nor canceled");
    assert!(cancel.canceled, "{cancel:?}");
    assert_eq!(cancel.compact_revision, head);
    assert!(cancel.events.is_empty());

    let mut ok = Watcher::open(&url, b"/k", b"", head + 1).await;
    kv.put(put("/k", "after")).await.unwrap();
    let ev = ok.next_event().await.unwrap();
    assert_eq!(ev.events[0].kv.as_ref().unwrap().value, b"after");
}

#[tokio::test]
async fn future_watch_starts_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let base = kv
        .put(put("/f", "0"))
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    let mut w = Watcher::open(&url, b"/f", b"", base + 3).await;
    kv.put(put("/f", "1")).await.unwrap();
    kv.put(put("/f", "2")).await.unwrap();
    kv.put(put("/f", "3")).await.unwrap();
    let ev = w.next_event().await.unwrap();
    assert_eq!(ev.events.len(), 1);
    assert_eq!(ev.events[0].kv.as_ref().unwrap().mod_revision, base + 3);
}

#[tokio::test]
async fn range_revision_errors_match_etcd() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    let r1 = kv
        .put(put("/a", "1"))
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    kv.put(put("/a", "2")).await.unwrap();
    let head = kv
        .put(put("/b", "1"))
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    kv.compact(CompactionRequest {
        revision: head,
        physical: false,
    })
    .await
    .unwrap();

    let at = |revision| RangeRequest {
        key: b"/".to_vec(),
        range_end: b"0".to_vec(),
        revision,
        ..Default::default()
    };
    let e = kv.range(at(r1)).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::OutOfRange);
    assert_eq!(
        e.message(),
        "etcdserver: mvcc: required revision has been compacted"
    );

    let e = kv.range(at(head + 100)).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::OutOfRange);
    assert_eq!(
        e.message(),
        "etcdserver: mvcc: required revision is a future revision"
    );

    assert_eq!(kv.range(at(head)).await.unwrap().into_inner().kvs.len(), 2);
    assert_eq!(kv.range(at(0)).await.unwrap().into_inner().kvs.len(), 2);

    let e = kv
        .compact(CompactionRequest {
            revision: head + 100,
            physical: false,
        })
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (
            tonic::Code::OutOfRange,
            "etcdserver: mvcc: required revision is a future revision"
        )
    );
    let e = kv
        .compact(CompactionRequest {
            revision: head,
            physical: false,
        })
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (
            tonic::Code::OutOfRange,
            "etcdserver: mvcc: required revision has been compacted"
        )
    );
}

#[tokio::test]
async fn huge_lease_ttl_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut lease = LeaseClient::connect(url.clone()).await.unwrap();
    let mut kv = KvClient::connect(url).await.unwrap();
    for ttl in [i64::MAX, i64::MAX / 2, 9_000_000_001] {
        let e = lease
            .lease_grant(LeaseGrantRequest { ttl, id: 0 })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::OutOfRange, "{ttl}: {e}");
    }
    lease
        .lease_grant(LeaseGrantRequest {
            ttl: 9_000_000_000,
            id: 0,
        })
        .await
        .unwrap();
    lease
        .lease_grant(LeaseGrantRequest {
            ttl: 10,
            id: i64::MAX,
        })
        .await
        .unwrap();
    lease
        .lease_grant(LeaseGrantRequest { ttl: 10, id: 0 })
        .await
        .unwrap();
    kv.put(put("/still", "serving")).await.unwrap();
}

#[tokio::test]
async fn absurd_persisted_ttl_boots() {
    use edge_state::entry::Entry;
    use edge_state::log::Log;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.log");
    {
        let (mut log, _) = Log::open(&path).unwrap();
        for (id, ttl) in [
            (1, i64::MAX),
            (2, -5),
            (3, 0),
            (i64::MAX, 30),
            (5, i64::MIN),
        ] {
            log.append(&Entry::LeaseGrant { id, ttl }.encode(), true)
                .unwrap();
        }
        log.append(
            &Entry::Put {
                revision: 2,
                key: b"/k".to_vec(),
                value: b"v".to_vec(),
                lease: 1,
            }
            .encode(),
            true,
        )
        .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let server = EtcdServer::new(store);
    let url = serve(server).await;
    let mut lease = LeaseClient::connect(url.clone()).await.unwrap();
    let mut kv = KvClient::connect(url).await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(LeaseKeepAliveRequest { id: 1 }).await.unwrap();
    let mut s = lease
        .lease_keep_alive(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let r = s.message().await.unwrap().unwrap();
    assert_eq!(r.id, 1);
    assert_eq!(
        kv.range(RangeRequest {
            key: b"/k".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .len(),
        1
    );
    lease
        .lease_grant(LeaseGrantRequest { ttl: 10, id: 0 })
        .await
        .unwrap();
}

#[tokio::test]
async fn full_disk_recovers() {
    use edge_state::log::fault::Faults;
    use std::sync::Mutex;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.log");
    let faults = Arc::new(Mutex::new(Faults::default()));
    let mut store = Store::open(&path).unwrap();
    store.inject_faults(faults.clone());
    let url = serve(EtcdServer::new(store)).await;
    let mut kv = KvClient::connect(url).await.unwrap();

    kv.put(put("/before", "1")).await.unwrap();
    faults.lock().unwrap().bytes_before_enospc = Some(10);
    let e = kv.put(put("/refused", "2")).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::ResourceExhausted, "{e}");
    assert!(e.message().contains("space exceeded"), "{e}");

    faults.lock().unwrap().bytes_before_enospc = None;
    kv.put(put("/after", "3")).await.unwrap();
    let r = kv
        .range(RangeRequest {
            key: b"/".to_vec(),
            range_end: b"0".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let keys: Vec<_> = r
        .kvs
        .iter()
        .map(|k| String::from_utf8_lossy(&k.key).into_owned())
        .collect();
    assert_eq!(keys, ["/after", "/before"]);

    let reopened = Store::open_readonly(&path).unwrap();
    assert!(reopened.get(b"/before", 0).is_some());
    assert!(
        reopened.get(b"/after", 0).is_some(),
        "an acknowledged write was lost behind the garbage"
    );
    assert!(reopened.get(b"/refused", 0).is_none());
}

#[tokio::test]
async fn failed_fsync_requests_restart() {
    use edge_state::log::fault::Faults;
    use std::sync::Mutex;
    let dir = tempfile::tempdir().unwrap();
    let faults = Arc::new(Mutex::new(Faults::default()));
    let mut store = Store::open(dir.path().join("state.log")).unwrap();
    store.inject_faults(faults.clone());
    let fired = Arc::new(AtomicBool::new(false));
    let f = fired.clone();
    let url =
        serve(EtcdServer::new(store).with_fatal_handler(move || f.store(true, Ordering::SeqCst)))
            .await;
    let mut kv = KvClient::connect(url).await.unwrap();

    kv.put(put("/ok", "1")).await.unwrap();
    faults.lock().unwrap().fail_sync = true;
    let e = kv.put(put("/lost", "2")).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::Unavailable, "{e}");
    assert!(
        fired.load(Ordering::SeqCst),
        "the process was not asked to restart"
    );

    faults.lock().unwrap().fail_sync = false;
    let e = kv.put(put("/after", "3")).await.unwrap_err();
    assert_eq!(
        e.code(),
        tonic::Code::Unavailable,
        "a failed log must stay failed: {e}"
    );
    // "/lost" is in memory but not on disk: no read may reveal it.
    match kv
        .range(RangeRequest {
            key: b"/lost".to_vec(),
            ..Default::default()
        })
        .await
    {
        Ok(r) => assert!(
            r.into_inner().kvs.is_empty(),
            "served a write that is not on disk"
        ),
        Err(e) => assert_eq!(e.code(), tonic::Code::Unavailable, "{e}"),
    }
}

#[tokio::test]
async fn panic_under_lock_is_survived() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.log")).unwrap();
    let server = EtcdServer::new(store);
    let handle = server.store();
    let url = serve(server).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut watch = WatchClient::connect(url.clone()).await.unwrap();
    kv.put(put("/before", "1")).await.unwrap();

    let h = handle.clone();
    let _ = std::thread::spawn(move || {
        let _g = h.lock().unwrap();
        panic!("a handler died holding the store");
    })
    .join();
    assert!(handle.is_poisoned());

    kv.put(put("/after", "2")).await.unwrap();
    assert_eq!(
        kv.range(RangeRequest {
            key: b"/".to_vec(),
            range_end: b"0".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .len(),
        2
    );
    let _ = &mut watch;
    let mut w = Watcher::open(&url, b"/w", b"", 0).await;
    kv.put(put("/w", "x")).await.unwrap();
    assert!(!w.next_event().await.unwrap().events.is_empty());
}
