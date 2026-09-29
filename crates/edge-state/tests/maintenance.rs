mod common;

use common::{serve, spawn};
use edge_state::pb::etcdserverpb::{
    AlarmRequest, AlarmType, CompactionRequest, DefragmentRequest, HashKvRequest, HashRequest,
    PutRequest, RangeRequest, SnapshotRequest, StatusRequest, alarm_request::AlarmAction,
    kv_client::KvClient, maintenance_client::MaintenanceClient,
};
use edge_state::server::EtcdServer;
use edge_state::store::Store;

fn put(key: &str, value: &[u8]) -> PutRequest {
    PutRequest {
        key: key.into(),
        value: value.to_vec(),
        ..Default::default()
    }
}

async fn all(kv: &mut KvClient<tonic::transport::Channel>) -> Vec<(Vec<u8>, Vec<u8>, i64)> {
    kv.range(RangeRequest {
        key: vec![0],
        range_end: vec![0],
        ..Default::default()
    })
    .await
    .unwrap()
    .into_inner()
    .kvs
    .into_iter()
    .map(|k| (k.key, k.value, k.mod_revision))
    .collect()
}

#[tokio::test]
async fn status_reports_sizes() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut m = MaintenanceClient::connect(url).await.unwrap();

    let s = m.status(StatusRequest {}).await.unwrap().into_inner();
    let empty_size = s.db_size;
    for i in 0..30 {
        kv.put(put("/churn", &vec![i as u8; 10_000])).await.unwrap();
    }
    let s = m.status(StatusRequest {}).await.unwrap().into_inner();
    let on_disk = std::fs::metadata(dir.path().join("state.log"))
        .unwrap()
        .len() as i64;
    assert_eq!(s.db_size, on_disk, "db_size is the file's size");
    assert!(s.db_size > empty_size + 300_000);
    assert!(s.db_size_in_use <= s.db_size && s.db_size_in_use > 0);
    assert_eq!(s.leader, s.header.as_ref().unwrap().member_id);
    assert!(s.errors.is_empty());

    let head = s.header.unwrap().revision;
    kv.compact(CompactionRequest {
        revision: head,
        physical: true,
    })
    .await
    .unwrap();
    let s = m.status(StatusRequest {}).await.unwrap().into_inner();
    assert!(
        s.db_size_in_use * 5 < s.db_size,
        "after compaction the live data ({}) should be a small part of the file ({})",
        s.db_size_in_use,
        s.db_size
    );
    m.defragment(DefragmentRequest {}).await.unwrap();
    let after = m.status(StatusRequest {}).await.unwrap().into_inner();
    assert!(
        after.db_size * 5 < s.db_size,
        "defragment did not shrink the log: {} -> {}",
        s.db_size,
        after.db_size
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("state.log"))
            .unwrap()
            .len() as i64,
        after.db_size
    );
    assert_eq!(all(&mut kv).await.len(), 1);
    kv.put(put("/after", b"1")).await.unwrap();
}

#[tokio::test]
async fn snapshot_restores_state() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut m = MaintenanceClient::connect(url).await.unwrap();
    for i in 0..12 {
        kv.put(put(&format!("/snap/{i}"), &vec![i as u8; 30_000]))
            .await
            .unwrap();
    }
    let state_at_snapshot = all(&mut kv).await;

    let mut stream = m.snapshot(SnapshotRequest {}).await.unwrap().into_inner();
    let mut blob = Vec::new();
    let mut last_remaining = u64::MAX;
    let mut chunks = 0;
    while let Some(msg) = stream.message().await.unwrap() {
        assert!(
            msg.remaining_bytes < last_remaining,
            "remaining_bytes must fall"
        );
        last_remaining = msg.remaining_bytes;
        blob.extend_from_slice(&msg.blob);
        chunks += 1;
        if chunks == 1 {
            kv.put(put("/after-snapshot", b"x")).await.unwrap();
        }
    }
    assert!(chunks > 3 && last_remaining == 0);

    let restored = common::tempdir();
    std::fs::write(restored.path().join("state.log"), &blob).unwrap();
    let store = Store::open(restored.path().join("state.log")).unwrap();
    let got: Vec<_> = store
        .range_from(&[], 0)
        .into_iter()
        .map(|k| (k.key, k.value, k.mod_revision as i64))
        .collect();
    assert_eq!(got, state_at_snapshot);
}

#[tokio::test]
async fn snapshot_survives_rotation() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut m = MaintenanceClient::connect(url).await.unwrap();
    for i in 0..40 {
        kv.put(put("/one-key", &vec![i as u8; 40_000]))
            .await
            .unwrap();
    }
    let state = all(&mut kv).await;
    let mut stream = m.snapshot(SnapshotRequest {}).await.unwrap().into_inner();
    let first = stream.message().await.unwrap().unwrap();
    let head = kv
        .range(RangeRequest {
            key: b"/one-key".to_vec(),
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
        physical: true,
    })
    .await
    .unwrap();
    m.defragment(DefragmentRequest {}).await.unwrap();
    kv.put(put("/late", b"y")).await.unwrap();

    let mut blob = first.blob;
    while let Some(msg) = stream.message().await.unwrap() {
        blob.extend_from_slice(&msg.blob);
    }
    let d = common::tempdir();
    std::fs::write(d.path().join("state.log"), &blob).unwrap();
    let store = Store::open(d.path().join("state.log")).unwrap();
    let got: Vec<_> = store
        .range_from(&[], 0)
        .into_iter()
        .map(|k| (k.key, k.value, k.mod_revision as i64))
        .collect();
    assert_eq!(got, state);
}

#[tokio::test]
async fn hash_ignores_log_layout() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut m = MaintenanceClient::connect(url).await.unwrap();
    for i in 0..10 {
        kv.put(put(&format!("/h/{}", i % 4), &[i as u8; 100]))
            .await
            .unwrap();
    }
    let h1 = m.hash(HashRequest {}).await.unwrap().into_inner().hash;
    assert_ne!(h1, 0);
    assert_eq!(
        m.hash(HashRequest {}).await.unwrap().into_inner().hash,
        h1,
        "hash is stable"
    );

    let head = m
        .hash_kv(HashKvRequest { revision: 0 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(head.hash, h1);
    assert_eq!(head.compact_revision, 0);

    let rev = kv
        .range(RangeRequest {
            key: b"/h/0".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    kv.compact(CompactionRequest {
        revision: rev,
        physical: true,
    })
    .await
    .unwrap();
    m.defragment(DefragmentRequest {}).await.unwrap();
    assert_eq!(m.hash(HashRequest {}).await.unwrap().into_inner().hash, h1);
    let after = m
        .hash_kv(HashKvRequest { revision: 0 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((after.hash, after.compact_revision), (h1, rev));

    kv.put(put("/h/new", b"x")).await.unwrap();
    assert_ne!(m.hash(HashRequest {}).await.unwrap().into_inner().hash, h1);
    let e = m.hash_kv(HashKvRequest { revision: 1 }).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::OutOfRange);
}

#[tokio::test]
async fn alarms_and_nospace() {
    use edge_state::log::fault::Faults;
    use std::sync::{Arc, Mutex};
    let dir = common::tempdir();
    let faults = Arc::new(Mutex::new(Faults::default()));
    let mut store = Store::open(dir.path().join("state.log")).unwrap();
    store.inject_faults(faults.clone());
    let url = serve(EtcdServer::new(store)).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut m = MaintenanceClient::connect(url).await.unwrap();

    let get = |m: &mut MaintenanceClient<tonic::transport::Channel>| {
        let mut m = m.clone();
        async move {
            m.alarm(AlarmRequest {
                action: AlarmAction::Get as i32,
                member_id: 0,
                alarm: AlarmType::None as i32,
            })
            .await
            .unwrap()
            .into_inner()
            .alarms
        }
    };
    assert!(get(&mut m).await.is_empty());

    let a = m
        .alarm(AlarmRequest {
            action: AlarmAction::Activate as i32,
            member_id: 0,
            alarm: AlarmType::Corrupt as i32,
        })
        .await
        .unwrap()
        .into_inner()
        .alarms;
    assert_eq!(a.len(), 1);
    assert_eq!(get(&mut m).await.len(), 1);
    let s = m.status(StatusRequest {}).await.unwrap().into_inner();
    assert!(
        s.errors.iter().any(|e| e.contains("CORRUPT")),
        "{:?}",
        s.errors
    );
    let gone = m
        .alarm(AlarmRequest {
            action: AlarmAction::Deactivate as i32,
            member_id: 0,
            alarm: AlarmType::Corrupt as i32,
        })
        .await
        .unwrap()
        .into_inner()
        .alarms;
    assert_eq!(gone.len(), 1);
    assert!(get(&mut m).await.is_empty());
    assert!(
        m.alarm(AlarmRequest {
            action: AlarmAction::Activate as i32,
            member_id: 0,
            alarm: AlarmType::None as i32
        })
        .await
        .is_err()
    );

    assert!(
        kv.put(PutRequest {
            lease: 999,
            ..put("/x", b"1")
        })
        .await
        .is_err()
    );
    assert!(
        get(&mut m).await.is_empty(),
        "only a full disk raises an alarm"
    );

    faults.lock().unwrap().bytes_before_enospc = Some(4);
    assert!(kv.put(put("/x", b"1")).await.is_err());
    let alarms = get(&mut m).await;
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].alarm, AlarmType::Nospace as i32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn defragment_loses_nothing() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    for i in 0..60 {
        kv.put(put("/ballast", &vec![i as u8; 50_000]))
            .await
            .unwrap();
    }
    let head = kv
        .range(RangeRequest {
            key: b"/ballast".to_vec(),
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
        physical: true,
    })
    .await
    .unwrap();

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut writers = Vec::new();
    for w in 0..4 {
        let (url, stop) = (url.clone(), stop.clone());
        writers.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            let mut n = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                kv.put(put(
                    &format!("/w/{w}/{}", n % 50),
                    format!("{n}").as_bytes(),
                ))
                .await
                .unwrap();
                n += 1;
            }
            n
        }));
    }
    let mut m = MaintenanceClient::connect(url.clone()).await.unwrap();
    let started = std::time::Instant::now();
    let mut rotations = 0;
    // A minimum number of rotations, not a fixed window: a loaded machine may be slow.
    while (started.elapsed() < std::time::Duration::from_millis(1500) || rotations < 4)
        && started.elapsed() < std::time::Duration::from_secs(60)
    {
        m.defragment(DefragmentRequest {}).await.unwrap();
        rotations += 1;
    }
    assert!(rotations > 3, "only {rotations} rotations in 60 s");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut total = 0;
    for w in writers {
        total += w.await.unwrap();
    }
    assert!(total > 20, "the writers barely ran ({total})");

    let served = all(&mut kv).await;
    let d = common::tempdir();
    std::fs::copy(dir.path().join("state.log"), d.path().join("state.log")).unwrap();
    let store = Store::open_readonly(d.path().join("state.log")).unwrap();
    let on_disk: Vec<_> = store
        .range_from(&[], 0)
        .into_iter()
        .map(|k| (k.key, k.value, k.mod_revision as i64))
        .collect();
    assert_eq!(
        on_disk, served,
        "the log on disk differs from what was served"
    );
}
