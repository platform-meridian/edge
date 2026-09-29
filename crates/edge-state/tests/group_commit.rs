mod common;

use common::{Watcher, serve};
use edge_state::log::fault::Faults;
use edge_state::pb::etcdserverpb::{
    DefragmentRequest, PutRequest, kv_client::KvClient, maintenance_client::MaintenanceClient,
};
use edge_state::server::EtcdServer;
use edge_state::store::Store;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn put(key: &str, value: &str) -> PutRequest {
    PutRequest {
        key: key.into(),
        value: value.into(),
        ..Default::default()
    }
}

async fn slow_disk(
    dir: &std::path::Path,
    sync_delay: Duration,
    images: bool,
) -> (String, Arc<Mutex<Faults>>) {
    let faults = Arc::new(Mutex::new(Faults {
        sync_delay: Some(sync_delay),
        keep_sync_images: images,
        ..Default::default()
    }));
    let mut store = Store::open(dir.join("state.log")).unwrap();
    store.inject_faults(faults.clone());
    (serve(EtcdServer::new(store)).await, faults)
}

struct Ack {
    key: String,
    value: String,
    revision: u64,
    syncs_at_ack: usize,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writers_share_fsyncs() {
    const WRITERS: usize = 16;
    const EACH: usize = 12;
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path(), Duration::from_millis(5), true).await;
    let mut tasks = Vec::new();
    for w in 0..WRITERS {
        let (url, faults) = (url.clone(), faults.clone());
        tasks.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            let mut acks = Vec::new();
            for i in 0..EACH {
                let (key, value) = (format!("/w{w}/{i}"), format!("v{w}.{i}"));
                let r = kv.put(put(&key, &value)).await.unwrap().into_inner();
                let synced = faults.lock().unwrap().syncs_completed;
                acks.push(Ack {
                    key,
                    value,
                    revision: r.header.unwrap().revision as u64,
                    syncs_at_ack: synced,
                });
            }
            acks
        }));
    }
    let mut acks = Vec::new();
    for t in tasks {
        acks.extend(t.await.unwrap());
    }
    let writes = WRITERS * EACH;
    let (syncs, images) = {
        let mut f = faults.lock().unwrap();
        (f.syncs_completed, std::mem::take(&mut f.image_at_each_sync))
    };
    assert!(
        syncs * 3 < writes,
        "{syncs} fsyncs for {writes} concurrent writes: they are not shared"
    );

    let by_rev: BTreeMap<u64, &Ack> = acks.iter().map(|a| (a.revision, a)).collect();
    assert_eq!(by_rev.len(), writes, "two writes shared a revision");
    let crash = common::tempdir();
    let path = crash.path().join("state.log");
    for (j, image) in images.iter().enumerate() {
        std::fs::write(&path, image).unwrap();
        let s = Store::open(&path).unwrap();
        for a in &acks {
            let got = s.get(a.key.as_bytes(), 0);
            if a.revision <= s.revision() {
                assert_eq!(
                    got.map(|kv| kv.value),
                    Some(a.value.clone().into_bytes()),
                    "crash after fsync {j}: not a prefix; {} (rev {}) is wrong",
                    a.key,
                    a.revision
                );
            } else {
                assert!(
                    got.is_none(),
                    "crash after fsync {j}: a hole before {}",
                    a.key
                );
            }
            assert!(
                a.syncs_at_ack > j + 1 || a.revision <= s.revision(),
                "crash after fsync {j}: {} was acknowledged when {} fsyncs had completed, and is lost",
                a.key,
                a.syncs_at_ack
            );
        }
        drop(s);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lone_writer_waits_one_fsync() {
    let delay = Duration::from_millis(250);
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path(), delay, false).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    kv.put(put("/warm", "x")).await.unwrap();
    let before = faults.lock().unwrap().syncs_completed;
    let mut took = Vec::new();
    for i in 0..9 {
        let t = Instant::now();
        kv.put(put(&format!("/lone/{i}"), "v")).await.unwrap();
        took.push(t.elapsed());
    }
    took.sort();
    assert_eq!(
        faults.lock().unwrap().syncs_completed - before,
        9,
        "each lone write gets its own fsync"
    );
    assert!(
        took[4] >= delay && took[4] < 2 * delay,
        "median lone write took {:?} with a {delay:?} fsync",
        took[4]
    );
}

async fn seen(w: &mut Watcher, value: &str) -> Instant {
    loop {
        let m = w
            .next_event_within(60.0)
            .await
            .expect("the probe's event never came");
        if m.events
            .iter()
            .any(|e| e.kv.as_ref().unwrap().value == value.as_bytes())
        {
            return Instant::now();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn watches_hear_before_writer() {
    let delay = Duration::from_millis(150);
    let dir = common::tempdir();
    let (url, _faults) = slow_disk(dir.path(), delay, false).await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut noise = Vec::new();
    for w in 0..8 {
        let (url, stop) = (url.clone(), stop.clone());
        noise.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            let mut i = 0u64;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                kv.put(put(&format!("/noise/{w}"), &i.to_string()))
                    .await
                    .unwrap();
                i += 1;
            }
        }));
    }
    let mut a = Watcher::open(&url, b"/probe", b"", 0).await;
    let mut b = Watcher::open(&url, b"/probe", b"", 0).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let (mut lag, mut skew) = (Vec::new(), Vec::new());
    for i in 0..15 {
        let value = i.to_string();
        let writer = async {
            kv.put(put("/probe", &value)).await.unwrap();
            Instant::now()
        };
        let (ta, tb, answered) = tokio::join!(seen(&mut a, &value), seen(&mut b, &value), writer);
        lag.push(ta.max(tb).saturating_duration_since(answered));
        skew.push(if ta > tb { ta - tb } else { tb - ta });
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    for n in noise {
        n.await.unwrap();
    }
    kv.put(put("/done", "x")).await.unwrap();
    lag.sort();
    skew.sort();
    let (lag90, skew90) = (lag[13], skew[13]);
    assert!(
        lag90 < delay / 2,
        "events arrived {lag90:?} after the write was answered (p90), fsync {delay:?}: {lag:?}"
    );
    assert!(
        skew90 < delay / 2,
        "two streams saw one event {skew90:?} apart (p90), fsync {delay:?}: {skew:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn rotation_during_commits_keeps_acks() {
    let dir = common::tempdir();
    let (url, _faults) = slow_disk(dir.path(), Duration::from_millis(2), false).await;
    let mut tasks = Vec::new();
    for w in 0..8 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            let mut acked = Vec::new();
            for i in 0..40 {
                let key = format!("/r{w}/{}", i % 5);
                let r = kv.put(put(&key, &i.to_string())).await.unwrap();
                acked.push((key, i.to_string(), r.into_inner().header.unwrap().revision));
            }
            acked
        }));
    }
    let mut m = MaintenanceClient::connect(url.clone()).await.unwrap();
    for _ in 0..6 {
        m.defragment(DefragmentRequest {}).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let mut latest: BTreeMap<String, (String, i64)> = BTreeMap::new();
    let mut revs = Vec::new();
    for t in tasks {
        for (k, v, r) in t.await.unwrap() {
            revs.push(r);
            latest.insert(k, (v, r));
        }
    }
    revs.sort();
    revs.dedup();
    assert_eq!(revs.len(), 320);
    assert_eq!(revs[319] - revs[0], 319, "revisions are not contiguous");

    let s = Store::open_readonly(dir.path().join("state.log")).unwrap();
    assert_eq!(s.revision() as i64, revs[319]);
    for (k, (v, r)) in latest {
        let kv = s.get(k.as_bytes(), 0).unwrap();
        assert_eq!(
            (kv.value, kv.mod_revision as i64),
            (v.into_bytes(), r),
            "{k}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_fsync_rotated_log() {
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path(), Duration::ZERO, false).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    kv.put(put("/before", "1")).await.unwrap();
    MaintenanceClient::connect(url)
        .await
        .unwrap()
        .defragment(DefragmentRequest {})
        .await
        .unwrap();
    let replaced = faults.lock().unwrap().syncs_started;
    faults.lock().unwrap().fail_sync = true;
    for i in 0..3 {
        kv.put(put(&format!("/after/{i}"), "v")).await.unwrap();
    }
    assert_eq!(faults.lock().unwrap().syncs_started, replaced);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reopened_watch_starts_at_head() {
    let dir = common::tempdir();
    {
        let mut s = Store::open(dir.path().join("state.log")).unwrap();
        for i in 0..5 {
            s.put(b"/k", i.to_string().as_bytes(), 0).unwrap();
        }
    }
    let url = common::spawn(dir.path()).await;
    let mut w = Watcher::open_raw(&url, b"/k", b"", 0).await;
    let created = w.next().await.unwrap();
    assert!(created.created);
    assert_eq!(created.header.unwrap().revision, 6);
    assert!(w.next_within(0.5).await.is_none(), "history was replayed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compaction_waits_for_durability() {
    use edge_state::pb::etcdserverpb::CompactionRequest;
    let delay = Duration::from_millis(300);
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path(), Duration::ZERO, false).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    for i in 0..4 {
        kv.put(put("/k", &i.to_string())).await.unwrap();
    }
    faults.lock().unwrap().sync_delay = Some(delay);
    let started = Instant::now();
    let compact = tokio::spawn(async move {
        kv.compact(CompactionRequest {
            revision: 4,
            physical: false,
        })
        .await
        .unwrap();
    });
    tokio::time::sleep(delay / 4).await;
    let mut w = Watcher::open_raw(&url, b"/k", b"", 2).await;
    loop {
        let m = w.next().await.expect("the watch was never cancelled");
        if m.canceled {
            assert_eq!(m.compact_revision, 4);
            break;
        }
    }
    assert!(
        started.elapsed() >= delay,
        "cancelled {:?} into a {delay:?} fsync",
        started.elapsed()
    );
    compact.await.unwrap();
}

fn frame_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Ok(f) = edge_state::record::decode(&bytes[at..]) {
        out.push((at, at + f.total_len));
        at += f.total_len;
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reordered_crash_is_quiet_tail() {
    const WRITERS: usize = 16;
    const EACH: usize = 5;
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path(), Duration::from_millis(20), false).await;
    let mut tasks = Vec::new();
    for w in 0..WRITERS {
        let (url, faults) = (url.clone(), faults.clone());
        tasks.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            let pad = if w % 2 == 0 { 600 << 10 } else { 10 };
            let mut acks = Vec::new();
            for i in 0..EACH {
                let key = format!("/w{w}/{i}");
                let value = format!("v{w}.{i}{}", "x".repeat(pad));
                let r = kv.put(put(&key, &value)).await.unwrap().into_inner();
                let synced = faults.lock().unwrap().syncs_completed;
                acks.push(Ack {
                    key,
                    value,
                    revision: r.header.unwrap().revision as u64,
                    syncs_at_ack: synced,
                });
            }
            acks
        }));
    }
    let mut acks = Vec::new();
    for t in tasks {
        acks.extend(t.await.unwrap());
    }
    let (syncs, lens) = {
        let mut f = faults.lock().unwrap();
        (f.syncs_completed, std::mem::take(&mut f.len_at_each_sync))
    };
    assert!(
        syncs * 2 < WRITERS * EACH,
        "{syncs} fsyncs: they are not shared"
    );

    let written = std::fs::read(dir.path().join("state.log")).unwrap();
    let frames = frame_spans(&written);
    let crash = common::tempdir();
    let path = crash.path().join("state.log");
    let mut kept_behind_a_loss = 0;
    for (j, pair) in lens.windows(2).enumerate() {
        // Durable: at least what fsync j covered. Written by the time fsync j+1
        // completes: at least what it covers. Lose the first record after the one,
        // keep every whole record up to the other.
        let (synced, next) = (pair[0] as usize, pair[1] as usize);
        let batch: Vec<_> = frames
            .iter()
            .filter(|&&(s, e)| s >= synced && e <= next)
            .collect();
        let Some(&&(lost, lost_end)) = batch.first() else {
            continue;
        };
        let end = batch.last().unwrap().1;
        kept_behind_a_loss += usize::from(end > lost_end);
        let mut image = written[..end].to_vec();
        image[lost..lost_end].fill(0);
        std::fs::write(&path, &image).unwrap();
        let s = Store::open(&path).unwrap();
        assert!(
            s.recovery().damage.is_none(),
            "crash after fsync {j}: an unsynced tail reported as damage: {:?}",
            s.recovery().damage
        );
        assert_eq!(s.recovery().torn_bytes, (end - lost) as u64);
        assert_eq!(s.log_len(), lost as u64);
        for a in &acks {
            assert!(
                a.syncs_at_ack > j + 1 || a.revision <= s.revision(),
                "crash after fsync {j}: {} was acknowledged when {} fsyncs had completed, and is lost",
                a.key,
                a.syncs_at_ack
            );
        }
        drop(s);
        let others: Vec<_> = crash
            .path()
            .read_dir()
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "state.log" && n != "state.log.tail")
            .collect();
        assert!(others.is_empty(), "crash after fsync {j}: left {others:?}");
        assert_eq!(
            std::fs::read(edge_state::log::tail_copy_path(&path)).unwrap(),
            &image[lost..],
            "crash after fsync {j}: the cut bytes were not kept"
        );
    }
    assert!(
        kept_behind_a_loss > 0,
        "no batch held two records: the crashes tested nothing"
    );
}
