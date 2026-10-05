mod common;

use common::{Watcher, serve};
use edge_state::log::fault::Faults;
use edge_state::pb::etcdserverpb::{PutRequest, RangeRequest, kv_client::KvClient};
use edge_state::server::EtcdServer;
use edge_state::store::Store;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn put(key: &str, value: Vec<u8>) -> PutRequest {
    PutRequest {
        key: key.into(),
        value,
        ..Default::default()
    }
}

async fn slow_disk(dir: &std::path::Path) -> (String, Arc<Mutex<Faults>>) {
    let faults = Arc::new(Mutex::new(Faults::default()));
    let mut store = Store::open(dir.join("state.log")).unwrap();
    store.inject_faults(faults.clone());
    (serve(EtcdServer::new(store)).await, faults)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_skip_unrelated_fsyncs() {
    let delay = Duration::from_millis(800);
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    kv.put(put("/read", b"before".to_vec())).await.unwrap();
    faults.lock().unwrap().sync_delay = Some(delay);
    let mut writer = kv.clone();
    let write = tokio::spawn(async move { writer.put(put("/other", b"x".to_vec())).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let got = kv
        .range(RangeRequest {
            key: b"/read".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let took = started.elapsed();
    assert_eq!(got.kvs[0].value, b"before");
    assert!(
        took < delay / 4,
        "a read waited {took:?} behind another client's {delay:?} fsync"
    );
    let acked = write.await.unwrap().unwrap().into_inner();
    let after = kv
        .range(RangeRequest {
            key: b"/other".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        after.header.unwrap().revision >= acked.header.unwrap().revision,
        "a read after an acknowledged write did not see it"
    );
    assert_eq!(after.kvs[0].value, b"x");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reads_skip_a_full_batch_fsync() {
    let delay = Duration::from_millis(800);
    let dir = common::tempdir();
    let (url, faults) = slow_disk(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    kv.put(put("/read", b"before".to_vec())).await.unwrap();
    faults.lock().unwrap().sync_delay = Some(delay);
    let mut writers = Vec::new();
    for w in 0..8 {
        let mut kv = kv.clone();
        writers.push(tokio::spawn(async move {
            kv.put(put(&format!("/big/{w}"), vec![b'b'; 1 << 20]))
                .await
                .unwrap();
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    kv.range(RangeRequest {
        key: b"/read".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap();
    let took = started.elapsed();
    assert!(
        took < delay / 4,
        "a read waited {took:?} behind the fsync that makes room in a full batch"
    );
    for w in writers {
        w.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_client_is_measured() {
    use edge_state::metrics::METRICS;
    let dir = common::tempdir();
    let url = common::spawn(dir.path()).await;
    let mut w = Watcher::open(&url, b"/stalled", b"", 0).await;
    let slow_before = METRICS.slow_watch_deliveries.load(Ordering::Relaxed);
    let blocked_before = METRICS.watch_send_blocked_us.load(Ordering::Relaxed);
    let mut kv = KvClient::connect(url).await.unwrap();
    let value = vec![b's'; 16 << 10];
    for _ in 0..600 {
        kv.put(put("/stalled", value.clone())).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut seen = 0;
    while seen < 600 {
        seen += w
            .next_event_within(10.0)
            .await
            .expect("events lost")
            .events
            .len();
    }
    assert!(
        METRICS.slow_watch_deliveries.load(Ordering::Relaxed) > slow_before,
        "a stream held up by its client was not counted as slow"
    );
    assert!(
        METRICS.watch_send_blocked_us.load(Ordering::Relaxed) - blocked_before >= 1_000_000,
        "the time spent waiting on the client was not counted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_on_the_client_port() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = common::tempdir();
    let url = common::spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    kv.range(RangeRequest {
        key: b"/m".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut conn = tokio::net::TcpStream::connect(url.trim_start_matches("http://"))
        .await
        .unwrap();
    conn.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    conn.read_to_string(&mut body).await.unwrap();
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    for want in [
        "grpc_server_handling_seconds_count{grpc_method=\"Range\"}",
        "etcd_disk_wal_fsync_duration_seconds_count",
        "edge_state_watch_delivery_lag_seconds_bucket{le=\"+Inf\"}",
        "etcd_debugging_mvcc_watcher_total",
    ] {
        assert!(body.contains(want), "{want} missing from\n{body}");
    }
}
