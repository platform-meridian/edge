mod common;

use common::{Rng, Watcher, spawn};
use edge_state::pb::etcdserverpb::{
    Compare, DeleteRangeRequest, PutRequest, RangeRequest, RequestOp, TxnRequest, compare,
    kv_client::KvClient, request_op,
};
use edge_state::pb::mvccpb;
use std::collections::BTreeMap;

const WRITERS: usize = 8;
const PER_WRITER: usize = 150;

fn compare_mod(key: &[u8], rev: i64) -> Compare {
    Compare {
        result: compare::CompareResult::Equal as i32,
        target: compare::CompareTarget::Mod as i32,
        key: key.to_vec(),
        target_union: Some(compare::TargetUnion::ModRevision(rev)),
        range_end: vec![],
    }
}

fn put_op(key: &[u8], value: &[u8]) -> RequestOp {
    RequestOp {
        request: Some(request_op::Request::RequestPut(PutRequest {
            key: key.to_vec(),
            value: value.to_vec(),
            ..Default::default()
        })),
    }
}

/// Each event's `prev_kv` must match the mirror, so a duplicated, dropped or reordered
/// event shows at once.
#[derive(Default)]
struct Mirror {
    kvs: BTreeMap<Vec<u8>, (Vec<u8>, i64)>,
    last_rev: i64,
    events: usize,
}

impl Mirror {
    fn apply(&mut self, e: &mvccpb::Event) {
        let kv = e.kv.as_ref().unwrap();
        assert!(
            kv.mod_revision > self.last_rev,
            "event at revision {} after {} — duplicate or out of order",
            kv.mod_revision,
            self.last_rev
        );
        self.last_rev = kv.mod_revision;
        self.events += 1;
        let prev = self.kvs.get(&kv.key).cloned();
        match (&e.prev_kv, prev) {
            (None, None) => {}
            (Some(p), Some((v, r))) => {
                assert_eq!(
                    (&p.value, p.mod_revision),
                    (&v, r),
                    "prev_kv disagrees with the mirror for {:?}",
                    kv.key
                )
            }
            (a, b) => panic!(
                "prev_kv {a:?} vs mirror {b:?} for key {:?} at {}",
                kv.key, kv.mod_revision
            ),
        }
        if e.r#type == mvccpb::event::EventType::Delete as i32 {
            self.kvs.remove(&kv.key);
        } else {
            self.kvs
                .insert(kv.key.clone(), (kv.value.clone(), kv.mod_revision));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watchers_reconstruct_store() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();

    for i in 0..10 {
        kv.put(PutRequest {
            key: format!("/m/k{}", i % 5).into_bytes(),
            value: vec![i as u8],
            ..Default::default()
        })
        .await
        .unwrap();
    }

    let list = |mut kv: KvClient<tonic::transport::Channel>| async move {
        let r = kv
            .range(RangeRequest {
                key: b"/m/".to_vec(),
                range_end: b"/m0".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let rev = r.header.unwrap().revision;
        let mut mirror = Mirror::default();
        for k in r.kvs {
            mirror.kvs.insert(k.key, (k.value, k.mod_revision));
        }
        mirror.last_rev = rev;
        (mirror, rev)
    };
    let (mut early_mirror, early_rev) = list(kv.clone()).await;
    let mut early = Watcher::open(&url, b"/m/", b"/m0", early_rev + 1).await;
    let (mut late_mirror, list_rev) = list(kv.clone()).await;
    let mut late = Watcher::open(&url, b"/m/", b"/m0", list_rev + 1).await;

    let mut writers = Vec::new();
    for w in 0..WRITERS {
        let url = url.clone();
        writers.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ ((w as u64 + 1) * 0x1234_5678_9ABC_DEF1));
            for n in 0..PER_WRITER {
                let key = format!("/m/k{}", rng.below(12)).into_bytes();
                match rng.below(4) {
                    0 => {
                        kv.put(PutRequest {
                            key,
                            value: format!("{w}-{n}").into_bytes(),
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    }
                    1 => {
                        kv.delete_range(DeleteRangeRequest {
                            key,
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    }
                    _ => {
                        let cur = kv
                            .range(RangeRequest {
                                key: key.clone(),
                                ..Default::default()
                            })
                            .await
                            .unwrap()
                            .into_inner();
                        let rev = cur.kvs.first().map_or(0, |k| k.mod_revision);
                        let cmp = if rev == 0 {
                            Compare {
                                result: compare::CompareResult::Equal as i32,
                                target: compare::CompareTarget::Create as i32,
                                key: key.clone(),
                                target_union: Some(compare::TargetUnion::CreateRevision(0)),
                                range_end: vec![],
                            }
                        } else {
                            compare_mod(&key, rev)
                        };
                        kv.txn(TxnRequest {
                            compare: vec![cmp],
                            success: vec![put_op(&key, format!("{w}-{n}-cas").as_bytes())],
                            failure: vec![],
                        })
                        .await
                        .unwrap();
                    }
                }
            }
        }));
    }
    for w in writers {
        w.await.unwrap();
    }

    let truth = kv
        .range(RangeRequest {
            key: b"/m/".to_vec(),
            range_end: b"/m0".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let final_rev = truth.header.unwrap().revision;
    let truth: BTreeMap<Vec<u8>, (Vec<u8>, i64)> = truth
        .kvs
        .into_iter()
        .map(|k| (k.key, (k.value, k.mod_revision)))
        .collect();

    for (w, mirror) in [
        (&mut early, &mut early_mirror),
        (&mut late, &mut late_mirror),
    ] {
        while mirror.last_rev < final_rev {
            let Some(resp) = w.next().await else { break };
            for e in &resp.events {
                mirror.apply(e);
            }
        }
        // Nothing further may arrive: a straggler is a duplicate.
        while let Some(resp) = w.next_within(0.7).await {
            for e in &resp.events {
                mirror.apply(e);
            }
        }
    }

    // A delete or failed guard can be the last revision; the state is what matters.
    assert_eq!(
        early_mirror.kvs, truth,
        "early watcher's reconstruction differs from the store"
    );
    assert_eq!(
        late_mirror.kvs, truth,
        "late watcher's reconstruction differs from the store"
    );
    assert!(early_mirror.events > 0 && late_mirror.events > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_delivers_commit_order() {
    use edge_state::pb::etcdserverpb::{WatchCreateRequest, WatchRequest, watch_request};

    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut w = Watcher::open(&url, b"/a/", b"/a0", 0).await;
    w.tx.send(WatchRequest {
        request_union: Some(watch_request::RequestUnion::CreateRequest(
            WatchCreateRequest {
                key: b"/b/".to_vec(),
                range_end: b"/b0".to_vec(),
                watch_id: 2,
                ..Default::default()
            },
        )),
    })
    .await
    .unwrap();
    loop {
        let r = w.next().await.expect("no ack for the second watch");
        if r.created && r.watch_id == 2 {
            break;
        }
    }

    let mut writers = Vec::new();
    for t in 0..WRITERS {
        let url = url.clone();
        writers.push(tokio::spawn(async move {
            let mut kv = KvClient::connect(url).await.unwrap();
            for i in 0..PER_WRITER {
                let prefix = if (t + i) % 2 == 0 { "a" } else { "b" };
                kv.put(PutRequest {
                    key: format!("/{prefix}/{t}/{i}").into_bytes(),
                    value: b"v".to_vec(),
                    ..Default::default()
                })
                .await
                .unwrap();
            }
        }));
    }

    let want = WRITERS * PER_WRITER;
    let mut seen: Vec<i64> = Vec::new();
    while seen.len() < want {
        let Some(resp) = w.next_within(30.0).await else {
            break;
        };
        for e in &resp.events {
            seen.push(e.kv.as_ref().unwrap().mod_revision);
        }
    }
    for h in writers {
        h.await.unwrap();
    }
    assert_eq!(seen.len(), want, "events were lost or duplicated");
    let inversions = seen.windows(2).filter(|p| p[0] > p[1]).count();
    assert_eq!(
        inversions, 0,
        "{inversions} events arrived after one with a higher revision: the stream is not in commit order"
    );
}

#[tokio::test]
async fn txn_events_in_write_order() {
    use edge_state::server::{EtcdServer, lock};
    use edge_state::store::Store;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.log");
    let server = EtcdServer::new(Store::open(&path).unwrap());
    let store = server.store();
    let url = common::serve(server).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    kv.put(PutRequest {
        key: b"/t/m".to_vec(),
        value: b"v".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut live = Watcher::open(&url, b"/t/", b"/t0", 0).await;
    let delete_m = RequestOp {
        request: Some(request_op::Request::RequestDeleteRange(
            DeleteRangeRequest {
                key: b"/t/m".to_vec(),
                ..Default::default()
            },
        )),
    };
    let rev = kv
        .txn(TxnRequest {
            success: vec![put_op(b"/t/z", b"1"), delete_m, put_op(b"/t/a", b"2")],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    let order = ["/t/z", "/t/m", "/t/a"].map(|k| k.as_bytes().to_vec());
    let keys = |events: &[mvccpb::Event]| -> Vec<Vec<u8>> {
        events
            .iter()
            .map(|e| e.kv.as_ref().unwrap().key.clone())
            .collect()
    };

    let got = live.next_event().await.expect("no live events");
    assert_eq!(keys(&got.events), order, "live watch");
    let mut catch_up = Watcher::open(&url, b"/t/", b"/t0", rev).await;
    let got = catch_up.next_event().await.expect("no catch-up events");
    assert_eq!(keys(&got.events), order, "catch-up watch");

    let replayed = || -> Vec<Vec<u8>> {
        let s = Store::open_readonly(&path).unwrap();
        let events = s.events_since(rev as u64 - 1).unwrap();
        events.into_iter().map(|e| e.kv.key).collect()
    };
    assert_eq!(replayed(), order, "replayed from the log");
    lock(&store).rotate().unwrap();
    assert_eq!(replayed(), order, "replayed from a rotated log");
}
