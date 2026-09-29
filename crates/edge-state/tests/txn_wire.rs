mod common;

use common::{Watcher, spawn};
use edge_state::pb::etcdserverpb::{
    Compare, DeleteRangeRequest, PutRequest, RangeRequest, RequestOp, TxnRequest, compare,
    kv_client::KvClient, range_request, request_op, response_op,
};
use tonic::Code;

fn put(key: &str, value: &str) -> PutRequest {
    PutRequest {
        key: key.into(),
        value: value.into(),
        ..Default::default()
    }
}

fn op_put(key: &str, value: &str) -> RequestOp {
    RequestOp {
        request: Some(request_op::Request::RequestPut(put(key, value))),
    }
}

fn op_put_prev(key: &str, value: &str) -> RequestOp {
    RequestOp {
        request: Some(request_op::Request::RequestPut(PutRequest {
            prev_kv: true,
            ..put(key, value)
        })),
    }
}

fn op_del(key: &str, end: &str, prev: bool) -> RequestOp {
    RequestOp {
        request: Some(request_op::Request::RequestDeleteRange(
            DeleteRangeRequest {
                key: key.into(),
                range_end: end.into(),
                prev_kv: prev,
            },
        )),
    }
}

fn op_range(r: RangeRequest) -> RequestOp {
    RequestOp {
        request: Some(request_op::Request::RequestRange(r)),
    }
}

fn cmp_mod(key: &str, rev: i64) -> Compare {
    Compare {
        result: compare::CompareResult::Equal as i32,
        target: compare::CompareTarget::Mod as i32,
        key: key.into(),
        target_union: Some(compare::TargetUnion::ModRevision(rev)),
        range_end: vec![],
    }
}

#[tokio::test]
async fn apiserver_guarded_update() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();

    let r = kv
        .txn(TxnRequest {
            compare: vec![cmp_mod("/registry/x", 0)],
            success: vec![op_put("/registry/x", "v1")],
            failure: vec![op_range(RangeRequest {
                key: b"/registry/x".to_vec(),
                ..Default::default()
            })],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.succeeded);
    let rev1 = r.header.as_ref().unwrap().revision;
    match r.responses[0].response.as_ref().unwrap() {
        response_op::Response::ResponsePut(p) => {
            assert_eq!(p.header.as_ref().unwrap().revision, rev1)
        }
        other => panic!("{other:?}"),
    }

    let r = kv
        .txn(TxnRequest {
            compare: vec![cmp_mod("/registry/x", rev1 - 1)],
            success: vec![op_put("/registry/x", "stale")],
            failure: vec![op_range(RangeRequest {
                key: b"/registry/x".to_vec(),
                ..Default::default()
            })],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!r.succeeded);
    match r.responses[0].response.as_ref().unwrap() {
        response_op::Response::ResponseRange(g) => {
            assert_eq!(g.kvs[0].value, b"v1");
            assert_eq!(g.kvs[0].mod_revision, rev1);
            assert_eq!(g.count, 1);
            assert_eq!(g.header.as_ref().unwrap().revision, rev1);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn multi_op_branch_one_revision() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    kv.put(put("/t/gone", "x")).await.unwrap();
    let mut w = Watcher::open(&url, b"/t/", b"/t0", 0).await;
    let before = kv
        .range(RangeRequest {
            key: b"/t/gone".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;

    let r = kv
        .txn(TxnRequest {
            compare: vec![],
            success: vec![
                op_put("/t/a", "1"),
                op_put("/t/b", "2"),
                op_del("/t/gone", "", false),
            ],
            failure: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        r.header.unwrap().revision,
        before + 1,
        "three writes, one revision"
    );

    let mut revs = Vec::new();
    while revs.len() < 3 {
        let m = w.next_event().await.unwrap();
        revs.extend(m.events.iter().map(|e| e.kv.as_ref().unwrap().mod_revision));
    }
    assert_eq!(revs, vec![before + 1; 3]);
}

#[tokio::test]
async fn delete_range_counts() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    for i in 0..4 {
        kv.put(put(&format!("/d/{i}"), "v")).await.unwrap();
    }
    let head = kv
        .put(put("/other", "v"))
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;

    let r = kv
        .delete_range(DeleteRangeRequest {
            key: b"/d/".to_vec(),
            range_end: b"/d0".to_vec(),
            prev_kv: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.deleted, 4);
    assert_eq!(r.prev_kvs.len(), 4);
    assert_eq!(
        r.header.unwrap().revision,
        head + 1,
        "a range delete is one revision"
    );

    let r = kv
        .delete_range(DeleteRangeRequest {
            key: b"/d/".to_vec(),
            range_end: b"/d0".to_vec(),
            prev_kv: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.deleted, 0);
    assert_eq!(r.header.unwrap().revision, head + 1);

    for i in 0..3 {
        kv.put(put(&format!("/e/{i}"), "v")).await.unwrap();
    }
    let t = kv
        .txn(TxnRequest {
            compare: vec![],
            success: vec![op_del("/e/", "/e0", true), op_del("/nothing", "", false)],
            failure: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let counts: Vec<i64> = t
        .responses
        .iter()
        .map(|r| match r.response.as_ref().unwrap() {
            response_op::Response::ResponseDeleteRange(d) => d.deleted,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(counts, vec![3, 0]);
}

#[tokio::test]
async fn txn_range_honours_limit() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    for i in 0..5 {
        kv.put(put(&format!("/x/{i}"), "v")).await.unwrap();
    }
    kv.put(put("/y", "v")).await.unwrap();
    let t = kv
        .txn(TxnRequest {
            compare: vec![],
            success: vec![op_range(RangeRequest {
                key: b"/x/".to_vec(),
                range_end: b"/x0".to_vec(),
                limit: 2,
                ..Default::default()
            })],
            failure: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    match t.responses[0].response.as_ref().unwrap() {
        response_op::Response::ResponseRange(g) => {
            assert_eq!((g.kvs.len(), g.count, g.more), (2, 5, true));
            assert!(g.header.is_some());
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn txn_put_honours_prev_kv() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    kv.put(put("/k", "old")).await.unwrap();
    let t = kv
        .txn(TxnRequest {
            compare: vec![],
            success: vec![op_put_prev("/k", "new")],
            failure: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    match t.responses[0].response.as_ref().unwrap() {
        response_op::Response::ResponsePut(p) => {
            assert_eq!(p.prev_kv.as_ref().unwrap().value, b"old")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn range_compare_covers_every_key() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    kv.put(put("/r/a", "1")).await.unwrap();
    let last = kv
        .put(put("/r/b", "1"))
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    let guard = |bound: i64| Compare {
        result: compare::CompareResult::Less as i32,
        target: compare::CompareTarget::Mod as i32,
        key: b"/r/".to_vec(),
        range_end: b"/r0".to_vec(),
        target_union: Some(compare::TargetUnion::ModRevision(bound)),
    };
    let ok = kv
        .txn(TxnRequest {
            compare: vec![guard(last + 1)],
            success: vec![op_put("/ok", "1")],
            failure: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(ok.succeeded);
    // /r/a alone satisfies it; /r/b does not.
    let no = kv
        .txn(TxnRequest {
            compare: vec![guard(last)],
            success: vec![op_put("/no", "1")],
            failure: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!no.succeeded);
}

#[tokio::test]
async fn refuses_bad_txns() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    kv.put(put("/k", "v")).await.unwrap();
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

    let refused = |t: TxnRequest| {
        let mut kv = kv.clone();
        async move { kv.txn(t).await.unwrap_err() }
    };
    let e = refused(TxnRequest {
        compare: vec![],
        success: vec![RequestOp {
            request: Some(request_op::Request::RequestTxn(TxnRequest::default())),
        }],
        failure: vec![],
    })
    .await;
    assert_eq!(e.code(), Code::Unimplemented);
    let e = refused(TxnRequest {
        compare: vec![],
        success: vec![op_put("/k", "1"), op_put("/k", "2")],
        failure: vec![],
    })
    .await;
    assert_eq!(
        (e.code(), e.message()),
        (
            Code::InvalidArgument,
            "etcdserver: duplicate key given in txn request"
        )
    );
    let e = refused(TxnRequest {
        compare: vec![],
        success: vec![
            op_put("/k/1", "1"),
            op_range(RangeRequest {
                key: b"/k/".to_vec(),
                range_end: b"/k0".to_vec(),
                ..Default::default()
            }),
            op_put("/k/2", "2"),
        ],
        failure: vec![],
    })
    .await;
    assert_eq!(e.code(), Code::Unimplemented);
    let many: Vec<RequestOp> = (0..129).map(|i| op_put(&format!("/m{i}"), "v")).collect();
    let e = refused(TxnRequest {
        compare: vec![],
        success: many,
        failure: vec![],
    })
    .await;
    assert_eq!(
        (e.code(), e.message()),
        (
            Code::InvalidArgument,
            "etcdserver: too many operations in txn request"
        )
    );
    let e = kv
        .put(PutRequest {
            key: b"/k".to_vec(),
            ignore_value: true,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
    assert_eq!(
        kv.range(RangeRequest {
            key: b"/k".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision,
        head
    );
}

#[tokio::test]
async fn mutex_txn_reads_own_put() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    let create_absent = |key: &str| Compare {
        result: compare::CompareResult::Equal as i32,
        target: compare::CompareTarget::Create as i32,
        key: key.into(),
        target_union: Some(compare::TargetUnion::CreateRevision(0)),
        range_end: vec![],
    };
    let oldest = || {
        op_range(RangeRequest {
            key: b"/mutex/".to_vec(),
            range_end: b"/mutex0".to_vec(),
            limit: 1,
            sort_order: range_request::SortOrder::Ascend as i32,
            sort_target: range_request::SortTarget::Create as i32,
            ..Default::default()
        })
    };
    let first = kv
        .txn(TxnRequest {
            compare: vec![create_absent("/mutex/a")],
            success: vec![op_put("/mutex/a", ""), oldest()],
            failure: vec![oldest()],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(first.succeeded);
    let rev = first.header.unwrap().revision;
    let Some(response_op::Response::ResponseRange(r)) = first.responses[1].response.clone() else {
        panic!("no range response: {:?}", first.responses)
    };
    assert_eq!(r.kvs.len(), 1, "the put is visible to the range after it");
    assert_eq!(r.kvs[0].key, b"/mutex/a");
    assert_eq!(r.kvs[0].mod_revision, rev);
    let second = kv
        .txn(TxnRequest {
            compare: vec![create_absent("/mutex/b")],
            success: vec![op_put("/mutex/b", ""), oldest()],
            failure: vec![oldest()],
        })
        .await
        .unwrap()
        .into_inner();
    let Some(response_op::Response::ResponseRange(r)) = second.responses[1].response.clone() else {
        panic!("no range response")
    };
    assert_eq!(r.kvs[0].key, b"/mutex/a");
}

#[tokio::test]
async fn apiserver_compaction_txn() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    for i in 0..5 {
        kv.put(put("/data", &format!("{i}"))).await.unwrap();
    }
    let version_is = |v: i64| Compare {
        result: compare::CompareResult::Equal as i32,
        target: compare::CompareTarget::Version as i32,
        key: b"compact_rev_key".to_vec(),
        target_union: Some(compare::TargetUnion::Version(v)),
        range_end: vec![],
    };
    let t = kv
        .txn(TxnRequest {
            compare: vec![version_is(0)],
            success: vec![op_put("compact_rev_key", "6")],
            failure: vec![op_range(RangeRequest {
                key: b"compact_rev_key".to_vec(),
                ..Default::default()
            })],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(t.succeeded);
    let rev = t.header.unwrap().revision;
    kv.compact(edge_state::pb::etcdserverpb::CompactionRequest {
        revision: rev,
        physical: true,
    })
    .await
    .unwrap();
    let t = kv
        .txn(TxnRequest {
            compare: vec![version_is(0)],
            success: vec![op_put("compact_rev_key", "x")],
            failure: vec![op_range(RangeRequest {
                key: b"compact_rev_key".to_vec(),
                ..Default::default()
            })],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!t.succeeded);
}

async fn seeded(url: &str) -> KvClient<tonic::transport::Channel> {
    let mut kv = KvClient::connect(url.to_string()).await.unwrap();
    kv.put(put("/s/b", "3")).await.unwrap(); // rev 2
    kv.put(put("/s/a", "9")).await.unwrap(); // rev 3
    kv.put(put("/s/c", "1")).await.unwrap(); // rev 4
    kv.put(put("/s/b", "3")).await.unwrap(); // rev 5 (b: version 2)
    kv
}

fn keys(r: &edge_state::pb::etcdserverpb::RangeResponse) -> Vec<String> {
    r.kvs
        .iter()
        .map(|k| String::from_utf8_lossy(&k.key).into_owned())
        .collect()
}

#[tokio::test]
async fn range_sorts() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = seeded(&url).await;
    let ask = |order: range_request::SortOrder, target: range_request::SortTarget| RangeRequest {
        key: b"/s/".to_vec(),
        range_end: b"/s0".to_vec(),
        sort_order: order as i32,
        sort_target: target as i32,
        ..Default::default()
    };
    use range_request::{SortOrder as O, SortTarget as T};
    let cases = [
        (O::None, T::Key, vec!["/s/a", "/s/b", "/s/c"]),
        (O::Descend, T::Key, vec!["/s/c", "/s/b", "/s/a"]),
        (O::Ascend, T::Mod, vec!["/s/a", "/s/c", "/s/b"]),
        (O::Descend, T::Mod, vec!["/s/b", "/s/c", "/s/a"]),
        (O::Ascend, T::Create, vec!["/s/b", "/s/a", "/s/c"]),
        (O::Descend, T::Version, vec!["/s/b", "/s/a", "/s/c"]),
        (O::Ascend, T::Value, vec!["/s/c", "/s/b", "/s/a"]),
    ];
    for (order, target, want) in cases {
        let got = kv.range(ask(order, target)).await.unwrap().into_inner();
        assert_eq!(keys(&got), want, "{order:?} by {target:?}");
    }
    // Sorting happens before the limit; count and more describe the whole set.
    let mut r = ask(O::Descend, T::Mod);
    r.limit = 2;
    let got = kv.range(r).await.unwrap().into_inner();
    assert_eq!(
        (keys(&got), got.count, got.more),
        (vec!["/s/b".into(), "/s/c".into()], 3, true)
    );
}

#[tokio::test]
async fn range_filters() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = seeded(&url).await;
    let base = RangeRequest {
        key: b"/s/".to_vec(),
        range_end: b"/s0".to_vec(),
        ..Default::default()
    };

    let got = kv
        .range(RangeRequest {
            min_mod_revision: 4,
            ..base.clone()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (keys(&got), got.count),
        (vec!["/s/b".into(), "/s/c".into()], 3)
    );
    let got = kv
        .range(RangeRequest {
            max_mod_revision: 3,
            ..base.clone()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(keys(&got), vec!["/s/a"]);
    let got = kv
        .range(RangeRequest {
            min_create_revision: 3,
            max_create_revision: 3,
            ..base.clone()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((keys(&got), got.count), (vec!["/s/a".into()], 3));
    let got = kv
        .range(RangeRequest {
            key: b"/s/a".to_vec(),
            max_create_revision: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (got.kvs.len(), got.count),
        (0, 1),
        "a single key, filtered out"
    );

    let got = kv
        .range(RangeRequest {
            keys_only: true,
            ..base.clone()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(got.kvs.iter().all(|k| k.value.is_empty()) && got.kvs.len() == 3);
    let got = kv
        .range(RangeRequest {
            count_only: true,
            ..base.clone()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(got.kvs.is_empty() && got.count == 3);
    let got = kv
        .range(RangeRequest {
            revision: 3,
            ..base
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(keys(&got), vec!["/s/a", "/s/b"]);
}

#[tokio::test]
async fn inverted_range_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = seeded(&url).await;
    for (k, e) in [("/z", "/a"), ("/s/b", "/s/b"), ("/s/c", "/s/a")] {
        let r = kv
            .range(RangeRequest {
                key: k.into(),
                range_end: e.into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert!(r.kvs.is_empty() && r.count == 0, "{k}..{e}");
    }
    assert_eq!(
        kv.range(RangeRequest {
            key: b"/s/a".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .len(),
        1
    );
}

#[tokio::test]
async fn limited_list_pages() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    let big = "x".repeat(50_000);
    for i in 0..200 {
        kv.put(put(&format!("/big/{i:04}"), &big)).await.unwrap();
    }
    let mut start = b"/big/".to_vec();
    let mut seen = 0;
    loop {
        let r = kv
            .range(RangeRequest {
                key: start.clone(),
                range_end: b"/big0".to_vec(),
                limit: 25,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.count, 200 - seen as i64);
        seen += r.kvs.len();
        if !r.more {
            break;
        }
        start = r.kvs.last().unwrap().key.clone();
        start.push(0);
    }
    assert_eq!(seen, 200);
}
