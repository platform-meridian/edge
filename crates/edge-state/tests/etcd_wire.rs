mod common;

use edge_state::pb::etcdserverpb::{
    LeaseGrantRequest, MemberAddRequest, MemberListRequest, MemberUpdateRequest, PutRequest,
    RangeRequest, WatchCreateRequest, WatchProgressRequest, WatchRequest,
    cluster_client::ClusterClient, kv_client::KvClient, lease_client::LeaseClient,
    watch_client::WatchClient, watch_request,
};
use edge_state::server::EtcdServer;
use edge_state::store::Store;
use std::time::{Duration, Instant};

async fn spawn(dir: &std::path::Path) -> String {
    let store = Store::open(dir.join("state.log")).unwrap();
    common::serve(EtcdServer::new(store).with_identity(
        "node-1",
        vec!["https://10.51.0.1:2379".into()],
        vec!["https://10.51.0.1:2380".into()],
    ))
    .await
}

#[tokio::test]
async fn progress_only_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.log")).unwrap();
    let url = common::serve(EtcdServer::new(store).with_progress_interval(Some(1))).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut watch = WatchClient::connect(url).await.unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    for (id, ask) in [(1, false), (2, true)] {
        tx.send(WatchRequest {
            request_union: Some(watch_request::RequestUnion::CreateRequest(
                WatchCreateRequest {
                    key: b"/quiet".to_vec(),
                    watch_id: id,
                    progress_notify: ask,
                    ..Default::default()
                },
            )),
        })
        .await
        .unwrap();
    }
    let mut stream = watch
        .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let head = kv
        .put(PutRequest {
            key: b"/elsewhere".to_vec(),
            value: b"x".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;

    let mut notified = std::collections::BTreeSet::new();
    let mut last = 0;
    let end = std::time::Instant::now() + std::time::Duration::from_millis(3500);
    while let Ok(Ok(Some(m))) = tokio::time::timeout(
        end.saturating_duration_since(std::time::Instant::now()),
        stream.message(),
    )
    .await
    {
        if !m.created && !m.canceled && m.events.is_empty() {
            let rev = m.header.unwrap().revision;
            assert!(
                rev >= last && rev <= head,
                "notification revision {rev} after {last}, head {head}"
            );
            last = rev;
            notified.insert(m.watch_id);
        }
    }
    assert_eq!(last, head, "the last notification reaches the head");
    assert_eq!(
        notified,
        std::collections::BTreeSet::from([2]),
        "watches that received an event-less notification"
    );
}

#[tokio::test]
async fn revoke_deletes_lease_keys() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut lease = LeaseClient::connect(url.clone()).await.unwrap();
    let mut kv = KvClient::connect(url).await.unwrap();

    let id = lease
        .lease_grant(LeaseGrantRequest { ttl: 30, id: 0 })
        .await
        .unwrap()
        .into_inner()
        .id;
    kv.put(PutRequest {
        key: b"/node".to_vec(),
        value: b"up".to_vec(),
        lease: id,
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        kv.range(RangeRequest {
            key: b"/node".to_vec(),
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
        .lease_revoke(edge_state::pb::etcdserverpb::LeaseRevokeRequest { id })
        .await
        .unwrap();
    assert!(
        kv.range(RangeRequest {
            key: b"/node".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .is_empty()
    );
}

#[tokio::test]
async fn expiry_deletes_lease_keys() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut lease = LeaseClient::connect(url.clone()).await.unwrap();
    let mut kv = KvClient::connect(url).await.unwrap();

    let id = lease
        .lease_grant(LeaseGrantRequest { ttl: 1, id: 0 })
        .await
        .unwrap()
        .into_inner()
        .id;
    kv.put(PutRequest {
        key: b"/ephemeral".to_vec(),
        value: b"x".to_vec(),
        lease: id,
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        kv.range(RangeRequest {
            key: b"/ephemeral".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .len(),
        1
    );
    tokio::time::sleep(std::time::Duration::from_millis(1800)).await;
    // Reads see the revoke once its fsync lands.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !kv
        .range(RangeRequest {
            key: b"/ephemeral".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .is_empty()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the expired lease did not take its key"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn member_list_reports_identity() {
    let dir = tempfile::tempdir().unwrap();
    let addr = spawn(dir.path()).await;
    let mut c = ClusterClient::connect(addr).await.unwrap();

    let r = c
        .member_list(MemberListRequest {
            linearizable: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        r.members.len(),
        1,
        "a single-node cluster has exactly one member"
    );
    let m = &r.members[0];
    assert_eq!(m.name, "node-1", "the name Talos passed as --name");
    assert_eq!(m.client_ur_ls, vec!["https://10.51.0.1:2379".to_string()]);
    assert_eq!(m.peer_ur_ls, vec!["https://10.51.0.1:2380".to_string()]);
    assert!(!m.is_learner);
    assert!(m.id != 0, "etcd clients treat a zero member id as absent");
    assert!(r.header.is_some(), "Talos reads cluster_id off the header");
}

#[tokio::test]
async fn peer_urls_can_be_updated() {
    let dir = tempfile::tempdir().unwrap();
    let addr = spawn(dir.path()).await;
    let mut c = ClusterClient::connect(addr).await.unwrap();
    let id = c
        .member_list(MemberListRequest {
            linearizable: false,
        })
        .await
        .unwrap()
        .into_inner()
        .members[0]
        .id;

    let moved = vec!["https://10.50.0.1:2380".to_string()];
    let r = c
        .member_update(MemberUpdateRequest {
            id,
            peer_ur_ls: moved.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        r.members[0].peer_ur_ls, moved,
        "the response carries the new peers"
    );

    let after = c
        .member_list(MemberListRequest {
            linearizable: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        after.members[0].peer_ur_ls, moved,
        "and so does the next member list"
    );
    assert_eq!(after.members[0].name, "node-1", "the identity is untouched");
    assert_eq!(after.members[0].id, id);
}

#[tokio::test]
async fn unknown_member_update_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let addr = spawn(dir.path()).await;
    let mut c = ClusterClient::connect(addr).await.unwrap();
    let e = c
        .member_update(MemberUpdateRequest {
            id: 42,
            peer_ur_ls: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn member_add_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let addr = spawn(dir.path()).await;
    let mut c = ClusterClient::connect(addr).await.unwrap();
    let e = c
        .member_add(MemberAddRequest {
            peer_ur_ls: vec!["https://1.2.3.4:2380".into()],
            is_learner: false,
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::FailedPrecondition);
    assert!(
        e.message().contains("single-member"),
        "the error should say why: {}",
        e.message()
    );
}

#[tokio::test]
async fn truncated_range_reports_more() {
    let dir = tempfile::tempdir().unwrap();
    let addr = spawn(dir.path()).await;
    let mut c = KvClient::connect(addr).await.unwrap();
    for i in 0..10 {
        c.put(PutRequest {
            key: format!("/k{i:02}").into_bytes(),
            value: b"v".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let r = c
        .range(RangeRequest {
            key: b"/k".to_vec(),
            range_end: b"/l".to_vec(),
            limit: 4,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.kvs.len(), 4, "the page is the limit");
    assert_eq!(r.count, 10, "count is the whole match, not the page");
    assert!(r.more, "six keys remain unsent, so more must be true");

    let r2 = c
        .range(RangeRequest {
            key: b"/k".to_vec(),
            range_end: b"/l".to_vec(),
            limit: 50,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r2.kvs.len(), 10);
    assert!(!r2.more, "everything fitted, so more must be false");
}

#[tokio::test]
async fn write_racing_new_watch_is_delivered() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();

    for i in 0..40u32 {
        let key = format!("/registry/secrets/apps/key-{i}");

        let listed = kv
            .range(RangeRequest {
                key: b"/registry/secrets/".to_vec(),
                range_end: b"/registry/secrets0".to_vec(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .header
            .unwrap()
            .revision;

        let mut watch = WatchClient::connect(url.clone()).await.unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(WatchRequest {
            request_union: Some(watch_request::RequestUnion::CreateRequest(
                WatchCreateRequest {
                    key: b"/registry/secrets/".to_vec(),
                    range_end: b"/registry/secrets0".to_vec(),
                    start_revision: listed + 1,
                    ..Default::default()
                },
            )),
        })
        .await
        .unwrap();
        let mut stream = watch
            .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();

        kv.put(PutRequest {
            key: key.clone().into_bytes(),
            value: b"a-private-key".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap();

        let mut seen = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, stream.message()).await {
                Ok(Ok(Some(msg))) => {
                    if msg
                        .events
                        .iter()
                        .any(|e| e.kv.as_ref().is_some_and(|kv| kv.key == key.as_bytes()))
                    {
                        seen = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            seen,
            "iteration {i}: the watch never delivered {key} — an informer here would believe the key does not exist and write a second one"
        );
    }
}

#[tokio::test]
async fn range_stream_merges_to_range() {
    use edge_state::pb::etcdserverpb::range_request::{SortOrder, SortTarget};
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url).await.unwrap();
    for i in 0..25 {
        kv.put(PutRequest {
            key: format!("/pods/p{i:02}").into_bytes(),
            value: vec![b'v'; i],
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let pinned = kv
        .put(PutRequest {
            key: b"/other".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    kv.put(PutRequest {
        key: b"/pods/p99".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap();

    let prefix = |limit, revision, count_only| RangeRequest {
        key: b"/pods/".to_vec(),
        range_end: b"/pods0".to_vec(),
        limit,
        revision,
        count_only,
        ..Default::default()
    };
    for req in [
        prefix(0, 0, false),
        prefix(12, 0, false),
        prefix(0, pinned, false),
        prefix(0, 0, true),
    ] {
        let want = kv.range(req.clone()).await.unwrap().into_inner();
        let mut stream = kv.range_stream(req.clone()).await.unwrap().into_inner();
        let mut chunks = Vec::new();
        while let Some(m) = stream.message().await.unwrap() {
            chunks.push(m.range_response.unwrap());
        }
        let (last, rest) = chunks.split_last().expect("at least one chunk");
        assert!(
            rest.iter()
                .all(|c| c.header.is_none() && !c.more && c.count == 0),
            "{req:?}: only the last chunk carries header, more and count"
        );
        if !req.count_only && want.kvs.len() > 10 {
            assert!(
                !rest.is_empty(),
                "{req:?}: {} keys in one chunk",
                want.kvs.len()
            );
        }
        let merged: Vec<_> = chunks.iter().flat_map(|c| c.kvs.clone()).collect();
        assert_eq!(merged, want.kvs, "{req:?}");
        assert_eq!((last.more, last.count), (want.more, want.count), "{req:?}");
        assert_eq!(
            last.header.as_ref().unwrap().revision,
            want.header.unwrap().revision,
            "{req:?}"
        );
    }

    for refused in [
        RangeRequest {
            sort_order: SortOrder::Descend as i32,
            ..prefix(0, 0, false)
        },
        RangeRequest {
            sort_order: SortOrder::Ascend as i32,
            sort_target: SortTarget::Create as i32,
            ..prefix(0, 0, false)
        },
        RangeRequest {
            min_mod_revision: 5,
            ..prefix(0, 0, false)
        },
        RangeRequest {
            max_mod_revision: 5,
            ..prefix(0, 0, false)
        },
        RangeRequest {
            min_create_revision: 5,
            ..prefix(0, 0, false)
        },
        RangeRequest {
            max_create_revision: 5,
            ..prefix(0, 0, false)
        },
    ] {
        let code = kv
            .range_stream(refused.clone())
            .await
            .err()
            .map(|e| e.code());
        assert_eq!(code, Some(tonic::Code::Unimplemented), "{refused:?}");
    }
}

#[tokio::test]
async fn negative_start_is_compacted() {
    let dir = tempfile::tempdir().unwrap();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let mut watch = WatchClient::connect(url).await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(WatchRequest {
        request_union: Some(watch_request::RequestUnion::CreateRequest(
            WatchCreateRequest {
                key: b"/k".to_vec(),
                start_revision: -5,
                ..Default::default()
            },
        )),
    })
    .await
    .unwrap();
    let mut stream = watch
        .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let first = stream.message().await.unwrap().unwrap();
    assert!(first.created && first.canceled, "{first:?}");
    assert_eq!(first.watch_id, -1);
    assert_eq!(
        first.cancel_reason,
        "etcdserver: mvcc: required revision has been compacted"
    );
    kv.put(PutRequest {
        key: b"/k".to_vec(),
        value: b"v".to_vec(),
        ..Default::default()
    })
    .await
    .unwrap();
    let later = tokio::time::timeout(std::time::Duration::from_millis(300), stream.message()).await;
    assert!(later.is_err(), "the refused watch delivered {later:?}");
}

#[tokio::test]
async fn future_watch_gets_no_early_progress() {
    let dir = common::tempdir();
    let store = Store::open(dir.path().join("state.log")).unwrap();
    let url = common::serve(EtcdServer::new(store).with_progress_interval(Some(1))).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let head = kv
        .range(RangeRequest {
            key: b"x".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(WatchRequest {
        request_union: Some(watch_request::RequestUnion::CreateRequest(
            WatchCreateRequest {
                key: b"/future".to_vec(),
                start_revision: head + 1,
                progress_notify: true,
                ..Default::default()
            },
        )),
    })
    .await
    .unwrap();
    let mut stream = WatchClient::connect(url)
        .await
        .unwrap()
        .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().unwrap().created);
    tx.send(WatchRequest {
        request_union: Some(watch_request::RequestUnion::ProgressRequest(
            WatchProgressRequest {},
        )),
    })
    .await
    .unwrap();

    let quiet = tokio::time::timeout(Duration::from_millis(2500), stream.message()).await;
    if let Ok(Ok(Some(m))) = quiet {
        panic!(
            "progress at revision {} (watch {}) for a watch starting at {}",
            m.header.unwrap().revision,
            m.watch_id,
            head + 1
        );
    }
}

#[tokio::test]
async fn prev_kv_only_when_asked() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let put = |value: &'static [u8]| PutRequest {
        key: b"/p".to_vec(),
        value: value.to_vec(),
        ..Default::default()
    };
    kv.put(put(b"old")).await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    for (id, prev_kv) in [(1, false), (2, true)] {
        tx.send(WatchRequest {
            request_union: Some(watch_request::RequestUnion::CreateRequest(
                WatchCreateRequest {
                    key: b"/p".to_vec(),
                    watch_id: id,
                    prev_kv,
                    ..Default::default()
                },
            )),
        })
        .await
        .unwrap();
    }
    let mut stream = WatchClient::connect(url)
        .await
        .unwrap()
        .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let mut created = 0;
    while created < 2 {
        created += stream.message().await.unwrap().unwrap().created as usize;
    }
    kv.put(put(b"new")).await.unwrap();
    let mut prev = std::collections::BTreeMap::new();
    while prev.len() < 2 {
        let m = stream.message().await.unwrap().unwrap();
        for e in m.events {
            prev.insert(m.watch_id, e.prev_kv.map(|p| p.value));
        }
    }
    assert_eq!(prev[&1], None);
    assert_eq!(prev[&2], Some(b"old".to_vec()));
}

#[tokio::test]
async fn watch_sees_exactly_its_range() {
    let dir = common::tempdir();
    let url = spawn(dir.path()).await;
    let mut kv = KvClient::connect(url.clone()).await.unwrap();
    let keys = ["/a", "/b", "/b0", "/c", "/d", "/e"];
    let ranges: [(&[u8], &[u8], &[&str]); 3] = [
        (b"/b", b"", &["/b"]),
        (b"/b", b"/d", &["/b", "/b0", "/c"]),
        (b"/c", b"\0", &["/c", "/d", "/e"]),
    ];
    for start_revision in [0, 2] {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        for (id, (key, end, _)) in ranges.iter().enumerate() {
            tx.send(WatchRequest {
                request_union: Some(watch_request::RequestUnion::CreateRequest(
                    WatchCreateRequest {
                        key: key.to_vec(),
                        range_end: end.to_vec(),
                        watch_id: id as i64 + 1,
                        start_revision,
                        ..Default::default()
                    },
                )),
            })
            .await
            .unwrap();
        }
        let mut stream = WatchClient::connect(url.clone())
            .await
            .unwrap()
            .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        if start_revision == 0 {
            let mut created = 0;
            while created < ranges.len() {
                created += stream.message().await.unwrap().unwrap().created as usize;
            }
            for k in keys {
                kv.put(PutRequest {
                    key: k.into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            }
        }
        let mut seen: Vec<Vec<String>> = vec![Vec::new(); ranges.len()];
        let end = Instant::now() + Duration::from_millis(1500);
        while let Ok(Ok(Some(m))) = tokio::time::timeout(
            end.saturating_duration_since(Instant::now()),
            stream.message(),
        )
        .await
        {
            for e in m.events {
                let key = String::from_utf8(e.kv.unwrap().key).unwrap();
                seen[m.watch_id as usize - 1].push(key);
            }
        }
        for ((key, end, want), got) in ranges.iter().zip(&seen) {
            assert_eq!(got, want, "start {start_revision}: [{key:?}, {end:?})");
        }
    }
}
