#![allow(dead_code)]

use edge_state::pb::etcdserverpb::{
    WatchCreateRequest, WatchRequest, WatchResponse, watch_client::WatchClient, watch_request,
};
use edge_state::server::EtcdServer;
use edge_state::store::Store;

/// On disk rather than a RAM /tmp, and removed with the guard: nothing is
/// left behind, not even a parent.
pub fn tempdir() -> tempfile::TempDir {
    let base = std::env::var_os("EDGE_STATE_TEST_TMP")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    tempfile::Builder::new()
        .prefix("edge-state-test-")
        .tempdir_in(base)
        .unwrap()
}

pub fn fill_past_a_batch(path: &std::path::Path) {
    let mut s = Store::open(path).unwrap();
    let mib = vec![b'p'; 1 << 20];
    for _ in 0..=edge_state::log::BATCH_BYTES >> 20 {
        s.put(b"/fill", &mib, 0).unwrap();
    }
}

pub async fn serve(server: EtcdServer) -> String {
    server.spawn_lease_reaper();
    server.spawn_log_rotation();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        server
            .router(tonic::transport::Server::builder())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

pub async fn spawn(dir: &std::path::Path) -> String {
    let store = Store::open(dir.join("state.log")).unwrap();
    serve(EtcdServer::new(store)).await
}

pub struct Watcher {
    pub stream: tonic::Streaming<WatchResponse>,
    pub tx: tokio::sync::mpsc::Sender<WatchRequest>,
}

impl Watcher {
    pub async fn open(url: &str, key: &[u8], range_end: &[u8], start_revision: i64) -> Watcher {
        let mut w = Watcher::open_raw(url, key, range_end, start_revision).await;
        let created = w.next().await.expect("no created response");
        assert!(
            created.created,
            "first response must be the created marker: {created:?}"
        );
        w
    }

    pub async fn open_raw(url: &str, key: &[u8], range_end: &[u8], start_revision: i64) -> Watcher {
        let mut client = WatchClient::connect(url.to_string()).await.unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tx.send(WatchRequest {
            request_union: Some(watch_request::RequestUnion::CreateRequest(
                WatchCreateRequest {
                    key: key.to_vec(),
                    range_end: range_end.to_vec(),
                    start_revision,
                    prev_kv: true,
                    ..Default::default()
                },
            )),
        })
        .await
        .unwrap();
        let stream = client
            .watch(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        Watcher { stream, tx }
    }

    pub async fn next_within(&mut self, secs: f64) -> Option<WatchResponse> {
        match tokio::time::timeout(
            std::time::Duration::from_secs_f64(secs),
            self.stream.message(),
        )
        .await
        {
            Ok(Ok(Some(m))) => Some(m),
            _ => None,
        }
    }

    pub async fn next(&mut self) -> Option<WatchResponse> {
        self.next_within(5.0).await
    }

    pub async fn next_event(&mut self) -> Option<WatchResponse> {
        self.next_event_within(5.0).await
    }

    pub async fn next_event_within(&mut self, secs: f64) -> Option<WatchResponse> {
        loop {
            let m = self.next_within(secs).await?;
            if !m.events.is_empty() || m.canceled {
                return Some(m);
            }
        }
    }
}

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

use edge_state::store::{Event, KeyValue};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum Op {
    Put(Vec<u8>, Vec<u8>, i64),
    Delete(Vec<u8>),
    Grant(i64, i64),
    Revoke(i64),
    CompactBehind(u64),
    Txn(Vec<edge_state::entry::Write>),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Dump {
    pub revision: u64,
    pub compact_revision: u64,
    pub leases: BTreeMap<i64, i64>,
    pub lease_keys: BTreeMap<i64, Vec<Vec<u8>>>,
    pub live: Vec<KeyValue>,
    pub history: Result<Vec<Event>, u64>,
}

pub fn dump(s: &Store) -> Dump {
    let leases: BTreeMap<i64, i64> = s
        .lease_ids()
        .into_iter()
        .map(|id| (id, s.lease_ttl(id).unwrap()))
        .collect();
    let lease_keys = leases.keys().map(|id| (*id, s.lease_keys(*id))).collect();
    Dump {
        revision: s.revision(),
        compact_revision: s.compact_revision(),
        leases,
        lease_keys,
        live: s.range_from(&[], 0),
        history: s.events_since(s.compact_revision()),
    }
}

pub fn script(seed: u64, n: usize) -> Vec<Op> {
    let mut rng = Rng(seed | 1);
    let mut ops = Vec::new();
    let mut leases: Vec<i64> = Vec::new();
    let mut next_lease = 100;
    for _ in 0..n {
        let key = format!("/k{}", rng.below(6)).into_bytes();
        let op = match rng.below(12) {
            10 | 11 => {
                use edge_state::entry::Write;
                let n = 2 + rng.below(3) as usize;
                let mut keys: Vec<u64> = (0..6).collect();
                let mut writes = Vec::new();
                for _ in 0..n {
                    let k = keys.swap_remove(rng.below(keys.len() as u64) as usize);
                    let key = format!("/k{k}").into_bytes();
                    writes.push(if rng.below(4) == 0 {
                        Write::Delete { key }
                    } else {
                        Write::Put {
                            key,
                            value: vec![rng.next() as u8; 1 + rng.below(9) as usize],
                            lease: 0,
                        }
                    });
                }
                Op::Txn(writes)
            }
            0..=3 => {
                let len = rng.below(20) as usize;
                let value: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                Op::Put(key, value, 0)
            }
            4 => Op::Delete(key),
            5 => {
                next_lease += 1;
                leases.push(next_lease);
                Op::Grant(next_lease, 30 + rng.below(30) as i64)
            }
            6 | 7 if !leases.is_empty() => {
                let l = leases[rng.below(leases.len() as u64) as usize];
                Op::Put(key, vec![rng.next() as u8; 3], l)
            }
            8 if !leases.is_empty() => {
                let i = rng.below(leases.len() as u64) as usize;
                Op::Revoke(leases.swap_remove(i))
            }
            9 => Op::CompactBehind(1 + rng.below(3)),
            _ => Op::Delete(key),
        };
        ops.push(op);
    }
    ops
}

/// Returns false if the op wrote no record.
pub fn apply(s: &mut Store, op: &Op) -> bool {
    match op {
        Op::Put(k, v, l) => {
            s.put(k, v, *l).unwrap();
        }
        Op::Delete(k) => {
            s.delete(k).unwrap();
        }
        Op::Grant(id, ttl) => {
            s.grant_lease(*id, *ttl).unwrap();
        }
        Op::Revoke(id) => {
            s.revoke_lease(*id).unwrap();
        }
        Op::CompactBehind(n) => {
            let target = s.revision().saturating_sub(*n);
            if target <= s.compact_revision() {
                return false;
            }
            s.compact(target).unwrap();
        }
        Op::Txn(writes) => {
            let rev = s.revision();
            s.commit_writes(writes.clone()).unwrap();
            return s.revision() != rev;
        }
    }
    true
}
