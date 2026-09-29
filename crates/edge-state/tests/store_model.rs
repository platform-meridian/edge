mod common;

use common::Rng;
use edge_state::store::{EventKind, KeyValue, Store};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct Rec {
    rev: u64,
    key: Vec<u8>,
    val: Option<Vec<u8>>,
    lease: i64,
}

#[derive(Default)]
struct Model {
    rev: u64,
    floor: u64,
    hist: Vec<Rec>,
    leases: BTreeMap<i64, i64>,
}

impl Model {
    fn new() -> Self {
        Model {
            rev: 1,
            ..Default::default()
        }
    }

    fn get(&self, key: &[u8], at: u64) -> Option<KeyValue> {
        let recs: Vec<&Rec> = self
            .hist
            .iter()
            .filter(|r| r.key == key && r.rev <= at)
            .collect();
        let last = recs.last()?;
        let value = last.val.clone()?;
        let start = recs
            .iter()
            .rposition(|r| r.val.is_none())
            .map_or(0, |i| i + 1);
        let life = &recs[start..];
        Some(KeyValue {
            key: key.to_vec(),
            value,
            create_revision: life[0].rev,
            mod_revision: last.rev,
            version: life.len() as i64,
            lease: last.lease,
        })
    }

    fn live_at(&self, at: u64) -> Vec<KeyValue> {
        let keys: std::collections::BTreeSet<&Vec<u8>> = self.hist.iter().map(|r| &r.key).collect();
        keys.into_iter().filter_map(|k| self.get(k, at)).collect()
    }

    fn put(&mut self, key: &[u8], val: &[u8], lease: i64) -> Option<KeyValue> {
        let prev = self.get(key, u64::MAX);
        self.rev += 1;
        self.hist.push(Rec {
            rev: self.rev,
            key: key.to_vec(),
            val: Some(val.to_vec()),
            lease,
        });
        prev
    }

    fn delete(&mut self, key: &[u8]) -> Option<KeyValue> {
        let prev = self.get(key, u64::MAX);
        if prev.is_some() {
            self.rev += 1;
            self.hist.push(Rec {
                rev: self.rev,
                key: key.to_vec(),
                val: None,
                lease: 0,
            });
        }
        prev
    }

    fn revoke(&mut self, id: i64) {
        let keys: Vec<Vec<u8>> = self
            .live_at(u64::MAX)
            .into_iter()
            .filter(|kv| kv.lease == id)
            .map(|kv| kv.key)
            .collect();
        if !keys.is_empty() {
            self.rev += 1;
            for k in keys {
                self.hist.push(Rec {
                    rev: self.rev,
                    key: k,
                    val: None,
                    lease: 0,
                });
            }
        }
        self.leases.remove(&id);
    }
}

fn assert_agrees(store: &Store, m: &Model, rng: &mut Rng, what: &str) {
    assert_eq!(store.revision(), m.rev, "{what}: revision");
    assert_eq!(store.compact_revision(), m.floor, "{what}: floor");
    let ids: BTreeMap<i64, i64> = store
        .lease_ids()
        .into_iter()
        .map(|i| (i, store.lease_ttl(i).unwrap()))
        .collect();
    assert_eq!(ids, m.leases, "{what}: leases");

    let mut revs = vec![m.rev, m.floor.max(1)];
    for _ in 0..4 {
        revs.push(m.floor.max(1) + rng.below(m.rev - m.floor.max(1) + 1));
    }
    for at in revs {
        assert!(
            store.check_revision(at).is_ok(),
            "{what}: revision {at} should be servable"
        );
        assert_eq!(
            store.range_from(&[], at),
            m.live_at(at),
            "{what}: full range at {at}"
        );
        for k in 0..8 {
            let key = format!("/k{k}").into_bytes();
            assert_eq!(
                store.get(&key, at),
                m.get(&key, at),
                "{what}: get {k} at {at}"
            );
        }
    }
    for id in m.leases.keys() {
        let want: Vec<Vec<u8>> = m
            .live_at(u64::MAX)
            .into_iter()
            .filter(|kv| kv.lease == *id)
            .map(|kv| kv.key)
            .collect();
        assert_eq!(store.lease_keys(*id), want, "{what}: keys of lease {id}");
    }
    for after in [m.floor, m.floor + rng.below(m.rev - m.floor + 1)] {
        let got: Vec<(u64, Vec<u8>, bool)> = store
            .events_since(after)
            .unwrap()
            .into_iter()
            .map(|e| (e.kv.mod_revision, e.kv.key, e.kind == EventKind::Put))
            .collect();
        let mut want: Vec<(u64, Vec<u8>, bool)> = m
            .hist
            .iter()
            .filter(|r| r.rev > after)
            .map(|r| (r.rev, r.key.clone(), r.val.is_some()))
            .collect();
        want.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        assert_eq!(got, want, "{what}: events after {after}");
    }
    if m.floor > 1 {
        assert!(
            store.check_revision(m.floor - 1).is_err(),
            "{what}: below the floor"
        );
    }
    assert!(
        store.check_revision(m.rev + 1).is_err(),
        "{what}: the future"
    );
}

#[test]
fn store_matches_model() {
    std::thread::scope(|s| {
        for seed in 1..=8u64 {
            s.spawn(move || agrees_with_the_model(seed));
        }
    });
}

fn agrees_with_the_model(seed: u64) {
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.log");
        let mut store = Store::open(&path).unwrap();
        let mut m = Model::new();
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut next_lease = 1000;

        for step in 0..260 {
            let key = format!("/k{}", rng.below(8)).into_bytes();
            let what = format!("seed {seed} step {step}");
            match rng.below(12) {
                0..=3 => {
                    let v: Vec<u8> = (0..rng.below(6)).map(|_| rng.next() as u8).collect();
                    let (rev, prev) = store.put(&key, &v, 0).unwrap();
                    let mprev = m.put(&key, &v, 0);
                    assert_eq!((rev, prev), (m.rev, mprev), "{what}: put result");
                }
                4 | 5 => {
                    let (rev, prev) = store.delete(&key).unwrap();
                    let mprev = m.delete(&key);
                    assert_eq!((rev, prev), (m.rev, mprev), "{what}: delete result");
                }
                6 => {
                    next_lease += 1;
                    let ttl = 5 + rng.below(50) as i64;
                    assert_eq!(store.grant_lease(next_lease, ttl).unwrap(), next_lease);
                    m.leases.insert(next_lease, ttl);
                }
                7 | 8 if !m.leases.is_empty() => {
                    let ids: Vec<i64> = m.leases.keys().copied().collect();
                    let id = ids[rng.below(ids.len() as u64) as usize];
                    let v = vec![rng.next() as u8];
                    let (rev, prev) = store.put(&key, &v, id).unwrap();
                    let mprev = m.put(&key, &v, id);
                    assert_eq!((rev, prev), (m.rev, mprev), "{what}: leased put");
                }
                9 if !m.leases.is_empty() => {
                    let ids: Vec<i64> = m.leases.keys().copied().collect();
                    let id = ids[rng.below(ids.len() as u64) as usize];
                    let rev = store.revoke_lease(id).unwrap();
                    m.revoke(id);
                    assert_eq!(rev, m.rev, "{what}: revoke revision");
                }
                10 => {
                    let target = m.floor + 1 + rng.below(m.rev - m.floor + 1);
                    let r = store.compact(target);
                    if target <= m.rev {
                        r.unwrap();
                        m.floor = target;
                    } else {
                        assert!(r.is_err(), "{what}: compaction into the future");
                    }
                }
                _ => {
                    assert!(store.put(&key, b"x", 999_999).is_err());
                    assert!(
                        store.compact(m.floor).is_err(),
                        "{what}: compacting at the floor again"
                    );
                    assert!(store.revoke_lease(888_888).is_err());
                }
            }
            assert_agrees(&store, &m, &mut rng, &what);
            if step % 40 == 39 {
                drop(store);
                store = Store::open(&path).unwrap();
                assert_agrees(&store, &m, &mut rng, &format!("{what} (after reopen)"));
            }
        }
    }
}

#[test]
fn revoke_is_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path().join("state.log")).unwrap();
    let id = s.grant_lease(0, 30).unwrap();
    for i in 0..25 {
        s.put(format!("/e/{i}").as_bytes(), b"x", id).unwrap();
    }
    let (rev_before, len_before) = (s.revision(), s.log_len());
    let rev = s.revoke_lease(id).unwrap();
    assert_eq!(rev, rev_before + 1, "one revision for the whole revoke");
    let grew = s.log_len() - len_before;
    assert!(
        grew < 25 * 16 + 64,
        "revoke wrote {grew} bytes; expected one compact record"
    );
    assert!(s.range_prefix(b"/e/", 0).is_empty());
    let evs = s.events_since(rev_before).unwrap();
    assert_eq!(evs.len(), 25);
    assert!(evs.iter().all(|e| e.kv.mod_revision == rev));
}

#[test]
fn lease_ids_never_collide() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path().join("state.log")).unwrap();
    s.grant_lease(1, 10).unwrap();
    let auto = s.grant_lease(0, 10).unwrap();
    s.grant_lease(i64::MAX, 10).unwrap();
    let a = s.grant_lease(0, 10).unwrap();
    let b = s.grant_lease(0, 10).unwrap();
    assert_eq!(
        (auto, a, b),
        (2, 3, 4),
        "skips taken ids and wraps at i64::MAX"
    );
    drop(s);
    let s = Store::open(dir.path().join("state.log")).unwrap();
    assert_eq!(s.lease_ids().len(), 5);
}
