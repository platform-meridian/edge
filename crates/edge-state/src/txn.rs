//! A branch's reads see the state before it or, when they follow every write they overlap,
//! the state after it (etcd's `concurrency.Mutex` depends on this).

use crate::entry::Write;
use crate::store::{KeyValue, MAX_TXN_OPS, RangeOutput, RangeQuery, Store, StoreError};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Equal,
    NotEqual,
    Greater,
    Less,
}

#[derive(Debug, Clone)]
pub enum Target {
    Mod(i64),
    Create(i64),
    Version(i64),
    Value(Vec<u8>),
    Lease(i64),
}

#[derive(Debug, Clone)]
pub struct Compare {
    pub key: Vec<u8>,
    pub range_end: Vec<u8>,
    pub op: CmpOp,
    pub target: Target,
}

#[derive(Debug, Clone)]
pub enum Op {
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
        lease: i64,
        prev_kv: bool,
    },
    Delete {
        key: Vec<u8>,
        range_end: Vec<u8>,
        prev_kv: bool,
    },
    Range(RangeQuery),
}

#[derive(Debug)]
pub enum OpResult {
    Put { prev: Option<KeyValue> },
    Delete { deleted: i64, prev: Vec<KeyValue> },
    Range(RangeOutput),
}

#[derive(Debug)]
pub struct TxnResult {
    pub succeeded: bool,
    pub revision: u64,
    pub results: Vec<OpResult>,
}

impl CmpOp {
    fn eval<T: Ord>(self, actual: &T, target: &T) -> bool {
        match self {
            CmpOp::Equal => actual == target,
            CmpOp::NotEqual => actual != target,
            CmpOp::Greater => actual > target,
            CmpOp::Less => actual < target,
        }
    }
}

impl Compare {
    fn eval(&self, store: &Store) -> Result<bool, StoreError> {
        let want_value = matches!(self.target, Target::Value(_));
        let found = store.query(&RangeQuery {
            key: self.key.clone(),
            range_end: self.range_end.clone(),
            keys_only: !want_value,
            ..Default::default()
        })?;
        if found.kvs.is_empty() {
            return Ok(match &self.target {
                Target::Value(_) => false,
                Target::Mod(t) | Target::Create(t) | Target::Version(t) | Target::Lease(t) => {
                    self.op.eval(&0, t)
                }
            });
        }
        Ok(found.kvs.iter().all(|kv| match &self.target {
            Target::Mod(t) => self.op.eval(&(kv.mod_revision as i64), t),
            Target::Create(t) => self.op.eval(&(kv.create_revision as i64), t),
            Target::Version(t) => self.op.eval(&kv.version, t),
            Target::Value(t) => self.op.eval(&kv.value, t),
            Target::Lease(t) => self.op.eval(&kv.lease, t),
        }))
    }
}

struct Interval {
    start: Vec<u8>,
    end_exclusive: Option<Vec<u8>>,
}

fn interval(key: &[u8], range_end: &[u8]) -> Interval {
    let end_exclusive = if range_end.is_empty() {
        let mut end = key.to_vec();
        end.push(0);
        Some(end)
    } else if range_end == [0] {
        None
    } else {
        Some(range_end.to_vec())
    };
    Interval {
        start: key.to_vec(),
        end_exclusive,
    }
}

fn overlaps(a: &Interval, b: &Interval) -> bool {
    let a_before_b = a.end_exclusive.as_ref().is_some_and(|e| *e <= b.start);
    let b_before_a = b.end_exclusive.as_ref().is_some_and(|e| *e <= a.start);
    !(a_before_b || b_before_a)
}

fn validate_and_find_reads_after_writes(branch: &[Op]) -> Result<Vec<bool>, StoreError> {
    let mut puts: Vec<Interval> = Vec::new();
    let mut dels: Vec<Interval> = Vec::new();
    let mut after_write = vec![false; branch.len()];
    for (i, op) in branch.iter().enumerate() {
        match op {
            Op::Put { key, .. } => {
                let iv = interval(key, &[]);
                if puts.iter().any(|p| p.start == iv.start) || dels.iter().any(|d| overlaps(d, &iv))
                {
                    return Err(StoreError::DuplicateKey);
                }
                puts.push(iv);
            }
            Op::Delete { key, range_end, .. } => {
                let iv = interval(key, range_end);
                if puts.iter().any(|p| overlaps(p, &iv)) {
                    return Err(StoreError::DuplicateKey);
                }
                dels.push(iv);
            }
            Op::Range(q) => {
                let iv = interval(&q.key, &q.range_end);
                after_write[i] = puts.iter().chain(dels.iter()).any(|w| overlaps(w, &iv));
            }
        }
    }
    for (i, op) in branch.iter().enumerate() {
        let Op::Range(q) = op else { continue };
        if !after_write[i] {
            continue;
        }
        let iv = interval(&q.key, &q.range_end);
        let later_write = branch[i + 1..].iter().any(|o| match o {
            Op::Put { key, .. } => overlaps(&interval(key, &[]), &iv),
            Op::Delete { key, range_end, .. } => overlaps(&interval(key, range_end), &iv),
            Op::Range(_) => false,
        });
        if later_write {
            return Err(StoreError::Unsupported(
                "a range between two writes it could observe in the same txn branch".into(),
            ));
        }
    }
    Ok(after_write)
}

pub fn run(
    store: &mut Store,
    compares: &[Compare],
    success: &[Op],
    failure: &[Op],
) -> Result<TxnResult, StoreError> {
    if compares.len() > MAX_TXN_OPS || success.len() > MAX_TXN_OPS || failure.len() > MAX_TXN_OPS {
        return Err(StoreError::TooManyOps);
    }
    let mut succeeded = true;
    for c in compares {
        if !c.eval(store)? {
            succeeded = false;
            break;
        }
    }
    let branch = if succeeded { success } else { failure };
    let read_after_write = validate_and_find_reads_after_writes(branch)?;
    for op in branch {
        if let Op::Range(q) = op {
            store.check_revision(q.revision)?;
        }
    }

    let mut results = Vec::with_capacity(branch.len());
    let mut writes: Vec<Write> = Vec::new();
    let mut deleted_in_branch: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (op, after_write) in branch.iter().zip(&read_after_write) {
        results.push(match op {
            Op::Put {
                key,
                value,
                lease,
                prev_kv,
            } => {
                let prev = if *prev_kv { store.get(key, 0) } else { None };
                writes.push(Write::Put {
                    key: key.clone(),
                    value: value.clone(),
                    lease: *lease,
                });
                OpResult::Put { prev }
            }
            Op::Delete {
                key,
                range_end,
                prev_kv,
            } => {
                let hit = store.query(&RangeQuery {
                    key: key.clone(),
                    range_end: range_end.clone(),
                    keys_only: !*prev_kv,
                    ..Default::default()
                })?;
                let mut n = 0;
                let mut prev = Vec::new();
                for kv in hit.kvs {
                    if deleted_in_branch.insert(kv.key.clone()) {
                        n += 1;
                        writes.push(Write::Delete {
                            key: kv.key.clone(),
                        });
                        if *prev_kv {
                            prev.push(kv);
                        }
                    }
                }
                OpResult::Delete { deleted: n, prev }
            }
            Op::Range(_) if *after_write => OpResult::Range(RangeOutput::default()),
            Op::Range(q) => OpResult::Range(store.query(q)?),
        });
    }

    let revision = store.commit_writes(writes)?;

    for ((op, after_write), result) in branch.iter().zip(&read_after_write).zip(results.iter_mut())
    {
        if let (Op::Range(q), true) = (op, after_write) {
            *result = OpResult::Range(store.query(q)?);
        }
    }
    Ok(TxnResult {
        succeeded,
        revision,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path().join("s.log")).unwrap();
        (d, s)
    }

    fn cmp(key: &str, op: CmpOp, target: Target) -> Compare {
        Compare {
            key: key.into(),
            range_end: vec![],
            op,
            target,
        }
    }

    fn put(key: &str, value: &str) -> Op {
        Op::Put {
            key: key.into(),
            value: value.into(),
            lease: 0,
            prev_kv: false,
        }
    }

    fn get(key: &str) -> Op {
        Op::Range(RangeQuery {
            key: key.into(),
            ..Default::default()
        })
    }

    fn get_range(key: &str, end: &str) -> Op {
        Op::Range(RangeQuery {
            key: key.into(),
            range_end: end.into(),
            ..Default::default()
        })
    }

    fn del(key: &str, end: &str) -> Op {
        Op::Delete {
            key: key.into(),
            range_end: end.into(),
            prev_kv: false,
        }
    }

    #[test]
    fn compare_operators_and_targets() {
        use CmpOp::*;
        let (_d, mut s) = store();
        let lease = s.grant_lease(0, 30).unwrap();
        let rev = s.put(b"/k", b"b", lease).unwrap().0 as i64;
        s.put(b"/other", b"x", 0).unwrap();
        let cases = [
            ("/k", Equal, Target::Mod(rev), true),
            ("/k", NotEqual, Target::Mod(rev), false),
            ("/k", Greater, Target::Mod(rev), false),
            ("/k", Greater, Target::Mod(rev - 1), true),
            ("/k", Less, Target::Mod(rev), false),
            ("/k", Less, Target::Mod(rev + 1), true),
            ("/k", Equal, Target::Create(rev), true),
            ("/k", Equal, Target::Version(1), true),
            ("/k", Less, Target::Version(1), false),
            ("/k", Equal, Target::Value(b"b".to_vec()), true),
            ("/k", Greater, Target::Value(b"a".to_vec()), true),
            ("/k", Less, Target::Value(b"c".to_vec()), true),
            ("/k", Equal, Target::Lease(lease), true),
            ("/k", Equal, Target::Lease(0), false),
            ("/absent", Equal, Target::Mod(0), true),
            ("/absent", Equal, Target::Create(0), true),
            ("/absent", Greater, Target::Version(0), false),
            ("/absent", Equal, Target::Lease(0), true),
            ("/absent", Equal, Target::Value(vec![]), false),
            ("/absent", NotEqual, Target::Value(vec![]), false),
            ("/absent", Greater, Target::Value(vec![]), false),
            ("/absent", Less, Target::Value(b"z".to_vec()), false),
        ];
        for (key, op, target, want) in cases {
            let what = format!("{key} {op:?} {target:?}");
            let r = run(&mut s, &[cmp(key, op, target)], &[], &[]).unwrap();
            assert_eq!(r.succeeded, want, "{what}");
        }
        let both = [
            cmp("/k", Equal, Target::Version(1)),
            cmp("/other", Equal, Target::Version(9)),
        ];
        assert!(!run(&mut s, &both, &[], &[]).unwrap().succeeded);
    }

    #[test]
    fn invalid_branch_writes_nothing() {
        let (_d, mut s) = store();
        s.put(b"/k", b"v", 0).unwrap();
        let before = (s.revision(), s.log_len());
        let bad_lease = Op::Put {
            key: b"/b".to_vec(),
            value: b"2".to_vec(),
            lease: 999,
            prev_kv: false,
        };
        let too_many: Vec<Op> = (0..=MAX_TXN_OPS)
            .map(|i| put(&format!("/m{i}"), "v"))
            .collect();
        type Refusal = (Vec<Op>, fn(&StoreError) -> bool);
        let refused: Vec<Refusal> = vec![
            (vec![put("/k", "1"), put("/k", "2")], |e| {
                matches!(e, StoreError::DuplicateKey)
            }),
            (vec![put("/k", "1"), del("/k", "")], |e| {
                matches!(e, StoreError::DuplicateKey)
            }),
            (vec![del("/", "0"), put("/k", "1")], |e| {
                matches!(e, StoreError::DuplicateKey)
            }),
            (vec![put("/k", "1"), get("/k"), del("/k", "")], |e| {
                matches!(e, StoreError::DuplicateKey)
            }),
            (
                vec![put("/a/1", "1"), get_range("/a/", "/a0"), put("/a/2", "2")],
                |e| matches!(e, StoreError::Unsupported(_)),
            ),
            (
                vec![del("/a/1", ""), get_range("/a/", "/a0"), put("/a/2", "2")],
                |e| matches!(e, StoreError::Unsupported(_)),
            ),
            (vec![put("/a", "1"), bad_lease], |e| {
                matches!(e, StoreError::LeaseNotFound(999))
            }),
            (too_many, |e| matches!(e, StoreError::TooManyOps)),
        ];
        for (branch, want) in refused {
            let e = run(&mut s, &[], &branch, &[]).unwrap_err();
            assert!(want(&e), "{branch:?}: {e}");
            assert_eq!((s.revision(), s.log_len()), before, "{branch:?}");
        }
    }

    #[test]
    fn reads_see_before_or_after_writes() {
        let (_d, mut s) = store();
        s.put(b"/k", b"v", 0).unwrap();
        let range = |r: &OpResult| match r {
            OpResult::Range(out) => out
                .kvs
                .iter()
                .map(|kv| kv.value.clone())
                .collect::<Vec<_>>(),
            other => panic!("{other:?}"),
        };
        let r = run(
            &mut s,
            &[],
            &[get("/k"), put("/k", "1"), get("/other")],
            &[],
        )
        .unwrap();
        assert_eq!(range(&r.results[0]), vec![b"v".to_vec()]);
        let r = run(&mut s, &[], &[put("/k", "2"), get("/k")], &[]).unwrap();
        assert_eq!(range(&r.results[1]), vec![b"2".to_vec()]);
        let r = run(&mut s, &[], &[del("/k", ""), get("/k")], &[]).unwrap();
        assert!(range(&r.results[1]).is_empty());
    }

    #[test]
    fn overlapping_deletes_count_once() {
        let (_d, mut s) = store();
        for k in ["/d/1", "/d/2", "/e"] {
            s.put(k.as_bytes(), b"v", 0).unwrap();
        }
        let r = run(
            &mut s,
            &[],
            &[del("/d/", "/d0"), del("/d/1", ""), del("/", "\0")],
            &[],
        )
        .unwrap();
        let counts: Vec<i64> = r
            .results
            .iter()
            .map(|r| match r {
                OpResult::Delete { deleted, .. } => *deleted,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(counts, vec![2, 0, 1]);
        assert!(s.range_from(&[], 0).is_empty());
    }

    #[test]
    fn max_txn_ops_allowed() {
        let (_d, mut s) = store();
        let ops: Vec<Op> = (0..MAX_TXN_OPS)
            .map(|i| put(&format!("/k{i}"), "v"))
            .collect();
        let compares: Vec<Compare> = (0..MAX_TXN_OPS)
            .map(|i| cmp(&format!("/k{i}"), CmpOp::Equal, Target::Mod(0)))
            .collect();
        assert!(run(&mut s, &compares, &ops, &ops).unwrap().succeeded);
    }
}
