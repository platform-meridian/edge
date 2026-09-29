mod common;

use common::{Dump, apply, dump, script};
use edge_state::store::Store;
use std::path::Path;

fn build(path: &Path, ops: &[common::Op]) -> Vec<(u64, Dump)> {
    let mut s = Store::open(path).unwrap();
    let mut cps = vec![(0u64, dump(&s))];
    for op in ops {
        let before = s.log_len();
        apply(&mut s, op);
        if s.log_len() > before {
            cps.push((s.log_len(), dump(&s)));
        }
    }
    cps
}

fn open_bytes(dir: &Path, bytes: &[u8]) -> (anyhow::Result<Store>, std::path::PathBuf) {
    let p = dir.join("crashed.log");
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, bytes).unwrap();
    (Store::open(&p), p)
}

// Every byte offset is a case, so the script stays small.
const SCRIPT_LEN: usize = 45;

#[test]
fn every_truncation_recovers() {
    for seed in [1u64, 7] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.log");
        let cps = build(&path, &script(seed, SCRIPT_LEN));
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, cps.last().unwrap().0);

        for cut in 0..=bytes.len() {
            let (store, p) = open_bytes(dir.path(), &bytes[..cut]);
            let mut store =
                store.unwrap_or_else(|e| panic!("seed {seed}: open failed at cut {cut}: {e:#}"));
            let (len, want) = cps.iter().rev().find(|(l, _)| *l <= cut as u64).unwrap();
            assert_eq!(
                &dump(&store),
                want,
                "seed {seed}: cut at {cut} did not recover the prefix ending at {len}"
            );
            assert_eq!(
                std::fs::metadata(&p).unwrap().len(),
                *len,
                "cut {cut}: the torn tail was not trimmed"
            );
            if cut % 11 == 0 {
                store.put(b"/after-crash", b"still-here", 0).unwrap();
                drop(store);
                let again = Store::open(&p).unwrap();
                assert!(
                    again.get(b"/after-crash", 0).is_some(),
                    "seed {seed}: cut {cut}: a write after recovery was lost"
                );
            }
        }
    }
}

#[test]
fn zero_filled_tails_recover() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.log");
    let cps = build(&path, &script(3, 30));
    let bytes = std::fs::read(&path).unwrap();

    for zeros in [1usize, 7, 8, 9, 37, 4096] {
        for cut in 0..=bytes.len() {
            let mut damaged = bytes[..cut].to_vec();
            damaged.extend(std::iter::repeat_n(0u8, zeros));
            let (store, p) = open_bytes(dir.path(), &damaged);
            let store = store
                .unwrap_or_else(|e| panic!("{zeros} zeros after byte {cut}: open failed: {e:#}"));
            // Zeros can complete a record whose tail was zeros anyway, so any
            // checkpoint at or past the cut's is correct.
            let recovered_len = std::fs::metadata(&p).unwrap().len();
            let (_, want) = cps
                .iter()
                .find(|(l, _)| *l == recovered_len)
                .unwrap_or_else(|| panic!("{zeros} zeros after {cut}: recovered to {recovered_len}, which is not a record boundary"));
            assert_eq!(&dump(&store), want, "{zeros} zeros after byte {cut}");
            let floor = cps.iter().rev().find(|(l, _)| *l <= cut as u64).unwrap().0;
            assert!(
                recovered_len >= floor,
                "{zeros} zeros after {cut}: lost a committed record ({recovered_len} < {floor})"
            );
        }
    }
}

#[test]
fn final_record_flip_costs_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.log");
    let cps = build(&path, &script(5, SCRIPT_LEN));
    let bytes = std::fs::read(&path).unwrap();
    let last_start = cps[cps.len() - 2].0 as usize;
    let want = &cps[cps.len() - 2].1;

    for byte in last_start..bytes.len() {
        for bit in 0..8 {
            let mut damaged = bytes.clone();
            damaged[byte] ^= 1 << bit;
            let (store, _) = open_bytes(dir.path(), &damaged);
            let store = store.unwrap_or_else(|e| panic!("flip {byte}.{bit}: open failed: {e:#}"));
            assert_eq!(&dump(&store), want, "flip of byte {byte} bit {bit}");
        }
    }
}

fn flip_bits(synced: bool, step: usize) -> usize {
    let dir = common::tempdir();
    let path = dir.path().join("state.log");
    let cps = build(&path, &script(9, 40));
    let last_start = cps[cps.len() - 2].0 as usize;
    if synced {
        common::fill_past_a_batch(&path);
    }
    let bytes = std::fs::read(&path).unwrap();

    let mut tested = 0;
    for byte in (0..last_start).step_by(step) {
        for bit in [0u8, 3, 7] {
            let mut damaged = bytes.clone();
            damaged[byte] ^= 1 << bit;
            let (store, p) = open_bytes(dir.path(), &damaged);
            let store = store
                .unwrap_or_else(|e| panic!("flip of byte {byte} bit {bit} refused to boot: {e:#}"));
            let i = cps.iter().rposition(|(l, _)| *l as usize <= byte).unwrap();
            assert_eq!(
                dump(&store),
                cps[i].1,
                "flip of byte {byte} bit {bit} (record {i})"
            );
            let cut = cps[i].0;
            assert_eq!(
                std::fs::metadata(&p).unwrap().len(),
                cut,
                "the log was not cut back"
            );
            let r = store.recovery();
            if synced {
                let d = r.damage.as_ref().expect("the damage must be reported");
                assert_eq!(d.offset, cut);
                let copy = d.preserved.as_ref().expect("dropped bytes must be kept");
                assert_eq!(std::fs::read(copy).unwrap(), &damaged[cut as usize..]);
            } else {
                assert!(r.damage.is_none(), "flip of byte {byte}: {:?}", r.damage);
                assert_eq!(r.torn_bytes, damaged.len() as u64 - cut);
            }
            drop(store);
            let again = Store::open(&p).unwrap();
            assert!(again.recovery().damage.is_none());
            tested += 1;
        }
    }
    tested
}

#[test]
fn synced_flip_is_cut_and_kept() {
    assert!(flip_bits(true, 29) > 100);
}

#[test]
fn last_batch_flip_is_cut_quietly() {
    assert!(flip_bits(false, 3) > 100);
}
