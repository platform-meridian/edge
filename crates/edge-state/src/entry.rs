//! On-disk format: existing tags never change their bytes, new records get new tags, and
//! `decode` must never panic. Versions and create-revisions are recomputed on replay.

#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    Put {
        revision: u64,
        key: Vec<u8>,
        value: Vec<u8>,
        lease: i64,
    },
    Delete {
        revision: u64,
        key: Vec<u8>,
    },
    Compaction {
        compact_revision: u64,
    },
    LeaseGrant {
        id: i64,
        ttl: i64,
    },
    /// Read from existing logs, never written: superseded by `Revoke`. Its keys' deletes
    /// are separate `Delete` records before it.
    LeaseRevoke {
        id: i64,
    },
    Txn {
        revision: u64,
        writes: Vec<Write>,
    },
    /// `revision` is 0, consuming none, when the lease had no keys.
    Revoke {
        id: i64,
        revision: u64,
        keys: Vec<Vec<u8>>,
    },
    /// Opens a rotated log with the counters its surviving records cannot reconstruct.
    Base {
        revision: u64,
        compact_revision: u64,
        next_lease: i64,
    },
    /// A key's oldest version after rotation, whose metadata depended on versions that
    /// are gone.
    PutWithMeta {
        revision: u64,
        key: Vec<u8>,
        value: Vec<u8>,
        lease: i64,
        create_revision: u64,
        version: i64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Write {
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
        lease: i64,
    },
    Delete {
        key: Vec<u8>,
    },
}

const TAG_PUT: u8 = 0;
const TAG_DELETE: u8 = 1;
const TAG_COMPACTION: u8 = 2;
const TAG_LEASE_GRANT: u8 = 3;
const TAG_LEASE_REVOKE: u8 = 4;
const TAG_TXN: u8 = 5;
const TAG_REVOKE: u8 = 6;
const TAG_BASE: u8 = 7;
const TAG_PUT_WITH_META: u8 = 8;

const WRITE_PUT: u8 = 0;
const WRITE_DELETE: u8 = 1;

const LEN_PREFIX_BYTES: usize = 4;
const MIN_TXN_WRITE_BYTES: usize = 1 + LEN_PREFIX_BYTES;

fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    o.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        anyhow::ensure!(
            self.0.len() >= n,
            "entry truncated: wanted {n} bytes, have {}",
            self.0.len()
        );
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> anyhow::Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> anyhow::Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn count(&mut self, min_item_bytes: usize) -> anyhow::Result<usize> {
        let n = self.u32()? as usize;
        anyhow::ensure!(
            n.checked_mul(min_item_bytes)
                .is_some_and(|b| b <= self.0.len()),
            "entry count {n} overruns the entry"
        );
        Ok(n)
    }
    fn end(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.0.is_empty(),
            "{} trailing bytes in entry",
            self.0.len()
        );
        Ok(())
    }
}

impl Entry {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Entry::Put {
                revision,
                key,
                value,
                lease,
            } => {
                o.push(TAG_PUT);
                o.extend_from_slice(&revision.to_le_bytes());
                o.extend_from_slice(&lease.to_le_bytes());
                o.extend_from_slice(&(key.len() as u32).to_le_bytes());
                o.extend_from_slice(key);
                o.extend_from_slice(value);
            }
            Entry::Delete { revision, key } => {
                o.push(TAG_DELETE);
                o.extend_from_slice(&revision.to_le_bytes());
                o.extend_from_slice(key);
            }
            Entry::Compaction { compact_revision } => {
                o.push(TAG_COMPACTION);
                o.extend_from_slice(&compact_revision.to_le_bytes());
            }
            Entry::LeaseGrant { id, ttl } => {
                o.push(TAG_LEASE_GRANT);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&ttl.to_le_bytes());
            }
            Entry::LeaseRevoke { id } => {
                o.push(TAG_LEASE_REVOKE);
                o.extend_from_slice(&id.to_le_bytes());
            }
            Entry::Txn { revision, writes } => {
                o.push(TAG_TXN);
                o.extend_from_slice(&revision.to_le_bytes());
                o.extend_from_slice(&(writes.len() as u32).to_le_bytes());
                for w in writes {
                    match w {
                        Write::Put { key, value, lease } => {
                            o.push(WRITE_PUT);
                            o.extend_from_slice(&lease.to_le_bytes());
                            put_bytes(&mut o, key);
                            put_bytes(&mut o, value);
                        }
                        Write::Delete { key } => {
                            o.push(WRITE_DELETE);
                            put_bytes(&mut o, key);
                        }
                    }
                }
            }
            Entry::Revoke { id, revision, keys } => {
                o.push(TAG_REVOKE);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&revision.to_le_bytes());
                o.extend_from_slice(&(keys.len() as u32).to_le_bytes());
                for k in keys {
                    put_bytes(&mut o, k);
                }
            }
            Entry::Base {
                revision,
                compact_revision,
                next_lease,
            } => {
                o.push(TAG_BASE);
                o.extend_from_slice(&revision.to_le_bytes());
                o.extend_from_slice(&compact_revision.to_le_bytes());
                o.extend_from_slice(&next_lease.to_le_bytes());
            }
            Entry::PutWithMeta {
                revision,
                key,
                value,
                lease,
                create_revision,
                version,
            } => {
                o.push(TAG_PUT_WITH_META);
                o.extend_from_slice(&revision.to_le_bytes());
                o.extend_from_slice(&lease.to_le_bytes());
                o.extend_from_slice(&create_revision.to_le_bytes());
                o.extend_from_slice(&version.to_le_bytes());
                put_bytes(&mut o, key);
                o.extend_from_slice(value);
            }
        }
        o
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        let tag = *buf.first().ok_or_else(|| anyhow::anyhow!("empty entry"))?;
        let mut r = Reader(&buf[1..]);
        match tag {
            TAG_PUT => {
                let revision = r.u64()?;
                let lease = r.i64()?;
                let key = r.bytes()?;
                let value = r.0.to_vec();
                Ok(Entry::Put {
                    revision,
                    key,
                    value,
                    lease,
                })
            }
            TAG_DELETE => {
                let revision = r.u64()?;
                Ok(Entry::Delete {
                    revision,
                    key: r.0.to_vec(),
                })
            }
            TAG_COMPACTION => {
                let compact_revision = r.u64()?;
                r.end()?;
                Ok(Entry::Compaction { compact_revision })
            }
            TAG_LEASE_GRANT => {
                let id = r.i64()?;
                let ttl = r.i64()?;
                r.end()?;
                Ok(Entry::LeaseGrant { id, ttl })
            }
            TAG_LEASE_REVOKE => {
                let id = r.i64()?;
                r.end()?;
                Ok(Entry::LeaseRevoke { id })
            }
            TAG_TXN => {
                let revision = r.u64()?;
                let n = r.count(MIN_TXN_WRITE_BYTES)?;
                let mut writes = Vec::with_capacity(n);
                for _ in 0..n {
                    writes.push(match r.u8()? {
                        WRITE_PUT => {
                            let lease = r.i64()?;
                            let key = r.bytes()?;
                            let value = r.bytes()?;
                            Write::Put { key, value, lease }
                        }
                        WRITE_DELETE => Write::Delete { key: r.bytes()? },
                        other => anyhow::bail!("unknown txn write kind {other}"),
                    });
                }
                r.end()?;
                Ok(Entry::Txn { revision, writes })
            }
            TAG_REVOKE => {
                let id = r.i64()?;
                let revision = r.u64()?;
                let n = r.count(LEN_PREFIX_BYTES)?;
                let mut keys = Vec::with_capacity(n);
                for _ in 0..n {
                    keys.push(r.bytes()?);
                }
                r.end()?;
                Ok(Entry::Revoke { id, revision, keys })
            }
            TAG_BASE => {
                let revision = r.u64()?;
                let compact_revision = r.u64()?;
                let next_lease = r.i64()?;
                r.end()?;
                Ok(Entry::Base {
                    revision,
                    compact_revision,
                    next_lease,
                })
            }
            TAG_PUT_WITH_META => {
                let revision = r.u64()?;
                let lease = r.i64()?;
                let create_revision = r.u64()?;
                let version = r.i64()?;
                let key = r.bytes()?;
                let value = r.0.to_vec();
                Ok(Entry::PutWithMeta {
                    revision,
                    key,
                    value,
                    lease,
                    create_revision,
                    version,
                })
            }
            other => anyhow::bail!("unknown entry tag {other}"),
        }
    }

    pub fn consumed_revision(&self) -> Option<u64> {
        match self {
            Entry::Put { revision, .. }
            | Entry::Delete { revision, .. }
            | Entry::Txn { revision, .. }
            | Entry::PutWithMeta { revision, .. } => Some(*revision),
            Entry::Revoke { revision, .. } if *revision != 0 => Some(*revision),
            Entry::Compaction { compact_revision } => Some(*compact_revision),
            Entry::Base { revision, .. } => Some(*revision),
            Entry::LeaseGrant { .. } | Entry::LeaseRevoke { .. } | Entry::Revoke { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn golden() -> Vec<(Entry, Vec<u8>)> {
        vec![
            (
                Entry::Put {
                    revision: 7,
                    key: b"/a".to_vec(),
                    value: vec![0, 0, 0, 8, TAG_PUT, 255],
                    lease: -1,
                },
                cat(&[
                    &[0],
                    &7u64.to_le_bytes(),
                    &(-1i64).to_le_bytes(),
                    &2u32.to_le_bytes(),
                    b"/a",
                    &[0, 0, 0, 8, TAG_PUT, 255],
                ]),
            ),
            (
                Entry::Delete {
                    revision: 9,
                    key: b"/a".to_vec(),
                },
                cat(&[&[1], &9u64.to_le_bytes(), b"/a"]),
            ),
            (
                Entry::Compaction {
                    compact_revision: 5,
                },
                cat(&[&[2], &5u64.to_le_bytes()]),
            ),
            (
                Entry::LeaseGrant { id: -7, ttl: 30 },
                cat(&[&[3], &(-7i64).to_le_bytes(), &30i64.to_le_bytes()]),
            ),
            (
                Entry::LeaseRevoke { id: 42 },
                cat(&[&[4], &42i64.to_le_bytes()]),
            ),
            (
                Entry::Txn {
                    revision: 11,
                    writes: vec![
                        Write::Put {
                            key: b"/a".to_vec(),
                            value: b"v".to_vec(),
                            lease: 3,
                        },
                        Write::Delete {
                            key: b"/b".to_vec(),
                        },
                    ],
                },
                cat(&[
                    &[5],
                    &11u64.to_le_bytes(),
                    &2u32.to_le_bytes(),
                    &[0],
                    &3i64.to_le_bytes(),
                    &2u32.to_le_bytes(),
                    b"/a",
                    &1u32.to_le_bytes(),
                    b"v",
                    &[1],
                    &2u32.to_le_bytes(),
                    b"/b",
                ]),
            ),
            (
                Entry::Revoke {
                    id: 9,
                    revision: 12,
                    keys: vec![b"/x".to_vec(), vec![]],
                },
                cat(&[
                    &[6],
                    &9i64.to_le_bytes(),
                    &12u64.to_le_bytes(),
                    &2u32.to_le_bytes(),
                    &2u32.to_le_bytes(),
                    b"/x",
                    &0u32.to_le_bytes(),
                ]),
            ),
            (
                Entry::Base {
                    revision: 40,
                    compact_revision: 30,
                    next_lease: 7,
                },
                cat(&[
                    &[7],
                    &40u64.to_le_bytes(),
                    &30u64.to_le_bytes(),
                    &7i64.to_le_bytes(),
                ]),
            ),
            (
                Entry::PutWithMeta {
                    revision: 8,
                    key: b"/k".to_vec(),
                    value: b"v".to_vec(),
                    lease: 2,
                    create_revision: 3,
                    version: 4,
                },
                cat(&[
                    &[8],
                    &8u64.to_le_bytes(),
                    &2i64.to_le_bytes(),
                    &3u64.to_le_bytes(),
                    &4i64.to_le_bytes(),
                    &2u32.to_le_bytes(),
                    b"/k",
                    b"v",
                ]),
            ),
        ]
    }

    #[test]
    fn golden_bytes_round_trip() {
        for (e, bytes) in golden() {
            assert_eq!(e.encode(), bytes, "{e:?}");
            assert_eq!(Entry::decode(&bytes).unwrap(), e);
        }
    }

    #[test]
    fn empty_fields_round_trip() {
        for e in [
            Entry::Put {
                revision: 1,
                key: vec![],
                value: vec![],
                lease: 0,
            },
            Entry::Txn {
                revision: 1,
                writes: vec![Write::Put {
                    key: vec![],
                    value: vec![],
                    lease: 0,
                }],
            },
            Entry::Txn {
                revision: 1,
                writes: vec![],
            },
            Entry::Revoke {
                id: 9,
                revision: 0,
                keys: vec![],
            },
        ] {
            assert_eq!(Entry::decode(&e.encode()).unwrap(), e);
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        for (e, mut bytes) in golden() {
            if matches!(
                e,
                Entry::Put { .. } | Entry::Delete { .. } | Entry::PutWithMeta { .. }
            ) {
                continue;
            }
            bytes.push(0);
            assert!(Entry::decode(&bytes).is_err(), "{e:?}");
        }
    }

    #[test]
    fn rejects_unknown_tags() {
        assert!(Entry::decode(&[]).is_err());
        assert!(Entry::decode(&[99, 0, 0]).is_err());
        let txn = cat(&[
            &[5],
            &1u64.to_le_bytes(),
            &1u32.to_le_bytes(),
            &[2],
            &0u32.to_le_bytes(),
        ]);
        assert!(Entry::decode(&txn).is_err());
    }

    #[test]
    fn revision_only_when_consumed() {
        for (e, want) in golden().into_iter().map(|(e, _)| e).zip([
            Some(7),
            Some(9),
            Some(5),
            None,
            None,
            Some(11),
            Some(12),
            Some(40),
            Some(8),
        ]) {
            assert_eq!(e.consumed_revision(), want, "{e:?}");
        }
        let empty_revoke = Entry::Revoke {
            id: 1,
            revision: 0,
            keys: vec![],
        };
        assert_eq!(empty_revoke.consumed_revision(), None);
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    #[test]
    fn decode_never_panics() {
        let mut rng = Rng(0xDEAD_BEEF_1234_5678);
        for _ in 0..20_000 {
            let n = (rng.next() % 96) as usize;
            let mut buf: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            if !buf.is_empty() {
                buf[0] %= 12;
            }
            let _ = Entry::decode(&buf);
        }
        for (e, bytes) in golden() {
            for cut in 0..bytes.len() {
                let _ = Entry::decode(&bytes[..cut]);
            }
            for i in 0..bytes.len() {
                for b in [0x00, 0xff, 0x80, bytes[i] ^ 1] {
                    let mut m = bytes.clone();
                    m[i] = b;
                    let _ = Entry::decode(&m);
                }
            }
            let count_at = match e {
                Entry::Txn { .. } => 9,
                Entry::Revoke { .. } => 17,
                _ => continue,
            };
            let mut m = bytes.clone();
            m[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(Entry::decode(&m).is_err());
        }
    }
}
