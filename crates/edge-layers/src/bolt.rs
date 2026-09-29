//! A read-only bbolt reader (format version 2). The file is read whole, never locked
//! or mapped, and trusted only if the active meta is unchanged afterwards: bbolt reuses
//! a freed page only after a later commit.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail, ensure};

const MAGIC: u32 = 0xED0C_DAED;
const VERSION: u32 = 2;
const PAGE_HEADER: usize = 16;
const ELEMENT: usize = 16;
const BUCKET_HEADER: usize = 16;
const BRANCH: u16 = 0x01;
const LEAF: u16 = 0x02;
const BUCKET_LEAF: u32 = 0x01;
const READ_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Meta {
    page_size: usize,
    root: u64,
    high_water: u64,
    txid: u64,
}

pub struct Db {
    data: Vec<u8>,
    meta: Meta,
}

#[derive(Clone, Copy)]
pub enum Bucket<'a> {
    Page(u64),
    /// An inline bucket carries its single leaf page inside its value.
    Inline(&'a [u8]),
}

pub enum Value<'a> {
    Bucket(Bucket<'a>),
    Data(&'a [u8]),
}

fn u16_at(b: &[u8], at: usize) -> anyhow::Result<u16> {
    let s = b.get(at..at + 2).context("truncated")?;
    Ok(u16::from_le_bytes(s.try_into()?))
}

fn u32_at(b: &[u8], at: usize) -> anyhow::Result<u32> {
    let s = b.get(at..at + 4).context("truncated")?;
    Ok(u32::from_le_bytes(s.try_into()?))
}

fn u64_at(b: &[u8], at: usize) -> anyhow::Result<u64> {
    let s = b.get(at..at + 8).context("truncated")?;
    Ok(u64::from_le_bytes(s.try_into()?))
}

fn fnv64a(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325, |h, &x| {
        (h ^ u64::from(x)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn meta_at(data: &[u8], page_offset: usize) -> Option<Meta> {
    let m = page_offset + PAGE_HEADER;
    let body = data.get(m..m + 64)?;
    let ok = u32_at(body, 0).ok()? == MAGIC
        && u32_at(body, 4).ok()? == VERSION
        && u64_at(body, 56).ok()? == fnv64a(&body[..56]);
    let page_size = u32_at(body, 8).ok()? as usize;
    (ok && (512..=1 << 20).contains(&page_size) && page_size.is_power_of_two()).then(|| Meta {
        page_size,
        root: u64_at(body, 16).unwrap_or(0),
        high_water: u64_at(body, 40).unwrap_or(0),
        txid: u64_at(body, 48).unwrap_or(0),
    })
}

/// The newer of the two valid metas. Meta 1 lives one page in; if meta 0 is
/// torn its page size is unknown, so the common sizes are tried.
fn active_meta(data: &[u8]) -> Option<Meta> {
    let m0 = meta_at(data, 0);
    let m1 = match m0 {
        Some(m) => meta_at(data, m.page_size),
        None => [4096, 8192, 16384, 65536]
            .into_iter()
            .find_map(|ps| meta_at(data, ps).filter(|m| m.page_size == ps)),
    };
    match (m0, m1) {
        (Some(a), Some(b)) => Some(if b.txid > a.txid { b } else { a }),
        (a, b) => a.or(b),
    }
}

impl Db {
    pub fn read(path: &Path) -> anyhow::Result<Db> {
        let mut last = None;
        for _ in 0..READ_ATTEMPTS {
            let data =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let Some(before) = active_meta(&data) else {
                last = Some(anyhow::anyhow!("no valid meta page"));
                continue;
            };
            let head = read_prefix(path, before.page_size * 2)?;
            if active_meta(&head) == Some(before) {
                return Db::parse(data).with_context(|| format!("parsing {}", path.display()));
            }
            last = Some(anyhow::anyhow!("committed to while being read"));
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("unreadable")))
            .with_context(|| format!("{} after {READ_ATTEMPTS} attempts", path.display()))
    }

    pub fn parse(data: Vec<u8>) -> anyhow::Result<Db> {
        let meta = active_meta(&data)
            .context("no valid meta page: not a bbolt file, or both metas torn")?;
        ensure!(
            (meta.high_water as usize).saturating_mul(meta.page_size) <= data.len(),
            "file is shorter than its high-water mark"
        );
        Ok(Db { data, meta })
    }

    pub fn root(&self) -> Bucket<'_> {
        Bucket::Page(self.meta.root)
    }

    fn page(&self, id: u64) -> anyhow::Result<&[u8]> {
        ensure!(
            id >= 2 && id < self.meta.high_water,
            "page {id} out of range"
        );
        let start = id as usize * self.meta.page_size;
        let hdr = self
            .data
            .get(start..start + PAGE_HEADER)
            .context("page past end")?;
        ensure!(u64_at(hdr, 0)? == id, "page {id} carries another id");
        let span = (u32_at(hdr, 12)? as usize + 1) * self.meta.page_size;
        self.data
            .get(start..start + span)
            .context("page overflow past end")
    }

    pub fn entries<'a>(&'a self, b: Bucket<'a>) -> anyhow::Result<Vec<(&'a [u8], Value<'a>)>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        match b {
            Bucket::Page(id) => {
                seen.insert(id);
                self.walk(self.page(id)?, &mut out, &mut seen)?
            }
            Bucket::Inline(p) => self.walk(p, &mut out, &mut seen)?,
        }
        Ok(out)
    }

    /// `seen` stops a corrupt branch that points back into its own tree.
    fn walk<'a>(
        &'a self,
        page: &'a [u8],
        out: &mut Vec<(&'a [u8], Value<'a>)>,
        seen: &mut HashSet<u64>,
    ) -> anyhow::Result<()> {
        let flags = u16_at(page, 8)?;
        let count = u16_at(page, 10)? as usize;
        let slice = |at: usize, len: u32| -> anyhow::Result<&'a [u8]> {
            page.get(at..at + len as usize)
                .context("element past page end")
        };
        for i in 0..count {
            let e = PAGE_HEADER + i * ELEMENT;
            match flags {
                BRANCH => {
                    let child = u64_at(page, e + 8)?;
                    ensure!(seen.insert(child), "page {child} reached twice");
                    self.walk(self.page(child)?, out, seen)?;
                }
                LEAF => {
                    let kflags = u32_at(page, e)?;
                    let pos = u32_at(page, e + 4)?;
                    let ksize = u32_at(page, e + 8)?;
                    let vsize = u32_at(page, e + 12)?;
                    let key = slice(e + pos as usize, ksize)?;
                    let val = slice(e + pos as usize + ksize as usize, vsize)?;
                    let v = if kflags & BUCKET_LEAF != 0 {
                        ensure!(val.len() >= BUCKET_HEADER, "short bucket header");
                        match u64_at(val, 0)? {
                            0 => Value::Bucket(Bucket::Inline(&val[BUCKET_HEADER..])),
                            root => Value::Bucket(Bucket::Page(root)),
                        }
                    } else {
                        Value::Data(val)
                    };
                    out.push((key, v));
                }
                f => bail!("page of kind {f:#x} where a branch or leaf belongs"),
            }
        }
        Ok(())
    }

    pub fn bucket<'a>(
        &'a self,
        parent: Bucket<'a>,
        name: &[u8],
    ) -> anyhow::Result<Option<Bucket<'a>>> {
        Ok(self
            .entries(parent)?
            .into_iter()
            .find_map(|(k, v)| match v {
                Value::Bucket(b) if k == name => Some(b),
                _ => None,
            }))
    }

    pub fn get<'a>(&'a self, parent: Bucket<'a>, name: &[u8]) -> anyhow::Result<Option<&'a [u8]>> {
        Ok(self
            .entries(parent)?
            .into_iter()
            .find_map(|(k, v)| match v {
                Value::Data(d) if k == name => Some(d),
                _ => None,
            }))
    }

    pub fn path<'a>(&'a self, names: &[&[u8]]) -> anyhow::Result<Option<Bucket<'a>>> {
        let mut b = self.root();
        for n in names {
            match self.bucket(b, n)? {
                Some(next) => b = next,
                None => return Ok(None),
            }
        }
        Ok(Some(b))
    }
}

fn read_prefix(path: &Path, len: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    std::fs::File::open(path)?
        .take(len as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fixture_root;

    const SNAPSHOTTER_DB: &str = "io.containerd.snapshotter.v1.overlayfs/metadata.db";

    fn keys(db: &Db, b: Bucket) -> Vec<String> {
        db.entries(b)
            .unwrap()
            .into_iter()
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
            .collect()
    }

    #[test]
    fn reads_nested_and_inline_buckets() {
        let root = fixture_root();
        let db = Db::read(&root.path().join(SNAPSHOTTER_DB)).unwrap();
        let snaps = db.path(&[b"v1", b"snapshots"]).unwrap().unwrap();
        let names = keys(&db, snaps);
        assert_eq!(names.len(), 11, "{names:?}");
        assert!(
            names.iter().any(|n| n == "k8s.io/13/container-rw-1"),
            "{names:?}"
        );

        let rw = db
            .bucket(snaps, b"k8s.io/13/container-rw-1")
            .unwrap()
            .unwrap();
        assert!(matches!(rw, Bucket::Inline(_)));
        assert_eq!(db.get(rw, b"id").unwrap(), Some(&[7u8][..]));
        assert_eq!(db.get(rw, b"kind").unwrap(), Some(&[2u8][..]));
        assert_eq!(db.get(rw, b"absent").unwrap(), None);
        assert!(
            db.bucket(rw, b"id").unwrap().is_none(),
            "a value is not a bucket"
        );
    }

    #[test]
    fn reads_branch_and_overflow_pages() {
        let root = fixture_root();
        let db = Db::read(&root.path().join("bolt-large.db")).unwrap();
        let b = db.path(&[b"big"]).unwrap().unwrap();
        let e = db.entries(b).unwrap();
        assert_eq!(e.len(), 1500);
        for (i, (k, v)) in e.iter().enumerate() {
            assert_eq!(*k, format!("key-{i:05}").as_bytes());
            let Value::Data(v) = v else {
                panic!("{i}: a bucket")
            };
            let want = if i % 500 == 0 { 9000 } else { 8 };
            assert_eq!(v.len(), want, "{i}");
        }
    }

    fn set_txid(data: &mut [u8], at: usize, txid: u64) {
        let m = at + PAGE_HEADER;
        data[m + 48..m + 56].copy_from_slice(&txid.to_le_bytes());
        let sum = fnv64a(&data[m..m + 56]);
        data[m + 56..m + 64].copy_from_slice(&sum.to_le_bytes());
    }

    #[test]
    fn higher_txid_meta_is_active() {
        let root = fixture_root();
        let mut data = std::fs::read(root.path().join(SNAPSHOTTER_DB)).unwrap();
        let ps = active_meta(&data).unwrap().page_size;
        for (m0, m1, want) in [(20, 21, 21), (31, 30, 31)] {
            set_txid(&mut data, 0, m0);
            set_txid(&mut data, ps, m1);
            assert_eq!(active_meta(&data).unwrap().txid, want, "{m0} {m1}");
        }
    }

    #[test]
    fn torn_meta_falls_back() {
        let root = fixture_root();
        let mut data = std::fs::read(root.path().join(SNAPSHOTTER_DB)).unwrap();
        let good = active_meta(&data).unwrap();
        let active_page = if meta_at(&data, 0) == Some(good) {
            0
        } else {
            good.page_size
        };
        data[active_page + PAGE_HEADER + 20] ^= 0xff;
        let fallback = active_meta(&data).unwrap();
        assert_eq!(fallback.txid, good.txid - 1);

        data[(good.page_size - active_page) + PAGE_HEADER + 20] ^= 0xff;
        assert!(Db::parse(data).is_err());
    }

    #[test]
    fn garbage_errors_without_panic() {
        let root = fixture_root();
        let good = std::fs::read(root.path().join(SNAPSHOTTER_DB)).unwrap();
        assert!(Db::parse(Vec::new()).is_err());
        assert!(Db::parse(vec![0xAA; 16384]).is_err());
        assert!(
            Db::parse(good[..good.len() / 8].to_vec()).is_err(),
            "shorter than its high-water mark"
        );

        let ps = active_meta(&good).unwrap().page_size;
        for page in 2..good.len() / ps {
            let mut d = good.clone();
            for b in &mut d[page * ps..(page + 1) * ps] {
                *b = b.wrapping_mul(31).wrapping_add(7);
            }
            if let Ok(db) = Db::parse(d) {
                let _ = db
                    .path(&[b"v1", b"snapshots"])
                    .map(|b| b.map(|b| db.entries(b)));
            }
        }
    }
}
