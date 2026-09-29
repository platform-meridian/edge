//! Fixed-size, CRC-checked, sequence-numbered records in a preallocated file. A cut
//! damages at most the slot being written, and "newest" is the highest sequence: no
//! head pointer to tear. The header is `magic, seq, crc`; the magic's last byte is
//! the version (`ESCP` v1, `ESCQ` v2, same layout), and a ring may mix both.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::Context;

pub const RECORD_SIZE: usize = 256;
const MAGIC_V1: u32 = 0x45_53_43_50;
const MAGIC_V2: u32 = 0x45_53_43_51;
pub const HEADER: usize = 4 + 8 + 4;
pub const PAYLOAD: usize = RECORD_SIZE - HEADER;

/// 256 MB: larger is not a ring this recorder made.
const MAX_SLOTS: u64 = 1_000_000;

/// Not damage: never set aside for it.
#[derive(Debug)]
pub struct Held;

impl std::fmt::Display for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("another recorder holds the ring")
    }
}

impl std::error::Error for Held {}

fn lock(f: &File) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid fd; the lock is released when the file closes.
    if unsafe { nix::libc::flock(f.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(nix::libc::EWOULDBLOCK) {
        return Err(Held.into());
    }
    Err(anyhow::Error::new(e).context("flock"))
}

pub struct Ring {
    file: File,
    record: usize,
    slots: u64,
    next_seq: u64,
    next_slot: u64,
    writable: bool,
    valid: u64,
    garbage: u64,
    recovered: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub version: u8,
}

/// Real blocks, so a full disk fails now rather than at the first write into a hole.
/// Without fallocate a fresh file is zero-filled; an existing one keeps its history.
fn preallocate(f: &File, len: u64, fresh: bool) -> anyhow::Result<()> {
    use nix::errno::Errno;
    match nix::fcntl::posix_fallocate(f, 0, len as i64) {
        Ok(()) => Ok(()),
        Err(Errno::EOPNOTSUPP | Errno::EINVAL) if fresh => {
            let zeros = [0u8; 4096];
            let mut at = 0u64;
            while at < len {
                let n = ((len - at) as usize).min(zeros.len());
                f.write_all_at(&zeros[..n], at)?;
                at += n as u64;
            }
            Ok(())
        }
        Err(Errno::EOPNOTSUPP | Errno::EINVAL) => {
            tracing::warn!("this filesystem cannot preallocate; the ring may be sparse");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("preallocate {len} bytes: {e}")),
    }
}

fn crc(record: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(&record[0..12]);
    h.update(&record[HEADER..]);
    h.finalize()
}

impl Ring {
    pub fn open(path: &Path, slots_if_new: u64) -> anyhow::Result<Self> {
        Self::open_with(path, slots_if_new, RECORD_SIZE)
    }

    pub fn open_with(path: &Path, slots_if_new: u64, record: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(slots_if_new > 0, "a ring needs at least one slot");
        anyhow::ensure!(
            record > HEADER,
            "a {record}-byte record has no room for a payload"
        );
        match Self::try_open(path, slots_if_new, record) {
            Ok(r) => Ok(r),
            Err(why) if why.is::<Held>() => Err(why),
            Err(why) => {
                let kept = edge_common::set_aside(path);
                tracing::error!(
                    ring = %path.display(), error = %format!("{why:#}"),
                    kept_as = ?kept,
                    "ring unusable; starting a new one"
                );
                let mut r = Self::try_open(path, slots_if_new, record)
                    .with_context(|| format!("recreating {} after: {why:#}", path.display()))?;
                r.recovered = Some(match kept {
                    Some(k) => format!("previous ring unusable ({why:#}); kept as {}", k.display()),
                    None => format!("previous ring unusable ({why:#}); it could not be kept"),
                });
                Ok(r)
            }
        }
    }

    /// Whether `path` still names the open file; writes to a ring deleted or
    /// replaced underneath succeed silently.
    pub fn is_current(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        match (self.file.metadata(), std::fs::metadata(path)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }

    pub fn take_recovered(&mut self) -> Option<String> {
        self.recovered.take()
    }

    fn try_open(path: &Path, slots_if_new: u64, record: usize) -> anyhow::Result<Self> {
        let existing = match std::fs::metadata(path) {
            Ok(m) => {
                anyhow::ensure!(m.is_file(), "{} is not a regular file", path.display());
                let n = m.len() / record as u64;
                anyhow::ensure!(
                    n <= MAX_SLOTS,
                    "{} is {} bytes: not a ring this recorder made",
                    path.display(),
                    m.len()
                );
                n
            }
            // ENOTDIR: a file squats on a parent; creating the ring sets it aside.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(nix::libc::ENOTDIR) =>
            {
                0
            }
            Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        };
        if existing == 0 {
            // Built beside the path and renamed in: a cut leaves no ring, not a
            // short one trusted as the intended size.
            let len = slots_if_new * record as u64;
            edge_common::durable_write_with(path, |f| {
                preallocate(f, len, true).map_err(std::io::Error::other)
            })
            .with_context(|| format!("create {}", path.display()))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        lock(&file)?;
        let len = file.metadata()?.len();
        let slots = len / record as u64;
        if existing != 0 {
            if slots != slots_if_new {
                tracing::warn!(
                    have = slots,
                    requested = slots_if_new,
                    "the ring already has a size and keeps it; delete the file to resize"
                );
            }
            if len % record as u64 != 0 {
                tracing::warn!(
                    len,
                    "ring length is not a whole number of records; ignoring the tail"
                );
            }
            // Older rings may be sparse.
            if let Err(e) = preallocate(&file, slots * record as u64, false) {
                tracing::warn!(error = %e, "could not fully allocate the existing ring; it may be sparse");
            }
        }
        let ring = Self::scan(file, record, slots, true);
        // No good record at all is not our ring (or a future format we would
        // overwrite); one torn record among good ones is just a power cut.
        if existing != 0 && ring.valid == 0 && ring.garbage > 0 {
            anyhow::bail!(
                "{} slot(s) hold data but none is a readable record",
                ring.garbage
            );
        }
        Ok(ring)
    }

    pub fn open_read_only(path: &Path) -> anyhow::Result<Self> {
        Self::open_read_only_with(path, RECORD_SIZE)
    }

    pub fn open_read_only_with(path: &Path, record: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            record > HEADER,
            "a {record}-byte record has no room for a payload"
        );
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let len = file.metadata()?.len();
        let slots = len / record as u64;
        anyhow::ensure!(
            slots > 0,
            "{} is {len} bytes, shorter than one {record}-byte record: not a ring",
            path.display()
        );
        Ok(Self::scan(file, record, slots, false))
    }

    fn scan(file: File, record: usize, slots: u64, writable: bool) -> Self {
        let mut ring = Self {
            file,
            record,
            slots,
            next_seq: 0,
            next_slot: 0,
            writable,
            valid: 0,
            garbage: 0,
            recovered: None,
        };
        let mut newest: Option<(u64, u64)> = None; // (seq, slot)
        for slot in 0..slots {
            if let Some(e) = ring.read_slot(slot) {
                ring.valid += 1;
                if newest.is_none_or(|(seq, _)| e.seq > seq) {
                    newest = Some((e.seq, slot));
                }
            } else if ring.slot_has_bytes(slot) {
                ring.garbage += 1;
            }
        }
        if let Some((seq, slot)) = newest {
            ring.next_seq = seq + 1;
            ring.next_slot = (slot + 1) % slots;
        }
        ring
    }

    fn slot_has_bytes(&self, slot: u64) -> bool {
        let mut buf = vec![0u8; self.record];
        self.file
            .read_exact_at(&mut buf, slot * self.record as u64)
            .is_ok()
            && buf.iter().any(|b| *b != 0)
    }

    pub fn slots(&self) -> u64 {
        self.slots
    }

    pub fn payload_size(&self) -> usize {
        self.record - HEADER
    }

    fn read_slot(&self, slot: u64) -> Option<Entry> {
        let mut buf = vec![0u8; self.record];
        if let Err(e) = self.file.read_exact_at(&mut buf, slot * self.record as u64) {
            tracing::warn!(slot, error = %e, "could not read a slot; treating it as empty");
            return None;
        }
        let version = match u32::from_le_bytes(buf[0..4].try_into().unwrap()) {
            MAGIC_V1 => 1,
            MAGIC_V2 => 2,
            _ => return None,
        };
        let seq = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        let want = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        if crc(&buf) != want {
            tracing::warn!(slot, seq, "torn record; skipping");
            return None;
        }
        Some(Entry {
            seq,
            payload: buf[HEADER..].to_vec(),
            version,
        })
    }

    pub fn append(&mut self, payload: &[u8]) -> anyhow::Result<u64> {
        self.append_all(&[payload])
    }

    /// One sync at the end: a cut before it can tear only the slots being written.
    pub fn append_all<P: AsRef<[u8]>>(&mut self, payloads: &[P]) -> anyhow::Result<u64> {
        anyhow::ensure!(self.writable, "the ring was opened read-only");
        anyhow::ensure!(!payloads.is_empty(), "nothing to append");
        let limit = self.payload_size();
        if let Some(p) = payloads.iter().find(|p| p.as_ref().len() > limit) {
            anyhow::bail!("payload {} exceeds {limit}", p.as_ref().len());
        }
        for payload in payloads {
            let payload = payload.as_ref();
            let mut buf = vec![0u8; self.record];
            buf[0..4].copy_from_slice(&MAGIC_V2.to_le_bytes());
            buf[4..12].copy_from_slice(&self.next_seq.to_le_bytes());
            buf[HEADER..HEADER + payload.len()].copy_from_slice(payload);
            let sum = crc(&buf);
            buf[12..16].copy_from_slice(&sum.to_le_bytes());
            self.file
                .write_all_at(&buf, self.next_slot * self.record as u64)?;
            self.next_seq += 1;
            self.next_slot = (self.next_slot + 1) % self.slots;
        }
        self.file.sync_data()?;
        Ok(self.next_seq - 1)
    }

    pub fn read_all(&mut self) -> anyhow::Result<Vec<Entry>> {
        let mut out: Vec<Entry> = (0..self.slots).filter_map(|s| self.read_slot(s)).collect();
        out.sort_by_key(|e| e.seq);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("edge-scope-{}-{}", std::process::id(), name));
        std::fs::remove_file(&p).ok();
        p
    }

    fn dir_for(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("edge-scope-{}-{}", std::process::id(), name));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn edge_tmp(p: &Path) -> std::path::PathBuf {
        let mut n = p.file_name().unwrap().to_os_string();
        n.push(edge_common::TMP_SUFFIX);
        p.with_file_name(n)
    }

    fn allocated(p: &Path) -> u64 {
        std::fs::metadata(p).unwrap().blocks() * 512
    }

    fn seqs(r: &mut Ring) -> Vec<u64> {
        r.read_all().unwrap().iter().map(|e| e.seq).collect()
    }

    /// Built from the documented layout, not through `append`: what rings
    /// already in the field contain.
    fn v1_record(seq: u64, payload: &[u8]) -> [u8; RECORD_SIZE] {
        let mut buf = [0u8; RECORD_SIZE];
        buf[0..4].copy_from_slice(b"PCSE");
        buf[4..12].copy_from_slice(&seq.to_le_bytes());
        buf[16..16 + payload.len()].copy_from_slice(payload);
        let mut h = crc32fast::Hasher::new();
        h.update(&buf[0..12]);
        h.update(&buf[16..]);
        buf[12..16].copy_from_slice(&h.finalize().to_le_bytes());
        buf
    }

    fn corrupt_slot(p: &Path, slot: u64) {
        let f = OpenOptions::new().write(true).open(p).unwrap();
        f.write_all_at(b"XXXXXXXX", slot * RECORD_SIZE as u64 + 40)
            .unwrap();
    }

    #[test]
    fn reopen_continues_sequence() {
        let p = tmp("order");
        drop(Ring::open(&p, 8).unwrap());
        {
            let mut r = Ring::open(&p, 8).unwrap();
            assert!(
                r.take_recovered().is_none(),
                "an unwritten ring is not garbage"
            );
            assert!(r.read_all().unwrap().is_empty());
            for i in 0..3u8 {
                assert_eq!(r.append(&[i]).unwrap(), i as u64);
            }
        }
        let mut r = Ring::open(&p, 8).unwrap();
        assert_eq!(r.append(&[3]).unwrap(), 3);
        let all = r.read_all().unwrap();
        assert_eq!(
            all.iter()
                .map(|e| (e.seq, e.payload[0], e.version))
                .collect::<Vec<_>>(),
            [(0, 0, 2), (1, 1, 2), (2, 2, 2), (3, 3, 2)]
        );
        assert_eq!(all[0].payload.len(), PAYLOAD);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn full_ring_wraps() {
        let p = tmp("wrap");
        {
            let mut r = Ring::open(&p, 4).unwrap();
            for i in 0..10u8 {
                r.append(&[i]).unwrap();
            }
            let all = r.read_all().unwrap();
            assert_eq!(
                all.iter()
                    .map(|e| (e.seq, e.payload[0]))
                    .collect::<Vec<_>>(),
                [(6, 6), (7, 7), (8, 8), (9, 9)]
            );
        }
        // Reopened mid-ring: the next write replaces the oldest (seq 6).
        let mut r = Ring::open(&p, 4).unwrap();
        r.append(b"x").unwrap();
        assert_eq!(seqs(&mut r), [7, 8, 9, 10]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn torn_record_dropped() {
        let d = dir_for("torn");
        let p = d.join("ring.bin");
        {
            let mut r = Ring::open(&p, 4).unwrap();
            for s in [b"good0", b"good1", b"good2"] {
                r.append(s).unwrap();
            }
        }
        corrupt_slot(&p, 1);
        let mut r = Ring::open(&p, 4).unwrap();
        assert!(r.take_recovered().is_none());
        assert!(!d.join("ring.bin.corrupt").exists());
        assert_eq!(seqs(&mut r), [0, 2]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn batch_appends_in_order() {
        let p = tmp("batch");
        let mut r = Ring::open_with(&p, 4, 64).unwrap();
        assert_eq!(r.payload_size(), 64 - HEADER);
        assert_eq!(r.append_all(&[b"a", b"b", b"c"]).unwrap(), 2);
        assert_eq!(r.append_all(&[b"d", b"e"]).unwrap(), 4);
        let got: Vec<_> = r
            .read_all()
            .unwrap()
            .iter()
            .map(|e| (e.seq, e.payload[0]))
            .collect();
        assert_eq!(got, [(1, b'b'), (2, b'c'), (3, b'd'), (4, b'e')]);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 4 * 64);

        let over = vec![b'x'; 64 - HEADER + 1];
        assert!(r.append_all(&[b"f".as_slice(), &over]).is_err());
        assert!(r.append_all::<&[u8]>(&[]).is_err());
        assert_eq!(seqs(&mut r), [1, 2, 3, 4], "a refused batch writes nothing");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn wrong_record_size_replaced() {
        let d = dir_for("resized");
        let p = d.join("ring.bin");
        Ring::open_with(&p, 8, 512).unwrap().append(b"big").unwrap();
        let mut r = Ring::open_read_only_with(&p, 512).unwrap();
        assert_eq!(seqs(&mut r), [0]);
        let mut small = Ring::open(&p, 4).unwrap();
        assert!(small.take_recovered().is_some());
        assert_eq!(small.slots(), 4);
        assert!(d.join("ring.bin.corrupt").exists());
        assert!(Ring::open_with(&p, 4, HEADER).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn payload_limit() {
        let p = tmp("big");
        let mut r = Ring::open(&p, 2).unwrap();
        r.append(&[7u8; PAYLOAD]).unwrap();
        assert!(r.append(&[0u8; PAYLOAD + 1]).is_err());
        assert_eq!(r.read_all().unwrap()[0].payload, vec![7u8; PAYLOAD]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn new_ring_fully_allocated() {
        let p = tmp("alloc");
        let r = Ring::open(&p, 64).unwrap();
        assert_eq!(r.slots(), 64);
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            64 * RECORD_SIZE as u64
        );
        assert!(allocated(&p) >= 64 * RECORD_SIZE as u64);
        assert!(!edge_tmp(&p).exists());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sparse_ring_allocated_keeping_history() {
        let p = tmp("sparse");
        {
            let f = File::create(&p).unwrap();
            f.set_len(32 * RECORD_SIZE as u64).unwrap();
            f.write_all_at(&v1_record(7, b"old history"), 5 * RECORD_SIZE as u64)
                .unwrap();
        }
        assert!(allocated(&p) < 32 * RECORD_SIZE as u64, "premise: sparse");
        let mut r = Ring::open(&p, 32).unwrap();
        assert!(allocated(&p) >= 32 * RECORD_SIZE as u64);
        let all = r.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(&all[0].payload[..11], b"old history");
        assert_eq!(r.append(b"new").unwrap(), 8);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn existing_ring_never_resized() {
        let p = tmp("noresize");
        {
            let mut r = Ring::open(&p, 8).unwrap();
            for i in 0..8u8 {
                r.append(&[i]).unwrap();
            }
        }
        for asked in [2u64, 900] {
            let mut r = Ring::open(&p, asked).unwrap();
            assert_eq!(r.slots(), 8, "asked for {asked}");
            assert_eq!(std::fs::metadata(&p).unwrap().len(), 8 * RECORD_SIZE as u64);
            assert_eq!(r.read_all().unwrap().len(), 8, "asked for {asked}");
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn read_only_changes_nothing() {
        let p = tmp("ro");
        {
            let mut r = Ring::open(&p, 6).unwrap();
            r.append(b"a").unwrap();
            r.append(b"b").unwrap();
        }
        let before = std::fs::read(&p).unwrap();
        let mut r = Ring::open_read_only(&p).unwrap();
        assert_eq!(r.slots(), 6);
        assert_eq!(seqs(&mut r), [0, 1]);
        assert!(r.append(b"c").is_err());
        assert_eq!(std::fs::read(&p).unwrap(), before);
        std::fs::remove_file(&p).ok();

        assert!(Ring::open_read_only(&p).is_err());
        assert!(!p.exists(), "created by a read");
    }

    #[test]
    fn stub_or_temp_is_not_ring() {
        let p = tmp("stub");
        std::fs::write(&p, b"tiny").unwrap();
        assert!(Ring::open_read_only(&p).is_err());
        assert_eq!(Ring::open(&p, 4).unwrap().slots(), 4);
        std::fs::remove_file(&p).ok();

        std::fs::write(edge_tmp(&p), vec![0u8; 3 * RECORD_SIZE]).unwrap();
        assert!(Ring::open_read_only(&p).is_err());
        assert_eq!(Ring::open(&p, 8).unwrap().slots(), 8);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn v1_ring_still_works() {
        let p = tmp("v1");
        let v1: Vec<u8> = (0..4u64)
            .flat_map(|i| v1_record(10 + i, format!("old{i}").as_bytes()))
            .collect();
        std::fs::write(&p, &v1).unwrap();
        let mut r = Ring::open(&p, 900).unwrap();
        assert_eq!(r.slots(), 4);
        assert_eq!(r.append(b"new").unwrap(), 14);
        let all = r.read_all().unwrap();
        assert_eq!(
            all.iter().map(|e| (e.seq, e.version)).collect::<Vec<_>>(),
            [(11, 1), (12, 1), (13, 1), (14, 2)]
        );
        assert_eq!(&all[0].payload[..4], b"old1");
        assert_eq!(&all[3].payload[..3], b"new");
        assert_eq!(std::fs::read(&p).unwrap()[RECORD_SIZE..], v1[RECORD_SIZE..]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn unreadable_slot_is_empty() {
        // A directory fails every pread, like a bad block on every slot.
        let dir = File::open(std::env::temp_dir()).unwrap();
        let mut ring = Ring::scan(dir, RECORD_SIZE, 4, false);
        assert_eq!((ring.next_seq, ring.valid, ring.garbage), (0, 0, 0));
        assert!(ring.read_all().unwrap().is_empty());
    }

    #[test]
    fn unusable_ring_replaced() {
        let d = dir_for("recover");
        let p = d.join("ring.bin");
        let corrupt = d.join("ring.bin.corrupt");

        std::fs::create_dir_all(p.join("inner")).unwrap();
        let mut r = Ring::open(&p, 4).unwrap();
        assert!(r.take_recovered().unwrap().contains("not a regular file"));
        assert!(r.take_recovered().is_none(), "taken once");
        assert!(corrupt.join("inner").is_dir());
        r.append(b"works").unwrap();
        drop(r);

        let mut torn_only = vec![0u8; 4 * RECORD_SIZE];
        torn_only[3 * RECORD_SIZE + 100] = 1;
        let mut future = vec![0u8; 4 * RECORD_SIZE];
        for i in 0..4 {
            future[i * RECORD_SIZE..i * RECORD_SIZE + 4].copy_from_slice(b"ESCZ");
        }
        for (what, bytes) in [
            ("garbage", vec![0xABu8; 8 * RECORD_SIZE]),
            ("future format", future),
            ("nothing but a torn slot", torn_only),
        ] {
            std::fs::remove_file(&p).unwrap();
            std::fs::write(&p, &bytes).unwrap();
            let mut r = Ring::open(&p, 4).unwrap();
            assert_eq!(r.slots(), 4, "{what}");
            assert!(r.take_recovered().is_some(), "{what}");
            assert_eq!(std::fs::read(&corrupt).unwrap(), bytes, "{what}");
            assert!(r.read_all().unwrap().is_empty(), "{what}");
        }

        std::fs::remove_file(&p).unwrap();
        File::create(&p)
            .unwrap()
            .set_len((MAX_SLOTS + 1) * RECORD_SIZE as u64)
            .unwrap();
        assert_eq!(Ring::open(&p, 4).unwrap().slots(), 4, "absurdly large");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn unwritable_ring_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir_for("readonly");
        let p = d.join("ring.bin");
        drop(Ring::open(&p, 4).unwrap());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        if unsafe { nix::libc::geteuid() } == 0 {
            return;
        }
        let mut r = Ring::open(&p, 4).unwrap();
        assert!(r.take_recovered().is_some());
        r.append(b"x").unwrap();
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn replaced_ring_noticed() {
        let d = dir_for("replaced");
        let p = d.join("ring.bin");
        let r = Ring::open(&p, 4).unwrap();
        assert!(r.is_current(&p));
        std::fs::remove_file(&p).unwrap();
        assert!(!r.is_current(&p), "deleted");
        drop(Ring::open(&p, 4).unwrap());
        assert!(!r.is_current(&p), "replaced");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn second_recorder_refused() {
        let d = dir_for("held");
        let p = d.join("ring.bin");
        let mut first = Ring::open(&p, 4).unwrap();
        first.append(b"one").unwrap();
        let err = Ring::open(&p, 4).err().expect("a second writer");
        assert!(err.is::<Held>(), "{err:#}");
        assert!(!d.join("ring.bin.corrupt").exists());
        let mut reader = Ring::open_read_only(&p).unwrap();
        assert_eq!(seqs(&mut reader), [0], "readers are not locked out");
        drop(first);
        let mut again = Ring::open(&p, 4).unwrap();
        assert_eq!(again.append(b"two").unwrap(), 1);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn missing_dir_created_squatter_set_aside() {
        let d = dir_for("nodir");
        assert_eq!(Ring::open(&d.join("a/b/ring.bin"), 2).unwrap().slots(), 2);
        std::fs::write(d.join("file"), b"squatter").unwrap();
        assert_eq!(Ring::open(&d.join("file/ring.bin"), 2).unwrap().slots(), 2);
        assert_eq!(std::fs::read(d.join("file.corrupt")).unwrap(), b"squatter");
        assert!(Ring::open(&d.join("zero.bin"), 0).is_err());
        std::fs::remove_dir_all(&d).ok();
    }
}
