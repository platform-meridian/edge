//! One upload at a time, in fixed chunks written in place. A chunk counts once
//! it is on disk and recorded; a cut before the record only costs a resend.
//! The bundle's signed head is read as soon as its start has arrived, so a
//! bundle this unit will refuse is refused before the rest is sent.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::{self, Manifest, Verifier};
use crate::engine::Clock;

pub const CHUNK: u32 = 2 << 20;
/// An upload untouched this long may be replaced by anyone's.
pub const LEASE: i64 = 120;
/// The head is looked for in this much of the start, then in the whole.
const HEAD_WITHIN: u64 = 64 << 20;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Upload {
    pub sha256: String,
    pub size: u64,
    pub chunk_size: u32,
    pub received: Vec<u8>,
    pub complete: bool,
    #[serde(default)]
    pub started: i64,
    #[serde(default)]
    pub finished: i64,
    #[serde(default)]
    pub by: String,
    /// The last chunk taken.
    #[serde(default)]
    pub active: i64,
    #[serde(default)]
    pub head: Option<Head>,
    /// Why the start that arrived is refused.
    #[serde(default)]
    pub refused: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Head {
    pub manifest: Manifest,
    pub notes: Option<String>,
    pub signer: String,
}

impl Upload {
    pub fn chunks(&self) -> u32 {
        self.size.div_ceil(self.chunk_size as u64) as u32
    }
    fn has(&self, i: u32) -> bool {
        self.received[(i / 8) as usize] & (1 << (i % 8)) != 0
    }
    fn mark(&mut self, i: u32) {
        self.received[(i / 8) as usize] |= 1 << (i % 8);
    }
    fn all(&self) -> bool {
        (0..self.chunks()).all(|i| self.has(i))
    }
    /// Bytes held from the start without a gap.
    fn start(&self) -> u64 {
        let n = (0..self.chunks()).take_while(|&i| self.has(i)).count() as u64;
        (n * self.chunk_size as u64).min(self.size)
    }
    /// Someone else's, and still being sent.
    pub fn live_for_other(&self, by: &str, now: i64) -> bool {
        !self.complete && !self.by.is_empty() && self.by != by && now - self.active < LEASE
    }
}

pub struct Uploads {
    dir: PathBuf,
    verifier: Option<Verifier>,
    now: Clock,
}

impl Uploads {
    /// Without a verifier the head is not read.
    #[cfg(test)]
    pub fn new(dir: &Path) -> Self {
        Self::with(dir, None, std::sync::Arc::new(crate::engine::unix_now))
    }

    pub fn with(dir: &Path, verifier: Option<Verifier>, now: Clock) -> Self {
        Self {
            dir: dir.into(),
            verifier,
            now,
        }
    }

    fn meta(&self) -> PathBuf {
        self.dir.join("upload.json")
    }

    pub fn bundle(&self) -> PathBuf {
        self.dir.join("bundle.tar")
    }

    pub fn current(&self) -> Option<Upload> {
        let u: Upload = serde_json::from_slice(&std::fs::read(self.meta()).ok()?).ok()?;
        // A record that disagrees with its file is started over.
        let len = std::fs::metadata(self.bundle()).ok()?.len();
        (len == u.size && u.received.len() == u.chunks().div_ceil(8) as usize).then_some(u)
    }

    fn save(&self, u: &Upload) -> anyhow::Result<()> {
        edge_common::durable_write(&self.meta(), &serde_json::to_vec(u)?)
            .context("record the upload")
    }

    pub fn discard(&self) {
        let _ = std::fs::remove_file(self.meta());
        let _ = std::fs::remove_file(self.bundle());
    }

    pub fn begin(&self, size: u64, sha256: &str, by: &str) -> anyhow::Result<Upload> {
        ensure!(size > 0, "an empty bundle");
        ensure!(
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "the bundle's sha256 is not 32 bytes"
        );
        let now = (self.now)();
        if let Some(u) = self.current() {
            if u.sha256 == sha256 && u.size == size {
                return Ok(u);
            }
            ensure!(
                !u.live_for_other(by, now),
                "{} is uploading another bundle",
                u.by
            );
        }
        self.discard();
        std::fs::create_dir_all(&self.dir)?;
        let free = nix::sys::statvfs::statvfs(&self.dir)
            .map(|s| s.blocks_available() * s.fragment_size())
            .unwrap_or(u64::MAX);
        ensure!(
            size <= free,
            "the bundle is {size} bytes and the update volume has {free} free"
        );
        let f = File::create(self.bundle())?;
        f.set_len(size)?;
        f.sync_all()?;
        let mut u = Upload {
            sha256: sha256.into(),
            size,
            chunk_size: CHUNK,
            received: Vec::new(),
            complete: false,
            started: now,
            finished: 0,
            by: by.into(),
            active: now,
            head: None,
            refused: String::new(),
        };
        u.received = vec![0; u.chunks().div_ceil(8) as usize];
        self.save(&u)?;
        Ok(u)
    }

    pub fn put(
        &self,
        sha256: &str,
        index: u32,
        data: &[u8],
        data_sha256: &[u8],
    ) -> anyhow::Result<Upload> {
        let mut u = self
            .current()
            .filter(|u| u.sha256 == sha256)
            .context("no upload of that bundle is in progress: begin it first")?;
        ensure!(u.refused.is_empty(), "the bundle is refused: {}", u.refused);
        ensure!(index < u.chunks(), "chunk {index} is past the end");
        let offset = index as u64 * u.chunk_size as u64;
        let want = (u.size - offset).min(u.chunk_size as u64);
        ensure!(
            data.len() as u64 == want,
            "chunk {index} is {} bytes, not {want}",
            data.len()
        );
        ensure!(
            Sha256::digest(data).as_slice() == data_sha256,
            "chunk {index} does not match its sha256"
        );
        if u.complete || u.has(index) {
            return Ok(u);
        }
        let f = OpenOptions::new().write(true).open(self.bundle())?;
        f.write_all_at(data, offset)?;
        f.sync_data()?;
        u.mark(index);
        u.active = (self.now)();
        self.read_head(&mut u);
        if !u.refused.is_empty() {
            self.save(&u)?;
            bail!("the bundle is refused: {}", u.refused);
        }
        if u.all() {
            let got = hash_file(&self.bundle())?;
            if got != u.sha256 {
                self.discard();
                bail!(
                    "the uploaded bundle hashes to {got}, not {}: upload it again",
                    u.sha256
                );
            }
            u.complete = true;
            u.finished = (self.now)();
        }
        self.save(&u)?;
        Ok(u)
    }

    /// Looks for the signed head in the start held, once.
    fn read_head(&self, u: &mut Upload) {
        let Some(v) = &self.verifier else {
            return;
        };
        let (start, whole) = (u.start(), u.start() == u.size);
        if u.head.is_some()
            || !u.refused.is_empty()
            || start == 0
            || (start > HEAD_WITHIN && !whole)
        {
            return;
        }
        let read = File::open(self.bundle())
            .map_err(anyhow::Error::from)
            .and_then(|f| bundle::read_head(f.take(start), v));
        match read {
            Ok(Some(h)) => match crate::engine::manifest_check(&h.manifest) {
                Ok(()) => {
                    u.head = Some(Head {
                        manifest: h.manifest,
                        notes: h.notes,
                        signer: h.signer,
                    })
                }
                Err(e) => u.refused = format!("{e:#}"),
            },
            Ok(None) if whole => u.refused = "the bundle ends before its MANIFEST".into(),
            Ok(None) => {}
            Err(e) => u.refused = format!("{e:#}"),
        }
    }
}

pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sha(b: &[u8]) -> Vec<u8> {
        Sha256::digest(b).to_vec()
    }

    fn body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn put_all(up: &Uploads, data: &[u8], order: impl Iterator<Item = u32>) -> Upload {
        let h = hex::encode(sha(data));
        let mut last = None;
        for i in order {
            let s = i as usize * CHUNK as usize;
            let c = &data[s..(s + CHUNK as usize).min(data.len())];
            last = Some(up.put(&h, i, c, &sha(c)).unwrap());
        }
        last.unwrap()
    }

    #[test]
    fn chunks_in_any_order_complete_it() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let data = body(CHUNK as usize * 2 + 5);
        let u = up
            .begin(data.len() as u64, &hex::encode(sha(&data)), "")
            .unwrap();
        assert_eq!(u.chunks(), 3);
        let u = put_all(&up, &data, [2, 0, 1].into_iter());
        assert!(u.complete);
        assert_eq!(std::fs::read(up.bundle()).unwrap(), data);
    }

    #[test]
    fn a_restart_resumes_where_it_stopped() {
        let d = tempfile::tempdir().unwrap();
        let data = body(CHUNK as usize * 3);
        let h = hex::encode(sha(&data));
        {
            let up = Uploads::new(d.path());
            up.begin(data.len() as u64, &h, "").unwrap();
            put_all(&up, &data, [1].into_iter());
        }
        let up = Uploads::new(d.path());
        let u = up.begin(data.len() as u64, &h, "").unwrap();
        assert_eq!(u.received, vec![0b010]);
        let u = put_all(&up, &data, [0, 2, 1].into_iter());
        assert!(u.complete);
    }

    #[test]
    fn a_bad_chunk_is_refused_and_not_counted() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let data = body(10);
        let h = hex::encode(sha(&data));
        up.begin(10, &h, "").unwrap();
        assert!(up.put(&h, 0, &data, &sha(b"other")).is_err());
        assert!(up.put(&h, 0, &data[..9], &sha(&data[..9])).is_err());
        assert!(up.put(&h, 1, &data, &sha(&data)).is_err());
        assert_eq!(up.current().unwrap().received, vec![0]);
    }

    #[test]
    fn a_whole_that_does_not_match_is_discarded() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let data = body(10);
        let claimed = hex::encode(sha(b"something else"));
        up.begin(10, &claimed, "").unwrap();
        let e = up.put(&claimed, 0, &data, &sha(&data)).unwrap_err();
        assert!(e.to_string().contains("upload it again"), "{e}");
        assert!(up.current().is_none());
    }

    #[test]
    fn another_bundle_replaces_the_upload() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let a = body(10);
        up.begin(10, &hex::encode(sha(&a)), "").unwrap();
        let b = body(20);
        let u = up.begin(20, &hex::encode(sha(&b)), "").unwrap();
        assert_eq!(u.size, 20);
        assert!(up.put(&hex::encode(sha(&a)), 0, &a, &sha(&a)).is_err());
    }

    #[test]
    fn a_record_that_disagrees_with_its_file_starts_over() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let data = body(CHUNK as usize + 1);
        up.begin(data.len() as u64, &hex::encode(sha(&data)), "")
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(up.bundle())
            .unwrap()
            .set_len(3)
            .unwrap();
        assert!(up.current().is_none());
    }

    #[test]
    fn a_bundle_must_fit_the_volume() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        up.begin(256 << 20, &"a".repeat(64), "").unwrap();
        let e = up.begin(1 << 62, &"b".repeat(64), "").unwrap_err();
        assert!(e.to_string().contains("free"), "{e}");
    }

    const MF: &str = "FORMAT=2\nSTACK_TAG=s2\nSTACK_DIGEST=sha256:11\nINSTALLER_REF=r/i:1@sha256:22\n\
                      TALOS_VERSION=v1.14.1\nBUILT_EPOCH=2000\nSECUREBOOT=1\n";

    /// A bundle three chunks long, its head in the first.
    fn signed(dir: &Path, key: &Path, manifest: &str) -> Vec<u8> {
        use crate::bundle::testkit;
        let src = dir.join("src");
        let _ = std::fs::remove_dir_all(&src);
        testkit::tree(&src, manifest);
        std::fs::write(
            src.join("images/blobs/sha256/big"),
            body(CHUNK as usize * 2 + 9),
        )
        .unwrap();
        testkit::seal(&src, key, testkit::NAMESPACE);
        let tar = dir.join("b.tar");
        testkit::pack(&src, &tar, testkit::HEAD);
        std::fs::read(tar).unwrap()
    }

    fn put_one(up: &Uploads, data: &[u8], i: u32) -> anyhow::Result<Upload> {
        let s = i as usize * CHUNK as usize;
        let c = &data[s..(s + CHUNK as usize).min(data.len())];
        up.put(&hex::encode(sha(data)), i, c, &sha(c))
    }

    fn checking(d: &Path, public: &str) -> Uploads {
        let v = Verifier::new(public, crate::bundle::testkit::NAMESPACE).unwrap();
        Uploads::with(&d.join("up"), Some(v), Arc::new(|| 50))
    }

    #[test]
    fn the_head_is_read_as_soon_as_the_start_arrives() {
        let d = tempfile::tempdir().unwrap();
        let (key, public) = crate::bundle::testkit::keygen(d.path(), "k");
        let up = checking(d.path(), &public);
        let data = signed(d.path(), &key, MF);
        let u = up
            .begin(data.len() as u64, &hex::encode(sha(&data)), "ann")
            .unwrap();
        assert_eq!((u.chunks(), u.started, u.by.as_str()), (3, 50, "ann"));
        assert!(
            put_one(&up, &data, 2).unwrap().head.is_none(),
            "read past a gap"
        );
        let u = put_one(&up, &data, 0).unwrap();
        let h = u.head.unwrap();
        assert_eq!(h.manifest["STACK_TAG"], "s2");
        assert!(h.signer.starts_with("SHA256:"));
        let u = put_one(&up, &data, 1).unwrap();
        assert!(u.complete && u.finished == 50 && u.refused.is_empty());
    }

    #[test]
    fn a_bundle_this_unit_refuses_is_refused_from_its_start() {
        let d = tempfile::tempdir().unwrap();
        let (key, public) = crate::bundle::testkit::keygen(d.path(), "k");
        let (stranger, _) = crate::bundle::testkit::keygen(d.path(), "stranger");
        let up = checking(d.path(), &public);
        for (key, manifest, why) in [
            (&stranger, MF, "pinned update key"),
            (&key, &MF.replace("FORMAT=2", "FORMAT=1")[..], "format 1"),
        ] {
            let data = signed(d.path(), key, manifest);
            up.begin(data.len() as u64, &hex::encode(sha(&data)), "")
                .unwrap();
            let e = format!("{:#}", put_one(&up, &data, 0).unwrap_err());
            assert!(e.contains(why), "{e}");
            assert!(up.current().unwrap().refused.contains(why));
            assert!(format!("{:#}", put_one(&up, &data, 1).unwrap_err()).contains("refused"));
        }
    }

    #[test]
    fn anothers_live_upload_is_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        let clock = Arc::new(std::sync::atomic::AtomicI64::new(1000));
        let c = clock.clone();
        let up = Uploads::with(
            d.path(),
            None,
            Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst)),
        );
        let (a, b) = (body(CHUNK as usize + 1), body(10));
        let (ha, hb) = (hex::encode(sha(&a)), hex::encode(sha(&b)));
        up.begin(a.len() as u64, &ha, "ann").unwrap();
        put_one(&up, &a, 0).unwrap();
        let e = up.begin(10, &hb, "bob").unwrap_err();
        assert!(e.to_string().contains("ann is uploading"), "{e}");
        // Hers to resume, whoever asks.
        assert_eq!(up.begin(a.len() as u64, &ha, "bob").unwrap().by, "ann");
        clock.fetch_add(LEASE, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(up.begin(10, &hb, "bob").unwrap().by, "bob");
        assert_eq!(
            up.begin(a.len() as u64, &ha, "ann")
                .unwrap_err()
                .to_string(),
            "bob is uploading another bundle"
        );
        // His own he may replace at once.
        assert_eq!(up.begin(a.len() as u64, &ha, "bob").unwrap().by, "bob");
    }

    #[test]
    fn a_chunk_already_held_is_not_written_again() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let data = body(CHUNK as usize + 5);
        let h = hex::encode(sha(&data));
        up.begin(data.len() as u64, &h, "").unwrap();
        put_all(&up, &data, [0].into_iter());
        let other = vec![9u8; CHUNK as usize];
        up.put(&h, 0, &other, &sha(&other)).unwrap();
        assert!(put_all(&up, &data, [1].into_iter()).complete);
    }
}
