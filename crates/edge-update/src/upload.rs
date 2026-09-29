//! One upload at a time, in fixed chunks written in place. A chunk counts once
//! it is on disk and recorded; a cut before the record only costs a resend.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHUNK: u32 = 2 << 20;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Upload {
    pub sha256: String,
    pub size: u64,
    pub chunk_size: u32,
    pub received: Vec<u8>,
    pub complete: bool,
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
}

pub struct Uploads {
    dir: PathBuf,
}

impl Uploads {
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.into() }
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

    pub fn begin(&self, size: u64, sha256: &str) -> anyhow::Result<Upload> {
        ensure!(size > 0, "an empty bundle");
        ensure!(
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "the bundle's sha256 is not 32 bytes"
        );
        if let Some(u) = self.current()
            && u.sha256 == sha256
            && u.size == size
        {
            return Ok(u);
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
        }
        self.save(&u)?;
        Ok(u)
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
            .begin(data.len() as u64, &hex::encode(sha(&data)))
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
            up.begin(data.len() as u64, &h).unwrap();
            put_all(&up, &data, [1].into_iter());
        }
        let up = Uploads::new(d.path());
        let u = up.begin(data.len() as u64, &h).unwrap();
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
        up.begin(10, &h).unwrap();
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
        up.begin(10, &claimed).unwrap();
        let e = up.put(&claimed, 0, &data, &sha(&data)).unwrap_err();
        assert!(e.to_string().contains("upload it again"), "{e}");
        assert!(up.current().is_none());
    }

    #[test]
    fn another_bundle_replaces_the_upload() {
        let d = tempfile::tempdir().unwrap();
        let up = Uploads::new(d.path());
        let a = body(10);
        up.begin(10, &hex::encode(sha(&a))).unwrap();
        let b = body(20);
        let u = up.begin(20, &hex::encode(sha(&b))).unwrap();
        assert_eq!(u.size, 20);
        assert!(up.put(&hex::encode(sha(&a)), 0, &a, &sha(&a)).is_err());
    }
}
