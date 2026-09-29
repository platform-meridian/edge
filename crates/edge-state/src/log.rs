//! A record is acknowledged once an fsync covers it. At most [`BATCH_BYTES`] are ever
//! written past the last completed fsync, so a power cut can only lose, tear or reorder
//! the file's final `BATCH_BYTES`. A bad frame there, or with nothing intact after it, is
//! an unsynced tail; anything else is damage to synced data, kept as evidence.
//! No file header: an older build would read one as a torn first frame.

use crate::record;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

pub trait Storage: Send + Sync {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;
    fn sync(&self) -> io::Result<()>;
    fn set_len(&self, len: u64) -> io::Result<()>;
}

impl Storage for File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        FileExt::read_at(self, buf, offset)
    }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        FileExt::write_all_at(self, buf, offset)
    }
    fn sync(&self) -> io::Result<()> {
        self.sync_all()
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        File::set_len(self, len)
    }
}

struct NullStorage;
impl Storage for NullStorage {
    fn read_at(&self, _: &mut [u8], _: u64) -> io::Result<usize> {
        Ok(0)
    }
    fn write_all_at(&self, _: &[u8], _: u64) -> io::Result<()> {
        Ok(())
    }
    fn sync(&self) -> io::Result<()> {
        Ok(())
    }
    fn set_len(&self, _: u64) -> io::Result<()> {
        Ok(())
    }
}

fn lock_unpoisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

type OnDurable = Arc<dyn Fn(u64) + Send + Sync>;

pub struct GroupCommit {
    state: Mutex<GroupState>,
    synced_cv: Condvar,
    durable_revision: AtomicU64,
    on_durable: Mutex<Option<OnDurable>>,
}

struct GroupState {
    storage: Arc<dyn Storage>,
    published: u64,
    published_revision: u64,
    synced: u64,
    published_end: u64,
    synced_end: u64,
    /// Bumped by rotation, so an fsync of the old file does not count its offsets
    /// against the new one.
    file_generation: u64,
    syncing: bool,
    failed: Option<String>,
}

pub struct Ticket {
    group: Arc<GroupCommit>,
    seq: u64,
}

impl Ticket {
    pub fn wait(&self) -> Result<(), LogError> {
        self.group.wait(self.seq)
    }
}

impl GroupCommit {
    fn new(storage: Arc<dyn Storage>, len: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GroupState {
                storage,
                published: 0,
                published_revision: 0,
                synced: 0,
                published_end: len,
                synced_end: len,
                file_generation: 0,
                syncing: false,
                failed: None,
            }),
            synced_cv: Condvar::new(),
            durable_revision: AtomicU64::new(0),
            on_durable: Mutex::new(None),
        })
    }

    fn publish(&self, revision: Option<u64>, end: u64) -> u64 {
        let mut st = lock_unpoisoned(&self.state);
        st.published += 1;
        st.published_end = end;
        if let Some(r) = revision {
            st.published_revision = st.published_revision.max(r);
        }
        st.published
    }

    fn wait(&self, seq: u64) -> Result<(), LogError> {
        self.sync_until(|st| st.synced >= seq)
    }

    fn make_room(&self, frame_len: u64) -> Result<(), LogError> {
        self.sync_until(|st| {
            let unsynced = st.published_end - st.synced_end;
            unsynced == 0 || unsynced + frame_len <= BATCH_BYTES
        })
    }

    fn sync_until(&self, done: impl Fn(&GroupState) -> bool) -> Result<(), LogError> {
        let mut st = lock_unpoisoned(&self.state);
        loop {
            if done(&st) {
                return Ok(());
            }
            if let Some(why) = &st.failed {
                return Err(LogError::Failed(why.clone()));
            }
            if st.syncing {
                st = self.synced_cv.wait(st).unwrap_or_else(|p| p.into_inner());
                continue;
            }
            st.syncing = true;
            let (target, target_end, generation, revision, storage) = (
                st.published,
                st.published_end,
                st.file_generation,
                st.published_revision,
                st.storage.clone(),
            );
            drop(st);
            // A panic here must not leave `syncing` set, or every writer waits forever.
            let synced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                storage.sync()?;
                // Watchers hear of it before the writers are answered, as with etcd.
                self.mark_durable(revision);
                Ok(())
            }))
            .unwrap_or_else(|_| Err(io::Error::other("the fsync panicked")));
            st = lock_unpoisoned(&self.state);
            st.syncing = false;
            match synced {
                Ok(()) => {
                    st.synced = st.synced.max(target);
                    if st.file_generation == generation {
                        st.synced_end = st.synced_end.max(target_end);
                    }
                }
                // Never retry: after a failed fsync the kernel may have dropped the
                // dirty pages, and a second fsync can succeed for data that is nowhere.
                Err(e) => {
                    let why = format!("fsync failed: {e}");
                    tracing::error!(error = %why, "log failed; a restart will recover it from disk");
                    st.failed.get_or_insert(why);
                }
            }
            self.synced_cv.notify_all();
        }
    }

    fn mark_durable(&self, revision: u64) {
        if self.durable_revision.fetch_max(revision, Ordering::SeqCst) < revision {
            let cb = lock_unpoisoned(&self.on_durable).clone();
            if let Some(cb) = cb {
                cb(revision);
            }
        }
    }

    fn adopt_synced_file(&self, storage: Arc<dyn Storage>, len: u64) {
        let revision = {
            let mut st = lock_unpoisoned(&self.state);
            st.storage = storage;
            st.synced = st.published;
            st.file_generation += 1;
            st.published_end = len;
            st.synced_end = len;
            st.published_revision
        };
        self.mark_durable(revision);
        self.synced_cv.notify_all();
    }

    fn set_storage(&self, storage: Arc<dyn Storage>) {
        lock_unpoisoned(&self.state).storage = storage;
    }

    fn failed(&self) -> Option<String> {
        lock_unpoisoned(&self.state).failed.clone()
    }

    fn ticket(self: &Arc<Self>) -> Ticket {
        Ticket {
            group: self.clone(),
            seq: lock_unpoisoned(&self.state).published,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Degraded {
    pub disk_full: bool,
    pub reason: String,
}

#[derive(Debug)]
pub enum LogError {
    Write(io::Error),
    Failed(String),
    Degraded(Degraded),
    Locked(PathBuf),
    ReadOnly,
    Io(io::Error),
}

impl LogError {
    pub fn is_disk_full(&self) -> bool {
        match self {
            LogError::Write(e) | LogError::Io(e) => is_disk_full(e),
            LogError::Degraded(d) => d.disk_full,
            _ => false,
        }
    }
    pub fn is_fatal(&self) -> bool {
        matches!(self, LogError::Failed(_))
    }
}

pub fn is_disk_full(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::StorageFull || matches!(e.raw_os_error(), Some(28 | 122))
}

fn is_unwritable(e: &anyhow::Error) -> bool {
    let Some(io) = e.downcast_ref::<io::Error>() else {
        return false;
    };
    matches!(
        io.kind(),
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::ReadOnlyFilesystem
            | io::ErrorKind::StorageFull
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::NotFound
    ) || matches!(io.raw_os_error(), Some(1 | 13 | 28 | 30 | 122))
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::Write(e) => write!(f, "log append failed and was rolled back: {e}"),
            LogError::Failed(why) => {
                write!(f, "log has failed and refuses writes until restart: {why}")
            }
            LogError::Degraded(d) => write!(
                f,
                "log cannot be written ({}); serving reads and retrying",
                d.reason
            ),
            LogError::Locked(p) => write!(
                f,
                "{} is locked by another process (another edge-state on this data dir?)",
                p.display()
            ),
            LogError::ReadOnly => write!(f, "log was opened read-only"),
            LogError::Io(e) => write!(f, "log I/O error: {e}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<io::Error> for LogError {
    fn from(e: io::Error) -> Self {
        LogError::Io(e)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    pub readonly: bool,
}

#[derive(Debug, Clone)]
pub struct TailDamage {
    pub offset: u64,
    pub dropped_bytes: u64,
    pub dropped_records_at_least: u64,
    pub detail: String,
    pub preserved: Option<PathBuf>,
}

#[derive(Debug, Default, Clone)]
pub struct Recovered {
    pub torn_bytes: u64,
    pub torn_copy: Option<PathBuf>,
    pub damage: Option<TailDamage>,
}

pub struct Log {
    file: Arc<dyn Storage>,
    group: Arc<GroupCommit>,
    path: PathBuf,
    len: u64,
    failed: Option<String>,
    degraded: Option<Degraded>,
    readonly: bool,
}

/// gRPC's largest request (4 MiB) is about one batch and apiserver objects (1.5 MiB at
/// most) fit two, so batches stay shared.
pub const BATCH_BYTES: u64 = 4 * 1024 * 1024;

/// A torn tail is one record plus zero-fill; a longer one is damage, not scanned.
const MAX_TORN_SCAN: u64 = 64 * 1024 * 1024;

const EVIDENCE_COPIES_PER_KIND: usize = 2;
const EVIDENCE_MAX_BYTES: u64 = 1 << 30;
const EVIDENCE_MIN_FREE_AFTER_COPY: u64 = 64 << 20;

pub fn rotation_temp_path(path: &Path) -> PathBuf {
    with_suffix(path, ".rot")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Miri cannot call statvfs.
#[cfg(miri)]
fn free_space(_: &Path) -> Option<u64> {
    Some(u64::MAX)
}

#[cfg(not(miri))]
fn free_space(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `st` is a plain-old-data out parameter that statvfs fills in, and
    // `c` is a valid NUL-terminated path for the duration of the call.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

pub fn has_room_for_evidence(free: u64, size: u64) -> bool {
    size <= EVIDENCE_MAX_BYTES && free >= size.saturating_add(EVIDENCE_MIN_FREE_AFTER_COPY)
}

fn prune_evidence(log: &Path, label: &str, keep_newest: usize) {
    let Some(base) = log.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return;
    };
    let prefix = format!("{base}.{label}-");
    let Ok(rd) = std::fs::read_dir(parent_of(log)) else {
        return;
    };
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&prefix) {
            continue;
        }
        if name.ends_with(".part") {
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        let when = e
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        found.push((when, e.path()));
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    for (_, p) in found.into_iter().skip(keep_newest) {
        let _ = std::fs::remove_file(p);
    }
}

pub(crate) fn preserve_evidence(log: &Path, label: &str, tag: &str, from: u64) -> Option<PathBuf> {
    let mut dest = with_suffix(log, &format!(".{label}-{tag}"));
    if dest.exists() {
        // An undecodable record's offset names the same evidence; a timestamp clash
        // is a different event.
        if label != "corrupt" {
            return Some(dest);
        }
        let mut n = 1;
        while dest.exists() {
            dest = with_suffix(log, &format!(".{label}-{tag}-{n}"));
            n += 1;
        }
    }
    let dest = copy_from(log, from, dest)?;
    prune_evidence(log, label, EVIDENCE_COPIES_PER_KIND);
    Some(dest)
}

pub fn tail_copy_path(log: &Path) -> PathBuf {
    with_suffix(log, ".tail")
}

fn copy_from(log: &Path, from: u64, dest: PathBuf) -> Option<PathBuf> {
    let src = File::open(log).ok()?;
    let size = src.metadata().ok()?.len().saturating_sub(from);
    if size == 0 {
        return None;
    }
    let free = free_space(parent_of(log))?;
    if !has_room_for_evidence(free, size) {
        tracing::warn!(
            size,
            free,
            "not keeping a copy of the dropped bytes: not enough free space"
        );
        return None;
    }
    let part = with_suffix(&dest, ".part");
    let copied = (|| -> io::Result<()> {
        let mut out = File::create(&part)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut off = from;
        loop {
            let n = FileExt::read_at(&src, &mut buf, off)?;
            if n == 0 {
                break;
            }
            io::Write::write_all(&mut out, &buf[..n])?;
            off += n as u64;
        }
        out.sync_all()?;
        std::fs::rename(&part, &dest)
    })();
    match copied {
        Ok(()) => Some(dest),
        Err(e) => {
            tracing::warn!(error = %e, "could not keep a copy of the dropped bytes");
            let _ = std::fs::remove_file(&part);
            None
        }
    }
}

pub fn reclaim_evidence(log: &Path) -> u64 {
    let mut freed = 0;
    let mut rm = |p: &Path| {
        if let Ok(m) = std::fs::metadata(p) {
            let n = if m.is_dir() { 0 } else { m.len() };
            let gone = if m.is_dir() {
                std::fs::remove_dir_all(p)
            } else {
                std::fs::remove_file(p)
            };
            if gone.is_ok() {
                freed += n;
            }
        }
    };
    rm(&rotation_temp_path(log));
    rm(&tail_copy_path(log));
    if let Some(base) = log.file_name().map(|n| n.to_string_lossy().into_owned())
        && let Ok(rd) = std::fs::read_dir(parent_of(log))
    {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_evidence = ["corrupt-", "undecodable-", "notafile-"]
                .iter()
                .any(|l| name.starts_with(&format!("{base}.{l}")));
            if is_evidence {
                rm(&e.path());
            }
        }
    }
    freed
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

pub struct RecoveryNote<'a> {
    pub kind: &'a str,
    pub log: &'a Path,
    pub offset: u64,
    pub dropped_bytes: u64,
    pub dropped_records: u64,
    pub skipped_records: u64,
    pub revision: u64,
    pub preserved: Option<&'a Path>,
    pub detail: &'a str,
}

/// Read by edge-scope's flight record.
pub fn write_recovery_note(n: &RecoveryNote<'_>) {
    let dir = parent_of(n.log);
    let json = format!(
        "{{\n  \"time_unix_ms\": {},\n  \"kind\": \"{}\",\n  \"log\": \"{}\",\n  \"offset\": {},\n  \
         \"dropped_bytes\": {},\n  \"dropped_records_at_least\": {},\n  \"skipped_records\": {},\n  \
         \"revision\": {},\n  \"preserved\": {},\n  \"detail\": \"{}\"\n}}\n",
        now_ms(),
        json_escape(n.kind),
        json_escape(&n.log.display().to_string()),
        n.offset,
        n.dropped_bytes,
        n.dropped_records,
        n.skipped_records,
        n.revision,
        n.preserved.map_or("null".to_string(), |p| format!(
            "\"{}\"",
            json_escape(&p.display().to_string())
        )),
        json_escape(n.detail),
    );
    let tmp = dir.join("recovery.json.tmp");
    let res =
        std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, dir.join("recovery.json")));
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not write recovery.json");
        let _ = std::fs::remove_file(&tmp);
    }
}

fn first_intact_frame(tail: &[u8]) -> Option<usize> {
    (1..tail.len()).find(|&o| record::decode(&tail[o..]).is_ok())
}

fn replay_intact_prefix(
    file: &File,
    file_len: u64,
    on_payload: &mut impl FnMut(&[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<u64> {
    let mut reader = io::BufReader::with_capacity(1 << 20, file);
    let mut payload = Vec::new();
    let mut good = 0u64;
    loop {
        let remaining = file_len - good;
        if remaining < record::HEADER_LEN as u64 {
            break;
        }
        let mut header = [0u8; record::HEADER_LEN];
        if !read_or_torn(&mut reader, &mut header)? {
            break;
        }
        let (len, crc) = record::parse_header(&header);
        if len == 0
            || len as usize > record::MAX_PAYLOAD
            || (len as u64) + record::HEADER_LEN as u64 > remaining
        {
            break;
        }
        payload.resize(len as usize, 0);
        if !read_or_torn(&mut reader, &mut payload)? || !record::checksum_ok(&payload, crc) {
            break;
        }
        on_payload(&payload)?;
        good += record::HEADER_LEN as u64 + len as u64;
    }
    Ok(good)
}

fn read_or_torn(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    match r.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

fn count_frames(mut buf: &[u8]) -> u64 {
    let mut n = 0;
    while let Ok(f) = record::decode(buf) {
        n += 1;
        buf = &buf[f.total_len..];
    }
    n
}

fn discard_leftover(p: &Path, what: &str) {
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return;
    };
    let gone = if md.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    };
    match gone {
        Ok(()) => {
            tracing::warn!(leftover = %p.display(), "removed the leftover of an interrupted {what}")
        }
        Err(e) => {
            tracing::warn!(leftover = %p.display(), error = %e, "could not remove the leftover of an interrupted {what}")
        }
    }
}

impl Log {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<(Self, Vec<Vec<u8>>)> {
        let mut payloads = Vec::new();
        let (log, _) = Self::open_with(path, OpenOptions::default(), |p| {
            payloads.push(p.to_vec());
            Ok(())
        })?;
        Ok((log, payloads))
    }

    pub fn open_resilient(
        path: impl AsRef<Path>,
        opts: OpenOptions,
        mut on_payload: impl FnMut(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<(Self, Recovered)> {
        let path = path.as_ref();
        if !opts.readonly {
            if let Err(e) = std::fs::create_dir_all(parent_of(path)) {
                tracing::error!(dir = %parent_of(path).display(), error = %e, "cannot create the data directory");
            }
            if path.is_dir() {
                let aside = with_suffix(path, &format!(".notafile-{}", now_ms()));
                match std::fs::rename(path, &aside) {
                    Ok(()) => tracing::error!(
                        moved_to = %aside.display(),
                        "moved a directory off the log path; starting a fresh log"
                    ),
                    Err(e) => {
                        return Ok((
                            Self::degraded_empty(
                                path,
                                false,
                                format!(
                                    "a directory occupies the log path and cannot be moved: {e}"
                                ),
                            ),
                            Recovered::default(),
                        ));
                    }
                }
            }
        }
        match Self::open_with(path, opts, &mut on_payload) {
            Err(e) if !opts.readonly && is_unwritable(&e) => {
                let disk_full = e.downcast_ref::<io::Error>().is_some_and(is_disk_full);
                let reason = format!("{e:#}");
                tracing::error!(error = %reason, "cannot open the log for writing; serving what can be read");
                match Self::open_with(path, OpenOptions { readonly: true }, &mut on_payload) {
                    Ok((mut log, rec)) => {
                        log.degraded = Some(Degraded { disk_full, reason });
                        Ok((log, rec))
                    }
                    Err(e2)
                        if e2.downcast_ref::<io::Error>().is_some_and(|i| {
                            matches!(
                                i.kind(),
                                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                            )
                        }) =>
                    {
                        Ok((
                            Self::degraded_empty(path, disk_full, reason),
                            Recovered::default(),
                        ))
                    }
                    Err(e2) => Err(e2),
                }
            }
            other => other,
        }
    }

    pub fn open_with(
        path: impl AsRef<Path>,
        opts: OpenOptions,
        mut on_payload: impl FnMut(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<(Self, Recovered)> {
        let path = path.as_ref().to_path_buf();
        let mut created = false;
        let file = if opts.readonly {
            File::open(&path)?
        } else {
            let mut o = std::fs::OpenOptions::new();
            o.read(true).write(true);
            match o.clone().create_new(true).open(&path) {
                Ok(f) => {
                    created = true;
                    f
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => o.open(&path)?,
                Err(e) => return Err(e.into()),
            }
        };
        if !opts.readonly {
            match file.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => return Err(LogError::Locked(path).into()),
                Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
            }
            if created && let Err(e) = sync_dir(parent_of(&path)) {
                tracing::warn!(error = %e, "could not fsync the data directory after creating the log");
            }
            // Only the log's lock holder may discard a rotation temp.
            discard_leftover(&rotation_temp_path(&path), "log rotation");
        }

        let file_len = file.metadata()?.len();
        let mut rec = Recovered::default();
        let good = replay_intact_prefix(&file, file_len, &mut on_payload)?;

        let mut degraded = None;
        if good < file_len {
            let at = good;
            let tail_len = file_len - at;
            // Within the last batch, intact frames after a bad one are unsynced writes too.
            let mut intact_after = None;
            let mut dropped_records = 0;
            if tail_len > BATCH_BYTES && tail_len <= MAX_TORN_SCAN {
                let mut tail = vec![0u8; tail_len as usize];
                file.read_exact_at(&mut tail, at)?;
                if let Some(o) = first_intact_frame(&tail) {
                    intact_after = Some(o);
                    dropped_records = count_frames(&tail[o..]);
                }
            }
            let corrupt = intact_after.is_some() || tail_len > MAX_TORN_SCAN;
            if corrupt {
                let detail = match intact_after {
                    Some(o) => format!("a bad frame is followed by an intact one {o} bytes later"),
                    None => format!("{tail_len} bytes follow the first bad frame"),
                };
                let preserved = if opts.readonly {
                    None
                } else {
                    preserve_evidence(&path, "corrupt", &now_ms().to_string(), at)
                };
                rec.damage = Some(TailDamage {
                    offset: at,
                    dropped_bytes: tail_len,
                    dropped_records_at_least: dropped_records,
                    detail,
                    preserved,
                });
            } else {
                rec.torn_bytes = tail_len;
                // In case the tail held a real bit flip.
                if !opts.readonly && tail_len <= BATCH_BYTES {
                    rec.torn_copy = copy_from(&path, at, tail_copy_path(&path));
                }
            }
            if !opts.readonly {
                let cut = file.set_len(at).and_then(|()| file.sync_all());
                if let Err(e) = cut {
                    tracing::error!(error = %e, "could not truncate the damaged tail");
                    degraded = Some(Degraded {
                        disk_full: is_disk_full(&e),
                        reason: format!("could not truncate the log: {e}"),
                    });
                }
            }
        }

        let file: Arc<dyn Storage> = Arc::new(file);
        Ok((
            Self {
                group: GroupCommit::new(file.clone(), good),
                file,
                path,
                len: good,
                failed: None,
                degraded,
                readonly: opts.readonly,
            },
            rec,
        ))
    }

    pub fn degraded_empty(path: &Path, disk_full: bool, reason: String) -> Self {
        Self {
            file: Arc::new(NullStorage),
            group: GroupCommit::new(Arc::new(NullStorage), 0),
            path: path.to_path_buf(),
            len: 0,
            failed: None,
            degraded: Some(Degraded { disk_full, reason }),
            readonly: true,
        }
    }

    /// On `LogError::Write` nothing was appended; any other error leaves the log refusing
    /// writes.
    pub fn append(&mut self, payload: &[u8], sync: bool) -> Result<u64, LogError> {
        let (offset, ticket) = self.append_published(payload, None)?;
        if sync {
            ticket.wait()?;
        }
        Ok(offset)
    }

    pub fn append_published(
        &mut self,
        payload: &[u8],
        revision: Option<u64>,
    ) -> Result<(u64, Ticket), LogError> {
        if let Some(d) = &self.degraded {
            return Err(LogError::Degraded(d.clone()));
        }
        if self.readonly {
            return Err(LogError::ReadOnly);
        }
        if let Some(why) = self.failed.clone().or_else(|| self.group.failed()) {
            return Err(LogError::Failed(why));
        }
        let mut frame = Vec::with_capacity(payload.len() + record::HEADER_LEN);
        record::encode(payload, &mut frame);
        self.group.make_room(frame.len() as u64)?;
        if let Err(e) = self.file.write_all_at(&frame, self.len) {
            // Cut off any partial frame, or recovery would drop the records after it.
            return Err(match self.file.set_len(self.len) {
                Ok(()) => LogError::Write(e),
                Err(te) => self.fail(format!(
                    "append failed ({e}) and the rollback failed too ({te})"
                )),
            });
        }
        let offset = self.len;
        self.len += frame.len() as u64;
        let seq = self.group.publish(revision, self.len);
        Ok((
            offset,
            Ticket {
                group: self.group.clone(),
                seq,
            },
        ))
    }

    pub fn ticket(&self) -> Ticket {
        self.group.ticket()
    }

    pub fn durable_revision(&self) -> u64 {
        self.group.durable_revision.load(Ordering::SeqCst)
    }

    pub(crate) fn set_recovered_revision(&mut self, revision: u64) {
        self.group
            .durable_revision
            .fetch_max(revision, Ordering::SeqCst);
        lock_unpoisoned(&self.group.state).published_revision = revision;
    }

    pub fn set_on_durable(&self, f: Option<OnDurable>) {
        *lock_unpoisoned(&self.group.on_durable) = f;
    }

    pub fn on_durable(&self) -> Option<OnDurable> {
        lock_unpoisoned(&self.group.on_durable).clone()
    }

    fn fail(&mut self, why: String) -> LogError {
        tracing::error!(log = %self.path.display(), error = %why, "log failed; a restart will recover it from disk");
        self.failed = Some(why.clone());
        LogError::Failed(why)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    #[doc(hidden)]
    pub fn unsynced_bytes(&self) -> u64 {
        let st = lock_unpoisoned(&self.group.state);
        st.published_end - st.synced_end
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_failed(&self) -> bool {
        self.failed.is_some() || self.group.failed().is_some()
    }

    pub fn degraded(&self) -> Option<&Degraded> {
        self.degraded.as_ref()
    }

    pub fn read_committed(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        assert!(
            offset + len <= self.len,
            "reading past the committed length"
        );
        let mut out = vec![0u8; len as usize];
        let mut done = 0usize;
        while done < out.len() {
            let n = self.file.read_at(&mut out[done..], offset + done as u64)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(out)
    }

    pub(crate) fn placeholder() -> Self {
        Self {
            file: Arc::new(NullStorage),
            group: GroupCommit::new(Arc::new(NullStorage), 0),
            path: PathBuf::new(),
            len: 0,
            failed: None,
            degraded: None,
            readonly: true,
        }
    }

    #[doc(hidden)]
    pub fn wrap_storage(&mut self, f: impl FnOnce(Arc<dyn Storage>) -> Arc<dyn Storage>) {
        self.file = f(self.file.clone());
        self.group.set_storage(self.file.clone());
    }

    /// Until the directory fsync returns either file may survive a power cut, so nothing
    /// may be acknowledged to the new one before it.
    pub(crate) fn install(
        &mut self,
        temp: RotatedLog,
        hook: &mut dyn FnMut(RotationStep),
    ) -> Result<(), LogError> {
        if let Err(e) = std::fs::rename(&temp.path, &self.path) {
            temp.abandon();
            return Err(LogError::Io(e));
        }
        hook(RotationStep::Renamed);
        if let Err(e) = sync_dir(parent_of(&self.path)) {
            return Err(self.fail(format!("directory fsync after log rotation failed: {e}")));
        }
        hook(RotationStep::DirSynced);
        self.file = Arc::new(temp.file);
        self.len = temp.len;
        self.group.adopt_synced_file(self.file.clone(), self.len);
        Ok(())
    }

    pub fn is_readonly(&self) -> bool {
        self.readonly
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStep {
    TempWritten,
    DeltaCopied,
    TempSynced,
    Renamed,
    DirSynced,
}

pub(crate) struct RotatedLog {
    pub(crate) file: File,
    pub(crate) path: PathBuf,
    pub(crate) len: u64,
}

impl RotatedLog {
    pub(crate) fn create(live: &Path) -> io::Result<Self> {
        let path = rotation_temp_path(live);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        // Locked before the rename makes it live, so no second writer can take it.
        file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => io::Error::other("rotation temp is locked"),
            std::fs::TryLockError::Error(e) => e,
        })?;
        Ok(Self { file, path, len: 0 })
    }

    pub(crate) fn write_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        FileExt::write_all_at(&self.file, bytes, self.len)?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    pub(crate) fn sync(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    pub(crate) fn abandon(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[doc(hidden)]
pub mod fault {
    use super::*;

    #[derive(Default)]
    pub struct Faults {
        pub bytes_before_enospc: Option<usize>,
        pub fail_sync: bool,
        pub fail_set_len: bool,
        pub syncs_started: usize,
        pub syncs_completed: usize,
        pub sync_delay: Option<std::time::Duration>,
        pub keep_sync_images: bool,
        pub image_at_each_sync: Vec<Vec<u8>>,
        pub len_at_each_sync: Vec<u64>,
    }

    pub struct FaultyStorage {
        inner: Arc<dyn Storage>,
        pub faults: Arc<Mutex<Faults>>,
    }

    impl FaultyStorage {
        pub fn wrap(
            faults: Arc<Mutex<Faults>>,
        ) -> impl FnOnce(Arc<dyn Storage>) -> Arc<dyn Storage> {
            move |inner| Arc::new(FaultyStorage { inner, faults })
        }

        fn len(&self) -> io::Result<u64> {
            let mut len = 0;
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = self.inner.read_at(&mut buf, len)?;
                if n == 0 {
                    return Ok(len);
                }
                len += n as u64;
            }
        }

        fn image(&self) -> io::Result<Vec<u8>> {
            let mut out = Vec::new();
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = self.inner.read_at(&mut buf, out.len() as u64)?;
                if n == 0 {
                    return Ok(out);
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
    }

    impl Storage for FaultyStorage {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            self.inner.read_at(buf, offset)
        }
        fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
            let mut f = self.faults.lock().unwrap();
            if let Some(budget) = f.bytes_before_enospc {
                if buf.len() > budget {
                    f.bytes_before_enospc = Some(0);
                    drop(f);
                    self.inner.write_all_at(&buf[..budget], offset)?;
                    return Err(io::Error::from_raw_os_error(28));
                }
                f.bytes_before_enospc = Some(budget - buf.len());
            }
            drop(f);
            self.inner.write_all_at(buf, offset)
        }
        fn sync(&self) -> io::Result<()> {
            let mut f = self.faults.lock().unwrap();
            f.syncs_started += 1;
            if f.fail_sync {
                return Err(io::Error::from_raw_os_error(5));
            }
            if f.keep_sync_images {
                let image = self.image()?;
                f.image_at_each_sync.push(image);
            }
            let len = self.len()?;
            f.len_at_each_sync.push(len);
            let delay = f.sync_delay;
            drop(f);
            if let Some(d) = delay {
                std::thread::sleep(d);
            }
            self.inner.sync()?;
            self.faults.lock().unwrap().syncs_completed += 1;
            Ok(())
        }
        fn set_len(&self, len: u64) -> io::Result<()> {
            if self.faults.lock().unwrap().fail_set_len {
                return Err(io::Error::from_raw_os_error(5));
            }
            self.inner.set_len(len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fault::{Faults, FaultyStorage};
    use super::*;
    use std::io::Write;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.log");
        (d, p)
    }

    fn append_raw(p: &Path, bytes: &[u8]) {
        let mut raw = std::fs::OpenOptions::new().append(true).open(p).unwrap();
        raw.write_all(bytes).unwrap();
    }

    fn fill_past_a_batch(log: &mut Log) -> u64 {
        let n = BATCH_BYTES / (1 << 20) + 1;
        for _ in 0..n {
            log.append(&[7u8; 1 << 20], true).unwrap();
        }
        n
    }

    #[test]
    fn mid_file_corruption_is_cut_and_kept() {
        let (d, p) = tmp();
        let filler;
        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"good", true).unwrap();
            log.append(b"will-rot", true).unwrap();
            log.append(b"acknowledged-after", true).unwrap();
            filler = fill_past_a_batch(&mut log);
        }
        let mut bytes = std::fs::read(&p).unwrap();
        let rot_at = record::HEADER_LEN + 4 + record::HEADER_LEN + 2;
        bytes[rot_at] ^= 0xff;
        std::fs::write(&p, &bytes).unwrap();

        let mut got = Vec::new();
        let (mut log, rec) = Log::open_with(&p, OpenOptions::default(), |pl| {
            got.push(pl.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![b"good".to_vec()]);
        let dmg = rec.damage.expect("the damage must be reported");
        assert_eq!(
            (dmg.offset, dmg.dropped_bytes),
            (12, bytes.len() as u64 - 12)
        );
        assert_eq!(
            dmg.dropped_records_at_least,
            1 + filler,
            "every intact record beyond the damage is counted"
        );
        let copy = dmg
            .preserved
            .expect("a copy of the dropped bytes must be kept");
        assert_eq!(std::fs::read(copy).unwrap(), &bytes[12..]);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 12);
        log.append(b"after-heal", true).unwrap();
        drop(log);
        let (_l, payloads) = Log::open(&p).unwrap();
        assert_eq!(payloads, vec![b"good".to_vec(), b"after-heal".to_vec()]);
        assert!(d.path().read_dir().unwrap().count() >= 2);
    }

    #[test]
    fn keeps_two_newest_evidence_copies() {
        let (d, p) = tmp();
        for round in 0..5u8 {
            let _ = std::fs::remove_file(&p);
            {
                let (mut log, _) = Log::open(&p).unwrap();
                log.append(b"good", true).unwrap();
                log.append(&[round; 40], true).unwrap();
                log.append(b"after", true).unwrap();
                fill_past_a_batch(&mut log);
            }
            let mut bytes = std::fs::read(&p).unwrap();
            bytes[record::HEADER_LEN + 4 + record::HEADER_LEN + 3] ^= 0xff;
            std::fs::write(&p, bytes).unwrap();
            Log::open(&p).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(15)); // distinct names and mtimes
        }
        let mut rounds: Vec<u8> = d
            .path()
            .read_dir()
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .map(|e| std::fs::read(e.path()).unwrap()[record::HEADER_LEN])
            .collect();
        rounds.sort();
        assert_eq!(rounds, vec![3, 4]);
    }

    #[test]
    fn evidence_needs_free_space() {
        let size = 1 << 20;
        let max = EVIDENCE_MAX_BYTES;
        for (free, size, room) in [
            (size + EVIDENCE_MIN_FREE_AFTER_COPY, size, true),
            (size + EVIDENCE_MIN_FREE_AFTER_COPY - 1, size, false),
            (u64::MAX, max, true),
            (u64::MAX, max + 1, false),
        ] {
            assert_eq!(has_room_for_evidence(free, size), room, "{free} {size}");
        }
    }

    #[test]
    fn long_zero_tail_is_torn() {
        let (_d, p) = tmp();
        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"good", true).unwrap();
        }
        let zeros = 2 * BATCH_BYTES as usize;
        append_raw(&p, &vec![0u8; zeros]);
        let (log, rec) = Log::open_with(&p, OpenOptions::default(), |_| Ok(())).unwrap();
        assert!(rec.damage.is_none());
        assert_eq!(rec.torn_bytes, zeros as u64);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), log.len());
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        record::encode(payload, &mut f);
        f
    }

    fn evidence_in(d: &Path) -> usize {
        d.read_dir()
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .count()
    }

    #[test]
    fn reordered_last_batch_is_torn() {
        let (d, p) = tmp();
        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"acknowledged", true).unwrap();
            for r in [&b"lost"[..], b"kept-1", b"kept-2"] {
                log.append(r, false).unwrap();
            }
        }
        let lost_at = frame(b"acknowledged").len();
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[lost_at..lost_at + frame(b"lost").len()].fill(0);
        std::fs::write(&p, &bytes).unwrap();

        let mut got = Vec::new();
        let (log, rec) = Log::open_with(&p, OpenOptions::default(), |pl| {
            got.push(pl.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![b"acknowledged".to_vec()]);
        assert!(rec.damage.is_none(), "{:?}", rec.damage);
        assert_eq!(rec.torn_bytes, (bytes.len() - lost_at) as u64);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), log.len());
        assert_eq!(evidence_in(d.path()), 0);
        assert_eq!(rec.torn_copy, Some(tail_copy_path(&p)));
        assert_eq!(
            std::fs::read(tail_copy_path(&p)).unwrap(),
            &bytes[lost_at..]
        );
    }

    #[test]
    fn tail_copy_is_replaced() {
        let (d, p) = tmp();
        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"acknowledged", true).unwrap();
        }
        for torn in [&[9u8; 300][..], &[8u8; 5]] {
            append_raw(&p, torn);
            let (_log, rec) = Log::open_with(&p, OpenOptions::default(), |_| Ok(())).unwrap();
            assert_eq!(rec.torn_bytes, torn.len() as u64);
            assert_eq!(std::fs::read(tail_copy_path(&p)).unwrap(), torn);
        }
        let files = d.path().read_dir().unwrap().count();
        assert_eq!(files, 2, "the log and one copy");
    }

    #[test]
    fn unwritable_tail_copy_is_ignored() {
        let (_d, p) = tmp();
        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"acknowledged", true).unwrap();
        }
        std::fs::create_dir(tail_copy_path(&p)).unwrap();
        std::fs::write(tail_copy_path(&p).join("x"), b"x").unwrap();
        append_raw(&p, &[9u8; 30]);
        let (mut log, rec) = Log::open_with(&p, OpenOptions::default(), |_| Ok(())).unwrap();
        assert_eq!((rec.torn_bytes, rec.torn_copy), (30, None));
        assert!(rec.damage.is_none() && log.degraded().is_none());
        assert_eq!(std::fs::metadata(&p).unwrap().len(), log.len());
        log.append(b"after", true).unwrap();
    }

    #[test]
    fn batch_bound_separates_damage_from_tear() {
        for (tail, damage) in [(BATCH_BYTES, false), (BATCH_BYTES + 1, true)] {
            let (d, p) = tmp();
            let garbage = [0xffu8; record::HEADER_LEN];
            let payload = vec![5u8; tail as usize - 2 * record::HEADER_LEN];
            let mut bytes = frame(b"synced");
            bytes.extend_from_slice(&garbage);
            bytes.extend(frame(&payload));
            std::fs::write(&p, &bytes).unwrap();
            let (_log, rec) = Log::open_with(&p, OpenOptions::default(), |_| Ok(())).unwrap();
            assert_eq!(rec.damage.is_some(), damage, "tail of {tail} bytes");
            assert_eq!(evidence_in(d.path()), usize::from(damage));
            let cut = if damage { 0 } else { tail };
            assert_eq!(rec.torn_bytes, cut, "tail of {tail} bytes");
        }
    }

    #[test]
    fn tail_past_scan_limit_is_damage() {
        for (tail, damage) in [(MAX_TORN_SCAN, false), (MAX_TORN_SCAN + 1, true)] {
            let (_d, p) = tmp();
            std::fs::write(&p, frame(b"synced")).unwrap();
            let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_len(frame(b"synced").len() as u64 + tail).unwrap();
            let (_log, rec) =
                Log::open_with(&p, OpenOptions { readonly: true }, |_| Ok(())).unwrap();
            assert_eq!(rec.damage.is_some(), damage, "tail of {tail} bytes");
        }
    }

    fn faulty(p: &Path) -> (Log, Arc<Mutex<Faults>>) {
        let faults = Arc::new(Mutex::new(Faults::default()));
        let (mut log, _) = Log::open(p).unwrap();
        log.wrap_storage(FaultyStorage::wrap(faults.clone()));
        (log, faults)
    }

    #[test]
    fn unsynced_batch_stays_bounded() {
        let (_d, p) = tmp();
        let (mut log, faults) = faulty(&p);
        let mib = vec![1u8; 1 << 20];
        let frame_len = frame(&mib).len() as u64;
        let fit = BATCH_BYTES / frame_len;
        for _ in 0..fit {
            log.append_published(&mib, None).unwrap();
        }
        assert_eq!(
            faults.lock().unwrap().syncs_started,
            0,
            "a batch within the bound waits for nothing"
        );
        assert_eq!(log.unsynced_bytes(), fit * frame_len);
        log.append_published(&mib, None).unwrap();
        assert_eq!(faults.lock().unwrap().syncs_started, 1);
        assert_eq!(log.unsynced_bytes(), frame_len);

        let huge = vec![2u8; BATCH_BYTES as usize + 1];
        log.append_published(&huge, None).unwrap();
        assert_eq!(faults.lock().unwrap().syncs_started, 2);
        assert_eq!(log.unsynced_bytes(), frame(&huge).len() as u64);
        log.append_published(b"small", None).unwrap();
        assert_eq!(faults.lock().unwrap().syncs_started, 3);
        assert_eq!(log.unsynced_bytes(), frame(b"small").len() as u64);
    }

    #[test]
    fn batch_measured_in_rotated_file() {
        let (_d, p) = tmp();
        let (mut log, faults) = faulty(&p);
        log.append(b"synced", true).unwrap();
        let (_, pending) = log.append_published(&vec![3u8; 3 << 20], None).unwrap();
        faults.lock().unwrap().sync_delay = Some(std::time::Duration::from_millis(300));
        let old_fsync = std::thread::spawn(move || pending.wait());
        while faults.lock().unwrap().syncs_started < 2 {
            std::thread::yield_now();
        }

        let mut rotated = RotatedLog::create(&p).unwrap();
        rotated.write_raw(&frame(b"compacted")).unwrap();
        rotated.sync().unwrap();
        log.install(rotated, &mut |_| {}).unwrap();
        assert_eq!(log.unsynced_bytes(), 0, "the new file was synced whole");
        old_fsync.join().unwrap().unwrap();
        assert_eq!(log.unsynced_bytes(), 0);
        log.append_published(b"next", None).unwrap();
        assert_eq!(log.unsynced_bytes(), frame(b"next").len() as u64);
    }

    #[test]
    fn consumer_error_leaves_file_untouched() {
        let (_d, p) = tmp();
        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"ok", true).unwrap();
            log.append(b"boom", true).unwrap();
        }
        let before = std::fs::read(&p).unwrap();
        let err = Log::open_with(&p, OpenOptions::default(), |pl| {
            anyhow::ensure!(pl == b"ok", "consumer refused");
            Ok(())
        })
        .err()
        .expect("consumer error propagates");
        assert!(format!("{err:#}").contains("consumer refused"));
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[test]
    fn read_only_open_never_writes() {
        let (_d, p) = tmp();
        assert!(Log::open_with(&p, OpenOptions { readonly: true }, |_| Ok(())).is_err());
        assert!(!p.exists(), "a read-only open must not create the log");

        {
            let (mut log, _) = Log::open(&p).unwrap();
            log.append(b"one", true).unwrap();
        }
        append_raw(&p, &[1, 2, 3]);
        let before = std::fs::read(&p).unwrap();
        let mut n = 0;
        let (mut log, rec) = Log::open_with(&p, OpenOptions { readonly: true }, |_| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((n, rec.torn_bytes), (1, 3));
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "a torn tail must be left in place"
        );
        assert!(!tail_copy_path(&p).exists(), "nor copied");
        assert!(matches!(log.append(b"x", true), Err(LogError::ReadOnly)));
    }

    #[test]
    fn second_open_is_refused() {
        let (_d, p) = tmp();
        let (_first, _) = Log::open(&p).unwrap();
        let err = Log::open(&p).err().expect("second open must fail");
        assert!(
            format!("{err:#}").contains("locked by another process"),
            "{err:#}"
        );
        assert!(Log::open_with(&p, OpenOptions { readonly: true }, |_| Ok(())).is_ok());
    }

    #[test]
    fn failed_append_rolls_back() {
        let (_d, p) = tmp();
        let faults = Arc::new(Mutex::new(Faults::default()));
        let (mut log, _) = Log::open(&p).unwrap();
        log.append(b"before", true).unwrap();
        log.wrap_storage(FaultyStorage::wrap(faults.clone()));

        faults.lock().unwrap().bytes_before_enospc = Some(6);
        let e = log.append(b"does-not-fit", true).unwrap_err();
        assert!(e.is_disk_full() && !e.is_fatal(), "{e}");
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            log.len(),
            "garbage must be cut off"
        );

        faults.lock().unwrap().bytes_before_enospc = None;
        log.append(b"after", true).unwrap();
        drop(log);
        let (_log, payloads) = Log::open(&p).unwrap();
        assert_eq!(payloads, vec![b"before".to_vec(), b"after".to_vec()]);
    }

    #[test]
    fn failed_rollback_fails_log() {
        let (_d, p) = tmp();
        let faults = Arc::new(Mutex::new(Faults::default()));
        let (mut log, _) = Log::open(&p).unwrap();
        log.wrap_storage(FaultyStorage::wrap(faults.clone()));
        {
            let mut f = faults.lock().unwrap();
            f.bytes_before_enospc = Some(3);
            f.fail_set_len = true;
        }
        assert!(log.append(b"x", true).unwrap_err().is_fatal());
        faults.lock().unwrap().bytes_before_enospc = None;
        assert!(
            log.append(b"y", true).unwrap_err().is_fatal(),
            "a failed log accepts nothing"
        );
        assert!(log.is_failed());
    }

    #[test]
    fn failed_fsync_is_not_retried() {
        let (_d, p) = tmp();
        let faults = Arc::new(Mutex::new(Faults::default()));
        let (mut log, _) = Log::open(&p).unwrap();
        log.wrap_storage(FaultyStorage::wrap(faults.clone()));
        faults.lock().unwrap().fail_sync = true;
        assert!(log.append(b"x", true).unwrap_err().is_fatal());
        assert_eq!(faults.lock().unwrap().syncs_started, 1);
        faults.lock().unwrap().fail_sync = false;
        assert!(
            log.append(b"y", true).is_err(),
            "must not quietly resume after a failed fsync"
        );
        assert_eq!(
            faults.lock().unwrap().syncs_started,
            1,
            "no second fsync was attempted"
        );
    }
}
