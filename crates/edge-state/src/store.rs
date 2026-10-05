//! A mutation validates, appends one record, then applies it, so a multi-key write is
//! atomic.

use crate::entry::{Entry, Write};
use crate::log::{self, Log, LogError};
use crate::record;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;

/// etcd's default `--max-txn-ops`, per compare list and per branch.
pub const MAX_TXN_OPS: usize = 128;

pub const ROTATE_MIN_BYTES: u64 = 64 * 1024 * 1024;
pub const ROTATE_GARBAGE_RATIO: u64 = 2;

/// etcd's `MaxLeaseTTL`.
pub const MAX_LEASE_TTL: i64 = 9_000_000_000;

#[derive(Debug)]
pub enum StoreError {
    Compacted { floor: u64 },
    FutureRevision { current: u64 },
    LeaseNotFound(i64),
    LeaseExists(i64),
    TtlInvalid(i64),
    TtlTooLarge(i64),
    DuplicateKey,
    TooManyOps,
    Unsupported(String),
    Invalid(String),
    Rotation(String),
    Log(LogError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Compacted { floor } => {
                write!(
                    f,
                    "mvcc: required revision has been compacted (floor {floor})"
                )
            }
            StoreError::FutureRevision { current } => {
                write!(
                    f,
                    "mvcc: required revision is a future revision (store is at {current})"
                )
            }
            StoreError::LeaseNotFound(id) => write!(f, "requested lease not found: {id}"),
            StoreError::LeaseExists(id) => write!(f, "lease {id} already exists"),
            StoreError::TtlInvalid(t) => write!(f, "lease ttl must be positive, got {t}"),
            StoreError::TtlTooLarge(t) => write!(f, "too large lease TTL: {t}"),
            StoreError::DuplicateKey => write!(f, "duplicate key given in txn request"),
            StoreError::TooManyOps => write!(f, "too many operations in txn request"),
            StoreError::Unsupported(what) => write!(f, "unsupported: {what}"),
            StoreError::Invalid(what) => write!(f, "invalid request: {what}"),
            StoreError::Rotation(what) => write!(f, "log rotation: {what}"),
            StoreError::Log(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<LogError> for StoreError {
    fn from(e: LogError) -> Self {
        StoreError::Log(e)
    }
}

impl StoreError {
    pub fn is_disk_full(&self) -> bool {
        matches!(self, StoreError::Log(e) if e.is_disk_full())
    }
    pub fn is_fatal(&self) -> bool {
        matches!(self, StoreError::Log(e) if e.is_fatal())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StoreOptions {
    pub readonly: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryInfo {
    pub torn_bytes: u64,
    pub torn_copy: Option<std::path::PathBuf>,
    pub damage: Option<log::TailDamage>,
    pub skipped_records: u64,
    pub first_skipped_at: Option<u64>,
    pub contradictory_records: u64,
}

impl RecoveryInfo {
    pub fn is_notable(&self) -> bool {
        self.damage.is_some() || self.skipped_records > 0 || self.contradictory_records > 0
    }
}

const MAX_SANE_REVISION: u64 = 1 << 62;
const REVISION_HINT_WINDOW: u64 = 1 << 24;

/// A delete carries an empty value and `version == 0`, as etcd's DELETE event does.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub kv: KeyValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Put,
    Delete,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyValue {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub create_revision: u64,
    pub mod_revision: u64,
    pub version: i64,
    pub lease: i64,
}

#[derive(Debug, Clone)]
struct Version {
    mod_revision: u64,
    create_revision: u64,
    version: i64,
    value: Option<Arc<[u8]>>,
    lease: i64,
}

pub struct Store {
    log: Log,
    index: BTreeMap<Vec<u8>, Vec<Version>>,
    revision: u64,
    compact_revision: u64,
    lease_ttls: HashMap<i64, i64>,
    keys_by_lease: HashMap<i64, BTreeSet<Vec<u8>>>,
    next_lease: i64,
    /// Above the floor, in write order, as etcd delivers events.
    changes: BTreeSet<Change>,
    live_bytes: u64,
    rotating: bool,
    rotate_min_bytes: u64,
    rotate_garbage_ratio: u64,
    recovery: RecoveryInfo,
    deferred: bool,
}

type Change = (u64, u32, Vec<u8>);

fn encoded_size_estimate(key: &[u8], v: &Version) -> u64 {
    let value = v.value.as_ref().map_or(0, |v| v.len());
    (record::HEADER_LEN + 1 + 8 + 8 + 4 + key.len() + value) as u64
}

impl Store {
    fn empty(log: Log) -> Store {
        Store {
            log,
            index: BTreeMap::new(),
            revision: 1,
            compact_revision: 0,
            lease_ttls: HashMap::new(),
            keys_by_lease: HashMap::new(),
            next_lease: 1,
            changes: BTreeSet::new(),
            live_bytes: 0,
            rotating: false,
            rotate_min_bytes: ROTATE_MIN_BYTES,
            rotate_garbage_ratio: ROTATE_GARBAGE_RATIO,
            recovery: RecoveryInfo::default(),
            deferred: false,
        }
    }

    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with(path, StoreOptions::default())
    }

    pub fn open_readonly(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with(path, StoreOptions { readonly: true })
    }

    pub fn open_patiently(path: impl AsRef<Path>) -> Self {
        Self::open_patiently_for(path, None).expect("an unbounded wait returns a store")
    }

    pub fn open_patiently_for(
        path: impl AsRef<Path>,
        limit: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let started = std::time::Instant::now();
        let mut delay = std::time::Duration::from_millis(20);
        let mut attempts = 0u64;
        loop {
            match Self::open(path) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    if limit.is_some_and(|l| started.elapsed() >= l) {
                        return Err(e);
                    }
                    attempts += 1;
                    if attempts == 1 || attempts.is_power_of_two() {
                        tracing::error!(log = %path.display(), attempts, error = %format!("{e:#}"), "cannot open the log yet; retrying");
                    }
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(std::time::Duration::from_secs(2));
                }
            }
        }
    }

    pub fn open_with(path: impl AsRef<Path>, opts: StoreOptions) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let mut store = Store::empty(Log::placeholder());
        let mut skipped_offsets = Vec::<u64>::new();
        let mut offset = 0u64;
        let (log, recovered) = Log::open_resilient(
            path,
            log::OpenOptions {
                readonly: opts.readonly,
            },
            |payload| {
                match Entry::decode(payload) {
                    Ok(entry) => store.apply(&entry),
                    Err(_) => {
                        skipped_offsets.push(offset);
                        store.note_revision_hint(payload);
                    }
                }
                offset += (record::HEADER_LEN + payload.len()) as u64;
                Ok(())
            },
        )?;
        store.log = log;
        store.log.set_recovered_revision(store.revision);
        store.recovery = RecoveryInfo {
            torn_bytes: recovered.torn_bytes,
            torn_copy: recovered.torn_copy.clone(),
            damage: recovered.damage.clone(),
            skipped_records: skipped_offsets.len() as u64,
            first_skipped_at: skipped_offsets.first().copied(),
            contradictory_records: store.recovery.contradictory_records,
        };
        store.report_recovery(path, opts.readonly);
        Ok(store)
    }

    #[doc(hidden)]
    pub fn degraded(path: impl AsRef<Path>, disk_full: bool, reason: &str) -> Self {
        Store::empty(Log::degraded_empty(
            path.as_ref(),
            disk_full,
            reason.to_string(),
        ))
    }

    fn report_recovery(&self, path: &Path, readonly: bool) {
        let r = &self.recovery;
        if r.torn_bytes > 0 {
            tracing::info!(
                torn_bytes = r.torn_bytes,
                kept = ?r.torn_copy,
                readonly,
                "cut unsynced writes from the end of the log; every acknowledged write is intact"
            );
        }
        if let Some(d) = &self.log.degraded() {
            tracing::error!(disk_full = d.disk_full, reason = %d.reason, revision = self.revision,
                "store degraded: serving reads, refusing writes until the log can be written");
        }
        if !r.is_notable() {
            return;
        }
        if let Some(d) = &r.damage {
            tracing::error!(
                offset = d.offset,
                dropped_bytes = d.dropped_bytes,
                dropped_records_at_least = d.dropped_records_at_least,
                revision = self.revision,
                preserved = ?d.preserved,
                detail = %d.detail,
                readonly,
                "log damaged before its unsynced tail; recovered the valid prefix"
            );
        }
        if r.skipped_records > 0 {
            tracing::error!(
                skipped_records = r.skipped_records,
                first_at = ?r.first_skipped_at,
                revision = self.revision,
                "skipped records this build cannot decode"
            );
        }
        if r.contradictory_records > 0 {
            tracing::error!(
                records = r.contradictory_records,
                revision = self.revision,
                "ignored or clamped records that contradicted the state before them"
            );
        }
        if readonly || self.log.path().as_os_str().is_empty() {
            return;
        }
        let mut preserved = r.damage.as_ref().and_then(|d| d.preserved.clone());
        if r.skipped_records > 0
            && let Some(at) = r.first_skipped_at
        {
            preserved =
                log::preserve_evidence(path, "undecodable", &at.to_string(), at).or(preserved);
        }
        let (kind, offset, dropped_bytes, dropped_records, detail) = match &r.damage {
            Some(d) => (
                "corrupt_tail",
                d.offset,
                d.dropped_bytes,
                d.dropped_records_at_least,
                d.detail.clone(),
            ),
            None if r.skipped_records > 0 => (
                "undecodable_records",
                r.first_skipped_at.unwrap_or(0),
                0,
                0,
                "records this build cannot decode were skipped".to_string(),
            ),
            None => (
                "inconsistent_records",
                0,
                0,
                0,
                "records contradicting earlier state were ignored".to_string(),
            ),
        };
        log::write_recovery_note(&log::RecoveryNote {
            kind,
            log: path,
            offset,
            dropped_bytes,
            dropped_records,
            skipped_records: r.skipped_records,
            revision: self.revision,
            preserved: preserved.as_deref(),
            detail: &detail,
        });
    }

    pub fn recovery(&self) -> &RecoveryInfo {
        &self.recovery
    }

    /// Keeps revisions monotonic past a record this build cannot decode, which likely
    /// carries its revision in bytes 1..9 as every revision-bearing entry does.
    fn note_revision_hint(&mut self, payload: &[u8]) {
        if payload.len() >= 9 {
            let hint = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            if hint > self.revision && hint <= self.revision.saturating_add(REVISION_HINT_WINDOW) {
                self.revision = hint;
            }
        }
    }

    pub fn is_degraded(&self) -> bool {
        self.log.degraded().is_some()
    }

    pub fn degraded_reason(&self) -> Option<String> {
        self.log.degraded().map(|d| d.reason.clone())
    }

    /// Nothing was accepted while degraded, so replacing state loses nothing.
    pub fn try_recover(&mut self) -> anyhow::Result<bool> {
        let Some(d) = self.log.degraded().cloned() else {
            return Ok(false);
        };
        let path = self.log.path().to_path_buf();
        if path.as_os_str().is_empty() {
            return Ok(false);
        }
        if d.disk_full {
            let freed = log::reclaim_evidence(&path);
            if freed > 0 {
                tracing::warn!(freed, "disk full: deleted evidence files");
            }
        }
        let fresh = Store::open_with(&path, StoreOptions::default())?;
        if fresh.is_degraded() {
            return Ok(false);
        }
        fresh.log.set_on_durable(self.log.on_durable());
        let deferred = self.deferred;
        *self = fresh;
        self.deferred = deferred;
        tracing::warn!(
            revision = self.revision,
            "log writable again; store recovered"
        );
        Ok(true)
    }

    pub fn reclaim_space(&mut self) -> u64 {
        let path = self.log.path().to_path_buf();
        if path.as_os_str().is_empty() {
            return 0;
        }
        let before = self.log.len();
        let mut freed = log::reclaim_evidence(&path);
        if !self.rotating && !self.log.is_failed() && self.live_bytes < self.log.len() {
            match self.rotate() {
                Ok(r) => freed += r.before.saturating_sub(r.after),
                Err(e) => tracing::warn!(error = %e, "could not rotate the log to reclaim space"),
            }
        }
        tracing::warn!(
            freed,
            log_before = before,
            log_after = self.log.len(),
            "disk full: reclaimed space"
        );
        freed
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn compact_revision(&self) -> u64 {
        self.compact_revision
    }

    fn resolve(&self, revision: u64) -> u64 {
        if revision == 0 {
            self.revision
        } else {
            revision
        }
    }

    pub fn check_revision(&self, revision: u64) -> Result<(), StoreError> {
        if revision == 0 {
            return Ok(());
        }
        if revision > self.revision {
            return Err(StoreError::FutureRevision {
                current: self.revision,
            });
        }
        if revision < self.compact_revision {
            return Err(StoreError::Compacted {
                floor: self.compact_revision,
            });
        }
        Ok(())
    }

    fn apply_put(
        &mut self,
        revision: u64,
        key: &[u8],
        value: Arc<[u8]>,
        lease: i64,
        restored_meta: Option<(u64, i64)>,
    ) {
        // Binary searches need ascending versions; only a damaged log breaks that.
        if self
            .index
            .get(key)
            .and_then(|v| v.last())
            .is_some_and(|l| l.mod_revision >= revision)
        {
            self.recovery.contradictory_records += 1;
            return;
        }
        let versions = self.index.entry(key.to_vec()).or_default();
        let (create_revision, version, prev_lease) = match (restored_meta, versions.last()) {
            (Some((c, v)), last) => (c, v, last.filter(|l| l.value.is_some()).map(|l| l.lease)),
            (None, Some(v)) if v.value.is_some() => (
                v.create_revision,
                v.version.saturating_add(1),
                Some(v.lease),
            ),
            (None, _) => (revision, 1, None),
        };
        let v = Version {
            mod_revision: revision,
            create_revision,
            version,
            value: Some(value),
            lease,
        };
        self.live_bytes += encoded_size_estimate(key, &v);
        versions.push(v);
        if revision > self.compact_revision {
            self.record_change(revision, key);
        }
        if let Some(p) = prev_lease.filter(|p| *p != 0 && *p != lease) {
            self.detach(p, key);
        }
        if lease != 0 {
            self.keys_by_lease
                .entry(lease)
                .or_default()
                .insert(key.to_vec());
        }
    }

    fn apply_delete(&mut self, revision: u64, key: &[u8]) {
        let mut detach = None;
        if let Some(versions) = self.index.get_mut(key)
            && let Some(last) = versions.last()
            && last.value.is_some()
            && last.mod_revision < revision
        {
            detach = Some(last.lease).filter(|l| *l != 0);
            let v = Version {
                mod_revision: revision,
                create_revision: 0,
                version: 0,
                value: None,
                lease: 0,
            };
            self.live_bytes += encoded_size_estimate(key, &v);
            versions.push(v);
            if revision > self.compact_revision {
                self.record_change(revision, key);
            }
        }
        if let Some(l) = detach {
            self.detach(l, key);
        }
    }

    fn record_change(&mut self, revision: u64, key: &[u8]) {
        let position = match self
            .changes
            .range(..(revision.saturating_add(1), 0, Vec::new()))
            .next_back()
        {
            Some((r, p, _)) if *r == revision => p + 1,
            _ => 0,
        };
        self.changes.insert((revision, position, key.to_vec()));
    }

    fn detach(&mut self, lease: i64, key: &[u8]) {
        if let Some(set) = self.keys_by_lease.get_mut(&lease) {
            set.remove(key);
            if set.is_empty() {
                self.keys_by_lease.remove(&lease);
            }
        }
    }

    fn apply(&mut self, entry: &Entry) {
        if entry
            .consumed_revision()
            .is_some_and(|r| r > MAX_SANE_REVISION)
            || matches!(entry, Entry::Base { compact_revision, .. } if *compact_revision > MAX_SANE_REVISION)
        {
            self.recovery.contradictory_records += 1;
            return;
        }
        match entry {
            Entry::Put {
                revision,
                key,
                value,
                lease,
            } => {
                self.revision = self.revision.max(*revision);
                self.apply_put(*revision, key, value.as_slice().into(), *lease, None);
            }
            Entry::PutWithMeta {
                revision,
                key,
                value,
                lease,
                create_revision,
                version,
            } => {
                self.revision = self.revision.max(*revision);
                self.apply_put(
                    *revision,
                    key,
                    value.as_slice().into(),
                    *lease,
                    Some((*create_revision, *version)),
                );
            }
            Entry::Delete { revision, key } => {
                self.revision = self.revision.max(*revision);
                self.apply_delete(*revision, key);
            }
            Entry::Txn { revision, writes } => {
                self.revision = self.revision.max(*revision);
                for w in writes {
                    match w {
                        Write::Put { key, value, lease } => {
                            self.apply_put(*revision, key, value.as_slice().into(), *lease, None)
                        }
                        Write::Delete { key } => self.apply_delete(*revision, key),
                    }
                }
            }
            Entry::Compaction { compact_revision } => {
                let floor = self.raise_floor(*compact_revision);
                self.compact_below(floor);
            }
            Entry::Base {
                revision,
                compact_revision,
                next_lease,
            } => {
                self.revision = self.revision.max(*revision);
                self.raise_floor(*compact_revision);
                self.next_lease = self.next_lease.max(*next_lease);
            }
            Entry::LeaseGrant { id, ttl } => {
                self.lease_ttls.insert(*id, *ttl);
                self.next_lease = self.next_lease.max(id.saturating_add(1));
            }
            Entry::LeaseRevoke { id } => {
                self.lease_ttls.remove(id);
                self.keys_by_lease.remove(id);
            }
            Entry::Revoke { id, revision, keys } => {
                if *revision != 0 {
                    self.revision = self.revision.max(*revision);
                }
                for k in keys {
                    self.apply_delete(*revision, k);
                }
                self.lease_ttls.remove(id);
                self.keys_by_lease.remove(id);
            }
        }
    }

    /// Clamped to the head: a floor above it would make every read "compacted".
    fn raise_floor(&mut self, compact_revision: u64) -> u64 {
        let floor = compact_revision.min(self.revision);
        if floor != compact_revision {
            self.recovery.contradictory_records += 1;
        }
        self.compact_revision = self.compact_revision.max(floor);
        floor
    }

    fn commit(&mut self, entry: &Entry) -> Result<(), StoreError> {
        let after = self.revision.max(entry.consumed_revision().unwrap_or(0));
        let (_, ticket) = self.log.append_published(&entry.encode(), Some(after))?;
        if !self.deferred {
            ticket.wait()?;
        }
        self.apply(entry);
        Ok(())
    }

    /// Commits in `f` apply before they are durable: nothing `f` saw may be revealed
    /// before the returned ticket's `wait` succeeds.
    pub fn deferring<R>(&mut self, f: impl FnOnce(&mut Store) -> R) -> (R, log::Ticket) {
        self.deferred = true;
        let r = f(self);
        self.deferred = false;
        (r, self.log.ticket())
    }

    pub fn ticket(&self) -> log::Ticket {
        self.log.ticket()
    }

    /// `None` when a write of about `bytes` appends without waiting for an fsync, else
    /// the room to wait for with the store unlocked.
    pub fn room_for(&self, bytes: u64) -> Option<log::Room> {
        let frame = bytes + record::HEADER_LEN as u64 + 64;
        (!self.log.has_room(frame)).then(|| self.log.room())
    }

    pub fn durable_revision(&self) -> u64 {
        self.log.durable_revision().min(self.revision)
    }

    pub fn set_on_durable(&self, f: impl Fn(u64) + Send + Sync + 'static) {
        self.log.set_on_durable(Some(std::sync::Arc::new(f)));
    }

    pub fn put(
        &mut self,
        key: &[u8],
        value: &[u8],
        lease: i64,
    ) -> Result<(u64, Option<KeyValue>), StoreError> {
        let prev = self.get(key, 0);
        let revision = self.commit_writes(vec![Write::Put {
            key: key.to_vec(),
            value: value.to_vec(),
            lease,
        }])?;
        Ok((revision, prev))
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(u64, Option<KeyValue>), StoreError> {
        let prev = self.get(key, 0);
        if prev.is_none() {
            return Ok((self.revision, None));
        }
        let revision = self.commit_writes(vec![Write::Delete { key: key.to_vec() }])?;
        Ok((revision, prev))
    }

    fn is_live(&self, key: &[u8]) -> bool {
        self.index
            .get(key)
            .and_then(|v| v.last())
            .is_some_and(|v| v.value.is_some())
    }

    /// A single write stays a plain `Put`/`Delete`, readable by older builds.
    pub fn commit_writes(&mut self, writes: Vec<Write>) -> Result<u64, StoreError> {
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut kept = Vec::with_capacity(writes.len());
        for w in writes {
            match &w {
                Write::Put { key, lease, .. } => {
                    if *lease != 0 && !self.lease_ttls.contains_key(lease) {
                        return Err(StoreError::LeaseNotFound(*lease));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(StoreError::DuplicateKey);
                    }
                }
                Write::Delete { key } => {
                    if !self.is_live(key) {
                        continue;
                    }
                    if !seen.insert(key.clone()) {
                        return Err(StoreError::DuplicateKey);
                    }
                }
            }
            kept.push(w);
        }
        if kept.is_empty() {
            return Ok(self.revision);
        }
        let revision = self.revision + 1;
        let entry = if kept.len() == 1 {
            match kept.pop().unwrap() {
                Write::Put { key, value, lease } => Entry::Put {
                    revision,
                    key,
                    value,
                    lease,
                },
                Write::Delete { key } => Entry::Delete { revision, key },
            }
        } else {
            Entry::Txn {
                revision,
                writes: kept,
            }
        };
        self.commit(&entry)?;
        Ok(revision)
    }

    /// Unchecked against the compaction floor.
    pub fn get(&self, key: &[u8], at_revision: u64) -> Option<KeyValue> {
        let versions = self.index.get(key)?;
        let v = live_at(versions, self.resolve(at_revision))?;
        Some(kv_of(key, v, v.value.as_ref()?))
    }

    pub fn range(&self, start: &[u8], end: &[u8], at_revision: u64) -> Vec<KeyValue> {
        let lo = Bound::Included(start.to_vec());
        let hi = if end.is_empty() {
            Bound::Excluded({
                let mut e = start.to_vec();
                e.push(0);
                e
            })
        } else {
            Bound::Excluded(end.to_vec())
        };
        self.range_bounds(lo, hi, at_revision)
    }

    pub fn range_from(&self, start: &[u8], at_revision: u64) -> Vec<KeyValue> {
        self.range_bounds(
            Bound::Included(start.to_vec()),
            Bound::Unbounded,
            at_revision,
        )
    }

    pub fn range_prefix(&self, prefix: &[u8], at_revision: u64) -> Vec<KeyValue> {
        let lo = Bound::Included(prefix.to_vec());
        let hi = prefix_upper_bound(prefix)
            .map(Bound::Excluded)
            .unwrap_or(Bound::Unbounded);
        self.range_bounds(lo, hi, at_revision)
    }

    fn range_bounds(
        &self,
        lo: Bound<Vec<u8>>,
        hi: Bound<Vec<u8>>,
        at_revision: u64,
    ) -> Vec<KeyValue> {
        let at = self.resolve(at_revision);
        self.index
            .range((lo, hi))
            .filter_map(|(key, versions)| {
                let v = live_at(versions, at)?;
                Some(kv_of(key, v, v.value.as_ref()?))
            })
            .collect()
    }

    pub fn grant_lease(&mut self, id: i64, ttl: i64) -> Result<i64, StoreError> {
        if ttl <= 0 {
            return Err(StoreError::TtlInvalid(ttl));
        }
        if ttl > MAX_LEASE_TTL {
            return Err(StoreError::TtlTooLarge(ttl));
        }
        let id = if id == 0 { self.alloc_lease_id() } else { id };
        if self.lease_ttls.contains_key(&id) {
            return Err(StoreError::LeaseExists(id));
        }
        self.commit(&Entry::LeaseGrant { id, ttl })?;
        Ok(id)
    }

    fn alloc_lease_id(&self) -> i64 {
        let mut id = self.next_lease.max(1);
        while self.lease_ttls.contains_key(&id) {
            id = id.checked_add(1).unwrap_or(1);
        }
        id
    }

    pub fn revoke_lease(&mut self, id: i64) -> Result<u64, StoreError> {
        if !self.lease_ttls.contains_key(&id) {
            return Err(StoreError::LeaseNotFound(id));
        }
        let keys: Vec<Vec<u8>> = self.lease_keys(id);
        let revision = if keys.is_empty() {
            0
        } else {
            self.revision + 1
        };
        self.commit(&Entry::Revoke { id, revision, keys })?;
        Ok(self.revision)
    }

    pub fn lease_keys(&self, id: i64) -> Vec<Vec<u8>> {
        self.keys_by_lease
            .get(&id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn lease_ttl(&self, id: i64) -> Option<i64> {
        self.lease_ttls.get(&id).copied()
    }

    pub fn lease_exists(&self, id: i64) -> bool {
        self.lease_ttls.contains_key(&id)
    }

    pub fn lease_ids(&self) -> Vec<i64> {
        self.lease_ttls.keys().copied().collect()
    }

    pub fn compact(&mut self, revision: u64) -> Result<(), StoreError> {
        if revision > self.revision {
            return Err(StoreError::FutureRevision {
                current: self.revision,
            });
        }
        if revision <= self.compact_revision {
            return Err(StoreError::Compacted {
                floor: self.compact_revision,
            });
        }
        self.commit(&Entry::Compaction {
            compact_revision: revision,
        })
    }

    fn compact_below(&mut self, revision: u64) {
        let mut freed = 0u64;
        self.index.retain(|key, versions| {
            let floor = versions
                .iter()
                .rposition(|v| v.mod_revision <= revision)
                .unwrap_or(0);
            freed += versions
                .drain(..floor)
                .map(|v| encoded_size_estimate(key, &v))
                .sum::<u64>();
            let dead = versions.len() == 1 && versions[0].value.is_none();
            if dead {
                freed += encoded_size_estimate(key, &versions[0]);
            }
            !dead
        });
        self.live_bytes = self.live_bytes.saturating_sub(freed);
        self.changes = self
            .changes
            .split_off(&(revision.saturating_add(1), 0, Vec::new()));
    }

    pub fn events_since(&self, after: u64) -> Result<Vec<Event>, u64> {
        self.events_between(after, u64::MAX)
    }

    pub fn events_between(&self, after: u64, upto: u64) -> Result<Vec<Event>, u64> {
        self.events_matching(after, upto, |_| true)
    }

    /// Only the matching events' values are copied: a watch on one prefix must not pay
    /// for every other key's writes.
    pub fn events_matching(
        &self,
        after: u64,
        upto: u64,
        wanted: impl Fn(&[u8]) -> bool,
    ) -> Result<Vec<Event>, u64> {
        if after < self.compact_revision {
            return Err(self.compact_revision);
        }
        let mut events = Vec::new();
        for (rev, _, key) in self
            .changes
            .range((after.saturating_add(1), 0, Vec::new())..)
            .take_while(|(rev, _, _)| *rev <= upto)
            .filter(|(_, _, key)| wanted(key))
        {
            let Some(versions) = self.index.get(key) else {
                continue;
            };
            let Ok(i) = versions.binary_search_by_key(rev, |v| v.mod_revision) else {
                continue;
            };
            let v = &versions[i];
            let (kind, value, version) = match &v.value {
                Some(value) => (EventKind::Put, value.to_vec(), v.version),
                None => (EventKind::Delete, Vec::new(), 0),
            };
            events.push(Event {
                kind,
                kv: KeyValue {
                    key: key.clone(),
                    value,
                    create_revision: v.create_revision,
                    mod_revision: v.mod_revision,
                    version,
                    lease: v.lease,
                },
            });
        }
        Ok(events)
    }

    pub fn log_len(&self) -> u64 {
        self.log.len()
    }

    pub fn is_failed(&self) -> bool {
        self.log.is_failed()
    }

    #[doc(hidden)]
    pub fn inject_faults(&mut self, faults: std::sync::Arc<std::sync::Mutex<log::fault::Faults>>) {
        self.log
            .wrap_storage(log::fault::FaultyStorage::wrap(faults));
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortOrder {
    #[default]
    None,
    Ascend,
    Descend,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortTarget {
    #[default]
    Key,
    Version,
    Create,
    Mod,
    Value,
}

#[derive(Clone, Debug, Default)]
pub struct RangeQuery {
    pub key: Vec<u8>,
    /// etcd: empty means just `key`, `[0]` every key from `key` on.
    pub range_end: Vec<u8>,
    pub revision: u64,
    pub limit: i64,
    pub sort_order: SortOrder,
    pub sort_target: SortTarget,
    pub keys_only: bool,
    pub count_only: bool,
    pub min_mod_revision: i64,
    pub max_mod_revision: i64,
    pub min_create_revision: i64,
    pub max_create_revision: i64,
}

#[derive(Clone, Debug, Default)]
pub struct RangeOutput {
    pub kvs: Vec<KeyValue>,
    pub count: i64,
    pub more: bool,
    pub revision: u64,
}

impl Store {
    pub fn query(&self, q: &RangeQuery) -> Result<RangeOutput, StoreError> {
        self.query_at(q, self.revision)
    }

    /// The query as of the durable revision, which needs no fsync before it is answered;
    /// `None` when it asks for a newer revision or compaction has passed that one.
    pub fn query_durable(&self, q: &RangeQuery) -> Option<Result<RangeOutput, StoreError>> {
        let head = self.durable_revision();
        if q.revision > head || head < self.compact_revision {
            return None;
        }
        Some(self.query_at(q, head))
    }

    fn query_at(&self, q: &RangeQuery, head: u64) -> Result<RangeOutput, StoreError> {
        if q.revision > head {
            return Err(StoreError::FutureRevision { current: head });
        }
        self.check_revision(q.revision)?;
        let at = if q.revision == 0 { head } else { q.revision };

        let keep = |v: &Version| {
            !((q.min_mod_revision > 0 && (v.mod_revision as i64) < q.min_mod_revision)
                || (q.max_mod_revision > 0 && (v.mod_revision as i64) > q.max_mod_revision)
                || (q.min_create_revision > 0
                    && (v.create_revision as i64) < q.min_create_revision)
                || (q.max_create_revision > 0
                    && (v.create_revision as i64) > q.max_create_revision))
        };

        let mut hits: Vec<(&Vec<u8>, &Version)> = Vec::new();
        if q.range_end.is_empty() {
            if let Some((k, versions)) = self.index.get_key_value(&q.key)
                && let Some(v) = live_at(versions, at)
            {
                hits.push((k, v));
            }
        } else {
            let hi = if q.range_end == [0] {
                Some(Bound::Unbounded)
            } else if q.range_end <= q.key {
                None // BTreeMap::range panics on an inverted range
            } else {
                Some(Bound::Excluded(q.range_end.clone()))
            };
            if let Some(hi) = hi {
                for (k, versions) in self.index.range((Bound::Included(q.key.clone()), hi)) {
                    if let Some(v) = live_at(versions, at) {
                        hits.push((k, v));
                    }
                }
            }
        }
        // As etcd: the count is taken before the revision filters.
        let count = hits.len() as i64;
        hits.retain(|(_, v)| keep(v));

        match (q.sort_target, q.sort_order) {
            (SortTarget::Key, SortOrder::None | SortOrder::Ascend) => {}
            (SortTarget::Key, SortOrder::Descend) => hits.reverse(),
            (target, order) => {
                // Stable, so ties keep key order; `None` sorts ascending, as in etcd.
                let cmp = |a: &(&Vec<u8>, &Version), b: &(&Vec<u8>, &Version)| match target {
                    SortTarget::Version => a.1.version.cmp(&b.1.version),
                    SortTarget::Create => a.1.create_revision.cmp(&b.1.create_revision),
                    SortTarget::Mod => a.1.mod_revision.cmp(&b.1.mod_revision),
                    SortTarget::Value => a.1.value.cmp(&b.1.value),
                    SortTarget::Key => std::cmp::Ordering::Equal,
                };
                if order == SortOrder::Descend {
                    hits.sort_by(|a, b| cmp(b, a));
                } else {
                    hits.sort_by(cmp);
                }
            }
        }

        let mut more = false;
        if q.limit > 0 && hits.len() > q.limit as usize {
            hits.truncate(q.limit as usize);
            more = true;
        }
        let kvs = if q.count_only {
            Vec::new()
        } else {
            hits.into_iter()
                .map(|(k, v)| {
                    let mut kv = kv_of(k, v, v.value.as_ref().unwrap());
                    if q.keys_only {
                        kv.value.clear();
                    }
                    kv
                })
                .collect()
        };
        Ok(RangeOutput {
            kvs,
            count,
            more,
            revision: head,
        })
    }

    /// Independent of the log's layout.
    pub fn state_hash(&self, revision: u64) -> Result<u32, StoreError> {
        self.check_revision(revision)?;
        let at = self.resolve(revision);
        let mut h = crc32fast::Hasher::new();
        for (key, versions) in &self.index {
            if let Some(v) = live_at(versions, at)
                && let Some(value) = &v.value
            {
                h.update(&(key.len() as u32).to_le_bytes());
                h.update(key);
                h.update(&(value.len() as u32).to_le_bytes());
                h.update(value);
                h.update(&v.create_revision.to_le_bytes());
                h.update(&v.mod_revision.to_le_bytes());
                h.update(&v.version.to_le_bytes());
                h.update(&v.lease.to_le_bytes());
            }
        }
        Ok(h.finalize())
    }

    pub fn live_bytes(&self) -> u64 {
        self.live_bytes
    }

    /// Captured together so a rotation replacing the file cannot change what a snapshot
    /// reads.
    pub fn snapshot_source(&self) -> std::io::Result<(std::fs::File, u64, u64)> {
        Ok((
            std::fs::File::open(self.log.path())?,
            self.log.len(),
            self.revision,
        ))
    }

    // Rotation writes the index alone beside the log, then renames it over. Phase 2 runs
    // off the store lock; records appended meanwhile are copied in phase 3.

    pub fn rotation_due(&self) -> bool {
        !self.rotating
            && !self.log.is_failed()
            && self.log.len() >= self.rotate_min_bytes
            && self.log.len() >= self.rotate_garbage_ratio * self.live_bytes.max(1)
    }

    #[doc(hidden)]
    pub fn set_rotation_policy(&mut self, min_bytes: u64, garbage_ratio: u64) {
        self.rotate_min_bytes = min_bytes;
        self.rotate_garbage_ratio = garbage_ratio;
    }

    /// Phase 1, under the store lock.
    pub fn begin_rotation(&mut self) -> Result<RotationPlan, StoreError> {
        if self.rotating {
            return Err(StoreError::Rotation("a rotation is already running".into()));
        }
        if self.log.is_failed() {
            return Err(StoreError::Rotation("the log has failed".into()));
        }
        if self.log.is_readonly() {
            return Err(StoreError::Rotation("the log is read-only".into()));
        }
        self.rotating = true;
        Ok(RotationPlan {
            snapshot: self.index.clone(),
            changes: self.changes.clone(),
            revision: self.revision,
            compact_revision: self.compact_revision,
            leases: self.lease_ttls.iter().map(|(k, v)| (*k, *v)).collect(),
            next_lease: self.next_lease,
            cursor: self.log.len(),
            live_path: self.log.path().to_path_buf(),
        })
    }

    /// Phase 3, under the store lock.
    pub fn finish_rotation(&mut self, rotated: Rotated) -> Result<RotationReport, StoreError> {
        self.finish_rotation_observed(rotated, &mut |_| {})
    }

    #[doc(hidden)]
    pub fn finish_rotation_observed(
        &mut self,
        mut rotated: Rotated,
        hook: &mut dyn FnMut(log::RotationStep),
    ) -> Result<RotationReport, StoreError> {
        let before = self.log.len();
        let staged = (|| -> std::io::Result<()> {
            let len = self.log.len();
            if len > rotated.cursor {
                let delta = self
                    .log
                    .read_committed(rotated.cursor, len - rotated.cursor)?;
                rotated.file.write_raw(&delta)?;
            }
            hook(log::RotationStep::DeltaCopied);
            rotated.file.sync()?;
            hook(log::RotationStep::TempSynced);
            Ok(())
        })();
        if let Err(e) = staged {
            rotated.file.abandon();
            self.rotating = false;
            return Err(StoreError::Rotation(format!(
                "could not stage the new log: {e}"
            )));
        }
        let after = rotated.file.len;
        match self.log.install(rotated.file, hook) {
            Ok(()) => {
                self.rotating = false;
                Ok(RotationReport { before, after })
            }
            Err(e) => {
                self.rotating = false;
                Err(e.into())
            }
        }
    }

    pub fn abort_rotation(&mut self, rotated: Option<Rotated>) {
        if let Some(r) = rotated {
            r.file.abandon();
        }
        self.rotating = false;
    }

    /// All three phases under the caller's lock.
    pub fn rotate(&mut self) -> Result<RotationReport, StoreError> {
        self.rotate_observed(&mut |_| {})
    }

    #[doc(hidden)]
    pub fn rotate_observed(
        &mut self,
        hook: &mut dyn FnMut(log::RotationStep),
    ) -> Result<RotationReport, StoreError> {
        let plan = self.begin_rotation()?;
        match plan.write_observed(hook) {
            Ok(rotated) => self.finish_rotation_observed(rotated, hook),
            Err(e) => {
                self.abort_rotation(None);
                Err(StoreError::Rotation(format!(
                    "could not write the new log: {e}"
                )))
            }
        }
    }
}

pub struct RotationPlan {
    snapshot: BTreeMap<Vec<u8>, Vec<Version>>,
    changes: BTreeSet<Change>,
    revision: u64,
    compact_revision: u64,
    leases: BTreeMap<i64, i64>,
    next_lease: i64,
    cursor: u64,
    live_path: std::path::PathBuf,
}

pub struct Rotated {
    file: log::RotatedLog,
    cursor: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RotationReport {
    pub before: u64,
    pub after: u64,
}

impl RotationPlan {
    /// Phase 2, without the store lock.
    pub fn write(&self) -> std::io::Result<Rotated> {
        self.write_observed(&mut |_| {})
    }

    #[doc(hidden)]
    pub fn write_observed(
        &self,
        hook: &mut dyn FnMut(log::RotationStep),
    ) -> std::io::Result<Rotated> {
        let mut out = log::RotatedLog::create(&self.live_path)?;
        let mut pending: Vec<u8> = Vec::with_capacity(1 << 20);
        let result = (|| -> std::io::Result<()> {
            let mut emit = |e: Entry| -> std::io::Result<()> {
                record::encode(&e.encode(), &mut pending);
                if pending.len() >= 1 << 20 {
                    out.write_raw(&pending)?;
                    pending.clear();
                }
                Ok(())
            };
            emit(Entry::Base {
                revision: self.revision,
                compact_revision: self.compact_revision,
                next_lease: self.next_lease,
            })?;
            for (id, ttl) in &self.leases {
                emit(Entry::LeaseGrant { id: *id, ttl: *ttl })?;
            }
            // In commit and write order, so a replay rebuilds `changes` as it was.
            let position: HashMap<(u64, &[u8]), u32> = self
                .changes
                .iter()
                .map(|(r, p, k)| ((*r, k.as_slice()), *p))
                .collect();
            let mut writes: Vec<(u64, u32, &[u8], &Version, bool)> = Vec::new();
            for (key, versions) in &self.snapshot {
                // The oldest live version carries its derived metadata; a leading
                // tombstone is invisible at or above the floor and is dropped.
                let mut first = true;
                let mut live = false;
                for v in versions {
                    if v.value.is_some() || live {
                        let at = position
                            .get(&(v.mod_revision, key.as_slice()))
                            .copied()
                            .unwrap_or(0);
                        writes.push((v.mod_revision, at, key, v, first && v.value.is_some()));
                    }
                    live = v.value.is_some();
                    first &= !live;
                }
            }
            writes.sort_by_key(|(r, p, k, _, _)| (*r, *p, *k));
            for (_, _, key, v, absolute) in writes {
                emit(match &v.value {
                    Some(value) if absolute => Entry::PutWithMeta {
                        revision: v.mod_revision,
                        key: key.to_vec(),
                        value: value.to_vec(),
                        lease: v.lease,
                        create_revision: v.create_revision,
                        version: v.version,
                    },
                    Some(value) => Entry::Put {
                        revision: v.mod_revision,
                        key: key.to_vec(),
                        value: value.to_vec(),
                        lease: v.lease,
                    },
                    None => Entry::Delete {
                        revision: v.mod_revision,
                        key: key.to_vec(),
                    },
                })?;
            }
            Ok(())
        })();
        let finished = result.and_then(|()| {
            out.write_raw(&pending)?;
            hook(log::RotationStep::TempWritten);
            Ok(())
        });
        match finished {
            Ok(()) => Ok(Rotated {
                file: out,
                cursor: self.cursor,
            }),
            Err(e) => {
                out.abandon();
                Err(e)
            }
        }
    }
}

fn live_at(versions: &[Version], at: u64) -> Option<&Version> {
    versions
        .iter()
        .rev()
        .find(|v| v.mod_revision <= at)
        .filter(|v| v.value.is_some())
}

fn kv_of(key: &[u8], v: &Version, value: &Arc<[u8]>) -> KeyValue {
    KeyValue {
        key: key.to_vec(),
        value: value.to_vec(),
        create_revision: v.create_revision,
        mod_revision: v.mod_revision,
        version: v.version,
        lease: v.lease,
    }
}

fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.last_mut() {
        if *last < 0xff {
            *last += 1;
            return Some(end);
        }
        end.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path().join("s.log")).unwrap();
        (d, s)
    }

    fn keys(kvs: Vec<KeyValue>) -> Vec<Vec<u8>> {
        kvs.into_iter().map(|kv| kv.key).collect()
    }

    fn at(s: &Store, key: &[u8], revision: u64) -> Option<Option<(Vec<u8>, u64)>> {
        let q = RangeQuery {
            key: key.to_vec(),
            revision,
            ..Default::default()
        };
        s.query_durable(&q).map(|r| {
            r.unwrap()
                .kvs
                .first()
                .map(|kv| (kv.value.clone(), kv.mod_revision))
        })
    }

    #[test]
    fn durable_reads_hide_unsynced_writes() {
        let (_d, mut s) = store();
        s.put(b"/k", b"old", 0).unwrap();
        let (r, ticket) = s.deferring(|s| s.put(b"/k", b"new", 0));
        let (rev, _) = r.unwrap();
        assert_eq!(s.durable_revision(), rev - 1);
        assert_eq!(at(&s, b"/k", 0), Some(Some((b"old".to_vec(), rev - 1))));
        let q = RangeQuery {
            key: b"/k".to_vec(),
            ..Default::default()
        };
        assert_eq!(s.query_durable(&q).unwrap().unwrap().revision, rev - 1);
        assert_eq!(at(&s, b"/k", rev), None, "a newer revision must wait");
        ticket.wait().unwrap();
        assert_eq!(at(&s, b"/k", 0), Some(Some((b"new".to_vec(), rev))));
        assert_eq!(at(&s, b"/k", rev), Some(Some((b"new".to_vec(), rev))));
    }

    #[test]
    fn durable_reads_wait_below_the_floor() {
        let (_d, mut s) = store();
        for v in [&b"1"[..], b"2", b"3"] {
            s.put(b"/k", v, 0).unwrap();
        }
        let (r, ticket) = s.deferring(|s| {
            s.put(b"/k", b"4", 0)?;
            s.compact(5)
        });
        r.unwrap();
        assert_eq!((s.durable_revision(), s.compact_revision()), (4, 5));
        assert_eq!(at(&s, b"/k", 0), None);
        ticket.wait().unwrap();
        assert_eq!(at(&s, b"/k", 0), Some(Some((b"4".to_vec(), 5))));
    }

    #[test]
    fn matching_events_skip_other_keys() {
        let (_d, mut s) = store();
        for k in [&b"/a/1"[..], b"/b/1", b"/a/2", b"/b/2"] {
            s.put(k, b"v", 0).unwrap();
        }
        let keys = |evs: Vec<Event>| evs.into_iter().map(|e| e.kv.key).collect::<Vec<_>>();
        assert_eq!(
            keys(s.events_matching(1, 5, |k| k.starts_with(b"/a/")).unwrap()),
            [b"/a/1".to_vec(), b"/a/2".to_vec()]
        );
        assert_eq!(
            keys(s.events_matching(3, 4, |k| k.starts_with(b"/a/")).unwrap()),
            [b"/a/2".to_vec()]
        );
        s.compact(3).unwrap();
        assert_eq!(s.events_matching(1, 5, |_| true).unwrap_err(), 3);
    }

    #[test]
    fn range_bounds_and_0xff_prefixes() {
        let (_d, mut s) = store();
        for k in [
            &b"/a"[..],
            b"/a/1",
            b"/a/2",
            b"/a\xff",
            b"/a\xff\xff",
            b"/b",
            b"\xff",
        ] {
            s.put(k, b"v", 0).unwrap();
        }
        assert_eq!(keys(s.range(b"/a/", b"/a/2", 0)), vec![b"/a/1".to_vec()]);
        assert_eq!(keys(s.range(b"/a", b"", 0)), vec![b"/a".to_vec()]);
        assert_eq!(
            keys(s.range_prefix(b"/a\xff", 0)),
            vec![b"/a\xff".to_vec(), b"/a\xff\xff".to_vec()]
        );
        assert_eq!(keys(s.range_prefix(b"\xff", 0)), vec![b"\xff".to_vec()]);
        assert_eq!(keys(s.range_prefix(b"", 0)).len(), 7);
        assert_eq!(prefix_upper_bound(b"/a\xff"), Some(b"/b".to_vec()));
        assert_eq!(prefix_upper_bound(b"\xff\xff"), None);
    }

    #[test]
    fn live_bytes_estimates_rotation() {
        let (_d, mut s) = store();
        s.put(b"k", b"v", 0).unwrap();
        let one = (record::HEADER_LEN + 1 + 8 + 8 + 4 + 1 + 1) as u64;
        assert_eq!(s.live_bytes(), one);
        s.put(b"k", b"vv", 0).unwrap();
        assert_eq!(s.live_bytes(), 2 * one + 1);
        s.compact(s.revision()).unwrap();
        assert_eq!(s.live_bytes(), one + 1);
        s.delete(b"k").unwrap();
        s.compact(s.revision()).unwrap();
        assert_eq!(s.live_bytes(), 0);
    }

    #[test]
    fn torn_tail_writes_no_note() {
        let (d, s) = store();
        drop(s);
        let p = d.path().join("s.log");
        {
            let mut s = Store::open(&p).unwrap();
            s.put(b"k", b"v", 0).unwrap();
        }
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        std::io::Write::write_all(&mut f, &[9, 0, 0]).unwrap();
        let s = Store::open(&p).unwrap();
        assert_eq!(s.recovery().torn_bytes, 3);
        assert!(!s.recovery().is_notable());
        assert!(!d.path().join("recovery.json").exists());
    }

    #[test]
    fn grant_validates_ttl_and_id() {
        let (_d, mut s) = store();
        let a = s.grant_lease(0, 10).unwrap();
        let b = s.grant_lease(0, MAX_LEASE_TTL).unwrap();
        assert_eq!((a, b), (1, 2));
        assert_eq!(s.grant_lease(1000, 1).unwrap(), 1000);
        assert!(matches!(
            s.grant_lease(1000, 10),
            Err(StoreError::LeaseExists(1000))
        ));
        assert!(matches!(
            s.grant_lease(0, 0),
            Err(StoreError::TtlInvalid(0))
        ));
        assert!(matches!(
            s.grant_lease(0, -1),
            Err(StoreError::TtlInvalid(-1))
        ));
        assert!(matches!(
            s.grant_lease(0, MAX_LEASE_TTL + 1),
            Err(StoreError::TtlTooLarge(_))
        ));
    }
}
