//! The store lock covers validation, append and apply, never an fsync; a call answers
//! once a shared fsync covers everything it saw. The lock tolerates poison because the
//! store never applies before it appends. Watches read only the durable history.

use crate::pb::etcdserverpb::{
    self as pb, cluster_server::Cluster, cluster_server::ClusterServer, kv_server::Kv,
    kv_server::KvServer, lease_server::LeaseServer, maintenance_server::Maintenance,
    maintenance_server::MaintenanceServer, watch_server::WatchServer,
};
use crate::pb::mvccpb;
use crate::store::{
    Event, EventKind, KeyValue, MAX_LEASE_TTL, RangeOutput, RangeQuery, SortOrder, SortTarget,
    Store, StoreError,
};
use crate::txn;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tonic::codegen::http;
use tonic::transport::Server;
use tonic::transport::server::Router;
use tonic::{Request, Response, Status};
use tower::layer::util::{Identity, Stack};
use tower::util::MapResponseLayer;

const ROTATION_POLL: Duration = Duration::from_secs(30);
const HEAVY_WRITES_PER_POLL: u64 = 600;
const ROTATION_OVERDUE_BYTES: u64 = 512 * 1024 * 1024;
const ROTATION_OVERDUE_GARBAGE_RATIO: u64 = 8;
/// etcd's `--max-request-bytes` default.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 1536 * 1024;
/// etcd accepts gRPC messages this much over `--max-request-bytes`.
const GRPC_OVERHEAD_BYTES: usize = 512 * 1024;

/// Field numbers of etcd's InternalRaftRequest.
mod raft_field {
    pub const HEADER: u32 = 100;
    pub const PUT: u32 = 4;
    pub const DELETE_RANGE: u32 = 5;
    pub const TXN: u32 = 6;
    pub const COMPACTION: u32 = 7;
    pub const LEASE_GRANT: u32 = 8;
    pub const LEASE_REVOKE: u32 = 9;
    pub const ALARM: u32 = 10;
}

type GrpcResponse = http::Response<tonic::body::Body>;
pub type GrpcLayer = Stack<MapResponseLayer<fn(GrpcResponse) -> GrpcResponse>, Identity>;

/// grpc-go, so etcd, refuses an oversized message with ResourceExhausted, tonic
/// with OutOfRange.
fn oversize_as_grpc_go(mut response: GrpcResponse) -> GrpcResponse {
    let Some(status) = Status::from_header_map(response.headers()) else {
        return response;
    };
    let sizes = status
        .message()
        .strip_prefix("Error, decoded message length too large: found ")
        .and_then(|m| m.strip_suffix(" bytes"))
        .and_then(|m| m.split_once(" bytes, the limit is: "));
    if status.code() == tonic::Code::OutOfRange
        && let Some((found, limit)) = sizes
    {
        let go = Status::resource_exhausted(format!(
            "grpc: received message larger than max ({found} vs. {limit})"
        ));
        let _ = go.add_header(response.headers_mut());
    }
    response
}

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        tracing::error!("recovered a mutex poisoned by a panic");
        m.clear_poison();
        poisoned.into_inner()
    })
}

pub fn spawn_supervised<F, Fut>(name: &'static str, make: F) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            match tokio::spawn(make()).await {
                Ok(()) => tracing::error!(task = name, "background task returned; restarting it"),
                Err(e) if e.is_panic() => {
                    tracing::error!(task = name, "background task panicked; restarting it")
                }
                Err(_) => return,
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn deadline_after(ttl: i64) -> Instant {
    let now = Instant::now();
    now.checked_add(Duration::from_secs(ttl.clamp(1, MAX_LEASE_TTL) as u64))
        .unwrap_or_else(|| now + Duration::from_secs(365 * 24 * 3600))
}

#[derive(Clone)]
pub struct EtcdServer {
    store: Arc<Mutex<Store>>,
    durable_ticks: broadcast::Sender<u64>,
    /// Lock order: store, then this. Changes that can race a revoke hold the store lock,
    /// so the reaper's re-check is atomic.
    deadlines: Arc<Mutex<HashMap<i64, (Instant, i64)>>>,
    cluster_id: u64,
    member_id: u64,
    member_name: String,
    client_urls: Vec<String>,
    peer_urls: Arc<Mutex<Vec<String>>>,
    progress_interval: Duration,
    on_fatal: Option<Arc<dyn Fn() + Send + Sync>>,
    fatal_fired: Arc<AtomicBool>,
    alarms: Arc<Mutex<std::collections::BTreeSet<(u64, i32)>>>,
    reclaiming: Arc<AtomicBool>,
    max_request_bytes: usize,
}

impl EtcdServer {
    pub fn with_progress_interval(mut self, secs: Option<u64>) -> Self {
        if let Some(s) = secs.filter(|s| *s > 0) {
            self.progress_interval = Duration::from_secs(s);
        }
        self
    }

    pub fn with_max_request_bytes(mut self, bytes: Option<u64>) -> Self {
        if let Some(b) = bytes {
            self.max_request_bytes = usize::try_from(b).unwrap_or(usize::MAX);
        }
        self
    }

    pub fn with_identity(
        mut self,
        name: impl Into<String>,
        client_urls: Vec<String>,
        peer_urls: Vec<String>,
    ) -> Self {
        self.member_name = name.into();
        if !client_urls.is_empty() {
            self.client_urls = client_urls;
        }
        if !peer_urls.is_empty() {
            *lock(&self.peer_urls) = peer_urls;
        }
        self
    }

    pub fn with_fatal_handler(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_fatal = Some(Arc::new(f));
        self
    }

    pub fn new(store: Store) -> Self {
        let (ticks, _) = broadcast::channel(1024);
        let durable = ticks.clone();
        store.set_on_durable(move |rev| {
            let _ = durable.send(rev);
        });
        let deadlines = store
            .lease_ids()
            .into_iter()
            .filter_map(|id| {
                store
                    .lease_ttl(id)
                    .map(|ttl| (id, (deadline_after(ttl), ttl)))
            })
            .collect();
        Self {
            store: Arc::new(Mutex::new(store)),
            durable_ticks: ticks,
            deadlines: Arc::new(Mutex::new(deadlines)),
            cluster_id: 0x1005_7a7e,
            member_id: 0x1005_7a7e_0001,
            member_name: "edge-state".into(),
            client_urls: vec!["https://127.0.0.1:2379".into()],
            peer_urls: Arc::new(Mutex::new(vec!["https://127.0.0.1:2380".into()])),
            progress_interval: Duration::from_secs(5),
            on_fatal: None,
            fatal_fired: Arc::new(AtomicBool::new(false)),
            alarms: Arc::new(Mutex::new(Default::default())),
            reclaiming: Arc::new(AtomicBool::new(false)),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
        }
    }

    pub fn store(&self) -> Arc<Mutex<Store>> {
        self.store.clone()
    }

    pub fn router(self, builder: Server) -> Router<GrpcLayer> {
        let limit = self.max_request_bytes.saturating_add(GRPC_OVERHEAD_BYTES);
        builder
            .layer(MapResponseLayer::new(
                oversize_as_grpc_go as fn(GrpcResponse) -> GrpcResponse,
            ))
            .add_service(KvServer::new(self.clone()).max_decoding_message_size(limit))
            .add_service(WatchServer::new(self.clone()).max_decoding_message_size(limit))
            .add_service(LeaseServer::new(self.clone()).max_decoding_message_size(limit))
            .add_service(ClusterServer::new(self.clone()).max_decoding_message_size(limit))
            .add_service(MaintenanceServer::new(self).max_decoding_message_size(limit))
    }

    /// etcd refuses a request whose raft entry, the request wrapped in an
    /// InternalRaftRequest with a request ID, is over `--max-request-bytes`.
    fn check_request_size(&self, field: u32, request: &impl prost::Message) -> Result<(), Status> {
        use prost::encoding::{encoded_len_varint, key_len, message};
        let header = key_len(1) + encoded_len_varint(self.raft_request_id());
        let entry = key_len(raft_field::HEADER)
            + encoded_len_varint(header as u64)
            + header
            + message::encoded_len(field, request);
        if entry > self.max_request_bytes {
            return Err(Status::invalid_argument("etcdserver: request is too large"));
        }
        Ok(())
    }

    /// The largest ID etcd's generator gives this member: the low 16 bits of the
    /// member ID above a 48-bit timestamp and counter.
    fn raft_request_id(&self) -> u64 {
        ((self.member_id & 0xffff) << 48) | ((1 << 48) - 1)
    }

    async fn blocking<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Store) -> R + Send + 'static,
    ) -> Result<R, Status> {
        match durable_on(&self.store, f).await? {
            Ok(r) => Ok(r),
            Err(e) => {
                let e = StoreError::Log(e);
                self.note_error(&e);
                Err(status_of(&e))
            }
        }
    }

    async fn store_op<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<R, StoreError> + Send + 'static,
    ) -> Result<R, Status> {
        match self.blocking(f).await? {
            Ok(r) => Ok(r),
            Err(e) => {
                self.note_error(&e);
                Err(status_of(&e))
            }
        }
    }

    fn note_error(&self, e: &StoreError) {
        self.note_fatal(e);
        if e.is_disk_full() {
            lock(&self.alarms).insert((self.member_id, pb::AlarmType::Nospace as i32));
            self.kick_reclaim();
        }
    }

    fn kick_reclaim(&self) {
        if self.reclaiming.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let freed = this.blocking(|s| s.reclaim_space()).await.unwrap_or(0);
            if freed > 0 {
                tracing::warn!(
                    freed,
                    "reclaimed disk space after a full-disk write failure"
                );
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
            this.reclaiming.store(false, Ordering::SeqCst);
        });
    }

    pub fn spawn_log_recovery(&self) {
        let this = self.clone();
        spawn_supervised("log recovery", move || {
            let this = this.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let Ok(Ok(recovered)) = this
                        .blocking(|s| {
                            if !s.is_degraded() {
                                return Ok(None);
                            }
                            s.try_recover().map(|ok| ok.then(|| s.revision()))
                        })
                        .await
                    else {
                        continue;
                    };
                    if let Some(rev) = recovered {
                        lock(&this.alarms).clear();
                        this.notify(rev);
                    }
                }
            }
        });
    }

    fn note_fatal(&self, e: &StoreError) {
        if e.is_fatal()
            && let Some(f) = &self.on_fatal
            && !self.fatal_fired.swap(true, Ordering::SeqCst)
        {
            f();
        }
    }

    async fn current_revision(&self) -> Result<u64, Status> {
        self.blocking(|s| s.revision()).await
    }

    pub fn spawn_lease_reaper(&self) {
        let this = self.clone();
        spawn_supervised("lease reaper", move || {
            let this = this.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(500));
                loop {
                    interval.tick().await;
                    this.reap_expired().await;
                }
            }
        });
    }

    pub fn spawn_log_rotation(&self) {
        let this = self.clone();
        spawn_supervised("log rotation", move || {
            let this = this.clone();
            async move {
                // Not at t=0: boot is when the apiserver writes hardest.
                let mut interval = tokio::time::interval_at(
                    tokio::time::Instant::now() + ROTATION_POLL,
                    ROTATION_POLL,
                );
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut last_rev: Option<u64> = None;
                loop {
                    interval.tick().await;
                    let Ok((due, rev, len, live)) = this
                        .blocking(|s| (s.rotation_due(), s.revision(), s.log_len(), s.live_bytes()))
                        .await
                    else {
                        continue;
                    };
                    let busy =
                        last_rev.is_some_and(|p| rev.saturating_sub(p) > HEAVY_WRITES_PER_POLL);
                    last_rev = Some(rev);
                    if !due {
                        continue;
                    }
                    let overdue = len >= ROTATION_OVERDUE_BYTES
                        && len >= ROTATION_OVERDUE_GARBAGE_RATIO * live.max(1);
                    if busy && !overdue {
                        tracing::debug!(
                            log_bytes = len,
                            "log rotation due but writes are heavy; waiting for a quiet interval"
                        );
                        continue;
                    }
                    match this.rotate_in_background().await {
                        Ok(r) => tracing::info!(before = r.before, after = r.after, "log rotated"),
                        Err(e) => {
                            tracing::warn!(error = %e, "log rotation failed; the log is unchanged")
                        }
                    }
                }
            }
        });
    }

    pub async fn rotate_in_background(&self) -> Result<crate::store::RotationReport, Status> {
        let plan = self.store_op(|s| s.begin_rotation()).await?;
        let written = tokio::task::spawn_blocking(move || plan.write()).await;
        match written {
            Ok(Ok(rotated)) => self.store_op(move |s| s.finish_rotation(rotated)).await,
            Ok(Err(e)) => {
                let _ = self.blocking(|s| s.abort_rotation(None)).await;
                Err(Status::internal(format!(
                    "edge-state: could not write the new log: {e}"
                )))
            }
            Err(e) => {
                let _ = self.blocking(|s| s.abort_rotation(None)).await;
                Err(Status::internal(format!(
                    "edge-state: log rotation task failed: {e}"
                )))
            }
        }
    }

    fn expired_ids(&self) -> Vec<i64> {
        let now = Instant::now();
        let d = lock(&self.deadlines);
        d.iter()
            .filter(|(_, (dl, _))| *dl <= now)
            .map(|(id, _)| *id)
            .collect()
    }

    async fn revoke_if_expired(&self, id: i64) -> Result<Result<Option<u64>, StoreError>, Status> {
        let this = self.clone();
        self.blocking(move |s| {
            // A keepalive may have renewed it.
            {
                let d = lock(&this.deadlines);
                match d.get(&id) {
                    Some((dl, _)) if *dl <= Instant::now() => {}
                    _ => return Ok(None),
                }
            }
            let r = s.revoke_lease(id);
            match &r {
                Ok(_) | Err(StoreError::LeaseNotFound(_)) => {
                    lock(&this.deadlines).remove(&id);
                }
                Err(_) => {
                    lock(&this.deadlines).insert(id, (deadline_after(5), 5));
                }
            }
            r.map(Some)
        })
        .await
    }

    pub async fn reap_expired(&self) {
        for id in self.expired_ids() {
            match self.revoke_if_expired(id).await {
                Ok(Ok(Some(_))) => {
                    tracing::debug!(lease = id, "lease expired; keys revoked");
                }
                Ok(Ok(None)) => {}
                Ok(Err(StoreError::LeaseNotFound(_))) => {}
                Ok(Err(e)) => {
                    self.note_fatal(&e);
                    tracing::warn!(lease = id, error = %e, "could not revoke an expired lease; will retry");
                }
                Err(e) => tracing::error!(lease = id, error = %e, "lease revoke task failed"),
            }
        }
    }

    fn set_deadline(&self, id: i64, ttl: i64) {
        lock(&self.deadlines).insert(id, (deadline_after(ttl), ttl));
    }

    fn clear_deadline(&self, id: i64) {
        lock(&self.deadlines).remove(&id);
    }

    fn remaining_ttl_secs(&self, id: i64) -> i64 {
        lock(&self.deadlines)
            .get(&id)
            .map(|(dl, _)| dl.saturating_duration_since(Instant::now()).as_secs() as i64)
            .unwrap_or(-1)
    }

    fn notify(&self, revision: u64) {
        let _ = self.durable_ticks.send(revision);
    }

    fn member(&self) -> pb::Member {
        pb::Member {
            id: self.member_id,
            name: self.member_name.clone(),
            peer_ur_ls: lock(&self.peer_urls).clone(),
            client_ur_ls: self.client_urls.clone(),
            is_learner: false,
        }
    }

    fn header(&self, revision: u64) -> Option<pb::ResponseHeader> {
        Some(pb::ResponseHeader {
            cluster_id: self.cluster_id,
            member_id: self.member_id,
            revision: revision as i64,
            raft_term: 1,
        })
    }
}

async fn durable_on<R: Send + 'static>(
    store: &Arc<Mutex<Store>>,
    f: impl FnOnce(&mut Store) -> R + Send + 'static,
) -> Result<Result<R, crate::log::LogError>, Status> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        let (r, ticket) = lock(&store).deferring(f);
        ticket.wait().map(|()| r)
    })
    .await
    .map_err(|e| Status::internal(format!("store task failed: {e}")))
}

async fn locked_on<R: Send + 'static>(
    store: &Arc<Mutex<Store>>,
    f: impl FnOnce(&Store) -> R + Send + 'static,
) -> Result<R, Status> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || f(&lock(&store)))
        .await
        .map_err(|e| Status::internal(format!("store task failed: {e}")))
}

/// A compaction is applied before it is durable; wait before telling a watch of it.
async fn wait_durable(ticket: crate::log::Ticket) {
    let _ = tokio::task::spawn_blocking(move || ticket.wait()).await;
}

/// The apiserver acts on the codes: OutOfRange is its 410/"too large resource
/// version", and InvalidArgument is never retried.
fn status_of(e: &StoreError) -> Status {
    match e {
        StoreError::Compacted { .. } => {
            Status::out_of_range("etcdserver: mvcc: required revision has been compacted")
        }
        StoreError::FutureRevision { .. } => {
            Status::out_of_range("etcdserver: mvcc: required revision is a future revision")
        }
        StoreError::LeaseNotFound(_) => Status::not_found("etcdserver: requested lease not found"),
        StoreError::LeaseExists(_) => {
            Status::failed_precondition("etcdserver: lease already exists")
        }
        StoreError::TtlInvalid(_) => {
            Status::invalid_argument("etcdserver: lease TTL must be positive")
        }
        StoreError::TtlTooLarge(_) => Status::out_of_range("etcdserver: too large lease TTL"),
        StoreError::DuplicateKey => {
            Status::invalid_argument("etcdserver: duplicate key given in txn request")
        }
        StoreError::TooManyOps => {
            Status::invalid_argument("etcdserver: too many operations in txn request")
        }
        StoreError::Unsupported(what) => Status::unimplemented(format!("edge-state: {what}")),
        StoreError::Invalid(what) => Status::invalid_argument(format!("etcdserver: {what}")),
        StoreError::Rotation(what) => {
            Status::failed_precondition(format!("edge-state: log rotation: {what}"))
        }
        StoreError::Log(l) if l.is_disk_full() => {
            Status::resource_exhausted("etcdserver: mvcc: database space exceeded")
        }
        StoreError::Log(crate::log::LogError::Degraded(d)) => Status::unavailable(format!(
            "etcdserver: log cannot be written ({}); serving reads and retrying",
            d.reason
        )),
        StoreError::Log(l) if l.is_fatal() => {
            Status::unavailable(format!("etcdserver: log failed; restarting: {l}"))
        }
        StoreError::Log(l) => Status::internal(format!("etcdserver: {l}")),
    }
}

fn to_pb(kv: KeyValue) -> mvccpb::KeyValue {
    mvccpb::KeyValue {
        key: kv.key,
        create_revision: kv.create_revision as i64,
        mod_revision: kv.mod_revision as i64,
        version: kv.version,
        value: kv.value,
        lease: kv.lease,
    }
}

fn to_query(r: &pb::RangeRequest) -> RangeQuery {
    use pb::range_request::{SortOrder as O, SortTarget as T};
    RangeQuery {
        key: r.key.clone(),
        range_end: r.range_end.clone(),
        revision: r.revision.max(0) as u64,
        limit: r.limit,
        sort_order: match O::try_from(r.sort_order).unwrap_or(O::None) {
            O::None => SortOrder::None,
            O::Ascend => SortOrder::Ascend,
            O::Descend => SortOrder::Descend,
        },
        sort_target: match T::try_from(r.sort_target).unwrap_or(T::Key) {
            T::Key => SortTarget::Key,
            T::Version => SortTarget::Version,
            T::Create => SortTarget::Create,
            T::Mod => SortTarget::Mod,
            T::Value => SortTarget::Value,
        },
        keys_only: r.keys_only,
        count_only: r.count_only,
        min_mod_revision: r.min_mod_revision,
        max_mod_revision: r.max_mod_revision,
        min_create_revision: r.min_create_revision,
        max_create_revision: r.max_create_revision,
    }
}

/// etcd's first RangeStream chunk, in keys; later chunks double.
const STREAM_FIRST_CHUNK: usize = 10;

/// etcd puts the header, `more` and `count` on the last chunk only.
fn stream_chunks(resp: pb::RangeResponse) -> Vec<pb::RangeStreamResponse> {
    let pb::RangeResponse {
        header,
        kvs,
        more,
        count,
    } = resp;
    let mut kvs = kvs.into_iter().peekable();
    let mut chunks = Vec::new();
    let mut limit = STREAM_FIRST_CHUNK;
    loop {
        let chunk: Vec<_> = kvs.by_ref().take(limit).collect();
        limit = limit.saturating_mul(2);
        let done = kvs.peek().is_none();
        chunks.push(pb::RangeResponse {
            kvs: chunk,
            ..Default::default()
        });
        if done {
            break;
        }
    }
    if let Some(last) = chunks.last_mut() {
        last.header = header;
        last.more = more;
        last.count = count;
    }
    chunks
        .into_iter()
        .map(|c| pb::RangeStreamResponse {
            range_response: Some(c),
        })
        .collect()
}

fn range_response(out: RangeOutput) -> pb::RangeResponse {
    pb::RangeResponse {
        header: None,
        kvs: out.kvs.into_iter().map(to_pb).collect(),
        more: out.more,
        count: out.count,
    }
}

#[tonic::async_trait]
impl Kv for EtcdServer {
    type RangeStreamStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<pb::RangeStreamResponse, Status>>>;

    async fn range_stream(
        &self,
        req: Request<pb::RangeRequest>,
    ) -> Result<Response<Self::RangeStreamStream>, Status> {
        use pb::range_request::{SortOrder as O, SortTarget as T};
        let r = req.into_inner();
        let default_order = r.sort_order == O::None as i32
            || (r.sort_target == T::Key as i32 && r.sort_order == O::Ascend as i32);
        if !default_order {
            return Err(Status::unimplemented(
                "etcdserver: RangeStream does not support custom sort orders",
            ));
        }
        if r.min_mod_revision != 0
            || r.max_mod_revision != 0
            || r.min_create_revision != 0
            || r.max_create_revision != 0
        {
            return Err(Status::unimplemented(
                "etcdserver: RangeStream does not support revision filters",
            ));
        }
        let q = to_query(&r);
        let out = self.store_op(move |store| store.query(&q)).await?;
        let revision = out.revision;
        let mut resp = range_response(out);
        resp.header = self.header(revision);
        let chunks = stream_chunks(resp).into_iter().map(Ok).collect::<Vec<_>>();
        Ok(Response::new(tokio_stream::iter(chunks)))
    }

    async fn range(
        &self,
        req: Request<pb::RangeRequest>,
    ) -> Result<Response<pb::RangeResponse>, Status> {
        let q = to_query(&req.into_inner());
        let out = self.store_op(move |store| store.query(&q)).await?;
        let revision = out.revision;
        let mut resp = range_response(out);
        resp.header = self.header(revision);
        Ok(Response::new(resp))
    }

    async fn put(&self, req: Request<pb::PutRequest>) -> Result<Response<pb::PutResponse>, Status> {
        let r = req.into_inner();
        self.check_request_size(raft_field::PUT, &r)?;
        refuse_ignore_flags(&r)?;
        let want_prev = r.prev_kv;
        let (rev, prev) = self
            .store_op(move |store| {
                let (_rev, prev) = store.put(&r.key, &r.value, r.lease)?;
                Ok((store.revision(), prev))
            })
            .await?;
        Ok(Response::new(pb::PutResponse {
            header: self.header(rev),
            prev_kv: if want_prev { prev.map(to_pb) } else { None },
        }))
    }

    async fn delete_range(
        &self,
        req: Request<pb::DeleteRangeRequest>,
    ) -> Result<Response<pb::DeleteRangeResponse>, Status> {
        let r = req.into_inner();
        self.check_request_size(raft_field::DELETE_RANGE, &r)?;
        let want_prev = r.prev_kv;
        let res = self
            .store_op(move |store| {
                txn::run(
                    store,
                    &[],
                    &[txn::Op::Delete {
                        key: r.key,
                        range_end: r.range_end,
                        prev_kv: want_prev,
                    }],
                    &[],
                )
            })
            .await?;
        let (deleted, prev_kvs) = match res.results.into_iter().next() {
            Some(txn::OpResult::Delete { deleted, prev }) => {
                (deleted, prev.into_iter().map(to_pb).collect())
            }
            _ => (0, Vec::new()),
        };
        Ok(Response::new(pb::DeleteRangeResponse {
            header: self.header(res.revision),
            deleted,
            prev_kvs,
        }))
    }

    async fn txn(&self, req: Request<pb::TxnRequest>) -> Result<Response<pb::TxnResponse>, Status> {
        let r = req.into_inner();
        let compares = r
            .compare
            .iter()
            .map(map_compare)
            .collect::<Result<Vec<_>, _>>()?;
        let success = r
            .success
            .iter()
            .map(map_op)
            .collect::<Result<Vec<_>, _>>()?;
        let failure = r
            .failure
            .iter()
            .map(map_op)
            .collect::<Result<Vec<_>, _>>()?;
        if !is_read_only(&r) {
            self.check_request_size(raft_field::TXN, &r)?;
        }
        let result = self
            .store_op(move |store| txn::run(store, &compares, &success, &failure))
            .await?;
        let rev = result.revision;
        let responses = result
            .results
            .into_iter()
            .map(|r| pb::ResponseOp {
                response: Some(map_op_result(r, self.header(rev))),
            })
            .collect();
        Ok(Response::new(pb::TxnResponse {
            header: self.header(rev),
            succeeded: result.succeeded,
            responses,
        }))
    }

    async fn compact(
        &self,
        req: Request<pb::CompactionRequest>,
    ) -> Result<Response<pb::CompactionResponse>, Status> {
        let r = req.into_inner();
        self.check_request_size(raft_field::COMPACTION, &r)?;
        let rev = self
            .store_op(move |store| {
                store.compact(r.revision.max(0) as u64)?;
                Ok(store.revision())
            })
            .await?;
        Ok(Response::new(pb::CompactionResponse {
            header: self.header(rev),
        }))
    }
}

fn map_compare(c: &pb::Compare) -> Result<txn::Compare, Status> {
    use pb::compare::{CompareResult, TargetUnion};
    let op = match CompareResult::try_from(c.result).unwrap_or(CompareResult::Equal) {
        CompareResult::Equal => txn::CmpOp::Equal,
        CompareResult::NotEqual => txn::CmpOp::NotEqual,
        CompareResult::Greater => txn::CmpOp::Greater,
        CompareResult::Less => txn::CmpOp::Less,
    };
    let target = match c.target_union.as_ref() {
        Some(TargetUnion::ModRevision(v)) => txn::Target::Mod(*v),
        Some(TargetUnion::CreateRevision(v)) => txn::Target::Create(*v),
        Some(TargetUnion::Version(v)) => txn::Target::Version(*v),
        Some(TargetUnion::Value(v)) => txn::Target::Value(v.clone()),
        Some(TargetUnion::Lease(v)) => txn::Target::Lease(*v),
        None => return Err(Status::invalid_argument("compare with no target")),
    };
    Ok(txn::Compare {
        key: c.key.clone(),
        range_end: c.range_end.clone(),
        op,
        target,
    })
}

/// etcd serves a txn of only reads without raft, so without a size check.
fn is_read_only(t: &pb::TxnRequest) -> bool {
    use pb::request_op::Request as R;
    t.success
        .iter()
        .chain(&t.failure)
        .all(|op| matches!(op.request, Some(R::RequestRange(_))))
}

fn refuse_ignore_flags(p: &pb::PutRequest) -> Result<(), Status> {
    if p.ignore_value || p.ignore_lease {
        return Err(Status::unimplemented(
            "edge-state: put with ignore_value / ignore_lease",
        ));
    }
    Ok(())
}

fn map_op(op: &pb::RequestOp) -> Result<txn::Op, Status> {
    use pb::request_op::Request as R;
    match op.request.as_ref() {
        Some(R::RequestPut(p)) => {
            refuse_ignore_flags(p)?;
            Ok(txn::Op::Put {
                key: p.key.clone(),
                value: p.value.clone(),
                lease: p.lease,
                prev_kv: p.prev_kv,
            })
        }
        Some(R::RequestDeleteRange(d)) => Ok(txn::Op::Delete {
            key: d.key.clone(),
            range_end: d.range_end.clone(),
            prev_kv: d.prev_kv,
        }),
        Some(R::RequestRange(g)) => Ok(txn::Op::Range(to_query(g))),
        Some(R::RequestTxn(_)) => Err(Status::unimplemented("edge-state: nested txn")),
        None => Err(Status::invalid_argument("empty txn op")),
    }
}

fn map_op_result(
    r: txn::OpResult,
    header: Option<pb::ResponseHeader>,
) -> pb::response_op::Response {
    use pb::response_op::Response as R;
    match r {
        txn::OpResult::Put { prev } => R::ResponsePut(pb::PutResponse {
            header,
            prev_kv: prev.map(to_pb),
        }),
        txn::OpResult::Delete { deleted, prev } => {
            R::ResponseDeleteRange(pb::DeleteRangeResponse {
                header,
                deleted,
                prev_kvs: prev.into_iter().map(to_pb).collect(),
            })
        }
        txn::OpResult::Range(out) => {
            let mut resp = range_response(out);
            resp.header = header;
            R::ResponseRange(resp)
        }
    }
}

const SNAPSHOT_CHUNK: usize = 64 * 1024;

#[tonic::async_trait]
impl Maintenance for EtcdServer {
    async fn status(
        &self,
        _req: Request<pb::StatusRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        let (rev, len, live) = self
            .blocking(|s| (s.revision(), s.log_len(), s.live_bytes()))
            .await?;
        let errors = lock(&self.alarms)
            .iter()
            .map(|(member, kind)| {
                format!(
                    "memberID:{member} alarm:{}",
                    pb::AlarmType::try_from(*kind).map_or("UNKNOWN", |k| k.as_str_name())
                )
            })
            .collect();
        Ok(Response::new(pb::StatusResponse {
            header: self.header(rev),
            version: "3.5.16-edge".into(),
            db_size: len as i64,
            leader: self.member_id,
            raft_index: rev,
            raft_term: 1,
            raft_applied_index: rev,
            errors,
            db_size_in_use: live.min(len) as i64,
            is_learner: false,
        }))
    }

    /// Unlike etcd, NOSPACE does not refuse writes: a failed append rolls back.
    async fn alarm(
        &self,
        req: Request<pb::AlarmRequest>,
    ) -> Result<Response<pb::AlarmResponse>, Status> {
        use pb::alarm_request::AlarmAction;
        let r = req.into_inner();
        self.check_request_size(raft_field::ALARM, &r)?;
        let member = if r.member_id == 0 {
            self.member_id
        } else {
            r.member_id
        };
        let alarms: Vec<pb::AlarmMember> = {
            let mut set = lock(&self.alarms);
            match AlarmAction::try_from(r.action).unwrap_or(AlarmAction::Get) {
                AlarmAction::Get => set
                    .iter()
                    .filter(|(m, k)| {
                        (r.member_id == 0 || *m == r.member_id) && (r.alarm == 0 || *k == r.alarm)
                    })
                    .map(|(m, k)| pb::AlarmMember {
                        member_id: *m,
                        alarm: *k,
                    })
                    .collect(),
                AlarmAction::Activate => {
                    if r.alarm == 0 {
                        return Err(Status::invalid_argument(
                            "etcdserver: alarm type NONE cannot be activated",
                        ));
                    }
                    set.insert((member, r.alarm));
                    vec![pb::AlarmMember {
                        member_id: member,
                        alarm: r.alarm,
                    }]
                }
                AlarmAction::Deactivate => {
                    let gone: Vec<_> = set
                        .iter()
                        .filter(|(m, k)| *m == member && (r.alarm == 0 || *k == r.alarm))
                        .copied()
                        .collect();
                    for a in &gone {
                        set.remove(a);
                    }
                    gone.into_iter()
                        .map(|(m, k)| pb::AlarmMember {
                            member_id: m,
                            alarm: k,
                        })
                        .collect()
                }
            }
        };
        let rev = self.current_revision().await?;
        Ok(Response::new(pb::AlarmResponse {
            header: self.header(rev),
            alarms,
        }))
    }

    async fn defragment(
        &self,
        _req: Request<pb::DefragmentRequest>,
    ) -> Result<Response<pb::DefragmentResponse>, Status> {
        let report = self.rotate_in_background().await?;
        tracing::info!(
            before = report.before,
            after = report.after,
            "defragment: log rotated"
        );
        let rev = self.current_revision().await?;
        Ok(Response::new(pb::DefragmentResponse {
            header: self.header(rev),
        }))
    }

    async fn hash(
        &self,
        _req: Request<pb::HashRequest>,
    ) -> Result<Response<pb::HashResponse>, Status> {
        let (rev, hash) = self
            .store_op(|s| Ok((s.revision(), s.state_hash(0)?)))
            .await?;
        Ok(Response::new(pb::HashResponse {
            header: self.header(rev),
            hash,
        }))
    }

    async fn hash_kv(
        &self,
        req: Request<pb::HashKvRequest>,
    ) -> Result<Response<pb::HashKvResponse>, Status> {
        let at = req.into_inner().revision.max(0) as u64;
        let (rev, floor, hash) = self
            .store_op(move |s| Ok((s.revision(), s.compact_revision(), s.state_hash(at)?)))
            .await?;
        Ok(Response::new(pb::HashKvResponse {
            header: self.header(rev),
            hash,
            compact_revision: floor as i64,
        }))
    }

    type SnapshotStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::SnapshotResponse, Status>>;

    /// Not etcd's bbolt format: the log's committed prefix.
    async fn snapshot(
        &self,
        _req: Request<pb::SnapshotRequest>,
    ) -> Result<Response<Self::SnapshotStream>, Status> {
        let (file, len, rev) = self
            .blocking(|s| s.snapshot_source())
            .await?
            .map_err(|e| Status::internal(format!("cannot open the log for a snapshot: {e}")))?;
        let header = self.header(rev);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::FileExt;
            let mut off = 0u64;
            loop {
                let n = ((len - off) as usize).min(SNAPSHOT_CHUNK);
                let mut blob = vec![0u8; n];
                if let Err(e) = file.read_exact_at(&mut blob, off) {
                    let _ = tx
                        .blocking_send(Err(Status::internal(format!("snapshot read failed: {e}"))));
                    return;
                }
                off += n as u64;
                let msg = pb::SnapshotResponse {
                    header,
                    remaining_bytes: len - off,
                    blob,
                };
                if tx.blocking_send(Ok(msg)).is_err() || off >= len {
                    return;
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn move_leader(
        &self,
        _req: Request<pb::MoveLeaderRequest>,
    ) -> Result<Response<pb::MoveLeaderResponse>, Status> {
        let rev = self.current_revision().await?;
        Ok(Response::new(pb::MoveLeaderResponse {
            header: self.header(rev),
        }))
    }

    async fn downgrade(
        &self,
        _req: Request<pb::DowngradeRequest>,
    ) -> Result<Response<pb::DowngradeResponse>, Status> {
        Err(Status::unimplemented("downgrade"))
    }
}

fn in_range(key: &[u8], key0: &[u8], range_end: &[u8]) -> bool {
    if range_end.is_empty() {
        key == key0
    } else if range_end == [0] {
        key >= key0
    } else {
        key >= key0 && key < range_end
    }
}

fn event_to_pb(store: &Store, e: &Event, prev_kv: bool) -> mvccpb::Event {
    let prev =
        e.kv.mod_revision
            .checked_sub(1)
            .filter(|_| prev_kv)
            .and_then(|r| store.get(&e.kv.key, r))
            .map(to_pb);
    mvccpb::Event {
        r#type: match e.kind {
            EventKind::Put => mvccpb::event::EventType::Put as i32,
            EventKind::Delete => mvccpb::event::EventType::Delete as i32,
        },
        kv: Some(to_pb(e.kv.clone())),
        prev_kv: prev,
    }
}

struct Watch {
    id: i64,
    key: Vec<u8>,
    range_end: Vec<u8>,
    /// Everything up to here has been delivered or is not owed.
    cursor: u64,
    progress_notify: bool,
    prev_kv: bool,
    start_revision: u64,
}

/// What `collect_owed` needs of a watch: id, key, range end, cursor, prev_kv.
type WatchView = (i64, Vec<u8>, Vec<u8>, u64, bool);

enum Owed {
    Nothing,
    Events(Vec<mvccpb::Event>),
    Compacted(u64),
}

/// The durable revision and every watch's owed events up to it, from one critical
/// section: a cursor advanced to any other revision would repeat or skip events.
fn collect_owed(store: &Store, watches: &[WatchView]) -> (u64, Vec<(i64, Owed)>) {
    let rev = store.durable_revision();
    let mut out = Vec::new();
    for (id, key, range_end, cursor, prev_kv) in watches {
        if *cursor >= rev {
            continue;
        }
        out.push((
            *id,
            match store.events_between(*cursor, rev) {
                Err(floor) => Owed::Compacted(floor),
                Ok(events) => {
                    let evs: Vec<_> = events
                        .iter()
                        .filter(|e| in_range(&e.kv.key, key, range_end))
                        .map(|e| event_to_pb(store, e, *prev_kv))
                        .collect();
                    if evs.is_empty() {
                        Owed::Nothing
                    } else {
                        Owed::Events(evs)
                    }
                }
            },
        ));
    }
    (rev, out)
}

fn watch_response(cluster_id: u64, member_id: u64, rev: u64, watch_id: i64) -> pb::WatchResponse {
    pb::WatchResponse {
        header: Some(pb::ResponseHeader {
            cluster_id,
            member_id,
            revision: rev as i64,
            raft_term: 1,
        }),
        watch_id,
        created: false,
        canceled: false,
        compact_revision: 0,
        cancel_reason: String::new(),
        fragment: false,
        events: Vec::new(),
    }
}

fn compacted_cancel(ids: (u64, u64), rev: u64, watch_id: i64, floor: u64) -> pb::WatchResponse {
    let mut resp = watch_response(ids.0, ids.1, rev, watch_id);
    resp.canceled = true;
    resp.compact_revision = floor as i64;
    resp.cancel_reason = COMPACTED.into();
    resp
}

const COMPACTED: &str = "etcdserver: mvcc: required revision has been compacted";

/// For a new watch: (durable revision, its cursor, its catch-up events or the floor).
fn start_watch(
    s: &Store,
    start_revision: i64,
    key: &[u8],
    range_end: &[u8],
    prev_kv: bool,
) -> (u64, u64, Result<Vec<mvccpb::Event>, u64>) {
    let cur = s.durable_revision();
    if start_revision == 0 {
        return (cur, cur, Ok(Vec::new()));
    }
    let after = (start_revision as u64).saturating_sub(1);
    match s.events_between(after, cur) {
        Err(floor) => (cur, after, Err(floor)),
        Ok(events) => (
            cur,
            cur.max(after),
            Ok(events
                .iter()
                .filter(|e| in_range(&e.kv.key, key, range_end))
                .map(|e| event_to_pb(s, e, prev_kv))
                .collect()),
        ),
    }
}

use crate::pb::etcdserverpb::watch_server::Watch as WatchSvc;

type WatchTx = tokio::sync::mpsc::Sender<Result<pb::WatchResponse, Status>>;

/// The revision the cursors advanced to, or `None` if the client has gone.
async fn deliver_owed(
    store: &Arc<Mutex<Store>>,
    watches: &mut Vec<Watch>,
    tx: &WatchTx,
    ids: (u64, u64),
) -> Option<u64> {
    let snapshot: Vec<_> = watches
        .iter()
        .map(|w| {
            (
                w.id,
                w.key.clone(),
                w.range_end.clone(),
                w.cursor,
                w.prev_kv,
            )
        })
        .collect();
    let (rev, owed, ticket) = match locked_on(store, move |s| {
        let (rev, owed) = collect_owed(s, &snapshot);
        (rev, owed, s.ticket())
    })
    .await
    {
        Ok(x) => x,
        Err(_) => return Some(watches.iter().map(|w| w.cursor).max().unwrap_or(0)),
    };
    if owed.iter().any(|(_, o)| matches!(o, Owed::Compacted(_))) {
        wait_durable(ticket).await;
    }
    let mut pending: Vec<(i64, mvccpb::Event)> = Vec::new();
    for (id, what) in owed {
        match what {
            Owed::Nothing => {}
            Owed::Events(events) => pending.extend(events.into_iter().map(|e| (id, e))),
            Owed::Compacted(floor) => {
                tx.send(Ok(compacted_cancel(ids, rev, id, floor)))
                    .await
                    .ok()?;
                watches.retain(|w| w.id != id);
                continue;
            }
        }
        if let Some(w) = watches.iter_mut().find(|w| w.id == id) {
            w.cursor = w.cursor.max(rev);
        }
    }
    // Commit order across watches, as etcd sends it; consecutive events for one watch
    // share a response.
    pending.sort_by_key(|(id, e)| (e.kv.as_ref().map_or(0, |kv| kv.mod_revision), *id));
    let mut run: Option<(i64, Vec<mvccpb::Event>)> = None;
    for (id, event) in pending {
        match run.as_mut() {
            Some((rid, evs)) if *rid == id => evs.push(event),
            _ => {
                if let Some((rid, evs)) = run.take() {
                    let mut resp = watch_response(ids.0, ids.1, rev, rid);
                    resp.events = evs;
                    tx.send(Ok(resp)).await.ok()?;
                }
                run = Some((id, vec![event]));
            }
        }
    }
    if let Some((rid, evs)) = run {
        let mut resp = watch_response(ids.0, ids.1, rev, rid);
        resp.events = evs;
        tx.send(Ok(resp)).await.ok()?;
    }
    Some(rev)
}

#[tonic::async_trait]
impl WatchSvc for EtcdServer {
    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<pb::WatchResponse, Status>>;

    async fn watch(
        &self,
        req: Request<tonic::Streaming<pb::WatchRequest>>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let mut requests = req.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let store = self.store.clone();
        let mut ticks = self.durable_ticks.subscribe();
        let ids = (self.cluster_id, self.member_id);
        let progress_interval = self.progress_interval;

        tokio::spawn(async move {
            let mut watches: Vec<Watch> = Vec::new();
            let mut next_id: i64 = 1;
            let header_only = |rev: u64, id: i64| watch_response(ids.0, ids.1, rev, id);
            let mut progress = tokio::time::interval(progress_interval);
            progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    msg = requests.message() => {
                        let Ok(Some(req)) = msg else { break };
                        match req.request_union {
                            Some(pb::watch_request::RequestUnion::CreateRequest(c)) if c.start_revision < 0 => {
                                let rev = locked_on(&store, |s| s.durable_revision()).await.unwrap_or(0);
                                let mut refused = header_only(rev, -1);
                                refused.created = true;
                                refused.canceled = true;
                                refused.cancel_reason = COMPACTED.into();
                                if tx.send(Ok(refused)).await.is_err() { break; }
                            }
                            Some(pb::watch_request::RequestUnion::CreateRequest(c)) => {
                                let start_revision = c.start_revision;
                                let (key, range_end) = (c.key.clone(), c.range_end.clone());
                                let prev_kv = c.prev_kv;
                                let created = locked_on(&store, move |s| (start_watch(s, start_revision, &key, &range_end, prev_kv), s.ticket())).await;
                                let Ok(((current, cursor, catch_up), ticket)) = created else { break };
                                if catch_up.is_err() { wait_durable(ticket).await; }
                                let id = if c.watch_id != 0 {
                                    c.watch_id
                                } else {
                                    while watches.iter().any(|w| w.id == next_id) { next_id += 1; }
                                    let i = next_id;
                                    next_id += 1;
                                    i
                                };
                                let mut created = header_only(current, id);
                                created.created = true;
                                if watches.iter().any(|w| w.id == id) {
                                    created.canceled = true;
                                    created.cancel_reason = "etcdserver: watcher with this ID already exists".into();
                                    if tx.send(Ok(created)).await.is_err() { break; }
                                    continue;
                                }
                                if tx.send(Ok(created)).await.is_err() { break; }
                                match catch_up {
                                    Err(floor) => {
                                        if tx.send(Ok(compacted_cancel(ids, current, id, floor))).await.is_err() { break; }
                                    }
                                    Ok(evs) => {
                                        if !evs.is_empty() {
                                            let mut resp = header_only(current, id);
                                            resp.events = evs;
                                            if tx.send(Ok(resp)).await.is_err() { break; }
                                        }
                                        watches.push(Watch { id, key: c.key, range_end: c.range_end, cursor, progress_notify: c.progress_notify, prev_kv, start_revision: start_revision as u64 });
                                    }
                                }
                            }
                            Some(pb::watch_request::RequestUnion::CancelRequest(c)) => {
                                watches.retain(|w| w.id != c.watch_id);
                                let rev = locked_on(&store, |s| s.durable_revision()).await.unwrap_or(0);
                                let mut resp = header_only(rev, c.watch_id);
                                resp.canceled = true;
                                if tx.send(Ok(resp)).await.is_err() { break; }
                            }
                            Some(pb::watch_request::RequestUnion::ProgressRequest(_)) => {
                                // It claims everything up to `rev`, so deliver what is owed first.
                                let Some(rev) = deliver_owed(&store, &mut watches, &tx, ids).await else { break };
                                if watches.iter().any(|w| rev < w.start_revision) { continue; }
                                if tx.send(Ok(header_only(rev, -1))).await.is_err() { break; }
                            }
                            _ => {}
                        }
                    }
                    _ = progress.tick() => {
                        let Some(rev) = deliver_owed(&store, &mut watches, &tx, ids).await else { break };
                        for w in watches.iter().filter(|w| w.progress_notify) {
                            if w.cursor < rev || rev < w.start_revision { continue; }
                            if tx.send(Ok(header_only(rev, w.id))).await.is_err() { return; }
                        }
                    }
                    // `collect_owed` reads the durable revision itself, so lagging is fine.
                    tick = ticks.recv() => {
                        match tick {
                            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                        if deliver_owed(&store, &mut watches, &tx, ids).await.is_none() { break; }
                    }
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

use crate::pb::etcdserverpb::lease_server::Lease as LeaseSvc;

#[tonic::async_trait]
impl LeaseSvc for EtcdServer {
    async fn lease_grant(
        &self,
        req: Request<pb::LeaseGrantRequest>,
    ) -> Result<Response<pb::LeaseGrantResponse>, Status> {
        let r = req.into_inner();
        // etcd picks the ID of an ID-less lease before sizing the request.
        let sized = pb::LeaseGrantRequest {
            id: if r.id == 0 {
                (self.raft_request_id() & i64::MAX as u64) as i64
            } else {
                r.id
            },
            ttl: r.ttl,
        };
        self.check_request_size(raft_field::LEASE_GRANT, &sized)?;
        let this = self.clone();
        let (id, rev) = self
            .store_op(move |store| {
                let id = store.grant_lease(r.id, r.ttl)?;
                this.set_deadline(id, r.ttl);
                Ok((id, store.revision()))
            })
            .await?;
        Ok(Response::new(pb::LeaseGrantResponse {
            header: self.header(rev),
            id,
            ttl: r.ttl,
            error: String::new(),
        }))
    }

    async fn lease_revoke(
        &self,
        req: Request<pb::LeaseRevokeRequest>,
    ) -> Result<Response<pb::LeaseRevokeResponse>, Status> {
        let r = req.into_inner();
        self.check_request_size(raft_field::LEASE_REVOKE, &r)?;
        let this = self.clone();
        let rev = self
            .store_op(move |store| {
                let rev = store.revoke_lease(r.id)?;
                this.clear_deadline(r.id);
                Ok(rev)
            })
            .await?;
        Ok(Response::new(pb::LeaseRevokeResponse {
            header: self.header(rev),
        }))
    }

    async fn lease_time_to_live(
        &self,
        req: Request<pb::LeaseTimeToLiveRequest>,
    ) -> Result<Response<pb::LeaseTimeToLiveResponse>, Status> {
        let r = req.into_inner();
        let this = self.clone();
        let (rev, ttl, keys, remaining) = self
            .blocking(move |store| {
                let keys = if r.keys {
                    store.lease_keys(r.id)
                } else {
                    Vec::new()
                };
                (
                    store.revision(),
                    store.lease_ttl(r.id),
                    keys,
                    this.remaining_ttl_secs(r.id),
                )
            })
            .await?;
        Ok(Response::new(pb::LeaseTimeToLiveResponse {
            header: self.header(rev),
            id: r.id,
            ttl: remaining,
            granted_ttl: ttl.unwrap_or(0),
            keys,
        }))
    }

    async fn lease_leases(
        &self,
        _req: Request<pb::LeaseLeasesRequest>,
    ) -> Result<Response<pb::LeaseLeasesResponse>, Status> {
        let (rev, ids) = self.blocking(|s| (s.revision(), s.lease_ids())).await?;
        Ok(Response::new(pb::LeaseLeasesResponse {
            header: self.header(rev),
            leases: ids.into_iter().map(|id| pb::LeaseStatus { id }).collect(),
        }))
    }

    type LeaseKeepAliveStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::LeaseKeepAliveResponse, Status>>;

    async fn lease_keep_alive(
        &self,
        req: Request<tonic::Streaming<pb::LeaseKeepAliveRequest>>,
    ) -> Result<Response<Self::LeaseKeepAliveStream>, Status> {
        let mut requests = req.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let this = self.clone();
        tokio::spawn(async move {
            while let Ok(Some(req)) = requests.message().await {
                let id = req.id;
                let worker = this.clone();
                let Ok((rev, ttl)) = this
                    .blocking(move |store| {
                        let ttl = store.lease_ttl(id).unwrap_or(0);
                        if ttl > 0 {
                            worker.set_deadline(id, ttl);
                        }
                        (store.revision(), ttl)
                    })
                    .await
                else {
                    break;
                };
                if tx
                    .send(Ok(pb::LeaseKeepAliveResponse {
                        header: this.header(rev),
                        id,
                        ttl,
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

/// One member, always: membership changes are refused rather than faked.
#[tonic::async_trait]
impl Cluster for EtcdServer {
    async fn member_list(
        &self,
        _req: Request<pb::MemberListRequest>,
    ) -> Result<Response<pb::MemberListResponse>, Status> {
        let rev = self.current_revision().await?;
        Ok(Response::new(pb::MemberListResponse {
            header: self.header(rev),
            members: vec![self.member()],
        }))
    }

    async fn member_add(
        &self,
        _req: Request<pb::MemberAddRequest>,
    ) -> Result<Response<pb::MemberAddResponse>, Status> {
        Err(Status::failed_precondition(
            "edge-state is a single-member store",
        ))
    }

    async fn member_remove(
        &self,
        _req: Request<pb::MemberRemoveRequest>,
    ) -> Result<Response<pb::MemberRemoveResponse>, Status> {
        Err(Status::failed_precondition(
            "edge-state cannot remove its only member",
        ))
    }

    /// Honoured: peer URLs are not identity and move with the node's addresses.
    async fn member_update(
        &self,
        req: Request<pb::MemberUpdateRequest>,
    ) -> Result<Response<pb::MemberUpdateResponse>, Status> {
        let req = req.into_inner();
        if req.id != self.member_id {
            return Err(Status::not_found(format!(
                "edge-state has one member ({:x}); there is no member {:x} to update",
                self.member_id, req.id
            )));
        }
        *lock(&self.peer_urls) = req.peer_ur_ls;
        let rev = self.current_revision().await?;
        Ok(Response::new(pb::MemberUpdateResponse {
            header: self.header(rev),
            members: vec![self.member()],
        }))
    }

    async fn member_promote(
        &self,
        _req: Request<pb::MemberPromoteRequest>,
    ) -> Result<Response<pb::MemberPromoteResponse>, Status> {
        Err(Status::failed_precondition(
            "edge-state has no learners to promote",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn panicked_task_restarts() {
        let runs = Arc::new(AtomicUsize::new(0));
        let r = runs.clone();
        let h = spawn_supervised("test", move || {
            let r = r.clone();
            async move {
                if r.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("boom");
                }
                std::future::pending::<()>().await;
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while runs.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the task was never restarted");
        h.abort();
    }

    #[tokio::test]
    async fn only_compacted_watch_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path().join("state.log")).unwrap();
        for v in [&b"1"[..], b"2", b"3"] {
            store.put(b"/k", v, 0).unwrap();
        }
        store.compact(3).unwrap();
        let store = Arc::new(Mutex::new(store));
        let watch = |id, cursor| Watch {
            id,
            key: b"/k".to_vec(),
            range_end: Vec::new(),
            cursor,
            progress_notify: false,
            prev_kv: false,
            start_revision: 0,
        };
        let mut watches = vec![watch(1, 1), watch(2, 3)];
        store.lock().unwrap().put(b"/k", b"4", 0).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        assert_eq!(
            deliver_owed(&store, &mut watches, &tx, (1, 1)).await,
            Some(5)
        );
        let cancelled = rx.recv().await.unwrap().unwrap();
        assert!(cancelled.canceled && cancelled.watch_id == 1 && cancelled.compact_revision == 3);
        let events = rx.recv().await.unwrap().unwrap();
        assert_eq!((events.watch_id, events.events.len()), (2, 2));
        assert_eq!(
            watches.iter().map(|w| (w.id, w.cursor)).collect::<Vec<_>>(),
            [(2, 5)]
        );
    }

    fn server_with_leased_key() -> (tempfile::TempDir, EtcdServer, i64) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path().join("state.log")).unwrap();
        let id = store.grant_lease(0, 30).unwrap();
        store.put(b"/leased", b"v", id).unwrap();
        let server = EtcdServer::new(store);
        (dir, server, id)
    }

    #[tokio::test]
    async fn renewed_lease_is_not_reaped() {
        let (_d, server, id) = server_with_leased_key();
        lock(&server.deadlines).insert(id, (Instant::now() - Duration::from_secs(1), 30));
        let collected = server.expired_ids();
        assert_eq!(collected, vec![id]);
        server.set_deadline(id, 30);
        assert_eq!(server.revoke_if_expired(id).await.unwrap().unwrap(), None);
        let store = server.store();
        let s = lock(&store);
        assert!(
            s.lease_exists(id) && s.get(b"/leased", 0).is_some(),
            "a renewed lease lost its keys"
        );
    }

    #[tokio::test]
    async fn expired_lease_is_reaped() {
        let (_d, server, id) = server_with_leased_key();
        lock(&server.deadlines).insert(id, (Instant::now() - Duration::from_secs(1), 30));
        let rev = server.revoke_if_expired(id).await.unwrap().unwrap();
        assert!(rev.is_some());
        let store = server.store();
        let s = lock(&store);
        assert!(!s.lease_exists(id) && s.get(b"/leased", 0).is_none());
        assert!(lock(&server.deadlines).get(&id).is_none());
    }

    #[test]
    fn deadlines_are_clamped() {
        let secs = |ttl| {
            deadline_after(ttl)
                .saturating_duration_since(Instant::now())
                .as_secs_f64()
        };
        for (ttl, want) in [
            (i64::MIN, 1.0),
            (0, 1.0),
            (30, 30.0),
            (MAX_LEASE_TTL, MAX_LEASE_TTL as f64),
            (i64::MAX, MAX_LEASE_TTL as f64),
        ] {
            assert!((secs(ttl) - want).abs() < 0.5, "ttl {ttl}: {}", secs(ttl));
        }
    }
}
