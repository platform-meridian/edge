use super::frontend::Derived;
use super::report::{publish_policy_status, publish_route_status, run_gateway_status};
use super::state::{Built, Key, Kind, Msg, RefEvent, State};
use super::trust::BUNDLE_GROUP;
use super::trust::RefKind;
use super::{GATEWAY_GROUP, GatewayRef, Routes, Settings, api_resource};
use edge_common::Outage;
use futures::{Stream, StreamExt};
use kube::api::{Api, DynamicObject};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, ResourceExt};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

const SUPERVISE_MIN: Duration = Duration::from_secs(1);
const SUPERVISE_MAX: Duration = Duration::from_secs(60);

pub fn spawn(
    routes: Routes,
    gateway: GatewayRef,
    settings: Settings,
    tls: Option<crate::tls::Acceptor>,
) {
    let g = gateway.clone();
    tokio::spawn(supervise(
        "gateway status watch",
        SUPERVISE_MIN,
        SUPERVISE_MAX,
        move || run_gateway_status(g.clone()),
    ));
    tokio::spawn(supervise(
        "gateway api controller",
        SUPERVISE_MIN,
        SUPERVISE_MAX,
        move || {
            run(
                routes.clone(),
                gateway.clone(),
                settings.clone(),
                tls.clone(),
            )
        },
    ));
}

pub(super) async fn supervise<F, Fut>(what: &'static str, min: Duration, max: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut delay = min;
    loop {
        let began = tokio::time::Instant::now();
        match f().await {
            Ok(()) => tracing::warn!(what, "ended; restarting"),
            Err(e) => {
                tracing::warn!(what, error = %e, retry_in = ?delay, "failed; serving the last table")
            }
        }
        if began.elapsed() > max {
            delay = min;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(max);
    }
}

pub(super) fn step(
    state: &mut State,
    msg: Msg,
    gateway: &GatewayRef,
    settings: &Settings,
    routes: &Routes,
) -> Option<Built> {
    let applied = state.apply(msg);
    let synced = state.sync_refs(gateway);
    if !(applied || synced) || !state.ready() {
        return None;
    }
    let built = state.build(gateway, settings);
    if **routes.load() != built.table {
        tracing::info!(
            total = built.table.len(),
            static_routes = settings.statics.len(),
            "route table updated"
        );
        routes.store(Arc::new(built.table.clone()));
    }
    Some(built)
}

async fn run(
    routes: Routes,
    gateway: GatewayRef,
    settings: Settings,
    tls: Option<crate::tls::Acceptor>,
) -> anyhow::Result<()> {
    let client = Client::try_default().await?;
    let route_ar = api_resource(GATEWAY_GROUP, "v1", "HTTPRoute");
    let watch_all = |group, version, kind, k| {
        watch(
            Api::all_with(client.clone(), &api_resource(group, version, kind)),
            k,
        )
        .boxed()
    };
    let (ref_tx, ref_rx) = futures::channel::mpsc::unbounded();
    let mut ref_watches = RefWatches::default();
    let mut msgs = futures::stream::select_all(vec![
        ref_rx.boxed(),
        watch_all(GATEWAY_GROUP, "v1", "HTTPRoute", Kind::Route),
        watch_all(GATEWAY_GROUP, "v1", "Gateway", Kind::Gateway),
        watch_all("", "v1", "Service", Kind::Service),
        watch_all(GATEWAY_GROUP, "v1beta1", "ReferenceGrant", Kind::Grant),
        watch_all(BUNDLE_GROUP, "v1", "ClusterTrustBundle", Kind::TrustBundle),
        watch_all(GATEWAY_GROUP, "v1", "BackendTLSPolicy", Kind::Policy),
    ]);
    let policy_ar = api_resource(GATEWAY_GROUP, "v1", "BackendTLSPolicy");

    let mut state = State::default();
    let mut frontend = None;
    while let Some(msg) = msgs.next().await {
        let built = step(&mut state, msg, &gateway, &settings, &routes);
        ref_watches.follow(&client, state.ref_keys(), &ref_tx);
        let Some(built) = built else {
            continue;
        };
        if let Some(tls) = &tls
            && frontend.as_ref() != Some(&built.frontend)
        {
            apply_frontend(tls, &built.frontend);
            frontend = Some(built.frontend.clone());
        }
        for (o, outcome) in &built.outcomes {
            if let Err(e) = publish_route_status(&client, &route_ar, o, outcome).await {
                tracing::warn!(route = %o.name_any(), error = %e, "status not written");
            }
        }
        for (o, outcome, ours) in &built.policies {
            if let Err(e) =
                publish_policy_status(&client, &policy_ar, &gateway, o, outcome, *ours).await
            {
                tracing::warn!(policy = %o.name_any(), error = %e, "status not written");
            }
        }
    }
    anyhow::bail!("every watch ended")
}

/// One watch per referenced object, each answering for its object alone.
#[derive(Default)]
struct RefWatches(std::collections::BTreeMap<(RefKind, Key), tokio::task::AbortHandle>);

impl Drop for RefWatches {
    fn drop(&mut self) {
        self.0.values().for_each(|h| h.abort());
    }
}

impl RefWatches {
    fn follow<'a>(
        &mut self,
        client: &Client,
        wanted: impl Iterator<Item = &'a (RefKind, Key)>,
        tx: &futures::channel::mpsc::UnboundedSender<Msg>,
    ) {
        let wanted: std::collections::BTreeSet<&(RefKind, Key)> = wanted.collect();
        self.0.retain(|k, h| {
            let keep = wanted.contains(k);
            if !keep {
                h.abort();
            }
            keep
        });
        for k in wanted {
            if !self.0.contains_key(k) {
                let h = tokio::spawn(watch_ref(client.clone(), k.clone(), tx.clone()));
                self.0.insert(k.clone(), h.abort_handle());
            }
        }
    }
}

async fn watch_ref(
    client: Client,
    (kind, key): (RefKind, Key),
    tx: futures::channel::mpsc::UnboundedSender<Msg>,
) {
    let (group, version, k) = kind.api();
    let api: Api<DynamicObject> =
        Api::namespaced_with(client, &key.0, &api_resource(group, version, k));
    let named = watcher::Config::default().fields(&format!("metadata.name={}", key.1));
    let mut events = watcher(api, named).default_backoff().boxed();
    let mut listing = None;
    while let Some(r) = events.next().await {
        let ev = match r {
            Ok(watcher::Event::Init) => {
                listing = None;
                continue;
            }
            Ok(watcher::Event::InitApply(o)) => {
                listing = Some(o);
                continue;
            }
            Ok(watcher::Event::InitDone) => RefEvent::Listed(listing.take()),
            Ok(watcher::Event::Apply(o)) => RefEvent::Applied(o),
            Ok(watcher::Event::Delete(_)) => RefEvent::Deleted,
            Err(e) => {
                tracing::warn!(object = %format!("{k} {}/{}", key.0, key.1), error = %e, "watch failed");
                RefEvent::Failed
            }
        };
        if tx.unbounded_send(Msg::Ref(kind, key.clone(), ev)).is_err() {
            return;
        }
    }
}

fn apply_frontend(tls: &crate::tls::Acceptor, d: &Derived) {
    for p in &d.problems {
        tracing::warn!(problem = %p, "gateway tls");
    }
    let usable = tls.set_frontend(d.frontend.clone());
    match &d.frontend {
        None => tracing::info!("no client certificate is asked for"),
        Some(f) => tracing::info!(
            mode = ?f.mode,
            usable,
            names = ?f.names,
            "client certificate validation applied"
        ),
    }
}

fn watch(api: Api<DynamicObject>, kind: Kind) -> impl Stream<Item = Msg> {
    let (what, mut outage) = (format!("{kind:?}"), Outage::default());
    watcher(api, watcher::Config::default())
        .default_backoff()
        .inspect(move |r| outage.observe(&what, r))
        .map(move |r| match r {
            Ok(ev) => Msg::Event(kind, ev),
            Err(e) => Msg::Error(kind, not_served(&e)),
        })
}

fn not_served(e: &watcher::Error) -> bool {
    match e {
        watcher::Error::InitialListFailed(kube::Error::Api(s))
        | watcher::Error::WatchStartFailed(kube::Error::Api(s))
        | watcher::Error::WatchFailed(kube::Error::Api(s)) => s.is_not_found(),
        watcher::Error::WatchError(s) => s.is_not_found(),
        _ => false,
    }
}

/// The watcher reports its own retried failures as items, so an `Err` is not
/// the end of the stream.
pub(super) async fn each_ok<S, T, E, F, Fut>(mut st: S, what: &str, mut f: F)
where
    S: Stream<Item = Result<T, E>> + Unpin,
    E: std::fmt::Display,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut outage = Outage::default();
    while let Some(item) = st.next().await {
        outage.observe(what, &item);
        if let Ok(o) = item {
            f(o).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn supervise_backs_off_and_restarts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let stamps = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (c2, s2) = (calls.clone(), stamps.clone());
        let task = tokio::spawn(supervise(
            "t",
            Duration::from_secs(1),
            Duration::from_secs(8),
            move || {
                let (c, s) = (c2.clone(), s2.clone());
                async move {
                    s.lock().unwrap().push(tokio::time::Instant::now());
                    match c.fetch_add(1, Ordering::SeqCst) {
                        0..=3 => anyhow::bail!("no cluster"),
                        4 => Ok(()),
                        5 => {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            anyhow::bail!("ran longer than the cap, then failed")
                        }
                        _ => std::future::pending().await,
                    }
                }
            },
        ));
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            7,
            "failures and a clean end are both restarted"
        );
        assert!(!task.is_finished());
        let st = stamps.lock().unwrap();
        let gaps: Vec<u64> = st.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
        assert_eq!(gaps, [1, 2, 4, 8, 8, 11]);
    }

    #[tokio::test]
    async fn each_ok_survives_errors() {
        let items: Vec<Result<u32, String>> = vec![
            Ok(1),
            Err("hiccup".into()),
            Ok(2),
            Err("again".into()),
            Ok(3),
        ];
        let got = std::sync::Mutex::new(Vec::new());
        each_ok(futures::stream::iter(items), "t", |x| {
            got.lock().unwrap().push(x);
            async {}
        })
        .await;
        assert_eq!(*got.lock().unwrap(), [1, 2, 3]);
    }
}
