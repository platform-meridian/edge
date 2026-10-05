use super::frontend::Derived;
use super::report::{publish_route_status, run_gateway_status};
use super::state::{Built, Kind, Msg, State};
use super::trust::BUNDLE_GROUP;
use super::{GATEWAY_GROUP, GatewayRef, Routes, api_resource};
use crate::config::Route;
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
    static_routes: Vec<Route>,
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
                static_routes.clone(),
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
    statics: &[Route],
    routes: &Routes,
) -> Option<Built> {
    if !state.apply(msg) || !state.ready() {
        return None;
    }
    let built = state.build(gateway, statics);
    if **routes.load() != built.table {
        tracing::info!(
            total = built.table.len(),
            static_routes = statics.len(),
            "route table updated"
        );
        routes.store(Arc::new(built.table.clone()));
    }
    Some(built)
}

/// `static_routes` survive every republish: they reach loopback-bound backends,
/// which no Service can name (Endpoints reject 127.0.0.1).
async fn run(
    routes: Routes,
    gateway: GatewayRef,
    static_routes: Vec<Route>,
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
    let mut msgs = futures::stream::select_all(vec![
        watch_all(GATEWAY_GROUP, "v1", "HTTPRoute", Kind::Route),
        watch_all(GATEWAY_GROUP, "v1", "Gateway", Kind::Gateway),
        watch_all("", "v1", "Service", Kind::Service),
        watch_all(GATEWAY_GROUP, "v1beta1", "ReferenceGrant", Kind::Grant),
        watch_all("", "v1", "ConfigMap", Kind::ConfigMap),
        watch_all(BUNDLE_GROUP, "v1", "ClusterTrustBundle", Kind::TrustBundle),
    ]);

    let mut state = State::default();
    let mut frontend = None;
    while let Some(msg) = msgs.next().await {
        let Some(built) = step(&mut state, msg, &gateway, &static_routes, &routes) else {
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
    }
    anyhow::bail!("every watch ended")
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
            Err(_) => Msg::Error(kind),
        })
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
