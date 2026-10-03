//! Shared by edge-cni's service map and edge-dns's zone, so the two cannot disagree.

pub mod policy;

use std::collections::{HashMap, HashSet};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointSlice};
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::{Api, Client, Resource, ResourceExt};

const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

#[derive(Debug, Default, Clone)]
pub struct ServiceView {
    pub services: HashMap<String, Service>,
    pub slices: HashMap<String, Vec<EndpointSlice>>,
}

impl ServiceView {
    pub fn slices_for(&self, key: &str) -> &[EndpointSlice] {
        self.slices.get(key).map_or(&[], |v| v.as_slice())
    }

    pub fn apply_service(&mut self, s: Service) -> String {
        let k = service_key(&s);
        self.services.insert(k.clone(), s);
        k
    }

    // Takes the service's slices too: nothing else would remove them.
    pub fn remove_service(&mut self, s: &Service) -> String {
        let k = service_key(s);
        self.services.remove(&k);
        self.slices.remove(&k);
        k
    }

    // Replaces by slice name: every relist re-delivers the same slices.
    pub fn apply_slice(&mut self, e: EndpointSlice) -> Option<String> {
        slice_key(&e).inspect(|k| {
            let entry = self.slices.entry(k.clone()).or_default();
            entry.retain(|s| s.name_any() != e.name_any());
            entry.push(e.clone());
        })
    }

    pub fn remove_slice(&mut self, e: &EndpointSlice) -> Option<String> {
        slice_key(e).inspect(|k| {
            if let Some(entry) = self.slices.get_mut(k) {
                entry.retain(|s| s.name_any() != e.name_any());
                if entry.is_empty() {
                    self.slices.remove(k);
                }
            }
        })
    }
}

pub fn object_key<K: Resource>(o: &K) -> String {
    match o.namespace() {
        Some(ns) => format!("{ns}/{}", o.name_any()),
        None => o.name_any(),
    }
}

pub fn service_key(s: &Service) -> String {
    object_key(s)
}

pub fn slice_key(e: &EndpointSlice) -> Option<String> {
    let owner = e.labels().get(SERVICE_NAME_LABEL)?;
    Some(format!("{}/{}", e.namespace().unwrap_or_default(), owner))
}

// The EndpointSlice API: an unset `ready` means ready.
pub fn is_ready(ep: &Endpoint) -> bool {
    ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true)
}

// An unset `serving` means the same as `ready`.
pub fn is_serving_terminating(ep: &Endpoint) -> bool {
    let Some(c) = ep.conditions.as_ref() else {
        return false;
    };
    c.terminating == Some(true) && c.serving.or(c.ready).unwrap_or(true)
}

pub fn select_with<T>(
    candidates: impl IntoIterator<Item = T>,
    ep: impl Fn(&T) -> &Endpoint,
) -> Vec<T> {
    let all: Vec<T> = candidates.into_iter().collect();
    if all.iter().any(|t| is_ready(ep(t))) {
        return all.into_iter().filter(|t| is_ready(ep(t))).collect();
    }
    all.into_iter()
        .filter(|t| is_serving_terminating(ep(t)))
        .collect()
}

// kube-proxy's fallback: serving-but-terminating endpoints when none is ready.
pub fn select_endpoints<'a>(
    candidates: impl IntoIterator<Item = &'a Endpoint>,
) -> Vec<&'a Endpoint> {
    select_with(candidates, |e| *e)
}

pub fn service_endpoints(slices: &[EndpointSlice]) -> Vec<&Endpoint> {
    select_endpoints(slices.iter().flat_map(|s| s.endpoints.iter().flatten()))
}

#[allow(clippy::large_enum_variant)]
enum WatchEvent {
    Svc(Result<Event<Service>, watcher::Error>),
    Eps(Result<Event<EndpointSlice>, watcher::Error>),
}

// A delete during a disconnect is never delivered, so whatever a relist does not
// list is pruned.
#[derive(Default)]
struct Fold {
    svc_seen: Option<HashSet<String>>,
    eps_seen: Option<HashSet<(String, String)>>,
    svc_listed: bool,
    eps_listed: bool,
}

impl Fold {
    fn synced(&self) -> bool {
        self.svc_listed && self.eps_listed
    }

    fn service(&mut self, view: &mut ServiceView, ev: Event<Service>) -> Vec<String> {
        match ev {
            Event::Init => {
                self.svc_seen = Some(HashSet::new());
                Vec::new()
            }
            Event::InitApply(s) => {
                let k = view.apply_service(s);
                if let Some(seen) = self.svc_seen.as_mut() {
                    seen.insert(k.clone());
                }
                vec![k]
            }
            Event::InitDone => {
                self.svc_listed = true;
                let Some(seen) = self.svc_seen.take() else {
                    return Vec::new();
                };
                let mut gone: Vec<String> = view
                    .services
                    .keys()
                    .filter(|k| !seen.contains(*k))
                    .cloned()
                    .collect();
                gone.sort();
                for k in &gone {
                    view.services.remove(k);
                    view.slices.remove(k);
                }
                gone
            }
            Event::Apply(s) => vec![view.apply_service(s)],
            Event::Delete(s) => vec![view.remove_service(&s)],
        }
    }

    fn slice(&mut self, view: &mut ServiceView, ev: Event<EndpointSlice>) -> Vec<String> {
        match ev {
            Event::Init => {
                self.eps_seen = Some(HashSet::new());
                Vec::new()
            }
            Event::InitApply(e) => {
                let name = e.name_any();
                let k = view.apply_slice(e);
                if let (Some(seen), Some(k)) = (self.eps_seen.as_mut(), k.as_ref()) {
                    seen.insert((k.clone(), name));
                }
                k.into_iter().collect()
            }
            Event::InitDone => {
                self.eps_listed = true;
                let Some(seen) = self.eps_seen.take() else {
                    return Vec::new();
                };
                let mut touched = std::collections::BTreeSet::new();
                for (k, slices) in view.slices.iter_mut() {
                    let before = slices.len();
                    slices.retain(|s| seen.contains(&(k.clone(), s.name_any())));
                    if slices.len() != before {
                        touched.insert(k.clone());
                    }
                }
                view.slices.retain(|_, v| !v.is_empty());
                touched.into_iter().collect()
            }
            Event::Apply(e) => view.apply_slice(e).into_iter().collect(),
            Event::Delete(e) => view.remove_slice(&e).into_iter().collect(),
        }
    }
}

pub async fn run<F, S>(client: Client, mut on_change: F, on_synced: S) -> anyhow::Result<()>
where
    F: FnMut(&ServiceView, &str) -> anyhow::Result<()>,
    S: FnOnce(&ServiceView) -> anyhow::Result<()>,
{
    let svc_api: Api<Service> = Api::all(client.clone());
    let eps_api: Api<EndpointSlice> = Api::all(client);
    let mut view = ServiceView::default();

    let svc_stream = watch(svc_api, "services").map(WatchEvent::Svc);
    let eps_stream = watch(eps_api, "endpointslices").map(WatchEvent::Eps);
    let mut stream = futures::stream::select(svc_stream, eps_stream).boxed();
    let mut fold = Fold::default();
    let mut on_synced = Some(on_synced);

    while let Some(ev) = stream.next().await {
        let touched = match ev {
            WatchEvent::Svc(Ok(e)) => fold.service(&mut view, e),
            WatchEvent::Eps(Ok(e)) => fold.slice(&mut view, e),
            WatchEvent::Svc(Err(_)) | WatchEvent::Eps(Err(_)) => Vec::new(),
        };

        for key in touched {
            on_change(&view, &key)?;
        }
        if fold.synced()
            && let Some(f) = on_synced.take()
        {
            f(&view)?;
        }
    }

    anyhow::bail!("service/endpointslice watch ended unexpectedly")
}

pub fn watch<K>(
    api: Api<K>,
    what: &'static str,
) -> impl futures::Stream<Item = Result<Event<K>, watcher::Error>> + Send
where
    K: kube::Resource
        + Clone
        + std::fmt::Debug
        + k8s_openapi::serde::de::DeserializeOwned
        + Send
        + 'static,
    K::DynamicType: Default,
{
    watch_with(api, watcher::Config::default(), what)
}

pub fn watch_with<K>(
    api: Api<K>,
    config: watcher::Config,
    what: &'static str,
) -> impl futures::Stream<Item = Result<Event<K>, watcher::Error>> + Send
where
    K: kube::Resource
        + Clone
        + std::fmt::Debug
        + k8s_openapi::serde::de::DeserializeOwned
        + Send
        + 'static,
    K::DynamicType: Default,
{
    let mut outage = edge_common::Outage::default();
    watcher(api, config)
        .default_backoff()
        .inspect(move |r| outage.observe(what, r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::discovery::v1::EndpointConditions;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn svc(ns: &str, name: &str) -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn slice(ns: &str, name: &str, owner: Option<&str>) -> EndpointSlice {
        let mut labels = std::collections::BTreeMap::new();
        if let Some(o) = owner {
            labels.insert(SERVICE_NAME_LABEL.to_string(), o.to_string());
        }
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn names(v: &ServiceView, key: &str) -> Vec<String> {
        let mut n: Vec<String> = v.slices_for(key).iter().map(|s| s.name_any()).collect();
        n.sort();
        n
    }

    #[test]
    fn cluster_scoped_key_is_bare_name() {
        let ns = k8s_openapi::api::core::v1::Namespace {
            metadata: ObjectMeta {
                name: Some("netpol-y".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(object_key(&ns), "netpol-y");
        assert_eq!(object_key(&svc("ns", "web")), "ns/web");
    }

    #[test]
    fn service_and_slices_share_key() {
        let mut v = ServiceView::default();
        assert_eq!(
            v.apply_service(svc("kube-system", "kube-dns")),
            "kube-system/kube-dns"
        );
        assert_eq!(
            v.apply_slice(slice("kube-system", "kube-dns-abc", Some("kube-dns")))
                .as_deref(),
            Some("kube-system/kube-dns")
        );
        assert_eq!(names(&v, "kube-system/kube-dns"), ["kube-dns-abc"]);
    }

    #[test]
    fn slices_keyed_by_name() {
        let mut v = ServiceView::default();
        for _ in 0..3 {
            v.apply_slice(slice("a", "web-1", Some("web")));
        }
        v.apply_slice(slice("a", "web-2", Some("web")));
        v.apply_slice(slice("b", "web-1", Some("web")));
        assert_eq!(names(&v, "a/web"), ["web-1", "web-2"]);
        assert_eq!(names(&v, "b/web"), ["web-1"]);
    }

    #[test]
    fn remove_slice_drops_empty_key() {
        let mut v = ServiceView::default();
        v.apply_slice(slice("default", "web-1", Some("web")));
        v.apply_slice(slice("default", "web-2", Some("web")));
        assert_eq!(
            v.remove_slice(&slice("default", "web-1", Some("web")))
                .as_deref(),
            Some("default/web")
        );
        assert_eq!(names(&v, "default/web"), ["web-2"]);
        v.remove_slice(&slice("default", "web-2", Some("web")));
        assert!(!v.slices.contains_key("default/web"));
        v.remove_slice(&slice("default", "ghost", Some("web")));
        assert!(v.slices.is_empty(), "removing an unknown slice is harmless");
    }

    #[test]
    fn service_delete_takes_slices() {
        let mut v = ServiceView::default();
        v.apply_service(svc("default", "web"));
        v.apply_slice(slice("default", "web-1", Some("web")));
        assert_eq!(v.remove_service(&svc("default", "web")), "default/web");
        assert!(v.services.is_empty());
        assert!(v.slices_for("default/web").is_empty());
    }

    #[test]
    fn unlabelled_slice_ignored() {
        let mut v = ServiceView::default();
        assert!(v.apply_slice(slice("default", "orphan", None)).is_none());
        assert!(v.remove_slice(&slice("default", "orphan", None)).is_none());
        assert!(v.slices.is_empty());
    }

    #[test]
    fn relist_prunes_service() {
        let mut v = ServiceView::default();
        let mut f = Fold::default();
        f.service(&mut v, Event::Init);
        f.service(&mut v, Event::InitApply(svc("ns", "a")));
        f.service(&mut v, Event::InitApply(svc("ns", "b")));
        f.service(&mut v, Event::InitDone);
        v.apply_slice(slice("ns", "b-1", Some("b")));
        assert_eq!(v.services.len(), 2);

        f.service(&mut v, Event::Init);
        f.service(&mut v, Event::InitApply(svc("ns", "a")));
        let gone = f.service(&mut v, Event::InitDone);

        assert_eq!(gone, ["ns/b"], "the pruned key is reported");
        assert!(v.services.contains_key("ns/a"));
        assert!(!v.services.contains_key("ns/b"));
        assert!(v.slices_for("ns/b").is_empty());
    }

    #[test]
    fn relist_prunes_slice() {
        let mut v = ServiceView::default();
        let mut f = Fold::default();
        f.slice(&mut v, Event::Init);
        f.slice(&mut v, Event::InitApply(slice("ns", "web-1", Some("web"))));
        f.slice(&mut v, Event::InitApply(slice("ns", "web-2", Some("web"))));
        f.slice(&mut v, Event::InitApply(slice("ns", "db-1", Some("db"))));
        f.slice(&mut v, Event::InitDone);

        f.slice(&mut v, Event::Init);
        f.slice(&mut v, Event::InitApply(slice("ns", "web-1", Some("web"))));
        f.slice(&mut v, Event::InitApply(slice("ns", "db-1", Some("db"))));
        let touched = f.slice(&mut v, Event::InitDone);

        assert_eq!(touched, ["ns/web"]);
        assert_eq!(names(&v, "ns/web"), ["web-1"]);
        assert_eq!(names(&v, "ns/db"), ["db-1"]);
    }

    #[test]
    fn full_relist_prunes_nothing() {
        let mut v = ServiceView::default();
        let mut f = Fold::default();
        for _ in 0..3 {
            f.service(&mut v, Event::Init);
            f.service(&mut v, Event::InitApply(svc("ns", "a")));
            assert!(f.service(&mut v, Event::InitDone).is_empty());
            f.slice(&mut v, Event::Init);
            f.slice(&mut v, Event::InitApply(slice("ns", "a-1", Some("a"))));
            assert!(f.slice(&mut v, Event::InitDone).is_empty());
        }
        assert!(v.services.contains_key("ns/a"));
        assert_eq!(names(&v, "ns/a"), ["a-1"]);
    }

    #[test]
    fn relist_prunes_late_service() {
        let mut v = ServiceView::default();
        let mut f = Fold::default();
        f.service(&mut v, Event::Init);
        f.service(&mut v, Event::InitDone);
        f.service(&mut v, Event::Apply(svc("ns", "late")));
        assert!(v.services.contains_key("ns/late"));
        f.service(&mut v, Event::Init);
        assert_eq!(f.service(&mut v, Event::InitDone), ["ns/late"]);
        assert!(v.services.is_empty());
    }

    #[test]
    fn synced_after_both_lists() {
        let mut v = ServiceView::default();
        let mut f = Fold::default();
        assert!(!f.synced());
        f.service(&mut v, Event::InitDone);
        assert!(!f.synced());
        f.slice(&mut v, Event::InitDone);
        assert!(f.synced());
    }

    fn ep(addr: &str, conditions: Option<(Option<bool>, Option<bool>, Option<bool>)>) -> Endpoint {
        Endpoint {
            addresses: vec![addr.into()],
            conditions: conditions.map(|(ready, serving, terminating)| EndpointConditions {
                ready,
                serving,
                terminating,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn endpoint_selection() {
        let t = Some(true);
        let f = Some(false);
        #[allow(clippy::type_complexity)]
        let cases: &[(
            &str,
            &[Option<(Option<bool>, Option<bool>, Option<bool>)>],
            &[&str],
        )] = &[
            ("no conditions is ready", &[None], &["1"]),
            ("unset ready is ready", &[Some((None, None, None))], &["1"]),
            ("ready false", &[Some((f, None, None))], &[]),
            (
                "ready wins over serving-terminating",
                &[Some((t, t, f)), Some((f, t, t))],
                &["1"],
            ),
            (
                "nothing ready: serving-terminating only",
                &[Some((f, t, t)), Some((f, f, t)), Some((f, f, f))],
                &["1"],
            ),
            (
                "unset serving follows ready",
                &[Some((f, None, t)), Some((None, None, t))],
                &["2"],
            ),
        ];
        for (what, conds, want) in cases {
            let eps: Vec<Endpoint> = conds
                .iter()
                .enumerate()
                .map(|(i, c)| ep(&(i + 1).to_string(), *c))
                .collect();
            let got: Vec<&str> = select_endpoints(eps.iter())
                .iter()
                .map(|e| e.addresses[0].as_str())
                .collect();
            assert_eq!(got, *want, "{what}");
        }
    }

    #[test]
    fn selection_spans_slices() {
        let mut a = slice("ns", "web-1", Some("web"));
        a.endpoints = Some(vec![ep(
            "10.0.0.1",
            Some((Some(false), Some(true), Some(true))),
        )]);
        let mut b = slice("ns", "web-2", Some("web"));
        b.endpoints = Some(vec![ep("10.0.0.2", Some((None, None, None)))]);
        let slices = [a, b];
        let got = service_endpoints(&slices);
        assert_eq!(
            got.len(),
            1,
            "a ready one elsewhere suppresses the terminating one"
        );
        assert_eq!(got[0].addresses[0], "10.0.0.2");
    }
}
