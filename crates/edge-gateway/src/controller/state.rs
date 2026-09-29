//! The cluster's objects as a plain value, with no I/O.

use super::GatewayRef;
use super::convert::{Ctx, Outcome, convert};
use super::schema::{Listener, ReferenceGrant};
use crate::config::Route;
use kube::ResourceExt;
use kube::api::DynamicObject;
use kube::runtime::watcher::Event;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    Route,
    Gateway,
    Service,
    Grant,
}

// Consumed one at a time, never stored; boxing would only allocate.
#[allow(clippy::large_enum_variant)]
pub(super) enum Msg {
    Event(Kind, Event<DynamicObject>),
    Error(Kind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Phase {
    #[default]
    AwaitingFirstList,
    Listed,
    Unavailable,
}

pub(super) type Key = (String, String);

pub(super) fn key(o: &DynamicObject) -> Key {
    (o.namespace().unwrap_or_default(), o.name_any())
}

/// A relist replaces the live set only at `InitDone`, so objects deleted while
/// the watch was down disappear and a half-received list is never visible.
#[derive(Default)]
struct Store {
    live: BTreeMap<Key, DynamicObject>,
    staging: Option<BTreeMap<Key, DynamicObject>>,
    phase: Phase,
}

impl Store {
    fn event(&mut self, ev: Event<DynamicObject>) {
        match ev {
            Event::Init => self.staging = Some(BTreeMap::new()),
            Event::InitApply(o) => {
                self.staging.get_or_insert_default().insert(key(&o), o);
            }
            Event::InitDone => {
                self.live = self.staging.take().unwrap_or_default();
                self.phase = Phase::Listed;
            }
            Event::Apply(o) if o.metadata.deletion_timestamp.is_some() => {
                self.live.remove(&key(&o));
            }
            Event::Apply(o) => {
                self.live.insert(key(&o), o);
            }
            Event::Delete(o) => {
                self.live.remove(&key(&o));
            }
        }
    }

    fn fail_pending_first_list(&mut self) -> bool {
        let settles = self.phase == Phase::AwaitingFirstList;
        if settles {
            self.phase = Phase::Unavailable;
        }
        settles
    }
}

#[derive(Default)]
pub(super) struct State {
    routes: Store,
    gateways: Store,
    services: Store,
    grants: Store,
}

pub(super) struct Built {
    pub table: Vec<Route>,
    pub outcomes: Vec<(DynamicObject, Outcome)>,
}

impl State {
    fn store(&mut self, k: Kind) -> &mut Store {
        match k {
            Kind::Route => &mut self.routes,
            Kind::Gateway => &mut self.gateways,
            Kind::Service => &mut self.services,
            Kind::Grant => &mut self.grants,
        }
    }

    /// True when the message can change the table or whether one can be built.
    pub fn apply(&mut self, msg: Msg) -> bool {
        match msg {
            Msg::Event(k, ev) => {
                let ev = if k == Kind::Service { thin(ev) } else { ev };
                let changes = !matches!(ev, Event::Init | Event::InitApply(_));
                self.store(k).event(ev);
                changes
            }
            Msg::Error(k) => self.store(k).fail_pending_first_list(),
        }
    }

    pub fn ready(&self) -> bool {
        self.routes.phase == Phase::Listed
            && self.gateways.phase == Phase::Listed
            && self.services.phase != Phase::AwaitingFirstList
            && self.grants.phase != Phase::AwaitingFirstList
    }

    /// Without Services the existence check is skipped (the route would only
    /// 502); without ReferenceGrants every cross-namespace backend is refused.
    pub fn build(&self, gateway: &GatewayRef, statics: &[Route]) -> Built {
        let listeners = self
            .gateways
            .live
            .get(&(gateway.namespace.clone(), gateway.name.clone()))
            .map(Listener::all_of);
        let services: Option<BTreeSet<Key>> = (self.services.phase == Phase::Listed)
            .then(|| self.services.live.keys().cloned().collect());
        let grants: Vec<ReferenceGrant> = self
            .grants
            .live
            .values()
            .filter_map(ReferenceGrant::parse)
            .collect();
        let static_hosts: HashSet<String> =
            statics.iter().filter_map(|r| r.hostname.clone()).collect();
        let ctx = Ctx {
            gateway,
            listeners: listeners.as_deref(),
            services: services.as_ref(),
            grants: &grants,
            static_hosts: &static_hosts,
        };

        let mut outcomes = Vec::new();
        let mut table: Vec<Route> = statics.to_vec();
        for o in self.routes_oldest_first() {
            if let Some(out) = convert(o, &ctx) {
                table.extend(out.routes.iter().cloned());
                outcomes.push((o.clone(), out));
            }
        }
        // Stable sort: on a tie, statics then the oldest route win.
        table.sort_by(Route::precedence);
        Built { table, outcomes }
    }

    /// Gateway API conflict resolution: oldest first, then namespace/name.
    fn routes_oldest_first(&self) -> Vec<&DynamicObject> {
        let mut objs: Vec<&DynamicObject> = self.routes.live.values().collect();
        objs.sort_by_key(|o| {
            let created = o.metadata.creation_timestamp.as_ref().map(|t| t.0);
            (created.is_none(), created, key(o))
        });
        objs
    }
}

/// Only a Service's existence matters; drop the rest to save memory.
pub(super) fn thin(ev: Event<DynamicObject>) -> Event<DynamicObject> {
    let identity_only = |mut o: DynamicObject| {
        o.data = Value::Null;
        o.metadata.managed_fields = None;
        o
    };
    match ev {
        Event::Apply(o) => Event::Apply(identity_only(o)),
        Event::Delete(o) => Event::Delete(identity_only(o)),
        Event::InitApply(o) => Event::InitApply(identity_only(o)),
        e => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Authz, Backend};
    use crate::controller::convert::Outcome;
    use crate::controller::run::step;
    use crate::controller::{GATEWAY_GROUP, Routes};
    use arc_swap::ArcSwap;
    use serde_json::json;
    use std::sync::Arc;

    const T0: &str = "2026-01-01T00:00:00Z";

    fn gw() -> GatewayRef {
        GatewayRef {
            name: "edge".into(),
            namespace: "meridian".into(),
            bound_port: 8443,
        }
    }

    fn obj(
        api: &str,
        kind: &str,
        ns: &str,
        name: &str,
        created: &str,
        ann: Value,
        spec: Value,
    ) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": api,
            "kind": kind,
            "metadata": { "name": name, "namespace": ns, "annotations": ann, "creationTimestamp": created },
            "spec": spec,
        }))
        .unwrap()
    }

    fn http_route(
        ns: &str,
        name: &str,
        created: &str,
        ann: Value,
        mut spec: Value,
    ) -> DynamicObject {
        if spec.get("parentRefs").is_none() {
            spec["parentRefs"] = json!([{ "name": "edge", "namespace": "meridian" }]);
        }
        obj(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            ns,
            name,
            created,
            ann,
            spec,
        )
    }

    fn gateway_obj(listeners: Value) -> DynamicObject {
        obj(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "meridian",
            "edge",
            T0,
            json!({}),
            json!({ "gatewayClassName": "edge", "listeners": listeners }),
        )
    }

    fn all_ns() -> Value {
        json!([{ "name": "https", "port": 8443, "protocol": "HTTPS", "allowedRoutes": { "namespaces": { "from": "All" } } }])
    }

    fn service(ns: &str, name: &str) -> DynamicObject {
        obj(
            "v1",
            "Service",
            ns,
            name,
            T0,
            json!({}),
            json!({ "ports": [{ "port": 80 }] }),
        )
    }

    fn grant(ns: &str, from_ns: &str, to: Value) -> DynamicObject {
        obj(
            "gateway.networking.k8s.io/v1beta1",
            "ReferenceGrant",
            ns,
            "g",
            T0,
            json!({}),
            json!({ "from": [{ "group": GATEWAY_GROUP, "kind": "HTTPRoute", "namespace": from_ns }], "to": to }),
        )
    }

    fn static_route(host: Option<&str>, backend: &str) -> Route {
        Route {
            hostname: host.map(str::to_string),
            prefix: "/".into(),
            authz: Authz::Skip,
            rewrite_host: None,
            backend: Backend {
                host: backend.into(),
                port: 1,
            },
        }
    }

    fn served(host: Option<&str>, prefix: &str, service: &str, port: u16) -> Route {
        Route {
            hostname: host.map(str::to_string),
            prefix: prefix.into(),
            authz: Authz::Required,
            rewrite_host: None,
            backend: Backend {
                host: format!("{service}.svc.cluster.local"),
                port,
            },
        }
    }

    fn verdicts(o: &Outcome) -> ((bool, &'static str), (bool, &'static str)) {
        (
            (o.accepted.ok, o.accepted.reason),
            (o.resolved.ok, o.resolved.reason),
        )
    }

    struct Cluster {
        state: State,
        routes: Routes,
        statics: Vec<Route>,
        last: Option<Built>,
    }

    impl Cluster {
        fn new(statics: Vec<Route>) -> Self {
            Self {
                state: State::default(),
                routes: Arc::new(ArcSwap::from_pointee(statics.clone())),
                statics,
                last: None,
            }
        }

        fn basic() -> Self {
            Self::with_gateway(vec![], all_ns())
        }

        fn with_gateway(statics: Vec<Route>, listeners: Value) -> Self {
            let mut c = Self::new(statics);
            c.list(Kind::Gateway, vec![gateway_obj(listeners)]);
            c.fail(Kind::Service);
            c.fail(Kind::Grant);
            c
        }

        fn feed(&mut self, msg: Msg) {
            if let Some(b) = step(&mut self.state, msg, &gw(), &self.statics, &self.routes) {
                self.last = Some(b);
            }
        }
        fn list(&mut self, k: Kind, objs: Vec<DynamicObject>) {
            self.feed(Msg::Event(k, Event::Init));
            for o in objs {
                self.feed(Msg::Event(k, Event::InitApply(o)));
            }
            self.feed(Msg::Event(k, Event::InitDone));
        }
        fn apply(&mut self, k: Kind, o: DynamicObject) {
            self.feed(Msg::Event(k, Event::Apply(o)));
        }
        fn delete(&mut self, k: Kind, o: DynamicObject) {
            self.feed(Msg::Event(k, Event::Delete(o)));
        }
        fn fail(&mut self, k: Kind) {
            self.feed(Msg::Error(k));
        }
        fn table(&self) -> Vec<Route> {
            (**self.routes.load()).clone()
        }
        fn backends(&self) -> Vec<String> {
            self.table().into_iter().map(|r| r.backend.host).collect()
        }
        fn outcome(&self, name: &str) -> &Outcome {
            let built = self.last.as_ref().expect("no table built");
            &built
                .outcomes
                .iter()
                .find(|(o, _)| o.name_any() == name)
                .expect("no outcome")
                .1
        }

        fn one(mut self, spec: Value, ann: Value) -> (Vec<Route>, Cluster) {
            self.list(Kind::Route, vec![http_route("apps", "t", T0, ann, spec)]);
            (self.table(), self)
        }
    }

    fn to_service(name: &str, created: &str, host: &str, svc: &str) -> DynamicObject {
        http_route(
            "apps",
            name,
            created,
            json!({ "edge.meridian/authz": "skip" }),
            json!({ "hostnames": [host], "rules": [{ "backendRefs": [{ "name": svc, "port": 80 }] }] }),
        )
    }

    fn backend_ref(b: Value) -> Value {
        json!({ "rules": [{ "backendRefs": [b] }] })
    }

    fn svc_spec() -> Value {
        backend_ref(json!({ "name": "svc", "port": 80 }))
    }

    #[test]
    fn deleted_routes_leave_table() {
        let mut c = Cluster::basic();
        let a = to_service("a", T0, "a.test", "svc-a");
        let b = to_service("b", "2026-01-01T00:00:01Z", "b.test", "svc-b");
        let d = to_service("d", "2026-01-01T00:00:02Z", "d.test", "svc-d");
        c.list(Kind::Route, vec![a.clone(), b.clone(), d.clone()]);
        assert_eq!(c.table().len(), 3);

        c.delete(Kind::Route, a);
        let mut being_deleted = b.clone();
        being_deleted.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        c.apply(Kind::Route, being_deleted);
        assert_eq!(c.backends(), ["svc-d.apps.svc.cluster.local"]);

        // Deleted while the watch was down.
        c.list(Kind::Route, vec![b]);
        assert_eq!(c.backends(), ["svc-b.apps.svc.cluster.local"]);
    }

    #[test]
    fn file_table_until_watches_settle() {
        let file = vec![static_route(Some("static.test"), "127.0.0.1")];
        let mut c = Cluster::new(file.clone());
        c.fail(Kind::Route);
        c.fail(Kind::Gateway);
        assert!(!c.state.ready(), "routes and the Gateway are required");

        c.list(Kind::Route, vec![to_service("a", T0, "a.test", "svc-a")]);
        c.feed(Msg::Event(Kind::Gateway, Event::Init));
        c.feed(Msg::Event(
            Kind::Gateway,
            Event::InitApply(gateway_obj(all_ns())),
        ));
        assert_eq!(
            c.table(),
            file,
            "a partial Gateway listing replaced the table"
        );
        c.feed(Msg::Event(Kind::Gateway, Event::InitDone));
        assert_eq!(c.table(), file, "Services have neither listed nor failed");
        c.fail(Kind::Service);
        assert_eq!(
            c.table(),
            file,
            "ReferenceGrants have neither listed nor failed"
        );
        c.fail(Kind::Grant);
        assert_eq!(c.table().len(), 2);
    }

    #[test]
    fn partial_relist_keeps_table() {
        let mut c = Cluster::basic();
        c.list(Kind::Route, vec![to_service("a", T0, "a.test", "svc-a")]);
        c.feed(Msg::Event(Kind::Route, Event::Init));
        c.feed(Msg::Event(
            Kind::Route,
            Event::InitApply(to_service("b", T0, "b.test", "svc-b")),
        ));
        c.feed(Msg::Error(Kind::Route));
        assert_eq!(c.backends(), ["svc-a.apps.svc.cluster.local"]);
    }

    #[test]
    fn attachment_follows_listeners() {
        let listeners = json!([
            { "name": "https", "port": 8443, "allowedRoutes": { "namespaces": { "from": "All" } } },
            { "name": "private", "port": 9000, "allowedRoutes": { "namespaces": { "from": "Same" } } },
        ]);
        let one_listener =
            |allowed: Value| json!([{ "name": "https", "port": 8443, "allowedRoutes": allowed }]);
        let default_parent = json!({ "name": "edge", "namespace": "meridian" });
        let parent = |extra: Value| {
            let mut p = default_parent.clone();
            p.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            p
        };
        let admitted = (true, "Accepted");
        let not_allowed = (false, "NotAllowedByListeners");
        let no_parent = (false, "NoMatchingParent");
        for (what, listeners, route_ns, parent, want) in [
            (
                "default allowedRoutes is Same",
                json!([{ "name": "https", "port": 8443 }]),
                "apps",
                default_parent.clone(),
                not_allowed,
            ),
            (
                "Same admits the gateway's namespace",
                json!([{ "name": "https", "port": 8443 }]),
                "meridian",
                default_parent.clone(),
                admitted,
            ),
            (
                "a Selector cannot be evaluated",
                one_listener(json!({ "namespaces": { "from": "Selector", "selector": {} } })),
                "apps",
                default_parent.clone(),
                not_allowed,
            ),
            (
                "kinds without HTTPRoute",
                one_listener(
                    json!({ "namespaces": { "from": "All" }, "kinds": [{ "kind": "GRPCRoute" }] }),
                ),
                "apps",
                default_parent.clone(),
                not_allowed,
            ),
            (
                "kinds with HTTPRoute of another group",
                one_listener(
                    json!({ "namespaces": { "from": "All" }, "kinds": [{ "kind": "HTTPRoute", "group": "example.com" }] }),
                ),
                "apps",
                default_parent.clone(),
                not_allowed,
            ),
            (
                "kinds with HTTPRoute",
                one_listener(
                    json!({ "namespaces": { "from": "All" }, "kinds": [{ "kind": "HTTPRoute" }] }),
                ),
                "apps",
                default_parent.clone(),
                admitted,
            ),
            (
                "sectionName of an admitting listener",
                listeners.clone(),
                "apps",
                parent(json!({ "sectionName": "https" })),
                admitted,
            ),
            (
                "sectionName of a Same listener",
                listeners.clone(),
                "apps",
                parent(json!({ "sectionName": "private" })),
                not_allowed,
            ),
            (
                "sectionName of no listener",
                listeners.clone(),
                "apps",
                parent(json!({ "sectionName": "nope" })),
                no_parent,
            ),
            (
                "port of a listener",
                listeners.clone(),
                "apps",
                parent(json!({ "port": 8443 })),
                admitted,
            ),
            (
                "port of no listener",
                listeners.clone(),
                "apps",
                parent(json!({ "port": 1234 })),
                no_parent,
            ),
            (
                "sectionName and port of different listeners",
                listeners.clone(),
                "apps",
                parent(json!({ "sectionName": "https", "port": 9000 })),
                no_parent,
            ),
            (
                "any of our parentRefs may attach",
                listeners.clone(),
                "apps",
                json!([
                    parent(json!({ "sectionName": "nope" })),
                    parent(json!({ "port": 8443 }))
                ]),
                admitted,
            ),
        ] {
            let mut c = Cluster::with_gateway(vec![], listeners);
            let parents = if parent.is_array() {
                parent
            } else {
                json!([parent])
            };
            let mut spec = svc_spec();
            spec["parentRefs"] = parents;
            c.list(
                Kind::Route,
                vec![http_route(route_ns, "t", T0, json!({}), spec)],
            );
            assert_eq!(verdicts(c.outcome("t")).0, want, "{what}");
            assert_eq!(c.table().len(), usize::from(want.0), "{what}");
        }

        let mut c = Cluster::new(vec![]);
        c.list(Kind::Gateway, vec![]);
        c.fail(Kind::Service);
        c.fail(Kind::Grant);
        let (t, c) = c.one(svc_spec(), json!({}));
        assert!(t.is_empty());
        assert_eq!(verdicts(c.outcome("t")).0, no_parent, "missing Gateway");
    }

    #[test]
    fn foreign_parent_refs_ignored() {
        for parent in [
            json!({ "name": "edge", "namespace": "meridian", "kind": "Service" }),
            json!({ "name": "edge", "namespace": "meridian", "group": "" }),
            json!({ "name": "edge", "namespace": "meridian", "group": "example.com" }),
            json!({ "name": "other", "namespace": "meridian" }),
            json!({ "name": "edge", "namespace": "elsewhere" }),
            json!({ "name": "edge" }),
        ] {
            let mut s = svc_spec();
            s["parentRefs"] = json!([parent]);
            let (t, c) = Cluster::basic().one(s, json!({}));
            assert!(t.is_empty(), "claimed a route it does not own: {parent}");
            assert!(
                c.last.as_ref().unwrap().outcomes.is_empty(),
                "wrote status on {parent}"
            );
        }
        let mut s = svc_spec();
        s["parentRefs"] = json!([{ "name": "edge", "namespace": "meridian", "kind": "Gateway", "group": GATEWAY_GROUP }]);
        assert_eq!(Cluster::basic().one(s, json!({})).0.len(), 1);
    }

    #[test]
    fn static_hostnames_not_claimable() {
        let statics = vec![
            static_route(Some("headlamp.example.lan"), "127.0.0.1"),
            static_route(None, "127.0.0.1"),
        ];
        let mut c = Cluster::with_gateway(statics.clone(), all_ns());
        let hijack = http_route(
            "evil",
            "hijack",
            "2020-01-01T00:00:00Z",
            json!({ "edge.meridian/authz": "skip" }),
            json!({ "hostnames": ["Headlamp.Example.LAN.", "ok.test"], "rules": [{ "backendRefs": [{ "name": "x", "port": 80 }] }] }),
        );
        c.list(Kind::Route, vec![hijack]);
        let mut ok = served(Some("ok.test"), "/", "x.evil", 80);
        ok.authz = Authz::Skip;
        assert_eq!(c.table(), [statics[0].clone(), ok, statics[1].clone()]);
        assert_eq!(
            verdicts(c.outcome("hijack")).0,
            (false, "NoMatchingListenerHostname")
        );
    }

    #[test]
    fn conflict_resolution_order() {
        let mk = |ns: &str, name: &str, created: &str, svc: &str, path: &str| {
            http_route(
                ns,
                name,
                created,
                json!({}),
                json!({ "hostnames": ["x.test"], "rules": [{ "matches": [{ "path": { "value": path } }], "backendRefs": [{ "name": svc, "port": 80 }] }] }),
            )
        };
        let winner = |statics: Vec<Route>, routes: Vec<DynamicObject>| {
            let mut c = Cluster::with_gateway(statics, all_ns());
            c.list(Kind::Route, routes);
            c.backends()[0].split('.').next().unwrap().to_string()
        };
        let old = mk("apps", "zzz", T0, "old", "/");
        let new = mk("apps", "aaa", "2026-02-01T00:00:00Z", "new", "/");
        assert_eq!(winner(vec![], vec![old.clone(), new.clone()]), "old");
        assert_eq!(winner(vec![], vec![new.clone(), old.clone()]), "old");

        let same_age = |ns, name, svc| mk(ns, name, T0, svc, "/");
        let (b, a, z) = (
            same_age("apps", "b-route", "second"),
            same_age("apps", "a-route", "first"),
            same_age("aaa-ns", "z-route", "zero"),
        );
        assert_eq!(winner(vec![], vec![b.clone(), a.clone()]), "first");
        assert_eq!(winner(vec![], vec![a.clone(), b.clone(), z]), "zero");

        let longer = mk("apps", "longer", "2027-01-01T00:00:00Z", "long", "/api/v1");
        assert_eq!(winner(vec![], vec![old.clone(), longer]), "long");

        let file = static_route(Some("x.test"), "static-x");
        assert_eq!(winner(vec![file], vec![old]), "static-x");
    }

    #[test]
    fn cross_namespace_needs_grant() {
        let service =
            |name: Option<&str>| json!([{ "group": "", "kind": "Service", "name": name }]);
        let any_service = json!([{ "group": "", "kind": "Service" }]);
        for (what, grants, served_) in [
            ("no grant", vec![], false),
            (
                "named Service",
                vec![grant("data", "apps", service(Some("db")))],
                true,
            ),
            (
                "any Service",
                vec![grant("data", "apps", any_service.clone())],
                true,
            ),
            (
                "another Service",
                vec![grant("data", "apps", service(Some("other")))],
                false,
            ),
            (
                "another source namespace",
                vec![grant("data", "elsewhere", any_service.clone())],
                false,
            ),
            (
                "another kind",
                vec![grant(
                    "data",
                    "apps",
                    json!([{ "group": "", "kind": "Secret" }]),
                )],
                false,
            ),
            (
                "another group",
                vec![grant(
                    "data",
                    "apps",
                    json!([{ "group": "x.io", "kind": "Service" }]),
                )],
                false,
            ),
            (
                "grant in the wrong namespace",
                vec![grant("apps", "apps", any_service.clone())],
                false,
            ),
        ] {
            let mut c = Cluster::new(vec![]);
            c.list(Kind::Gateway, vec![gateway_obj(all_ns())]);
            c.fail(Kind::Service);
            c.list(Kind::Grant, grants);
            let (t, c) = c.one(
                backend_ref(json!({ "name": "db", "namespace": "data", "port": 80 })),
                json!({}),
            );
            let want = if served_ {
                (
                    vec![served(None, "/", "db.data", 80)],
                    (true, "ResolvedRefs"),
                )
            } else {
                (vec![], (false, "RefNotPermitted"))
            };
            assert_eq!((t, verdicts(c.outcome("t")).1), want, "{what}");
        }
    }

    #[test]
    fn resolved_refs_tracks_service() {
        let mut c = Cluster::new(vec![]);
        c.list(Kind::Gateway, vec![gateway_obj(all_ns())]);
        c.list(Kind::Service, vec![service("apps", "present")]);
        c.fail(Kind::Grant);
        let route = |name, svc| {
            http_route(
                "apps",
                name,
                T0,
                json!({}),
                backend_ref(json!({ "name": svc, "port": 80 })),
            )
        };
        c.list(
            Kind::Route,
            vec![route("ok", "present"), route("missing", "absent")],
        );
        assert_eq!(c.table().len(), 1);
        assert_eq!(verdicts(c.outcome("ok")).1, (true, "ResolvedRefs"));
        assert_eq!(verdicts(c.outcome("missing")).1, (false, "BackendNotFound"));

        c.apply(Kind::Service, service("apps", "absent"));
        assert_eq!(c.table().len(), 2);
        assert_eq!(verdicts(c.outcome("missing")).1, (true, "ResolvedRefs"));
        c.delete(Kind::Service, service("apps", "absent"));
        assert_eq!(c.table().len(), 1);
    }

    #[test]
    fn route_conversion_table() {
        const ACCEPTED: &[&str] = &[
            "Accepted",
            "NotAllowedByListeners",
            "NoMatchingListenerHostname",
            "NoMatchingParent",
            "UnsupportedValue",
        ];
        const RESOLVED: &[&str] = &[
            "ResolvedRefs",
            "InvalidKind",
            "RefNotPermitted",
            "BackendNotFound",
        ];
        let accepted = (true, "Accepted");
        let resolved = (true, "ResolvedRefs");
        let unsupported = (false, "UnsupportedValue");
        let svc = || vec![served(None, "/", "svc.apps", 80)];
        let skip = |mut r: Vec<Route>| {
            r[0].authz = Authz::Skip;
            r
        };
        let be = json!([{ "name": "svc", "port": 80 }]);
        let rule = |r: Value| json!({ "rules": [r] });

        for (what, spec, ann, routes, want_accepted, want_resolved) in [
            (
                "no matches is PathPrefix /, locked by default",
                svc_spec(),
                json!({}),
                svc(),
                accepted,
                resolved,
            ),
            (
                "authz skip",
                svc_spec(),
                json!({ "edge.meridian/authz": "skip" }),
                skip(svc()),
                accepted,
                resolved,
            ),
            (
                "anything but exactly skip stays locked",
                svc_spec(),
                json!({ "edge.meridian/authz": "Skip" }),
                svc(),
                accepted,
                resolved,
            ),
            (
                "rewrite-host is carried",
                svc_spec(),
                json!({ "edge.meridian/rewrite-host": "mesh.name" }),
                vec![Route {
                    rewrite_host: Some("mesh.name".into()),
                    ..served(None, "/", "svc.apps", 80)
                }],
                accepted,
                resolved,
            ),
            (
                "hostnames x matches fan out, hostnames normalised",
                json!({ "hostnames": ["a.example", "B.example."], "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/one" } }, { "path": { "value": "/two/../2" } }],
                    "backendRefs": [{ "name": "svc", "port": 8080 }] }] }),
                json!({}),
                vec![
                    served(Some("a.example"), "/one", "svc.apps", 8080),
                    served(Some("b.example"), "/one", "svc.apps", 8080),
                    served(Some("a.example"), "/2", "svc.apps", 8080),
                    served(Some("b.example"), "/2", "svc.apps", 8080),
                ],
                accepted,
                resolved,
            ),
            (
                "zero weight gets no traffic",
                rule(
                    json!({ "backendRefs": [{ "name": "live", "port": 80, "weight": 5 }, { "name": "drained", "port": 80, "weight": 0 }] }),
                ),
                json!({}),
                vec![served(None, "/", "live.apps", 80)],
                accepted,
                resolved,
            ),
            (
                "explicit own namespace is not cross-namespace",
                backend_ref(
                    json!({ "name": "svc", "namespace": "apps", "port": 80, "kind": "Service", "group": "" }),
                ),
                json!({}),
                svc(),
                accepted,
                resolved,
            ),
            (
                "cross-namespace without the grant API",
                backend_ref(json!({ "name": "db", "namespace": "data", "port": 80 })),
                json!({}),
                vec![],
                accepted,
                (false, "RefNotPermitted"),
            ),
            (
                "kind",
                backend_ref(json!({ "name": "x", "port": 80, "kind": "ConfigMap" })),
                json!({}),
                vec![],
                accepted,
                (false, "InvalidKind"),
            ),
            (
                "group",
                backend_ref(json!({ "name": "x", "port": 80, "group": "example.com" })),
                json!({}),
                vec![],
                accepted,
                (false, "InvalidKind"),
            ),
            (
                "InvalidKind outranks RefNotPermitted and BackendNotFound",
                json!({ "rules": [
                    { "backendRefs": [{ "name": "x" }] },
                    { "backendRefs": [{ "name": "db", "namespace": "data", "port": 80 }] },
                    { "backendRefs": [{ "name": "x", "port": 80, "kind": "Secret" }] },
                ] }),
                json!({}),
                vec![],
                accepted,
                (false, "InvalidKind"),
            ),
            (
                "RefNotPermitted outranks BackendNotFound",
                json!({ "rules": [{ "backendRefs": [{ "name": "x" }] }, { "backendRefs": [{ "name": "db", "namespace": "data", "port": 80 }] }] }),
                json!({}),
                vec![],
                accepted,
                (false, "RefNotPermitted"),
            ),
            (
                "portless",
                backend_ref(json!({ "name": "svc" })),
                json!({}),
                vec![],
                accepted,
                (false, "BackendNotFound"),
            ),
            (
                "no backendRefs",
                rule(json!({ "backendRefs": [] })),
                json!({}),
                vec![],
                accepted,
                (false, "BackendNotFound"),
            ),
            (
                "header match",
                rule(
                    json!({ "matches": [{ "headers": [{ "name": "x", "value": "y" }] }], "backendRefs": be }),
                ),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "method match",
                rule(
                    json!({ "matches": [{ "method": "POST", "path": { "value": "/a" } }], "backendRefs": be }),
                ),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "query match",
                rule(
                    json!({ "matches": [{ "queryParams": [{ "name": "a", "value": "b" }] }], "backendRefs": be }),
                ),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "exact path",
                rule(
                    json!({ "matches": [{ "path": { "type": "Exact", "value": "/abc" } }], "backendRefs": be }),
                ),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "non-canonical prefix",
                rule(json!({ "matches": [{ "path": { "value": "/a/%2fb" } }], "backendRefs": be })),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "rule filter",
                rule(json!({ "filters": [{ "type": "URLRewrite" }], "backendRefs": be })),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "backendRef filter",
                rule(json!({ "backendRefs": [{ "name": "svc", "port": 80, "filters": [{}] }] })),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "weighted split",
                rule(
                    json!({ "backendRefs": [{ "name": "a", "port": 80, "weight": 1 }, { "name": "b", "port": 80 }] }),
                ),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "is a wildcard",
                json!({ "hostnames": ["*.example.test"], "rules": [{ "backendRefs": be }] }),
                json!({}),
                vec![],
                unsupported,
                resolved,
            ),
            (
                "supported parts of a partly unsupported rule are served",
                rule(json!({ "matches": [
                    { "path": { "type": "PathPrefix", "value": "/ok" } },
                    { "path": { "type": "Exact", "value": "/no" } },
                ], "backendRefs": be })),
                json!({}),
                vec![served(None, "/ok", "svc.apps", 80)],
                unsupported,
                resolved,
            ),
        ] {
            let (t, c) = Cluster::basic().one(spec, ann);
            let (a, r) = verdicts(c.outcome("t"));
            assert_eq!((t, a, r), (routes, want_accepted, want_resolved), "{what}");
            assert!(ACCEPTED.contains(&a.1) && RESOLVED.contains(&r.1), "{what}");
        }
    }

    #[test]
    fn status_names_dropped_parts() {
        let spec = json!({
            "parentRefs": [
                { "name": "other" },
                { "name": "edge", "namespace": "meridian", "sectionName": "https", "port": 8443 },
            ],
            "rules": [
                { "filters": [{}], "backendRefs": [{ "name": "a", "port": 80 }] },
                { "matches": [{ "method": "GET" }], "backendRefs": [{ "name": "b", "port": 80 }] },
                { "backendRefs": [{ "name": "c" }] },
                { "backendRefs": [{ "name": "d", "kind": "Secret" }] },
            ],
        });
        let (_, c) = Cluster::basic().one(spec, json!({}));
        let o = c.outcome("t");
        assert_eq!(
            o.parent,
            json!({ "name": "edge", "namespace": "meridian", "kind": "Gateway", "group": GATEWAY_GROUP,
                    "sectionName": "https", "port": 8443 })
        );
        assert_eq!(
            o.accepted.message,
            "rule 0: filters, rule 1: method matches; unsupported parts were dropped, the rest is served"
        );
        assert_eq!(
            o.resolved.message,
            "backendRef c has no port; backendRef d is a /Secret; only Service is supported"
        );

        let (_, c) = Cluster::basic().one(svc_spec(), json!({}));
        let o = c.outcome("t");
        assert_eq!(
            o.parent,
            json!({ "name": "edge", "namespace": "meridian", "kind": "Gateway", "group": GATEWAY_GROUP })
        );
        assert_eq!(o.accepted.message, "1 route(s) served");
    }
}
