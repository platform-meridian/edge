use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use edge_kube::ServiceView;
use kube::Client;
use tokio::sync::watch;

use crate::zone::Zone;

pub struct ZoneState {
    domain: String,
    zone: ArcSwap<Zone>,
    synced: watch::Sender<bool>,
    /// A restarted watch's listing is a prefix of the API's: keep the old zone.
    relisting: AtomicBool,
}

impl ZoneState {
    pub fn new(domain: &str) -> Arc<Self> {
        Arc::new(Self {
            domain: domain.to_string(),
            zone: ArcSwap::from_pointee(Zone::unsynced(domain)),
            synced: watch::Sender::new(false),
            relisting: AtomicBool::new(false),
        })
    }

    pub fn zone(&self) -> Arc<Zone> {
        self.zone.load_full()
    }

    pub fn is_synced(&self) -> bool {
        *self.synced.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.synced.subscribe()
    }

    pub fn on_change(&self, view: &ServiceView) {
        if self.is_synced() && !self.relisting.load(Ordering::SeqCst) {
            self.rebuild(view);
        }
    }

    pub fn begin_listing(&self) {
        self.relisting.store(true, Ordering::SeqCst);
    }

    pub fn on_synced(&self, view: &ServiceView) {
        self.rebuild(view);
        self.relisting.store(false, Ordering::SeqCst);
        self.synced.send_replace(true);
        tracing::info!(services = view.services.len(), "zone synced");
    }

    fn rebuild(&self, view: &ServiceView) {
        let z = Zone::build(&self.domain, view.services.values(), &view.slices);
        self.zone.store(Arc::new(z));
    }
}

pub async fn run(client: Client, state: Arc<ZoneState>) -> anyhow::Result<()> {
    state.begin_listing();
    let on_change = state.clone();
    edge_kube::run(
        client,
        move |view, _touched| {
            on_change.on_change(view);
            Ok(())
        },
        move |view| {
            state.on_synced(view);
            Ok(())
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{Local, QType};
    use k8s_openapi::api::core::v1::{Service, ServiceSpec};

    fn svc(name: &str, ip: &str) -> Service {
        let mut s = Service::default();
        s.metadata.name = Some(name.into());
        s.metadata.namespace = Some("default".into());
        s.spec = Some(ServiceSpec {
            cluster_ip: Some(ip.into()),
            ..Default::default()
        });
        s
    }

    fn view(names: &[(&str, &str)]) -> ServiceView {
        let mut v = ServiceView::default();
        for (n, ip) in names {
            v.apply_service(svc(n, ip));
        }
        v
    }

    #[test]
    fn unsynced_names_not_denied() {
        let st = ZoneState::new("cluster.local");
        st.on_change(&view(&[("a", "10.96.0.1")]));
        st.on_change(&view(&[("a", "10.96.0.1"), ("b", "10.96.0.2")]));
        assert!(!st.is_synced());
        assert_eq!(
            st.zone().resolve("b.default.svc.cluster.local", QType::A),
            Local::NotSynced
        );
        assert_eq!(st.zone().resolve("example.com", QType::A), Local::Forward);
    }

    #[test]
    fn synced_zone_is_whole_listing() {
        let st = ZoneState::new("cluster.local");
        st.on_synced(&view(&[("a", "10.96.0.1"), ("b", "10.96.0.2")]));
        assert!(st.is_synced());
        assert!(matches!(
            st.zone().resolve("b.default.svc.cluster.local", QType::A),
            Local::A(_)
        ));
        assert_eq!(
            st.zone().resolve("c.default.svc.cluster.local", QType::A),
            Local::NxDomain
        );
        st.on_change(&view(&[("c", "10.96.0.3")]));
        assert!(matches!(
            st.zone().resolve("c.default.svc.cluster.local", QType::A),
            Local::A(_)
        ));
        assert_eq!(
            st.zone().resolve("a.default.svc.cluster.local", QType::A),
            Local::NxDomain
        );
    }

    #[test]
    fn relist_keeps_old_zone() {
        let st = ZoneState::new("cluster.local");
        st.on_synced(&view(&[("a", "10.96.0.1"), ("b", "10.96.0.2")]));
        st.begin_listing();
        st.on_change(&view(&[("a", "10.96.0.1")]));
        assert!(
            matches!(
                st.zone().resolve("b.default.svc.cluster.local", QType::A),
                Local::A(_)
            ),
            "b was denied mid-relist"
        );
        st.on_synced(&view(&[("a", "10.96.0.1"), ("c", "10.96.0.3")]));
        assert_eq!(
            st.zone().resolve("b.default.svc.cluster.local", QType::A),
            Local::NxDomain,
            "the completed relist is authoritative"
        );
        assert!(matches!(
            st.zone().resolve("c.default.svc.cluster.local", QType::A),
            Local::A(_)
        ));
        st.on_change(&view(&[("d", "10.96.0.4")]));
        assert!(
            matches!(
                st.zone().resolve("d.default.svc.cluster.local", QType::A),
                Local::A(_)
            ),
            "changes apply again after the relist"
        );
    }
}
