//! Signs the PodCertificateRequests for [`policy::SIGNER`] and publishes the CA root as
//! a ClusterTrustBundle. A certificate issued while the clock ran ahead starts in the
//! future once the clock steps back, and kubelet renews it only at its equally future
//! refresh time, so the signer deletes that pod for its controller to recreate.
//! It does the same when the node gains an address a `node` certificate lacks.

mod api;
mod ca;
mod kubelet;
mod policy;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use edge_common::health::Heartbeat;
use futures::StreamExt;
use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use k8s_openapi::api::core::v1::{Node, Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{
    ApiResource, DeleteParams, DynamicObject, GroupVersionKind, Patch, PatchParams, Preconditions,
};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};

use api::{PodCertificateRequest, Status};
use ca::{Ca, Source};
use policy::{Decision, SIGNER, Unit};

/// The ClusterTrustBundle's name must start with the signer's, `/` as `:`.
const BUNDLE_NAME: &str = "edge.meridian:node:ca";
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// The client sets no response timeout, so one hung apiserver call would stall
/// the loop for good.
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// Six loop ticks, and twice the longest an apiserver call may take.
const STALE_AFTER: Duration = Duration::from_secs(30);
const _: () = assert!(
    RETRY_INTERVAL.as_secs() + CALL_TIMEOUT.as_secs() < STALE_AFTER.as_secs(),
    "a pass waiting on a hung call must not go stale"
);
/// Re-applied this often even unchanged, so a deleted bundle comes back.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(600);
/// kube-apiserver's own tolerance for an issued notBefore; within it the clocks
/// agree, and a slewing clock catches up sooner than a recreated pod would.
const CLOCK_SKEW_SECS: i64 = 300;

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();
    let env = |name| std::env::var(name).unwrap_or_default();
    let node = env("NODE_NAME");
    anyhow::ensure!(
        !node.is_empty(),
        "NODE_NAME: unset; set it from spec.nodeName"
    );
    let unit = Unit::new(&env("EDGE_SIGNER_DOMAIN"));
    let health =
        std::env::var("EDGE_SIGNER_HEALTH_LISTEN").unwrap_or_else(|_| "0.0.0.0:9750".into());
    edge_common::sandbox::restrict(&edge_common::sandbox::signer(&health));
    run(health, &node, &unit)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[tokio::main]
async fn run(health: String, node: &str, unit: &Unit) -> anyhow::Result<()> {
    let mut term = edge_common::Terminator::new();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let heartbeat = Heartbeat::default();
    tokio::spawn(edge_common::health::serve(
        health,
        heartbeat.clone(),
        STALE_AFTER,
    ));
    tracing::info!(
        signer = SIGNER,
        bundle = BUNDLE_NAME,
        ca = ca::SECRET,
        node,
        ?unit,
        "edge-signer: ready"
    );

    let mut outage = edge_common::Outage::default();
    let client = loop {
        heartbeat.beat();
        let r = Client::try_default().await;
        outage.observe("kubernetes client", &r);
        if let Ok(c) = r {
            break c;
        }
        tokio::select! {
            _ = tokio::time::sleep(RETRY_INTERVAL) => {}
            _ = term.wait() => return Ok(()),
        }
    };
    tokio::select! {
        r = serve(client, node, unit, host_addresses, &heartbeat) => r,
        _ = term.wait() => Ok(()),
    }
}

/// The CA Secret as last listed: unknown until the first listing answers.
#[derive(Default)]
struct CaSecret {
    listing: Option<Secret>,
    current: Option<Option<Secret>>,
}

impl CaSecret {
    fn apply(&mut self, ev: Event<Secret>) {
        match ev {
            Event::Init => self.listing = None,
            Event::InitApply(s) => self.listing = Some(s),
            Event::InitDone => self.current = Some(self.listing.take()),
            Event::Apply(s) => self.current = Some(Some(s)),
            Event::Delete(_) => self.current = Some(None),
        }
    }

    /// An apiserver that refuses the first listing (no RBAC, say) leaves it as
    /// good as missing; once known, a refusal keeps what was known.
    fn failed(&mut self, e: &watcher::Error) {
        let answered = matches!(
            e,
            watcher::Error::InitialListFailed(kube::Error::Api(_))
                | watcher::Error::WatchStartFailed(kube::Error::Api(_))
                | watcher::Error::WatchFailed(kube::Error::Api(_))
                | watcher::Error::WatchError(_)
        );
        if answered && self.current.is_none() {
            self.current = Some(None);
        }
    }

    fn known(&self) -> Option<Option<&Secret>> {
        self.current.as_ref().map(Option::as_ref)
    }
}

/// Every address a client could reach the host on. Polled, as edge-cni polls
/// its node addresses: a link change is seen within a tick.
fn host_addresses() -> nix::Result<Vec<IpAddr>> {
    let mut out: Vec<IpAddr> = nix::ifaddrs::getifaddrs()?
        .filter_map(|i| {
            let a = i.address?;
            a.as_sockaddr_in()
                .map(|s| IpAddr::V4(s.ip()))
                .or_else(|| a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))
        })
        .filter(reachable)
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

fn reachable(ip: &IpAddr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(a) => !a.is_link_local() && !a.is_broadcast(),
            IpAddr::V6(a) => !a.is_unicast_link_local(),
        }
}

/// Beats only from the loop itself, so a wedged loop goes stale while an
/// apiserver outage does not.
async fn serve(
    client: Client,
    node: &str,
    unit: &Unit,
    host: impl Fn() -> nix::Result<Vec<IpAddr>>,
    heartbeat: &Heartbeat,
) -> anyhow::Result<()> {
    let requests: Api<PodCertificateRequest> = Api::all(client.clone());
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    let csrs: Api<CertificateSigningRequest> = Api::all(client.clone());
    let nodes: Api<Node> = Api::all(client.clone());
    let bundles: Api<DynamicObject> = Api::all_with(
        client.clone(),
        &ApiResource::from_gvk(&GroupVersionKind::gvk(
            "certificates.k8s.io",
            "v1",
            "ClusterTrustBundle",
        )),
    );

    let watch_requests = || edge_kube::watch(requests.clone(), "podcertificaterequests").boxed();
    let watch_secret = || {
        let named = watcher::Config::default().fields(&format!("metadata.name={}", ca::SECRET));
        edge_kube::watch_with(secrets.clone(), named, "node CA secret").boxed()
    };
    let watch_csrs = || {
        let kubelet =
            watcher::Config::default().fields(&format!("spec.signerName={}", kubelet::SIGNER));
        edge_kube::watch_with(csrs.clone(), kubelet, "certificatesigningrequests").boxed()
    };
    let (mut events, mut secret_events, mut csr_events) =
        (watch_requests(), watch_secret(), watch_csrs());
    let mut secret = CaSecret::default();
    let mut source: Option<Source> = None;
    let mut pending = BTreeMap::new();
    let mut issued = BTreeMap::new();
    let mut kubelet_csrs = kubelet::Pending::default();
    let mut published: Option<(String, Instant)> = None;
    let mut bundle_outage = edge_common::Outage::default();
    let mut status_outage = edge_common::Outage::default();
    let mut pod_outage = edge_common::Outage::default();
    let mut approval_outage = edge_common::Outage::default();
    let mut address_outage = edge_common::Outage::default();
    let mut unit = unit.clone();
    let mut held = Vec::new();
    let mut tick = tokio::time::interval(RETRY_INTERVAL);
    loop {
        heartbeat.beat();
        tokio::select! {
            ev = events.next() => match ev {
                Some(Ok(ev)) => apply_event(node, &mut pending, &mut issued, ev),
                Some(Err(_)) => continue,
                None => events = watch_requests(),
            },
            ev = secret_events.next() => match ev {
                Some(Ok(ev)) => secret.apply(ev),
                Some(Err(e)) => secret.failed(&e),
                None => secret_events = watch_secret(),
            },
            ev = csr_events.next() => match ev {
                Some(Ok(ev)) => kubelet_csrs.apply(ev),
                Some(Err(_)) => continue,
                None => csr_events = watch_csrs(),
            },
            _ = tick.tick() => {}
        }

        let now = now();
        let approved = approve_kubelets(&csrs, &nodes, &mut kubelet_csrs, heartbeat, now).await;
        approval_outage.observe("certificatesigningrequest approval", &approved);

        let Some(known) = secret.known() else {
            continue;
        };
        let source = match &mut source {
            Some(s) => {
                s.refresh(known, now)?;
                s
            }
            None => source.insert(Source::new(known, now)?),
        };
        let r = host();
        address_outage.observe("node addresses", &r);
        if let Ok(now_held) = r {
            held = now_held;
        }
        let permitted: Vec<IpAddr> = held
            .iter()
            .copied()
            .filter(|ip| source.ca.permits(*ip))
            .collect();
        if permitted != unit.addresses {
            tracing::info!(addresses = ?permitted, ?held, "node addresses");
            unit.addresses = permitted;
        }

        let root = source.ca.root();
        if bundle_due(&published, root) {
            let r = bounded(publish(&bundles, root)).await;
            heartbeat.beat();
            bundle_outage.observe("clustertrustbundle", &r);
            if r.is_ok() {
                published = Some((root.to_string(), Instant::now()));
            }
        }

        let mut settled = Vec::new();
        for (key, pcr) in &pending {
            let status = settle(pcr, &source.ca, &unit, now);
            let requests = Api::<PodCertificateRequest>::namespaced(client.clone(), &key.0);
            let r = bounded(requests.patch_status(
                &key.1,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "status": status })),
            ))
            .await;
            heartbeat.beat();
            status_outage.observe("podcertificaterequest status", &r);
            if r.is_ok() {
                log_verdict(pcr, &status);
                settled.push(key.clone());
            }
        }
        for key in settled {
            pending.remove(&key);
        }

        for (key, why) in due(&issued, &unit.addresses, now) {
            let Some(cert) = issued.get(&key) else {
                continue;
            };
            let pods = Api::<Pod>::namespaced(client.clone(), &key.0);
            let r = bounded(recreate(&pods, cert)).await;
            heartbeat.beat();
            pod_outage.observe("pod deletion", &r);
            if let Ok(deleted) = r {
                if deleted {
                    tracing::info!(
                        namespace = key.0,
                        pod = cert.pod,
                        not_before = %time(cert.not_before).0,
                        addresses = ?cert.ips,
                        "{why}: pod deleted for recreation"
                    );
                }
                let uid = cert.uid.clone();
                issued.retain(|_, c| c.uid != uid);
            }
        }
    }
}

/// The certificates whose pods are due for recreation, and why. Only a gained
/// address counts, so an address that comes and goes costs no restart.
fn due(
    issued: &BTreeMap<RequestKey, Issued>,
    addresses: &[IpAddr],
    now: i64,
) -> Vec<(RequestKey, &'static str)> {
    let newest = |c: &Issued| {
        !issued
            .values()
            .any(|o| o.follows && o.uid == c.uid && o.not_before > c.not_before)
    };
    issued
        .iter()
        .filter_map(|(k, c)| {
            let why = if c.dated_ahead(now) {
                "certificate dated ahead of the clock"
            } else if c.follows && addresses.iter().any(|a| !c.ips.contains(a)) && newest(c) {
                "certificate lacks a node address"
            } else {
                return None;
            };
            Some((k.clone(), why))
        })
        .collect()
}

/// A request that is not the kubelet's own stays pending: its Node may yet
/// report the names it asks for.
async fn approve_kubelets(
    csrs: &Api<CertificateSigningRequest>,
    nodes: &Api<Node>,
    pending: &mut kubelet::Pending,
    heartbeat: &Heartbeat,
    now: i64,
) -> kube::Result<()> {
    let mut result = Ok(());
    let names: Vec<String> = pending.0.keys().cloned().collect();
    for name in names {
        let csr = &pending.0[&name].0;
        let node = match kubelet::requesting_node(csr) {
            Ok(n) => n,
            Err(why) => {
                pending.passed_over(&name, why);
                continue;
            }
        };
        let got = bounded(nodes.get_opt(&node)).await;
        heartbeat.beat();
        let verdict = match got {
            Ok(Some(n)) => kubelet::check_names(csr, &n),
            Ok(None) => Err(format!("no Node {node}")),
            Err(e) => {
                result = Err(e);
                continue;
            }
        };
        if let Err(why) = verdict {
            pending.passed_over(&name, why);
            continue;
        }
        let r = bounded(csrs.patch_approval(
            &name,
            &PatchParams::default(),
            &Patch::Merge(kubelet::approval(time(now))),
        ))
        .await;
        heartbeat.beat();
        match r {
            Ok(_) => {
                tracing::info!(csr = name, node, "kubelet serving certificate approved");
                pending.0.remove(&name);
            }
            Err(e) => result = Err(e),
        }
    }
    result
}

async fn bounded<T>(call: impl Future<Output = kube::Result<T>>) -> kube::Result<T> {
    tokio::time::timeout(CALL_TIMEOUT, call)
        .await
        .unwrap_or_else(|elapsed| Err(kube::Error::Service(elapsed.into())))
}

#[derive(Debug, PartialEq)]
struct Issued {
    pod: String,
    uid: String,
    not_before: i64,
    follows: bool,
    ips: Vec<IpAddr>,
}

impl Issued {
    fn of(pcr: &PodCertificateRequest) -> Option<Self> {
        Some(Self {
            pod: pcr.spec.pod_name.clone(),
            uid: pcr.spec.pod_uid.clone(),
            not_before: pcr.status.not_before.as_ref()?.0.as_second(),
            follows: policy::follows_node(&pcr.spec),
            ips: ca::leaf_addresses(pcr.status.certificate_chain.as_deref().unwrap_or_default()),
        })
    }

    fn dated_ahead(&self, now: i64) -> bool {
        self.not_before > now + CLOCK_SKEW_SECS
    }
}

/// The UID precondition keeps a replacement of the same name alive.
async fn recreate(pods: &Api<Pod>, cert: &Issued) -> kube::Result<bool> {
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(cert.uid.clone()),
            resource_version: None,
        }),
        ..DeleteParams::default()
    };
    deleted_unless_gone(pods.delete(&cert.pod, &params).await.map(drop))
}

fn deleted_unless_gone(r: kube::Result<()>) -> kube::Result<bool> {
    match r {
        Ok(()) => Ok(true),
        Err(kube::Error::Api(s)) if s.is_not_found() || s.is_conflict() => Ok(false),
        Err(e) => Err(e),
    }
}

fn bundle_due(published: &Option<(String, Instant)>, pem: &str) -> bool {
    published
        .as_ref()
        .is_none_or(|(last, at)| last != pem || at.elapsed() >= REPUBLISH_INTERVAL)
}

async fn publish(bundles: &Api<DynamicObject>, pem: &str) -> kube::Result<()> {
    let body = serde_json::json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "ClusterTrustBundle",
        "metadata": { "name": BUNDLE_NAME },
        "spec": { "signerName": SIGNER, "trustBundle": pem },
    });
    bundles
        .patch(
            BUNDLE_NAME,
            &PatchParams::apply("edge-signer").force(),
            &Patch::Apply(&body),
        )
        .await
        .map(drop)
}

type RequestKey = (String, String);

/// A relist re-delivers every live request, so it starts both maps afresh and a
/// request deleted during a disconnect drops out. Only this node's requests are
/// answered: their addresses are its own.
fn apply_event(
    node: &str,
    pending: &mut BTreeMap<RequestKey, PodCertificateRequest>,
    issued: &mut BTreeMap<RequestKey, Issued>,
    ev: Event<PodCertificateRequest>,
) {
    let key = |p: &PodCertificateRequest| (p.namespace().unwrap_or_default(), p.name_any());
    match ev {
        Event::Init => {
            pending.clear();
            issued.clear();
        }
        Event::InitApply(p) | Event::Apply(p) => {
            let k = key(&p);
            pending.remove(&k);
            issued.remove(&k);
            if p.spec.signer_name == SIGNER && p.spec.node_name == node {
                if !p.is_settled() {
                    pending.insert(k, p);
                } else if let Some(cert) = Issued::of(&p) {
                    issued.insert(k, cert);
                }
            }
        }
        Event::Delete(p) => {
            pending.remove(&key(&p));
            issued.remove(&key(&p));
        }
        Event::InitDone => {}
    }
}

fn settle(pcr: &PodCertificateRequest, ca: &Ca, unit: &Unit, now: i64) -> Status {
    let condition = |type_: &str, reason: &str, message: String| Condition {
        type_: type_.into(),
        status: "True".into(),
        reason: reason.into(),
        message,
        last_transition_time: time(now),
        observed_generation: None,
    };
    let key = match ca::requested_key(&pcr.spec.stub_pkcs10_request.0) {
        Ok(k) => k,
        Err(ca::Refusal { reason, message }) => {
            return Status {
                conditions: vec![condition("Denied", reason, message)],
                ..Status::default()
            };
        }
    };
    let (dns, ips, lifetime) = match policy::decide(&pcr.spec, unit) {
        Decision::Issue { dns, ips, lifetime } => (dns, ips, lifetime),
        Decision::Deny { reason, message } => {
            return Status {
                conditions: vec![condition("Denied", reason, message)],
                ..Status::default()
            };
        }
    };
    match ca.issue(&key, &dns, &ips, now, lifetime) {
        Ok(leaf) => Status {
            conditions: vec![condition("Issued", "Issued", String::new())],
            certificate_chain: Some(leaf.chain),
            not_before: Some(time(leaf.not_before)),
            // Halfway: the old certificate's second half is the margin for a
            // signer or apiserver that is down when the kubelet asks.
            begin_refresh_at: Some(time((leaf.not_before + leaf.not_after) / 2)),
            not_after: Some(time(leaf.not_after)),
        },
        Err(e) => Status {
            conditions: vec![condition("Failed", "SigningFailed", format!("{e:#}"))],
            ..Status::default()
        },
    }
}

fn time(unix: i64) -> Time {
    Time(k8s_openapi::jiff::Timestamp::from_second(unix).unwrap_or_default())
}

fn log_verdict(pcr: &PodCertificateRequest, status: &Status) {
    let ns = pcr.namespace().unwrap_or_default();
    let c = &status.conditions[0];
    if c.type_ == "Issued" {
        tracing::info!(namespace = ns, pod = pcr.spec.pod_name, "issued");
    } else {
        tracing::warn!(
            namespace = ns,
            pod = pcr.spec.pod_name,
            verdict = c.type_,
            reason = c.reason,
            message = c.message
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::tests::{NOW, TestCert, csr, file_ca, intermediate, root, rsa_csr, secret};
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use rustls_pki_types::pem::PemObject;
    use x509_parser::prelude::*;

    fn unit() -> Unit {
        Unit::new("example.lan")
    }

    fn request(csr: Vec<u8>, annotations: &[(&str, &str)], max: i32) -> PodCertificateRequest {
        PodCertificateRequest {
            metadata: kube::api::ObjectMeta {
                name: Some("r".into()),
                namespace: Some("edge".into()),
                ..Default::default()
            },
            spec: api::Spec {
                signer_name: SIGNER.into(),
                pod_name: "p".into(),
                pod_uid: "u".into(),
                node_name: "n".into(),
                max_expiration_seconds: Some(max),
                stub_pkcs10_request: k8s_openapi::ByteString(csr),
                unverified_user_annotations: annotations
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            status: Status::default(),
        }
    }

    fn secs(t: &Option<Time>) -> i64 {
        t.as_ref().unwrap().0.as_second()
    }

    #[test]
    fn issued_status_passes_apiserver_validation() {
        let ca = file_ca(NOW);
        for max in [3600, 864_000, 7_862_400] {
            let (key, der) = csr(&PKCS_ECDSA_P256_SHA256);
            let pcr = request(der, &[("edge.meridian/dns-names", "example.lan")], max);
            let s = settle(&pcr, &ca, &unit(), NOW);
            assert_eq!(s.conditions.len(), 1);
            let c = &s.conditions[0];
            assert_eq!(
                (c.type_.as_str(), c.status.as_str(), c.reason.as_str()),
                ("Issued", "True", "Issued")
            );
            let mut answered = pcr.clone();
            answered.status = s.clone();
            assert!(!pcr.is_settled() && answered.is_settled());

            let chain = s.certificate_chain.as_deref().unwrap();
            let der = rustls_pki_types::CertificateDer::from_pem_slice(chain.as_bytes()).unwrap();
            let (_, leaf) = parse_x509_certificate(&der).unwrap();
            let (nb, na, refresh) = (
                secs(&s.not_before),
                secs(&s.not_after),
                secs(&s.begin_refresh_at),
            );
            assert_eq!(nb, leaf.validity().not_before.timestamp());
            assert_eq!(na, leaf.validity().not_after.timestamp());
            assert!((nb - NOW).abs() < 300, "notBefore within 5 minutes of now");
            assert!(
                na - nb >= 3600 && na - nb <= i64::from(max),
                "lifetime {max}"
            );
            assert!(
                refresh >= nb + 600 && refresh <= na - 600,
                "beginRefreshAt {max}"
            );
            assert_eq!(refresh, nb + i64::from(max) / 2);
            assert_eq!(
                leaf.public_key().subject_public_key.data.as_ref(),
                key.public_key_raw()
            );
            for name in leaf
                .subject_alternative_name()
                .unwrap()
                .unwrap()
                .value
                .general_names
                .iter()
            {
                if let GeneralName::DNSName(d) = name {
                    assert!(
                        !d.is_empty()
                            && !d.contains("..")
                            && !d.starts_with('.')
                            && !d.ends_with('.')
                    );
                }
            }
        }
    }

    #[test]
    fn rsa_requests_issued_others_told_what_is() {
        let ca = file_ca(NOW);
        let names = [("edge.meridian/dns-names", "example.lan")];
        for bits in [3072, 4096] {
            let (key, der) = rsa_csr(bits);
            let s = settle(&request(der, &names, 3600), &ca, &unit(), NOW);
            assert_eq!(s.conditions[0].type_, "Issued", "RSA{bits}");
            let chain = s.certificate_chain.unwrap();
            let der = rustls_pki_types::CertificateDer::from_pem_slice(chain.as_bytes()).unwrap();
            let (_, leaf) = parse_x509_certificate(&der).unwrap();
            assert_eq!(
                leaf.public_key().subject_public_key.data.as_ref(),
                key.public_key_raw()
            );
        }
        let s = settle(&request(rsa_csr(2048).1, &names, 3600), &ca, &unit(), NOW);
        let c = &s.conditions[0];
        assert_eq!(
            (c.type_.as_str(), c.reason.as_str()),
            ("Denied", "UnsupportedKeyType")
        );
        assert_eq!(
            c.message,
            "a 2048-bit RSA key is not supported: use keyType ECDSAP256, RSA3072 or RSA4096"
        );
    }

    #[test]
    fn denial_has_only_condition() {
        let ca = file_ca(NOW);
        let p384 = csr(&rcgen::PKCS_ECDSA_P384_SHA384).1;
        let p256 = csr(&PKCS_ECDSA_P256_SHA256).1;
        let rsa2048 = rsa_csr(2048).1;
        for (pcr, reason) in [
            (
                request(p384, &[("edge.meridian/dns-names", "example.lan")], 3600),
                "UnsupportedKeyType",
            ),
            (
                request(rsa2048, &[("edge.meridian/dns-names", "example.lan")], 3600),
                "UnsupportedKeyType",
            ),
            (
                request(vec![], &[("edge.meridian/dns-names", "example.lan")], 3600),
                "InvalidStubPKCS10Request",
            ),
            (
                request(p256, &[("edge.meridian/dns-names", "example.com")], 3600),
                "InvalidUnverifiedUserAnnotations",
            ),
        ] {
            let s = settle(&pcr, &ca, &unit(), NOW);
            assert_eq!(s.conditions.len(), 1);
            assert_eq!(
                (
                    s.conditions[0].type_.as_str(),
                    s.conditions[0].reason.as_str()
                ),
                ("Denied", reason)
            );
            assert_eq!(
                Status {
                    conditions: vec![],
                    ..s
                },
                Status::default(),
                "non-condition fields must be empty"
            );
        }
    }

    #[test]
    fn status_uses_api_field_names() {
        let ca = file_ca(NOW);
        let pcr = request(
            csr(&PKCS_ECDSA_P256_SHA256).1,
            &[("edge.meridian/dns-names", "localhost")],
            3600,
        );
        let v = serde_json::to_value(settle(&pcr, &ca, &unit(), NOW)).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "beginRefreshAt",
                "certificateChain",
                "conditions",
                "notAfter",
                "notBefore"
            ]
        );
        assert_eq!(v["notBefore"], "2026-09-21T14:13:20Z");
        assert_eq!(
            v["conditions"][0]["lastTransitionTime"],
            "2026-09-21T14:13:20Z"
        );
    }

    #[test]
    fn pending_holds_own_unanswered_requests() {
        let mut pending = BTreeMap::new();
        let mut issued = BTreeMap::new();
        let mk = |name: &str, signer: &str, settled: bool| {
            let mut p = request(vec![], &[], 3600);
            p.metadata.name = Some(name.into());
            p.spec.signer_name = signer.into();
            if settled {
                p.status.conditions = vec![Condition {
                    type_: "Issued".into(),
                    status: "True".into(),
                    reason: "Issued".into(),
                    message: String::new(),
                    last_transition_time: time(NOW),
                    observed_generation: None,
                }];
            }
            p
        };
        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Apply(mk("a", SIGNER, false)),
        );
        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Apply(mk("other", "example.com/x", false)),
        );
        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Apply(mk("done", SIGNER, true)),
        );
        let mut elsewhere = mk("elsewhere", SIGNER, false);
        elsewhere.spec.node_name = "m".into();
        apply_event("n", &mut pending, &mut issued, Event::Apply(elsewhere));
        assert_eq!(
            pending.keys().map(|k| k.1.as_str()).collect::<Vec<_>>(),
            ["a"]
        );

        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Apply(mk("a", SIGNER, true)),
        );
        assert!(pending.is_empty(), "settled elsewhere");

        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Apply(mk("b", SIGNER, false)),
        );
        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Delete(mk("b", SIGNER, false)),
        );
        assert!(pending.is_empty(), "deleted");

        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Apply(mk("gone", SIGNER, false)),
        );
        apply_event("n", &mut pending, &mut issued, Event::Init);
        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::InitApply(mk("c", SIGNER, false)),
        );
        apply_event("n", &mut pending, &mut issued, Event::InitDone);
        assert_eq!(
            pending.keys().map(|k| k.1.as_str()).collect::<Vec<_>>(),
            ["c"]
        );
        assert!(issued.is_empty(), "none carried a certificate");
    }

    fn issued_to(name: &str, signer: &str, not_before: i64) -> PodCertificateRequest {
        let mut p = request(vec![], &[], 3600);
        p.metadata.name = Some(name.into());
        p.spec.signer_name = signer.into();
        p.spec.pod_name = format!("pod-{name}");
        p.spec.pod_uid = format!("uid-{name}");
        p.status = settle(
            &request(
                csr(&PKCS_ECDSA_P256_SHA256).1,
                &[("edge.meridian/dns-names", "localhost")],
                3600,
            ),
            &file_ca(not_before),
            &unit(),
            not_before,
        );
        p
    }

    #[test]
    fn recreates_only_own_pods_dated_ahead() {
        let (mut pending, mut issued) = (BTreeMap::new(), BTreeMap::new());
        for p in [
            issued_to("ahead", SIGNER, NOW + CLOCK_SKEW_SECS + 1),
            issued_to("year", SIGNER, NOW + 365 * 86_400),
            issued_to("skew", SIGNER, NOW + CLOCK_SKEW_SECS),
            issued_to("now", SIGNER, NOW),
            issued_to("past", SIGNER, NOW - 86_400),
            issued_to("foreign", "example.com/x", NOW + 365 * 86_400),
            issued_to("gone", SIGNER, NOW + 365 * 86_400),
        ] {
            apply_event("n", &mut pending, &mut issued, Event::InitApply(p));
        }
        apply_event(
            "n",
            &mut pending,
            &mut issued,
            Event::Delete(issued_to("gone", SIGNER, NOW + 365 * 86_400)),
        );
        let dated_ahead: Vec<_> = issued
            .iter()
            .filter(|(_, c)| c.dated_ahead(NOW))
            .map(|(k, c)| (k.1.as_str(), c))
            .collect();
        assert_eq!(
            dated_ahead,
            [
                (
                    "ahead",
                    &Issued {
                        pod: "pod-ahead".into(),
                        uid: "uid-ahead".into(),
                        not_before: NOW + CLOCK_SKEW_SECS + 1,
                        follows: false,
                        ips: vec![],
                    }
                ),
                (
                    "year",
                    &Issued {
                        pod: "pod-year".into(),
                        uid: "uid-year".into(),
                        not_before: NOW + 365 * 86_400,
                        follows: false,
                        ips: vec![],
                    }
                ),
            ]
        );
        assert!(pending.is_empty());

        apply_event("n", &mut pending, &mut issued, Event::Init);
        assert!(issued.is_empty(), "a relist starts afresh");
    }

    #[test]
    fn recreates_newest_node_certificate_lacking_a_gained_address() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let cert = |uid: &str, not_before: i64, follows: bool, ips: &[&str]| Issued {
            pod: format!("pod-{uid}"),
            uid: uid.into(),
            not_before,
            follows,
            ips: ips.iter().map(|a| ip(a)).collect(),
        };
        let key = |name: &str| ("edge".to_string(), name.to_string());
        let issued: BTreeMap<_, _> = [
            (key("gw-1"), cert("gw", NOW - 600, true, &["192.0.2.1"])),
            (
                key("gw-2"),
                cert("gw", NOW, true, &["192.0.2.1", "127.0.0.1"]),
            ),
            (key("fixed"), cert("fixed", NOW, false, &["192.0.2.1"])),
            (key("refreshed-1"), cert("refreshed", NOW - 600, true, &[])),
            (
                key("refreshed-2"),
                cert("refreshed", NOW, true, &["192.0.2.1", "192.0.2.2"]),
            ),
        ]
        .into();
        let due_for = |addresses: &[&str]| {
            let addresses: Vec<IpAddr> = addresses.iter().map(|a| ip(a)).collect();
            due(&issued, &addresses, NOW)
                .into_iter()
                .map(|(k, why)| (k.1, why))
                .collect::<Vec<_>>()
        };
        assert_eq!(due_for(&[]), []);
        assert_eq!(
            due_for(&["192.0.2.1"]),
            [],
            "a lost address costs no restart"
        );
        assert_eq!(
            due_for(&["192.0.2.1", "192.0.2.2"]),
            [("gw-2".to_string(), "certificate lacks a node address")]
        );
    }

    #[test]
    fn reachable_addresses_exclude_loopback_and_link_local() {
        for a in ["10.42.0.1", "192.0.2.1", "2001:db8::1", "fd00::1"] {
            assert!(reachable(&a.parse().unwrap()), "{a}");
        }
        for a in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
        ] {
            assert!(!reachable(&a.parse().unwrap()), "{a}");
        }
        let held = host_addresses().unwrap();
        assert!(held.iter().all(reachable), "{held:?}");
        assert!(held.is_sorted());
    }

    #[test]
    fn gone_or_replaced_pod_counts_as_recreated() {
        let api = |code, reason| {
            Err(kube::Error::Api(
                kube::core::Status::failure("", reason)
                    .with_code(code)
                    .boxed(),
            ))
        };
        assert_eq!(deleted_unless_gone(Ok(())).ok(), Some(true));
        assert_eq!(deleted_unless_gone(api(404, "NotFound")).ok(), Some(false));
        assert_eq!(deleted_unless_gone(api(409, "Conflict")).ok(), Some(false));
        assert!(deleted_unless_gone(api(403, "Forbidden")).is_err());
        assert!(deleted_unless_gone(api(500, "InternalError")).is_err());
    }

    #[test]
    fn bundle_due_when_new_changed_or_stale() {
        let fresh = Some(("a".to_string(), Instant::now()));
        assert!(bundle_due(&None, "a"));
        assert!(!bundle_due(&fresh, "a"));
        assert!(bundle_due(&fresh, "b"));
        let stale = Instant::now().checked_sub(REPUBLISH_INTERVAL).unwrap();
        assert!(bundle_due(&Some(("a".into(), stale)), "a"));
    }

    #[test]
    fn signing_error_fails_request() {
        let ca = file_ca(NOW);
        let pcr = request(
            csr(&PKCS_ECDSA_P256_SHA256).1,
            &[("edge.meridian/dns-names", "localhost")],
            3600,
        );
        let ca_expired = NOW + 3650 * 86_400;
        let s = settle(&pcr, &ca, &unit(), ca_expired);
        assert_eq!(s.conditions.len(), 1);
        assert_eq!(
            (
                s.conditions[0].type_.as_str(),
                s.conditions[0].reason.as_str()
            ),
            ("Failed", "SigningFailed")
        );
        assert_eq!(s.certificate_chain, None);
    }

    type Writes = std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>;
    type Watch = tokio::sync::mpsc::UnboundedSender<serde_json::Value>;

    /// What the fake apiserver lists; writes are recorded and echoed.
    #[derive(Clone, Default)]
    struct World {
        pcrs: Vec<serde_json::Value>,
        secret: Option<serde_json::Value>,
        secrets_forbidden: bool,
        csrs: Vec<serde_json::Value>,
        node: Option<serde_json::Value>,
        hang_writes: bool,
    }

    struct Watches {
        pcrs: Watch,
        secrets: Watch,
    }

    const LISTED: [&str; 3] = [
        "podcertificaterequests",
        "secrets",
        "certificatesigningrequests",
    ];

    async fn fake_apiserver(world: World) -> (String, Writes, Watches) {
        use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
        use std::sync::{Arc, Mutex};
        type Body = BoxBody<bytes::Bytes, std::convert::Infallible>;
        type Rx = Arc<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>>>>;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let writes = Writes::default();
        let recorded = writes.clone();
        let (pcrs, pcr_rx) = tokio::sync::mpsc::unbounded_channel();
        let (secrets, secret_rx) = tokio::sync::mpsc::unbounded_channel();
        let streams: Arc<Vec<(&str, Rx)>> = Arc::new(vec![
            ("podcertificaterequests", Arc::new(Mutex::new(Some(pcr_rx)))),
            ("secrets", Arc::new(Mutex::new(Some(secret_rx)))),
        ]);
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let (recorded, world, streams) = (recorded.clone(), world.clone(), streams.clone());
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let (recorded, world, streams) =
                            (recorded.clone(), world.clone(), streams.clone());
                        async move {
                            let (method, uri) = (req.method().to_string(), req.uri().to_string());
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let json = |v: &serde_json::Value| -> Body {
                                Full::new(bytes::Bytes::from(v.to_string())).boxed()
                            };
                            let list = |items: Vec<serde_json::Value>| {
                                json(&serde_json::json!({
                                    "apiVersion": "v1", "kind": "List",
                                    "metadata": { "resourceVersion": "1" },
                                    "items": items,
                                }))
                            };
                            let status = |code: u16| {
                                json(&serde_json::json!({
                                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                    "code": code, "reason": "", "message": "",
                                }))
                            };
                            let mut code = 200;
                            let resp = if method == "GET"
                                && uri.contains("/secrets")
                                && world.secrets_forbidden
                            {
                                code = 403;
                                status(403)
                            } else if method == "GET" && uri.contains("watch=") {
                                let rx = streams
                                    .iter()
                                    .find(|(what, _)| uri.contains(what))
                                    .and_then(|(_, rx)| rx.lock().unwrap().take());
                                let frames = match rx {
                                    Some(rx) => futures::stream::unfold(rx, |mut rx| async move {
                                        let line = format!("{}\n", rx.recv().await?);
                                        let frame = hyper::body::Frame::data(line.into());
                                        Some((Ok(frame), rx))
                                    })
                                    .left_stream(),
                                    None => futures::stream::pending().right_stream(),
                                };
                                BodyExt::boxed(StreamBody::new(frames))
                            } else if method == "GET" && uri.contains("/nodes/") {
                                match &world.node {
                                    Some(n) => json(n),
                                    None => {
                                        code = 404;
                                        status(404)
                                    }
                                }
                            } else if method == "GET" {
                                assert!(LISTED.iter().any(|l| uri.contains(l)), "{uri}");
                                list(if uri.contains("/secrets") {
                                    world.secret.clone().into_iter().collect()
                                } else if uri.contains("certificatesigningrequests") {
                                    world.csrs.clone()
                                } else {
                                    world.pcrs.clone()
                                })
                            } else {
                                if world.hang_writes {
                                    std::future::pending::<()>().await;
                                }
                                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                                let pod = serde_json::json!({ "apiVersion": "v1", "kind": "Pod" });
                                let echo = if uri.contains("clustertrustbundles") {
                                    v.clone()
                                } else if uri.contains("/pods/") {
                                    pod
                                } else if uri.contains("certificatesigningrequests") {
                                    world.csrs[0].clone()
                                } else {
                                    world.pcrs[0].clone()
                                };
                                recorded.lock().unwrap().push((method, uri, v));
                                json(&echo)
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(code)
                                    .header("content-type", "application/json")
                                    .body(resp)
                                    .unwrap(),
                            )
                        }
                    },
                );
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(socket), svc),
                );
            }
        });
        (url, writes, Watches { pcrs, secrets })
    }

    fn ca_secret(r: &TestCert) -> serde_json::Value {
        chain_secret(r, &[r])
    }

    fn chain_secret(key: &TestCert, chain: &[&TestCert]) -> serde_json::Value {
        let mut s = serde_json::to_value(secret(key, chain)).unwrap();
        s["metadata"] = serde_json::json!({
            "name": ca::SECRET, "namespace": "default", "resourceVersion": "2",
        });
        s
    }

    fn pcr_json(
        name: &str,
        pod: &str,
        uid: &str,
        der: Vec<u8>,
        status: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "PodCertificateRequest",
            "metadata": { "name": name, "namespace": "edge", "resourceVersion": "1" },
            "spec": {
                "signerName": SIGNER, "podName": pod, "podUID": uid,
                "serviceAccountName": "edge-gateway", "serviceAccountUID": "s",
                "nodeName": "n", "nodeUID": "nu", "maxExpirationSeconds": 3600,
                "stubPKCS10Request": k8s_openapi::ByteString(der),
                "unverifiedUserAnnotations": { "edge.meridian/dns-names": "example.lan" },
            },
            "status": status,
        })
    }

    type Held = std::sync::Arc<std::sync::Mutex<Vec<IpAddr>>>;

    fn start(url: &str) -> (tokio::task::JoinHandle<anyhow::Result<()>>, Heartbeat) {
        start_holding(url, Held::default())
    }

    fn start_holding(
        url: &str,
        held: Held,
    ) -> (tokio::task::JoinHandle<anyhow::Result<()>>, Heartbeat) {
        let client = Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap();
        let hb = Heartbeat::default();
        let beat = hb.clone();
        let host = move || Ok(held.lock().unwrap().clone());
        let task = tokio::spawn(async move { serve(client, "n", &unit(), host, &beat).await });
        (task, hb)
    }

    fn leaf_of(body: &serde_json::Value) -> Vec<u8> {
        let chain = body["status"]["certificateChain"].as_str().unwrap();
        rustls_pki_types::CertificateDer::from_pem_slice(chain.as_bytes())
            .unwrap()
            .to_vec()
    }

    fn status_writes(writes: &Writes) -> Vec<(String, String, serde_json::Value)> {
        writes
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.1.contains("/status"))
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn answers_once_and_publishes_root() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (key, der) = csr(&PKCS_ECDSA_P256_SHA256);
        let r = root("r", now() - 60, now() + 86_400 * 365);
        let (url, writes, _watch) = fake_apiserver(World {
            pcrs: vec![pcr_json("gw-1", "gw", "u", der, serde_json::json!({}))],
            secret: Some(ca_secret(&r)),
            ..World::default()
        })
        .await;
        let (task, _hb) = start(&url);

        // Long enough for the retry tick to answer a request twice if it would.
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        task.abort();
        let status = status_writes(&writes);
        assert_eq!(status.len(), 1, "{status:?}");
        let (method, uri, body) = &status[0];
        assert_eq!(method, "PATCH");
        assert!(
            uri.starts_with(
                "/apis/certificates.k8s.io/v1/namespaces/edge/podcertificaterequests/gw-1/status"
            ),
            "{uri}"
        );
        assert_eq!(body["status"]["conditions"][0]["type"], "Issued");
        let der = leaf_of(body);
        let (_, leaf) = parse_x509_certificate(&der).unwrap();
        assert_eq!(
            leaf.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
        let ca_der = rustls_pki_types::CertificateDer::from_pem_slice(r.pem.as_bytes()).unwrap();
        let (_, ca) = parse_x509_certificate(&ca_der).unwrap();
        leaf.verify_signature(Some(ca.public_key()))
            .expect("signed by the Secret's CA");

        let writes = writes.lock().unwrap().clone();
        let bundle: Vec<_> = writes
            .iter()
            .filter(|w| w.1.contains("clustertrustbundles"))
            .collect();
        assert_eq!(bundle.len(), 1, "{writes:?}");
        let (method, uri, body) = bundle[0];
        assert_eq!(method, "PATCH");
        assert!(uri.contains("fieldManager=edge-signer"), "{uri}");
        assert_eq!(body["metadata"]["name"], BUNDLE_NAME);
        assert_eq!(body["spec"]["signerName"], SIGNER);
        assert_eq!(body["spec"]["trustBundle"], r.pem.as_str());
    }

    async fn wait_for_writes(
        writes: &Writes,
        done: impl Fn(&[(String, String, serde_json::Value)]) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !done(&writes.lock().unwrap()) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{:?}", writes.lock().unwrap()));
    }

    fn bundles(w: &[(String, String, serde_json::Value)]) -> Vec<String> {
        w.iter()
            .filter(|w| w.1.contains("clustertrustbundles"))
            .map(|w| w.2["spec"]["trustBundle"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn missing_secret_signs_ephemeral_until_it_appears() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (url, writes, watch) = fake_apiserver(World {
            pcrs: vec![pcr_json(
                "gw-1",
                "gw",
                "u",
                csr(&PKCS_ECDSA_P256_SHA256).1,
                serde_json::json!({}),
            )],
            ..World::default()
        })
        .await;
        let (task, _hb) = start(&url);
        wait_for_writes(&writes, |w| {
            !bundles(w).is_empty() && w.iter().any(|w| w.1.contains("/status"))
        })
        .await;
        let ephemeral = bundles(&writes.lock().unwrap())[0].clone();
        assert_eq!(
            status_writes(&writes)[0].2["status"]["conditions"][0]["type"],
            "Issued",
            "a missing Secret still signs"
        );

        let r = root("r", now() - 60, now() + 86_400 * 365);
        assert_ne!(ephemeral, r.pem);
        watch
            .secrets
            .send(serde_json::json!({ "type": "ADDED", "object": ca_secret(&r) }))
            .unwrap();
        wait_for_writes(&writes, |w| bundles(w).last() == Some(&r.pem)).await;
        task.abort();
    }

    #[tokio::test]
    async fn refused_secret_signs_ephemeral() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (url, writes, _watch) = fake_apiserver(World {
            secrets_forbidden: true,
            ..World::default()
        })
        .await;
        let (task, _hb) = start(&url);
        wait_for_writes(&writes, |w| !bundles(w).is_empty()).await;
        task.abort();
    }

    #[tokio::test]
    async fn approves_only_the_kubelets_own_request() {
        use crate::kubelet::tests::{kubelet_csr, node, own_csr, pem};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut foreign = kubelet_csr(
            "foreign",
            pem(
                &[
                    (rcgen::DnType::CommonName, "system:node:node-1"),
                    (rcgen::DnType::OrganizationName, "system:nodes"),
                ],
                vec![rcgen::SanType::DnsName("elsewhere".try_into().unwrap())],
            ),
        );
        foreign.metadata.resource_version = Some("1".into());
        let mut own = own_csr("own");
        own.metadata.resource_version = Some("1".into());
        let (url, writes, _watch) = fake_apiserver(World {
            csrs: vec![
                serde_json::to_value(own).unwrap(),
                serde_json::to_value(foreign).unwrap(),
            ],
            node: Some(
                serde_json::to_value(node(&["node-1", "192.0.2.10", "2001:db8::10"])).unwrap(),
            ),
            ..World::default()
        })
        .await;
        let (task, _hb) = start(&url);
        let approvals = |w: &[(String, String, serde_json::Value)]| {
            w.iter()
                .filter(|w| w.1.contains("/approval"))
                .cloned()
                .collect::<Vec<_>>()
        };
        wait_for_writes(&writes, |w| !approvals(w).is_empty()).await;
        // Long enough for the retry tick to approve twice, or the other, if it would.
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        task.abort();
        let approvals = approvals(&writes.lock().unwrap());
        assert_eq!(approvals.len(), 1, "{approvals:?}");
        let (method, uri, body) = &approvals[0];
        assert_eq!(method, "PATCH");
        assert!(
            uri.starts_with("/apis/certificates.k8s.io/v1/certificatesigningrequests/own/approval"),
            "{uri}"
        );
        let c = &body["status"]["conditions"][0];
        assert_eq!(
            (&c["type"], &c["status"]),
            (&"Approved".into(), &"True".into())
        );
    }

    #[tokio::test]
    async fn deletes_pod_dated_ahead_once() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let year = now() + 365 * 86_400;
        let pcr = |name: &str, pod: &str, uid: &str, status: serde_json::Value| {
            pcr_json(name, pod, uid, csr(&PKCS_ECDSA_P256_SHA256).1, status)
        };
        let ahead = serde_json::to_value(settle(
            &serde_json::from_value(pcr("gw-a-1", "gw-a", "old", serde_json::json!({}))).unwrap(),
            &file_ca(year),
            &unit(),
            year,
        ))
        .unwrap();
        let r = root("r", now() - 60, year + 86_400);
        let (url, writes, watch) = fake_apiserver(World {
            pcrs: vec![pcr("gw-a-1", "gw-a", "old", ahead)],
            secret: Some(ca_secret(&r)),
            ..World::default()
        })
        .await;
        let (task, _hb) = start(&url);

        let deletes = |w: &[(String, String, serde_json::Value)]| {
            w.iter()
                .filter(|w| w.0 == "DELETE")
                .cloned()
                .collect::<Vec<_>>()
        };
        wait_for_writes(&writes, |w| !deletes(w).is_empty()).await;
        let replacement = pcr("gw-b-1", "gw-b", "new", serde_json::json!({}));
        watch
            .pcrs
            .send(serde_json::json!({ "type": "ADDED", "object": replacement }))
            .unwrap();
        wait_for_writes(&writes, |w| w.iter().any(|w| w.1.contains("gw-b-1/status"))).await;
        let issued = writes
            .lock()
            .unwrap()
            .iter()
            .find(|w| w.1.contains("gw-b-1/status"))
            .unwrap()
            .2["status"]
            .clone();
        let mut answered = replacement.clone();
        answered["status"] = issued;
        answered["metadata"]["resourceVersion"] = "2".into();
        watch
            .pcrs
            .send(serde_json::json!({ "type": "MODIFIED", "object": answered }))
            .unwrap();

        // Long enough for the retry tick to delete twice if it would.
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        task.abort();
        let deletes = deletes(&writes.lock().unwrap());
        assert_eq!(deletes.len(), 1, "{deletes:?}");
        let (_, uri, body) = &deletes[0];
        assert!(
            uri.starts_with("/api/v1/namespaces/edge/pods/gw-a?"),
            "{uri}"
        );
        assert_eq!(body["preconditions"], serde_json::json!({ "uid": "old" }));
    }

    #[tokio::test]
    async fn deletes_pod_once_node_gains_address() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let pcr = |name: &str, pod: &str, uid: &str, status: serde_json::Value| {
            let mut p = pcr_json(name, pod, uid, csr(&PKCS_ECDSA_P256_SHA256).1, status);
            p["spec"]["unverifiedUserAnnotations"]["edge.meridian/ip-addresses"] =
                "node,127.0.0.1".into();
            p
        };
        let r = root("r", now() - 60, now() + 86_400 * 365);
        let ca = Ca::from_secret(Some(&secret(&r, &[&r])), now()).unwrap();
        let before = Unit {
            addresses: vec![ip("192.0.2.1")],
            ..unit()
        };
        let old = serde_json::to_value(settle(
            &serde_json::from_value(pcr("gw-a-1", "gw-a", "old", serde_json::json!({}))).unwrap(),
            &ca,
            &before,
            now(),
        ))
        .unwrap();
        let (url, writes, watch) = fake_apiserver(World {
            pcrs: vec![pcr("gw-a-1", "gw-a", "old", old)],
            secret: Some(ca_secret(&r)),
            ..World::default()
        })
        .await;
        let held = Held::new(vec![ip("192.0.2.1")].into());
        let (task, _hb) = start_holding(&url, held.clone());
        let deletes = |w: &[(String, String, serde_json::Value)]| {
            w.iter()
                .filter(|w| w.0 == "DELETE")
                .cloned()
                .collect::<Vec<_>>()
        };

        wait_for_writes(&writes, |w| !bundles(w).is_empty()).await;
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        assert_eq!(deletes(&writes.lock().unwrap()), [], "nothing gained");

        held.lock().unwrap().push(ip("192.0.2.2"));
        wait_for_writes(&writes, |w| !deletes(w).is_empty()).await;
        let replacement = pcr("gw-b-1", "gw-b", "new", serde_json::json!({}));
        watch
            .pcrs
            .send(serde_json::json!({ "type": "ADDED", "object": replacement }))
            .unwrap();
        wait_for_writes(&writes, |w| w.iter().any(|w| w.1.contains("gw-b-1/status"))).await;
        let issued = writes
            .lock()
            .unwrap()
            .iter()
            .find(|w| w.1.contains("gw-b-1/status"))
            .unwrap()
            .2["status"]
            .clone();
        assert_eq!(
            ca::leaf_addresses(issued["certificateChain"].as_str().unwrap()),
            [ip("192.0.2.1"), ip("192.0.2.2"), ip("127.0.0.1")]
        );
        let mut answered = replacement.clone();
        answered["status"] = issued;
        answered["metadata"]["resourceVersion"] = "2".into();
        watch
            .pcrs
            .send(serde_json::json!({ "type": "MODIFIED", "object": answered }))
            .unwrap();

        // Long enough for the retry tick to delete twice if it would.
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        task.abort();
        let deletes = deletes(&writes.lock().unwrap());
        assert_eq!(deletes.len(), 1, "{deletes:?}");
        let (_, uri, body) = &deletes[0];
        assert!(
            uri.starts_with("/api/v1/namespaces/edge/pods/gw-a?"),
            "{uri}"
        );
        assert_eq!(body["preconditions"], serde_json::json!({ "uid": "old" }));
    }

    #[tokio::test]
    async fn address_the_ca_cannot_name_costs_no_restart() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let r = root("r", now() - 60, now() + 86_400 * 365);
        let i = intermediate(&r);
        let ca = Ca::from_secret(Some(&secret(&i, &[&i, &r])), now()).unwrap();
        let mut p = pcr_json(
            "gw-a-1",
            "gw-a",
            "old",
            csr(&PKCS_ECDSA_P256_SHA256).1,
            serde_json::json!({}),
        );
        p["spec"]["unverifiedUserAnnotations"]["edge.meridian/ip-addresses"] =
            "node,127.0.0.1".into();
        p["status"] = serde_json::to_value(settle(
            &serde_json::from_value(p.clone()).unwrap(),
            &ca,
            &unit(),
            now(),
        ))
        .unwrap();
        let (url, writes, _watch) = fake_apiserver(World {
            pcrs: vec![p],
            secret: Some(chain_secret(&i, &[&i, &r])),
            ..World::default()
        })
        .await;
        let held = Held::new(vec!["192.0.2.1".parse().unwrap()].into());
        let (task, _hb) = start_holding(&url, held);
        wait_for_writes(&writes, |w| !bundles(w).is_empty()).await;
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        task.abort();
        let writes = writes.lock().unwrap();
        assert!(writes.iter().all(|w| w.0 != "DELETE"), "{writes:?}");
    }

    async fn max_heartbeat_age(hb: &Heartbeat, span: Duration) -> Duration {
        let mut oldest = Duration::ZERO;
        let until = tokio::time::Instant::now() + span;
        while tokio::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(100)).await;
            oldest = oldest.max(hb.age());
        }
        oldest
    }

    #[tokio::test]
    async fn apiserver_down_keeps_beating() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (task, hb) = start(&format!("http://127.0.0.1:{port}"));
        let oldest = max_heartbeat_age(&hb, RETRY_INTERVAL * 2).await;
        task.abort();
        assert!(
            oldest <= RETRY_INTERVAL + Duration::from_secs(1),
            "{oldest:?}"
        );
    }

    #[tokio::test]
    async fn hung_apiserver_keeps_beating() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let r = root("r", now() - 60, now() + 86_400 * 365);
        let (url, writes, _watch) = fake_apiserver(World {
            secret: Some(ca_secret(&r)),
            hang_writes: true,
            ..World::default()
        })
        .await;
        let (task, hb) = start(&url);
        let oldest = max_heartbeat_age(&hb, CALL_TIMEOUT * 2).await;
        task.abort();
        assert!(
            oldest > CALL_TIMEOUT - Duration::from_secs(1),
            "the bundle write never hung: {oldest:?}"
        );
        assert!(
            oldest <= CALL_TIMEOUT + Duration::from_secs(1),
            "{oldest:?}"
        );
        assert!(oldest < STALE_AFTER);
        assert!(writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stalled_loop_stops_beating() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (url, _writes, _watch) = fake_apiserver(World::default()).await;
        let client = Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap();
        let hb = Heartbeat::default();
        let unit = unit();
        let mut serving = std::pin::pin!(serve(client, "n", &unit, || Ok(vec![]), &hb));
        let poll = Duration::from_millis(500);

        let beating = poll * 2;
        assert!(tokio::time::timeout(poll, serving.as_mut()).await.is_err());
        assert!(hb.age() < beating, "first pass beat");
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        assert!(hb.age() > RETRY_INTERVAL, "beat while stalled");

        assert!(tokio::time::timeout(poll, serving.as_mut()).await.is_err());
        assert!(hb.age() < beating, "no beat once running again");
    }
}
