//! Signs the PodCertificateRequests for [`policy::SIGNER`] and publishes the CA root as
//! a ClusterTrustBundle. A certificate issued while the clock ran ahead starts in the
//! future once the clock steps back, and kubelet renews it only at its equally future
//! refresh time, so the signer deletes that pod for its controller to recreate.

mod api;
mod ca;
mod heartbeat;
mod policy;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{
    ApiResource, DeleteParams, DynamicObject, GroupVersionKind, Patch, PatchParams, Preconditions,
};
use kube::runtime::watcher::Event;
use kube::{Api, Client, ResourceExt};

use api::{PodCertificateRequest, Status};
use ca::{Ca, Source};
use heartbeat::Heartbeat;
use policy::{Decision, SIGNER, Unit};

/// The ClusterTrustBundle's name must start with the signer's, `/` as `:`.
const BUNDLE_NAME: &str = "edge.meridian:appliance:ca";
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// The client sets no response timeout, so one hung apiserver call would stall
/// the loop for good.
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const _: () = assert!(
    RETRY_INTERVAL.as_secs() + CALL_TIMEOUT.as_secs() < heartbeat::STALE_AFTER.as_secs(),
    "a pass waiting on a hung call must not go stale"
);
/// Re-applied this often even unchanged, so a deleted bundle comes back.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(600);
/// kube-apiserver's own tolerance for an issued notBefore; within it the clocks
/// agree, and a slewing clock catches up sooner than a recreated pod would.
const CLOCK_SKEW_SECS: i64 = 300;

fn main() -> anyhow::Result<()> {
    let heartbeat_dir = Path::new(heartbeat::DIR);
    if std::env::args().nth(1).as_deref() == Some("check") {
        return heartbeat::check(heartbeat_dir, heartbeat::monotonic());
    }
    edge_common::init_tracing();
    let ca_path: PathBuf = std::env::var("EDGE_SIGNER_CA")
        .unwrap_or_else(|_| "/etc/edge-signer/ca.pem".into())
        .into();
    let env = |name| std::env::var(name).unwrap_or_default();
    let unit = Unit::new(&env("EDGE_SIGNER_DOMAIN"), &env("EDGE_SIGNER_ADDRESSES"));
    edge_common::sandbox::restrict(&edge_common::sandbox::signer(&ca_path, heartbeat_dir));
    run(&ca_path, &unit, &Heartbeat::new(heartbeat_dir))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[tokio::main]
async fn run(ca_path: &Path, unit: &Unit, heartbeat: &Heartbeat) -> anyhow::Result<()> {
    let mut term = edge_common::Terminator::new();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let source = Source::open(ca_path, now())?;
    tracing::info!(
        signer = SIGNER,
        bundle = BUNDLE_NAME,
        ?unit,
        "edge-signer: ready"
    );

    let mut outage = edge_common::Outage::default();
    let client = loop {
        heartbeat.beat().ok();
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
        r = serve(client, unit, source, heartbeat) => r,
        _ = term.wait() => Ok(()),
    }
}

/// Beats only from the loop itself, so a wedged loop goes stale while an
/// apiserver outage does not.
async fn serve(
    client: Client,
    unit: &Unit,
    mut source: Source,
    heartbeat: &Heartbeat,
) -> anyhow::Result<()> {
    let requests: Api<PodCertificateRequest> = Api::all(client.clone());
    let bundles: Api<DynamicObject> = Api::all_with(
        client.clone(),
        &ApiResource::from_gvk(&GroupVersionKind::gvk(
            "certificates.k8s.io",
            "v1",
            "ClusterTrustBundle",
        )),
    );

    let mut events = edge_kube::watch(requests.clone(), "podcertificaterequests").boxed();
    let mut pending = BTreeMap::new();
    let mut issued = BTreeMap::new();
    let mut published: Option<(String, Instant)> = None;
    let mut bundle_outage = edge_common::Outage::default();
    let mut status_outage = edge_common::Outage::default();
    let mut pod_outage = edge_common::Outage::default();
    let mut heartbeat_outage = edge_common::Outage::default();
    let mut beat = || heartbeat_outage.observe("heartbeat", &heartbeat.beat());
    let mut tick = tokio::time::interval(RETRY_INTERVAL);
    loop {
        beat();
        tokio::select! {
            ev = events.next() => match ev {
                Some(Ok(ev)) => apply_event(&mut pending, &mut issued, ev),
                Some(Err(_)) => continue,
                None => events = edge_kube::watch(requests.clone(), "podcertificaterequests").boxed(),
            },
            _ = tick.tick() => {}
        }

        let now = now();
        source.refresh(now)?;
        let root = source.ca.root();
        if bundle_due(&published, root) {
            let r = bounded(publish(&bundles, root)).await;
            beat();
            bundle_outage.observe("clustertrustbundle", &r);
            if r.is_ok() {
                published = Some((root.to_string(), Instant::now()));
            }
        }

        let mut settled = Vec::new();
        for (key, pcr) in &pending {
            let status = settle(pcr, &source.ca, unit, now);
            let requests = Api::<PodCertificateRequest>::namespaced(client.clone(), &key.0);
            let r = bounded(requests.patch_status(
                &key.1,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "status": status })),
            ))
            .await;
            beat();
            status_outage.observe("podcertificaterequest status", &r);
            if r.is_ok() {
                log_verdict(pcr, &status);
                settled.push(key.clone());
            }
        }
        for key in settled {
            pending.remove(&key);
        }

        let mut recreated = Vec::new();
        for (key, cert) in issued.iter().filter(|(_, c)| c.dated_ahead(now)) {
            let pods = Api::<Pod>::namespaced(client.clone(), &key.0);
            let r = bounded(recreate(&pods, cert)).await;
            beat();
            pod_outage.observe("pod deletion", &r);
            if let Ok(deleted) = r {
                if deleted {
                    tracing::info!(
                        namespace = key.0,
                        pod = cert.pod,
                        not_before = %time(cert.not_before).0,
                        "certificate dated ahead of the clock: pod deleted for recreation"
                    );
                }
                recreated.push(key.clone());
            }
        }
        for key in recreated {
            issued.remove(&key);
        }
    }
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
}

impl Issued {
    fn of(pcr: &PodCertificateRequest) -> Option<Self> {
        Some(Self {
            pod: pcr.spec.pod_name.clone(),
            uid: pcr.spec.pod_uid.clone(),
            not_before: pcr.status.not_before.as_ref()?.0.as_second(),
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
/// request deleted during a disconnect drops out.
fn apply_event(
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
            if p.spec.signer_name == SIGNER {
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
        Err(e) => {
            return Status {
                conditions: vec![condition(
                    "Denied",
                    "UnsupportedKeyType",
                    format!("{e}: use keyType ECDSAP256"),
                )],
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
    use crate::ca::tests::{NOW, csr, file, file_ca, root, scratch};
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use rustls_pki_types::pem::PemObject;
    use x509_parser::prelude::*;

    fn unit() -> Unit {
        Unit::new("example.lan", "")
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
    fn denial_has_only_condition() {
        let ca = file_ca(NOW);
        let p384 = csr(&rcgen::PKCS_ECDSA_P384_SHA384).1;
        let p256 = csr(&PKCS_ECDSA_P256_SHA256).1;
        for (pcr, reason) in [
            (
                request(p384, &[("edge.meridian/dns-names", "example.lan")], 3600),
                "UnsupportedKeyType",
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
            &mut pending,
            &mut issued,
            Event::Apply(mk("a", SIGNER, false)),
        );
        apply_event(
            &mut pending,
            &mut issued,
            Event::Apply(mk("other", "example.com/x", false)),
        );
        apply_event(
            &mut pending,
            &mut issued,
            Event::Apply(mk("done", SIGNER, true)),
        );
        assert_eq!(
            pending.keys().map(|k| k.1.as_str()).collect::<Vec<_>>(),
            ["a"]
        );

        apply_event(
            &mut pending,
            &mut issued,
            Event::Apply(mk("a", SIGNER, true)),
        );
        assert!(pending.is_empty(), "settled elsewhere");

        apply_event(
            &mut pending,
            &mut issued,
            Event::Apply(mk("b", SIGNER, false)),
        );
        apply_event(
            &mut pending,
            &mut issued,
            Event::Delete(mk("b", SIGNER, false)),
        );
        assert!(pending.is_empty(), "deleted");

        apply_event(
            &mut pending,
            &mut issued,
            Event::Apply(mk("gone", SIGNER, false)),
        );
        apply_event(&mut pending, &mut issued, Event::Init);
        apply_event(
            &mut pending,
            &mut issued,
            Event::InitApply(mk("c", SIGNER, false)),
        );
        apply_event(&mut pending, &mut issued, Event::InitDone);
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
            apply_event(&mut pending, &mut issued, Event::InitApply(p));
        }
        apply_event(
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
                    }
                ),
                (
                    "year",
                    &Issued {
                        pod: "pod-year".into(),
                        uid: "uid-year".into(),
                        not_before: NOW + 365 * 86_400,
                    }
                ),
            ]
        );
        assert!(pending.is_empty());

        apply_event(&mut pending, &mut issued, Event::Init);
        assert!(issued.is_empty(), "a relist starts afresh");
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

    async fn fake_apiserver(pcr: serde_json::Value) -> (String, Writes, Watch) {
        use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
        type Body = BoxBody<bytes::Bytes, std::convert::Infallible>;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let writes = Writes::default();
        let recorded = writes.clone();
        let (watch, rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let (recorded, pcr, rx) = (recorded.clone(), pcr.clone(), rx.clone());
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let (recorded, pcr, rx) = (recorded.clone(), pcr.clone(), rx.clone());
                        async move {
                            let (method, uri) = (req.method().to_string(), req.uri().to_string());
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let json = |v: &serde_json::Value| -> Body {
                                Full::new(bytes::Bytes::from(v.to_string())).boxed()
                            };
                            let resp = if method == "GET" && uri.contains("watch=") {
                                let frames = match rx.lock().unwrap().take() {
                                    Some(rx) => futures::stream::unfold(rx, |mut rx| async move {
                                        let line = format!("{}\n", rx.recv().await?);
                                        let frame = hyper::body::Frame::data(line.into());
                                        Some((Ok(frame), rx))
                                    })
                                    .left_stream(),
                                    None => futures::stream::pending().right_stream(),
                                };
                                BodyExt::boxed(StreamBody::new(frames))
                            } else if method == "GET" {
                                json(&serde_json::json!({
                                    "apiVersion": "certificates.k8s.io/v1",
                                    "kind": "PodCertificateRequestList",
                                    "metadata": { "resourceVersion": "1" },
                                    "items": [pcr],
                                }))
                            } else {
                                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                                let pod = serde_json::json!({ "apiVersion": "v1", "kind": "Pod" });
                                let echo = if uri.contains("clustertrustbundles") {
                                    &v
                                } else if uri.contains("/pods/") {
                                    &pod
                                } else {
                                    &pcr
                                };
                                let resp = json(echo);
                                recorded.lock().unwrap().push((method, uri, v));
                                resp
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
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
        (url, writes, watch)
    }

    #[tokio::test]
    async fn answers_once_and_publishes_root() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (key, der) = csr(&PKCS_ECDSA_P256_SHA256);
        let pcr = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "PodCertificateRequest",
            "metadata": { "name": "gw-1", "namespace": "edge", "resourceVersion": "1" },
            "spec": {
                "signerName": SIGNER, "podName": "gw", "podUID": "u",
                "serviceAccountName": "edge-gateway", "serviceAccountUID": "s",
                "nodeName": "n", "nodeUID": "nu", "maxExpirationSeconds": 3600,
                "stubPKCS10Request": k8s_openapi::ByteString(der),
                "unverifiedUserAnnotations": { "edge.meridian/dns-names": "example.lan" },
            },
        });
        let (url, writes, _watch) = fake_apiserver(pcr).await;
        let client = Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap();
        let path = scratch("serve");
        let r = root("r", now() - 60, now() + 86_400 * 365);
        std::fs::write(&path, file(&r, &[&r])).unwrap();
        let source = Source::open(&path, now()).unwrap();
        let heartbeat = Heartbeat::new(path.parent().unwrap());
        let task = tokio::spawn(async move { serve(client, &unit(), source, &heartbeat).await });

        // Long enough for the retry tick to answer a request twice if it would.
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        task.abort();
        let writes = writes.lock().unwrap().clone();
        let status: Vec<_> = writes.iter().filter(|w| w.1.contains("/status")).collect();
        assert_eq!(status.len(), 1, "{writes:?}");
        let (method, uri, body) = status[0];
        assert_eq!(method, "PATCH");
        assert!(
            uri.starts_with(
                "/apis/certificates.k8s.io/v1/namespaces/edge/podcertificaterequests/gw-1/status"
            ),
            "{uri}"
        );
        assert_eq!(body["status"]["conditions"][0]["type"], "Issued");
        let chain = body["status"]["certificateChain"].as_str().unwrap();
        let der = rustls_pki_types::CertificateDer::from_pem_slice(chain.as_bytes()).unwrap();
        let (_, leaf) = parse_x509_certificate(&der).unwrap();
        assert_eq!(
            leaf.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );

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

    #[tokio::test]
    async fn deletes_pod_dated_ahead_once() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let year = now() + 365 * 86_400;
        let pcr = |name: &str, pod: &str, uid: &str, status: serde_json::Value| {
            serde_json::json!({
                "apiVersion": "certificates.k8s.io/v1",
                "kind": "PodCertificateRequest",
                "metadata": { "name": name, "namespace": "edge", "resourceVersion": "1" },
                "spec": {
                    "signerName": SIGNER, "podName": pod, "podUID": uid,
                    "serviceAccountName": "edge-gateway", "serviceAccountUID": "s",
                    "nodeName": "n", "nodeUID": "nu", "maxExpirationSeconds": 3600,
                    "stubPKCS10Request": k8s_openapi::ByteString(csr(&PKCS_ECDSA_P256_SHA256).1),
                    "unverifiedUserAnnotations": { "edge.meridian/dns-names": "example.lan" },
                },
                "status": status,
            })
        };
        let ahead = serde_json::to_value(settle(
            &serde_json::from_value(pcr("gw-a-1", "gw-a", "old", serde_json::json!({}))).unwrap(),
            &file_ca(year),
            &unit(),
            year,
        ))
        .unwrap();
        let (url, writes, watch) = fake_apiserver(pcr("gw-a-1", "gw-a", "old", ahead)).await;
        let client = Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap();
        let path = scratch("recreate");
        let r = root("r", now() - 60, year + 86_400);
        std::fs::write(&path, file(&r, &[&r])).unwrap();
        let source = Source::open(&path, now()).unwrap();
        let heartbeat = Heartbeat::new(path.parent().unwrap());
        let task = tokio::spawn(async move { serve(client, &unit(), source, &heartbeat).await });

        let deletes = |w: &[(String, String, serde_json::Value)]| {
            w.iter()
                .filter(|w| w.0 == "DELETE")
                .cloned()
                .collect::<Vec<_>>()
        };
        wait_for_writes(&writes, |w| !deletes(w).is_empty()).await;
        let replacement = pcr("gw-b-1", "gw-b", "new", serde_json::json!({}));
        watch
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

    fn signer_at(url: &str, name: &str) -> (Client, Source, PathBuf) {
        let client = Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap();
        let path = scratch(name);
        let r = root("r", now() - 60, now() + 86_400 * 365);
        std::fs::write(&path, file(&r, &[&r])).unwrap();
        let source = Source::open(&path, now()).unwrap();
        (client, source, path.parent().unwrap().to_path_buf())
    }

    fn stamp(dir: &Path) -> Option<u128> {
        std::fs::read_to_string(dir.join("heartbeat"))
            .ok()?
            .parse()
            .ok()
    }

    async fn max_heartbeat_age(dir: &Path, span: Duration) -> Duration {
        let (mut first, mut oldest) = (None, Duration::ZERO);
        tokio::time::timeout(span * 2, async {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let Some(s) = stamp(dir) else { continue };
                let first = *first.get_or_insert(s);
                oldest = oldest.max(heartbeat::monotonic() - Duration::from_millis(s as u64));
                if s - first >= span.as_millis() {
                    break;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("heartbeat stuck at {:?}", stamp(dir)));
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
        let (client, source, dir) = signer_at(&format!("http://127.0.0.1:{port}"), "down");
        let heartbeat = Heartbeat::new(&dir);
        let task = tokio::spawn(async move { serve(client, &unit(), source, &heartbeat).await });
        let oldest = max_heartbeat_age(&dir, RETRY_INTERVAL).await;
        task.abort();
        assert!(
            oldest <= RETRY_INTERVAL + Duration::from_secs(1),
            "{oldest:?}"
        );
    }

    #[tokio::test]
    async fn hung_apiserver_keeps_beating() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut unanswered = Vec::new();
            loop {
                unanswered.push(listener.accept().await.unwrap().0);
            }
        });
        let (client, source, dir) = signer_at(&url, "hung");
        let heartbeat = Heartbeat::new(&dir);
        let task = tokio::spawn(async move { serve(client, &unit(), source, &heartbeat).await });
        let oldest = max_heartbeat_age(&dir, CALL_TIMEOUT).await;
        task.abort();
        assert!(
            oldest <= CALL_TIMEOUT + Duration::from_secs(1),
            "{oldest:?}"
        );
        assert!(heartbeat::check(&dir, heartbeat::monotonic()).is_ok());
    }

    #[tokio::test]
    async fn stalled_loop_stops_beating() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (url, _writes, _watch) = fake_apiserver(serde_json::json!({})).await;
        let (client, source, dir) = signer_at(&url, "stalled");
        let heartbeat = Heartbeat::new(&dir);
        let unit = unit();
        let mut serving = std::pin::pin!(serve(client, &unit, source, &heartbeat));
        let poll = Duration::from_millis(500);

        assert!(tokio::time::timeout(poll, serving.as_mut()).await.is_err());
        let before = stamp(&dir).expect("first pass beat");
        tokio::time::sleep(RETRY_INTERVAL + Duration::from_secs(1)).await;
        assert_eq!(stamp(&dir), Some(before), "beat while stalled");

        assert!(tokio::time::timeout(poll, serving.as_mut()).await.is_err());
        assert!(stamp(&dir).unwrap() > before, "no beat once running again");
    }
}
