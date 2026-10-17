//! Short-lived administrator access to the unit: a talosconfig Talos issues
//! from its own CA, and a kubeconfig the cluster's client signer issues, for a
//! caller the cluster authorizes. Nothing issued is kept.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine as _;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use k8s_openapi::ByteString;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SubjectAccessReview, SubjectAccessReviewSpec,
};
use k8s_openapi::api::certificates::v1::{
    CertificateSigningRequest, CertificateSigningRequestSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Patch, PatchParams, PostParams};
use kube::{Api, Client, ResourceExt};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::Deserialize;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

#[allow(clippy::enum_variant_names)]
pub mod talos_pb {
    tonic::include_proto!("machine");
}

pub mod pb {
    connectrpc::include_generated!();
}

use pb::edge::signer::v1 as api;
use talos_pb::machine_service_client::MachineServiceClient;

/// A few hours: long enough for a session's work, short enough to need no revocation.
pub const LIFETIME: Duration = Duration::from_secs(4 * 3600);
/// What a caller must be allowed: verb `issue` on this signer.
pub const SIGNER: &str = "edge.meridian/access";
/// The deploy binds this group to `cluster-admin`.
pub const GROUP: &str = "edge:administrators";
const CLIENT_SIGNER: &str = "kubernetes.io/kube-apiserver-client";
const ISSUE_WAIT: Duration = Duration::from_secs(30);
const CALL: Duration = Duration::from_secs(15);

/// Where operators reach the unit.
#[derive(Clone, Debug)]
pub struct Reach {
    pub unit: String,
    pub address: Option<IpAddr>,
    pub apiserver_port: u16,
}

pub struct Service {
    client: Client,
    talos: Talos,
    reach: Reach,
    cluster_ca: PathBuf,
}

impl Service {
    pub fn new(client: Client, talos: Talos, reach: Reach, cluster_ca: PathBuf) -> Self {
        Self {
            client,
            talos,
            reach,
            cluster_ca,
        }
    }

    /// The caller's service account token, reviewed, and its permission.
    async fn authorize(&self, headers: &http::HeaderMap) -> Result<String, ConnectError> {
        let token = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| ConnectError::unauthenticated("no bearer token"))?;
        let review = TokenReview {
            spec: TokenReviewSpec {
                token: token.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let reviewed = timed(
            Api::<TokenReview>::all(self.client.clone()).create(&PostParams::default(), &review),
        )
        .await
        .map_err(|e| ConnectError::unavailable(format!("token review: {e:#}")))?;
        let user = reviewed
            .status
            .filter(|s| s.authenticated == Some(true))
            .and_then(|s| s.user)
            .ok_or_else(|| ConnectError::unauthenticated("the token is not valid"))?;
        let name = user.username.clone().unwrap_or_default();
        let sar = SubjectAccessReview {
            spec: SubjectAccessReviewSpec {
                user: user.username,
                groups: user.groups,
                uid: user.uid,
                extra: user.extra,
                resource_attributes: Some(ResourceAttributes {
                    group: Some("certificates.k8s.io".into()),
                    resource: Some("signers".into()),
                    name: Some(SIGNER.into()),
                    verb: Some("issue".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let decided = timed(
            Api::<SubjectAccessReview>::all(self.client.clone())
                .create(&PostParams::default(), &sar),
        )
        .await
        .map_err(|e| ConnectError::unavailable(format!("access review: {e:#}")))?;
        if !decided.status.is_some_and(|s| s.allowed) {
            return Err(ConnectError::permission_denied(format!(
                "{name} may not issue {SIGNER}"
            )));
        }
        Ok(name)
    }

    async fn issue(&self, by: &str) -> anyhow::Result<api::IssueAccessResponse> {
        let address = self
            .reach
            .address
            .context("no address operators reach the unit at (EDGE_SIGNER_ADDRESS)")?;
        let cluster_ca = std::fs::read(&self.cluster_ca)
            .with_context(|| format!("read {}", self.cluster_ca.display()))?;
        let (talos, kube) = tokio::join!(
            self.talos.issue(LIFETIME),
            client_certificate(&self.client, by, LIFETIME)
        );
        let talos = talos.context("Talos issued no client certificate")?;
        let (crt, key) = kube.context("the cluster issued no client certificate")?;
        Ok(api::IssueAccessResponse {
            talosconfig: talosconfig(&self.reach.unit, address, &talos)?.into_bytes(),
            kubeconfig: kubeconfig(
                &self.reach.unit,
                by,
                SocketAddr::new(address, self.reach.apiserver_port),
                &cluster_ca,
                &crt,
                &key,
            )?
            .into_bytes(),
            expires_at: crate::now() + LIFETIME.as_secs() as i64,
            ..Default::default()
        })
    }
}

#[allow(refining_impl_trait_internal, refining_impl_trait_reachable)]
impl api::AccessService for Service {
    async fn issue_access(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, api::IssueAccessRequest>,
    ) -> ServiceResult<api::IssueAccessResponse> {
        let caller = self.authorize(ctx.headers()).await?;
        let by = holder(request.by).map_err(ConnectError::invalid_argument)?;
        let r = self.issue(&by).await.map_err(|e| {
            tracing::warn!(caller, by, error = format!("{e:#}"), "access not issued");
            ConnectError::unavailable(format!("{e:#}"))
        })?;
        tracing::info!(caller, by, expires_at = r.expires_at, "access issued");
        Response::ok(r)
    }
}

async fn timed<T>(call: impl Future<Output = kube::Result<T>>) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(CALL, call).await??)
}

/// The certificate's subject: who asked, else the role it grants.
fn holder(by: &str) -> Result<String, String> {
    let by = by.trim();
    if by.is_empty() {
        return Ok("administrator".into());
    }
    if by.len() > 64 || by.starts_with("system:") || by.chars().any(char::is_control) {
        return Err(format!("{by:?} cannot name a certificate"));
    }
    Ok(by.into())
}

/// A client certificate from the cluster's own signer, through a request this
/// signer approves.
async fn client_certificate(
    client: &Client,
    by: &str,
    lifetime: Duration,
) -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let request = client_request(by, &key)?;
    let csrs: Api<CertificateSigningRequest> = Api::all(client.clone());
    let csr = CertificateSigningRequest {
        metadata: ObjectMeta {
            generate_name: Some("edge-access-".into()),
            ..Default::default()
        },
        spec: CertificateSigningRequestSpec {
            request: ByteString(request.into_bytes()),
            signer_name: CLIENT_SIGNER.into(),
            expiration_seconds: Some(lifetime.as_secs() as i32),
            usages: Some(vec!["digital signature".into(), "client auth".into()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let name = timed(csrs.create(&PostParams::default(), &csr))
        .await?
        .name_any();
    timed(csrs.patch_approval(
        &name,
        &PatchParams::default(),
        &Patch::Merge(approval(crate::time(crate::now()))),
    ))
    .await?;
    let deadline = tokio::time::Instant::now() + ISSUE_WAIT;
    loop {
        let got = timed(csrs.get(&name)).await?;
        let status = got.status.unwrap_or_default();
        if let Some(c) = status
            .conditions
            .iter()
            .flatten()
            .find(|c| matches!(c.type_.as_str(), "Denied" | "Failed") && c.status == "True")
        {
            bail!(
                "{name}: {} ({})",
                c.type_,
                c.message.clone().unwrap_or_default()
            );
        }
        if let Some(crt) = status.certificate.filter(|c| !c.0.is_empty()) {
            return Ok((String::from_utf8(crt.0)?, key.serialize_pem()));
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("{name}: not signed within {}s", ISSUE_WAIT.as_secs());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Kubernetes reads the user from the subject's CN and its groups from O.
fn client_request(by: &str, key: &KeyPair) -> anyhow::Result<String> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, by);
    params
        .distinguished_name
        .push(DnType::OrganizationName, GROUP);
    Ok(params.serialize_request(key)?.pem()?)
}

fn approval(now: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time) -> serde_json::Value {
    serde_json::json!({ "status": { "conditions": [{
        "type": "Approved",
        "status": "True",
        "reason": "AccessIssued",
        "message": "operator access, approved by edge-signer",
        "lastUpdateTime": now,
    }]}})
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn host(address: IpAddr) -> String {
    match address {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{a}]"),
    }
}

/// Talos's client certificate, as talosctl reads it.
pub struct TalosCertificate {
    pub ca: Vec<u8>,
    pub crt: Vec<u8>,
    pub key: Vec<u8>,
}

fn talosconfig(unit: &str, address: IpAddr, c: &TalosCertificate) -> anyhow::Result<String> {
    let context = serde_json::json!({
        "endpoints": [host(address)],
        "nodes": [address.to_string()],
        "ca": b64(&c.ca),
        "crt": b64(&c.crt),
        "key": b64(&c.key),
    });
    Ok(serde_yaml::to_string(&serde_json::json!({
        "context": unit,
        "contexts": { unit: context },
    }))?)
}

fn kubeconfig(
    unit: &str,
    by: &str,
    apiserver: SocketAddr,
    ca: &[u8],
    crt: &str,
    key: &str,
) -> anyhow::Result<String> {
    let user = format!("{by}@{unit}");
    Ok(serde_yaml::to_string(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{ "name": unit, "cluster": {
            "server": format!("https://{apiserver}"),
            "certificate-authority-data": b64(ca),
        }}],
        "users": [{ "name": user, "user": {
            "client-certificate-data": b64(crt.as_bytes()),
            "client-key-data": b64(key.as_bytes()),
        }}],
        "contexts": [{ "name": unit, "context": { "cluster": unit, "user": user } }],
        "current-context": unit,
    }))?)
}

/// The node's Talos API, as the pod's `talos.dev/v1alpha1` ServiceAccount
/// allows. The talosconfig Talos mounts is read per call: Talos renews its
/// certificate in place.
pub struct Talos {
    talosconfig: PathBuf,
    apid: String,
}

#[derive(Deserialize)]
struct Talosconfig {
    context: String,
    contexts: std::collections::BTreeMap<String, TalosContext>,
}

#[derive(Deserialize)]
struct TalosContext {
    #[serde(default)]
    endpoints: Vec<String>,
    ca: String,
    crt: String,
    key: String,
}

impl Talos {
    /// `apid` is dialled; its certificate is checked against the talosconfig's endpoint.
    pub fn new(talosconfig: &Path, apid: &str) -> Self {
        Self {
            talosconfig: talosconfig.into(),
            apid: format!("https://{apid}"),
        }
    }

    fn channel(&self) -> anyhow::Result<Channel> {
        let text = std::fs::read_to_string(&self.talosconfig)
            .with_context(|| format!("read {}", self.talosconfig.display()))?;
        let tc: Talosconfig = serde_yaml::from_str(&text)?;
        let ctx = tc
            .contexts
            .get(&tc.context)
            .context("the talosconfig's context is missing")?;
        let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s.trim());
        // The certificate names the service Talos made for pods, not the address dialled.
        let name = ctx
            .endpoints
            .first()
            .map(String::as_str)
            .unwrap_or("talos.default");
        let name = name.rsplit_once(':').map_or(name, |(h, _)| h);
        // Talos labels its PKCS#8 Ed25519 keys its own way.
        let key =
            String::from_utf8(decode(&ctx.key)?)?.replace("ED25519 PRIVATE KEY", "PRIVATE KEY");
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(decode(&ctx.ca)?))
            .identity(Identity::from_pem(decode(&ctx.crt)?, key))
            .domain_name(name);
        Ok(Endpoint::from_shared(self.apid.clone())?
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(10))
            .connect_lazy())
    }

    async fn issue(&self, lifetime: Duration) -> anyhow::Result<TalosCertificate> {
        let mut req = tonic::Request::new(talos_pb::GenerateClientConfigurationRequest {
            roles: vec!["os:admin".into()],
            crt_ttl: Some(prost_types::Duration {
                seconds: lifetime.as_secs() as i64,
                nanos: 0,
            }),
        });
        req.set_timeout(CALL);
        let reply = MachineServiceClient::new(self.channel()?)
            .generate_client_configuration(req)
            .await?
            .into_inner();
        let m = reply.messages.into_iter().next().context("no reply")?;
        if let Some(e) = m.metadata.map(|m| m.error).filter(|e| !e.is_empty()) {
            bail!("{e}");
        }
        Ok(TalosCertificate {
            ca: m.ca,
            crt: m.crt,
            key: m.key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::pem::PemObject;
    use x509_parser::prelude::FromDer;

    #[test]
    fn a_holder_is_who_asked_else_the_role() {
        assert_eq!(holder("").unwrap(), "administrator");
        assert_eq!(holder(" ada ").unwrap(), "ada");
        assert!(holder("system:masters").is_err());
        assert!(holder("a\nb").is_err());
        assert!(holder(&"x".repeat(65)).is_err());
    }

    #[test]
    fn a_talosconfig_names_the_unit_at_its_address() {
        let c = TalosCertificate {
            ca: b"ca".to_vec(),
            crt: b"crt".to_vec(),
            key: b"key".to_vec(),
        };
        let v4: serde_yaml::Value =
            serde_yaml::from_str(&talosconfig("u1", "10.50.0.1".parse().unwrap(), &c).unwrap())
                .unwrap();
        assert_eq!(v4["context"], "u1");
        let ctx = &v4["contexts"]["u1"];
        assert_eq!(ctx["endpoints"][0], "10.50.0.1");
        assert_eq!(ctx["nodes"][0], "10.50.0.1");
        assert_eq!(ctx["crt"], b64(b"crt"));
        let v6: serde_yaml::Value =
            serde_yaml::from_str(&talosconfig("u1", "fd00::1".parse().unwrap(), &c).unwrap())
                .unwrap();
        assert_eq!(v6["contexts"]["u1"]["endpoints"][0], "[fd00::1]");
        assert_eq!(v6["contexts"]["u1"]["nodes"][0], "fd00::1");
    }

    #[test]
    fn a_kubeconfig_reaches_the_apiserver_as_the_holder() {
        let text = kubeconfig(
            "u1",
            "ada",
            "[fd00::1]:6443".parse().unwrap(),
            b"ca",
            "crt",
            "key",
        )
        .unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        assert_eq!(v["current-context"], "u1");
        assert_eq!(
            v["clusters"][0]["cluster"]["server"],
            "https://[fd00::1]:6443"
        );
        assert_eq!(
            v["clusters"][0]["cluster"]["certificate-authority-data"],
            b64(b"ca")
        );
        assert_eq!(v["contexts"][0]["context"]["user"], "ada@u1");
        assert_eq!(v["users"][0]["user"]["client-key-data"], b64(b"key"));
    }

    #[test]
    fn the_request_names_the_holder_in_the_administrators_group() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = client_request("ada", &key).unwrap();
        let der =
            rustls_pki_types::CertificateSigningRequestDer::from_pem_slice(pem.as_bytes()).unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der).unwrap();
        let subject = csr.certification_request_info.subject.to_string();
        assert_eq!(subject, format!("CN=ada, O={GROUP}"));
    }

    /// An apiserver that knows one token, allows one service account, and signs
    /// every approved request; it records what it was sent.
    async fn apiserver(calls: Calls) -> Client {
        use http_body_util::{BodyExt, Full};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let calls = calls.clone();
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let calls = calls.clone();
                        async move {
                            let (method, path) =
                                (req.method().to_string(), req.uri().path().to_string());
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let v: serde_json::Value =
                                serde_json::from_slice(&body).unwrap_or_default();
                            calls
                                .lock()
                                .unwrap()
                                .push((method.clone(), path.clone(), v.clone()));
                            let reply = if path.ends_with("/tokenreviews") {
                                let good = v["spec"]["token"] == "good";
                                serde_json::json!({ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                                "spec": v["spec"], "status": { "authenticated": good,
                                "user": { "username": "system:serviceaccount:ops:console",
                                          "groups": ["system:serviceaccounts"] } } })
                            } else if path.ends_with("/subjectaccessreviews") {
                                let ok = v["spec"]["user"] == "system:serviceaccount:ops:console"
                                    && v["spec"]["resourceAttributes"]["verb"] == "issue"
                                    && v["spec"]["resourceAttributes"]["name"] == SIGNER;
                                serde_json::json!({ "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                                "spec": v["spec"], "status": { "allowed": ok } })
                            } else {
                                let mut csr = serde_json::json!({ "apiVersion": "certificates.k8s.io/v1",
                                "kind": "CertificateSigningRequest",
                                "metadata": { "name": "edge-access-x" },
                                "spec": { "request": "", "signerName": CLIENT_SIGNER } });
                                if method == "GET" {
                                    csr["status"] =
                                        serde_json::json!({ "certificate": b64(b"CERT") });
                                }
                                csr
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .header("content-type", "application/json")
                                    .body(Full::new(bytes::Bytes::from(reply.to_string())))
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
        Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap()
    }

    type Calls = std::sync::Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>;

    fn service(client: Client) -> Service {
        let reach = Reach {
            unit: "u1".into(),
            address: Some("10.50.0.1".parse().unwrap()),
            apiserver_port: 6443,
        };
        Service::new(
            client,
            Talos::new(Path::new("/nonexistent"), "127.0.0.1:1"),
            reach,
            "/nonexistent".into(),
        )
    }

    fn bearer(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn only_a_caller_the_cluster_allows_is_served() {
        let calls = Calls::default();
        let s = service(apiserver(calls.clone()).await);
        let name = s.authorize(&bearer("good")).await.unwrap();
        assert_eq!(name, "system:serviceaccount:ops:console");
        let e = s.authorize(&bearer("bad")).await.unwrap_err();
        assert_eq!(e.code, connectrpc::ErrorCode::Unauthenticated);
        let e = s.authorize(&http::HeaderMap::new()).await.unwrap_err();
        assert_eq!(e.code, connectrpc::ErrorCode::Unauthenticated);
        let sar = calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.1.ends_with("/subjectaccessreviews"))
            .cloned()
            .unwrap();
        assert_eq!(sar.2["spec"]["resourceAttributes"]["resource"], "signers");
        assert_eq!(sar.2["spec"]["groups"][0], "system:serviceaccounts");
    }

    #[tokio::test]
    async fn the_client_certificate_is_requested_short_lived_and_approved() {
        let calls = Calls::default();
        let client = apiserver(calls.clone()).await;
        let (crt, key) = client_certificate(&client, "ada", LIFETIME).await.unwrap();
        assert_eq!(crt, "CERT");
        assert!(key.contains("PRIVATE KEY"));
        let calls = calls.lock().unwrap();
        let created = &calls.iter().find(|c| c.0 == "POST").unwrap().2;
        assert_eq!(created["spec"]["signerName"], CLIENT_SIGNER);
        assert_eq!(created["spec"]["expirationSeconds"], 4 * 3600);
        assert_eq!(created["metadata"]["generateName"], "edge-access-");
        let approved = calls.iter().find(|c| c.0 == "PATCH").unwrap();
        assert!(
            approved
                .1
                .ends_with("/certificatesigningrequests/edge-access-x/approval")
        );
        assert_eq!(approved.2["status"]["conditions"][0]["type"], "Approved");
    }
}
