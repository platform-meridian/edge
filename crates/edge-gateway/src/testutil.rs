use crate::authz::HeaderOp;
use crate::config::{Authz, Backend, Config, Route};
use crate::controller::Routes;
use crate::proxy::{Gateway, status};
use envoy_types::pb::envoy::config::core::v3::{HeaderValue as PbHeaderValue, HeaderValueOption};
use envoy_types::pb::envoy::service::auth::v3::authorization_server::{
    Authorization, AuthorizationServer,
};
use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
use envoy_types::pb::envoy::service::auth::v3::{CheckRequest, CheckResponse, OkHttpResponse};
use envoy_types::pb::google::rpc::Status as RpcStatus;
use http_body_util::BodyExt;
use hyper::{Request, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub fn insecure_cfg() -> Config {
    Config::parse_plaintext("listen: '127.0.0.1:0'\nroutes: []\n").unwrap()
}

pub fn authz_cfg(authz: SocketAddr) -> Config {
    Config::parse_plaintext(&format!(
        "listen: '127.0.0.1:0'\nauthz_backend: {{ host: '{}', port: {} }}\nroutes: []\n",
        authz.ip(),
        authz.port()
    ))
    .unwrap()
}

pub fn route(prefix: &str, authz: Authz, backend: SocketAddr) -> Route {
    Route {
        hostname: None,
        prefix: prefix.into(),
        authz,
        rewrite_host: None,
        backend: Backend {
            host: backend.ip().to_string(),
            port: backend.port(),
        },
    }
}

pub fn host_route(host: &str, prefix: &str, authz: Authz, backend: SocketAddr) -> Route {
    Route {
        hostname: Some(host.into()),
        ..route(prefix, authz, backend)
    }
}

pub struct RunningGateway {
    pub addr: SocketAddr,
    pub routes: Routes,
    _stop: tokio::sync::oneshot::Sender<()>,
}

pub async fn gateway(cfg: Config, routes: Vec<Route>) -> RunningGateway {
    start(cfg, routes, None).await
}

pub async fn start(
    cfg: Config,
    routes: Vec<Route>,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
) -> RunningGateway {
    let table: Routes = Arc::new(arc_swap::ArcSwap::from_pointee(routes));
    let gw = Gateway::new(Arc::new(cfg), table.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(crate::server::serve(listener, gw, acceptor, async move {
        let _ = rx.await;
    }));
    RunningGateway {
        addr,
        routes: table,
        _stop: tx,
    }
}

#[derive(Debug, Clone, Default)]
pub struct Seen {
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

pub struct Recorder {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Recorder {
    pub fn all(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    pub fn last(&self) -> Seen {
        self.all().pop().expect("backend saw no request")
    }
}

pub async fn recorder(tag: &'static str) -> Recorder {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let s2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = s2.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let seen = seen.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        seen.lock().unwrap().push(Seen {
                            target: parts
                                .uri
                                .path_and_query()
                                .map(|p| p.to_string())
                                .unwrap_or_default(),
                            headers: parts
                                .headers
                                .iter()
                                .map(|(k, v)| {
                                    (
                                        k.to_string(),
                                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                                    )
                                })
                                .collect(),
                            body: body.to_vec(),
                        });
                        Ok::<_, hyper::Error>(status(StatusCode::OK, tag))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Recorder { addr, seen }
}

pub async fn raw(addr: SocketAddr, req: &str) -> String {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

pub async fn get(addr: SocketAddr, target: &str, extra_headers: &str) -> (u16, String) {
    let resp = raw(
        addr,
        &format!(
            "GET {target} HTTP/1.1\r\nHost: t.test\r\n{extra_headers}Connection: close\r\n\r\n"
        ),
    )
    .await;
    parse_status(&resp)
}

pub fn parse_status(resp: &str) -> (u16, String) {
    let code = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (code, body)
}

#[derive(Clone, Default)]
pub enum AuthzMode {
    #[default]
    Allow,
    Deny,
    AllowWith {
        ops: Vec<HeaderOp>,
        remove: Vec<String>,
        response: Vec<(String, String)>,
    },
    SlowAllow(Duration),
    AllowWithHugeHeader(usize),
    Fail,
}

pub struct FakeAuthz {
    pub addr: SocketAddr,
    pub mode: Arc<Mutex<AuthzMode>>,
    pub calls: Arc<Mutex<Vec<CheckRequest>>>,
}

impl FakeAuthz {
    pub fn set(&self, m: AuthzMode) {
        *self.mode.lock().unwrap() = m;
    }
    pub fn calls(&self) -> Vec<CheckRequest> {
        self.calls.lock().unwrap().clone()
    }
}

struct FakeService {
    mode: Arc<Mutex<AuthzMode>>,
    calls: Arc<Mutex<Vec<CheckRequest>>>,
}

fn pb_header(key: &str, value: String, action: i32) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(PbHeaderValue {
            key: key.into(),
            value,
            ..Default::default()
        }),
        append_action: action,
        ..Default::default()
    }
}

#[tonic::async_trait]
impl Authorization for FakeService {
    async fn check(
        &self,
        req: tonic::Request<CheckRequest>,
    ) -> Result<tonic::Response<CheckResponse>, tonic::Status> {
        self.calls.lock().unwrap().push(req.into_inner());
        let mode = self.mode.lock().unwrap().clone();
        let ok = |ok: OkHttpResponse| CheckResponse {
            status: Some(RpcStatus {
                code: 0,
                ..Default::default()
            }),
            http_response: Some(HttpResponse::OkResponse(ok)),
            ..Default::default()
        };
        Ok(tonic::Response::new(match mode {
            AuthzMode::Allow => ok(OkHttpResponse::default()),
            AuthzMode::Deny => CheckResponse {
                status: Some(RpcStatus {
                    code: 7,
                    ..Default::default()
                }),
                ..Default::default()
            },
            AuthzMode::Fail => return Err(tonic::Status::unavailable("down")),
            AuthzMode::SlowAllow(d) => {
                tokio::time::sleep(d).await;
                ok(OkHttpResponse::default())
            }
            AuthzMode::AllowWithHugeHeader(n) => ok(OkHttpResponse {
                headers: vec![pb_header("x-big", "a".repeat(n), 2)],
                ..Default::default()
            }),
            AuthzMode::AllowWith {
                ops,
                remove,
                response,
            } => ok(OkHttpResponse {
                headers: ops
                    .into_iter()
                    .map(|op| match op {
                        HeaderOp::Append(k, v) => pb_header(&k, v, 0),
                        HeaderOp::AddIfAbsent(k, v) => pb_header(&k, v, 1),
                        HeaderOp::Set(k, v) => pb_header(&k, v, 2),
                        HeaderOp::OverwriteIfExists(k, v) => pb_header(&k, v, 3),
                    })
                    .collect(),
                headers_to_remove: remove,
                response_headers_to_add: response
                    .into_iter()
                    .map(|(k, v)| pb_header(&k, v, 2))
                    .collect(),
                ..Default::default()
            }),
        }))
    }
}

pub fn fake_service(
    mode: Arc<Mutex<AuthzMode>>,
    calls: Arc<Mutex<Vec<CheckRequest>>>,
) -> impl Authorization {
    FakeService { mode, calls }
}

pub async fn fake_authz() -> FakeAuthz {
    let mode = Arc::new(Mutex::new(AuthzMode::Allow));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = AuthorizationServer::new(FakeService {
        mode: mode.clone(),
        calls: calls.clone(),
    });
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });
    FakeAuthz { addr, mode, calls }
}

pub struct Issued {
    pub cert_pem: String,
    pub key_pem: String,
    pub der: Vec<u8>,
}

pub fn issue() -> Issued {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    Issued {
        cert_pem: ck.cert.pem(),
        key_pem: ck.signing_key.serialize_pem(),
        der: ck.cert.der().to_vec(),
    }
}

pub fn install(dir: &std::path::Path, c: &Issued) -> (String, String) {
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    for (path, body) in [(&cert, &c.cert_pem), (&key, &c.key_pem)] {
        let tmp = dir.join(format!(
            ".{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&tmp, body).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls_pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls_pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub async fn tls_connect(
    addr: SocketAddr,
    alpn: &[&str],
) -> std::io::Result<(
    tokio_rustls::client::TlsStream<TcpStream>,
    Vec<u8>,
    Option<Vec<u8>>,
)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    let tcp = TcpStream::connect(addr).await?;
    let s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await?;
    let (_, conn) = s.get_ref();
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();
    let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
    Ok((s, leaf, alpn))
}

pub async fn tls_get(addr: SocketAddr, target: &str) -> (u16, String, Vec<u8>) {
    let (mut s, leaf, _) = tls_connect(addr, &["http/1.1"]).await.unwrap();
    s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    let (code, body) = parse_status(&String::from_utf8_lossy(&buf));
    (code, body, leaf)
}
