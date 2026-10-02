//! The node's Talos API, as the pod's `talos.dev/v1alpha1` ServiceAccount
//! allows. The talosconfig Talos mounts is read per call: Talos renews its
//! certificate in place.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use base64::Engine as _;
use futures::StreamExt;
use prost::Message;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

#[allow(clippy::enum_variant_names)]
pub mod pb {
    tonic::include_proto!("machine");
    pub mod cosi {
        tonic::include_proto!("cosi.resource");
    }
}

use pb::apply_configuration_request::Mode;
use pb::cosi::state_client::StateClient;
use pb::image_service_client::ImageServiceClient;
use pb::lifecycle_service_client::LifecycleServiceClient;
use pb::lifecycle_service_install_progress::Response as Progress;
use pb::machine_service_client::MachineServiceClient;

const CALL: Duration = Duration::from_secs(60);

pub struct Node {
    talosconfig: PathBuf,
    apid: String,
}

#[derive(Deserialize)]
struct Talosconfig {
    context: String,
    contexts: std::collections::BTreeMap<String, Context_>,
}

#[derive(Deserialize)]
struct Context_ {
    #[serde(default)]
    endpoints: Vec<String>,
    ca: String,
    crt: String,
    key: String,
}

fn b64(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s.trim())?)
}

impl Node {
    /// `apid` is dialled; the certificate is checked against the talosconfig's endpoint.
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
        // The certificate names the service Talos made for pods, not the address dialled.
        let host = ctx
            .endpoints
            .first()
            .map(String::as_str)
            .unwrap_or("talos.default");
        let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
        // Talos labels its PKCS#8 Ed25519 keys its own way.
        let key = String::from_utf8(b64(&ctx.key)?)?.replace("ED25519 PRIVATE KEY", "PRIVATE KEY");
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(b64(&ctx.ca)?))
            .identity(Identity::from_pem(b64(&ctx.crt)?, key))
            .domain_name(host);
        Ok(Endpoint::from_shared(self.apid.clone())?
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(10))
            .connect_lazy())
    }

    fn machine(&self) -> anyhow::Result<MachineServiceClient<Channel>> {
        Ok(MachineServiceClient::new(self.channel()?))
    }
}

fn req<T>(msg: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    r.set_timeout(CALL);
    r
}

fn upstream(md: Option<&pb::Metadata>) -> anyhow::Result<()> {
    match md.map(|m| m.error.as_str()) {
        Some(e) if !e.is_empty() => bail!("{e}"),
        _ => Ok(()),
    }
}

fn system() -> pb::ContainerdInstance {
    pb::ContainerdInstance {
        driver: pb::ContainerDriver::Cri as i32,
        namespace: pb::ContainerdNamespace::NsSystem as i32,
    }
}

impl Node {
    /// The first of `ids` among the node's machine configs.
    async fn config(&self, ids: &[&str]) -> anyhow::Result<String> {
        let mut client = StateClient::new(self.channel()?);
        for &id in ids {
            let get = pb::cosi::GetRequest {
                namespace: "config".into(),
                r#type: "MachineConfigs.config.talos.dev".into(),
                id: id.into(),
            };
            let r = match client.get(req(get)).await {
                Ok(r) => r.into_inner(),
                Err(e) if e.code() == tonic::Code::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let spec = r
                .resource
                .and_then(|r| r.spec)
                .context("the machine config has no spec")?;
            if !spec.proto_spec.is_empty() {
                let s = pb::cosi::MachineConfigSpec::decode(spec.proto_spec.as_slice())?;
                return Ok(String::from_utf8(s.yaml_marshalled)?);
            }
            return Ok(serde_yaml::from_str::<String>(&spec.yaml_spec)?);
        }
        bail!("the node has no machine config")
    }

    async fn apply(&self, config: &str, mode: Mode, dry_run: bool) -> anyhow::Result<()> {
        let r = self
            .machine()?
            .apply_configuration(req(pb::ApplyConfigurationRequest {
                data: config.as_bytes().to_vec(),
                mode: mode as i32,
                dry_run,
            }))
            .await?
            .into_inner();
        for m in &r.messages {
            upstream(m.metadata.as_ref())?;
            for w in &m.warnings {
                tracing::warn!(warning = %w, "machine config");
            }
        }
        Ok(())
    }
}

#[async_trait]
impl crate::unit::Talos for Node {
    async fn version(&self) -> anyhow::Result<String> {
        let r = self
            .machine()?
            .version(req(pb::Empty {}))
            .await?
            .into_inner();
        let v = r.messages.into_iter().next().context("no version reply")?;
        upstream(v.metadata.as_ref())?;
        Ok(v.version.context("no version")?.tag)
    }

    async fn read(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut s = match self
            .machine()?
            .read(req(pb::ReadRequest { path: path.into() }))
            .await
        {
            Ok(s) => s.into_inner(),
            Err(e) if e.code() == tonic::Code::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        while let Some(d) = s.next().await {
            match d {
                Ok(d) => {
                    upstream(d.metadata.as_ref())?;
                    out.extend(d.bytes);
                }
                Err(e) if e.code() == tonic::Code::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Some(out))
    }

    async fn size(&self, path: &str) -> anyhow::Result<Option<u64>> {
        let dir = Path::new(path)
            .parent()
            .context("a path with no directory")?;
        let root = dir.to_string_lossy().into_owned();
        let mut s = match self.machine()?.list(req(pb::ListRequest { root })).await {
            Ok(s) => s.into_inner(),
            Err(e) if e.code() == tonic::Code::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        while let Some(f) = s.next().await {
            let f = f?;
            if f.name == path && f.error.is_empty() && !f.is_dir {
                return Ok(Some(f.size as u64));
            }
        }
        Ok(None)
    }

    async fn copy(&self, path: &str, dest: &Path) -> anyhow::Result<u64> {
        let mut r = req(pb::ReadRequest { path: path.into() });
        r.set_timeout(Duration::from_secs(3600));
        let mut s = self.machine()?.read(r).await?.into_inner();
        let mut f = tokio::fs::File::create(dest).await?;
        let mut n = 0u64;
        while let Some(d) = s.next().await {
            let d = d?;
            upstream(d.metadata.as_ref())?;
            f.write_all(&d.bytes).await?;
            n += d.bytes.len() as u64;
        }
        f.flush().await?;
        Ok(n)
    }

    async fn machine_config(&self) -> anyhow::Result<String> {
        // `persistent` is what the next boot uses, a staged config included.
        self.config(&["persistent", "v1alpha1"]).await
    }

    async fn running_config(&self) -> anyhow::Result<String> {
        self.config(&["v1alpha1"]).await
    }

    async fn stage_config(&self, config: &str, dry_run: bool) -> anyhow::Result<()> {
        self.apply(config, Mode::Staged, dry_run).await
    }

    async fn apply_config(&self, config: &str) -> anyhow::Result<()> {
        self.apply(config, Mode::NoReboot, false).await
    }

    async fn install(&self, image: &str) -> anyhow::Result<()> {
        let mut pull = req(pb::ImageServicePullRequest {
            containerd: Some(system()),
            image_ref: image.into(),
        });
        pull.set_timeout(Duration::from_secs(1800));
        let mut s = ImageServiceClient::new(self.channel()?)
            .pull(pull)
            .await?
            .into_inner();
        let mut name = None;
        while let Some(r) = s.next().await {
            if let Some(pb::image_service_pull_response::Response::Name(n)) = r?.response {
                name = Some(n);
            }
        }
        let name = name.with_context(|| format!("pulling {image} named no image"))?;

        let mut up = req(pb::LifecycleServiceUpgradeRequest {
            containerd: Some(system()),
            source: Some(pb::InstallArtifactsSource { image_name: name }),
        });
        up.set_timeout(Duration::from_secs(1800));
        let mut s = LifecycleServiceClient::new(self.channel()?)
            .upgrade(up)
            .await?
            .into_inner();
        while let Some(r) = s.next().await {
            match r?.progress.and_then(|p| p.response) {
                Some(Progress::Message(m)) => tracing::info!(%m, "install"),
                Some(Progress::ExitCode(0)) => return Ok(()),
                Some(Progress::ExitCode(c)) => bail!("the installer exited {c}"),
                None => {}
            }
        }
        bail!("the install ended without an exit code")
    }

    async fn reboot(&self) -> anyhow::Result<()> {
        let r = self
            .machine()?
            .reboot(req(pb::RebootRequest {
                mode: pb::reboot_request::Mode::Powercycle as i32,
            }))
            .await?
            .into_inner();
        for m in &r.messages {
            upstream(m.metadata.as_ref())?;
        }
        Ok(())
    }

    async fn rollback(&self) -> anyhow::Result<()> {
        let r = self
            .machine()?
            .rollback(req(pb::RollbackRequest {}))
            .await?
            .into_inner();
        for m in &r.messages {
            upstream(m.metadata.as_ref())?;
        }
        Ok(())
    }

    async fn shutdown(&self) -> anyhow::Result<()> {
        let r = self
            .machine()?
            .shutdown(req(pb::ShutdownRequest { force: false }))
            .await?
            .into_inner();
        for m in &r.messages {
            upstream(m.metadata.as_ref())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::Talos;
    use pb::machine_service_server::{MachineService, MachineServiceServer};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ED25519};
    use tonic::transport::{Server, ServerTlsConfig};
    use tonic::{Request, Response, Status};

    type Stream<T> = std::pin::Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

    /// Answers as apid does, and says which config and power calls it took.
    #[derive(Clone, Default)]
    struct Apid(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    #[tonic::async_trait]
    impl MachineService for Apid {
        type ListStream = Stream<pb::FileInfo>;
        type ReadStream = Stream<pb::Data>;
        async fn apply_configuration(
            &self,
            r: Request<pb::ApplyConfigurationRequest>,
        ) -> Result<Response<pb::ApplyConfigurationResponse>, Status> {
            let r = r.into_inner();
            let call = format!("{:?} dry_run={}", r.mode(), r.dry_run);
            self.0.lock().unwrap().push(call);
            Ok(Response::new(pb::ApplyConfigurationResponse {
                messages: vec![],
            }))
        }
        async fn list(
            &self,
            _: Request<pb::ListRequest>,
        ) -> Result<Response<Self::ListStream>, Status> {
            let f = pb::FileInfo {
                name: "/var/lib/etcd/state.log".into(),
                size: 42,
                ..Default::default()
            };
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(f)]))))
        }
        async fn read(
            &self,
            r: Request<pb::ReadRequest>,
        ) -> Result<Response<Self::ReadStream>, Status> {
            if r.into_inner().path != "/proc/sys/kernel/random/boot_id" {
                return Err(Status::not_found("no such file"));
            }
            let chunks = ["b00t", "-id\n"].map(|c| {
                Ok(pb::Data {
                    metadata: None,
                    bytes: c.as_bytes().to_vec(),
                })
            });
            Ok(Response::new(Box::pin(futures::stream::iter(chunks))))
        }
        async fn reboot(
            &self,
            r: Request<pb::RebootRequest>,
        ) -> Result<Response<pb::RebootResponse>, Status> {
            let mode = r.into_inner().mode();
            self.0.lock().unwrap().push(format!("reboot {mode:?}"));
            Ok(Response::new(pb::RebootResponse { messages: vec![] }))
        }
        async fn rollback(
            &self,
            _: Request<pb::RollbackRequest>,
        ) -> Result<Response<pb::RollbackResponse>, Status> {
            self.0.lock().unwrap().push("rollback".into());
            Ok(Response::new(pb::RollbackResponse { messages: vec![] }))
        }
        async fn shutdown(
            &self,
            r: Request<pb::ShutdownRequest>,
        ) -> Result<Response<pb::ShutdownResponse>, Status> {
            let force = r.into_inner().force;
            self.0
                .lock()
                .unwrap()
                .push(format!("shutdown force={force}"));
            Ok(Response::new(pb::ShutdownResponse {
                messages: vec![pb::Shutdown {
                    metadata: Some(pb::Metadata {
                        hostname: String::new(),
                        error: "already shutting down".into(),
                    }),
                }],
            }))
        }
        async fn version(
            &self,
            _: Request<pb::Empty>,
        ) -> Result<Response<pb::VersionResponse>, Status> {
            Ok(Response::new(pb::VersionResponse {
                messages: vec![pb::Version {
                    metadata: None,
                    version: Some(pb::VersionInfo {
                        tag: "v1.14.1".into(),
                    }),
                }],
            }))
        }
    }

    struct Pki {
        ca: String,
        issuer: Issuer<'static, KeyPair>,
    }

    impl Pki {
        fn new() -> Self {
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = p.self_signed(&key).unwrap().pem();
            Self {
                ca,
                issuer: Issuer::new(p, key),
            }
        }
        /// A leaf and its key, the key labelled as Talos labels it.
        fn leaf(&self, names: &[&str]) -> (String, String) {
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let p = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
            let cert = p.signed_by(&key, &self.issuer).unwrap().pem();
            (
                cert,
                key.serialize_pem()
                    .replace("PRIVATE KEY", "ED25519 PRIVATE KEY"),
            )
        }
    }

    async fn serve(server: &Pki, clients: &Pki, apid: Apid) -> std::net::SocketAddr {
        let (cert, key) = server.leaf(&["talos.default"]);
        let key = key.replace("ED25519 PRIVATE KEY", "PRIVATE KEY");
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .client_ca_root(Certificate::from_pem(&clients.ca));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(MachineServiceServer::new(apid))
                .serve_with_incoming(incoming),
        );
        addr
    }

    fn talosconfig(dir: &Path, ca: &str, (crt, key): (String, String)) -> PathBuf {
        let e = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let text = format!(
            "context: pod\ncontexts:\n  pod:\n    endpoints: [talos.default]\n    ca: {}\n    crt: {}\n    key: {}\n",
            e(ca),
            e(&crt),
            e(&key)
        );
        let p = dir.join("config");
        std::fs::write(&p, text).unwrap();
        p
    }

    /// A node whose talosconfig apid's PKI issued.
    async fn node(apid: Apid) -> (Node, tempfile::TempDir) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = Pki::new();
        let addr = serve(&pki, &pki, apid).await;
        let d = tempfile::tempdir().unwrap();
        let node = Node::new(
            &talosconfig(d.path(), &pki.ca, pki.leaf(&[])),
            &addr.to_string(),
        );
        (node, d)
    }

    #[tokio::test]
    async fn a_pod_talosconfig_reaches_apid() {
        let (node, _d) = node(Apid::default()).await;
        assert_eq!(node.version().await.unwrap(), "v1.14.1");
        assert_eq!(
            node.read("/proc/sys/kernel/random/boot_id")
                .await
                .unwrap()
                .unwrap(),
            b"b00t-id\n"
        );
        assert_eq!(node.read("/nope").await.unwrap(), None);
        assert_eq!(
            node.size("/var/lib/etcd/state.log").await.unwrap(),
            Some(42)
        );
        assert_eq!(node.size("/var/lib/etcd/other").await.unwrap(), None);
    }

    #[tokio::test]
    async fn another_pki_is_turned_away() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server, other) = (Pki::new(), Pki::new());
        let addr = serve(&server, &server, Apid::default()).await;
        let d = tempfile::tempdir().unwrap();
        // A client from another PKI, trusting the right server.
        let node = Node::new(
            &talosconfig(d.path(), &server.ca, other.leaf(&[])),
            &addr.to_string(),
        );
        assert!(node.version().await.is_err());
        // The right client, trusting another server.
        let node = Node::new(
            &talosconfig(d.path(), &other.ca, server.leaf(&[])),
            &addr.to_string(),
        );
        assert!(node.version().await.is_err());
    }

    #[tokio::test]
    async fn power_calls_power_cycle_roll_back_and_shut_down_gracefully() {
        let apid = Apid::default();
        let (node, _d) = node(apid.clone()).await;
        node.reboot().await.unwrap();
        node.rollback().await.unwrap();
        let e = node.shutdown().await.unwrap_err();
        assert_eq!(e.to_string(), "already shutting down");
        assert_eq!(
            *apid.0.lock().unwrap(),
            ["reboot Powercycle", "rollback", "shutdown force=false"]
        );
    }

    #[tokio::test]
    async fn configs_stage_or_apply_without_reboot() {
        let apid = Apid::default();
        let (node, _d) = node(apid.clone()).await;
        node.stage_config("c", true).await.unwrap();
        node.stage_config("c", false).await.unwrap();
        node.apply_config("c").await.unwrap();
        assert_eq!(
            *apid.0.lock().unwrap(),
            [
                "Staged dry_run=true",
                "Staged dry_run=false",
                "NoReboot dry_run=false"
            ]
        );
    }
}
