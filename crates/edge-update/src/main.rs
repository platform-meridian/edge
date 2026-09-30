//! Verifies signed update bundles and applies them to the unit it runs on.
//!
//!   edge-update                 serve the update API and run the engine
//!   edge-update strip-config    a full machine config on stdin, its patch on stdout
//!   edge-update check-bundle <bundle.tar> <key.pub> <namespace> <scratch dir>
//!                               what the unit checks before touching anything, and
//!                               an import into a scratch registry store

mod api;
mod bundle;
mod cluster;
mod engine;
mod machineconfig;
mod registry;
mod talos;
mod unit;
mod upload;

mod pb {
    connectrpc::include_generated!();
}

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::{mpsc, watch};

use api::{Command, Snapshot};
use engine::{Engine, Tick};
use pb::edge::update::v1::UpdateServiceExt;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("strip-config") => {
            let mut full = String::new();
            std::io::stdin().read_to_string(&mut full)?;
            print!("{}", machineconfig::strip(&full)?);
            return Ok(());
        }
        Some("check-bundle") if args.len() == 6 => return check_bundle(&args[2..]),
        _ => {}
    }
    edge_common::init_tracing();
    serve()
}

/// Signature, sums, patch and layout, as the unit checks them; prints the MANIFEST.
fn check_bundle(a: &[String]) -> anyhow::Result<()> {
    let signer = bundle::Signer::new(&std::fs::read_to_string(&a[1])?, &a[2])?;
    let dest = PathBuf::from(&a[3]).join("check-bundle");
    let _ = std::fs::remove_dir_all(&dest);
    let r = (|| {
        let manifest = bundle::unpack(std::path::Path::new(&a[0]), &dest, &signer)?;
        machineconfig::check_patch(&std::fs::read_to_string(dest.join(bundle::PATCH))?)?;
        let refs = bundle::layout_refs(&dest.join(bundle::IMAGES))?;
        anyhow::ensure!(!refs.is_empty(), "the image layout names no image");
        // Into a scratch store, as the unit imports it.
        let store = edge_registry::Store::open(dest.join("store"))?;
        let tagged = store.import_layout(&dest.join(bundle::IMAGES))?;
        // Images named by digest alone are held untagged, found by their digest.
        let named = refs
            .iter()
            .filter(|r| {
                r.parse::<edge_registry::ImageRef>()
                    .is_ok_and(|i| i.tag.is_some())
            })
            .count();
        anyhow::ensure!(
            tagged.len() == named,
            "the registry tagged {} of the layout's {named} tagged images",
            tagged.len()
        );
        for (k, v) in &manifest {
            println!("{k}={v}");
        }
        for r in refs {
            println!("IMAGE={r}");
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dest);
    r
}

#[tokio::main]
async fn serve() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let settings: unit::Settings = serde_yaml::from_str(
        &std::fs::read_to_string(env("EDGE_UPDATE_CONFIG", "/etc/edge-update/config.yaml"))
            .context("read the settings")?,
    )
    .context("parse the settings")?;
    let state = PathBuf::from(env("EDGE_UPDATE_STATE", "/var/mnt/edge-update"));
    std::fs::create_dir_all(&state)?;
    // One engine per record, whatever the Deployment does.
    let lock = std::fs::File::create(state.join("lock"))?;
    let _lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| e)
        .context("another edge-update holds the state volume")?;

    // apid on the host: the pod shares the host's network.
    let talos = Arc::new(talos::Node::new(
        &PathBuf::from(env(
            "EDGE_UPDATE_TALOSCONFIG",
            "/var/run/secrets/talos.dev/config",
        )),
        "127.0.0.1:50000",
    ));
    let kube = Arc::new(cluster::Kube::new(kube::Client::try_default().await?));
    let now: engine::Clock = Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    });
    let mut engine = Engine::open(
        &state,
        settings,
        talos,
        kube,
        Arc::new(registry::Registry::open(&PathBuf::from(env(
            "EDGE_UPDATE_REGISTRY",
            "/var/mnt/edge-registry",
        )))?),
        now,
    )?;

    let (tx, rx) = mpsc::channel(8);
    let (publish, status) = watch::channel(Snapshot::default());
    let service = Arc::new(api::Service::new(tx, status, engine.uploads()));
    let listen = env("EDGE_UPDATE_LISTEN", "127.0.0.1:7443");
    let rpc = connectrpc::ConnectRpcService::new(service.register(connectrpc::Router::new()))
        .with_limits(
            connectrpc::Limits::default()
                .with_max_message_size(8 << 20)
                .with_max_request_body_size(8 << 20),
        );
    let bound = connectrpc::Server::bind(&listen)
        .await
        .map_err(|e| anyhow::anyhow!("bind {listen}: {e}"))?;
    tracing::info!(%listen, "edge-update: serving");
    tokio::spawn(async move {
        if let Err(e) = bound.serve_with_service(rpc).await {
            tracing::error!(error = %e, "the update API stopped");
        }
    });

    let mut term = edge_common::Terminator::new();
    run(&mut engine, rx, publish, term.wait()).await;
    Ok(())
}

/// How often the unit is reread while nothing else happens.
const UNIT_EVERY: Duration = Duration::from_secs(30);

async fn run(
    engine: &mut Engine,
    mut rx: mpsc::Receiver<Command>,
    publish: watch::Sender<Snapshot>,
    stop: impl std::future::Future<Output = ()>,
) {
    let snap = |e: &Engine| Snapshot {
        record: e.record.clone(),
        detail: e.detail.clone(),
        unit: e.unit.clone(),
    };
    let mut unit = tokio::time::interval(UNIT_EVERY);
    unit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut phase = engine.record.phase.clone();
    let mut backoff = Duration::from_secs(5);
    tokio::pin!(stop);
    loop {
        publish.send_replace(snap(engine));
        let wait = match engine.step().await {
            Ok(Tick::Moved) => {
                backoff = Duration::from_secs(5);
                continue;
            }
            Ok(Tick::Wait(d)) => d,
            Ok(Tick::Idle) => Duration::from_secs(3600),
            Err(e) => {
                tracing::warn!(error = format!("{e:#}"), "update step failed; retrying");
                engine.detail = format!("retrying: {e:#}");
                backoff = (backoff * 2).min(Duration::from_secs(60));
                backoff
            }
        };
        publish.send_replace(snap(engine));
        // A new phase has moved something on the unit.
        if engine.record.phase != phase {
            phase = engine.record.phase.clone();
            unit.reset_immediately();
        }
        let next = tokio::time::Instant::now() + wait;
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    match cmd {
                        Some(Command::Verify(sha, reply)) => {
                            let r = engine.request_verify(&sha);
                            publish.send_replace(snap(engine));
                            let _ = reply.send(r);
                        }
                        Some(Command::Apply(tag, reply)) => {
                            let r = engine.request_apply(&tag).await;
                            publish.send_replace(snap(engine));
                            let _ = reply.send(r);
                        }
                        Some(Command::Power(p, reply)) => {
                            let _ = reply.send(engine.power(p).await);
                        }
                        None => return,
                    }
                    break;
                }
                _ = unit.tick() => {
                    if engine.refresh_unit().await {
                        publish.send_replace(snap(engine));
                    }
                }
                _ = tokio::time::sleep_until(next) => break,
                _ = &mut stop => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests::{Harness, OLD_TAG, Spec};

    #[tokio::test(start_paused = true)]
    async fn the_unit_is_reread_while_idle_and_sent_on_change() {
        let mut h = Harness::new();
        let mut engine = h.engine.take().unwrap();
        let (_tx, rx) = mpsc::channel(1);
        let (publish, mut status) = watch::channel(Snapshot::default());
        tokio::spawn(async move { run(&mut engine, rx, publish, std::future::pending()).await });

        status.wait_for(|s| s.unit.good == OLD_TAG).await.unwrap();
        tokio::time::sleep(UNIT_EVERY + Duration::from_secs(1)).await;
        assert!(!status.has_changed().unwrap(), "sent with nothing changed");

        h.world
            .lock()
            .unwrap()
            .judge
            .insert("good".into(), "update-new".into());
        let asked = tokio::time::Instant::now();
        status
            .wait_for(|s| s.unit.good == "update-new")
            .await
            .unwrap();
        assert!(
            asked.elapsed() < UNIT_EVERY,
            "reread after {:?}",
            asked.elapsed()
        );
    }

    // Real time: the import runs on a blocking thread, which paused time skips past.
    #[tokio::test]
    async fn a_new_phase_rereads_the_unit_at_once() {
        let mut h = Harness::new();
        assert!(h.verify(&Spec::new("update-new")).await.is_none());
        let mut engine = h.engine.take().unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (publish, mut status) = watch::channel(Snapshot::default());
        tokio::spawn(async move { run(&mut engine, rx, publish, std::future::pending()).await });
        status.wait_for(|s| s.unit.good == OLD_TAG).await.unwrap();

        let (reply, applied) = tokio::sync::oneshot::channel();
        tx.send(Command::Apply("update-new".into(), reply))
            .await
            .unwrap();
        applied.await.unwrap().unwrap();
        tokio::time::timeout(UNIT_EVERY / 6, status.wait_for(|s| s.unit.os_trial))
            .await
            .expect("the unit was not reread when the phase moved")
            .unwrap();
    }
}
