//! edge-state: a power-cut-native etcd v3 server for a single-node cluster.

use edge_state::server::EtcdServer;
use edge_state::store::Store;

/// Watch streams never finish on their own.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();

    // argv is etcd's command line and wins over the environment.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let subcommand = std::env::args().nth(1).filter(|a| !a.starts_with("--"));

    let etcd = edge_state::etcdflags::parse(argv);
    if !etcd.ignored.is_empty() && subcommand.is_none() {
        tracing::warn!(flags = ?etcd.ignored, "ignoring unrecognised etcd flags");
    }

    let data = match &etcd.data_dir {
        Some(d) => format!("{d}/state.log"),
        None => std::env::var("EDGE_STATE_LOG")
            .unwrap_or_else(|_| "/var/lib/edge-state/state.log".into()),
    };
    // The offline commands open the log read-only: nothing before them may touch the disk.
    match subcommand.as_deref() {
        Some("history") => run_history(&data),
        Some("diff") => run_diff(&data),
        None => {
            let addr = etcd.listen_client.clone().unwrap_or_else(|| {
                std::env::var("EDGE_STATE_LISTEN").unwrap_or_else(|_| "127.0.0.1:2379".into())
            });
            let tls: Vec<&std::path::Path> =
                [&etcd.cert_file, &etcd.key_file, &etcd.trusted_ca_file]
                    .into_iter()
                    .flatten()
                    .map(|f| f.as_ref())
                    .collect();
            edge_common::sandbox::restrict(&edge_common::sandbox::state(
                data.as_ref(),
                &tls,
                &addr,
            ));
            tokio::runtime::Runtime::new()?.block_on(serve(etcd, data, addr))
        }
        Some(other) => {
            anyhow::bail!("unknown command {other:?}: expected history, diff, or none to serve")
        }
    }
}

fn advertised(advertise: &Option<String>, listen: &Option<String>) -> Vec<String> {
    advertise
        .clone()
        .or_else(|| listen.as_ref().map(|a| format!("https://{a}")))
        .into_iter()
        .collect()
}

async fn serve(
    etcd: edge_state::etcdflags::EtcdArgs,
    data: String,
    addr: String,
) -> anyhow::Result<()> {
    let open_path = data.clone();
    let store = tokio::task::spawn_blocking(move || Store::open_patiently(&open_path)).await?;
    tracing::info!(log = %data, revision = store.revision(), degraded = store.is_degraded(), "recovered store");

    let mut server = EtcdServer::new(store)
        .with_progress_interval(etcd.watch_progress_notify_interval_secs)
        .with_max_request_bytes(etcd.max_request_bytes)
        // After a failed fsync only a restart can learn what is on disk. The delay
        // lets the error reach the client.
        .with_fatal_handler(|| {
            tracing::error!("log failed; exiting so a restart recovers it from disk");
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(300));
                std::process::exit(70);
            });
        });
    if let Some(name) = &etcd.name {
        // Clients dial what MemberList reports, so never the 0.0.0.0 bind address.
        server = server.with_identity(
            name.clone(),
            advertised(&etcd.advertise_client, &etcd.listen_client),
            advertised(&etcd.advertise_peer, &etcd.listen_peer),
        );
        tracing::info!(name = %name, "serving as etcd member");
    }
    server.spawn_lease_reaper();
    server.spawn_log_recovery();
    server.spawn_log_rotation();

    let tls = edge_state::etcdtls::build(
        etcd.cert_file.as_deref(),
        etcd.key_file.as_deref(),
        etcd.trusted_ca_file.as_deref(),
        etcd.client_cert_auth,
    )?;

    let mut builder = tonic::transport::Server::builder();
    if let Some(cfg) = tls {
        tracing::info!(%addr, client_cert_auth = etcd.client_cert_auth, "serving the etcd v3 API over TLS");
        builder = builder.tls_config(cfg)?;
    } else {
        tracing::info!(%addr, "serving the etcd v3 API in plaintext");
    }

    // Nothing needs flushing on SIGTERM: every acknowledged write is already fsynced.
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let serve = server
        .router(builder)
        .serve_with_shutdown(addr.parse()?, async move {
            let _ = stop_rx.wait_for(|stop| *stop).await;
        });
    tokio::pin!(serve);
    tokio::select! {
        r = &mut serve => r?,
        _ = edge_common::terminated() => {
            tracing::info!("draining in-flight requests on SIGTERM");
            let _ = stop_tx.send(true);
            if tokio::time::timeout(SHUTDOWN_DRAIN, &mut serve).await.is_err() {
                tracing::info!(drain = ?SHUTDOWN_DRAIN, "watch streams still open at the drain limit; exiting");
            }
        }
    }
    Ok(())
}

fn warn_if_damaged(store: &Store) {
    let r = store.recovery();
    if let Some(d) = &r.damage {
        eprintln!(
            "WARNING: the log is damaged at byte {} ({}); {} byte(s) after it were NOT read. \
             Everything shown is from before the damage.",
            d.offset, d.detail, d.dropped_bytes
        );
    }
    if r.skipped_records > 0 {
        eprintln!(
            "WARNING: {} record(s) in the log could not be decoded by this build and are not reflected below.",
            r.skipped_records
        );
    }
}

fn run_history(log: &str) -> anyhow::Result<()> {
    let store = Store::open_readonly(log)?;
    warn_if_damaged(&store);
    let since: u64 = std::env::args()
        .nth(2)
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| anyhow::anyhow!("since-revision must be a number: {e}"))?
        .unwrap_or(0);

    anyhow::ensure!(
        since <= store.revision(),
        "revision {since} is ahead of the store, which is at {}",
        store.revision()
    );

    let changes = edge_state::history::changes(&store, since).map_err(|floor| {
        anyhow::anyhow!("revision {since} is below the compaction floor {floor}")
    })?;

    println!(
        "{} change(s) after revision {since} (store is at {})",
        changes.len(),
        store.revision()
    );
    for c in &changes {
        let op = match c.kind {
            edge_state::store::EventKind::Put => "put",
            edge_state::store::EventKind::Delete => "del",
        };
        println!(
            "  {:>8}  {op}  {:<52} {} B",
            c.revision,
            c.ident.to_string(),
            c.value_bytes
        );
    }
    Ok(())
}

fn run_diff(log: &str) -> anyhow::Result<()> {
    let store = Store::open_readonly(log)?;
    warn_if_damaged(&store);
    let (a, b) = (
        std::env::args().nth(2).unwrap_or_default(),
        std::env::args().nth(3).unwrap_or_default(),
    );
    let a: u64 = a
        .parse()
        .map_err(|_| anyhow::anyhow!("usage: edge-state diff <rev-a> <rev-b>"))?;
    let b: u64 = b
        .parse()
        .map_err(|_| anyhow::anyhow!("usage: edge-state diff <rev-a> <rev-b>"))?;

    for (label, rev) in [("a", a), ("b", b)] {
        anyhow::ensure!(
            rev <= store.revision(),
            "revision {rev} ({label}) is ahead of this store, which is at {}",
            store.revision()
        );
    }

    let d = edge_state::history::diff(&store, a, b)
        .map_err(|floor| anyhow::anyhow!("a revision is below the compaction floor {floor}"))?;
    println!("{} difference(s) between revision {a} and {b}", d.len());
    for x in &d {
        let (mark, detail) = match x.delta {
            edge_state::history::Delta::Added => ("+", format!("{} B", x.to_bytes)),
            edge_state::history::Delta::Removed => ("-", format!("{} B", x.from_bytes)),
            edge_state::history::Delta::Changed => {
                ("~", format!("{} -> {} B", x.from_bytes, x.to_bytes))
            }
        };
        println!("  {mark} {:<52} {detail}", x.ident.to_string());
    }
    Ok(())
}
