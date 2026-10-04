//! Serves the image store read-only on loopback, passing misses through to an
//! upstream registry. Images arrive through the library, never over the network.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use edge_common::mount::is_mount_point;
use edge_registry::Store;

const DEFAULT_LISTEN: &str = "127.0.0.1:5000";
const DEFAULT_ROOT: &str = "/var/lib/edge-registry";
/// Talos's registryd, which serves the image cache baked into the media.
const DEFAULT_UPSTREAM: &str = "127.0.0.1:3172";
const VOLUME_POLL: Duration = Duration::from_secs(1);
/// At boot registryd comes up after the first pulls: a refused one is held this long.
const DEFAULT_UPSTREAM_WAIT: u64 = 60;

#[derive(Debug, PartialEq)]
struct Config {
    listen: SocketAddr,
    root: PathBuf,
    upstream: SocketAddr,
    upstream_wait: Duration,
    volume: Option<PathBuf>,
}

fn config(args: impl IntoIterator<Item = String>, env: impl Fn(&str) -> Option<String>) -> Config {
    let mut listen = env("EDGE_REGISTRY_LISTEN");
    let mut root = env("EDGE_REGISTRY_ROOT");
    let mut upstream = env("EDGE_REGISTRY_UPSTREAM");
    let mut volume = env("EDGE_REGISTRY_VOLUME");
    let mut wait = env("EDGE_REGISTRY_UPSTREAM_WAIT");
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--root" => root = args.next(),
            "--upstream" => upstream = args.next(),
            "--volume" => volume = args.next(),
            "--upstream-wait" => wait = args.next(),
            _ => tracing::warn!(arg, "ignoring an unknown argument"),
        }
    }
    Config {
        listen: loopback("listen", listen, DEFAULT_LISTEN),
        root: root.map_or_else(|| DEFAULT_ROOT.into(), PathBuf::from),
        upstream: loopback("upstream", upstream, DEFAULT_UPSTREAM),
        upstream_wait: Duration::from_secs(
            wait.and_then(|w| w.parse().ok())
                .unwrap_or(DEFAULT_UPSTREAM_WAIT),
        ),
        volume: volume.map(PathBuf::from),
    }
}

fn loopback(what: &str, addr: Option<String>, default: &str) -> SocketAddr {
    let default: SocketAddr = default.parse().expect("the default parses");
    match addr.map(|a| a.parse::<SocketAddr>()) {
        None => default,
        Some(Ok(a)) if a.ip().is_loopback() => a,
        Some(got) => {
            tracing::error!(what, ?got, %default, "not a loopback address; using the default");
            default
        }
    }
}

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();
    let Config {
        listen,
        root,
        upstream,
        upstream_wait,
        volume,
    } = config(std::env::args().skip(1), |k| std::env::var(k).ok());
    let unmounted = volume.filter(|v| !is_mount_point(v));
    let store = match &unmounted {
        None => Some(open(&root)?),
        Some(v) => {
            tracing::warn!(volume = %v.display(), "store volume not mounted; passing every pull through until it is");
            None
        }
    };
    edge_common::sandbox::restrict(&edge_common::sandbox::registry(
        &root,
        listen.port(),
        upstream.port(),
    ));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(edge_registry::serve_waiting(
            store,
            listen,
            Some(upstream),
            upstream_wait,
            mounted(unmounted),
        ))
}

fn open(root: &std::path::Path) -> anyhow::Result<Store> {
    let store = Store::open(root)?;
    match store.repair() {
        Ok(0) => {}
        Ok(n) => tracing::warn!(removed = n, "repaired the store"),
        Err(e) => tracing::error!(error = %e, "could not finish repairing the store"),
    }
    Ok(store)
}

/// The sandbox cannot take in a volume mounted later, so its arrival ends
/// the process and the restart serves it.
async fn mounted(volume: Option<PathBuf>) {
    let Some(v) = volume else {
        return std::future::pending().await;
    };
    while !is_mount_point(&v) {
        tokio::time::sleep(VOLUME_POLL).await;
    }
    tracing::info!(volume = %v.display(), "store volume mounted; restarting to serve it");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str], env: &[(&str, &str)]) -> Config {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        config(args.iter().map(|a| a.to_string()), |k| {
            env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        })
    }

    #[test]
    fn defaults() {
        assert_eq!(
            cfg(&[], &[]),
            Config {
                listen: DEFAULT_LISTEN.parse().unwrap(),
                root: DEFAULT_ROOT.into(),
                upstream: DEFAULT_UPSTREAM.parse().unwrap(),
                upstream_wait: Duration::from_secs(DEFAULT_UPSTREAM_WAIT),
                volume: None,
            }
        );
    }

    #[test]
    fn args_beat_env() {
        let env = [
            ("EDGE_REGISTRY_LISTEN", "127.0.0.1:6000"),
            ("EDGE_REGISTRY_ROOT", "/env"),
            ("EDGE_REGISTRY_UPSTREAM", "127.0.0.1:6001"),
            ("EDGE_REGISTRY_VOLUME", "/env-vol"),
        ];
        assert_eq!(
            cfg(&[], &env),
            Config {
                listen: "127.0.0.1:6000".parse().unwrap(),
                root: "/env".into(),
                upstream: "127.0.0.1:6001".parse().unwrap(),
                upstream_wait: Duration::from_secs(DEFAULT_UPSTREAM_WAIT),
                volume: Some("/env-vol".into()),
            }
        );
        let c = cfg(
            &[
                "--root",
                "/arg",
                "--listen",
                "[::1]:7000",
                "--upstream",
                "127.0.0.2:7001",
                "--volume",
                "/arg-vol",
                "--upstream-wait",
                "3",
            ],
            &env,
        );
        assert_eq!(
            c,
            Config {
                listen: "[::1]:7000".parse().unwrap(),
                root: "/arg".into(),
                upstream: "127.0.0.2:7001".parse().unwrap(),
                upstream_wait: Duration::from_secs(3),
                volume: Some("/arg-vol".into()),
            }
        );
    }

    #[test]
    fn loopback_only() {
        for bad in ["0.0.0.0:5000", "192.168.1.2:5000", "localhost:5000", "5000"] {
            let c = cfg(&["--listen", bad, "--upstream", bad], &[]);
            assert_eq!(c.listen, DEFAULT_LISTEN.parse().unwrap(), "{bad}");
            assert_eq!(c.upstream, DEFAULT_UPSTREAM.parse().unwrap(), "{bad}");
        }
    }
}
