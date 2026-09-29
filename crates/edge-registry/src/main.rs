//! Serves the image store read-only on loopback. Images arrive through the
//! library, from the process that imports them, never over the network.

mod server;

use std::net::SocketAddr;
use std::path::PathBuf;

use edge_registry::Store;

const DEFAULT_LISTEN: &str = "127.0.0.1:5000";
const DEFAULT_ROOT: &str = "/var/lib/edge-registry";

#[derive(Debug, PartialEq)]
struct Config {
    listen: SocketAddr,
    root: PathBuf,
}

fn config(args: impl IntoIterator<Item = String>, env: impl Fn(&str) -> Option<String>) -> Config {
    let (mut listen, mut root) = (env("EDGE_REGISTRY_LISTEN"), env("EDGE_REGISTRY_ROOT"));
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--root" => root = args.next(),
            _ => tracing::warn!(arg, "ignoring an unknown argument"),
        }
    }
    let default: SocketAddr = DEFAULT_LISTEN.parse().expect("the default parses");
    let listen = match listen.map(|l| l.parse::<SocketAddr>()) {
        None => default,
        Some(Ok(a)) if a.ip().is_loopback() => a,
        Some(got) => {
            tracing::error!(?got, %default, "not a loopback address; using the default");
            default
        }
    };
    Config {
        listen,
        root: root.map_or_else(|| DEFAULT_ROOT.into(), PathBuf::from),
    }
}

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();
    let Config { listen, root } = config(std::env::args().skip(1), |k| std::env::var(k).ok());
    let store = Store::open(&root)?;
    match store.repair() {
        Ok(0) => {}
        Ok(n) => tracing::warn!(removed = n, "repaired the store"),
        Err(e) => tracing::error!(error = %e, "could not finish repairing the store"),
    }
    // After repair, the only writing this process does.
    edge_common::sandbox::restrict(&edge_common::sandbox::registry(&root, listen.port()));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(server::serve(store, listen))
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
                root: DEFAULT_ROOT.into()
            }
        );
    }

    #[test]
    fn args_beat_env() {
        let env = [
            ("EDGE_REGISTRY_LISTEN", "127.0.0.1:6000"),
            ("EDGE_REGISTRY_ROOT", "/env"),
        ];
        assert_eq!(cfg(&[], &env).listen.port(), 6000);
        assert_eq!(cfg(&[], &env).root, PathBuf::from("/env"));
        let c = cfg(&["--root", "/arg", "--listen", "[::1]:7000"], &env);
        assert_eq!(c.listen, "[::1]:7000".parse().unwrap());
        assert_eq!(c.root, PathBuf::from("/arg"));
    }

    #[test]
    fn loopback_only() {
        for bad in ["0.0.0.0:5000", "192.168.1.2:5000", "localhost:5000", "5000"] {
            assert_eq!(
                cfg(&["--listen", bad], &[]).listen,
                DEFAULT_LISTEN.parse().unwrap(),
                "{bad}"
            );
        }
    }
}
