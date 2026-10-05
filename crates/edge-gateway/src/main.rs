//! Binds the host directly: a single node has no load-balancer controller to
//! hand it an address.

mod authz;
mod config;
mod controller;
mod path;
mod proxy;
mod server;
mod status;
#[cfg(test)]
mod testutil;
mod tls;
mod xfcc;

use std::sync::Arc;
use tokio::net::TcpListener;

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        std::env::var("EDGE_GATEWAY_CONFIG").unwrap_or_else(|_| "edge-gateway.yaml".into())
    });
    let (cfg, skipped) = config::Config::load(path.as_ref())?;
    for e in skipped {
        tracing::error!(error = %e, "route fragment skipped");
    }
    let tls: Vec<&std::path::Path> = cfg
        .tls
        .iter()
        .flat_map(|t| [t.cert.as_ref(), t.key.as_ref()])
        .collect();
    edge_common::sandbox::restrict(&edge_common::sandbox::gateway(
        path.as_ref(),
        &tls,
        &cfg.listen,
    ));
    serve(cfg)
}

#[tokio::main]
async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let routes: controller::Routes = Arc::new(arc_swap::ArcSwap::from_pointee(cfg.routes.clone()));

    let acceptor = cfg.tls.as_ref().map(|t| {
        let resolver = tls::Reloading::new(&t.cert, &t.key);
        resolver.spawn_reloader(std::time::Duration::from_millis(
            cfg.limits.tls_reload_interval_ms,
        ));
        tls::acceptor(resolver)
    });
    let mut gw = proxy::Gateway::new(cfg.clone(), routes.clone())?;
    if let Some(a) = &acceptor {
        gw = gw.with_tls(a.clone());
    }

    let listener = bind(&cfg.listen).await;
    tracing::info!(
        listen = %cfg.listen,
        routes = cfg.routes.len(),
        authz = cfg.authz_backend.is_some(),
        tls = cfg.tls.is_some(),
        "edge-gateway up"
    );
    controller::spawn(
        routes.clone(),
        controller::GatewayRef {
            name: std::env::var("EDGE_GATEWAY_NAME").unwrap_or_else(|_| "edge".into()),
            namespace: std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "edge".into()),
            bound_port: listen_port(&cfg.listen),
        },
        controller::Settings {
            statics: cfg.routes.clone(),
            strip: cfg.strip_request_headers.clone(),
            dialers: proxy::Dialers {
                identity: acceptor
                    .as_ref()
                    .map(|a| a.identity() as Arc<dyn rustls::client::ResolvesClientCert>),
                connect_timeout: std::time::Duration::from_millis(
                    cfg.limits.upstream_connect_timeout_ms,
                ),
            },
        },
        acceptor.clone(),
    );

    for r in routes.load().iter() {
        tracing::info!(
            host = r.hostname.as_deref().unwrap_or("*"),
            prefix = %r.prefix,
            authz = ?r.authz,
            backend = %r.backend.as_ref().map_or("-".into(), |b| format!("{}:{}", b.host, b.port)),
            "route"
        );
    }

    server::serve(listener, gw, acceptor, async {
        edge_common::terminated().await;
        tracing::info!("SIGTERM: edge-gateway exiting");
    })
    .await;
    Ok(())
}

fn listen_port(listen: &str) -> u16 {
    listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// Retries forever: a predecessor still holding the host port (hostNetwork,
/// Recreate) will release it, and exiting would only add crash-loop back-off.
async fn bind(addr: &str) -> TcpListener {
    let mut delay = std::time::Duration::from_millis(250);
    loop {
        match TcpListener::bind(addr).await {
            Ok(l) => return l,
            Err(e) => {
                tracing::error!(error = %e, %addr, retry_in = ?delay, "cannot bind; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(5));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn listen_port_parses() {
        for (listen, port) in [("0.0.0.0:443", 443), ("[::]:8443", 8443), ("h:x", 0)] {
            assert_eq!(super::listen_port(listen), port, "{listen}");
        }
    }
}
