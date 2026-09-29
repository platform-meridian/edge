use edge_dns::{forward, handler, upstream, watch};

use std::time::Duration;

use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};

use crate::forward::{ForwardCfg, Forwarder};
use crate::handler::EdgeDns;
use crate::watch::ZoneState;

/// hickory's default (5 s, 2 retries) makes a dead upstream cost 15 s against a
/// client resolver that gives up at 5; the client retries on its own clock.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(1);
const UPSTREAM_RETRIES: usize = 0;
const TCP_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_RESPONSE_BUFFER: usize = 1;

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();
    // The pod's own netns, not hostNetwork: unreachable off the node. Under
    // hostNetwork this must be narrowed or it is an open resolver on the LAN.
    let bind = std::env::var("DNS_BIND").unwrap_or_else(|_| "0.0.0.0:53".into());
    edge_common::sandbox::restrict(&edge_common::sandbox::dns(&bind));
    serve(bind)
}

#[tokio::main]
async fn serve(bind: String) -> anyhow::Result<()> {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a CryptoProvider was already installed");
    }

    let domain = std::env::var("CLUSTER_DOMAIN").unwrap_or_else(|_| "cluster.local".into());
    let state = ZoneState::new(&domain);

    // dnsPolicy: Default, so this is the host's upstream list, never ourselves.
    let resolver = upstream::build(
        std::path::Path::new("/etc/resolv.conf"),
        UPSTREAM_TIMEOUT,
        UPSTREAM_RETRIES,
    );

    let watch_state = state.clone();
    tokio::spawn(edge_common::forever(
        Duration::from_secs(1),
        Duration::from_secs(30),
        move || {
            let state = watch_state.clone();
            async move {
                let client = match kube::Client::try_default().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %format!("{e:#}"), "cannot build the kube client; retrying");
                        return;
                    }
                };
                match crate::watch::run(client, state).await {
                    Ok(()) => tracing::error!("watch loop ended; restarting it"),
                    Err(e) => {
                        tracing::error!(error = %format!("{e:#}"), "watch loop failed; restarting it")
                    }
                }
            }
        },
    ));

    let handler = EdgeDns::new(state, Forwarder::new(resolver, ForwardCfg::default()));
    let mut server = Server::new(handler);
    server.register_socket(retry_bind("udp", || UdpSocket::bind(&bind)).await);
    server.register_listener(
        retry_bind("tcp", || TcpListener::bind(&bind)).await,
        TCP_QUERY_TIMEOUT,
        TCP_RESPONSE_BUFFER,
    );

    tracing::info!(%bind, %domain, "edge-dns serving");
    tokio::select! {
        r = server.block_until_done() => r?,
        _ = edge_common::terminated() => tracing::info!("SIGTERM: edge-dns exiting"),
    }
    Ok(())
}

async fn retry_bind<T, F, Fut>(what: &str, mut bind: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut delay = Duration::from_millis(250);
    loop {
        match bind().await {
            Ok(v) => return v,
            Err(e) => {
                tracing::error!(error = %e, what, retry_in = ?delay, "cannot bind; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_retries_until_port_frees() {
        let holder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = holder.local_addr().unwrap();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            drop(holder);
        });
        let started = std::time::Instant::now();
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            retry_bind("udp", || UdpSocket::bind(addr)),
        )
        .await
        .expect("never bound");
        assert_eq!(got.local_addr().unwrap(), addr);
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "bound while it was still held?"
        );
        release.await.unwrap();
    }
}
