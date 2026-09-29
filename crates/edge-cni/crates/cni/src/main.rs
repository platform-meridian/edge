use edge_cni::cni::{self, Command, NetConf};
use edge_cni::ipam::Pool;
use edge_cni::netlink::{self, GATEWAY, Net};
use edge_cni::{daemon, install, pins};
use std::io::Read;
use std::os::fd::AsRawFd;

fn main() {
    // argv, not env: containerd controls the plugin's env.
    let mode = std::env::args().nth(1);
    if matches!(mode.as_deref(), Some("daemon" | "floor")) {
        edge_common::init_tracing();
        if mode.as_deref() == Some("floor") {
            if let Err(e) = install::floor() {
                eprintln!("edge-cni floor: {e:#}");
                std::process::exit(1);
            }
            return;
        }
        edge_common::sandbox::restrict(&edge_common::sandbox::cni_daemon(
            std::path::Path::new("/sys/fs/bpf"),
            std::path::Path::new("/opt/cni/bin"),
            std::path::Path::new("/etc/cni/net.d"),
        ));
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("edge-cni daemon: cannot start the async runtime: {e}");
                std::process::exit(1);
            }
        };
        let node = node_name();
        rt.block_on(async {
            tokio::select! {
                never = daemon::run(&node) => match never {},
                _ = edge_common::terminated() => {
                    tracing::info!("exiting on SIGTERM; the pinned dataplane stays attached");
                }
            }
        });
        return;
    }
    let code = match run() {
        Ok(out) => {
            println!("{out}");
            0
        }
        Err(e) => {
            let err = cni::Error::generic("edge-cni failed", format!("{e:#}"));
            println!("{}", serde_json::to_string(&err).unwrap_or_default());
            1
        }
    };
    std::process::exit(code);
}

// The kubelet registers the Node under the host's name.
fn node_name() -> String {
    std::env::var("NODE_NAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .map(|n| n.trim().to_string())
        .unwrap_or_default()
}

const HOOKS_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("{key} is not set"))
}

fn run() -> anyhow::Result<String> {
    let command = Command::parse(&env("CNI_COMMAND")?)?;

    if command == Command::Version {
        return Ok(serde_json::to_string(&cni::VersionInfo {
            cni_version: cni::CURRENT.into(),
            supported_versions: cni::SUPPORTED.iter().map(|s| s.to_string()).collect(),
        })?);
    }

    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;
    let conf: NetConf = serde_json::from_str(&stdin)
        .map_err(|e| anyhow::anyhow!("network config is not valid JSON: {e}"))?;

    let container_id = env("CNI_CONTAINERID")?;
    let (host_veth, peer_veth) = netlink::veth_names(&container_id);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    match command {
        Command::Add => {
            // Bounded: a missing daemon must not stop every pod starting.
            if let Err(e) = pins::wait_for_dataplane(std::time::Duration::from_secs(30)) {
                eprintln!(
                    "edge-cni: {e:#}; adding the pod anyway, service addresses will not resolve until the daemon is up"
                );
            }
            let netns = env("CNI_NETNS")?;
            let ifname = env("CNI_IFNAME")?;
            // The floor's conflist has no pod CIDR; the daemon's, installed by now, does.
            let pod_cidr = conf
                .pod_cidr
                .clone()
                .or_else(install::installed_pod_cidr)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no pod CIDR: the edge-cni daemon has not installed its conflist"
                    )
                })?;
            let out = rt.block_on(add(
                &conf, &pod_cidr, &host_veth, &peer_veth, &netns, &ifname,
            ))?;
            if pins::wait_for_hooks(&host_veth, HOOKS_WAIT) == pins::HooksWait::TimedOut {
                eprintln!(
                    "edge-cni: no NetworkPolicy hooks on {host_veth} after {HOOKS_WAIT:?}; the pod starts unfiltered"
                );
            }
            Ok(out)
        }
        Command::Del => {
            // CNI spec: DEL of something already gone succeeds.
            rt.block_on(async {
                let net = Net::open()?;
                let _ = net.delete_link(&host_veth).await;
                Ok(String::from("{}"))
            })
        }
        Command::Check => rt.block_on(async {
            let net = Net::open()?;
            net.link_index(&host_veth).await?;
            Ok(String::from("{}"))
        }),
        Command::Version => unreachable!("handled above"),
    }
}

async fn add(
    conf: &NetConf,
    pod_cidr: &str,
    host_veth: &str,
    peer_veth: &str,
    netns: &str,
    ifname: &str,
) -> anyhow::Result<String> {
    let (network, prefix) = cni::parse_cidr(pod_cidr)?;
    let pool = Pool::new(network, prefix)?;

    let net = Net::open()?;

    // The peer is renamed to CNI_IFNAME inside the netns; "eth0" collides here.
    net.create_veth(host_veth, peer_veth, conf.mtu).await?;

    let result = configure_pod(&net, conf, host_veth, peer_veth, netns, ifname, &pool).await;
    if result.is_err() {
        let _ = net.delete_link(host_veth).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn configure_pod(
    net: &Net,
    conf: &NetConf,
    host_veth: &str,
    peer_veth: &str,
    netns: &str,
    ifname: &str,
    pool: &Pool,
) -> anyhow::Result<String> {
    let ns = std::fs::File::open(netns)
        .map_err(|e| anyhow::anyhow!("cannot open netns {netns}: {e}"))?;
    net.move_to_netns(peer_veth, ns.as_raw_fd()).await?;

    net.set_up(host_veth).await?;
    netlink::enable_proxy_arp(host_veth)?;
    let addr = claim_address(net, pool, host_veth).await?;

    let mac = configure_pod_netns(&ns, peer_veth, ifname, addr, conf.mtu)?;

    let result = cni::Result {
        cni_version: cni::CURRENT.into(),
        interfaces: vec![
            cni::Interface {
                name: host_veth.to_string(),
                mac: net.mac_of(host_veth).await?,
                sandbox: None,
            },
            cni::Interface {
                name: ifname.to_string(),
                mac,
                sandbox: Some(netns.to_string()),
            },
        ],
        ips: vec![cni::IpConfig {
            // A pod is a host route, not a subnet member.
            address: format!("{addr}/32"),
            gateway: GATEWAY.to_string(),
            interface: 1,
        }],
        routes: vec![cni::Route {
            dst: "0.0.0.0/0".into(),
            gw: Some(GATEWAY.to_string()),
        }],
        dns: cni::Dns::default(),
    };
    Ok(serde_json::to_string(&result)?)
}

// Each loss means another ADD took an address: N concurrent ADDs lose at most N-1 times.
const CLAIM_ATTEMPTS: usize = 64;

// `lost` makes each retry pick a new address even if the winner's route is already gone.
async fn claim_address(
    net: &Net,
    pool: &Pool,
    host_veth: &str,
) -> anyhow::Result<std::net::Ipv4Addr> {
    let mut lost = Vec::new();
    for _ in 0..CLAIM_ATTEMPTS {
        let mut taken = net.leased(pool).await?;
        taken.extend_from_slice(&lost);
        let addr = pool.allocate(&taken)?;
        if net.claim_host_route(addr, host_veth).await? {
            return Ok(addr);
        }
        lost.push(addr);
    }
    anyhow::bail!(
        "lost the race for a pod address {CLAIM_ATTEMPTS} times in a row (last tried: {:?})",
        lost.last()
    )
}

// setns() moves only the calling thread, and a netlink socket stays in the netns
// it was opened in: hence a thread with its own connection.
fn configure_pod_netns(
    ns: &std::fs::File,
    peer_veth: &str,
    ifname: &str,
    addr: std::net::Ipv4Addr,
    mtu: u32,
) -> anyhow::Result<String> {
    let fd = ns.as_raw_fd();
    let peer_veth = peer_veth.to_string();
    let ifname = ifname.to_string();

    std::thread::scope(|s| {
        s.spawn(move || -> anyhow::Result<String> {
            nix::sched::setns(
                unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
                nix::sched::CloneFlags::CLONE_NEWNET,
            )?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let net = Net::open()?;
                let idx = net.link_index(&peer_veth).await?;
                net.rename(idx, &ifname, mtu).await?;
                net.set_up(&ifname).await?;
                net.set_up("lo").await?;
                net.add_addr(&ifname, addr, 32).await?;
                net.add_default_via_gateway(&ifname).await?;
                net.mac_of(&ifname).await
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("netns thread panicked"))?
    })
}
