use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use edge_dhcp::wire::{self, CLIENT_PORT};
use edge_dhcp::{Subnet, dhcp, dns, leases, net};
use hickory_proto::rr::Name;

fn main() {
    edge_common::init_tracing();
    let subnet = subnet(std::env::var("EDGE_DHCP_ADDR").ok().as_deref());
    let domain = domain(std::env::var("EDGE_DHCP_DOMAIN").ok().as_deref());
    let lease_file = std::env::var_os("EDGE_DHCP_LEASES")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    edge_common::sandbox::restrict(&edge_common::sandbox::dhcp(lease_file.as_deref()));
    // A dead worker would leave the port dark behind a live process; exiting
    // lets the supervisor restart it, and clients keep their addresses across that.
    std::panic::set_hook(Box::new(|p| {
        tracing::error!(panic = %p, "panicked: exiting for a restart");
        std::process::exit(70);
    }));
    if let Err(e) = edge_common::install() {
        tracing::error!(error = %e, "no SIGTERM handler; machined will have to kill");
    }
    if let Some(subnet) = subnet {
        let name = domain
            .as_ref()
            .map(|d| d.to_ascii().trim_end_matches('.').to_owned());
        std::thread::spawn(move || serve_dhcp(subnet, name, lease_file));
        if let Some(domain) = domain {
            std::thread::spawn(move || serve_dns(subnet.addr, domain));
        }
        tracing::info!(addr = %subnet.addr, prefix = subnet.prefix, "edge-dhcp serving");
    }
    while !edge_common::sleep(Duration::from_secs(3600)) {}
    tracing::info!("SIGTERM: edge-dhcp exiting");
}

fn subnet(raw: Option<&str>) -> Option<Subnet> {
    let s = raw.and_then(Subnet::parse);
    if s.is_none() {
        tracing::error!(
            value = raw,
            "EDGE_DHCP_ADDR is not an address/prefix; serving nothing"
        );
    }
    s
}

fn domain(raw: Option<&str>) -> Option<Name> {
    let d = raw
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .and_then(|d| Name::from_ascii(d).ok());
    if d.is_none() {
        tracing::error!(
            value = raw,
            "DOMAIN is not a domain name; serving DHCP without DNS"
        );
    }
    d
}

fn bind_retrying(what: &str, bind: impl Fn() -> std::io::Result<UdpSocket>) -> UdpSocket {
    let mut delay = Duration::from_millis(250);
    loop {
        match bind() {
            Ok(s) => return s,
            Err(e) => {
                tracing::error!(error = %e, what, retry_in = ?delay, "cannot bind; retrying");
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
}

/// Transient by nature on UDP; the pause only stops a persistent one spinning.
fn recv_failed(what: &str, e: std::io::Error) {
    tracing::warn!(error = %e, what, "receive failed");
    std::thread::sleep(Duration::from_millis(100));
}

/// What a reader of the file sees; serving never waits on it.
struct LeaseFile {
    path: PathBuf,
    written: Option<String>,
}

impl LeaseFile {
    fn restore(path: PathBuf, server: &mut dhcp::Server) -> LeaseFile {
        if let Ok(text) = std::fs::read_to_string(&path) {
            server.restore(leases::parse(&text), Instant::now(), SystemTime::now());
        }
        LeaseFile {
            path,
            written: None,
        }
    }

    fn write(&mut self, text: String) {
        if self.written.as_ref() == Some(&text) {
            return;
        }
        match edge_common::durable_write(&self.path, text.as_bytes()) {
            Ok(()) => self.written = Some(text),
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path.display(), "lease file not written")
            }
        }
    }
}

fn render(server: &dhcp::Server, subnet: Subnet, domain: Option<&str>) -> String {
    let records = server.records(Instant::now(), SystemTime::now());
    leases::render(subnet, domain, &records)
}

fn serve_dhcp(subnet: Subnet, domain: Option<String>, lease_file: Option<PathBuf>) {
    let sock = bind_retrying("dhcp", net::dhcp_socket);
    let mut server = dhcp::Server::new(subnet, domain.clone());
    let mut file = lease_file.map(|p| LeaseFile::restore(p, &mut server));
    let mut buf = [0u8; 1500];
    loop {
        if let Some(f) = &mut file {
            f.write(render(&server, subnet, domain.as_deref()));
        }
        let (n, ifindex) = match net::recv(&sock, &mut buf) {
            Ok(r) => r,
            Err(e) => {
                recv_failed("dhcp", e);
                continue;
            }
        };
        let Some(req) = wire::decode(&buf[..n]) else {
            continue;
        };
        let on_served_port = net::ifindex_of(subnet.addr) == Some(ifindex);
        if !on_served_port {
            continue;
        }
        let Some((reply, dest)) = server.handle(&req, Instant::now()) else {
            continue;
        };
        let to = match dest {
            dhcp::Dest::Broadcast => Ipv4Addr::BROADCAST,
            dhcp::Dest::Unicast(a) => a,
        };
        let to = SocketAddrV4::new(to, CLIENT_PORT);
        if let Err(e) = net::send(&sock, &reply.encode(), ifindex, subnet.addr, to) {
            tracing::warn!(error = %e, %to, "DHCP reply not sent");
        }
    }
}

fn serve_dns(addr: Ipv4Addr, domain: Name) {
    let sock = bind_retrying("dns", || net::dns_socket(addr));
    let mut buf = [0u8; 1500];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                recv_failed("dns", e);
                continue;
            }
        };
        if let Some(resp) = dns::answer(&buf[..n], &domain, addr)
            && let Err(e) = sock.send_to(&resp, peer)
        {
            tracing::debug!(error = %e, %peer, "DNS reply not sent");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_inputs() {
        assert_eq!(subnet(None), None);
        assert_eq!(subnet(Some("192.0.2.1")), None);
        assert_eq!(
            subnet(Some("192.0.2.1/24")),
            Some(Subnet {
                addr: Ipv4Addr::new(192, 0, 2, 1),
                prefix: 24
            })
        );
        assert_eq!(domain(None), None);
        assert_eq!(domain(Some(" ")), None);
        assert_eq!(domain(Some("a..b")), None);
        assert_eq!(
            domain(Some("example.test\n")).unwrap().to_ascii(),
            "example.test"
        );
    }
}
