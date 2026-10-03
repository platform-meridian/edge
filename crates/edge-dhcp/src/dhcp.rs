//! Authoritative for its subnet.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant, SystemTime};

use crate::Subnet;
use crate::leases::{self, Record};
use crate::wire::{Kind, Reply, Request, opt};

pub const LEASE_DURATION: Duration = Duration::from_secs(12 * 3600);
/// Long enough for the client's REQUEST; a second DISCOVER meanwhile gets
/// another address.
const OFFER_HOLD: Duration = Duration::from_secs(60);
/// dnsmasq's backoff for an address a client found in use.
const DECLINE_HOLD: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    Broadcast,
    Unicast(Ipv4Addr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Holder {
    Client(Vec<u8>),
    Declined,
}

#[derive(Clone, Debug)]
struct Lease {
    holder: Holder,
    until: Instant,
    /// Set once acknowledged: an offer is not yet anyone's.
    granted: Option<Granted>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Granted {
    mac: String,
    hostname: Option<String>,
}

pub struct Server {
    subnet: Subnet,
    domain: Option<String>,
    /// Keyed by pool address only, so bounded by the pool. An expired entry
    /// still remembers whose it was.
    leases: HashMap<Ipv4Addr, Lease>,
}

impl Server {
    pub fn new(subnet: Subnet, domain: Option<String>) -> Server {
        Server {
            subnet,
            domain,
            leases: HashMap::new(),
        }
    }

    fn available(&self, a: Ipv4Addr, client: &Holder, now: Instant) -> bool {
        self.subnet.in_pool(a)
            && self
                .leases
                .get(&a)
                .is_none_or(|l| l.holder == *client || l.until <= now)
    }

    fn held_by(&self, client: &Holder) -> Option<Ipv4Addr> {
        self.leases
            .iter()
            .find(|(_, l)| l.holder == *client)
            .map(|(a, _)| *a)
    }

    /// The free search starts where the client's identity fixes, so a DISCOVER
    /// after a restart tends to land where it was.
    fn pick(&self, client: &Holder, requested: Option<Ipv4Addr>, now: Instant) -> Option<Ipv4Addr> {
        let pool = self.subnet.pool();
        let size = pool.end().checked_sub(*pool.start())? + 1;
        let Holder::Client(id) = client else {
            return None;
        };
        let start = fnv1a(id) % size;
        self.held_by(client)
            .into_iter()
            .chain(requested)
            .chain((0..size).map(|i| Ipv4Addr::from(pool.start() + (start + i) % size)))
            .find(|&a| self.available(a, client, now))
    }

    fn hold(&mut self, a: Ipv4Addr, holder: Holder, until: Instant) -> &mut Lease {
        if let Holder::Client(_) = holder {
            self.leases.retain(|b, l| l.holder != holder || *b == a);
        }
        let granted = self
            .leases
            .remove(&a)
            .filter(|l| l.holder == holder)
            .and_then(|l| l.granted);
        self.leases
            .entry(a)
            .insert_entry(Lease {
                holder,
                until,
                granted,
            })
            .into_mut()
    }

    /// Granted and unexpired, by address, their expiry on the wall clock.
    pub fn records(&self, now: Instant, wall: SystemTime) -> Vec<Record> {
        let mut out: Vec<Record> = self
            .leases
            .iter()
            .filter(|(_, l)| l.until > now)
            .filter_map(|(a, l)| {
                let (Holder::Client(key), Some(g)) = (&l.holder, &l.granted) else {
                    return None;
                };
                Some(Record {
                    ip: *a,
                    mac: g.mac.clone(),
                    hostname: g.hostname.clone(),
                    key: key.clone(),
                    expires: unix(wall + (l.until - now)),
                })
            })
            .collect();
        out.sort_by_key(|r| r.ip);
        out
    }

    /// Takes back what a previous run granted, so a client that keeps its
    /// address without asking again still holds it here.
    pub fn restore(&mut self, records: Vec<Record>, now: Instant, wall: SystemTime) {
        let wall = unix(wall);
        for r in records {
            let left = r.expires.saturating_sub(wall);
            if left == 0 || !self.subnet.in_pool(r.ip) {
                continue;
            }
            let lease = self.hold(r.ip, Holder::Client(r.key), now + Duration::from_secs(left));
            lease.granted = Some(Granted {
                mac: r.mac,
                hostname: r.hostname,
            });
        }
    }

    pub fn handle(&mut self, req: &Request, now: Instant) -> Option<(Reply, Dest)> {
        let relayed_from_another_segment = !req.giaddr.is_unspecified();
        if relayed_from_another_segment {
            return None;
        }
        let client = Holder::Client(req.lease_key());
        let mac = req.mac();
        let hostname = req.hostname.as_deref().unwrap_or("");
        match req.kind {
            Kind::Discover => {
                let Some(a) = self.pick(&client, req.requested, now) else {
                    tracing::warn!(%mac, "no address free in the pool; DISCOVER unanswered");
                    return None;
                };
                let until = self
                    .leases
                    .get(&a)
                    .filter(|l| l.holder == client)
                    .map_or(now, |l| l.until)
                    .max(now + OFFER_HOLD);
                self.hold(a, client, until);
                tracing::debug!(%mac, addr = %a, "offer");
                Some(self.lease_reply(req, Kind::Offer, a))
            }
            Kind::Request => {
                let a = match (req.server_id, req.requested) {
                    (Some(s), _) if s != self.subnet.addr => return None,
                    (_, Some(a)) => a,
                    (None, None) if !req.ciaddr.is_unspecified() => req.ciaddr,
                    _ => return None,
                };
                if self.available(a, &client, now) {
                    self.hold(a, client, now + LEASE_DURATION).granted = Some(Granted {
                        mac: mac.clone(),
                        hostname: leases::hostname(hostname),
                    });
                    tracing::info!(%mac, addr = %a, hostname, "lease granted");
                    Some(self.lease_reply(req, Kind::Ack, a))
                } else {
                    tracing::info!(%mac, addr = %a, hostname, "NAK: address not available");
                    let mut r = Reply::to(req, Kind::Nak);
                    r.options
                        .push((opt::SERVER_ID, self.subnet.addr.octets().to_vec()));
                    Some((r, Dest::Broadcast))
                }
            }
            Kind::Release => {
                if self
                    .leases
                    .get(&req.ciaddr)
                    .is_some_and(|l| l.holder == client)
                {
                    self.leases.remove(&req.ciaddr);
                    tracing::info!(%mac, addr = %req.ciaddr, "lease released");
                }
                None
            }
            Kind::Decline => {
                let a = req.requested?;
                if self.leases.get(&a).is_some_and(|l| l.holder == client) {
                    self.hold(a, Holder::Declined, now + DECLINE_HOLD);
                    tracing::warn!(%mac, addr = %a, "declined: another host has the address");
                }
                None
            }
            Kind::Inform if !req.ciaddr.is_unspecified() => {
                let mut r = Reply::to(req, Kind::Ack);
                r.ciaddr = req.ciaddr;
                r.options = vec![(opt::SERVER_ID, self.subnet.addr.octets().to_vec())];
                r.options.extend(self.config_options());
                Some((r, Dest::Unicast(req.ciaddr)))
            }
            _ => None,
        }
    }

    fn lease_reply(&self, req: &Request, kind: Kind, a: Ipv4Addr) -> (Reply, Dest) {
        let secs = |d: Duration| (d.as_secs() as u32).to_be_bytes().to_vec();
        let mut r = Reply::to(req, kind);
        r.yiaddr = a;
        r.siaddr = self.subnet.addr;
        if kind == Kind::Ack {
            r.ciaddr = req.ciaddr;
        }
        r.options = vec![
            (opt::SERVER_ID, self.subnet.addr.octets().to_vec()),
            (opt::LEASE_TIME, secs(LEASE_DURATION)),
            (opt::T1, secs(LEASE_DURATION / 2)),
            (opt::T2, secs(LEASE_DURATION * 7 / 8)),
        ];
        r.options.extend(self.config_options());
        let dest = if req.ciaddr.is_unspecified() {
            Dest::Broadcast
        } else {
            Dest::Unicast(req.ciaddr)
        };
        (r, dest)
    }

    /// No router: the port is not a way out.
    fn config_options(&self) -> Vec<(u8, Vec<u8>)> {
        let mut o = vec![
            (opt::SUBNET_MASK, self.subnet.mask().octets().to_vec()),
            (opt::BROADCAST, self.subnet.broadcast().octets().to_vec()),
        ];
        if let Some(d) = &self.domain {
            o.push((opt::DOMAIN, d.as_bytes().to_vec()));
            o.push((opt::DNS, self.subnet.addr.octets().to_vec()));
        }
        o
    }
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Stable across restarts and builds, unlike std's hasher.
fn fnv1a(b: &[u8]) -> u32 {
    b.iter().fold(0x811c_9dc5, |h, &x| {
        (h ^ u32::from(x)).wrapping_mul(0x0100_0193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::testutil::dhcpcd_discover;
    use crate::wire::decode;

    const SUBNET: Subnet = Subnet {
        addr: Ipv4Addr::new(10, 51, 0, 1),
        prefix: 24,
    };
    const UNSPEC: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

    fn server() -> Server {
        Server::new(SUBNET, Some("example.lan".into()))
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 51, 0, last)
    }

    fn msg(kind: Kind, client: u8) -> Request {
        Request {
            kind,
            xid: 7,
            flags: 0,
            ciaddr: UNSPEC,
            giaddr: UNSPEC,
            htype: 1,
            chaddr: vec![2, 0, 0, 0, 0, client],
            client_id: None,
            requested: None,
            server_id: None,
            hostname: None,
        }
    }

    fn discover(client: u8) -> Request {
        msg(Kind::Discover, client)
    }

    fn select(client: u8, a: Ipv4Addr) -> Request {
        Request {
            requested: Some(a),
            server_id: Some(SUBNET.addr),
            ..msg(Kind::Request, client)
        }
    }

    fn init_reboot(client: u8, a: Ipv4Addr) -> Request {
        Request {
            requested: Some(a),
            ..msg(Kind::Request, client)
        }
    }

    fn renew(client: u8, a: Ipv4Addr) -> Request {
        Request {
            ciaddr: a,
            ..msg(Kind::Request, client)
        }
    }

    fn with_ciaddr(kind: Kind, client: u8, a: Ipv4Addr) -> Request {
        Request {
            ciaddr: a,
            ..msg(kind, client)
        }
    }

    fn decline(client: u8, a: Ipv4Addr) -> Request {
        Request {
            requested: Some(a),
            server_id: Some(SUBNET.addr),
            ..msg(Kind::Decline, client)
        }
    }

    fn lease(s: &mut Server, client: u8, now: Instant) -> Ipv4Addr {
        let (offer, _) = s.handle(&discover(client), now).expect("an offer");
        let (ack, _) = s
            .handle(&select(client, offer.yiaddr), now)
            .expect("an ack");
        assert_eq!((ack.kind, ack.yiaddr), (Kind::Ack, offer.yiaddr));
        ack.yiaddr
    }

    fn acked_addr(s: &mut Server, req: &Request, now: Instant) -> Option<Ipv4Addr> {
        match s.handle(req, now) {
            Some((r, _)) if r.kind == Kind::Ack => Some(r.yiaddr),
            _ => None,
        }
    }

    fn assert_nak(s: &mut Server, req: &Request, now: Instant) {
        let (r, dest) = s.handle(req, now).expect("an answer");
        assert_eq!(r.kind, Kind::Nak);
        assert_eq!(r.yiaddr, UNSPEC);
        assert_eq!(r.options, vec![(opt::SERVER_ID, vec![10, 51, 0, 1])]);
        assert_eq!(dest, Dest::Broadcast);
    }

    #[test]
    fn offer_options_have_no_router() {
        let mut s = server();
        let req = decode(&dhcpcd_discover()).unwrap();
        let (r, dest) = s.handle(&req, Instant::now()).unwrap();
        assert_eq!(r.kind, Kind::Offer);
        assert_eq!(dest, Dest::Broadcast);
        assert!(SUBNET.in_pool(r.yiaddr), "{}", r.yiaddr);
        assert_eq!((r.siaddr, r.ciaddr), (SUBNET.addr, UNSPEC));
        assert_eq!(
            r.options,
            vec![
                (opt::SERVER_ID, vec![10, 51, 0, 1]),
                (opt::LEASE_TIME, 43200u32.to_be_bytes().to_vec()),
                (opt::T1, 21600u32.to_be_bytes().to_vec()),
                (opt::T2, 37800u32.to_be_bytes().to_vec()),
                (opt::SUBNET_MASK, vec![255, 255, 255, 0]),
                (opt::BROADCAST, vec![10, 51, 0, 255]),
                (opt::DOMAIN, b"example.lan".to_vec()),
                (opt::DNS, vec![10, 51, 0, 1]),
            ]
        );
    }

    #[test]
    fn no_domain_no_name_server() {
        let mut s = Server::new(SUBNET, None);
        let (r, _) = s.handle(&discover(1), Instant::now()).unwrap();
        let codes: Vec<u8> = r.options.iter().map(|(c, _)| *c).collect();
        assert_eq!(
            codes,
            [
                opt::SERVER_ID,
                opt::LEASE_TIME,
                opt::T1,
                opt::T2,
                opt::SUBNET_MASK,
                opt::BROADCAST
            ]
        );
    }

    #[test]
    fn selected_offer_acked_by_broadcast() {
        let mut s = server();
        let now = Instant::now();
        let (offer, _) = s.handle(&discover(1), now).unwrap();
        let (ack, dest) = s.handle(&select(1, offer.yiaddr), now).unwrap();
        assert_eq!(
            (ack.kind, ack.yiaddr, dest),
            (Kind::Ack, offer.yiaddr, Dest::Broadcast)
        );
        assert_eq!(
            ack.option(opt::LEASE_TIME),
            Some(&43200u32.to_be_bytes()[..])
        );
        assert_eq!(ack.option(opt::DNS), Some(&[10, 51, 0, 1][..]));
    }

    #[test]
    fn ignores_request_for_other_server() {
        let mut s = server();
        let now = Instant::now();
        let (offer, _) = s.handle(&discover(1), now).unwrap();
        let req = Request {
            server_id: Some(ip(9)),
            ..select(1, offer.yiaddr)
        };
        assert_eq!(s.handle(&req, now), None);
    }

    #[test]
    fn rebooting_client_keeps_address() {
        let now = Instant::now();
        let mut s = server();
        assert_eq!(
            acked_addr(&mut s, &init_reboot(1, ip(150)), now),
            Some(ip(150))
        );
        let (r, dest) = s.handle(&init_reboot(2, ip(151)), now).unwrap();
        assert_eq!(
            (r.kind, r.ciaddr, dest),
            (Kind::Ack, UNSPEC, Dest::Broadcast)
        );
    }

    #[test]
    fn renewing_client_keeps_address() {
        let mut s = server();
        let (r, dest) = s.handle(&renew(1, ip(150)), Instant::now()).unwrap();
        assert_eq!((r.kind, r.yiaddr, r.ciaddr), (Kind::Ack, ip(150), ip(150)));
        assert_eq!(dest, Dest::Unicast(ip(150)));
    }

    #[test]
    fn naks_unavailable_address() {
        let now = Instant::now();
        let mut s = server();
        let taken = lease(&mut s, 1, now);
        assert_nak(&mut s, &init_reboot(2, Ipv4Addr::new(192, 168, 1, 50)), now);
        assert_nak(&mut s, &init_reboot(2, ip(50)), now);
        assert_nak(&mut s, &init_reboot(2, SUBNET.addr), now);
        assert_nak(&mut s, &init_reboot(2, taken), now);
        assert_nak(&mut s, &renew(2, taken), now);
        assert_nak(&mut s, &select(2, taken), now);
    }

    #[test]
    fn ignores_empty_request() {
        let mut s = server();
        assert_eq!(s.handle(&msg(Kind::Request, 1), Instant::now()), None);
    }

    #[test]
    fn offers_requested_address_if_free() {
        let now = Instant::now();
        let mut s = server();
        let asks = |c| Request {
            requested: Some(ip(170)),
            ..discover(c)
        };
        assert_eq!(s.handle(&asks(1), now).unwrap().0.yiaddr, ip(170));
        let other = s.handle(&asks(2), now).unwrap().0.yiaddr;
        assert!(other != ip(170) && SUBNET.in_pool(other));
        let outside = Request {
            requested: Some(ip(20)),
            ..discover(3)
        };
        assert!(SUBNET.in_pool(s.handle(&outside, now).unwrap().0.yiaddr));
    }

    #[test]
    fn offer_held_for_a_minute() {
        let now = Instant::now();
        let mut s = server();
        let a = s.handle(&discover(1), now).unwrap().0.yiaddr;
        assert_nak(&mut s, &init_reboot(2, a), now + Duration::from_secs(59));
        assert_eq!(
            acked_addr(&mut s, &init_reboot(2, a), now + Duration::from_secs(60)),
            Some(a)
        );
    }

    #[test]
    fn expired_address_returns_to_owner() {
        let now = Instant::now();
        let mut s = server();
        let a = lease(&mut s, 1, now);
        let later = now + LEASE_DURATION + Duration::from_secs(1);
        assert_eq!(s.handle(&discover(1), later).unwrap().0.yiaddr, a);
    }

    #[test]
    fn expired_lease_free_for_others() {
        let now = Instant::now();
        let mut s = server();
        let a = lease(&mut s, 1, now);
        assert_nak(
            &mut s,
            &init_reboot(2, a),
            now + LEASE_DURATION - Duration::from_secs(1),
        );
        assert_eq!(
            acked_addr(&mut s, &init_reboot(2, a), now + LEASE_DURATION),
            Some(a)
        );
    }

    #[test]
    fn moving_frees_old_address() {
        let now = Instant::now();
        let mut s = server();
        assert_eq!(
            acked_addr(&mut s, &init_reboot(1, ip(150)), now),
            Some(ip(150))
        );
        assert_eq!(
            acked_addr(&mut s, &init_reboot(1, ip(160)), now),
            Some(ip(160))
        );
        assert_eq!(
            acked_addr(&mut s, &init_reboot(2, ip(150)), now),
            Some(ip(150))
        );
    }

    #[test]
    fn release_only_by_holder() {
        let now = Instant::now();
        let mut s = server();
        let a = lease(&mut s, 1, now);
        assert_eq!(s.handle(&with_ciaddr(Kind::Release, 2, a), now), None);
        assert_nak(&mut s, &init_reboot(2, a), now);
        assert_eq!(s.handle(&with_ciaddr(Kind::Release, 1, a), now), None);
        assert_eq!(acked_addr(&mut s, &init_reboot(2, a), now), Some(a));
    }

    #[test]
    fn declined_address_held_ten_minutes() {
        let now = Instant::now();
        let mut s = server();
        let a = lease(&mut s, 1, now);
        assert_eq!(s.handle(&decline(2, a), now), None);
        assert_nak(&mut s, &init_reboot(3, a), now);
        assert_eq!(
            acked_addr(&mut s, &renew(1, a), now),
            Some(a),
            "a stranger's DECLINE took it"
        );
        s.handle(&decline(1, a), now);
        assert_ne!(s.handle(&discover(1), now).unwrap().0.yiaddr, a);
        assert_nak(&mut s, &init_reboot(1, a), now + Duration::from_secs(599));
        assert_eq!(
            acked_addr(&mut s, &init_reboot(3, a), now + Duration::from_secs(600)),
            Some(a)
        );
    }

    #[test]
    fn inform_answered_without_lease() {
        let mut s = server();
        let now = Instant::now();
        let (r, dest) = s
            .handle(&with_ciaddr(Kind::Inform, 1, ip(42)), now)
            .unwrap();
        assert_eq!((r.kind, r.yiaddr, r.ciaddr), (Kind::Ack, UNSPEC, ip(42)));
        assert_eq!(dest, Dest::Unicast(ip(42)));
        assert_eq!(r.option(opt::LEASE_TIME), None);
        assert_eq!(r.option(opt::SERVER_ID), Some(&[10, 51, 0, 1][..]));
        assert_eq!(r.option(opt::DNS), Some(&[10, 51, 0, 1][..]));
        assert_eq!(s.handle(&msg(Kind::Inform, 1), now), None);
    }

    #[test]
    fn ignores_relayed_and_server_messages() {
        let mut s = server();
        let now = Instant::now();
        let relayed = Request {
            giaddr: ip(254),
            ..discover(1)
        };
        assert_eq!(s.handle(&relayed, now), None);
        for k in [Kind::Offer, Kind::Ack, Kind::Nak] {
            assert_eq!(s.handle(&msg(k, 1), now), None);
        }
    }

    #[test]
    fn full_pool_waits_for_expiry() {
        let now = Instant::now();
        let mut s = server();
        let mut held = std::collections::HashSet::new();
        for c in 0..101 {
            assert!(held.insert(lease(&mut s, c, now)));
        }
        assert_eq!(s.handle(&discover(200), now), None);
        let first = s.handle(&discover(0), now).unwrap().0.yiaddr;
        let later = now + LEASE_DURATION;
        s.handle(&renew(0, first), later - Duration::from_secs(1));
        let (r, _) = s.handle(&discover(200), later).unwrap();
        assert!(held.contains(&r.yiaddr) && r.yiaddr != first);
    }

    #[test]
    fn empty_pool_offers_nothing() {
        let mut s = Server::new(Subnet::parse("10.51.0.1/26").unwrap(), None);
        assert_eq!(s.handle(&discover(1), Instant::now()), None);
    }

    #[test]
    fn rediscovery_lands_on_same_address() {
        let now = Instant::now();
        let before = lease(&mut server(), 9, now);
        assert_eq!(lease(&mut server(), 9, now), before);
    }

    #[test]
    fn rediscovery_order_independent() {
        let now = Instant::now();
        let (mut first, mut second) = (server(), server());
        let before: Vec<Ipv4Addr> = (0..20).map(|c| lease(&mut first, c, now)).collect();
        for c in (0..20).rev() {
            assert_eq!(
                lease(&mut second, c, now),
                before[usize::from(c)],
                "client {c}"
            );
        }
    }

    const WALL: u64 = 1_790_000_000;

    fn wall() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(WALL)
    }

    fn named(client: u8, a: Ipv4Addr, name: &str) -> Request {
        Request {
            hostname: Some(name.into()),
            ..init_reboot(client, a)
        }
    }

    #[test]
    fn granted_lease_recorded() {
        let now = Instant::now();
        let mut s = server();
        acked_addr(&mut s, &named(1, ip(150), "field laptop"), now).unwrap();
        assert_eq!(
            s.records(now, wall()),
            [Record {
                ip: ip(150),
                mac: "02:00:00:00:00:01".into(),
                hostname: Some("field_laptop".into()),
                key: vec![1, 2, 0, 0, 0, 0, 1],
                expires: WALL + LEASE_DURATION.as_secs(),
            }]
        );
    }

    #[test]
    fn offer_not_recorded() {
        let now = Instant::now();
        let mut s = server();
        s.handle(&discover(1), now).unwrap();
        assert_eq!(s.records(now, wall()), []);
    }

    #[test]
    fn rediscovery_keeps_record() {
        let now = Instant::now();
        let mut s = server();
        let a = lease(&mut s, 1, now);
        assert_eq!(s.handle(&discover(1), now).unwrap().0.yiaddr, a);
        assert_eq!(s.records(now, wall()).len(), 1);
    }

    #[test]
    fn released_declined_expired_unrecorded() {
        let now = Instant::now();
        let mut s = server();
        let released = lease(&mut s, 1, now);
        let declined = lease(&mut s, 2, now);
        lease(&mut s, 3, now);
        s.handle(&with_ciaddr(Kind::Release, 1, released), now);
        s.handle(&decline(2, declined), now);
        assert_eq!(
            s.records(now, wall())
                .iter()
                .map(|r| r.key[6])
                .collect::<Vec<_>>(),
            [3]
        );
        assert_eq!(s.records(now + LEASE_DURATION, wall()), []);
    }

    #[test]
    fn records_by_address() {
        let now = Instant::now();
        let mut s = server();
        for (c, last) in [(1, 170), (2, 120), (3, 150)] {
            acked_addr(&mut s, &init_reboot(c, ip(last)), now).unwrap();
        }
        let ips: Vec<Ipv4Addr> = s.records(now, wall()).iter().map(|r| r.ip).collect();
        assert_eq!(ips, [ip(120), ip(150), ip(170)]);
    }

    #[test]
    fn restored_lease_kept_for_owner() {
        let now = Instant::now();
        let mut first = server();
        acked_addr(&mut first, &named(1, ip(150), "laptop"), now).unwrap();
        let later = now + Duration::from_secs(3600);
        let records = first.records(later, wall());

        let mut restarted = server();
        restarted.restore(records.clone(), later, wall());
        assert_eq!(restarted.records(later, wall()), records);
        assert_nak(&mut restarted, &init_reboot(2, ip(150)), later);
        assert_eq!(
            acked_addr(&mut restarted, &renew(1, ip(150)), later),
            Some(ip(150))
        );
        let expiry = later + LEASE_DURATION - Duration::from_secs(3600);
        assert_eq!(
            acked_addr(
                &mut server_restored(&records, later),
                &init_reboot(2, ip(150)),
                expiry
            ),
            Some(ip(150))
        );
    }

    fn server_restored(records: &[Record], now: Instant) -> Server {
        let mut s = server();
        s.restore(records.to_vec(), now, wall());
        s
    }

    #[test]
    fn restore_skips_expired_and_foreign() {
        let now = Instant::now();
        let record = |last: u8, expires: u64| Record {
            ip: ip(last),
            mac: "02:00:00:00:00:01".into(),
            hostname: None,
            key: vec![1, 2, 0, 0, 0, 0, last],
            expires,
        };
        let s = server_restored(
            &[
                record(150, WALL),
                record(151, WALL - 1),
                record(20, WALL + 60),
                record(152, WALL + 60),
            ],
            now,
        );
        let ips: Vec<Ipv4Addr> = s.records(now, wall()).iter().map(|r| r.ip).collect();
        assert_eq!(ips, [ip(152)]);
    }

    #[derive(Clone, Debug)]
    enum Op {
        Discover(u8, Option<u8>),
        Select(u8, u8),
        InitReboot(u8, u8),
        Renew(u8, u8),
        Release(u8, u8),
        Decline(u8, u8),
        Wait(u64),
    }

    /// Few clients, addresses around the pool's edges, so they collide.
    fn op() -> impl Strategy<Value = Op> {
        let c = 0u8..6;
        let a = prop_oneof![95u8..105, 145u8..155, 195u8..205, Just(1u8)];
        prop_oneof![
            (c.clone(), proptest::option::of(a.clone())).prop_map(|(c, a)| Op::Discover(c, a)),
            (c.clone(), a.clone()).prop_map(|(c, a)| Op::Select(c, a)),
            (c.clone(), a.clone()).prop_map(|(c, a)| Op::InitReboot(c, a)),
            (c.clone(), a.clone()).prop_map(|(c, a)| Op::Renew(c, a)),
            (c.clone(), a.clone()).prop_map(|(c, a)| Op::Release(c, a)),
            (c, a).prop_map(|(c, a)| Op::Decline(c, a)),
            prop_oneof![0u64..120, Just(LEASE_DURATION.as_secs())].prop_map(Op::Wait),
        ]
    }

    fn request(op: &Op) -> Option<Request> {
        Some(match *op {
            Op::Discover(c, a) => Request {
                requested: a.map(ip),
                ..discover(c)
            },
            Op::Select(c, a) => select(c, ip(a)),
            Op::InitReboot(c, a) => init_reboot(c, ip(a)),
            Op::Renew(c, a) => renew(c, ip(a)),
            Op::Release(c, a) => with_ciaddr(Kind::Release, c, ip(a)),
            Op::Decline(c, a) => decline(c, ip(a)),
            Op::Wait(_) => return None,
        })
    }

    type Live = HashMap<u8, (Ipv4Addr, Instant)>;

    fn run(s: &mut Server, ops: &[Op], start: Instant) -> Result<(Instant, Live), TestCaseError> {
        let mut now = start;
        let mut live = Live::new();
        for op in ops {
            let Some(req) = request(op) else {
                if let Op::Wait(secs) = op {
                    now += Duration::from_secs(*secs);
                }
                continue;
            };
            let client = req.chaddr[5];
            match (&req.kind, s.handle(&req, now)) {
                (_, Some((r, _))) if matches!(r.kind, Kind::Offer | Kind::Ack) => {
                    prop_assert!(SUBNET.in_pool(r.yiaddr), "{:?} gave {}", op, r.yiaddr);
                    if r.kind == Kind::Ack {
                        for (other, (a, until)) in &live {
                            prop_assert!(
                                *other == client || *a != r.yiaddr || *until <= now,
                                "{} to client {client} while client {other} holds it",
                                r.yiaddr
                            );
                        }
                        live.insert(client, (r.yiaddr, now + LEASE_DURATION));
                    }
                }
                (Kind::Release, _) if live.get(&client).is_some_and(|l| l.0 == req.ciaddr) => {
                    live.remove(&client);
                }
                (Kind::Decline, _)
                    if live
                        .get(&client)
                        .is_some_and(|l| Some(l.0) == req.requested) =>
                {
                    live.remove(&client);
                }
                _ => {}
            }
        }
        Ok((now, live))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn leases_stay_in_pool_and_unique(
            ops in proptest::collection::vec(op(), 1..80)
        ) {
            run(&mut server(), &ops, Instant::now())?;
        }

        #[test]
        fn live_leases_survive_restart(
            ops in proptest::collection::vec(op(), 1..80),
            order in proptest::collection::vec(0u8..6, 0..12),
            renewing in any::<bool>(),
        ) {
            let (now, live) = run(&mut server(), &ops, Instant::now())?;
            let mut fresh = server();
            let mut returning: Vec<u8> = order.into_iter().filter(|c| live.contains_key(c)).collect();
            returning.extend(live.keys());
            for c in returning {
                let (a, until) = live[&c];
                if until <= now {
                    continue;
                }
                let req = if renewing { renew(c, a) } else { init_reboot(c, a) };
                prop_assert_eq!(acked_addr(&mut fresh, &req, now), Some(a), "client {}", c);
            }
        }
    }
}
