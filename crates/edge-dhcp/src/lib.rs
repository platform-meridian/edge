//! DHCP and one local DNS domain on the operator port. It runs as a host service, so
//! it answers whatever state Kubernetes is in.

pub mod dhcp;
pub mod dns;
pub mod leases;
pub mod net;
pub mod wire;

#[cfg(test)]
mod testutil;

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subnet {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn parse(s: &str) -> Option<Subnet> {
        let (addr, prefix) = s.trim().split_once('/')?;
        let subnet = Subnet {
            addr: addr.parse().ok()?,
            prefix: prefix.parse().ok().filter(|p| (1..=30).contains(p))?,
        };
        let host = subnet.host();
        (host != 0 && host != !subnet.mask_bits()).then_some(subnet)
    }

    fn mask_bits(&self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }

    fn host(&self) -> u32 {
        u32::from(self.addr) & !self.mask_bits()
    }

    pub fn mask(&self) -> Ipv4Addr {
        self.mask_bits().into()
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        (u32::from(self.addr) | !self.mask_bits()).into()
    }

    pub fn pool(&self) -> RangeInclusive<u32> {
        let network = u32::from(self.addr) & self.mask_bits();
        let last_host = u32::from(self.broadcast()) - 1;
        (network + 100)..=(network + 200).min(last_host)
    }

    pub fn in_pool(&self, a: Ipv4Addr) -> bool {
        a != self.addr && self.pool().contains(&u32::from(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn slash_24_pools_100_to_200() {
        let s = Subnet::parse("10.51.0.1/24").unwrap();
        assert_eq!(s.mask(), ip("255.255.255.0"));
        assert_eq!(s.broadcast(), ip("10.51.0.255"));
        assert_eq!(
            s.pool(),
            u32::from(ip("10.51.0.100"))..=u32::from(ip("10.51.0.200"))
        );
        assert!(s.in_pool(ip("10.51.0.100")) && s.in_pool(ip("10.51.0.200")));
        assert!(!s.in_pool(ip("10.51.0.99")) && !s.in_pool(ip("10.51.0.201")));
        assert!(!s.in_pool(ip("10.52.0.150")));
    }

    #[test]
    fn small_subnet_pool_is_cut() {
        let s = Subnet::parse("10.0.0.1/25").unwrap();
        assert_eq!(
            s.pool(),
            u32::from(ip("10.0.0.100"))..=u32::from(ip("10.0.0.126"))
        );
        assert!(Subnet::parse("10.0.0.1/26").unwrap().pool().is_empty());
    }

    #[test]
    fn server_address_not_in_pool() {
        let s = Subnet::parse("10.0.0.150/24").unwrap();
        assert!(!s.in_pool(s.addr));
        assert!(s.in_pool(ip("10.0.0.149")));
    }

    #[test]
    fn parses_only_host_address_with_prefix() {
        assert_eq!(
            Subnet::parse(" 10.50.0.1/24\n"),
            Some(Subnet {
                addr: ip("10.50.0.1"),
                prefix: 24
            })
        );
        for bad in [
            "",
            "10.50.0.1",
            "10.50.0.1/",
            "10.50.0.1/31",
            "10.50.0.1/0",
            "10.50.0.0/24",
            "10.50.0.255/24",
            "10.50.0/24",
            "example/24",
        ] {
            assert_eq!(Subnet::parse(bad), None, "{bad}");
        }
    }
}
