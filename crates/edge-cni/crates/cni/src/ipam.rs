//! IPAM with no database: the kernel's /32 routes to pod veths are the leases,
//! and the kernel drops a route when its veth goes.

use std::net::Ipv4Addr;

pub struct Pool {
    base: u32,
    first: u32,
    gateway: u32,
}

impl Pool {
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> anyhow::Result<Self> {
        if prefix_len > 30 {
            anyhow::bail!("prefix /{prefix_len} is too small to hold a pod");
        }
        // u64: a /0 would shift a u32 by 32.
        let size = 1u64 << (32 - prefix_len as u32);
        let mask = !((size - 1) as u32);
        let base = u32::from(network) & mask;
        Ok(Self {
            base,
            first: base + 1,
            gateway: (base as u64 + size - 2) as u32,
        })
    }

    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.gateway)
    }

    // Not the lowest free address: a just-released one is still held by stale
    // connections and caches.
    pub fn allocate(&self, taken: &[Ipv4Addr]) -> anyhow::Result<Ipv4Addr> {
        let held: std::collections::HashSet<u32> = taken
            .iter()
            .copied()
            .map(u32::from)
            .filter(|a| self.contains_raw(*a))
            .collect();
        let after = held.iter().max().map_or(self.first, |h| h + 1);
        let start = if after < self.gateway {
            after
        } else {
            self.first
        };

        let ahead = start..self.gateway;
        let wrapped = self.first..start;
        ahead
            .chain(wrapped)
            .find(|a| !held.contains(a))
            .map(Ipv4Addr::from)
            .ok_or_else(|| anyhow::anyhow!("pod CIDR {} is full", Ipv4Addr::from(self.base)))
    }

    fn contains_raw(&self, a: u32) -> bool {
        a >= self.first && a < self.gateway
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.contains_raw(u32::from(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Pool {
        Pool::new(Ipv4Addr::new(10, 244, 0, 0), 24).unwrap()
    }

    fn host(i: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 244, 0, i)
    }

    #[test]
    fn allocates_past_highest_and_wraps() {
        let cases: &[(&str, Vec<Ipv4Addr>, u8)] = &[
            ("empty pool starts at .1", vec![], 1),
            (
                "a freed .3 is not handed straight back",
                vec![host(1), host(2), host(4)],
                5,
            ),
            (
                "unsorted and duplicated",
                vec![host(3), host(1), host(1), host(2)],
                4,
            ),
            ("a full top wraps to the bottom", vec![host(253)], 1),
            (
                "wraps and finds the hole",
                (1..=253).filter(|i| *i != 10).map(host).collect(),
                10,
            ),
            (
                "routes outside the pool are not leases",
                vec![Ipv4Addr::new(10, 96, 0, 1), Ipv4Addr::new(192, 168, 1, 1)],
                1,
            ),
        ];
        for (what, taken, want) in cases {
            assert_eq!(pool().allocate(taken).unwrap(), host(*want), "{what}");
        }
    }

    #[test]
    fn gateway_never_allocated() {
        let p = pool();
        assert_eq!(p.gateway(), host(254));
        assert!(!p.contains(p.gateway()));
        assert!(p.contains(host(1)) && p.contains(host(253)) && !p.contains(host(0)));
        let taken: Vec<Ipv4Addr> = (1..254).map(host).collect();
        assert!(p.allocate(&taken).is_err());
    }

    #[test]
    fn rolling_replacement_walks_forward() {
        let p = pool();
        let mut live = vec![host(1)];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let next = p.allocate(&live).unwrap();
            assert!(seen.insert(next), "{next} handed out twice within one lap");
            live = vec![next];
        }
    }

    #[test]
    fn pool_is_masked_prefix() {
        assert!(Pool::new(Ipv4Addr::new(10, 0, 0, 0), 31).is_err());
        let p = Pool::new(Ipv4Addr::new(10, 244, 0, 77), 24).unwrap();
        assert_eq!(p.allocate(&[]).unwrap(), host(1));
        assert_eq!(p.gateway(), host(254));
        let wide = Pool::new(Ipv4Addr::new(10, 0, 0, 0), 0).unwrap();
        assert_eq!(wide.gateway(), Ipv4Addr::new(255, 255, 255, 254));
    }
}
