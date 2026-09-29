//! One veth per pod, no bridge: a host /32 route to the veth is both the path and
//! the lease, and the pod's gateway is answered by proxy ARP and assigned nowhere.

use crate::ipam::Pool;
use anyhow::Context;
use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteScope};
use rtnetlink::{Handle, LinkUnspec, LinkVeth, RouteMessageBuilder, new_connection};
use std::net::{IpAddr, Ipv4Addr};

pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);

pub struct Net {
    pub handle: Handle,
}

impl Net {
    pub fn open() -> anyhow::Result<Self> {
        let (conn, handle, _) = new_connection()?;
        tokio::spawn(conn);
        Ok(Self { handle })
    }

    pub async fn leased(&self, pool: &Pool) -> anyhow::Result<Vec<Ipv4Addr>> {
        let mut out = Vec::new();
        let mut routes = self
            .handle
            .route()
            .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
            .execute();
        while let Some(r) = routes.try_next().await.context("dump routes")? {
            if r.header.destination_prefix_length != 32 {
                continue;
            }
            for attr in &r.attributes {
                if let RouteAttribute::Destination(RouteAddress::Inet(a)) = attr
                    && pool.contains(*a)
                {
                    out.push(*a);
                }
            }
        }
        Ok(out)
    }

    pub async fn pod_veths(&self, pool: &Pool) -> anyhow::Result<Vec<(u32, Ipv4Addr)>> {
        let mut out = Vec::new();
        let mut routes = self
            .handle
            .route()
            .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
            .execute();
        while let Some(r) = routes.try_next().await.context("dump routes")? {
            if r.header.destination_prefix_length != 32 {
                continue;
            }
            let mut dst = None;
            let mut oif = None;
            for attr in &r.attributes {
                match attr {
                    RouteAttribute::Destination(RouteAddress::Inet(a)) if pool.contains(*a) => {
                        dst = Some(*a)
                    }
                    RouteAttribute::Oif(i) => oif = Some(*i),
                    _ => {}
                }
            }
            if let (Some(a), Some(i)) = (dst, oif) {
                out.push((i, a));
            }
        }
        Ok(out)
    }

    pub async fn local_addrs(&self) -> anyhow::Result<Vec<Ipv4Addr>> {
        use netlink_packet_route::address::AddressAttribute;
        let mut out = Vec::new();
        let mut addrs = self.handle.address().get().execute();
        while let Some(a) = addrs.try_next().await.context("dump addresses")? {
            for attr in &a.attributes {
                if let AddressAttribute::Local(IpAddr::V4(ip)) = attr {
                    out.push(*ip);
                }
            }
        }
        Ok(out)
    }

    pub async fn link_name(&self, index: u32) -> anyhow::Result<String> {
        use netlink_packet_route::link::LinkAttribute;
        let mut links = self.handle.link().get().match_index(index).execute();
        let l = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no link with index {index}"))?;
        l.attributes
            .into_iter()
            .find_map(|a| {
                if let LinkAttribute::IfName(n) = a {
                    Some(n)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("link {index} has no name"))
    }

    pub async fn link_index(&self, name: &str) -> anyhow::Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let l = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no link named {name}"))?;
        Ok(l.header.index)
    }

    pub async fn create_veth(&self, host: &str, peer: &str, mtu: u32) -> anyhow::Result<()> {
        self.handle
            .link()
            .add(LinkVeth::new(host, peer).build())
            .execute()
            .await
            .with_context(|| format!("create veth {host}<->{peer}"))?;
        for n in [host, peer] {
            let idx = self.link_index(n).await?;
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(idx).mtu(mtu).build())
                .execute()
                .await
                .with_context(|| format!("set mtu {mtu} on {n}"))?;
        }
        Ok(())
    }

    pub async fn set_up(&self, name: &str) -> anyhow::Result<()> {
        let idx = self.link_index(name).await?;
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await
            .with_context(|| format!("set {name} up"))?;
        Ok(())
    }

    pub async fn move_to_netns(&self, name: &str, fd: std::os::fd::RawFd) -> anyhow::Result<()> {
        let idx = self.link_index(name).await?;
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).setns_by_fd(fd).build())
            .execute()
            .await
            .with_context(|| format!("move {name} into netns"))?;
        Ok(())
    }

    // One message: a link can only be renamed while down.
    pub async fn rename(&self, idx: u32, name: &str, mtu: u32) -> anyhow::Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).name(name).mtu(mtu).build())
            .execute()
            .await
            .with_context(|| format!("rename link {idx} to {name}"))?;
        Ok(())
    }

    pub async fn add_addr(&self, name: &str, addr: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
        let idx = self.link_index(name).await?;
        self.handle
            .address()
            .add(idx, IpAddr::V4(addr), prefix)
            .execute()
            .await
            .with_context(|| format!("add {addr}/{prefix} to {name}"))?;
        Ok(())
    }

    // `Ok(false)`: a concurrent ADD claimed it first.
    pub async fn claim_host_route(&self, dst: Ipv4Addr, dev: &str) -> anyhow::Result<bool> {
        let idx = self.link_index(dev).await?;
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst, 32)
            .output_interface(idx)
            .scope(RouteScope::Link)
            .build();
        match self.handle.route().add(route).execute().await {
            Ok(()) => Ok(true),
            Err(rtnetlink::Error::NetlinkError(m))
                if m.to_io().kind() == std::io::ErrorKind::AlreadyExists =>
            {
                Ok(false)
            }
            Err(e) => Err(e).with_context(|| format!("add host route {dst}/32 dev {dev}")),
        }
    }

    // The on-link route first: the kernel rejects a default via an unreachable gateway.
    pub async fn add_default_via_gateway(&self, dev: &str) -> anyhow::Result<()> {
        let idx = self.link_index(dev).await?;
        let onlink = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(GATEWAY, 32)
            .output_interface(idx)
            .scope(RouteScope::Link)
            .build();
        self.handle
            .route()
            .add(onlink)
            .execute()
            .await
            .context("add on-link route to the gateway")?;

        let default = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .gateway(GATEWAY)
            .output_interface(idx)
            .build();
        self.handle
            .route()
            .add(default)
            .execute()
            .await
            .context("add default route via the gateway")?;
        Ok(())
    }

    pub async fn delete_link(&self, name: &str) -> anyhow::Result<()> {
        let idx = self.link_index(name).await?;
        self.handle
            .link()
            .del(idx)
            .execute()
            .await
            .with_context(|| format!("delete link {name}"))?;
        Ok(())
    }

    pub async fn mac_of(&self, name: &str) -> anyhow::Result<String> {
        use netlink_packet_route::link::LinkAttribute;
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let l = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no link named {name}"))?;
        for a in &l.attributes {
            if let LinkAttribute::Address(bytes) = a {
                return Ok(bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"));
            }
        }
        anyhow::bail!("{name} has no hardware address")
    }
}

const MAX_IFNAME_LEN: usize = 15;

pub fn veth_names(container_id: &str) -> (String, String) {
    let id: String = container_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let stem = &id[..id.len().min(MAX_IFNAME_LEN - "edge".len())];
    (format!("edge{stem}"), format!("edgp{stem}"))
}

pub fn enable_proxy_arp(host_veth: &str) -> anyhow::Result<()> {
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{host_veth}/proxy_arp"),
        b"1",
    )?;
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{host_veth}/forwarding"),
        b"1",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_names_fit_ifnamsiz() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (host, peer) = veth_names(id);
        assert_eq!(
            (host.as_str(), peer.as_str()),
            ("edge0123456789a", "edgp0123456789a")
        );
        assert!(host.len() <= 15 && peer.len() <= 15);
        assert_ne!(veth_names("aaaaaaaaaaaa").0, veth_names("bbbbbbbbbbbb").0);
        assert_eq!(veth_names("ab"), ("edgeab".into(), "edgpab".into()));
        assert_eq!(veth_names(""), ("edge".into(), "edgp".into()));
        assert_eq!(veth_names("a-b_c"), ("edgeabc".into(), "edgpabc".into()));
    }
}
