//! The server address may appear only after start. DNS binds it with IP_FREEBIND so it
//! answers as soon as the address exists. DHCP must hear clients that have no address,
//! so it binds 0.0.0.0:67 and uses IP_PKTINFO to take only datagrams from the
//! interface holding the server address, and to reply out of it.

use std::io::{self, IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn,
    bind, recvmsg, sendmsg, setsockopt, socket, sockopt,
};

use crate::wire::SERVER_PORT;

pub const DNS_PORT: u16 = 53;

fn udp() -> io::Result<std::os::fd::OwnedFd> {
    Ok(socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?)
}

pub fn dhcp_socket() -> io::Result<UdpSocket> {
    let fd = udp()?;
    setsockopt(&fd, sockopt::Broadcast, &true)?;
    setsockopt(&fd, sockopt::Ipv4PacketInfo, &true)?;
    bind(
        fd.as_raw_fd(),
        &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT)),
    )?;
    Ok(fd.into())
}

pub fn dns_socket(addr: Ipv4Addr) -> io::Result<UdpSocket> {
    let fd = udp()?;
    setsockopt(&fd, sockopt::IpFreebind, &true)?;
    bind(
        fd.as_raw_fd(),
        &SockaddrIn::from(SocketAddrV4::new(addr, DNS_PORT)),
    )?;
    Ok(fd.into())
}

pub fn recv(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, u32)> {
    let mut cmsg = nix::cmsg_space!(nix::libc::in_pktinfo);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<SockaddrIn>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )?;
    let ifindex = msg
        .cmsgs()?
        .find_map(|c| match c {
            ControlMessageOwned::Ipv4PacketInfo(p) => Some(p.ipi_ifindex as u32),
            _ => None,
        })
        .unwrap_or(0);
    Ok((msg.bytes, ifindex))
}

/// Send out of `ifindex` from `src`, whatever the routing table would pick:
/// a broadcast has no route to choose an interface by.
pub fn send(
    sock: &UdpSocket,
    buf: &[u8],
    ifindex: u32,
    src: Ipv4Addr,
    to: SocketAddrV4,
) -> io::Result<()> {
    let info = nix::libc::in_pktinfo {
        ipi_ifindex: ifindex as _,
        ipi_spec_dst: nix::libc::in_addr {
            s_addr: u32::from(src).to_be(),
        },
        ipi_addr: nix::libc::in_addr { s_addr: 0 },
    };
    sendmsg(
        sock.as_raw_fd(),
        &[IoSlice::new(buf)],
        &[ControlMessage::Ipv4PacketInfo(&info)],
        MsgFlags::empty(),
        Some(&SockaddrIn::from(to)),
    )?;
    Ok(())
}

pub fn ifindex_of(addr: Ipv4Addr) -> Option<u32> {
    nix::ifaddrs::getifaddrs()
        .ok()?
        .find(|i| {
            i.address
                .as_ref()
                .and_then(|a| a.as_sockaddr_in())
                .is_some_and(|a| a.ip() == addr)
        })
        .and_then(|i| nix::net::if_::if_nametoindex(i.interface_name.as_str()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_interface_by_address() {
        let lo = nix::net::if_::if_nametoindex("lo").unwrap();
        assert_eq!(ifindex_of(Ipv4Addr::LOCALHOST), Some(lo));
        assert_eq!(ifindex_of(Ipv4Addr::new(192, 0, 2, 77)), None);
    }

    #[test]
    fn dns_binds_absent_address() {
        let absent = Ipv4Addr::new(192, 0, 2, 77);
        assert!(UdpSocket::bind((absent, 0)).is_err());
        // Port 53 needs privilege; the freebind is what is under test.
        let fd = udp().unwrap();
        setsockopt(&fd, sockopt::IpFreebind, &true).unwrap();
        bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(absent, 0)),
        )
        .unwrap();
    }

    #[test]
    fn pktinfo_round_trip() {
        let fd = udp().unwrap();
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).unwrap();
        bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server: UdpSocket = fd.into();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .send_to(b"ping", server.local_addr().unwrap())
            .unwrap();

        let mut buf = [0u8; 16];
        let (n, ifindex) = recv(&server, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(Some(ifindex), ifindex_of(Ipv4Addr::LOCALHOST));

        let to = match client.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        send(&server, b"pong", ifindex, Ipv4Addr::LOCALHOST, to).unwrap();
        let (n, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(
            (&buf[..n], from),
            (&b"pong"[..], server.local_addr().unwrap())
        );
    }
}
