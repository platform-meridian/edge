//! DHCPv4 (RFC 2131, 2132): only the fields and options edge-dhcp uses.

use std::net::Ipv4Addr;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPTIONS_OFFSET: usize = 240;
/// BOOTP's minimum message: some clients drop anything shorter.
const MIN_LEN: usize = 300;
const BROADCAST_FLAG: u16 = 0x8000;

pub mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const DNS: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN: u8 = 15;
    pub const BROADCAST: u8 = 28;
    pub const REQUESTED: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const T1: u8 = 58;
    pub const T2: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Discover = 1,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl Kind {
    fn from_code(c: u8) -> Option<Kind> {
        use Kind::*;
        [Discover, Offer, Request, Decline, Ack, Nak, Release, Inform]
            .into_iter()
            .find(|k| *k as u8 == c)
    }
}

/// A client's message. BOOTP (no message type) is not one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub kind: Kind,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub htype: u8,
    pub chaddr: Vec<u8>,
    pub client_id: Option<Vec<u8>>,
    pub requested: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub hostname: Option<String>,
}

impl Request {
    /// Client identifier if sent, else hardware address, as dnsmasq keys leases.
    pub fn lease_key(&self) -> Vec<u8> {
        self.client_id.clone().unwrap_or_else(|| {
            let mut k = vec![self.htype];
            k.extend_from_slice(&self.chaddr);
            k
        })
    }

    pub fn mac(&self) -> String {
        let hex: Vec<String> = self.chaddr.iter().map(|b| format!("{b:02x}")).collect();
        hex.join(":")
    }
}

fn ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(b).ok().map(Ipv4Addr::from)
}

pub fn decode(b: &[u8]) -> Option<Request> {
    if b.len() < OPTIONS_OFFSET || b[0] != BOOTREQUEST || b[236..240] != COOKIE {
        return None;
    }
    let hlen = usize::from(b[2]);
    if hlen > 16 {
        return None;
    }
    let (mut kind, mut client_id, mut requested, mut server_id, mut hostname) =
        (None, None, None, None, None);
    let mut i = OPTIONS_OFFSET;
    while let Some(&code) = b.get(i) {
        i += 1;
        match code {
            opt::PAD => continue,
            opt::END => break,
            _ => {}
        }
        let len = usize::from(*b.get(i)?);
        let v = b.get(i + 1..i + 1 + len)?;
        i += 1 + len;
        match code {
            opt::TYPE if len == 1 => kind = Kind::from_code(v[0]),
            opt::CLIENT_ID if len > 0 => client_id = Some(v.to_vec()),
            opt::REQUESTED => requested = ipv4(v),
            opt::SERVER_ID => server_id = ipv4(v),
            opt::HOSTNAME => hostname = Some(String::from_utf8_lossy(v).into_owned()),
            _ => {}
        }
    }
    Some(Request {
        kind: kind?,
        xid: u32::from_be_bytes(b[4..8].try_into().ok()?),
        flags: u16::from_be_bytes([b[10], b[11]]),
        ciaddr: ipv4(&b[12..16])?,
        giaddr: ipv4(&b[24..28])?,
        htype: b[1],
        chaddr: b[28..28 + hlen].to_vec(),
        client_id,
        requested,
        server_id,
        hostname,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub kind: Kind,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub htype: u8,
    pub chaddr: Vec<u8>,
    /// After the message type, in order.
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Reply {
    pub fn to(req: &Request, kind: Kind) -> Reply {
        Reply {
            kind,
            xid: req.xid,
            flags: req.flags & BROADCAST_FLAG,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            htype: req.htype,
            chaddr: req.chaddr.clone(),
            options: Vec::new(),
        }
    }

    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MIN_LEN);
        b.extend_from_slice(&[BOOTREPLY, self.htype, self.chaddr.len() as u8, 0]);
        b.extend_from_slice(&self.xid.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.flags.to_be_bytes());
        for a in [self.ciaddr, self.yiaddr, self.siaddr, Ipv4Addr::UNSPECIFIED] {
            b.extend_from_slice(&a.octets());
        }
        b.extend_from_slice(&self.chaddr);
        b.resize(236, 0);
        b.extend_from_slice(&COOKIE);
        b.extend_from_slice(&[opt::TYPE, 1, self.kind as u8]);
        for (code, v) in &self.options {
            b.push(*code);
            b.push(v.len() as u8);
            b.extend_from_slice(v);
        }
        b.push(opt::END);
        b.resize(b.len().max(MIN_LEN), opt::PAD);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::dhcpcd_discover;

    const MAC_KEY: [u8; 7] = [1, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    const CLIENT_ID_RANGE: std::ops::Range<usize> = 260..281;

    #[test]
    fn decodes_real_discover() {
        let r = decode(&dhcpcd_discover()).unwrap();
        assert_eq!(r.kind, Kind::Discover);
        assert_eq!(r.xid, 0x5f52_6fc7);
        assert_eq!(r.mac(), "02:11:22:33:44:55");
        assert_eq!(r.client_id.as_ref().map(Vec::len), Some(19));
        assert_eq!(r.lease_key(), r.client_id.clone().unwrap());
        assert_eq!((r.requested, r.server_id, r.hostname), (None, None, None));
        assert_eq!(
            (r.ciaddr, r.giaddr),
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn mac_keys_lease_without_client_id() {
        let mut b = dhcpcd_discover();
        assert_eq!(b[CLIENT_ID_RANGE.start], opt::CLIENT_ID);
        b[CLIENT_ID_RANGE].fill(opt::PAD);
        let r = decode(&b).unwrap();
        assert_eq!(r.client_id, None);
        assert_eq!(r.lease_key(), MAC_KEY);
    }

    fn with_options(options: &[u8]) -> Vec<u8> {
        let mut b = dhcpcd_discover();
        b.truncate(OPTIONS_OFFSET);
        b.extend_from_slice(options);
        b
    }

    #[test]
    fn decodes_request_fields() {
        let r = decode(&with_options(&[
            53, 1, 3, 50, 4, 10, 51, 0, 150, 54, 4, 10, 51, 0, 1, 12, 6, b'l', b'a', b'p', b't',
            b'o', b'p', 255,
        ]))
        .unwrap();
        assert_eq!(r.kind, Kind::Request);
        assert_eq!(r.requested, Some(Ipv4Addr::new(10, 51, 0, 150)));
        assert_eq!(r.server_id, Some(Ipv4Addr::new(10, 51, 0, 1)));
        assert_eq!(r.hostname.as_deref(), Some("laptop"));
    }

    #[test]
    fn rejects_malformed_messages() {
        let good = dhcpcd_discover();
        let mut reply = good.clone();
        reply[0] = BOOTREPLY;
        let mut cookie = good.clone();
        cookie[239] ^= 1;
        let mut hlen = good.clone();
        hlen[2] = 17;
        for (what, b) in [
            ("bootp", &with_options(&[255])[..]),
            ("unknown type", &with_options(&[53, 1, 9, 255])[..]),
            ("reply", &reply[..]),
            ("cookie", &cookie[..]),
            ("hlen", &hlen[..]),
            ("overlong", &with_options(&[53, 1, 1, 12, 9, b'x'])[..]),
            ("two-byte type", &with_options(&[53, 2, 1, 1, 255])[..]),
            ("short", &good[..239]),
        ] {
            assert_eq!(decode(b), None, "{what}");
        }
    }

    #[test]
    fn decodes_long_chaddr_and_empty_client_id() {
        let mut b = with_options(&[53, 1, 1, 61, 0, 255]);
        b[2] = 16;
        let r = decode(&b).unwrap();
        assert_eq!(r.chaddr.len(), 16);
        assert_eq!(r.client_id, None);
    }

    #[test]
    fn decodes_unterminated_options() {
        assert_eq!(
            decode(&with_options(&[0, 53, 1, 8])).unwrap().kind,
            Kind::Inform
        );
    }

    #[test]
    fn reply_layout_padded_to_300() {
        let req = decode(&dhcpcd_discover()).unwrap();
        let mut r = Reply::to(&req, Kind::Offer);
        r.ciaddr = Ipv4Addr::new(10, 51, 0, 9);
        r.yiaddr = Ipv4Addr::new(10, 51, 0, 150);
        r.siaddr = Ipv4Addr::new(10, 51, 0, 1);
        r.options.push((opt::SERVER_ID, vec![10, 51, 0, 1]));
        let b = r.encode();
        assert_eq!(b.len(), MIN_LEN);
        assert_eq!(&b[..4], &[BOOTREPLY, 1, 6, 0]);
        assert_eq!(&b[4..8], &0x5f52_6fc7_u32.to_be_bytes());
        assert_eq!(&b[12..16], &[10, 51, 0, 9]);
        assert_eq!(&b[16..20], &[10, 51, 0, 150]);
        assert_eq!(&b[20..24], &[10, 51, 0, 1]);
        assert_eq!(&b[24..28], &[0; 4]);
        assert_eq!(&b[28..34], &req.chaddr[..]);
        assert!(b[34..236].iter().all(|&x| x == 0));
        assert_eq!(&b[236..240], &COOKIE);
        assert_eq!(&b[240..252], &[53, 1, 2, 54, 4, 10, 51, 0, 1, 255, 0, 0]);
    }

    #[test]
    fn long_reply_not_truncated() {
        let req = decode(&dhcpcd_discover()).unwrap();
        let mut r = Reply::to(&req, Kind::Ack);
        r.options.push((opt::DOMAIN, vec![b'x'; 100]));
        let b = r.encode();
        assert_eq!(b.len(), 240 + 3 + 102 + 1);
        assert_eq!(b[b.len() - 1], opt::END);
    }

    #[test]
    fn echoes_only_broadcast_flag() {
        let mut req = decode(&dhcpcd_discover()).unwrap();
        req.flags = 0xffff;
        assert_eq!(Reply::to(&req, Kind::Offer).encode()[10..12], [0x80, 0]);
    }
}
