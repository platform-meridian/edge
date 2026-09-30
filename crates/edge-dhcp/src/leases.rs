//! The lease file: what the port has handed out, for readers on the host and
//! for edge-dhcp after a restart. One record a line, fields split by spaces:
//! `serving <addr>/<prefix> <domain|->`, then per live lease
//! `lease <expires, unix s> <mac> <ip> <hostname|-> <client key, hex>`.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::Subnet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub hostname: Option<String>,
    pub key: Vec<u8>,
    pub expires: u64,
}

const NONE: &str = "-";
const HOSTNAME_MAX: usize = 63;

/// A client names itself; a space or a newline in that name would split a record.
pub fn hostname(raw: &str) -> Option<String> {
    let h: String = raw
        .chars()
        .take(HOSTNAME_MAX)
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    (!h.is_empty() && h != NONE).then_some(h)
}

pub fn render(subnet: Subnet, domain: Option<&str>, records: &[Record]) -> String {
    let mut out = format!(
        "serving {}/{} {}\n",
        subnet.addr,
        subnet.prefix,
        domain.unwrap_or(NONE)
    );
    for r in records {
        let key: String = r.key.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(
            out,
            "lease {} {} {} {} {key}",
            r.expires,
            r.mac,
            r.ip,
            r.hostname.as_deref().unwrap_or(NONE)
        );
    }
    out
}

/// The leases it can read; anything else is skipped.
pub fn parse(text: &str) -> Vec<Record> {
    text.lines().filter_map(record).collect()
}

fn record(line: &str) -> Option<Record> {
    let f: Vec<&str> = line.split(' ').collect();
    let ["lease", expires, mac, ip, hostname, key] = f[..] else {
        return None;
    };
    Some(Record {
        ip: ip.parse().ok()?,
        mac: mac.to_owned(),
        hostname: (hostname != NONE).then(|| hostname.to_owned()),
        key: hex(key)?,
        expires: expires.parse().ok()?,
    })
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laptop() -> Record {
        Record {
            ip: Ipv4Addr::new(10, 51, 0, 150),
            mac: "02:11:22:33:44:55".into(),
            hostname: Some("field-laptop".into()),
            key: vec![1, 2, 0x11, 0x22, 0x33, 0x44, 0x55],
            expires: 1_790_000_000,
        }
    }

    #[test]
    fn renders_serving_then_leases() {
        let subnet = Subnet::parse("10.51.0.1/24").unwrap();
        let anonymous = Record {
            hostname: None,
            ..laptop()
        };
        assert_eq!(
            render(subnet, Some("example.lan"), &[laptop(), anonymous]),
            "serving 10.51.0.1/24 example.lan\n\
             lease 1790000000 02:11:22:33:44:55 10.51.0.150 field-laptop 01021122334455\n\
             lease 1790000000 02:11:22:33:44:55 10.51.0.150 - 01021122334455\n"
        );
        assert_eq!(render(subnet, None, &[]), "serving 10.51.0.1/24 -\n");
    }

    #[test]
    fn round_trips() {
        let subnet = Subnet::parse("10.51.0.1/24").unwrap();
        let records = vec![
            laptop(),
            Record {
                hostname: None,
                ..laptop()
            },
        ];
        assert_eq!(parse(&render(subnet, None, &records)), records);
    }

    #[test]
    fn skips_unreadable_lines() {
        let text = "serving 10.51.0.1/24 -\n\
                    lease 1790000000 02:11:22:33:44:55 10.51.0.150 - 0102\n\
                    lease soon 02:11:22:33:44:55 10.51.0.151 - 0102\n\
                    lease 1790000000 02:11:22:33:44:55 10.51.0.152 - 010\n\
                    lease 1790000000 02:11:22:33:44:55 10.51.0.153 - zz\n\
                    lease 1790000000 02:11:22:33:44:55 10.51.0.154 -\n\
                    lease 1790000000 02:11:22:33:44:55 nowhere - 0102\n\
                    lease 1790000000 02:11:22:33:44:55 10.51.0.155 - \n\
                    lease 1790000000 02:11:22:33:44:55 10.51.0.156 - 0102";
        let ips: Vec<Ipv4Addr> = parse(text).iter().map(|r| r.ip).collect();
        assert_eq!(
            ips,
            [Ipv4Addr::new(10, 51, 0, 150), Ipv4Addr::new(10, 51, 0, 156)]
        );
    }

    #[test]
    fn hostnames_stay_one_field() {
        assert_eq!(hostname("Sam's laptop\n").as_deref(), Some("Sam's_laptop_"));
        assert_eq!(hostname(""), None);
        assert_eq!(hostname("-"), None);
        assert_eq!(hostname(&"a".repeat(80)).map(|h| h.len()), Some(63));
        assert_eq!(hostname("naïve").as_deref(), Some("na_ve"));
    }
}
