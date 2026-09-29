use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

// 0.4.0 because kubelet's conflist loader still probes it.
pub const SUPPORTED: &[&str] = &["1.0.0", "0.4.0"];
pub const CURRENT: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Add,
    Del,
    Check,
    Version,
}

impl Command {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "ADD" => Self::Add,
            "DEL" => Self::Del,
            "CHECK" => Self::Check,
            "VERSION" => Self::Version,
            other => anyhow::bail!("unknown CNI_COMMAND {other}"),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct NetConf {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "podCIDR", default)]
    pub pod_cidr: Option<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(rename = "prevResult", default)]
    pub prev_result: Option<serde_json::Value>,
}

fn default_mtu() -> u32 {
    1500
}

#[derive(Debug, Serialize)]
pub struct Result {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub interfaces: Vec<Interface>,
    pub ips: Vec<IpConfig>,
    pub routes: Vec<Route>,
    // Empty: kubelet supplies DNS.
    pub dns: Dns,
}

#[derive(Debug, Serialize)]
pub struct Interface {
    pub name: String,
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IpConfig {
    pub address: String,
    pub gateway: String,
    pub interface: usize,
}

#[derive(Debug, Serialize)]
pub struct Route {
    pub dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct Dns {}

#[derive(Debug, Serialize)]
pub struct Error {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    pub details: String,
}

impl Error {
    pub fn generic(msg: &str, details: String) -> Self {
        Self {
            cni_version: CURRENT.to_string(),
            // The spec's first code not reserved for the runtime.
            code: 100,
            msg: msg.to_string(),
            details,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VersionInfo {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    #[serde(rename = "supportedVersions")]
    pub supported_versions: Vec<String>,
}

pub fn parse_cidr(s: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("{s} is not a CIDR"))?;
    let prefix: u8 = prefix.parse()?;
    anyhow::ensure!(prefix <= 32, "{s}: an IPv4 prefix is at most /32");
    Ok((addr.parse()?, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr() {
        assert_eq!(
            parse_cidr("10.244.0.0/24").unwrap(),
            (Ipv4Addr::new(10, 244, 0, 0), 24)
        );
        assert!(parse_cidr("10.244.0.0").is_err());
        assert!(parse_cidr("nonsense/24").is_err());
        assert!(parse_cidr("10.244.0.0/33").is_err());
    }

    proptest::proptest! {
        #[test]
        fn parsed_cidr_builds_rule(s in "10\\.244\\.0\\.0/[0-9]{1,3}") {
            if let Ok((net, prefix)) = parse_cidr(&s) {
                crate::nft::masquerade_rule(net, prefix);
            }
        }
    }

    #[test]
    fn result_uses_spec_names() {
        let r = Result {
            cni_version: CURRENT.into(),
            interfaces: vec![
                Interface {
                    name: "edgeabc".into(),
                    mac: "aa:bb:cc:dd:ee:00".into(),
                    sandbox: None,
                },
                Interface {
                    name: "eth0".into(),
                    mac: "aa:bb:cc:dd:ee:ff".into(),
                    sandbox: Some("/proc/1/ns/net".into()),
                },
            ],
            ips: vec![IpConfig {
                address: "10.244.0.5/32".into(),
                gateway: "169.254.1.1".into(),
                interface: 1,
            }],
            routes: vec![Route {
                dst: "0.0.0.0/0".into(),
                gw: Some("169.254.1.1".into()),
            }],
            dns: Dns::default(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["cniVersion"], "1.0.0");
        assert_eq!(v["ips"][0]["address"], "10.244.0.5/32");
        assert!(v["interfaces"][0].get("sandbox").is_none());
        assert_eq!(v["interfaces"][1]["sandbox"], "/proc/1/ns/net");
    }

    #[test]
    fn netconf_defaults() {
        let c: NetConf = serde_json::from_str(
            r#"{"cniVersion":"1.0.0","name":"edge","podCIDR":"10.244.0.0/24"}"#,
        )
        .unwrap();
        assert_eq!(c.mtu, 1500);
        assert_eq!(c.pod_cidr.as_deref(), Some("10.244.0.0/24"));
        let floor: NetConf =
            serde_json::from_str(r#"{"cniVersion":"1.0.0","name":"edge"}"#).unwrap();
        assert_eq!(floor.pod_cidr, None);
        assert!(serde_json::from_str::<NetConf>(r#"{"name":"edge"}"#).is_err());
    }
}
