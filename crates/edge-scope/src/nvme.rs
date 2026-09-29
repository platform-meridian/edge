//! NVMe SMART / Health Information (log page 0x02), read through the admin
//! passthrough ioctl. Needs CAP_SYS_ADMIN; lockdown does not block it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const LOG_LEN: usize = 512;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Smart {
    pub dev: String,
    pub warn: u8,
    #[serde(rename = "temp")]
    pub temp_c: i32,
    pub spare: u8,
    #[serde(rename = "spare_th")]
    pub spare_min: u8,
    pub used: u8,
    #[serde(rename = "media")]
    pub media_err: u64,
    #[serde(rename = "cycles")]
    pub power_cycles: u64,
    #[serde(rename = "unsafe")]
    pub unsafe_shutdowns: u64,
    pub hours: u64,
}

/// The 128-bit counters saturate: no device reaches 2^64.
fn counter(log: &[u8; LOG_LEN], at: usize) -> u64 {
    let v = u128::from_le_bytes(log[at..at + 16].try_into().unwrap());
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// Offsets from the NVMe base specification, figure "SMART / Health Information".
pub fn parse(dev: &str, log: &[u8; LOG_LEN]) -> Smart {
    let kelvin = u16::from_le_bytes([log[1], log[2]]);
    Smart {
        dev: dev.to_string(),
        warn: log[0],
        temp_c: i32::from(kelvin) - 273,
        spare: log[3],
        spare_min: log[4],
        used: log[5],
        power_cycles: counter(log, 112),
        hours: counter(log, 128),
        unsafe_shutdowns: counter(log, 144),
        media_err: counter(log, 160),
    }
}

/// `struct nvme_passthru_cmd` from <linux/nvme_ioctl.h>.
#[repr(C)]
#[derive(Default)]
struct PassthruCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

nix::ioctl_readwrite!(nvme_admin_cmd, b'N', 0x41, PassthruCmd);

const GET_LOG_PAGE: u8 = 0x02;
const SMART_LID: u32 = 0x02;

fn smart_cmd(log: &mut [u8; LOG_LEN]) -> PassthruCmd {
    let dwords_minus_one = (LOG_LEN / 4 - 1) as u32;
    PassthruCmd {
        opcode: GET_LOG_PAGE,
        nsid: 0xFFFF_FFFF,
        addr: log.as_mut_ptr() as u64,
        data_len: LOG_LEN as u32,
        cdw10: (dwords_minus_one << 16) | SMART_LID,
        timeout_ms: 5000,
        ..Default::default()
    }
}

pub fn read(path: &Path) -> std::io::Result<Smart> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path)?;
    let mut log = [0u8; LOG_LEN];
    let mut cmd = smart_cmd(&mut log);
    // SAFETY: `cmd` describes `log`, which outlives the call.
    let status =
        unsafe { nvme_admin_cmd(f.as_raw_fd(), &mut cmd) }.map_err(std::io::Error::from)?;
    if status != 0 {
        return Err(std::io::Error::other(format!(
            "controller status {status:#x}"
        )));
    }
    let dev = path.file_name().unwrap_or_default().to_string_lossy();
    Ok(parse(&dev, &log))
}

pub fn controllers(dev_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dev_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("nvme"))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

pub fn read_all(dev_dir: &Path) -> Vec<Smart> {
    controllers(dev_dir)
        .iter()
        .filter_map(|p| match read(p) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(dev = %p.display(), error = %e, "could not read the SMART log");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthru_layout_matches_kernel() {
        assert_eq!(std::mem::size_of::<PassthruCmd>(), 72);
        assert_eq!(std::mem::offset_of!(PassthruCmd, addr), 24);
        assert_eq!(std::mem::offset_of!(PassthruCmd, cdw10), 40);
        assert_eq!(std::mem::offset_of!(PassthruCmd, result), 68);
        // NVME_IOCTL_ADMIN_CMD as the kernel headers expand it.
        assert_eq!(
            nix::request_code_readwrite!(b'N', 0x41, std::mem::size_of::<PassthruCmd>()),
            0xC048_4E41
        );
    }

    #[test]
    fn smart_cmd_reads_whole_log() {
        let mut log = [0u8; LOG_LEN];
        let c = smart_cmd(&mut log);
        assert_eq!(
            (c.opcode, c.nsid, c.data_len, c.cdw10, c.addr),
            (0x02, 0xFFFF_FFFF, 512, 0x007F_0002, log.as_ptr() as u64)
        );
        assert!(c.timeout_ms > 0);
    }

    fn put(log: &mut [u8; LOG_LEN], at: usize, v: u128) {
        log[at..at + 16].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn parses_spec_offsets() {
        let mut log = [0u8; LOG_LEN];
        log[0] = 0b0000_0101;
        log[1..3].copy_from_slice(&318u16.to_le_bytes());
        log[3] = 97;
        log[4] = 10;
        log[5] = 4;
        put(&mut log, 32, 111); // data units read: not recorded
        put(&mut log, 112, 1_234);
        put(&mut log, 128, 5_678);
        put(&mut log, 144, 42);
        put(&mut log, 160, 3);
        put(&mut log, 176, 999); // error log entries: not recorded
        assert_eq!(
            parse("nvme0", &log),
            Smart {
                dev: "nvme0".into(),
                warn: 5,
                temp_c: 45,
                spare: 97,
                spare_min: 10,
                used: 4,
                media_err: 3,
                power_cycles: 1_234,
                unsafe_shutdowns: 42,
                hours: 5_678,
            }
        );
    }

    #[test]
    fn counters_saturate() {
        let mut log = [0u8; LOG_LEN];
        put(&mut log, 144, u128::from(u64::MAX) + 1);
        put(&mut log, 160, u128::from(u64::MAX));
        let s = parse("nvme1", &log);
        assert_eq!((s.unsafe_shutdowns, s.media_err), (u64::MAX, u64::MAX));
        assert_eq!(s.temp_c, -273);
    }

    #[test]
    fn lists_only_controllers() {
        let d = std::env::temp_dir().join(format!("edge-scope-dev-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        for n in [
            "nvme1",
            "nvme0",
            "nvme0n1",
            "nvme0n1p1",
            "nvme",
            "nvme-fabrics",
            "sda",
        ] {
            std::fs::write(d.join(n), b"").unwrap();
        }
        assert_eq!(controllers(&d), [d.join("nvme0"), d.join("nvme1")]);
        assert!(controllers(&d.join("missing")).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn non_nvme_device_errors() {
        assert!(read(Path::new("/dev/null")).is_err());
        assert!(read(Path::new("/nonexistent/nvme0")).is_err());
    }
}
