//! PCR 11 as systemd-stub measures a UKI, and the TPM policies over it.

use sha2::{Digest, Sha256};

/// The UKI sections systemd-stub measures, in its order.
pub const MEASURED: [&str; 13] = [
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat",
    ".pcrpkey", ".profile", ".dtbauto", ".hwids",
];

pub const PCR: u8 = 11;

fn extend(pcr: &mut [u8; 32], data: &[u8]) {
    let mut h = Sha256::new();
    h.update(*pcr);
    h.update(Sha256::digest(data));
    *pcr = h.finalize().into();
}

/// PCR 11 after the sections (name, contents), then each phase.
pub fn pcr<'a>(sections: impl Fn(&str) -> Option<&'a [u8]>, phases: &[&str]) -> [u8; 32] {
    let mut pcr = [0u8; 32];
    for name in MEASURED {
        if let Some(contents) = sections(name) {
            extend(&mut pcr, &[name.as_bytes(), &[0]].concat());
            extend(&mut pcr, contents);
        }
    }
    for phase in phases {
        extend(&mut pcr, phase.as_bytes());
    }
    pcr
}

/// `TPML_PCR_SELECTION` of PCR 11 in the SHA-256 bank.
pub fn selection() -> [u8; 10] {
    let mut s = [0, 0, 0, 1, 0x00, 0x0b, 3, 0, 0, 0];
    s[7 + PCR as usize / 8] = 1 << (PCR % 8);
    s
}

/// The digest of TPM2_PolicyPCR on a fresh session, PCR 11 at `value`.
pub fn policy_pcr(value: &[u8; 32]) -> [u8; 32] {
    const POLICY_PCR: u32 = 0x17f;
    let mut h = Sha256::new();
    h.update([0u8; 32]);
    h.update(POLICY_PCR.to_be_bytes());
    h.update(selection());
    h.update(Sha256::digest(value));
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_pcr_11() {
        assert_eq!(selection(), [0, 0, 0, 1, 0, 0x0b, 3, 0, 8, 0]);
    }
}
