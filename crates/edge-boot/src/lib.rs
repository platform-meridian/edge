//! The unit signs its own boot chain: an EFI image with its Secure Boot key,
//! and a UKI's PCR 11 policies (`.pcrpkey`, `.pcrsig`) with its PCR key, as
//! `systemd-sbsign` and `systemd-measure` would. The keys are the unit's
//! own, in its TPM ([`tpm`]); [`Signer`] is what signs, so tests can use
//! keys in software.
//!
//! Re-signing a UKI also grants the OS it boots the right to sign
//! ([`Signer::grant`]): a unit's keys sign only under an OS the unit signed.

pub mod authenticode;
pub mod der;
pub mod measure;
pub mod pe;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod tpm;

use anyhow::{Context, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Signs EFI images; its certificate is in the firmware's db.
    SecureBoot,
    /// Signs a UKI's PCR 11 policies.
    Pcr,
}

pub trait Signer: Send + Sync {
    /// The Secure Boot key's certificate, DER.
    fn certificate(&self) -> anyhow::Result<Vec<u8>>;
    /// A key's RSA modulus and exponent.
    fn public(&self, key: Key) -> anyhow::Result<(Vec<u8>, u32)>;
    /// RSASSA-PKCS1-v1_5 SHA-256 over `message`.
    fn sign(&self, key: Key, message: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// Lets the OS that runs with PCR 11 policy `policy` sign too, beside the running one.
    fn grant(&self, policy: &[u8; 32]) -> anyhow::Result<()>;
}

/// PCR 11 phase paths, each `:`-joined as `systemd-measure --phase` takes them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Phases {
    /// Where a UKI's `.pcrsig` lets PCR 11 policies unseal.
    pub signed: Vec<String>,
    /// PCR 11's path once the OS runs: the OS a re-signed UKI boots may sign.
    pub running: String,
}

/// Signs an EFI image, in place of any signature it has.
pub fn sign_image(signer: &dyn Signer, image: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let mut image = pe::unsigned(image)?;
    let digest = pe::Pe::parse(&image)?.authenticode_digest()?;
    let pkcs7 = authenticode::signed_data(&digest, &signer.certificate()?, |m| {
        signer.sign(Key::SecureBoot, m)
    })?;
    pe::attach(&mut image, &pkcs7)?;
    Ok(image)
}

/// The UKI sections after sd-stub's own.
const UKI_SECTIONS: [&str; 14] = [
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".pcrsig",
    ".pcrpkey", ".profile", ".dtbauto", ".hwids", ".efifw",
];

#[derive(Serialize)]
struct Bank {
    pcrs: [u8; 1],
    pkfp: String,
    pol: String,
    sig: String,
}

#[derive(Serialize)]
struct PcrSig {
    sha256: Vec<Bank>,
}

/// Signs a UKI with the unit's keys: its `.pcrpkey` becomes the PCR key's,
/// each profile gets a `.pcrsig` for every signed phase path, and the first
/// profile's running PCR 11 is granted.
pub fn sign_uki(signer: &dyn Signer, uki: Vec<u8>, phases: &Phases) -> anyhow::Result<Vec<u8>> {
    let unsigned = pe::unsigned(uki)?;
    let image = pe::Pe::parse(&unsigned)?;
    let stub = image
        .sections
        .iter()
        .position(|s| UKI_SECTIONS.contains(&s.name.as_str()))
        .context("not a UKI")?;
    ensure!(stub > 0, "not a UKI: no sd-stub");
    let sbat = image.sections[..stub]
        .iter()
        .find(|s| s.name == ".sbat")
        .map(|s| image.contents(s));

    let (modulus, exponent) = signer.public(Key::Pcr)?;
    let pkfp = hex::encode(Sha256::digest(der::rsa_pkcs1(&modulus, exponent)));
    let pcrpkey = pem("PUBLIC KEY", &der::rsa_spki(&modulus, exponent)).into_bytes();

    let mut sections: Vec<(&str, &[u8])> = Vec::new();
    for s in &image.sections[stub..] {
        if s.name == ".pcrsig" || s.name == ".pcrpkey" {
            continue;
        }
        if s.name == ".profile" && !sections.iter().any(|(n, _)| *n == ".pcrpkey") {
            sections.push((".pcrpkey", &pcrpkey));
        }
        sections.push((&s.name, image.contents(s)));
    }
    if !sections.iter().any(|(n, _)| *n == ".pcrpkey") {
        sections.push((".pcrpkey", &pcrpkey));
    }

    // The base, then a block per profile; each profile measures the base under its own sections.
    let base = sections
        .iter()
        .position(|(n, _)| *n == ".profile")
        .unwrap_or(sections.len());
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    for (i, (n, _)) in sections.iter().enumerate().skip(base) {
        if *n == ".profile" {
            if let Some(b) = blocks.last_mut() {
                b.1 = i;
            }
            blocks.push((i, sections.len()));
        }
    }
    if blocks.is_empty() {
        blocks.push((base, base));
    }
    let measured = |block: (usize, usize)| {
        let (base, block) = (&sections[..base], &sections[block.0..block.1]);
        move |name: &str| {
            block
                .iter()
                .chain(base)
                .find(|(n, _)| *n == name)
                .map(|(_, c)| *c)
                .or(sbat.filter(|_| name == ".sbat"))
        }
    };

    let mut signatures = Vec::new();
    for &block in &blocks {
        let mut banks = Vec::new();
        for path in &phases.signed {
            let path: Vec<&str> = path.split(':').collect();
            let pol = measure::policy_pcr(&measure::pcr(measured(block), &path));
            banks.push(Bank {
                pcrs: [measure::PCR],
                pkfp: pkfp.clone(),
                pol: hex::encode(pol),
                sig: base64::engine::general_purpose::STANDARD.encode(signer.sign(Key::Pcr, &pol)?),
            });
        }
        signatures.push(serde_json::to_vec(&PcrSig { sha256: banks })?);
    }
    let running: Vec<&str> = phases.running.split(':').collect();
    let granted = measure::policy_pcr(&measure::pcr(measured(blocks[0]), &running));

    // Each .pcrsig closes its block.
    let mut appended = sections[..base].to_vec();
    for (&(start, end), sig) in blocks.iter().zip(&signatures) {
        appended.extend_from_slice(&sections[start..end]);
        appended.push((".pcrsig", sig));
    }
    let rebuilt = image.rebuild(stub, &appended)?;
    drop(appended);
    drop(sections);
    drop(unsigned);
    let signed = sign_image(signer, rebuilt)?;
    signer.grant(&granted)?;
    Ok(signed)
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
