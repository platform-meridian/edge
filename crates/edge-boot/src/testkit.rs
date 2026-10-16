//! Keys in software and a stand-in EFI image, for tests.

use std::sync::Mutex;

use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};

use crate::{Key, Signer, der};

pub const CERT: &[u8] = include_bytes!("../testdata/cert.der");
const KEY: &[u8] = include_bytes!("../testdata/key.pk8");

/// One RSA key in both roles; records what it grants.
pub struct Soft {
    key: RsaKeyPair,
    pub granted: Mutex<Vec<[u8; 32]>>,
}

impl Default for Soft {
    fn default() -> Self {
        Self {
            key: RsaKeyPair::from_pkcs8(KEY).expect("the test key"),
            granted: Mutex::default(),
        }
    }
}

impl Soft {
    pub fn modulus(&self) -> Vec<u8> {
        // RSAPublicKey: SEQUENCE { modulus, exponent }
        let (_, _, key) = der::next(self.key.public().as_ref()).expect("DER");
        let (_, _, n) = der::next(key).expect("DER");
        n[usize::from(n[0] == 0)..].to_vec()
    }

    /// Panics unless `sig` is this key's over `message`.
    pub fn verify(&self, message: &[u8], sig: &[u8]) {
        signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            self.key.public().as_ref(),
        )
        .verify(message, sig)
        .expect("a valid signature");
    }
}

impl Signer for Soft {
    fn certificate(&self) -> anyhow::Result<Vec<u8>> {
        Ok(CERT.to_vec())
    }
    fn public(&self, _: Key) -> anyhow::Result<(Vec<u8>, u32)> {
        Ok((self.modulus(), 65537))
    }
    fn sign(&self, _: Key, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut sig = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut sig,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(sig)
    }
    fn grant(&self, policy: &[u8; 32]) -> anyhow::Result<()> {
        self.granted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*policy);
        Ok(())
    }
}

/// A PE32+ image of the sections (name, contents), laid out as a linker does.
pub fn image(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let (falign, salign) = (0x200usize, 0x1000usize);
    let mut out = vec![0u8; 0x400];
    let put = |out: &mut Vec<u8>, at: usize, v: &[u8]| out[at..at + v.len()].copy_from_slice(v);
    put(&mut out, 0, b"MZ");
    put(&mut out, 0x3c, &0x40u32.to_le_bytes());
    put(&mut out, 0x40, b"PE\0\0");
    put(&mut out, 0x44, &0x8664u16.to_le_bytes());
    put(&mut out, 0x46, &(sections.len() as u16).to_le_bytes());
    put(&mut out, 0x54, &240u16.to_le_bytes());
    let opt = 0x58;
    put(&mut out, opt, &0x20bu16.to_le_bytes());
    put(&mut out, opt + 32, &(salign as u32).to_le_bytes());
    put(&mut out, opt + 36, &(falign as u32).to_le_bytes());
    put(&mut out, opt + 60, &0x400u32.to_le_bytes());
    put(&mut out, opt + 108, &16u32.to_le_bytes());
    let (mut va, mut ptr) = (salign, 0x400usize);
    let mut data = Vec::new();
    for (i, (name, contents)) in sections.iter().enumerate() {
        let h = opt + 240 + i * 40;
        let raw = contents.len().div_ceil(falign) * falign;
        put(&mut out, h, name.as_bytes());
        put(&mut out, h + 8, &(contents.len() as u32).to_le_bytes());
        put(&mut out, h + 12, &(va as u32).to_le_bytes());
        put(&mut out, h + 16, &(raw as u32).to_le_bytes());
        put(&mut out, h + 20, &(ptr as u32).to_le_bytes());
        put(&mut out, h + 36, &0x4000_0040u32.to_le_bytes());
        data.extend_from_slice(contents);
        data.resize(data.len() + raw - contents.len(), 0);
        va += contents.len().div_ceil(salign) * salign;
        ptr += raw;
    }
    put(&mut out, opt + 56, &(va as u32).to_le_bytes());
    out.extend(data);
    out
}

/// A two-profile UKI over a stand-in sd-stub.
pub fn uki() -> Vec<u8> {
    image(&[
        (".text", &[0xc3; 700]),
        (".sbat", b"sbat,1\n"),
        (".reloc", &[0; 8]),
        (".osrel", b"ID=test\n"),
        (".cmdline", b"console=ttyS0"),
        (".linux", &[1; 3000]),
        (".initrd", &[2; 5000]),
        (".profile", b"ID=main"),
        (".profile", b"ID=reset"),
        (".cmdline", b"console=ttyS0 wipe"),
    ])
}
