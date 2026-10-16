//! The unit's boot signing keys in its TPM, and the few TPM 2.0 commands
//! that use them.
//!
//! The layout, which whatever made the keys follows:
//! - [`SECURE_BOOT_KEY`] and [`PCR_KEY`]: persistent RSA signing keys, made
//!   in the TPM, whose auth value is a secret;
//! - [`SIGNING_AUTH`]: that secret, sealed under `TPM2_PolicyAuthorize` by
//!   the PCR key with [`POLICY_REF`] over a `TPM2_PolicyPCR` of PCR 11;
//! - [`CERTIFICATE`]: NV, the Secure Boot key's certificate (DER);
//! - [`GRANTS`]: NV, two [`GRANT`]-byte grants: a PCR 11 policy digest, then
//!   the PCR key's signature over it and [`POLICY_REF`]. Unused ones are zero.
//!
//! So the keys sign only while PCR 11 is at a value the PCR key granted: the
//! running OS of a UKI this unit signed.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, ensure};
use sha2::{Digest, Sha256};

use crate::{Key, measure};

pub const SECURE_BOOT_KEY: u32 = 0x8100_0101;
pub const PCR_KEY: u32 = 0x8100_0102;
pub const SIGNING_AUTH: u32 = 0x8100_0103;
pub const CERTIFICATE: u32 = 0x0180_0101;
pub const GRANTS: u32 = 0x0180_0102;
pub const POLICY_REF: &[u8] = b"boot-signing";
pub const GRANT: usize = 32 + 256;

const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const RS_PW: u32 = 0x4000_0009;
const RH_NULL: u32 = 0x4000_0007;
const ALG_SHA256: u16 = 0x000b;
const ALG_NULL: u16 = 0x0010;
const ALG_RSASSA: u16 = 0x0014;
const NV_CHUNK: usize = 512;

/// A command the TPM refused.
#[derive(Debug)]
pub struct Failed {
    pub cc: u32,
    pub rc: u32,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TPM command {:#x} failed: {:#x}", self.cc, self.rc)
    }
}

impl std::error::Error for Failed {}

/// A TPM 2.0 command stream: `/dev/tpmrm0`, or a simulator's socket.
pub struct Tpm<T> {
    io: T,
}

fn b2(v: &[u8]) -> Vec<u8> {
    [&(v.len() as u16).to_be_bytes()[..], v].concat()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "TPM response truncated");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn b2(&mut self) -> anyhow::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// A command's authorization: a password, or a policy session.
enum Auth<'a> {
    Password(&'a [u8]),
    Session(u32),
}

impl<T: Read + Write> Tpm<T> {
    pub fn new(io: T) -> Self {
        Self { io }
    }

    /// Runs a command: its response's handles and parameters.
    fn run(
        &mut self,
        cc: u32,
        handles: &[u32],
        auth: &[Auth],
        params: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut body = Vec::new();
        for h in handles {
            body.extend(h.to_be_bytes());
        }
        if !auth.is_empty() {
            let mut area = Vec::new();
            for a in auth {
                let (handle, hmac) = match a {
                    Auth::Password(p) => (RS_PW, *p),
                    Auth::Session(s) => (*s, &[][..]),
                };
                area.extend(handle.to_be_bytes());
                area.extend(b2(&[]));
                area.push(0x01); // continueSession
                area.extend(b2(hmac));
            }
            body.extend((area.len() as u32).to_be_bytes());
            body.extend(area);
        }
        body.extend(params);
        let tag = if auth.is_empty() {
            NO_SESSIONS
        } else {
            SESSIONS
        };
        let mut cmd = Vec::with_capacity(10 + body.len());
        cmd.extend(tag.to_be_bytes());
        cmd.extend(((10 + body.len()) as u32).to_be_bytes());
        cmd.extend(cc.to_be_bytes());
        cmd.extend(body);
        self.io.write_all(&cmd)?;
        self.io.flush()?;

        let mut header = [0u8; 10];
        self.io
            .read_exact(&mut header)
            .context("reading the TPM's response")?;
        let size = u32::from_be_bytes(header[2..6].try_into()?) as usize;
        let rc = u32::from_be_bytes(header[6..10].try_into()?);
        ensure!(size >= 10, "TPM response size {size}");
        let mut rest = vec![0u8; size - 10];
        self.io.read_exact(&mut rest)?;
        if rc != 0 {
            return Err(Failed { cc, rc }.into());
        }
        Ok(rest)
    }

    /// The parameters of a response to a command with sessions, after `handles` handles.
    fn params(rsp: &[u8], handles: usize) -> anyhow::Result<&[u8]> {
        let mut r = Reader(rsp);
        r.take(4 * handles)?;
        let n = r.u32()? as usize;
        r.take(n)
    }

    /// PCR 11's SHA-256 bank.
    pub fn pcr(&mut self) -> anyhow::Result<[u8; 32]> {
        let rsp = self.run(0x17e, &[], &[], &measure::selection())?;
        let mut r = Reader(&rsp);
        r.u32()?;
        r.take(measure::selection().len())?;
        ensure!(r.u32()? == 1, "PCR 11 has no SHA-256 bank");
        Ok(r.b2()?.try_into()?)
    }

    /// An RSA key's name, modulus and exponent.
    pub fn read_public(&mut self, handle: u32) -> anyhow::Result<(Vec<u8>, Vec<u8>, u32)> {
        let rsp = self.run(0x173, &[handle], &[], &[])?;
        let mut r = Reader(&rsp);
        let public = r.b2()?;
        let name = r.b2()?.to_vec();
        let mut p = Reader(public);
        ensure!(p.u16()? == 0x0001, "{handle:#x} is not an RSA key");
        p.u16()?;
        p.u32()?;
        p.b2()?;
        if p.u16()? != ALG_NULL {
            p.take(4)?;
        }
        if p.u16()? != ALG_NULL {
            p.take(2)?;
        }
        p.u16()?;
        let exponent = match p.u32()? {
            0 => 65537,
            e => e,
        };
        Ok((name, p.b2()?.to_vec(), exponent))
    }

    pub fn nv_defined(&mut self, index: u32) -> anyhow::Result<bool> {
        match self.run(0x169, &[index], &[], &[]) {
            Ok(_) => Ok(true),
            // TPM_RC_HANDLE, of the first handle
            Err(e) if e.downcast_ref::<Failed>().is_some_and(|f| f.rc == 0x18b) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn nv_read(&mut self, index: u32) -> anyhow::Result<Vec<u8>> {
        let rsp = self.run(0x169, &[index], &[], &[])?;
        let mut r = Reader(&rsp);
        let mut public = Reader(r.b2()?);
        public.take(4 + 2 + 4)?;
        public.b2()?;
        let size = public.u16()? as usize;
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let n = (size - out.len()).min(NV_CHUNK);
            let params = [(n as u16).to_be_bytes(), (out.len() as u16).to_be_bytes()].concat();
            let rsp = self.run(0x14e, &[index, index], &[Auth::Password(&[])], &params)?;
            out.extend(Reader(Self::params(&rsp, 0)?).b2()?);
        }
        Ok(out)
    }

    pub fn nv_write(&mut self, index: u32, data: &[u8]) -> anyhow::Result<()> {
        for (i, chunk) in data.chunks(NV_CHUNK).enumerate() {
            let params = [b2(chunk), ((i * NV_CHUNK) as u16).to_be_bytes().to_vec()].concat();
            self.run(0x137, &[index, index], &[Auth::Password(&[])], &params)?;
        }
        Ok(())
    }

    fn flush(&mut self, handle: u32) -> anyhow::Result<()> {
        self.run(0x165, &[], &[], &handle.to_be_bytes())?;
        Ok(())
    }

    /// Unseals `item` under PCR 11 now, by `grant` from the key at `signer`.
    pub fn unseal_granted(
        &mut self,
        item: u32,
        signer: u32,
        policy_ref: &[u8],
        grant: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (policy, signature) = grant.split_at(32);
        let (name, _, _) = self.read_public(signer)?;
        let a_hash = Sha256::digest([policy, policy_ref].concat());
        let sig = [
            &ALG_RSASSA.to_be_bytes()[..],
            &ALG_SHA256.to_be_bytes(),
            &b2(signature),
        ]
        .concat();
        let ticket = self.run(0x177, &[signer], &[], &[b2(&a_hash), sig].concat())?;

        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("{e}"))?;
        let start = [
            b2(&nonce),
            b2(&[]),
            vec![0x01], // policy session
            ALG_NULL.to_be_bytes().to_vec(),
            ALG_SHA256.to_be_bytes().to_vec(),
        ]
        .concat();
        let rsp = self.run(0x176, &[RH_NULL, RH_NULL], &[], &start)?;
        let session = Reader(&rsp).u32()?;
        let result = (|| {
            self.run(
                0x17f,
                &[session],
                &[],
                &[b2(&[]), measure::selection().to_vec()].concat(),
            )?;
            let authorize = [b2(policy), b2(policy_ref), b2(&name), ticket.clone()].concat();
            self.run(0x16a, &[session], &[], &authorize)?;
            let rsp = self.run(0x15e, &[item], &[Auth::Session(session)], &[])?;
            Ok(Reader(Self::params(&rsp, 0)?).b2()?.to_vec())
        })();
        let _ = self.flush(session);
        result
    }

    /// RSASSA-PKCS1-v1_5 over a SHA-256 digest.
    pub fn sign(&mut self, key: u32, auth: &[u8], digest: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        let params = [
            b2(digest),
            [ALG_RSASSA.to_be_bytes(), ALG_SHA256.to_be_bytes()].concat(),
            0x8024u16.to_be_bytes().to_vec(),
            RH_NULL.to_be_bytes().to_vec(),
            b2(&[]),
        ]
        .concat();
        let rsp = self.run(0x15d, &[key], &[Auth::Password(auth)], &params)?;
        let mut r = Reader(Self::params(&rsp, 0)?);
        ensure!(r.u16()? == ALG_RSASSA, "the TPM signed with another scheme");
        r.u16()?;
        Ok(r.b2()?.to_vec())
    }
}

/// The unit's boot signing keys, unlocked for the running OS.
pub struct TpmKeys<T> {
    tpm: Mutex<Tpm<T>>,
    auth: Vec<u8>,
    /// The running OS's grant, kept by every new one.
    running: Vec<u8>,
}

impl TpmKeys<File> {
    /// The keys, unlocked; `None` if the unit has no TPM or it holds no boot signing keys.
    pub fn open(device: &Path) -> anyhow::Result<Option<Self>> {
        let io = match File::options().read(true).write(true).open(device) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            r => r.with_context(|| format!("opening {}", device.display()))?,
        };
        let mut tpm = Tpm::new(io);
        if !tpm.nv_defined(CERTIFICATE)? {
            return Ok(None);
        }
        Self::unlock(tpm).map(Some)
    }
}

impl<T: Read + Write> TpmKeys<T> {
    /// Unseals the keys' auth with the grant of PCR 11 as it is now.
    pub fn unlock(mut tpm: Tpm<T>) -> anyhow::Result<Self> {
        let now = measure::policy_pcr(&tpm.pcr()?);
        let grants = tpm
            .nv_read(GRANTS)
            .context("reading the boot signing grants")?;
        let running = grants
            .chunks(GRANT)
            .find(|g| g.len() == GRANT && g[..32] == now)
            .context("this boot was not granted boot signing: it runs an OS the unit did not sign")?
            .to_vec();
        let auth = tpm
            .unseal_granted(SIGNING_AUTH, PCR_KEY, POLICY_REF, &running)
            .context("unsealing the boot signing keys")?;
        Ok(Self {
            tpm: Mutex::new(tpm),
            auth,
            running,
        })
    }

    fn tpm(&self) -> std::sync::MutexGuard<'_, Tpm<T>> {
        self.tpm.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T: Read + Write + Send> crate::Signer for TpmKeys<T> {
    fn certificate(&self) -> anyhow::Result<Vec<u8>> {
        self.tpm().nv_read(CERTIFICATE)
    }

    fn public(&self, key: Key) -> anyhow::Result<(Vec<u8>, u32)> {
        let (_, modulus, exponent) = self.tpm().read_public(handle(key))?;
        Ok((modulus, exponent))
    }

    fn sign(&self, key: Key, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.tpm()
            .sign(handle(key), &self.auth, &Sha256::digest(message).into())
    }

    fn grant(&self, policy: &[u8; 32]) -> anyhow::Result<()> {
        let sig = self.sign(Key::Pcr, &[&policy[..], POLICY_REF].concat())?;
        let grants = [&self.running[..], policy, &sig].concat();
        ensure!(grants.len() == 2 * GRANT, "a grant is {GRANT} bytes");
        self.tpm().nv_write(GRANTS, &grants)
    }
}

fn handle(key: Key) -> u32 {
    match key {
        Key::SecureBoot => SECURE_BOOT_KEY,
        Key::Pcr => PCR_KEY,
    }
}
