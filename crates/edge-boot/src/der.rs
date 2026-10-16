//! The little DER that Authenticode and an RSA public key need.

use anyhow::{Context, bail};

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match value.len() {
        n @ 0..0x80 => out.push(n as u8),
        n => {
            let be = n.to_be_bytes();
            let skip = be.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | (be.len() - skip) as u8);
            out.extend_from_slice(&be[skip..]);
        }
    }
    out.extend_from_slice(value);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A SET OF, its members in DER order.
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    tlv(0x31, &sorted.concat())
}

pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut chunk = vec![(a & 0x7f) as u8];
        let mut rest = a >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        body.extend(chunk);
    }
    tlv(0x06, &body)
}

/// A non-negative INTEGER from big-endian bytes.
pub fn uint(be: &[u8]) -> Vec<u8> {
    let be = &be[be
        .iter()
        .take_while(|b| **b == 0)
        .count()
        .min(be.len().saturating_sub(1))..];
    let mut v = Vec::with_capacity(be.len() + 1);
    if be.first().is_some_and(|b| b & 0x80 != 0) {
        v.push(0);
    }
    v.extend_from_slice(be);
    tlv(0x02, &v)
}

pub const NULL: &[u8] = &[0x05, 0x00];

/// The next TLV in `b`: (tag, the whole TLV, its value).
pub fn next(b: &[u8]) -> anyhow::Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first().context("DER ended")?;
    let (&first, rest) = rest.split_first().context("DER ended")?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            bail!("bad DER length");
        }
        let len = rest[..n].iter().fold(0usize, |a, b| a << 8 | *b as usize);
        (len, &rest[n..])
    };
    let header = b.len() - rest.len();
    if rest.len() < len {
        bail!("DER value past its end");
    }
    Ok((tag, &b[..header + len], &rest[..len]))
}

/// A certificate's issuer and serial number, each as its TLV.
pub fn issuer_and_serial(cert: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (_, _, cert) = next(cert)?;
    let (_, _, mut tbs) = next(cert)?;
    let (tag, _, _) = next(tbs)?;
    if tag == 0xa0 {
        tbs = &tbs[next(tbs)?.1.len()..];
    }
    let (_, serial, _) = next(tbs)?;
    tbs = &tbs[serial.len()..];
    let (_, alg, _) = next(tbs)?;
    tbs = &tbs[alg.len()..];
    let (_, issuer, _) = next(tbs)?;
    Ok((issuer.to_vec(), serial.to_vec()))
}

/// An RSA public key as PKCS#1 `RSAPublicKey`.
pub fn rsa_pkcs1(modulus: &[u8], exponent: u32) -> Vec<u8> {
    seq(&[&uint(modulus), &uint(&exponent.to_be_bytes())])
}

/// An RSA public key as X.509 `SubjectPublicKeyInfo`.
pub fn rsa_spki(modulus: &[u8], exponent: u32) -> Vec<u8> {
    let bits = [&[0u8][..], &rsa_pkcs1(modulus, exponent)].concat();
    seq(&[&seq(&[&oid(RSA_ENCRYPTION), NULL]), &tlv(0x03, &bits)])
}

pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
pub const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lengths_oids_and_integers() {
        assert_eq!(tlv(4, &[0; 3]), [4, 3, 0, 0, 0]);
        assert_eq!(&tlv(4, &[0; 300])[..4], [4, 0x82, 1, 44]);
        assert_eq!(oid(SHA256), hex::decode("0609608648016503040201").unwrap());
        assert_eq!(uint(&[0, 0, 0x80]), [2, 2, 0, 0x80]);
        assert_eq!(uint(&[0, 0]), [2, 1, 0]);
        let long = tlv(0x30, &[7; 200]);
        let (tag, whole, value) = next(&long).unwrap();
        assert_eq!((tag, whole.len(), value.len()), (0x30, 203, 200));
    }
}
