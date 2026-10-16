//! Authenticode: the PKCS#7 SignedData UEFI firmware checks an image's signature with.

use sha2::{Digest, Sha256};

use crate::der::{self, NULL, oid, seq, set, tlv};

const SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
const CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
const MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
const SPC_INDIRECT_DATA: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 4];
const SPC_PE_IMAGE_DATA: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 15];
const SPC_SP_OPUS_INFO: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 12];

fn attribute(kind: &[u64], value: &[u8]) -> Vec<u8> {
    seq(&[&oid(kind), &set(&[value])])
}

/// The SignedData over an image's Authenticode `digest`, by `cert`'s key through `sign`
/// (RSASSA-PKCS1-v1_5 SHA-256 over a message).
pub fn signed_data(
    digest: &[u8; 32],
    cert: &[u8],
    sign: impl FnOnce(&[u8]) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let sha256 = seq(&[&oid(der::SHA256), NULL]);
    // SpcPeImageData: no flags, and the file link every signer writes.
    let obsolete: Vec<u8> = "<<<Obsolete>>>"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    let image_data = seq(&[
        &tlv(0x03, &[0]),
        &tlv(0xa0, &tlv(0xa2, &tlv(0x80, &obsolete))),
    ]);
    let indirect = seq(&[
        &seq(&[&oid(SPC_PE_IMAGE_DATA), &image_data]),
        &seq(&[&sha256, &tlv(0x04, digest)]),
    ]);
    // The message digest covers the content's value, not its tag and length.
    let (_, _, indirect_value) = der::next(&indirect)?;
    let attrs = [
        attribute(CONTENT_TYPE, &oid(SPC_INDIRECT_DATA)),
        attribute(SPC_SP_OPUS_INFO, &seq(&[])),
        attribute(MESSAGE_DIGEST, &tlv(0x04, &Sha256::digest(indirect_value))),
    ];
    let attrs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    let signed_attrs = set(&attrs);
    let signature = sign(&signed_attrs)?;
    let (issuer, serial) = der::issuer_and_serial(cert)?;
    let signer_info = seq(&[
        &der::uint(&[1]),
        &seq(&[&issuer, &serial]),
        &sha256,
        &[&[0xa0][..], &signed_attrs[1..]].concat(),
        &seq(&[&oid(der::RSA_ENCRYPTION), NULL]),
        &tlv(0x04, &signature),
    ]);
    let signed = seq(&[
        &der::uint(&[1]),
        &set(&[&sha256]),
        &seq(&[&oid(SPC_INDIRECT_DATA), &tlv(0xa0, &indirect)]),
        &tlv(0xa0, cert),
        &set(&[&signer_info]),
    ]);
    Ok(seq(&[&oid(SIGNED_DATA), &tlv(0xa0, &signed)]))
}
