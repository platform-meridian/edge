//! The verified client certificate as Envoy's `X-Forwarded-Client-Cert`:
//! `Hash`, `Cert`, `Subject`, then each `URI` and `DNS` name. Gateway API names
//! no header for this; backends already read Envoy's.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate, X509Name};

pub const HEADER: &str = "x-forwarded-client-cert";

/// RFC 3986 unreserved stays literal, as Envoy's encoding leaves it.
const CERT_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// `None` for a leaf that does not parse, which rustls has already verified.
pub fn value(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    let hash: String = Sha256::digest(leaf_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pem = pem(leaf_der);
    let mut out = format!(
        "Hash={hash};Cert={};Subject=\"{}\"",
        utf8_percent_encode(&pem, CERT_ENCODE),
        rfc4514(cert.subject())
    );
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for kind in ["URI", "DNS"] {
            for n in &san.value.general_names {
                match (kind, n) {
                    ("URI", GeneralName::URI(u)) | ("DNS", GeneralName::DNSName(u)) => {
                        out.push_str(&format!(";{kind}={}", element(u)));
                    }
                    _ => {}
                }
            }
        }
    }
    Some(out)
}

fn pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Quoted when it holds a delimiter.
fn element(v: &str) -> String {
    if v.contains([',', ';', '=', '"']) {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        v.to_string()
    }
}

/// As OpenSSL's `XN_FLAG_RFC2253`, which nginx's `$ssl_client_s_dn` uses: the
/// last RDN first, short names, and bytes past ASCII escaped as `\XX`.
pub fn rfc4514(name: &X509Name) -> String {
    let rdns: Vec<String> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|atv| {
                    let oid = atv.attr_type().to_id_string();
                    let key = short_name(&oid).map_or(oid, str::to_string);
                    match decoded(atv.attr_value()) {
                        Some(v) => format!("{key}={}", escape(&v)),
                        None => format!("{key}=#{}", hex(atv.attr_value())),
                    }
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(",")
}

fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "emailAddress",
        _ => return None,
    })
}

fn decoded(v: &x509_parser::asn1_rs::Any) -> Option<String> {
    use x509_parser::asn1_rs::Tag;
    let data = v.data;
    match v.tag() {
        Tag::Utf8String
        | Tag::PrintableString
        | Tag::Ia5String
        | Tag::NumericString
        | Tag::VisibleString => String::from_utf8(data.to_vec()).ok(),
        // Latin-1, as OpenSSL reads it.
        Tag::TeletexString => Some(data.iter().map(|&b| char::from(b)).collect()),
        Tag::BmpString => {
            let units: Vec<u16> = data
                .chunks(2)
                .map(|c| Some(u16::from_be_bytes([c[0], *c.get(1)?])))
                .collect::<Option<_>>()?;
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

fn hex(v: &x509_parser::asn1_rs::Any) -> String {
    use x509_parser::asn1_rs::ToDer;
    v.to_der_vec()
        .unwrap_or_default()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

fn escape(v: &str) -> String {
    let bytes = v.as_bytes();
    let mut out = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        let edge_space = b == b' ' && (i == 0 || i == bytes.len() - 1);
        match b {
            b',' | b'+' | b'"' | b'\\' | b'<' | b'>' | b';' => {
                out.push('\\');
                out.push(b as char);
            }
            b'#' if i == 0 => out.push_str("\\#"),
            _ if edge_space => out.push_str("\\ "),
            0..0x20 | 0x7f.. => out.push_str(&format!("\\{b:02X}")),
            _ => out.push(b as char),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, DnValue, KeyPair, SanType};

    fn cert(dn: &[(DnType, &str)], sans: Vec<SanType>) -> Vec<u8> {
        let mut p = CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        for (t, v) in dn {
            p.distinguished_name
                .push(t.clone(), DnValue::Utf8String(v.to_string()));
        }
        p.subject_alt_names = sans;
        p.self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn envoy_format() {
        let der = cert(
            &[
                (DnType::CountryName, "US"),
                (DnType::OrganizationName, "U.S. Government"),
                (DnType::OrganizationalUnitName, "DoD"),
                (DnType::CommonName, "DOE.JOHN.Q.1234567890"),
            ],
            vec![
                SanType::DnsName("a.example".try_into().unwrap()),
                SanType::URI("spiffe://x/ns/a".try_into().unwrap()),
                SanType::DnsName("b.example".try_into().unwrap()),
                SanType::URI("urn:a=b".try_into().unwrap()),
            ],
        );
        let v = value(&der).unwrap();
        let hash: String = Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let (head, tail) = v.split_once(";Subject=").unwrap();
        let cert = head.strip_prefix(&format!("Hash={hash};Cert=")).expect(&v);
        assert!(
            cert.starts_with("-----BEGIN%20CERTIFICATE-----%0A"),
            "{cert}"
        );
        assert!(!cert.contains([',', ';', '=', '"', '\n']), "{cert}");
        let decoded = percent_encoding::percent_decode_str(cert)
            .decode_utf8()
            .unwrap();
        let back: Vec<u8> = rustls_pki_types::pem::PemObject::from_pem_slice(decoded.as_bytes())
            .map(|c: rustls_pki_types::CertificateDer| c.to_vec())
            .unwrap();
        assert_eq!(back, der);
        assert_eq!(
            tail,
            "\"CN=DOE.JOHN.Q.1234567890,OU=DoD,O=U.S. Government,C=US\";\
             URI=spiffe://x/ns/a;URI=\"urn:a=b\";DNS=a.example;DNS=b.example"
        );
    }

    #[test]
    fn subject_escaped_as_rfc4514() {
        let der = cert(
            &[
                (DnType::CommonName, "#Doe, \"J\" <x>; a+b\\ "),
                (DnType::OrganizationName, "Société"),
            ],
            vec![],
        );
        let (_, c) = X509Certificate::from_der(&der).unwrap();
        // rcgen orders the subject as pushed; the last comes first.
        assert_eq!(
            rfc4514(c.subject()),
            r#"O=Soci\C3\A9t\C3\A9,CN=\#Doe\, \"J\" \<x\>\; a\+b\\\ "#
        );
        assert_eq!(value(&der).unwrap().matches(";DNS=").count(), 0);
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(value(b"not a certificate"), None);
    }
}
