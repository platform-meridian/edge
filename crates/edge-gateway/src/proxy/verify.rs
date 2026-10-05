//! BackendTLSPolicy's `subjectAltNames`: the chain is verified as usual, the
//! name against those SANs instead of the hostname, which stays the SNI.

use crate::config::San;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

#[derive(Debug)]
pub struct SanVerifier {
    roots: Arc<RootCertStore>,
    sans: Vec<San>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl SanVerifier {
    pub fn new(roots: Arc<RootCertStore>, sans: Vec<San>) -> Self {
        Self {
            roots,
            sans,
            provider: crate::tls::provider(),
        }
    }

    fn named(&self, der: &[u8]) -> bool {
        let Ok((_, x)) = X509Certificate::from_der(der) else {
            return false;
        };
        let Ok(Some(san)) = x.subject_alternative_name() else {
            return false;
        };
        let names = &san.value.general_names;
        self.sans.iter().any(|want| {
            names.iter().any(|have| match (want, have) {
                (San::Hostname(w), GeneralName::DNSName(h)) => dns_matches(w, h),
                (San::Uri(w), GeneralName::URI(h)) => w == h,
                _ => false,
            })
        })
    }
}

/// Either side may be a `*.` wildcard over exactly one leftmost label.
fn dns_matches(want: &str, have: &str) -> bool {
    let (want, have) = (want.to_ascii_lowercase(), have.to_ascii_lowercase());
    let covers = |wild: &str, name: &str| {
        wild.strip_prefix("*.").is_some_and(|suffix| {
            name.split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && label != "*" && rest == suffix)
        })
    };
    want == have || covers(&want, &have) || covers(&have, &want)
}

impl ServerCertVerifier for SanVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        if self.named(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dns_san_matching() {
        for (want, have, ok) in [
            ("a.b", "A.B", true),
            ("*.b.c", "a.b.c", true),
            ("a.b.c", "*.b.c", true),
            ("*.b.c", "x.a.b.c", false),
            ("*.b.c", "b.c", false),
            ("*.b.c", "*.b.c", true),
            ("a.b", "a.c", false),
        ] {
            assert_eq!(super::dns_matches(want, have), ok, "{want} {have}");
        }
    }
}
