//! Edge's TLS, in one place (ADR-0024 §2): Meridian's terms, as
//! `meridian_tls` states them for the platform.
//!
//! - **One provider:** aws-lc-rs, built as its FIPS 140-3 module unless the
//!   `fips` feature is off. `ring`, which has no ML-KEM, is banned by
//!   `cargo deny`.
//! - **TLS 1.3 only:** neither provider here carries a TLS 1.2 suite.
//! - **Hybrid ML-KEM:** [`provider`], for a link both of whose ends are
//!   Meridian's (a browser to the gateway, the gateway to core, the signer's
//!   own), offers and accepts `X25519MLKEM768` alone. [`foreign`], for a
//!   system Meridian does not run (the Kubernetes API, Talos's apid, an
//!   upstream the gateway proxies to), prefers it and falls back to ECDHE on
//!   P-384 or P-256.
//! - **Record protection:** AES-256-GCM with SHA-384 first; AES-128-GCM
//!   stays for QUIC's Initial packets; ChaCha20-Poly1305 is not FIPS approved.

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::{SupportedCipherSuite, SupportedProtocolVersion};

/// The one protocol version.
pub static VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

static SUITES: &[SupportedCipherSuite] = &[
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_AES_128_GCM_SHA256,
];

/// Meridian's links: hybrid ML-KEM alone.
pub static GROUPS: &[&dyn SupportedKxGroup] = &[kx_group::X25519MLKEM768];

/// A system Meridian does not run: hybrid where offered, else P-384 or P-256.
pub static FOREIGN_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::SECP384R1,
    kx_group::SECP256R1,
];

fn with_groups(kx_groups: &[&'static dyn SupportedKxGroup]) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: SUITES.to_vec(),
        kx_groups: kx_groups.to_vec(),
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// The provider for a link both of whose ends are Meridian's.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(with_groups(GROUPS))
}

/// The provider for a link to a system Meridian does not run.
pub fn foreign() -> Arc<CryptoProvider> {
    Arc::new(with_groups(FOREIGN_GROUPS))
}

/// Installs [`foreign`] as the process default, which a library that builds
/// its own config takes (the Kubernetes client, tonic). Call it first thing in
/// `main`; a second call changes nothing.
pub fn install() {
    let _ = Arc::unwrap_or_clone(foreign()).install_default();
}

/// A server config builder on `provider`, at TLS 1.3.
pub fn server(
    provider: Arc<CryptoProvider>,
) -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(VERSIONS)
        .expect("both providers carry TLS 1.3 suites")
}

/// A client config builder on `provider`, at TLS 1.3.
pub fn client(
    provider: Arc<CryptoProvider>,
) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(VERSIONS)
        .expect("both providers carry TLS 1.3 suites")
}

#[cfg(test)]
mod tests {
    #[test]
    fn neither_provider_carries_tls_1_2_and_meridian_links_are_hybrid_alone() {
        for p in [super::provider(), super::foreign()] {
            assert!(p.cipher_suites.iter().all(|s| s.tls13().is_some()));
            #[cfg(feature = "fips")]
            assert!(p.fips());
        }
        let names: Vec<_> = super::provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert_eq!(names, [rustls::NamedGroup::X25519MLKEM768]);
    }
}
