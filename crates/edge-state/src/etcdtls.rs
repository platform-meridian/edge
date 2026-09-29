use std::path::Path;

use anyhow::Context;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

pub fn build(
    cert_file: Option<&str>,
    key_file: Option<&str>,
    trusted_ca_file: Option<&str>,
    client_cert_auth: bool,
) -> anyhow::Result<Option<ServerTlsConfig>> {
    match (cert_file, key_file) {
        (None, None) => {
            if trusted_ca_file.is_some() || client_cert_auth {
                anyhow::bail!(
                    "client authentication configured without --cert-file and --key-file"
                );
            }
            Ok(None)
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("--cert-file and --key-file must be given together")
        }
        (Some(c), Some(k)) => {
            let cert = read(c)?;
            let key = read(k)?;
            let mut cfg = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
            if client_cert_auth {
                let ca =
                    trusted_ca_file.context("--client-cert-auth=true needs --trusted-ca-file")?;
                cfg = cfg.client_ca_root(Certificate::from_pem(read(ca)?));
            }
            Ok(Some(cfg))
        }
    }
}

fn read(p: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(Path::new(p)).with_context(|| format!("read {p}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_material_is_plaintext() {
        assert!(build(None, None, None, false).unwrap().is_none());
    }

    #[test]
    fn partial_material_is_refused() {
        for (cert, key, ca, auth) in [
            (Some("/x.crt"), None, None, false),
            (None, Some("/x.key"), None, false),
            (None, None, None, true),
            (None, None, Some("/ca.crt"), false),
        ] {
            assert!(
                build(cert, key, ca, auth).is_err(),
                "{cert:?} {key:?} {ca:?} {auth}"
            );
        }
    }

    #[test]
    fn missing_file_is_named() {
        let e = build(
            Some("/nonexistent.crt"),
            Some("/nonexistent.key"),
            None,
            false,
        );
        assert!(format!("{:#}", e.unwrap_err()).contains("nonexistent.crt"));
    }

    #[test]
    fn client_auth_needs_ca() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("s.crt");
        let k = d.path().join("s.key");
        std::fs::write(&c, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        std::fs::write(&k, b"-----BEGIN PRIVATE KEY-----\n").unwrap();
        let (c, k) = (c.to_str().unwrap(), k.to_str().unwrap());
        assert!(build(Some(c), Some(k), None, false).unwrap().is_some());
        let e = build(Some(c), Some(k), None, true);
        assert!(format!("{:#}", e.unwrap_err()).contains("trusted-ca-file"));
    }
}
