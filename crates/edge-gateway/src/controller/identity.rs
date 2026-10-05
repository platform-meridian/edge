//! What the gateway presents to TLS backends: the Secret
//! `spec.tls.backend.clientCertificateRef` names, or else its pod certificate.

use super::GatewayRef;
use super::convert::Verdict;
use super::schema::ReferenceGrant;
use super::trust::{RefKind, Refs};
use base64::Engine;
use kube::api::DynamicObject;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl rustls::client::ResolvesClientCert for Fixed {
    fn resolve(
        &self,
        _root_hints: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0.key.choose_scheme(schemes).map(|_| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

pub(super) type Resolver = Option<Arc<dyn rustls::client::ResolvesClientCert>>;

/// The identity, its fingerprint, and the Gateway's `ResolvedRefs`. A bad
/// reference presents nothing: never an identity other than the one named.
pub(super) fn backend_identity(
    gateway: Option<&DynamicObject>,
    gw: &GatewayRef,
    refs: &Refs,
    grants: &[ReferenceGrant],
    pod: &Resolver,
) -> (Resolver, String, Verdict) {
    let ok = Verdict {
        ok: true,
        reason: "ResolvedRefs",
        message: "all references resolved".into(),
    };
    let r = gateway.map(|g| &g.data["spec"]["tls"]["backend"]["clientCertificateRef"]);
    let Some(r) = r.filter(|r| !r.is_null()) else {
        return (pod.clone(), "pod".into(), ok);
    };
    match secret_key(r, gw, refs, grants) {
        Ok((key, fingerprint)) => (Some(Arc::new(Fixed(key))), fingerprint, ok),
        Err((reason, message)) => (
            None,
            "none".into(),
            Verdict {
                ok: false,
                reason,
                message: format!("tls.backend.clientCertificateRef: {message}"),
            },
        ),
    }
}

fn secret_key(
    r: &serde_json::Value,
    gw: &GatewayRef,
    refs: &Refs,
    grants: &[ReferenceGrant],
) -> Result<(Arc<CertifiedKey>, String), (&'static str, String)> {
    let invalid = |m: String| ("InvalidClientCertificateRef", m);
    let group = r["group"].as_str().unwrap_or_default();
    let kind = r["kind"].as_str().unwrap_or("Secret");
    let name = r["name"].as_str().unwrap_or_default();
    let ns = r["namespace"].as_str().unwrap_or(&gw.namespace);
    if !group.is_empty() || kind != "Secret" {
        return Err(invalid(format!(
            "{name} is a {group}/{kind}; only Secret is supported"
        )));
    }
    if ns != gw.namespace
        && !grants
            .iter()
            .any(|g| g.permits("Gateway", &gw.namespace, "Secret", ns, name))
    {
        return Err((
            "RefNotPermitted",
            format!("Secret {ns}/{name} needs a ReferenceGrant in {ns}"),
        ));
    }
    let state = refs.get(&(RefKind::Secret, (ns.to_string(), name.to_string())));
    let secret = match state {
        Some(s) if s.listed == Some(false) => {
            return Err(invalid(format!("Secret {ns}/{name} cannot be listed")));
        }
        Some(s) => s.object.as_ref(),
        None => None,
    }
    .ok_or_else(|| invalid(format!("Secret {ns}/{name} does not exist")))?;
    let field = |k: &str| {
        secret.data["data"][k]
            .as_str()
            .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
            .ok_or_else(|| invalid(format!("Secret {ns}/{name} has no {k}")))
    };
    let (crt, key) = (field("tls.crt")?, field("tls.key")?);
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&crt)
        .collect::<Result<_, _>>()
        .map_err(|e| invalid(format!("Secret {ns}/{name}: tls.crt: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&key)
        .map_err(|e| invalid(format!("Secret {ns}/{name}: tls.key: {e}")))?;
    let leaf = chain.first().map(|c| c.to_vec()).unwrap_or_default();
    let certified = CertifiedKey::from_der(chain, key, &crate::tls::provider())
        .map_err(|e| invalid(format!("Secret {ns}/{name}: {e}")))?;
    let fingerprint = {
        use sha2::Digest;
        let h = sha2::Sha256::digest(&leaf);
        format!(
            "secret:{}",
            h.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    Ok((Arc::new(certified), fingerprint))
}
