//! GEP-91: the Gateway's `spec.tls.frontend`, for the port this gateway binds.

use super::GatewayRef;
use super::convert::Verdict;
use super::schema::ReferenceGrant;
use super::trust::{RefError, Sources};
use crate::config::Route;
use crate::tls::{Frontend, Mode};
use kube::api::DynamicObject;
use serde_json::Value;

/// `problems` are what was dropped, for the log; `refs` is the listener's
/// `ResolvedRefs`, and whether no reference was usable (its `Accepted`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Derived {
    pub frontend: Option<Frontend>,
    pub problems: Vec<String>,
    pub refs: Option<(Verdict, bool)>,
}

pub(super) fn derive(
    gateway: Option<&DynamicObject>,
    gw: &GatewayRef,
    sources: &Sources,
    grants: &[ReferenceGrant],
    table: &[Route],
) -> Derived {
    let mut problems = Vec::new();
    let Some(tls) = gateway.map(|g| &g.data["spec"]["tls"]) else {
        return Derived::default();
    };
    if tls.is_null() {
        return Derived::default();
    }
    let validation = validation(gateway.expect("checked above"), gw);
    if validation.is_null() {
        return Derived::default();
    }
    let mode = match validation["mode"].as_str() {
        None | Some("AllowValidOnly") => Mode::AllowValidOnly,
        Some("AllowInsecureFallback") => Mode::AllowInsecureFallback,
        Some(other) => {
            problems.push(format!(
                "frontend validation mode {other} is unknown; AllowValidOnly applies"
            ));
            Mode::AllowValidOnly
        }
    };
    let mut ca_pem = String::new();
    let mut bad: Vec<(&'static str, String)> = Vec::new();
    let refs = validation["caCertificateRefs"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    for r in refs {
        match resolve(r, gw, sources, grants) {
            Ok(pem) => {
                ca_pem.push_str(&pem);
                ca_pem.push('\n');
            }
            Err(e) => {
                problems.push(format!("frontend caCertificateRef: {}", e.1));
                bad.push(e);
            }
        }
    }
    let severity = |reason: &str| match reason {
        "InvalidCACertificateKind" => 0,
        "RefNotPermitted" => 1,
        _ => 2,
    };
    let resolved = match bad.iter().min_by_key(|(r, _)| severity(r)) {
        None => Verdict {
            ok: true,
            reason: "ResolvedRefs",
            message: "all caCertificateRefs resolved".into(),
        },
        Some((reason, _)) => Verdict {
            ok: false,
            reason,
            message: bad
                .iter()
                .map(|(_, m)| m.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        },
    };
    if ca_pem.is_empty() {
        problems.push(match mode {
            Mode::AllowValidOnly => "no usable client CA: every handshake is refused".into(),
            Mode::AllowInsecureFallback => {
                "no usable client CA: no certificate is asked for".into()
            }
        });
    }
    let names = table
        .iter()
        .filter(|r| r.client_cert)
        .filter_map(|r| r.hostname.clone())
        .collect();
    Derived {
        refs: Some((resolved, ca_pem.is_empty())),
        frontend: Some(Frontend {
            mode,
            ca_pem,
            names,
        }),
        problems,
    }
}

/// The `perPort` entry for the bound port, or else the default.
pub(super) fn validation<'a>(gateway: &'a DynamicObject, gw: &GatewayRef) -> &'a Value {
    let frontend = &gateway.data["spec"]["tls"]["frontend"];
    let per_port = frontend["perPort"].as_array().and_then(|ports| {
        ports
            .iter()
            .find(|p| p["port"].as_u64() == Some(u64::from(gw.bound_port)))
    });
    match per_port {
        Some(p) => &p["tls"]["validation"],
        None => &frontend["default"]["validation"],
    }
}

fn resolve(
    r: &Value,
    gw: &GatewayRef,
    sources: &Sources,
    grants: &[ReferenceGrant],
) -> Result<String, (&'static str, String)> {
    let text = |k: &str| r[k].as_str().unwrap_or_default();
    let (group, kind, name) = (text("group"), text("kind"), text("name"));
    let ns = r["namespace"].as_str().unwrap_or(&gw.namespace);
    if group.is_empty()
        && ns != gw.namespace
        && !grants
            .iter()
            .any(|g| g.permits("Gateway", &gw.namespace, kind, ns, name))
    {
        return Err((
            "RefNotPermitted",
            format!("{kind} {ns}/{name} needs a ReferenceGrant in {ns}"),
        ));
    }
    sources.resolve(group, kind, ns, name).map_err(|e| match e {
        RefError::Kind(m) => ("InvalidCACertificateKind", m),
        RefError::Invalid(m) => ("InvalidCACertificateRef", m),
    })
}
