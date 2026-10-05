//! The Gateway's own status and its listeners', GEP-91's conditions among them.

use super::GATEWAY_GROUP;
use super::GatewayRef;
use super::convert::{Outcome, Verdict};
use super::frontend::Derived;
use super::schema::Listener;
use kube::api::DynamicObject;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ListenerStatus {
    pub name: String,
    pub supported_kinds: Value,
    pub attached: usize,
    pub conditions: Vec<(&'static str, Verdict)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GatewayStatus {
    pub conditions: Vec<(&'static str, Verdict)>,
    pub listeners: Vec<ListenerStatus>,
}

fn verdict(ok: bool, reason: &'static str, message: impl Into<String>) -> Verdict {
    Verdict {
        ok,
        reason,
        message: message.into(),
    }
}

/// The listener comes from the config file, so Programmed means some declared
/// port is the bound one. Frontend validation is evaluated for that port, so
/// its references are reported on the HTTPS listeners there.
pub(super) fn derive(
    gateway: &DynamicObject,
    gw: &GatewayRef,
    outcomes: &[(DynamicObject, Outcome)],
    frontend: &Derived,
    client_cert: Verdict,
) -> GatewayStatus {
    let listeners = Listener::all_of(gateway);
    let declared: Vec<u16> = listeners.iter().filter_map(Listener::port).collect();
    let programmed = if declared.contains(&gw.bound_port) {
        verdict(true, "Programmed", "listener bound")
    } else {
        verdict(
            false,
            "Invalid",
            format!(
                "serving :{}, which no listener declares (declared: {declared:?}); \
                 the listener is set in edge-gateway's config, not here",
                gw.bound_port
            ),
        )
    };
    let listeners = listeners
        .iter()
        .map(|l| {
            let bound = l.port() == Some(gw.bound_port);
            let validated = frontend.refs.as_ref().filter(|_| bound && l.is_https());
            let accepted = match validated {
                Some((_, true)) => verdict(
                    false,
                    "NoValidCACertificate",
                    "no frontend caCertificateRef is usable",
                ),
                _ => verdict(true, "Accepted", "listener accepted"),
            };
            let resolved = match validated {
                Some((v, _)) if !v.ok => v.clone(),
                _ => verdict(true, "ResolvedRefs", "all references resolved"),
            };
            let programmed = if bound {
                verdict(true, "Programmed", "listener bound")
            } else {
                verdict(
                    false,
                    "Invalid",
                    format!("edge-gateway serves :{}", gw.bound_port),
                )
            };
            ListenerStatus {
                name: l.name().to_string(),
                supported_kinds: if l.admits_httproute() {
                    json!([{ "group": GATEWAY_GROUP, "kind": "HTTPRoute" }])
                } else {
                    json!([])
                },
                attached: outcomes
                    .iter()
                    .filter(|(_, o)| o.listeners.contains(l.name()))
                    .count(),
                conditions: vec![
                    ("Accepted", accepted),
                    ("Programmed", programmed),
                    ("ResolvedRefs", resolved),
                ],
            }
        })
        .collect();
    GatewayStatus {
        conditions: vec![
            (
                "Accepted",
                verdict(true, "Accepted", "claimed by edge-gateway"),
            ),
            ("Programmed", programmed),
            ("ResolvedRefs", client_cert),
        ],
        listeners,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::convert::Verdict;

    fn gateway(listeners: Value) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": { "name": "edge", "namespace": "edge" },
            "spec": { "listeners": listeners },
        }))
        .unwrap()
    }

    fn gw(port: u16) -> GatewayRef {
        GatewayRef {
            name: "edge".into(),
            namespace: "edge".into(),
            bound_port: port,
        }
    }

    fn reasons(c: &[(&'static str, Verdict)]) -> Vec<(&'static str, bool, &'static str)> {
        c.iter().map(|(t, v)| (*t, v.ok, v.reason)).collect()
    }

    #[test]
    fn programmed_needs_bound_port() {
        let g = gateway(
            json!([{ "name": "a", "port": 80 }, { "name": "b", "port": 443, "protocol": "HTTPS" }]),
        );
        let ok = verdict(true, "ResolvedRefs", "");
        let s = derive(&g, &gw(443), &[], &Derived::default(), ok.clone());
        assert_eq!(
            reasons(&s.conditions),
            [
                ("Accepted", true, "Accepted"),
                ("Programmed", true, "Programmed"),
                ("ResolvedRefs", true, "ResolvedRefs")
            ]
        );
        assert_eq!(
            reasons(&s.listeners[0].conditions)[1],
            ("Programmed", false, "Invalid")
        );
        assert_eq!(
            reasons(&s.listeners[1].conditions)[1],
            ("Programmed", true, "Programmed")
        );
        let s = derive(&g, &gw(8443), &[], &Derived::default(), ok);
        assert_eq!(reasons(&s.conditions)[1], ("Programmed", false, "Invalid"));
    }

    /// GEP-91: a frontend reference that does not resolve is the HTTPS
    /// listeners' `ResolvedRefs`; none usable, their `Accepted`.
    #[test]
    fn frontend_refs_reported_on_https_listeners() {
        let g = gateway(json!([
            { "name": "https", "port": 443, "protocol": "HTTPS" },
            { "name": "http", "port": 443, "protocol": "HTTP" },
        ]));
        let bad = verdict(
            false,
            "InvalidCACertificateRef",
            "ConfigMap operators: does not exist",
        );
        let ok = verdict(true, "ResolvedRefs", "");
        for (refs, https) in [
            (
                Some((bad.clone(), true)),
                [
                    ("Accepted", false, "NoValidCACertificate"),
                    ("Programmed", true, "Programmed"),
                    ("ResolvedRefs", false, "InvalidCACertificateRef"),
                ],
            ),
            (
                Some((bad.clone(), false)),
                [
                    ("Accepted", true, "Accepted"),
                    ("Programmed", true, "Programmed"),
                    ("ResolvedRefs", false, "InvalidCACertificateRef"),
                ],
            ),
            (
                Some((ok.clone(), false)),
                [
                    ("Accepted", true, "Accepted"),
                    ("Programmed", true, "Programmed"),
                    ("ResolvedRefs", true, "ResolvedRefs"),
                ],
            ),
            (
                None,
                [
                    ("Accepted", true, "Accepted"),
                    ("Programmed", true, "Programmed"),
                    ("ResolvedRefs", true, "ResolvedRefs"),
                ],
            ),
        ] {
            let d = Derived {
                refs: refs.clone(),
                ..Derived::default()
            };
            let s = derive(&g, &gw(443), &[], &d, ok.clone());
            assert_eq!(reasons(&s.listeners[0].conditions), https, "{refs:?}");
            assert!(
                s.listeners[1].conditions.iter().all(|(_, v)| v.ok),
                "not HTTPS"
            );
        }
    }
}
