//! The certificates.k8s.io/v1 kinds k8s-openapi does not carry yet: only the
//! fields the signer reads or writes.

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta, Time};
use k8s_openapi::{ByteString, NamespaceResourceScope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PodCertificateRequest {
    pub metadata: ObjectMeta,
    pub spec: Spec,
    #[serde(default)]
    pub status: Status,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub signer_name: String,
    #[serde(default)]
    pub pod_name: String,
    #[serde(default, rename = "podUID")]
    pub pod_uid: String,
    #[serde(default)]
    pub node_name: String,
    pub max_expiration_seconds: Option<i32>,
    #[serde(rename = "stubPKCS10Request")]
    pub stub_pkcs10_request: ByteString,
    #[serde(default)]
    pub unverified_user_annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub begin_refresh_at: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<Time>,
}

impl PodCertificateRequest {
    pub fn is_settled(&self) -> bool {
        self.status.conditions.iter().any(|c| {
            matches!(c.type_.as_str(), "Issued" | "Denied" | "Failed") && c.status == "True"
        })
    }
}

impl k8s_openapi::Resource for PodCertificateRequest {
    const API_VERSION: &'static str = "certificates.k8s.io/v1";
    const GROUP: &'static str = "certificates.k8s.io";
    const KIND: &'static str = "PodCertificateRequest";
    const VERSION: &'static str = "v1";
    const URL_PATH_SEGMENT: &'static str = "podcertificaterequests";
    type Scope = NamespaceResourceScope;
}

impl k8s_openapi::Metadata for PodCertificateRequest {
    type Ty = ObjectMeta;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apiserver_request() {
        let pending: PodCertificateRequest = serde_json::from_value(serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "PodCertificateRequest",
            "metadata": { "name": "edge-gateway-abc-1", "namespace": "edge" },
            "spec": {
                "signerName": "edge.meridian/node",
                "podName": "edge-gateway-abc",
                "podUID": "u", "serviceAccountName": "edge-gateway", "serviceAccountUID": "s",
                "nodeName": "n", "nodeUID": "nu",
                "maxExpirationSeconds": 864000,
                "stubPKCS10Request": "AQID",
                "unverifiedUserAnnotations": { "edge.meridian/dns-names": "example.lan" }
            }
        }))
        .unwrap();
        assert_eq!(pending.spec.pod_uid, "u");
        assert_eq!(pending.spec.node_name, "n");
        assert_eq!(pending.spec.stub_pkcs10_request.0, [1, 2, 3]);
        assert_eq!(pending.spec.max_expiration_seconds, Some(864000));
        assert_eq!(pending.spec.unverified_user_annotations.len(), 1);
        assert!(!pending.is_settled());

        for (kind, status, settled) in [
            ("Issued", "True", true),
            ("Denied", "True", true),
            ("Failed", "True", true),
            ("Issued", "False", false),
        ] {
            let mut r = pending.clone();
            r.status = serde_json::from_value(serde_json::json!({ "conditions": [{
                "type": kind, "status": status, "reason": "R", "message": "",
                "lastTransitionTime": "2026-09-28T00:00:00Z"
            }]}))
            .unwrap();
            assert_eq!(r.is_settled(), settled, "{kind}={status}");
        }
    }
}
