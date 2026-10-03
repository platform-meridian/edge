//! Approves the kubelet's serving-certificate requests, which
//! kube-controller-manager then signs. Only a request that is exactly a
//! kubelet's own is approved, and none is denied: the rest are left to another
//! approver or a person.

use std::collections::BTreeMap;
use std::net::IpAddr;

use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use k8s_openapi::api::core::v1::Node;
use kube::ResourceExt;
use kube::runtime::watcher::Event;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

pub const SIGNER: &str = "kubernetes.io/kubelet-serving";
const NODE_USER: &str = "system:node:";
const NODES_GROUP: &str = "system:nodes";
const USAGES: [&str; 3] = ["digital signature", "key encipherment", "server auth"];

/// The node a request comes from, when it is shaped as that kubelet's own.
pub fn requesting_node(csr: &CertificateSigningRequest) -> Result<String, String> {
    let spec = &csr.spec;
    let node = spec
        .username
        .as_deref()
        .and_then(|u| u.strip_prefix(NODE_USER))
        .filter(|n| !n.is_empty())
        .ok_or("not requested by a node")?;
    if !spec.groups.iter().flatten().any(|g| g == NODES_GROUP) {
        return Err(format!("requester not in {NODES_GROUP}"));
    }
    let usages = spec.usages.as_deref().unwrap_or_default();
    if !usages.iter().any(|u| u == "server auth")
        || usages.iter().any(|u| !USAGES.contains(&u.as_str()))
    {
        return Err(format!("usages {usages:?}"));
    }
    let request = Request::parse(&spec.request.0)?;
    if request.common_names != [format!("{NODE_USER}{node}")]
        || request.organizations != [NODES_GROUP]
        || request.other_attributes
    {
        return Err("subject is not the node's".into());
    }
    Ok(node.into())
}

/// Every name the request asks for must be one the Node reports.
pub fn check_names(csr: &CertificateSigningRequest, node: &Node) -> Result<(), String> {
    let request = Request::parse(&csr.spec.request.0)?;
    if request.dns.is_empty() && request.ips.is_empty() {
        return Err("no DNS name or IP address".into());
    }
    let reported: Vec<&str> = node
        .status
        .iter()
        .flat_map(|s| s.addresses.iter().flatten())
        .map(|a| a.address.as_str())
        .collect();
    let is_reported_ip = |ip: &IpAddr| reported.iter().any(|a| a.parse() == Ok(*ip));
    if let Some(d) = request.dns.iter().find(|d| !reported.contains(&d.as_str())) {
        return Err(format!("{d} is not among the Node's addresses"));
    }
    if let Some(ip) = request.ips.iter().find(|ip| !is_reported_ip(ip)) {
        return Err(format!("{ip} is not among the Node's addresses"));
    }
    Ok(())
}

struct Request {
    common_names: Vec<String>,
    organizations: Vec<String>,
    other_attributes: bool,
    dns: Vec<String>,
    ips: Vec<IpAddr>,
}

impl Request {
    fn parse(pem: &[u8]) -> Result<Self, String> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem).map_err(|_| "not PEM")?;
        if pem.label != "CERTIFICATE REQUEST" {
            return Err("not a certificate request".into());
        }
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
                .map_err(|_| "unparsable certificate request")?;
        let subject = &csr.certification_request_info.subject;
        let strings = |it: &mut dyn Iterator<Item = &x509_parser::x509::AttributeTypeAndValue>| {
            it.map(|a| a.as_str().map(str::to_string))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "unreadable subject")
        };
        let common_names = strings(&mut subject.iter_common_name())?;
        let organizations = strings(&mut subject.iter_organization())?;
        let other_attributes =
            subject.iter_attributes().count() != common_names.len() + organizations.len();
        let (mut dns, mut ips) = (Vec::new(), Vec::new());
        for ext in csr.requested_extensions().into_iter().flatten() {
            let ParsedExtension::SubjectAlternativeName(san) = ext else {
                continue;
            };
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(d) => dns.push(d.to_string()),
                    GeneralName::IPAddress(b) => ips.push(match *b {
                        [a, b, c, d] => IpAddr::from([*a, *b, *c, *d]),
                        b => IpAddr::from(
                            <[u8; 16]>::try_from(b).map_err(|_| "malformed IP address")?,
                        ),
                    }),
                    other => return Err(format!("unexpected name {other}")),
                }
            }
        }
        Ok(Self {
            common_names,
            organizations,
            other_attributes,
            dns,
            ips,
        })
    }
}

fn is_open(csr: &CertificateSigningRequest) -> bool {
    csr.spec.signer_name == SIGNER
        && csr.status.as_ref().is_none_or(|s| {
            s.certificate.is_none() && s.conditions.as_ref().is_none_or(Vec::is_empty)
        })
}

/// Requests not yet answered, with the last reason each was passed over, so a
/// reason is logged once.
#[derive(Default)]
pub struct Pending(pub BTreeMap<String, (CertificateSigningRequest, Option<String>)>);

impl Pending {
    pub fn apply(&mut self, ev: Event<CertificateSigningRequest>) {
        match ev {
            Event::Init => self.0.clear(),
            Event::InitApply(c) | Event::Apply(c) => {
                let name = c.name_any();
                if is_open(&c) {
                    let reason = self.0.remove(&name).and_then(|(_, r)| r);
                    self.0.insert(name, (c, reason));
                } else {
                    self.0.remove(&name);
                }
            }
            Event::Delete(c) => {
                self.0.remove(&c.name_any());
            }
            Event::InitDone => {}
        }
    }

    pub fn passed_over(&mut self, name: &str, reason: String) {
        if let Some((_, last)) = self.0.get_mut(name)
            && last.as_ref() != Some(&reason)
        {
            tracing::warn!(
                csr = name,
                reason,
                "kubelet serving certificate not approved"
            );
            *last = Some(reason);
        }
    }
}

pub fn approval(now: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time) -> serde_json::Value {
    serde_json::json!({ "status": { "conditions": [{
        "type": "Approved",
        "status": "True",
        "reason": "KubeletServing",
        "message": "the node's own names, approved by edge-signer",
        "lastUpdateTime": now,
    }]}})
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k8s_openapi::api::certificates::v1::{
        CertificateSigningRequestCondition, CertificateSigningRequestSpec,
        CertificateSigningRequestStatus,
    };
    use k8s_openapi::api::core::v1::{NodeAddress, NodeStatus};
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    pub fn pem(subject: &[(DnType, &str)], sans: Vec<SanType>) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        for (t, v) in subject {
            p.distinguished_name.push(t.clone(), *v);
        }
        p.subject_alt_names = sans;
        p.serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap()
            .into_bytes()
    }

    fn own_sans() -> Vec<SanType> {
        vec![
            SanType::DnsName("node-1".try_into().unwrap()),
            SanType::IpAddress("192.0.2.10".parse().unwrap()),
            SanType::IpAddress("2001:db8::10".parse().unwrap()),
        ]
    }

    pub fn kubelet_csr(name: &str, request: Vec<u8>) -> CertificateSigningRequest {
        CertificateSigningRequest {
            metadata: kube::api::ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            spec: CertificateSigningRequestSpec {
                signer_name: SIGNER.into(),
                username: Some("system:node:node-1".into()),
                groups: Some(vec!["system:nodes".into(), "system:authenticated".into()]),
                usages: Some(vec!["digital signature".into(), "server auth".into()]),
                request: k8s_openapi::ByteString(request),
                ..Default::default()
            },
            status: None,
        }
    }

    pub fn own_csr(name: &str) -> CertificateSigningRequest {
        kubelet_csr(
            name,
            pem(
                &[
                    (DnType::CommonName, "system:node:node-1"),
                    (DnType::OrganizationName, "system:nodes"),
                ],
                own_sans(),
            ),
        )
    }

    pub fn node(addresses: &[&str]) -> Node {
        Node {
            status: Some(NodeStatus {
                addresses: Some(
                    addresses
                        .iter()
                        .map(|a| NodeAddress {
                            address: a.to_string(),
                            type_: "InternalIP".into(),
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    const OWN: [&str; 3] = ["node-1", "192.0.2.10", "2001:db8::10"];

    #[test]
    fn approves_the_kubelets_own_request() {
        let csr = own_csr("a");
        assert_eq!(requesting_node(&csr), Ok("node-1".into()));
        assert_eq!(check_names(&csr, &node(&OWN)), Ok(()));
        assert_eq!(
            check_names(
                &csr,
                &node(&["node-1", "192.0.2.10", "2001:db8:0:0::10", "x"])
            ),
            Ok(()),
            "IPs compare as addresses"
        );
        let mut rsa = csr.clone();
        rsa.spec.usages = Some(USAGES.map(String::from).to_vec());
        assert_eq!(requesting_node(&rsa), Ok("node-1".into()));
    }

    #[test]
    fn refuses_anything_else() {
        let subject = [
            (DnType::CommonName, "system:node:node-1"),
            (DnType::OrganizationName, "system:nodes"),
        ];
        let mut cases: Vec<(&str, CertificateSigningRequest)> = Vec::new();
        let mut with = |what, f: &dyn Fn(&mut CertificateSigningRequest)| {
            let mut c = own_csr("a");
            f(&mut c);
            cases.push((what, c));
        };
        with("a user", &|c| c.spec.username = Some("alice".into()));
        with("no user", &|c| c.spec.username = None);
        with("an empty node", &|c| {
            c.spec.username = Some("system:node:".into())
        });
        with("not in system:nodes", &|c| {
            c.spec.groups = Some(vec!["system:authenticated".into()])
        });
        with("client auth", &|c| {
            c.spec.usages = Some(vec!["digital signature".into(), "client auth".into()])
        });
        with("no server auth", &|c| {
            c.spec.usages = Some(vec!["digital signature".into()])
        });
        with("another node's CN", &|c| {
            c.spec.username = Some("system:node:node-2".into())
        });
        with("garbage", &|c| c.spec.request.0 = b"garbage".to_vec());
        with("a certificate, not a request", &|c| {
            let text = String::from_utf8(c.spec.request.0.clone()).unwrap();
            c.spec.request.0 = text
                .replace("CERTIFICATE REQUEST", "CERTIFICATE")
                .into_bytes();
        });
        with("no O", &|c| {
            c.spec.request.0 = pem(&subject[..1], own_sans())
        });
        with("another O", &|c| {
            c.spec.request.0 = pem(
                &[
                    subject[0].clone(),
                    (DnType::OrganizationName, "system:masters"),
                ],
                own_sans(),
            )
        });
        with("a second O", &|c| {
            c.spec.request.0 = pem(
                &[
                    subject[0].clone(),
                    subject[1].clone(),
                    (DnType::OrganizationName, "system:masters"),
                ],
                own_sans(),
            )
        });
        with("an extra attribute", &|c| {
            c.spec.request.0 = pem(
                &[
                    subject[0].clone(),
                    subject[1].clone(),
                    (DnType::CountryName, "NZ"),
                ],
                own_sans(),
            )
        });
        with("an e-mail name", &|c| {
            let mut sans = own_sans();
            sans.push(SanType::Rfc822Name("a@example.com".try_into().unwrap()));
            c.spec.request.0 = pem(&subject, sans)
        });
        with("a URI", &|c| {
            let mut sans = own_sans();
            sans.push(SanType::URI("spiffe://x/y".try_into().unwrap()));
            c.spec.request.0 = pem(&subject, sans)
        });
        for (what, c) in cases {
            assert!(requesting_node(&c).is_err(), "{what}");
        }
    }

    #[test]
    fn names_must_be_the_nodes() {
        let subject = [
            (DnType::CommonName, "system:node:node-1"),
            (DnType::OrganizationName, "system:nodes"),
        ];
        let own = own_csr("a");
        assert!(
            check_names(&own, &node(&OWN[..2])).is_err(),
            "IPv6 unreported"
        );
        assert!(
            check_names(&own, &node(&OWN[1..])).is_err(),
            "name unreported"
        );
        assert!(check_names(&own, &node(&[])).is_err());
        assert!(check_names(&own, &Node::default()).is_err());
        let mut foreign = own.clone();
        foreign.spec.request.0 = pem(
            &subject,
            vec![
                SanType::DnsName("node-1".try_into().unwrap()),
                SanType::DnsName("kubernetes.default.svc".try_into().unwrap()),
            ],
        );
        assert!(check_names(&foreign, &node(&OWN)).is_err());
        let mut none = own.clone();
        none.spec.request.0 = pem(&subject, vec![]);
        assert!(check_names(&none, &node(&OWN)).is_err());
    }

    #[test]
    fn pending_holds_open_kubelet_serving_requests() {
        let mut p = Pending::default();
        let answered = |name: &str, type_: &str| {
            let mut c = own_csr(name);
            c.status = Some(CertificateSigningRequestStatus {
                conditions: Some(vec![CertificateSigningRequestCondition {
                    type_: type_.into(),
                    status: "True".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            });
            c
        };
        let mut client = own_csr("client");
        client.spec.signer_name = "kubernetes.io/kube-apiserver-client-kubelet".into();
        let mut issued = own_csr("issued");
        issued.status = Some(CertificateSigningRequestStatus {
            certificate: Some(k8s_openapi::ByteString(b"x".to_vec())),
            conditions: Some(vec![]),
        });
        for c in [
            own_csr("a"),
            client,
            answered("approved", "Approved"),
            answered("denied", "Denied"),
            issued,
        ] {
            p.apply(Event::Apply(c));
        }
        assert_eq!(p.0.keys().collect::<Vec<_>>(), ["a"]);

        p.passed_over("a", "why".into());
        p.apply(Event::Apply(own_csr("a")));
        assert_eq!(
            p.0["a"].1.as_deref(),
            Some("why"),
            "the reason survives an update"
        );
        p.apply(Event::Apply(answered("a", "Approved")));
        assert!(p.0.is_empty(), "approved elsewhere");

        p.apply(Event::Apply(own_csr("b")));
        p.apply(Event::Delete(own_csr("b")));
        assert!(p.0.is_empty());

        p.apply(Event::Apply(own_csr("gone")));
        p.apply(Event::Init);
        p.apply(Event::InitApply(own_csr("c")));
        p.apply(Event::InitDone);
        assert_eq!(p.0.keys().collect::<Vec<_>>(), ["c"]);
    }
}
