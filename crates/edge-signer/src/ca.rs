//! The node's CA: a `kubernetes.io/tls` Secret holding the issuing CA's P-256
//! key (PKCS#8) and its chain, issuing CA first, up to a self-signed root.

use std::net::IpAddr;

use anyhow::{Context, ensure};
use k8s_openapi::api::core::v1::Secret;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType, SubjectPublicKeyInfo,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;

const EPHEMERAL_LIFETIME: i64 = 10 * 365 * 86_400;
/// The shortest leaf kube-apiserver accepts: a CA with less left cannot sign.
pub const MIN_LEAF_LIFETIME: i64 = 3600;

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    certs: Vec<String>,
    chain_not_after: i64,
    ephemeral: bool,
    ip_constraints: Vec<IpConstraints>,
}

/// One certificate's iPAddress name constraints, each an address then its mask.
struct IpConstraints {
    permitted: Option<Vec<Vec<u8>>>,
    excluded: Vec<Vec<u8>>,
}

impl IpConstraints {
    fn of(c: &X509Certificate) -> Self {
        let nc = c.name_constraints().ok().flatten().map(|e| e.value);
        let ips = |subtrees: Option<&Vec<x509_parser::extensions::GeneralSubtree>>| {
            subtrees
                .into_iter()
                .flatten()
                .filter_map(|t| match t.base {
                    GeneralName::IPAddress(b) => Some(b.to_vec()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let permitted = ips(nc.and_then(|n| n.permitted_subtrees.as_ref()));
        Self {
            permitted: (!permitted.is_empty()).then_some(permitted),
            excluded: ips(nc.and_then(|n| n.excluded_subtrees.as_ref())),
        }
    }

    fn permit(&self, ip: &[u8]) -> bool {
        let within = |t: &Vec<u8>| {
            t.len() == 2 * ip.len()
                && ip
                    .iter()
                    .zip(&t[..ip.len()])
                    .zip(&t[ip.len()..])
                    .all(|((i, a), m)| i & m == a & m)
        };
        self.permitted.as_ref().is_none_or(|p| p.iter().any(within))
            && !self.excluded.iter().any(within)
    }
}

pub struct Leaf {
    pub chain: String,
    pub not_before: i64,
    pub not_after: i64,
}

/// In the signer's own namespace.
pub const SECRET: &str = "edge-signer-ca";

impl Ca {
    pub fn from_secret(secret: Option<&Secret>, now: i64) -> anyhow::Result<Self> {
        let data = secret.context("no Secret")?.data.as_ref();
        let field = |k: &str| {
            data.and_then(|d| d.get(k))
                .map(|b| b.0.as_slice())
                .with_context(|| format!("no {k}"))
        };
        Self::parse(&[field("tls.key")?, b"\n", field("tls.crt")?].concat(), now)
    }

    pub fn ephemeral(now: i64) -> anyhow::Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "edge ephemeral CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = datetime(now)?;
        params.not_after = datetime(now + EPHEMERAL_LIFETIME)?;
        let cert = params.self_signed(&key)?;
        let pem = format!("{}{}", key.serialize_pem(), cert.pem());
        Ok(Self {
            ephemeral: true,
            ..Self::parse(pem.as_bytes(), now)?
        })
    }

    fn parse(bytes: &[u8], now: i64) -> anyhow::Result<Self> {
        let key = PrivateKeyDer::from_pem_slice(bytes).context("no private key")?;
        let key = KeyPair::try_from(&key).context("the private key is not unencrypted PKCS#8")?;
        ensure!(
            key.algorithm() == &PKCS_ECDSA_P256_SHA256,
            "not an ECDSA P-256 key"
        );
        let pems = certificate_blocks(std::str::from_utf8(bytes).context("not PEM text")?);
        let ders = pems
            .iter()
            .map(|p| CertificateDer::from_pem_slice(p.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .context("unreadable certificate")?;
        let certs = ders
            .iter()
            .map(|d| x509_parser::parse_x509_certificate(d).map(|(_, c)| c))
            .collect::<Result<Vec<_>, _>>()
            .context("unparsable certificate")?;
        let (first, root) = match (certs.first(), certs.last()) {
            (Some(f), Some(r)) => (f, r),
            _ => anyhow::bail!("no certificate"),
        };
        ensure!(
            first.public_key().subject_public_key.data.as_ref() == key.public_key_raw(),
            "the key does not match the first certificate"
        );
        for (i, c) in certs.iter().enumerate() {
            ensure!(signs_certificates(c), "certificate {} is not a CA", i + 1);
        }
        for (i, pair) in certs.windows(2).enumerate() {
            ensure!(
                issued_by(&pair[0], &pair[1]),
                "certificate {} is not issued by the one after it: list the issuing CA first, up to the root",
                i + 1
            );
        }
        ensure!(
            issued_by(root, root),
            "the chain does not end at a self-signed root"
        );
        for c in &certs {
            ensure!(
                c.validity().not_before.timestamp() <= now,
                "{} is not valid yet",
                c.subject()
            );
        }
        let not_after = certs
            .iter()
            .map(|c| c.validity().not_after.timestamp())
            .min()
            .unwrap_or(now);
        ensure!(
            not_after - now >= MIN_LEAF_LIFETIME,
            "the chain expires within an hour"
        );
        Ok(Self {
            issuer: Issuer::from_ca_cert_der(&ders[0], key)?,
            certs: pems,
            chain_not_after: not_after,
            ephemeral: false,
            ip_constraints: certs.iter().map(IpConstraints::of).collect(),
        })
    }

    /// A leaf naming an address the chain's name constraints exclude is
    /// invalid whole.
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        self.ip_constraints.iter().all(|c| c.permit(&ip))
    }

    pub fn root(&self) -> &str {
        self.certs.last().map_or("", String::as_str)
    }

    /// The chain stops below the root: clients hold it.
    pub fn issue(
        &self,
        spki: &SubjectPublicKeyInfo,
        dns: &[String],
        ips: &[IpAddr],
        now: i64,
        lifetime: i64,
    ) -> anyhow::Result<Leaf> {
        // An ephemeral CA's leaves renew soonest, so a restored file reaches
        // every pod within half an hour.
        let lifetime = if self.ephemeral {
            MIN_LEAF_LIFETIME
        } else {
            lifetime
        };
        let not_after = (now + lifetime).min(self.chain_not_after);
        ensure!(
            not_after - now >= MIN_LEAF_LIFETIME,
            "the CA expires within an hour"
        );
        let mut params = CertificateParams::default();
        // An empty subject makes rcgen mark the SAN critical, as RFC 5280 asks.
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = dns
            .iter()
            .map(|d| Ok(SanType::DnsName(d.as_str().try_into()?)))
            .chain(ips.iter().map(|ip| Ok(SanType::IpAddress(*ip))))
            .collect::<Result<_, rcgen::Error>>()?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // A workload identity, used in both directions.
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        params.not_before = datetime(now)?;
        params.not_after = datetime(not_after)?;
        let cert = params.signed_by(spki, &self.issuer)?;
        let below_root = &self.certs[..self.certs.len() - 1];
        Ok(Leaf {
            chain: std::iter::once(cert.pem())
                .chain(below_root.iter().cloned())
                .collect(),
            not_before: now,
            not_after,
        })
    }
}

/// The IP addresses the chain's leaf names.
pub fn leaf_addresses(chain: &str) -> Vec<IpAddr> {
    let Ok(der) = CertificateDer::from_pem_slice(chain.as_bytes()) else {
        return Vec::new();
    };
    let Ok((_, leaf)) = x509_parser::parse_x509_certificate(&der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = leaf.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::IPAddress(b) => <[u8; 4]>::try_from(*b)
                .map(IpAddr::from)
                .or_else(|_| <[u8; 16]>::try_from(*b).map(IpAddr::from))
                .ok(),
            _ => None,
        })
        .collect()
}

fn certificate_blocks(text: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let Some(len) = rest[start..].find(END) else {
            break;
        };
        let end = start + len + END.len();
        blocks.push(format!("{}\n", &rest[start..end]));
        rest = &rest[end..];
    }
    blocks
}

fn signs_certificates(c: &X509Certificate) -> bool {
    c.is_ca()
        && c.key_usage()
            .ok()
            .flatten()
            .is_none_or(|ku| ku.value.key_cert_sign())
}

fn issued_by(cert: &X509Certificate, issuer: &X509Certificate) -> bool {
    cert.issuer() == issuer.subject() && cert.verify_signature(Some(issuer.public_key())).is_ok()
}

/// The CA the signer signs with: the Secret's, or while it is unusable an
/// ephemeral one, kept until the Secret is fixed.
pub struct Source {
    pub ca: Ca,
    problem: Option<String>,
}

impl Source {
    pub fn new(secret: Option<&Secret>, now: i64) -> anyhow::Result<Self> {
        let (ca, problem) = match Ca::from_secret(secret, now) {
            Ok(ca) => (ca, None),
            Err(e) => {
                let why = format!("{e:#}");
                unusable(&why);
                (Ca::ephemeral(now)?, Some(why))
            }
        };
        if problem.is_none() {
            tracing::info!(secret = SECRET, "node CA loaded");
        }
        Ok(Self { ca, problem })
    }

    pub fn refresh(&mut self, secret: Option<&Secret>, now: i64) -> anyhow::Result<()> {
        match Ca::from_secret(secret, now) {
            Ok(ca) if self.problem.is_some() || ca.certs != self.ca.certs => {
                tracing::info!(secret = SECRET, "node CA loaded");
                self.ca = ca;
                self.problem = None;
            }
            Ok(_) => {}
            Err(e) => {
                let why = format!("{e:#}");
                if self.problem.as_ref() != Some(&why) {
                    unusable(&why);
                    if self.problem.is_none() {
                        self.ca = Ca::ephemeral(now)?;
                    }
                    self.problem = Some(why);
                }
            }
        }
        Ok(())
    }
}

fn unusable(why: &str) {
    tracing::error!(
        secret = SECRET,
        error = why,
        "node CA unusable: signing with an ephemeral CA that clients will not trust"
    );
}

/// The API's `keyType`s this signer issues for.
pub const KEY_TYPES: &str = "ECDSAP256, RSA3072 or RSA4096";
/// kube-apiserver's bound on `stubPKCS10Request`.
const MAX_REQUEST: usize = 10 * 1024;

#[derive(Debug, PartialEq)]
pub struct Refusal {
    pub reason: &'static str,
    pub message: String,
}

/// The stub CSR's key, once its self-signature verifies: the proof of
/// possession kube-apiserver also checks.
pub fn requested_key(csr_der: &[u8]) -> Result<SubjectPublicKeyInfo, Refusal> {
    use x509_parser::prelude::FromDer;
    let invalid = |message: &str| Refusal {
        reason: "InvalidStubPKCS10Request",
        message: message.into(),
    };
    if csr_der.len() > MAX_REQUEST {
        return Err(invalid("the certificate request is too large"));
    }
    let Ok((_, csr)) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
    else {
        return Err(invalid("unparsable certificate request"));
    };
    let info = &csr.certification_request_info;
    let spki = &info.subject_pki;
    let key_alg = sequence(spki.raw).and_then(sequence).unwrap_or_default();
    key_type(key_alg, spki).map_err(|found| Refusal {
        reason: "UnsupportedKeyType",
        message: format!("{found} is not supported: use keyType {KEY_TYPES}"),
    })?;
    let signature_alg = sequence(csr_der)
        .and_then(element)
        .and_then(|(_, rest)| sequence(rest))
        .unwrap_or_default();
    let verifies = rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
        .iter()
        .find(|a| {
            a.public_key_alg_id().as_ref() == key_alg
                && a.signature_alg_id().as_ref() == signature_alg
        })
        .is_some_and(|a| {
            a.verify_signature(
                &spki.subject_public_key.data,
                info.raw,
                &csr.signature_value.data,
            )
            .is_ok()
        });
    if !verifies {
        return Err(invalid(
            "the certificate request is not signed by its own key",
        ));
    }
    SubjectPublicKeyInfo::from_der(spki.raw).map_err(|_| invalid("unreadable subject public key"))
}

/// The key's `keyType`, or what it is instead.
fn key_type(
    alg: &[u8],
    spki: &x509_parser::x509::SubjectPublicKeyInfo,
) -> Result<&'static str, String> {
    use rustls_pki_types::alg_id;
    use x509_parser::public_key::PublicKey;
    if alg == alg_id::ECDSA_P256.as_ref() {
        return Ok("ECDSAP256");
    }
    if alg == alg_id::RSA_ENCRYPTION.as_ref() {
        let Ok(PublicKey::RSA(rsa)) = spki.parsed() else {
            return Err("an unreadable RSA key".into());
        };
        // In bytes, as kube-apiserver measures it.
        let size = rsa.modulus.iter().skip_while(|b| **b == 0).count();
        return match size * 8 {
            3072 => Ok("RSA3072"),
            4096 => Ok("RSA4096"),
            bits => Err(format!("a {bits}-bit RSA key")),
        };
    }
    Err(match alg {
        a if a == alg_id::ECDSA_P384.as_ref() => "an ECDSA P-384 key",
        a if a == alg_id::ECDSA_P521.as_ref() => "an ECDSA P-521 key",
        a if a == alg_id::ED25519.as_ref() => "an Ed25519 key",
        _ => "the key type",
    }
    .into())
}

/// The contents of the DER element `der` starts with, and what follows it.
fn element(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = der.get(1..)?.split_first()?;
    let (len, rest) = match len {
        0..=0x7f => (usize::from(len), rest),
        0x81..=0x82 => {
            let (bytes, rest) = rest.split_at_checked(usize::from(len & 0x7f))?;
            (bytes.iter().fold(0, |n, b| n << 8 | usize::from(*b)), rest)
        }
        _ => return None,
    };
    let (content, rest) = rest.split_at_checked(len)?;
    Some((content, rest))
}

/// The contents of the SEQUENCE `der` starts with.
fn sequence(der: &[u8]) -> Option<&[u8]> {
    (der.first() == Some(&0x30))
        .then(|| element(der))
        .flatten()
        .map(|(content, _)| content)
}

fn datetime(unix: i64) -> anyhow::Result<OffsetDateTime> {
    Ok(OffsetDateTime::from_unix_timestamp(unix)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{GeneralSubtree, NameConstraints};
    use std::io::Write;
    use x509_parser::prelude::parse_x509_certificate;

    pub const NOW: i64 = 1_790_000_000;
    const YEAR: i64 = 365 * 86_400;

    pub fn tls(key: &str, crt: &str) -> Secret {
        Secret {
            data: Some(
                [("tls.key", key), ("tls.crt", crt)]
                    .into_iter()
                    .map(|(k, v)| (k.into(), k8s_openapi::ByteString(v.into())))
                    .collect(),
            ),
            ..Secret::default()
        }
    }

    pub fn secret(key: &TestCert, chain: &[&TestCert]) -> Secret {
        let crt: String = chain.iter().map(|c| c.pem.as_str()).collect();
        tls(&key.key.serialize_pem(), &crt)
    }

    /// One text in `tls.key`: the two fields are read as one.
    fn raw(text: &str) -> Secret {
        tls(text, "")
    }

    pub fn csr(alg: &'static rcgen::SignatureAlgorithm) -> (KeyPair, Vec<u8>) {
        request_by(KeyPair::generate_for(alg).unwrap())
    }

    /// ring cannot generate RSA keys: these are fixed, for tests only.
    pub fn rsa_csr(bits: u32) -> (KeyPair, Vec<u8>) {
        let der: &[u8] = match bits {
            2048 => include_bytes!("../testdata/rsa2048.pk8"),
            3072 => include_bytes!("../testdata/rsa3072.pk8"),
            4096 => include_bytes!("../testdata/rsa4096.pk8"),
            _ => unreachable!(),
        };
        let der = rustls_pki_types::PrivatePkcs8KeyDer::from(der);
        request_by(KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_RSA_SHA256).unwrap())
    }

    fn request_by(key: KeyPair) -> (KeyPair, Vec<u8>) {
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        let der = p.serialize_request(&key).unwrap().der().to_vec();
        (key, der)
    }

    pub struct TestCert {
        key: KeyPair,
        params: CertificateParams,
        pub pem: String,
    }

    fn params(cn: &str, is_ca: IsCa, not_before: i64, not_after: i64) -> CertificateParams {
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = is_ca;
        p.not_before = datetime(not_before).unwrap();
        p.not_after = datetime(not_after).unwrap();
        p
    }

    fn make_cert(
        params: CertificateParams,
        alg: &'static rcgen::SignatureAlgorithm,
        by: Option<&TestCert>,
    ) -> TestCert {
        let key = KeyPair::generate_for(alg).unwrap();
        let cert = match by {
            Some(i) => params.signed_by(&key, &Issuer::from_params(&i.params, &i.key)),
            None => params.self_signed(&key),
        }
        .unwrap();
        TestCert {
            key,
            params,
            pem: cert.pem(),
        }
    }

    pub fn root(cn: &str, not_before: i64, not_after: i64) -> TestCert {
        let ca = IsCa::Ca(BasicConstraints::Unconstrained);
        make_cert(
            params(cn, ca, not_before, not_after),
            &PKCS_ECDSA_P256_SHA256,
            None,
        )
    }

    pub fn intermediate(by: &TestCert) -> TestCert {
        let mut p = params(
            "unit CA",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            NOW - 60,
            NOW + 5 * YEAR,
        );
        p.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![
                GeneralSubtree::DnsName("example.lan".into()),
                GeneralSubtree::DnsName("localhost".into()),
                GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4([127, 0, 0, 0], [255, 0, 0, 0])),
            ],
            excluded_subtrees: vec![],
        });
        make_cert(p, &PKCS_ECDSA_P256_SHA256, Some(by))
    }

    pub fn file(key: &TestCert, chain: &[&TestCert]) -> String {
        std::iter::once(key.key.serialize_pem())
            .chain(chain.iter().map(|c| c.pem.clone()))
            .collect()
    }

    pub fn file_ca(now: i64) -> Ca {
        let r = root("root", now - 60, now + 10 * YEAR);
        Ca::parse(file(&r, &[&r]).as_bytes(), now).unwrap()
    }

    fn logged_warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
        let (out, text) = logged_info(f);
        let warn = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("INFO"))
            .map(|l| format!("{l}\n"))
            .collect();
        (out, warn)
    }

    /// Every capture is at one level: tracing's global level hint is shared by
    /// the tests' concurrent subscribers.
    fn logged_info<T>(f: impl FnOnce() -> T) -> (T, String) {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Lines(Arc<Mutex<Vec<u8>>>);
        impl Write for Lines {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let sink = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_writer(move || sink.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        (out, text)
    }

    fn one_error(log: &str, why: &str) -> bool {
        log.lines().count() == 1
            && log.trim_start().starts_with("ERROR")
            && log.contains(SECRET)
            && log.contains(why)
    }

    fn leaf(ca: &Ca, now: i64, lifetime: i64) -> Leaf {
        let (_, csr) = csr(&PKCS_ECDSA_P256_SHA256);
        ca.issue(
            &requested_key(&csr).unwrap(),
            &["*.example.lan".into(), "example.lan".into()],
            &["127.0.0.1".parse().unwrap()],
            now,
            lifetime,
        )
        .unwrap()
    }

    fn ders(pem: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn verify(chain: &str, root: &str, name: &str, at: i64) -> Result<(), rustls::Error> {
        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ders(root).remove(0)).unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            roots.into(),
            rustls::crypto::ring::default_provider().into(),
        )
        .build()
        .unwrap();
        let chain = ders(chain);
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &rustls_pki_types::ServerName::try_from(name.to_string()).unwrap(),
                &[],
                rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                    at as u64,
                )),
            )
            .map(drop)
    }

    #[test]
    fn intermediate_leaves_verify_to_root() {
        let r = root("operator root", NOW - 60, NOW + 20 * YEAR);
        let i = intermediate(&r);
        let (source, log) =
            logged_warnings(|| Source::new(Some(&secret(&i, &[&i, &r])), NOW).unwrap());
        assert_eq!(log, "");
        assert_eq!(source.ca.root(), r.pem);

        let leaf = leaf(&source.ca, NOW, 864_000);
        assert_eq!(leaf.chain.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(leaf.chain.ends_with(&i.pem));
        for name in ["example.lan", "gw.example.lan", "127.0.0.1"] {
            verify(&leaf.chain, &r.pem, name, NOW + 60).unwrap();
        }
        assert!(verify(&leaf.chain, &r.pem, "example.com", NOW + 60).is_err());
        let alone = leaf
            .chain
            .split_inclusive("-----END CERTIFICATE-----\n")
            .next()
            .unwrap();
        assert!(
            verify(alone, &r.pem, "example.lan", NOW + 60).is_err(),
            "the intermediate is needed"
        );
    }

    #[test]
    fn permits_only_addresses_the_chain_allows() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let unconstrained = file_ca(NOW);
        for a in ["10.42.0.1", "192.0.2.1", "2001:db8::1"] {
            assert!(unconstrained.permits(ip(a)), "{a}");
        }

        let r = root("operator root", NOW - 60, NOW + 20 * YEAR);
        let i = intermediate(&r);
        let ca = Ca::parse(file(&i, &[&i, &r]).as_bytes(), NOW).unwrap();
        assert!(ca.permits(ip("127.0.0.1")));
        assert!(!ca.permits(ip("10.42.0.1")));
        assert!(!ca.permits(ip("::1")), "v4 subtrees bar v6");

        let mut p = params(
            "unit CA",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            NOW - 60,
            NOW + YEAR,
        );
        p.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName("example.lan".into())],
            excluded_subtrees: vec![GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4(
                [10, 42, 0, 0],
                [255, 255, 0, 0],
            ))],
        });
        let i = make_cert(p, &PKCS_ECDSA_P256_SHA256, Some(&r));
        let ca = Ca::parse(file(&i, &[&i, &r]).as_bytes(), NOW).unwrap();
        assert!(!ca.permits(ip("10.42.7.1")));
        assert!(ca.permits(ip("10.43.0.1")));
        assert!(ca.permits(ip("2001:db8::1")));
    }

    #[test]
    fn leaf_addresses_read_back() {
        let ca = file_ca(NOW);
        let ips: Vec<IpAddr> = ["10.42.0.1", "2001:db8::1", "127.0.0.1"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let (_, csr) = csr(&PKCS_ECDSA_P256_SHA256);
        let leaf = ca
            .issue(
                &requested_key(&csr).unwrap(),
                &["example.lan".into()],
                &ips,
                NOW,
                3600,
            )
            .unwrap();
        assert_eq!(leaf_addresses(&leaf.chain), ips);
        assert!(leaf_addresses("not a chain").is_empty());
    }

    #[test]
    fn self_signed_ca_leaves_come_alone() {
        let r = root("unit CA", NOW - 60, NOW + 10 * YEAR);
        let source = Source::new(Some(&secret(&r, &[&r])), NOW).unwrap();
        assert_eq!(source.ca.root(), r.pem);
        let leaf = leaf(&source.ca, NOW, 864_000);
        assert_eq!(leaf.chain.matches("BEGIN CERTIFICATE").count(), 1);
        verify(&leaf.chain, &r.pem, "example.lan", NOW + 60).unwrap();
        assert_eq!((leaf.not_before, leaf.not_after), (NOW, NOW + 864_000));
    }

    #[test]
    fn unusable_secret_falls_back_to_ephemeral() {
        let r = root("root", NOW - 60, NOW + 20 * YEAR);
        let i = intermediate(&r);
        let other = root("other", NOW - 60, NOW + 20 * YEAR);
        let good = file(&r, &[&r]);
        let key = r.key.serialize_pem();
        let with = |p: CertificateParams, alg| {
            let m = make_cert(p, alg, None);
            file(&m, &[&m])
        };
        let ca = || IsCa::Ca(BasicConstraints::Unconstrained);
        let mut no_cert_sign = params("x", ca(), NOW - 60, NOW + YEAR);
        no_cert_sign.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        let shapes: Vec<(&str, Option<String>, &str)> = vec![
            ("garbage", Some("not pem".into()), "no private key"),
            ("empty", Some(String::new()), "no private key"),
            ("key only", Some(key.clone()), "no certificate"),
            ("certificate only", Some(r.pem.clone()), "no private key"),
            (
                "another CA's key",
                Some(format!("{}{}", other.key.serialize_pem(), r.pem)),
                "does not match",
            ),
            (
                "SEC1 key",
                Some(format!(
                    "{}{}",
                    key.replace("PRIVATE KEY", "EC PRIVATE KEY"),
                    r.pem
                )),
                "PKCS#8",
            ),
            (
                "P-384 key",
                Some(with(
                    params("x", ca(), NOW - 60, NOW + YEAR),
                    &rcgen::PKCS_ECDSA_P384_SHA384,
                )),
                "P-256",
            ),
            (
                "not a CA",
                Some(with(
                    params("x", IsCa::NoCa, NOW - 60, NOW + YEAR),
                    &PKCS_ECDSA_P256_SHA256,
                )),
                "certificate 1 is not a CA",
            ),
            (
                "a CA that may not sign certificates",
                Some(with(no_cert_sign, &PKCS_ECDSA_P256_SHA256)),
                "certificate 1 is not a CA",
            ),
            (
                "a leaf in the chain",
                Some(format!(
                    "{}{}",
                    good,
                    with(
                        params("x", IsCa::NoCa, NOW - 60, NOW + YEAR),
                        &PKCS_ECDSA_P256_SHA256
                    )
                )),
                "certificate 2 is not a CA",
            ),
            (
                "root before intermediate",
                Some(file(&i, &[&i, &other, &r])),
                "certificate 1 is not issued by the one after it",
            ),
            (
                "a root of the same name but another key",
                Some(file(&i, &[&i, &root("root", NOW - 60, NOW + YEAR)])),
                "certificate 1 is not issued by the one after it",
            ),
            (
                "no root",
                Some(file(&i, &[&i])),
                "does not end at a self-signed root",
            ),
            (
                "expired",
                Some(with(
                    params("x", ca(), NOW - YEAR, NOW - 1),
                    &PKCS_ECDSA_P256_SHA256,
                )),
                "expires within an hour",
            ),
            (
                "expiring within the hour",
                Some(with(
                    params("x", ca(), NOW - YEAR, NOW + MIN_LEAF_LIFETIME - 1),
                    &PKCS_ECDSA_P256_SHA256,
                )),
                "expires within an hour",
            ),
            (
                "root expiring before the intermediate",
                Some({
                    let short = root("short", NOW - 60, NOW + 60);
                    let i = intermediate(&short);
                    file(&i, &[&i, &short])
                }),
                "expires within an hour",
            ),
            (
                "not yet valid",
                Some(with(
                    params("x", ca(), NOW + 1, NOW + YEAR),
                    &PKCS_ECDSA_P256_SHA256,
                )),
                "not valid yet",
            ),
            (
                "truncated",
                Some(good[..good.len() - 40].to_string()),
                "no certificate",
            ),
        ];
        let mut shapes: Vec<(&str, Option<Secret>, &str)> = shapes
            .into_iter()
            .map(|(what, text, why)| (what, text.as_deref().map(raw), why))
            .collect();
        let mut no_crt = secret(&r, &[&r]);
        no_crt.data.as_mut().unwrap().remove("tls.crt");
        let mut no_key = secret(&r, &[&r]);
        no_key.data.as_mut().unwrap().remove("tls.key");
        shapes.extend([
            ("no Secret", None, "no Secret"),
            ("no data", Some(Secret::default()), "no tls.key"),
            ("no tls.crt", Some(no_crt), "no tls.crt"),
            ("no tls.key", Some(no_key), "no tls.key"),
        ]);
        for (what, secret, why) in shapes {
            let (source, log) = logged_warnings(|| Source::new(secret.as_ref(), NOW).unwrap());
            assert!(one_error(&log, why), "{what}: {log}");
            assert!(source.ca.ephemeral, "{what}");
            for m in [&r, &i, &other] {
                assert_ne!(source.ca.root(), m.pem, "{what}");
            }
        }
    }

    #[test]
    fn refresh_follows_secret_changes() {
        let a = root("a", NOW - 60, NOW + 10 * YEAR);
        let b = root("b", NOW - 60, NOW + 10 * YEAR);
        let mut source = Source::new(Some(&secret(&a, &[&a])), NOW).unwrap();
        let info = |source: &mut Source, s: Option<&Secret>| {
            logged_info(|| source.refresh(s, NOW).unwrap()).1
        };
        assert_eq!(
            info(&mut source, Some(&secret(&a, &[&a]))),
            "",
            "an unchanged Secret is not reloaded"
        );

        let log = info(&mut source, Some(&secret(&b, &[&b])));
        assert_eq!(source.ca.root(), b.pem);
        assert!(log.lines().count() == 1 && log.contains("loaded"), "{log}");

        let garbage = raw("garbage");
        let ((), log) = logged_warnings(|| source.refresh(Some(&garbage), NOW).unwrap());
        assert!(one_error(&log, "no private key"), "{log}");
        let ephemeral = source.ca.root().to_string();
        assert!(source.ca.ephemeral && ephemeral != b.pem);
        let ((), log) = logged_warnings(|| source.refresh(Some(&garbage), NOW).unwrap());
        assert_eq!(log, "", "the same problem is logged once");

        let ((), log) = logged_warnings(|| source.refresh(None, NOW).unwrap());
        assert!(one_error(&log, "no Secret"), "{log}");
        assert_eq!(source.ca.root(), ephemeral, "one ephemeral CA while broken");

        let fixed = secret(&a, &[&a]);
        let ((), log) = logged_warnings(|| source.refresh(Some(&fixed), NOW).unwrap());
        assert_eq!((source.ca.root(), log.as_str()), (a.pem.as_str(), ""));
        assert!(!source.ca.ephemeral);

        let ((), log) = logged_warnings(|| source.refresh(Some(&fixed), NOW + 10 * YEAR).unwrap());
        assert!(one_error(&log, "expires within an hour"), "{log}");
        assert!(source.ca.ephemeral);
    }

    #[test]
    fn not_yet_valid_ca_taken_once_valid() {
        let r = root("r", NOW, NOW + 10 * YEAR);
        let s = secret(&r, &[&r]);
        let (mut source, log) = logged_warnings(|| Source::new(Some(&s), NOW - 1).unwrap());
        assert!(one_error(&log, "not valid yet"), "{log}");
        source.refresh(Some(&s), NOW).unwrap();
        assert_eq!(source.ca.root(), r.pem);
    }

    #[test]
    fn leaf_lifetime_bounded_by_chain() {
        let r = root("r", NOW - 60, NOW + 20 * YEAR);
        let i = intermediate(&r);
        let ca = Ca::parse(file(&i, &[&i, &r]).as_bytes(), NOW).unwrap();
        assert_eq!(leaf(&ca, NOW, 864_000).not_after, NOW + 864_000);
        let end = NOW + 5 * YEAR;
        assert_eq!(leaf(&ca, end - 864_000, 864_000).not_after, end);
        let late = leaf(&ca, end - MIN_LEAF_LIFETIME, 864_000);
        assert_eq!(late.not_after, end, "a CA with exactly an hour left signs");
        let der = &ders(&late.chain)[0];
        let (_, x) = parse_x509_certificate(der).unwrap();
        assert_eq!(x.validity().not_after.timestamp(), end);
        assert!(Ca::parse(file(&i, &[&i, &r]).as_bytes(), end - MIN_LEAF_LIFETIME).is_ok());
        let (_, csr) = csr(&PKCS_ECDSA_P256_SHA256);
        let spki = requested_key(&csr).unwrap();
        let too_late = ca.issue(&spki, &[], &[], end - MIN_LEAF_LIFETIME + 1, 864_000);
        assert!(too_late.is_err(), "no leaf shorter than the API allows");

        let ephemeral = Ca::ephemeral(NOW).unwrap();
        let short = leaf(&ephemeral, NOW, 864_000);
        assert_eq!(
            (short.not_before, short.not_after),
            (NOW, NOW + MIN_LEAF_LIFETIME)
        );
        verify(&short.chain, ephemeral.root(), "example.lan", NOW + 60).unwrap();
    }

    #[test]
    fn ephemeral_ca_signs_only_leaves() {
        let ca = Ca::ephemeral(NOW).unwrap();
        let der = &ders(ca.root())[0];
        let (_, x) = parse_x509_certificate(der).unwrap();
        let bc = x.basic_constraints().unwrap().unwrap().value;
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        assert_eq!(x.subject(), x.issuer());
        assert_eq!(x.validity().not_before.timestamp(), NOW);
        assert_eq!(x.validity().not_after.timestamp(), NOW + 3650 * 86_400);
        assert_ne!(Ca::ephemeral(NOW).unwrap().root(), ca.root());
    }

    fn issued_with_key(
        ca: &Ca,
        (key, csr): (KeyPair, Vec<u8>),
        dns: &str,
        now: i64,
    ) -> (Vec<CertificateDer<'static>>, KeyPair) {
        let leaf = ca
            .issue(
                &requested_key(&csr).unwrap(),
                &[dns.into()],
                &[],
                now,
                864_000,
            )
            .unwrap();
        (ders(&leaf.chain), key)
    }

    /// A pod certificate as the client of a server that requires one and
    /// trusts the node CA, as Java's and OpenSSL's clients check it.
    #[test]
    fn leaf_authenticates_as_a_tls_client() {
        let p256 = || csr(&PKCS_ECDSA_P256_SHA256);
        handshake(p256(), p256());
    }

    /// An RSA key under the ECDSA CA, as server and as client.
    #[test]
    fn rsa_leaf_authenticates_both_ways() {
        handshake(rsa_csr(3072), rsa_csr(3072));
        handshake(rsa_csr(4096), csr(&PKCS_ECDSA_P256_SHA256));
        handshake(csr(&PKCS_ECDSA_P256_SHA256), rsa_csr(3072));
    }

    fn handshake(server: (KeyPair, Vec<u8>), client: (KeyPair, Vec<u8>)) {
        use rustls::pki_types::PrivateKeyDer;
        // The handshake checks validity on the wall clock.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let r = root("unit CA", now - 60, now + 10 * YEAR);
        let i = intermediate(&r);
        let ca = Ca::parse(file(&i, &[&i, &r]).as_bytes(), now).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ders(ca.root()).remove(0)).unwrap();
        let roots = std::sync::Arc::new(roots);
        let key = |k: &KeyPair| PrivateKeyDer::try_from(k.serialize_der()).unwrap();

        let (server_chain, server_key) =
            issued_with_key(&ca, server, "broker.example.lan", now - 60);
        let (client_chain, client_key) =
            issued_with_key(&ca, client, "client.example.lan", now - 60);
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots.clone(),
            provider.clone(),
        )
        .build()
        .unwrap();
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, key(&server_key))
            .unwrap();
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain.clone(), key(&client_key))
            .unwrap();
        let mut server = rustls::ServerConnection::new(server_cfg.into()).unwrap();
        let mut client = rustls::ClientConnection::new(
            client_cfg.into(),
            rustls_pki_types::ServerName::try_from("broker.example.lan").unwrap(),
        )
        .unwrap();
        let mut buf = Vec::new();
        for _ in 0..10 {
            buf.clear();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut buf.as_slice()).unwrap();
            server
                .process_new_packets()
                .expect("server rejected the client");
            buf.clear();
            server.write_tls(&mut buf).unwrap();
            client.read_tls(&mut buf.as_slice()).unwrap();
            client
                .process_new_packets()
                .expect("client rejected the server");
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!server.is_handshaking(), "handshake did not finish");
        assert_eq!(
            server.peer_certificates().unwrap()[0],
            client_chain[0],
            "the server saw the pod certificate"
        );
    }

    #[test]
    fn leaf_carries_names_and_key() {
        leaf_carries_names_and(csr(&PKCS_ECDSA_P256_SHA256));
        for bits in [3072, 4096] {
            leaf_carries_names_and(rsa_csr(bits));
        }
    }

    fn leaf_carries_names_and((key, csr): (KeyPair, Vec<u8>)) {
        let r = root("r", NOW - 60, NOW + 10 * YEAR);
        let ca = Ca::parse(file(&r, &[&r]).as_bytes(), NOW).unwrap();
        let leaf = ca
            .issue(
                &requested_key(&csr).unwrap(),
                &["example.lan".into(), "*.example.lan".into()],
                &["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
                NOW,
                864_000,
            )
            .unwrap();
        assert_eq!((leaf.not_before, leaf.not_after), (NOW, NOW + 864_000));

        let der = &ders(&leaf.chain)[0];
        let (_, x) = parse_x509_certificate(der).unwrap();
        let ca_der = &ders(ca.root())[0];
        let (_, cax) = parse_x509_certificate(ca_der).unwrap();
        x.verify_signature(Some(cax.public_key())).unwrap();
        assert_eq!(x.issuer(), cax.subject());
        assert_eq!(
            x.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
        assert_eq!(x.validity().not_before.timestamp(), NOW);
        assert_eq!(x.validity().not_after.timestamp(), NOW + 864_000);
        assert!(!x.is_ca());
        let san = x.subject_alternative_name().unwrap().unwrap();
        assert!(san.critical, "an empty subject needs a critical SAN");
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(
            names,
            [
                "DNSName(example.lan)",
                "DNSName(*.example.lan)",
                "IPAddress(7f:00:00:01)",
                "IPAddress(00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01)"
            ]
            .map(str::to_string)
        );
        let eku = x.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && eku.client_auth);
        assert!(!eku.any && !eku.code_signing && !eku.email_protection);
        let ku = x.key_usage().unwrap().unwrap().value;
        assert!(ku.digital_signature() && !ku.key_cert_sign());
    }

    fn refusal(csr: &[u8]) -> Refusal {
        requested_key(csr).map(drop).unwrap_err()
    }

    #[test]
    fn accepts_the_api_key_types() {
        assert!(requested_key(&csr(&PKCS_ECDSA_P256_SHA256).1).is_ok());
        for bits in [3072, 4096] {
            assert!(requested_key(&rsa_csr(bits).1).is_ok());
        }
        for (csr, found) in [
            (rsa_csr(2048).1, "a 2048-bit RSA key"),
            (csr(&rcgen::PKCS_ECDSA_P384_SHA384).1, "an ECDSA P-384 key"),
            (csr(&rcgen::PKCS_ED25519).1, "an Ed25519 key"),
        ] {
            assert_eq!(
                refusal(&csr),
                Refusal {
                    reason: "UnsupportedKeyType",
                    message: format!(
                        "{found} is not supported: use keyType ECDSAP256, RSA3072 or RSA4096"
                    ),
                }
            );
        }
        let padded = [csr(&PKCS_ECDSA_P256_SHA256).1, vec![0; MAX_REQUEST]].concat();
        for bad in [&b""[..], &[0x30, 0x82, 0xff, 0xff], &padded] {
            assert_eq!(refusal(bad).reason, "InvalidStubPKCS10Request");
        }
    }

    /// A CSR's parts: request info, signature algorithm, signature.
    fn parts(csr: &[u8]) -> [Vec<u8>; 3] {
        let mut rest = sequence(csr).unwrap();
        [(); 3].map(|()| {
            let (_, next) = element(rest).unwrap();
            let whole = rest[..rest.len() - next.len()].to_vec();
            rest = next;
            whole
        })
    }

    fn csr_of([info, alg, sig]: [&Vec<u8>; 3]) -> Vec<u8> {
        let body = [&info[..], alg, sig].concat();
        let len = u16::try_from(body.len()).unwrap().to_be_bytes();
        [&[0x30, 0x82][..], &len, &body].concat()
    }

    #[test]
    fn denies_requests_their_key_did_not_sign() {
        let p256 = csr(&PKCS_ECDSA_P256_SHA256).1;
        let rsa3072 = rsa_csr(3072).1;
        let rsa4096 = rsa_csr(4096).1;
        let [p256, rsa3072, rsa4096] = [&p256, &rsa3072, &rsa4096].map(|c| parts(c));
        assert!(requested_key(&csr_of([&rsa3072[0], &rsa3072[1], &rsa3072[2]])).is_ok());

        let mut flipped = rsa3072[2].clone();
        *flipped.last_mut().unwrap() ^= 1;
        let mut flipped_ec = p256[2].clone();
        flipped_ec[10] ^= 1;
        for (what, forged) in [
            (
                "RSA signature altered",
                [&rsa3072[0], &rsa3072[1], &flipped],
            ),
            ("ECDSA signature altered", [&p256[0], &p256[1], &flipped_ec]),
            (
                "another RSA key's signature",
                [&rsa3072[0], &rsa4096[1], &rsa4096[2]],
            ),
            (
                "an ECDSA signature on an RSA key",
                [&rsa3072[0], &p256[1], &p256[2]],
            ),
            (
                "an RSA signature on an ECDSA key",
                [&p256[0], &rsa3072[1], &rsa3072[2]],
            ),
        ] {
            assert_eq!(
                refusal(&csr_of(forged)),
                Refusal {
                    reason: "InvalidStubPKCS10Request",
                    message: "the certificate request is not signed by its own key".into(),
                },
                "{what}"
            );
        }
    }
}
