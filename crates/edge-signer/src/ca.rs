//! The appliance CA: one read-only file holding the issuing CA's P-256 key
//! (PKCS#8) and its chain, issuing CA first, up to a self-signed root.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType,
    SubjectPublicKeyInfo,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;

const EPHEMERAL_LIFETIME: i64 = 10 * 365 * 86_400;
/// The shortest leaf kube-apiserver accepts: a CA with less left cannot sign.
pub const MIN_LEAF_LIFETIME: i64 = 3600;

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    certs: Vec<String>,
    chain_not_after: i64,
    ephemeral: bool,
}

pub struct Leaf {
    pub chain: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl Ca {
    pub fn read(path: &Path, now: i64) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path).context("unreadable")?;
        Self::parse(&bytes, now)
    }

    pub fn ephemeral(now: i64) -> anyhow::Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "meridian appliance ephemeral CA");
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
        })
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
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
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

/// The CA the signer signs with: the file's, or while the file is unusable an
/// ephemeral one, kept until the file is fixed.
pub struct Source {
    path: PathBuf,
    pub ca: Ca,
    problem: Option<String>,
}

impl Source {
    pub fn open(path: &Path, now: i64) -> anyhow::Result<Self> {
        let (ca, problem) = match Ca::read(path, now) {
            Ok(ca) => (ca, None),
            Err(e) => {
                let why = format!("{e:#}");
                unusable(path, &why);
                (Ca::ephemeral(now)?, Some(why))
            }
        };
        if problem.is_none() {
            tracing::info!(path = %path.display(), "appliance CA loaded");
        }
        Ok(Self {
            path: path.into(),
            ca,
            problem,
        })
    }

    pub fn refresh(&mut self, now: i64) -> anyhow::Result<()> {
        match Ca::read(&self.path, now) {
            Ok(ca) if self.problem.is_some() || ca.certs != self.ca.certs => {
                tracing::info!(path = %self.path.display(), "appliance CA loaded");
                self.ca = ca;
                self.problem = None;
            }
            Ok(_) => {}
            Err(e) => {
                let why = format!("{e:#}");
                if self.problem.as_ref() != Some(&why) {
                    unusable(&self.path, &why);
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

fn unusable(path: &Path, why: &str) {
    tracing::error!(
        path = %path.display(), error = why,
        "appliance CA unusable: signing with an ephemeral CA that clients will not trust"
    );
}

pub fn requested_key(csr_der: &[u8]) -> anyhow::Result<SubjectPublicKeyInfo> {
    use x509_parser::prelude::FromDer;
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
        .context("unparsable certificate request")?;
    let spki = SubjectPublicKeyInfo::from_der(csr.certification_request_info.subject_pki.raw)
        .context("unsupported key type")?;
    ensure!(
        spki.algorithm() == &PKCS_ECDSA_P256_SHA256,
        "unsupported key type"
    );
    Ok(spki)
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

    pub fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("edge-signer-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("ca.pem")
    }

    pub fn csr(alg: &'static rcgen::SignatureAlgorithm) -> (KeyPair, Vec<u8>) {
        let key = KeyPair::generate_for(alg).unwrap();
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

    fn intermediate(by: &TestCert) -> TestCert {
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

    fn one_error(log: &str, path: &Path, why: &str) -> bool {
        log.lines().count() == 1
            && log.trim_start().starts_with("ERROR")
            && log.contains(&path.display().to_string())
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
        let path = scratch("intermediate");
        std::fs::write(&path, file(&i, &[&i, &r])).unwrap();
        let (source, log) = logged_warnings(|| Source::open(&path, NOW).unwrap());
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
    fn self_signed_ca_leaves_come_alone() {
        let r = root("unit CA", NOW - 60, NOW + 10 * YEAR);
        let path = scratch("self-signed");
        std::fs::write(&path, file(&r, &[&r])).unwrap();
        let source = Source::open(&path, NOW).unwrap();
        assert_eq!(source.ca.root(), r.pem);
        let leaf = leaf(&source.ca, NOW, 864_000);
        assert_eq!(leaf.chain.matches("BEGIN CERTIFICATE").count(), 1);
        verify(&leaf.chain, &r.pem, "example.lan", NOW + 60).unwrap();
        assert_eq!((leaf.not_before, leaf.not_after), (NOW, NOW + 864_000));
    }

    #[test]
    fn unusable_file_falls_back_to_ephemeral() {
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
            ("missing", None, "unreadable"),
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
        for (what, bytes, why) in shapes {
            let path = scratch("bad");
            if let Some(b) = &bytes {
                std::fs::write(&path, b).unwrap();
            }
            let (source, log) = logged_warnings(|| Source::open(&path, NOW).unwrap());
            assert!(one_error(&log, &path, why), "{what}: {log}");
            assert!(source.ca.ephemeral, "{what}");
            for m in [&r, &i, &other] {
                assert_ne!(source.ca.root(), m.pem, "{what}");
            }
            assert_eq!(
                std::fs::read(&path).ok(),
                bytes.map(String::into_bytes),
                "{what}: left as found"
            );
        }

        let path = scratch("dir");
        std::fs::create_dir(&path).unwrap();
        let (source, log) = logged_warnings(|| Source::open(&path, NOW).unwrap());
        assert!(one_error(&log, &path, "unreadable"), "a directory: {log}");
        assert!(source.ca.ephemeral);
    }

    #[test]
    fn refresh_follows_file_changes() {
        let path = scratch("refresh");
        let a = root("a", NOW - 60, NOW + 10 * YEAR);
        let b = root("b", NOW - 60, NOW + 10 * YEAR);
        std::fs::write(&path, file(&a, &[&a])).unwrap();
        let mut source = Source::open(&path, NOW).unwrap();
        let info = |source: &mut Source| logged_info(|| source.refresh(NOW).unwrap()).1;
        assert_eq!(info(&mut source), "", "an unchanged file is not reloaded");

        std::fs::write(&path, file(&b, &[&b])).unwrap();
        let log = info(&mut source);
        assert_eq!(source.ca.root(), b.pem);
        assert!(log.lines().count() == 1 && log.contains("loaded"), "{log}");

        std::fs::write(&path, "garbage").unwrap();
        let ((), log) = logged_warnings(|| source.refresh(NOW).unwrap());
        assert!(one_error(&log, &path, "no private key"), "{log}");
        let ephemeral = source.ca.root().to_string();
        assert!(source.ca.ephemeral && ephemeral != b.pem);
        let ((), log) = logged_warnings(|| source.refresh(NOW).unwrap());
        assert_eq!(log, "", "the same problem is logged once");

        std::fs::remove_file(&path).unwrap();
        let ((), log) = logged_warnings(|| source.refresh(NOW).unwrap());
        assert!(one_error(&log, &path, "unreadable"), "{log}");
        assert_eq!(source.ca.root(), ephemeral, "one ephemeral CA while broken");

        std::fs::write(&path, file(&a, &[&a])).unwrap();
        let ((), log) = logged_warnings(|| source.refresh(NOW).unwrap());
        assert_eq!((source.ca.root(), log.as_str()), (a.pem.as_str(), ""));
        assert!(!source.ca.ephemeral);

        let ((), log) = logged_warnings(|| source.refresh(NOW + 10 * YEAR).unwrap());
        assert!(one_error(&log, &path, "expires within an hour"), "{log}");
        assert!(source.ca.ephemeral);
    }

    #[test]
    fn not_yet_valid_ca_taken_once_valid() {
        let path = scratch("clock");
        let r = root("r", NOW, NOW + 10 * YEAR);
        std::fs::write(&path, file(&r, &[&r])).unwrap();
        let (mut source, log) = logged_warnings(|| Source::open(&path, NOW - 1).unwrap());
        assert!(one_error(&log, &path, "not valid yet"), "{log}");
        source.refresh(NOW).unwrap();
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

    #[test]
    fn leaf_carries_names_and_key() {
        let r = root("r", NOW - 60, NOW + 10 * YEAR);
        let ca = Ca::parse(file(&r, &[&r]).as_bytes(), NOW).unwrap();
        let (key, csr) = csr(&PKCS_ECDSA_P256_SHA256);
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
        assert!(eku.server_auth && !eku.client_auth);
        let ku = x.key_usage().unwrap().unwrap().value;
        assert!(ku.digital_signature() && !ku.key_cert_sign());
    }

    #[test]
    fn accepts_only_p256_requests() {
        assert!(requested_key(&csr(&PKCS_ECDSA_P256_SHA256).1).is_ok());
        for alg in [&rcgen::PKCS_ECDSA_P384_SHA384, &rcgen::PKCS_ED25519] {
            assert!(requested_key(&csr(alg).1).is_err(), "{alg:?}");
        }
        assert!(requested_key(b"").is_err());
    }
}
