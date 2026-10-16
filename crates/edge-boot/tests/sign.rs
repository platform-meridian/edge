//! Signing with keys in software: what the TPM's keys sign, checked against their public keys.

use base64::Engine;
use edge_boot::testkit::{CERT, Soft, image, uki};
use edge_boot::{Phases, der, measure, pe};
use sha2::{Digest, Sha256};

fn items(mut b: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let item = der::next(b).unwrap();
        b = &b[item.1.len()..];
        out.push(item);
    }
    out
}

/// The signature's signed attributes check against the image, and verify.
fn check_authenticode(soft: &Soft, signed: &[u8]) {
    let parsed = pe::Pe::parse(signed).unwrap();
    assert!(parsed.sections.len() > 1);
    let opt = u32::from_le_bytes(signed[0x3c..0x40].try_into().unwrap()) as usize + 24;
    let at = u32::from_le_bytes(signed[opt + 144..opt + 148].try_into().unwrap()) as usize;
    assert!(at > 0 && at.is_multiple_of(8));
    let unsigned = pe::unsigned(signed.to_vec()).unwrap();
    let digest = pe::Pe::parse(&unsigned)
        .unwrap()
        .authenticode_digest()
        .unwrap();

    // ContentInfo → [0] → SignedData: version, digests, content, [0] certificates, signers.
    let (_, _, ci) = der::next(&signed[at + 8..]).unwrap();
    let ci = items(ci);
    let sd = items(der::next(ci[1].2).unwrap().2);
    // content: OID, [0] SpcIndirectDataContent
    let content = items(sd[2].2);
    let indirect = der::next(content[1].2).unwrap().2;
    assert!(
        indirect.windows(32).any(|w| w == digest),
        "the content names the image's digest"
    );
    assert_eq!(sd[3].2, CERT);
    let fields = items(der::next(sd[4].2).unwrap().2);
    let attrs = [&[0x31][..], &fields[3].1[1..]].concat();
    let indirect_digest = Sha256::digest(indirect);
    assert!(attrs.windows(32).any(|w| w == indirect_digest.as_slice()));
    soft.verify(&attrs, fields[5].2);
}

#[test]
fn an_image_is_signed_with_the_secure_boot_key() {
    let soft = Soft::default();
    let boot = image(&[(".text", &[0xc3; 700]), (".sbat", b"sbat,1\n")]);
    let signed = edge_boot::sign_image(&soft, boot).unwrap();
    check_authenticode(&soft, &signed);
    // Signing again replaces the signature.
    let again = edge_boot::sign_image(&soft, signed.clone()).unwrap();
    assert_eq!(again.len(), signed.len());
    check_authenticode(&soft, &again);

    if let Ok(dir) = tempfile_dir() {
        let (img, cert) = (dir.join("img.efi"), dir.join("cert.pem"));
        std::fs::write(&img, &signed).unwrap();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(CERT)
        );
        std::fs::write(&cert, pem).unwrap();
        if let Ok(out) = std::process::Command::new("sbverify")
            .arg("--cert")
            .arg(&cert)
            .arg(&img)
            .output()
        {
            assert!(
                out.status.success(),
                "sbverify: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

fn tempfile_dir() -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("edge-boot-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn a_uki_gets_the_pcr_key_and_a_signed_policy_per_profile() {
    let soft = Soft::default();
    let uki = uki();
    let phases = Phases {
        signed: vec!["enter-initrd:leave-initrd:enter-machined".into()],
        running: "enter-initrd:leave-initrd:enter-machined:start-the-world".into(),
    };
    let signed = edge_boot::sign_uki(&soft, uki, &phases).unwrap();
    check_authenticode(&soft, &signed);

    let pe = pe::Pe::parse(&signed).unwrap();
    let names: Vec<&str> = pe.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            ".text", ".sbat", ".reloc", ".osrel", ".cmdline", ".linux", ".initrd", ".pcrpkey",
            ".profile", ".pcrsig", ".profile", ".cmdline", ".pcrsig"
        ]
    );
    let get = |i: usize| pe.contents(&pe.sections[i]);
    let pcrpkey = std::str::from_utf8(get(7)).unwrap();
    assert!(pcrpkey.starts_with("-----BEGIN PUBLIC KEY-----\n"));

    let base = |name: &str| match name {
        ".sbat" => Some(get(1)),
        ".osrel" => Some(get(3)),
        ".cmdline" => Some(get(4)),
        ".linux" => Some(get(5)),
        ".initrd" => Some(get(6)),
        ".pcrpkey" => Some(get(7)),
        _ => None,
    };
    let path = ["enter-initrd", "leave-initrd", "enter-machined"];
    for (profile, sig, cmdline) in [(8, 9, get(4)), (10, 12, get(11))] {
        let measured = |name: &str| match name {
            ".profile" => Some(get(profile)),
            ".cmdline" => Some(cmdline),
            n => base(n),
        };
        let pol = measure::policy_pcr(&measure::pcr(measured, &path));
        let json: serde_json::Value = serde_json::from_slice(get(sig)).unwrap();
        let bank = &json["sha256"][0];
        assert_eq!(bank["pcrs"], serde_json::json!([11]));
        assert_eq!(bank["pol"], hex::encode(pol));
        let pkcs1 = der::rsa_pkcs1(&soft.modulus(), 65537);
        assert_eq!(bank["pkfp"], hex::encode(Sha256::digest(pkcs1)));
        let s = base64::engine::general_purpose::STANDARD
            .decode(bank["sig"].as_str().unwrap())
            .unwrap();
        soft.verify(&pol, &s);
    }

    // The first profile's running OS is granted.
    let main = |name: &str| {
        if name == ".profile" {
            Some(get(8))
        } else {
            base(name)
        }
    };
    let running = [&path[..], &["start-the-world"]].concat();
    assert_eq!(
        *soft.granted.lock().unwrap(),
        [measure::policy_pcr(&measure::pcr(main, &running))]
    );

    // A signed UKI signs again to the same sections.
    let again = edge_boot::sign_uki(&soft, signed.clone(), &phases).unwrap();
    let pe2 = pe::Pe::parse(&again).unwrap();
    assert_eq!(pe2.sections.len(), pe.sections.len());
}
