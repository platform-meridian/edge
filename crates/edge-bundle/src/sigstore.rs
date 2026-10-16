//! Sigstore keyless signatures over a bundle's `SHA256SUMS`, as
//! `cosign sign-blob --bundle` writes them, verified offline against a pinned
//! `trusted_root.json` and a signer policy.

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::Bundle;
use sigstore_verify::crypto::FulcioCiClaims;
use sigstore_verify::{VerificationPolicy, Verifier};

/// Checks a signature over a bundle's sums; says who signed.
pub trait Trust: Send + Sync {
    fn verify(&self, sums: &[u8], signature: &[u8]) -> anyhow::Result<String>;
}

/// A signer a unit trusts: a workflow, run on a ref, as an OIDC issuer vouches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signer {
    /// The certificate's OIDC issuer.
    pub issuer: String,
    /// The certificate's identity without its `@<ref>`.
    pub workflow: String,
    /// The source ref: exact, or a prefix ending in `*`.
    #[serde(rename = "ref")]
    pub source_ref: String,
}

impl Signer {
    fn check(&self) -> anyhow::Result<()> {
        ensure!(
            !self.issuer.is_empty() && !self.workflow.is_empty() && !self.source_ref.is_empty(),
            "a trusted signer names its issuer, workflow and ref"
        );
        ensure!(
            !self.workflow.contains('@'),
            "a trusted signer's workflow {:?} names no ref: that is its ref's",
            self.workflow
        );
        Ok(())
    }

    fn admits(&self, issuer: &str, identity: &str, claims: &FulcioCiClaims) -> bool {
        let Some(on) = claims.source_repository_ref.as_deref() else {
            return false;
        };
        let ref_ok = match self.source_ref.strip_suffix('*') {
            Some(prefix) => on.starts_with(prefix),
            None => on == self.source_ref,
        };
        issuer == self.issuer && ref_ok && identity == format!("{}@{on}", self.workflow)
    }
}

/// The unit's trust: Sigstore's root, and the signers it takes.
pub struct Sigstore {
    verifier: Verifier,
    signers: Vec<Signer>,
}

impl Sigstore {
    pub fn new(trusted_root: &str, signers: Vec<Signer>) -> anyhow::Result<Self> {
        ensure!(!signers.is_empty(), "the trust policy names no signer");
        for s in &signers {
            s.check()?;
        }
        let root = TrustedRoot::from_json(trusted_root).context("the trusted root")?;
        let verifier = Verifier::new(&root).context("the trusted root")?;
        Ok(Self { verifier, signers })
    }
}

impl Trust for Sigstore {
    fn verify(&self, sums: &[u8], signature: &[u8]) -> anyhow::Result<String> {
        let bundle = std::str::from_utf8(signature)
            .ok()
            .and_then(|s| Bundle::from_json(s).ok())
            .context("the signature is not a Sigstore bundle")?;
        let r = self
            .verifier
            .verify(sums, &bundle, &VerificationPolicy::any_identity())
            .map_err(|e| anyhow::anyhow!("the signature does not verify: {e}"))?;
        ensure!(
            r.certificate_verified() && r.sct_verified() && r.tlog_verified(),
            "the signature was not checked in full"
        );
        let identity = r.identity().map(|i| i.as_str()).unwrap_or_default();
        let issuer = r.issuer().unwrap_or_default();
        let claims = &r
            .certificate()
            .context("the signature has no certificate")?
            .ci_claims;
        ensure!(
            self.signers
                .iter()
                .any(|s| s.admits(issuer, identity, claims)),
            "{identity} ({issuer}, on {}) is not a signer this unit trusts",
            claims.source_repository_ref.as_deref().unwrap_or("no ref")
        );
        Ok(identity.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = include_str!("../tests/fixtures/sigstore/trusted_root.json");
    const SUMS: &[u8] = include_bytes!("../tests/fixtures/sigstore/goreleaser_checksums.txt");
    const SIGNED: &[u8] =
        include_bytes!("../tests/fixtures/sigstore/goreleaser_checksums.txt.sigstore.json");
    const GHA: &str = "https://token.actions.githubusercontent.com";
    const WORKFLOW: &str = "https://github.com/goreleaser/goreleaser/.github/workflows/release.yml";

    fn signer(issuer: &str, workflow: &str, on: &str) -> Signer {
        Signer {
            issuer: issuer.into(),
            workflow: workflow.into(),
            source_ref: on.into(),
        }
    }

    fn trust(signers: &[Signer]) -> Sigstore {
        Sigstore::new(ROOT, signers.to_vec()).unwrap()
    }

    fn refused(t: &Sigstore, sums: &[u8], sig: &[u8], why: &str) {
        let e = format!("{:#}", t.verify(sums, sig).unwrap_err());
        assert!(e.contains(why), "want {why:?}, got {e:?}");
    }

    // goreleaser v2.18.3's release signature.
    #[test]
    fn a_release_workflows_signature_verifies_offline() {
        let t = trust(&[signer(GHA, WORKFLOW, "refs/tags/*")]);
        assert_eq!(
            t.verify(SUMS, SIGNED).unwrap(),
            format!("{WORKFLOW}@refs/tags/v2.18.3")
        );
        let exact = trust(&[signer(GHA, WORKFLOW, "refs/tags/v2.18.3")]);
        exact.verify(SUMS, SIGNED).unwrap();
    }

    #[test]
    fn another_signer_is_refused() {
        let not_trusted = "is not a signer this unit trusts";
        for s in [
            signer(GHA, WORKFLOW, "refs/heads/*"),
            signer(GHA, WORKFLOW, "refs/tags/v2.18.4"),
            signer(
                GHA,
                "https://github.com/evil/goreleaser/.github/workflows/release.yml",
                "refs/tags/*",
            ),
            signer("https://accounts.google.com", WORKFLOW, "refs/tags/*"),
        ] {
            refused(&trust(&[s]), SUMS, SIGNED, not_trusted);
        }
    }

    #[test]
    fn edited_sums_are_refused() {
        let t = trust(&[signer(GHA, WORKFLOW, "refs/tags/*")]);
        let mut sums = SUMS.to_vec();
        sums.push(b'x');
        refused(&t, &sums, SIGNED, "does not verify");
        refused(&t, SUMS, b"not json", "not a Sigstore bundle");
    }

    #[test]
    fn a_corrupt_inclusion_proof_is_refused() {
        let t = trust(&[signer(GHA, WORKFLOW, "refs/tags/*")]);
        let mut b: serde_json::Value = serde_json::from_slice(SIGNED).unwrap();
        let hashes = &mut b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"];
        let h = hashes[0].as_str().unwrap();
        // Another valid base64 hash: one character changed.
        let flipped = if h.starts_with('A') { "B" } else { "A" };
        hashes[0] = format!("{flipped}{}", &h[1..]).into();
        refused(
            &t,
            SUMS,
            &serde_json::to_vec(&b).unwrap(),
            "does not verify",
        );
    }

    #[test]
    fn a_root_without_the_log_is_refused() {
        let mut root: serde_json::Value = serde_json::from_str(ROOT).unwrap();
        root["tlogs"] = serde_json::json!([]);
        let t = Sigstore::new(
            &root.to_string(),
            vec![signer(GHA, WORKFLOW, "refs/tags/*")],
        )
        .unwrap();
        refused(&t, SUMS, SIGNED, "does not verify");
    }

    #[test]
    fn a_policy_names_whole_signers() {
        assert!(Sigstore::new(ROOT, vec![]).is_err());
        assert!(Sigstore::new(ROOT, vec![signer(GHA, "", "refs/tags/*")]).is_err());
        assert!(Sigstore::new(ROOT, vec![signer(GHA, &format!("{WORKFLOW}@x"), "x")]).is_err());
        assert!(Sigstore::new("{}", vec![signer(GHA, WORKFLOW, "refs/tags/*")]).is_err());
    }
}
