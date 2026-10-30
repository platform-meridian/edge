//! A layout of apps (ADR-0015 §7), as `meridian-app export` writes it: each
//! artifact and image a root named by its full reference, each signature a
//! referrer named by its repository alone, its manifest's `subject` the root it
//! signs. Imported as the instance registry holds what core uploads: every
//! repository relocated under the registry's own name, and each signature
//! listed in its subject's OCI 1.1 referrers fallback tag (`sha256-<hex>`), an
//! image index, which is where a client of a registry without the referrers
//! API looks.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Value, json};

use crate::{Digest, ImageRef, Store};

const REF_NAME: &str = "org.opencontainers.image.ref.name";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// `name`'s repository under `host`, its own registry dropped.
fn relocated(name: &str, host: &str) -> anyhow::Result<String> {
    let (_, path) = name
        .split_once('/')
        .with_context(|| format!("{name:?} names no registry"))?;
    Ok(format!("{host}/{path}"))
}

/// The OCI 1.1 referrers fallback tag of `subject`.
pub fn fallback_tag(subject: &Digest) -> String {
    format!("sha256-{}", subject.hex())
}

impl Store {
    /// Imports an apps layout, relocated under `host`. Returns what it tagged.
    pub fn import_apps(&self, layout: &Path, host: &str) -> anyhow::Result<Vec<ImageRef>> {
        self.import_layout_untagged(layout)?;
        let index: Value = serde_json::from_slice(
            &std::fs::read(layout.join("index.json")).context("reading index.json")?,
        )
        .context("parsing index.json")?;
        let mut referrers: BTreeMap<(String, Digest), Vec<Value>> = BTreeMap::new();
        let mut tagged = Vec::new();
        let _lock = self.lock()?;
        for d in index["manifests"].as_array().map(Vec::as_slice).unwrap_or_default() {
            let digest: Digest = d["digest"]
                .as_str()
                .context("an index entry names no digest")?
                .parse()
                .map_err(anyhow::Error::msg)?;
            let name = d["annotations"][REF_NAME]
                .as_str()
                .with_context(|| format!("index entry {digest} names no reference"))?;
            let (_, bytes) = self
                .manifest(&digest)?
                .with_context(|| format!("{digest} was not imported"))?;
            let m: Value = serde_json::from_slice(&bytes)?;
            if let Some(subject) = m["subject"]["digest"].as_str() {
                let subject: Digest = subject.parse().map_err(anyhow::Error::msg)?;
                let mut entry = json!({
                    "mediaType": m["mediaType"],
                    "digest": digest.to_string(),
                    "size": bytes.len(),
                });
                if let Some(t) = m["artifactType"].as_str() {
                    entry["artifactType"] = json!(t);
                }
                referrers
                    .entry((relocated(name, host)?, subject))
                    .or_default()
                    .push(entry);
                continue;
            }
            let r: ImageRef = relocated(name, host)?
                .parse()
                .map_err(|e: String| anyhow::anyhow!("{name}: {e}"))?;
            let Some(tag) = &r.tag else {
                bail!("{name} names no tag, so nothing would keep it");
            };
            self.set_tag(&r.repo, tag, &digest)
                .with_context(|| format!("tagging {}:{tag}", r.repo))?;
            tagged.push(ImageRef {
                digest: Some(digest),
                ..r
            });
        }
        for ((repo, subject), mut entries) in referrers {
            let tag = fallback_tag(&subject);
            if let Some(held) = self.resolve(&repo, &tag)
                && let Some((_, bytes)) = self.manifest(&held)?
            {
                let held: Value = serde_json::from_slice(&bytes)?;
                for e in held["manifests"].as_array().cloned().unwrap_or_default() {
                    if !entries.iter().any(|x| x["digest"] == e["digest"]) {
                        entries.push(e);
                    }
                }
            }
            let index = serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": OCI_INDEX,
                "manifests": entries,
            }))?;
            let digest = Digest::of(&index);
            self.put_manifest(&digest, &index)?;
            self.set_tag(&repo, &tag, &digest)?;
            tagged.push(ImageRef {
                repo,
                tag: Some(tag),
                digest: Some(digest),
            });
        }
        Ok(tagged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_is_relocated_under_the_registry() {
        assert_eq!(
            relocated("127.0.0.1:5999/platform-meridian/platform-core/app:v1", "127.0.0.1:5000").unwrap(),
            "127.0.0.1:5000/platform-meridian/platform-core/app:v1"
        );
        assert!(relocated("nohost", "h").is_err());
    }
}
