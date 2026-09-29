use std::collections::BTreeMap;

use serde::Deserialize;

use crate::Digest;

pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

#[derive(Clone, Debug, Deserialize)]
pub struct Descriptor {
    pub digest: Digest,
    pub size: u64,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// An image manifest or an index, Docker's or OCI's.
#[derive(Debug)]
pub struct Manifest {
    pub media_type: String,
    pub blobs: Vec<Descriptor>,
    pub children: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Raw {
    schema_version: u32,
    media_type: Option<String>,
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
    #[serde(default)]
    manifests: Vec<Descriptor>,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Manifest, String> {
        let raw: Raw = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if raw.schema_version != 2 {
            return Err(format!("schema version {}", raw.schema_version));
        }
        // OCI makes mediaType optional; a manifest has a config and an index does not.
        let media_type = raw.media_type.unwrap_or_else(|| {
            match raw.config {
                Some(_) => OCI_MANIFEST,
                None => OCI_INDEX,
            }
            .into()
        });
        Ok(Manifest {
            media_type,
            blobs: raw.config.into_iter().chain(raw.layers).collect(),
            children: raw.manifests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> String {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
    }

    #[test]
    fn reads_manifest_and_index() {
        let m = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{}","size":1}},"layers":[{{"digest":"{}","size":2}}]}}"#,
            d(1),
            d(2)
        );
        let m = Manifest::parse(m.as_bytes()).unwrap();
        assert_eq!(m.media_type, OCI_MANIFEST);
        let blobs: Vec<String> = m.blobs.iter().map(|b| b.digest.to_string()).collect();
        assert_eq!(blobs, [d(1), d(2)]);
        assert!(m.children.is_empty());

        let docker = "application/vnd.docker.distribution.manifest.list.v2+json";
        let i = format!(
            r#"{{"schemaVersion":2,"mediaType":"{docker}","manifests":[{{"digest":"{}","size":3,"annotations":{{"k":"v"}}}}]}}"#,
            d(3)
        );
        let i = Manifest::parse(i.as_bytes()).unwrap();
        assert_eq!(i.media_type, docker);
        assert!(i.blobs.is_empty());
        assert_eq!(i.children[0].annotations["k"], "v");

        let bare = Manifest::parse(br#"{"schemaVersion":2,"manifests":[]}"#).unwrap();
        assert_eq!(bare.media_type, OCI_INDEX);
    }

    #[test]
    fn rejects_other_schemas() {
        assert!(Manifest::parse(br#"{"schemaVersion":1,"fsLayers":[]}"#).is_err());
        assert!(Manifest::parse(br#"{"manifests":[]}"#).is_err());
        let bad_digest = r#"{"schemaVersion":2,"layers":[{"digest":"md5:00","size":1}]}"#;
        assert!(Manifest::parse(bad_digest.as_bytes()).is_err());
        assert!(Manifest::parse(b"{").is_err());
    }
}
