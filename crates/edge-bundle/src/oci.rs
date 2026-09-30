//! A bundle's images: one OCI image layout, every image named in its index by
//! `io.containerd.image.name`, as the unit's registry imports it.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;

pub const NAME: &str = "io.containerd.image.name";

/// The refs an OCI image layout names, from its index.
pub fn layout_refs(layout: &Path) -> anyhow::Result<BTreeSet<String>> {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(layout.join("index.json")).context("the image layout's index")?,
    )?;
    let mut refs = BTreeSet::new();
    for m in index["manifests"]
        .as_array()
        .context("the index lists no manifests")?
    {
        let a = &m["annotations"];
        let name = a[NAME]
            .as_str()
            .or_else(|| a["org.opencontainers.image.ref.name"].as_str())
            .context("an index entry names no image")?;
        refs.insert(name.to_string());
    }
    Ok(refs)
}
