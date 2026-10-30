//! What a bundle brings: the OS's refs, every image its machine config names.
//! Apps are `MeridianApp`s, which bring their own.
//!
//! Anti-rollback is the OS's, by `BUILT_EPOCH`. The same build again is taken.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const COMPONENTS: &str = "components.json";

/// A bundle's `components.json`: the OS's refs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub base: BTreeSet<String>,
}

impl Components {
    /// Every ref the OS runs.
    pub fn refs(&self) -> BTreeSet<String> {
        self.base.clone()
    }

    pub fn read(dir: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read(dir.join(COMPONENTS)).context("reading the components")?;
        serde_json::from_slice(&text)
            .context("the components are not an OS's: a bundle brings the OS alone")
    }
}
