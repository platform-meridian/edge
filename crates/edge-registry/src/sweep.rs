use std::collections::{BTreeSet, HashSet};
use std::path::Path;

use edge_common::sync_dir;

use crate::reference::repo_dir;
use crate::store::{entries, remove};
use crate::{Digest, ImageRef, Store};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub tags: usize,
    pub manifests: usize,
    pub blobs: usize,
    pub bytes: u64,
}

impl Store {
    /// Deletes everything `keep` does not reach. A tag stays when a kept reference
    /// in its repository names it or its digest; a manifest when a kept tag or
    /// digest reaches it; a blob when a kept manifest names it.
    pub fn retain(&self, keep: &[ImageRef]) -> anyhow::Result<Swept> {
        let _lock = self.lock()?;
        let live = self.live(keep)?;
        let mut swept = Swept::default();
        let mut repos = BTreeSet::new();
        for t in &live.dead_tags {
            if let Some(tag) = &t.tag {
                self.remove_tag(&t.repo, tag)?;
                repos.insert(self.tag_dir().join(repo_dir(&t.repo)));
                swept.tags += 1;
            }
        }
        for repo in &repos {
            sync_dir(repo)?;
            // Fails while it still holds a tag.
            let _ = std::fs::remove_dir(repo);
        }
        sync_dir(&self.tag_dir())?;
        (swept.manifests, swept.bytes) = sweep(&self.manifest_dir(), &live.manifests, true)?;
        let (n, bytes) = sweep(&self.blob_dir(), &live.blobs, true)?;
        swept.blobs = n;
        swept.bytes += bytes;
        Ok(swept)
    }

    /// What [`Store::retain`] would delete, deleting nothing.
    pub fn reclaimable(&self, keep: &[ImageRef]) -> anyhow::Result<Swept> {
        let live = self.live(keep)?;
        let (manifests, mbytes) = sweep(&self.manifest_dir(), &live.manifests, false)?;
        let (blobs, bbytes) = sweep(&self.blob_dir(), &live.blobs, false)?;
        Ok(Swept {
            tags: live.dead_tags.iter().filter(|t| t.tag.is_some()).count(),
            manifests,
            blobs,
            bytes: mbytes + bbytes,
        })
    }

    fn live(&self, keep: &[ImageRef]) -> anyhow::Result<Live> {
        let (kept_tags, dead_tags): (Vec<_>, Vec<_>) = self.tags()?.into_iter().partition(|t| {
            keep.iter().any(|k| {
                k.repo == t.repo
                    && ((k.tag.is_some() && k.tag == t.tag)
                        || (k.digest.is_some() && k.digest == t.digest))
            })
        });

        let mut manifests = HashSet::new();
        let mut blobs = HashSet::new();
        let mut reach: Vec<Digest> = kept_tags
            .iter()
            .chain(keep)
            .filter_map(|r| r.digest.clone())
            .collect();
        while let Some(d) = reach.pop() {
            if manifests.contains(&d) {
                continue;
            }
            let Some((children, named)) = self.children_and_blobs(&d) else {
                continue;
            };
            manifests.insert(d);
            reach.extend(children);
            blobs.extend(named);
        }
        Ok(Live {
            dead_tags,
            manifests,
            blobs,
        })
    }
}

struct Live {
    dead_tags: Vec<ImageRef>,
    manifests: HashSet<Digest>,
    blobs: HashSet<Digest>,
}

/// Counts, and if `delete` removes, what `live` does not name.
fn sweep(dir: &Path, live: &HashSet<Digest>, delete: bool) -> std::io::Result<(usize, u64)> {
    let (mut n, mut bytes) = (0, 0);
    for (name, path) in entries(dir)? {
        if Digest::from_hex(&name).is_some_and(|d| live.contains(&d)) {
            continue;
        }
        bytes += path.symlink_metadata().map_or(0, |m| m.len());
        if delete {
            remove(&path)?;
        }
        n += 1;
    }
    if delete {
        sync_dir(dir)?;
    }
    Ok((n, bytes))
}
