//! What a release holds, by component, and what applying it changes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bundle::{self, Manifest};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    /// The reference without its digest.
    pub image: String,
    /// What its build calls it, else its tag.
    pub version: String,
    pub digest: String,
    #[serde(default)]
    pub dirty: bool,
}

/// The repository without its registry, tag or digest: what stays the same
/// from one release of an image to the next.
pub fn key(image: &str) -> String {
    let name = image.split('@').next().unwrap_or(image);
    let (head, last) = name.rsplit_once('/').unwrap_or(("", name));
    let last = last.split(':').next().unwrap_or(last);
    let path = match head.split_once('/') {
        _ if head.is_empty() => String::new(),
        Some((host, rest)) if registry(host) => format!("{rest}/"),
        None if registry(head) => String::new(),
        _ => format!("{head}/"),
    };
    format!("{path}{last}")
}

fn registry(host: &str) -> bool {
    host.contains(['.', ':']) || host == "localhost"
}

fn tag(image: &str) -> &str {
    let name = image.split('@').next().unwrap_or(image);
    let last = name.rsplit('/').next().unwrap_or(name);
    last.split_once(':').map_or("", |(_, t)| t)
}

fn without_digest(image: &str) -> &str {
    image.split('@').next().unwrap_or(image)
}

/// A release's images: every ref it runs, not only those its bundle carries,
/// named and versioned by its `COMPONENT_` lines where they say. `images`
/// maps each carried ref to its digest; another ref's digest is its own, else
/// its component line's.
pub fn of_release(
    manifest: &Manifest,
    refs: &BTreeSet<String>,
    images: &BTreeMap<String, String>,
) -> Vec<Component> {
    let named: BTreeMap<String, bundle::Component> = bundle::components(manifest)
        .into_iter()
        .map(|c| (key(&c.image), c))
        .collect();
    let mut out = BTreeMap::new();
    for image in refs.iter().chain(images.keys()) {
        let k = key(image);
        let c = named.get(&k);
        let digest = images
            .get(image)
            .cloned()
            .or_else(|| image.split_once('@').map(|(_, d)| d.to_string()))
            .or_else(|| c.map(|c| c.digest.clone()))
            .unwrap_or_default();
        let c = match c {
            Some(c) => Component {
                name: c.name.clone(),
                image: without_digest(image).into(),
                version: if c.version.is_empty() {
                    tag(image).into()
                } else {
                    c.version.clone()
                },
                digest,
                dirty: c.dirty == Some(true),
            },
            None => Component {
                name: k.clone(),
                image: without_digest(image).into(),
                version: tag(image).into(),
                digest,
                dirty: false,
            },
        };
        out.insert(k, c);
    }
    out.into_values().collect()
}

/// Images as workloads name them: what runs when no release says.
pub fn of_refs(refs: &BTreeSet<String>, digest: impl Fn(&str) -> Option<String>) -> Vec<Component> {
    let mut out = BTreeMap::new();
    for r in refs {
        let k = key(r);
        out.insert(
            k.clone(),
            Component {
                name: k,
                image: without_digest(r).into(),
                version: tag(r).into(),
                digest: r
                    .split_once('@')
                    .map(|(_, d)| d.to_string())
                    .or_else(|| digest(r))
                    .unwrap_or_default(),
                dirty: false,
            },
        );
    }
    out.into_values().collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Unchanged,
    Changed,
    Added,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComponentChange {
    pub name: String,
    pub change: Change,
    pub from: Option<Component>,
    pub to: Option<Component>,
}

/// `before` against `after`, by [`key`]. Without `removals_known`, what
/// `before` alone holds is left out: it may run outside any release.
pub fn components(
    before: &[Component],
    after: &[Component],
    removals_known: bool,
) -> Vec<ComponentChange> {
    let by_key = |cs: &[Component]| -> BTreeMap<String, Component> {
        cs.iter().map(|c| (key(&c.image), c.clone())).collect()
    };
    let (before, after) = (by_key(before), by_key(after));
    let keys: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter_map(|k| {
            let (from, to) = (before.get(k).cloned(), after.get(k).cloned());
            let change = match (&from, &to) {
                (Some(f), Some(t)) if same(f, t) => Change::Unchanged,
                (Some(_), Some(_)) => Change::Changed,
                (None, Some(_)) => Change::Added,
                (Some(_), None) if removals_known => Change::Removed,
                _ => return None,
            };
            let name = to.as_ref().or(from.as_ref()).map(|c| c.name.clone())?;
            Some(ComponentChange {
                name,
                change,
                from,
                to,
            })
        })
        .collect()
}

fn same(a: &Component, b: &Component) -> bool {
    if !a.digest.is_empty() && !b.digest.is_empty() {
        a.digest == b.digest
    } else {
        a.version == b.version
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Diff {
    pub components: Vec<ComponentChange>,
    pub talos: (String, String),
    pub installer: (String, String),
    pub stack: (String, String),
    pub reboot: bool,
    pub config_changes: bool,
    pub downtime_secs: i64,
    pub removals_known: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_drops_the_registry_tag_and_digest() {
        for (r, k) in [
            ("127.0.0.1:5999/edge-cni:t2", "edge-cni"),
            ("ghcr.io/maplibre/martin@sha256:aa", "maplibre/martin"),
            ("ghcr.io/o/a/b:v1@sha256:aa", "o/a/b"),
            ("nats:2", "nats"),
            ("library/nats:2", "library/nats"),
            ("localhost/app:1", "app"),
            ("reg/app", "reg/app"),
        ] {
            assert_eq!(key(r), k, "{r}");
        }
    }

    fn manifest(lines: &str) -> Manifest {
        bundle::parse_manifest(lines).unwrap()
    }

    #[test]
    fn a_release_names_its_images_by_their_component_lines() {
        let m = manifest(
            "COMPONENT_EDGE_CNI=127.0.0.1:5999/edge-cni:t2 sha256:aa v0.3-4-gabc dirty=true\n",
        );
        let images = BTreeMap::from([
            (
                "127.0.0.1:5999/edge-cni:t2".to_string(),
                "sha256:aa".to_string(),
            ),
            (
                "ghcr.io/maplibre/martin@sha256:bb".into(),
                "sha256:bb".into(),
            ),
        ]);
        assert_eq!(
            of_release(&m, &BTreeSet::new(), &images),
            [
                Component {
                    name: "edge-cni".into(),
                    image: "127.0.0.1:5999/edge-cni:t2".into(),
                    version: "v0.3-4-gabc".into(),
                    digest: "sha256:aa".into(),
                    dirty: true,
                },
                Component {
                    name: "maplibre/martin".into(),
                    image: "ghcr.io/maplibre/martin".into(),
                    version: "".into(),
                    digest: "sha256:bb".into(),
                    dirty: false,
                },
            ]
        );
    }

    #[test]
    fn a_partial_release_runs_every_ref_it_lists_not_only_those_it_carries() {
        let m = manifest("COMPONENT_ETCD=reg.io/etcd:3.6 sha256:ee 3.6.1\n");
        let refs = BTreeSet::from([
            "reg.io/gateway:2".to_string(),
            "reg.io/etcd:3.6".into(),
            "reg.io/flux@sha256:ff".into(),
            "reg.io/kube:1".into(),
        ]);
        let carried = BTreeMap::from([("reg.io/gateway:2".to_string(), "sha256:g2".to_string())]);
        let got = of_release(&m, &refs, &carried);
        assert_eq!(
            got.iter()
                .map(|c| (c.name.as_str(), c.version.as_str(), c.digest.as_str()))
                .collect::<Vec<_>>(),
            [
                ("etcd", "3.6.1", "sha256:ee"),
                ("flux", "", "sha256:ff"),
                ("gateway", "2", "sha256:g2"),
                ("kube", "1", ""),
            ]
        );
        let before = [
            c("reg.io/gateway:1", "1", "sha256:g1"),
            c("reg.io/etcd:3.6", "3.6.1", "sha256:ee"),
            c("reg.io/flux", "", "sha256:ff"),
            c("reg.io/kube:1", "1", ""),
        ];
        let changes: Vec<_> = components(&before, &got, true)
            .into_iter()
            .map(|c| (c.name, c.change))
            .collect();
        assert_eq!(
            changes,
            [
                ("etcd".to_string(), Change::Unchanged),
                ("flux".into(), Change::Unchanged),
                ("gateway".into(), Change::Changed),
                ("kube".into(), Change::Unchanged),
            ]
        );
    }

    #[test]
    fn workloads_images_are_resolved_where_they_name_no_digest() {
        let refs = BTreeSet::from([
            "reg.io/a:1".to_string(),
            "reg.io/b@sha256:bb".into(),
            "reg.io/c:v2@sha256:cc".into(),
        ]);
        let c = of_refs(&refs, |r| (r == "reg.io/a:1").then(|| "sha256:aa".into()));
        assert_eq!(
            c.iter()
                .map(|c| (c.name.as_str(), c.version.as_str(), c.digest.as_str()))
                .collect::<Vec<_>>(),
            [
                ("a", "1", "sha256:aa"),
                ("b", "", "sha256:bb"),
                ("c", "v2", "sha256:cc")
            ]
        );
    }

    fn c(image: &str, version: &str, digest: &str) -> Component {
        Component {
            name: key(image),
            image: image.into(),
            version: version.into(),
            digest: digest.into(),
            dirty: false,
        }
    }

    #[test]
    fn changes_are_by_digest_else_by_version() {
        let before = [
            c("r.io/a:1", "1", "sha256:a1"),
            c("r.io/b:1", "1", "sha256:b1"),
            c("r.io/gone:1", "1", ""),
            c("r.io/v:1", "1", ""),
        ];
        let after = [
            c("r.io/a:2", "2", "sha256:a2"),
            c("r.io/b:2", "2", "sha256:b1"),
            c("r.io/new:1", "1", "sha256:n"),
            c("r.io/v:1", "1", "sha256:v"),
        ];
        let got = |known| {
            components(&before, &after, known)
                .into_iter()
                .map(|c| (c.name, c.change))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            got(true),
            [
                ("a".to_string(), Change::Changed),
                ("b".into(), Change::Unchanged),
                ("gone".into(), Change::Removed),
                ("new".into(), Change::Added),
                ("v".into(), Change::Unchanged),
            ]
        );
        assert!(!got(false).iter().any(|(n, _)| n == "gone"));
    }
}
