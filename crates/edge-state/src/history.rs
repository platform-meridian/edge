use crate::store::{EventKind, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ident {
    Object {
        resource: String,
        namespace: Option<String>,
        name: String,
    },
    Other(String),
}

impl std::fmt::Display for Ident {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ident::Object {
                resource,
                namespace: Some(ns),
                name,
            } => {
                write!(f, "{resource} {ns}/{name}")
            }
            Ident::Object {
                resource,
                namespace: None,
                name,
            } => write!(f, "{resource} {name}"),
            Ident::Other(k) => write!(f, "{k}"),
        }
    }
}

pub fn ident(key: &[u8]) -> Ident {
    let s = String::from_utf8_lossy(key);
    let Some(rest) = s.strip_prefix("/registry/") else {
        return Ident::Other(s.into_owned());
    };
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [resource, name] => Ident::Object {
            resource: (*resource).to_string(),
            namespace: None,
            name: (*name).to_string(),
        },
        [resource, ns, name] => Ident::Object {
            resource: (*resource).to_string(),
            namespace: Some((*ns).to_string()),
            name: (*name).to_string(),
        },
        [resource, tail @ ..] if !tail.is_empty() => Ident::Object {
            resource: (*resource).to_string(),
            namespace: None,
            name: tail.join("/"),
        },
        _ => Ident::Other(s.into_owned()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub revision: u64,
    pub kind: EventKind,
    pub ident: Ident,
    pub value_bytes: usize,
}

pub fn changes(store: &Store, since: u64) -> Result<Vec<Change>, u64> {
    Ok(store
        .events_since(since)?
        .into_iter()
        .map(|e| Change {
            revision: e.kv.mod_revision,
            kind: e.kind,
            ident: ident(&e.kv.key),
            value_bytes: e.kv.value.len(),
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delta {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub delta: Delta,
    pub ident: Ident,
    pub from_bytes: usize,
    pub to_bytes: usize,
}

pub fn diff(store: &Store, a: u64, b: u64) -> Result<Vec<Diff>, u64> {
    let floor = store.compact_revision();
    if a < floor || b < floor {
        return Err(floor);
    }
    let at = |rev: u64| -> std::collections::BTreeMap<Vec<u8>, usize> {
        store
            .range_from(&[], rev)
            .into_iter()
            .map(|kv| (kv.key, kv.value.len()))
            .collect()
    };
    let (before, after) = (at(a), at(b));

    let mut out = Vec::new();
    for (k, to) in &after {
        match before.get(k) {
            None => out.push(Diff {
                delta: Delta::Added,
                ident: ident(k),
                from_bytes: 0,
                to_bytes: *to,
            }),
            Some(from) if from != to => out.push(Diff {
                delta: Delta::Changed,
                ident: ident(k),
                from_bytes: *from,
                to_bytes: *to,
            }),
            // Size-only: a moved status timestamp is not a change worth reporting.
            Some(_) => {}
        }
    }
    for (k, from) in &before {
        if !after.contains_key(k) {
            out.push(Diff {
                delta: Delta::Removed,
                ident: ident(k),
                from_bytes: *from,
                to_bytes: 0,
            });
        }
    }
    out.sort_by_key(|x| x.ident.to_string());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path().join("state.log")).unwrap();
        (d, s)
    }

    #[test]
    fn keys_read_as_kubectl_names() {
        for (key, want) in [
            (
                &b"/registry/pods/kube-system/edge-cni-abc"[..],
                "pods kube-system/edge-cni-abc",
            ),
            (
                b"/registry/namespaces/kube-system",
                "namespaces kube-system",
            ),
            (
                b"/registry/leases/kube-system/apiserver/x",
                "leases kube-system/apiserver/x",
            ),
            (b"/registry/lonely", "/registry/lonely"),
            (b"/edge-state/marker", "/edge-state/marker"),
        ] {
            assert_eq!(ident(key).to_string(), want);
        }
    }

    #[test]
    fn changes_after_since_in_order() {
        let (_d, mut s) = store();
        s.put(b"/registry/pods/ns/a", b"1", 0).unwrap();
        let since = s.revision();
        s.put(b"/registry/pods/ns/b", b"22", 0).unwrap();
        s.delete(b"/registry/pods/ns/a").unwrap();

        let got: Vec<_> = changes(&s, since)
            .unwrap()
            .into_iter()
            .map(|c| (c.revision, c.kind, c.ident.to_string(), c.value_bytes))
            .collect();
        assert_eq!(
            got,
            vec![
                (since + 1, EventKind::Put, "pods ns/b".into(), 2),
                (since + 2, EventKind::Delete, "pods ns/a".into(), 0),
            ]
        );
    }

    #[test]
    fn diff_compares_by_size() {
        let (_d, mut s) = store();
        s.put(b"/registry/pods/ns/same", b"1", 0).unwrap();
        s.put(b"/registry/pods/ns/gone", b"1", 0).unwrap();
        s.put(b"/registry/pods/ns/grow", b"1", 0).unwrap();
        let a = s.revision();
        s.put(b"/registry/pods/ns/same", b"2", 0).unwrap();
        s.put(b"/registry/pods/ns/temp", b"x", 0).unwrap();
        s.delete(b"/registry/pods/ns/temp").unwrap();
        s.delete(b"/registry/pods/ns/gone").unwrap();
        s.put(b"/registry/pods/ns/grow", b"12345", 0).unwrap();
        s.put(b"/registry/pods/ns/added", b"yy", 0).unwrap();
        let b = s.revision();

        let got: Vec<_> = diff(&s, a, b)
            .unwrap()
            .into_iter()
            .map(|x| (x.delta, x.ident.to_string(), x.from_bytes, x.to_bytes))
            .collect();
        assert_eq!(
            got,
            vec![
                (Delta::Added, "pods ns/added".into(), 0, 2),
                (Delta::Removed, "pods ns/gone".into(), 1, 0),
                (Delta::Changed, "pods ns/grow".into(), 1, 5),
            ]
        );
        assert!(diff(&s, b, b).unwrap().is_empty());
    }

    #[test]
    fn refuses_history_below_floor() {
        let (_d, mut s) = store();
        s.put(b"/registry/pods/ns/p", b"1", 0).unwrap();
        let old = s.revision();
        s.put(b"/registry/pods/ns/p", b"22", 0).unwrap();
        let now = s.revision();
        s.compact(now).unwrap();
        assert_eq!(changes(&s, old), Err(now));
        assert_eq!(diff(&s, old, now), Err(now));
        assert_eq!(diff(&s, now, old), Err(now));
        assert_eq!(diff(&s, now, now), Ok(vec![]));
    }
}
