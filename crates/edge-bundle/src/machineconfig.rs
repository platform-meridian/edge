//! A bundle carries the build's machine config without the unit's secrets and
//! identity (a patch). The unit's next config is the patch with the unit's own
//! material put back, so the unit's secrets never travel.

use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use serde_yaml::{Mapping, Value};

/// In the v1alpha1 document. Secrets, then the unit's identity.
const V1_HELD: &[&[&str]] = &[
    &["machine", "token"],
    &["machine", "ca"],
    &["machine", "acceptedCAs"],
    &["machine", "registries"],
    &["machine", "files"],
    &["machine", "systemDiskEncryption"],
    &["cluster", "id"],
    &["cluster", "secret"],
    &["cluster", "token"],
    &["cluster", "ca"],
    &["cluster", "acceptedCAs"],
    &["cluster", "aggregatorCA"],
    &["cluster", "serviceAccount"],
    &["cluster", "aescbcEncryptionSecret"],
    &["cluster", "secretboxEncryptionSecret"],
    &["cluster", "etcd", "ca"],
    &["machine", "certSANs"],
    &["machine", "network"],
    &["cluster", "clusterName"],
    &["cluster", "controlPlane"],
    &["cluster", "apiServer", "certSANs"],
    // Create-only bootstrap seeds, rendered with the unit's values.
    &["cluster", "inlineManifests"],
];

/// Whole documents the unit keeps. Secrets, then the unit's identity.
const HELD_KINDS: &[&str] = &[
    "DiscoveryIdentityConfig",
    "KubeAPIServerCAConfig",
    "KubeAggregatorCAConfig",
    "KubeServiceAccountConfig",
    "KubeEtcdEncryptionConfig",
    "EtcFileConfig",
    "RegistryAuthConfig",
    "RegistryTLSConfig",
    "HostnameConfig",
    "KubeClusterConfig",
    "ResolverConfig",
    "LinkConfig",
    "LinkAliasConfig",
    "DummyLinkConfig",
    "BondConfig",
    "BridgeConfig",
    "VLANConfig",
    "WireguardConfig",
    "Layer2VIPConfig",
    "HCloudVIPConfig",
    "DHCPv4Config",
    "DHCPv6Config",
    "EthernetConfig",
    "RouteConfig",
    "RoutingRuleConfig",
];

/// Fields the unit keeps inside documents the build owns.
const HELD_FIELDS: &[(&str, &str)] = &[
    ("VolumeConfig", "encryption"),
    ("UserVolumeConfig", "encryption"),
    ("RawVolumeConfig", "encryption"),
    ("SwapVolumeConfig", "encryption"),
    ("KubeAPIServerConfig", "certExtraSANs"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Key {
    V1alpha1,
    Typed(String, String),
}

fn key(doc: &Value) -> anyhow::Result<Key> {
    let m = doc
        .as_mapping()
        .context("a config document is not a mapping")?;
    if let Some(kind) = m.get("kind") {
        let kind = kind.as_str().context("a document's kind is not a string")?;
        let name = m.get("name").and_then(Value::as_str).unwrap_or_default();
        return Ok(Key::Typed(kind.into(), name.into()));
    }
    ensure!(
        m.get("version").and_then(Value::as_str) == Some("v1alpha1"),
        "a document has neither a kind nor version: v1alpha1"
    );
    Ok(Key::V1alpha1)
}

fn parse(text: &str) -> anyhow::Result<Vec<(Key, Value)>> {
    let mut docs: Vec<(Key, Value)> = Vec::new();
    for de in serde_yaml::Deserializer::from_str(text) {
        let doc = Value::deserialize(de).context("the config is not YAML")?;
        if doc.is_null() {
            continue;
        }
        let k = key(&doc)?;
        ensure!(
            !docs.iter().any(|(d, _)| *d == k),
            "the config has two {k:?} documents"
        );
        docs.push((k, doc));
    }
    Ok(docs)
}

fn render(docs: &[(Key, Value)]) -> anyhow::Result<String> {
    let mut out = String::new();
    for (_, doc) in docs {
        if !out.is_empty() {
            out.push_str("---\n");
        }
        out.push_str(&serde_yaml::to_string(doc)?);
    }
    Ok(out)
}

fn get<'a>(doc: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(doc, |v, k| v.as_mapping()?.get(*k))
}

fn remove(doc: &mut Value, path: &[&str]) -> Option<Value> {
    let (last, parents) = path.split_last()?;
    let mut v = doc;
    for k in parents {
        v = v.as_mapping_mut()?.get_mut(*k)?;
    }
    v.as_mapping_mut()?.remove(*last)
}

fn set(doc: &mut Value, path: &[&str], value: Value) -> anyhow::Result<()> {
    let (last, parents) = path.split_last().context("empty path")?;
    let mut v = doc;
    for k in parents {
        let m = v.as_mapping_mut().context("not a mapping")?;
        v = m
            .entry(Value::from(*k))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
    }
    v.as_mapping_mut()
        .context("not a mapping")?
        .insert(Value::from(*last), value);
    Ok(())
}

fn held_kind(k: &Key) -> bool {
    matches!(k, Key::Typed(kind, _) if HELD_KINDS.contains(&kind.as_str()))
}

fn held_fields(k: &Key) -> impl Iterator<Item = &'static str> + '_ {
    HELD_FIELDS.iter().filter_map(move |(kind, field)| match k {
        Key::Typed(k, _) if k == kind => Some(*field),
        _ => None,
    })
}

fn describe(k: &Key) -> String {
    match k {
        Key::V1alpha1 => "v1alpha1".into(),
        Key::Typed(kind, name) => format!("{kind} {name}").trim_end().into(),
    }
}

/// What the unit keeps, for building a patch: the rest of `full`.
pub fn strip(full: &str) -> anyhow::Result<String> {
    let mut docs = parse(full)?;
    docs.retain(|(k, _)| !held_kind(k));
    for (k, doc) in &mut docs {
        if *k == Key::V1alpha1 {
            for path in V1_HELD {
                remove(doc, path);
            }
        }
        for field in held_fields(k).collect::<Vec<_>>() {
            remove(doc, &[field]);
        }
    }
    render(&docs)
}

/// A patch may carry nothing the unit keeps.
pub fn check_patch(patch: &str) -> anyhow::Result<()> {
    let docs = parse(patch)?;
    ensure!(
        docs.iter().any(|(k, _)| *k == Key::V1alpha1),
        "the patch has no v1alpha1 document"
    );
    for (k, doc) in &docs {
        ensure!(
            !held_kind(k),
            "the patch carries {}, which the unit keeps",
            describe(k)
        );
        if *k == Key::V1alpha1 {
            for path in V1_HELD {
                ensure!(
                    get(doc, path).is_none(),
                    "the patch carries {}, which the unit keeps",
                    path.join(".")
                );
            }
        }
        for field in held_fields(k) {
            ensure!(
                get(doc, &[field]).is_none(),
                "the patch carries {}.{field}, which the unit keeps",
                describe(k)
            );
        }
    }
    Ok(())
}

/// Everything the unit keeps, in a comparable form.
fn held(docs: &[(Key, Value)]) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for (k, doc) in docs {
        if held_kind(k) {
            out.push((describe(k), doc.clone()));
        }
        if *k == Key::V1alpha1 {
            for path in V1_HELD {
                if let Some(v) = get(doc, path) {
                    out.push((path.join("."), v.clone()));
                }
            }
        }
        for field in held_fields(k) {
            if let Some(v) = get(doc, &[field]) {
                out.push((format!("{}.{field}", describe(k)), v.clone()));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The unit's next config: `patch`, with what the unit keeps taken from `unit`.
pub fn merge(unit: &str, patch: &str) -> anyhow::Result<String> {
    check_patch(patch)?;
    let unit = parse(unit)?;
    let patch = parse(patch)?;
    let find = |k: &Key| unit.iter().find(|(u, _)| u == k).map(|(_, d)| d);
    let unit_v1 = find(&Key::V1alpha1).context("the unit's config has no v1alpha1 document")?;

    let mut out: Vec<(Key, Value)> = Vec::new();
    let mut expected = held(&unit);
    for (k, doc) in &patch {
        let mut doc = doc.clone();
        if *k == Key::V1alpha1 {
            for path in V1_HELD {
                if let Some(v) = get(unit_v1, path) {
                    set(&mut doc, path, v.clone())?;
                }
            }
        }
        for field in held_fields(k) {
            let theirs = find(k).and_then(|d| get(d, &[field]));
            match theirs {
                Some(v) => set(&mut doc, &[field], v.clone())?,
                None if field == "encryption" && find(k).is_none() => {
                    if let Some(v) = new_volume_encryption(&unit, k)? {
                        expected.push((format!("{}.{field}", describe(k)), v.clone()));
                        set(&mut doc, &[field], v)?;
                    }
                }
                None => {}
            }
        }
        out.push((k.clone(), doc));
    }
    for (k, doc) in &unit {
        if out.iter().any(|(o, _)| o == k) {
            continue;
        }
        if held_kind(k) {
            out.push((k.clone(), doc.clone()));
            continue;
        }
        // A document the build no longer renders goes, unless it holds the unit's.
        let fields: Vec<_> = held_fields(k)
            .filter_map(|f| get(doc, &[f]).map(|v| (f, v.clone())))
            .collect();
        if fields.is_empty() {
            continue;
        }
        let mut kept = Mapping::new();
        for h in ["apiVersion", "kind", "name"] {
            if let Some(v) = doc.as_mapping().and_then(|m| m.get(h)) {
                kept.insert(Value::from(h), v.clone());
            }
        }
        for (f, v) in fields {
            kept.insert(Value::from(f), v);
        }
        out.push((k.clone(), Value::Mapping(kept)));
    }

    // Whatever the rules above say, the unit's own material leaves unchanged.
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    if expected != held(&out) {
        bail!("merging would change what the unit keeps");
    }
    render(&out)
}

/// Documents a component adds to the base's: each of a kind and name, none the unit's.
pub fn check_part(part: &str) -> anyhow::Result<()> {
    for (k, _) in parse(part)? {
        ensure!(
            matches!(&k, Key::Typed(_, n) if !n.is_empty()),
            "{} is not a named document a component can add",
            describe(&k)
        );
        ensure!(!held_kind(&k), "{} is the unit's to keep", describe(&k));
    }
    Ok(())
}

/// `patch` without the documents `parts` carry, by kind and name.
pub fn without(patch: &str, parts: &[&str]) -> anyhow::Result<String> {
    let mut theirs = Vec::new();
    for p in parts {
        theirs.extend(parse(p)?.into_iter().map(|(k, _)| k));
    }
    let mut docs = parse(patch)?;
    docs.retain(|(k, _)| !theirs.contains(k));
    render(&docs)
}

/// Patches as one; a document two of them carry is refused.
pub fn join(patches: &[&str]) -> anyhow::Result<String> {
    let mut docs: Vec<(Key, Value)> = Vec::new();
    for p in patches {
        for (k, d) in parse(p)? {
            ensure!(
                !docs.iter().any(|(o, _)| *o == k),
                "two components carry {}",
                describe(&k)
            );
            docs.push((k, d));
        }
    }
    render(&docs)
}

/// A user volume new to the unit is keyed like the unit's other user volumes.
fn new_volume_encryption(unit: &[(Key, Value)], k: &Key) -> anyhow::Result<Option<Value>> {
    let Key::Typed(kind, name) = k else {
        return Ok(None);
    };
    if kind != "UserVolumeConfig" {
        return Ok(None);
    }
    let mut seen: Option<&Value> = None;
    let mut any_plain = false;
    for (u, doc) in unit {
        if !matches!(u, Key::Typed(uk, _) if uk == kind) {
            continue;
        }
        match get(doc, &["encryption"]) {
            Some(e) if seen.is_none_or(|s| s == e) => seen = Some(e),
            Some(_) => bail!(
                "the unit's user volumes are keyed differently, so the new volume {name} has no one key to take"
            ),
            None => any_plain = true,
        }
    }
    if seen.is_some() && any_plain {
        bail!(
            "the unit's user volumes are partly encrypted, so the new volume {name} has no one key to take"
        );
    }
    Ok(seen.cloned())
}

const ROTATION: &[&str] = &["config", "serverTLSBootstrap"];

fn kubelet(docs: &mut [(Key, Value)]) -> Option<&mut Value> {
    docs.iter_mut()
        .find(|(k, _)| matches!(k, Key::Typed(kind, _) if kind == "KubeletConfig"))
        .map(|(_, d)| d)
}

/// The kubelet asks for its serving certificate by CSR, which waits for an approver.
pub fn serving_rotation(config: &str) -> anyhow::Result<bool> {
    let mut docs = parse(config)?;
    Ok(kubelet(&mut docs).is_some_and(|d| get(d, ROTATION) == Some(&Value::Bool(true))))
}

/// `next` as `running` has it for serving rotation, and whether that held it back:
/// the approver comes with the stack, so turning it on waits for it.
pub fn rotation_as_running(next: &str, running: &str) -> anyhow::Result<(String, bool)> {
    if !serving_rotation(next)? || serving_rotation(running)? {
        return Ok((next.into(), false));
    }
    let mut docs = parse(next)?;
    if let Some(d) = kubelet(&mut docs) {
        remove(d, ROTATION);
    }
    Ok((render(&docs)?, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: &str = r#"version: v1alpha1
machine:
  type: init
  token: unit-machine-token
  ca:
    crt: unit-os-ca-crt
    key: unit-os-ca-key
  certSANs: [unit-a]
  sysctls:
    vm.dirty_ratio: "20"
  network:
    interfaces:
      - interface: dummy1
cluster:
  token: unit-bootstrap-token
  etcd:
    ca:
      crt: unit-etcd-crt
      key: unit-etcd-key
    image: store:old
  inlineManifests:
    - name: seed
      contents: unit-a
---
apiVersion: v1alpha1
kind: KubeAPIServerCAConfig
issuingCA:
  cert: unit-k8s-ca
  key: unit-k8s-ca-key
---
apiVersion: v1alpha1
kind: DiscoveryIdentityConfig
clusterID: unit-cluster-id
clusterSecret: unit-cluster-secret
---
apiVersion: v1alpha1
kind: HostnameConfig
hostname: unit-a
---
apiVersion: v1alpha1
kind: KubeAPIServerConfig
image: apiserver:old
certExtraSANs: [unit-a, 10.50.0.1]
---
apiVersion: v1alpha1
kind: VolumeConfig
name: STATE
encryption:
  provider: luks2
  keys: [{slot: 0, tpm: {}}]
---
apiVersion: v1alpha1
kind: UserVolumeConfig
name: data
provisioning:
  minSize: 1GB
encryption:
  provider: luks2
  keys: [{slot: 0, static: {passphrase: unit-recovery-key}}]
---
apiVersion: v1alpha1
kind: EtcFileConfig
name: signer/ca.pem
contents: unit-signer-ca-key
---
apiVersion: v1alpha1
kind: KubePrismConfig
port: 7445
"#;

    const PATCH: &str = r#"version: v1alpha1
machine:
  type: init
  sysctls:
    vm.dirty_ratio: "10"
cluster:
  etcd:
    image: store:new
---
apiVersion: v1alpha1
kind: KubeAPIServerConfig
image: apiserver:new
---
apiVersion: v1alpha1
kind: UserVolumeConfig
name: data
provisioning:
  minSize: 2GB
---
apiVersion: v1alpha1
kind: UserVolumeConfig
name: fresh
provisioning:
  minSize: 1GB
---
apiVersion: v1alpha1
kind: KubeletConfig
image: kubelet:new
"#;

    fn doc<'a>(docs: &'a [(Key, Value)], kind: &str, name: &str) -> Option<&'a Value> {
        let k = if kind == "v1alpha1" {
            Key::V1alpha1
        } else {
            Key::Typed(kind.into(), name.into())
        };
        docs.iter().find(|(d, _)| *d == k).map(|(_, v)| v)
    }

    fn s(v: Option<&Value>) -> String {
        serde_yaml::to_string(&v.cloned().unwrap_or(Value::Null)).unwrap()
    }

    #[test]
    fn build_wins_where_it_owns() {
        let out = parse(&merge(UNIT, PATCH).unwrap()).unwrap();
        let v1 = doc(&out, "v1alpha1", "").unwrap();
        assert_eq!(s(get(v1, &["cluster", "etcd", "image"])), "store:new\n");
        assert_eq!(
            s(get(v1, &["machine", "sysctls", "vm.dirty_ratio"])),
            "'10'\n"
        );
        let api = doc(&out, "KubeAPIServerConfig", "").unwrap();
        assert_eq!(s(get(api, &["image"])), "apiserver:new\n");
        assert!(doc(&out, "KubeletConfig", "").is_some());
        let data = doc(&out, "UserVolumeConfig", "data").unwrap();
        assert_eq!(s(get(data, &["provisioning", "minSize"])), "2GB\n");
    }

    #[test]
    fn unit_keeps_its_secrets_and_identity() {
        let unit = parse(UNIT).unwrap();
        let out = parse(&merge(UNIT, PATCH).unwrap()).unwrap();
        let mut kept = held(&out);
        kept.retain(|(k, _)| k != "UserVolumeConfig fresh.encryption");
        assert_eq!(held(&unit), kept);
        let v1 = doc(&out, "v1alpha1", "").unwrap();
        assert_eq!(s(get(v1, &["machine", "token"])), "unit-machine-token\n");
        assert_eq!(
            s(get(v1, &["cluster", "etcd", "ca", "key"])),
            "unit-etcd-key\n"
        );
        assert!(get(v1, &["machine", "network", "interfaces"]).is_some());
        assert!(doc(&out, "KubeAPIServerCAConfig", "").is_some());
        assert!(doc(&out, "EtcFileConfig", "signer/ca.pem").is_some());
        let api = doc(&out, "KubeAPIServerConfig", "").unwrap();
        assert_eq!(s(get(api, &["certExtraSANs"])), "- unit-a\n- 10.50.0.1\n");
        let state = doc(&out, "VolumeConfig", "STATE").unwrap();
        assert!(get(state, &["encryption"]).is_some());
    }

    #[test]
    fn new_user_volume_takes_the_units_key() {
        let out = parse(&merge(UNIT, PATCH).unwrap()).unwrap();
        let fresh = doc(&out, "UserVolumeConfig", "fresh").unwrap();
        assert_eq!(
            get(fresh, &["encryption"]),
            get(
                doc(&parse(UNIT).unwrap(), "UserVolumeConfig", "data").unwrap(),
                &["encryption"]
            )
        );
    }

    #[test]
    fn build_drops_what_it_stopped_rendering() {
        let out = parse(&merge(UNIT, PATCH).unwrap()).unwrap();
        assert!(doc(&out, "KubePrismConfig", "").is_none());
    }

    #[test]
    fn static_hosts_are_the_builds() {
        let hosts = "---\napiVersion: v1alpha1\nkind: StaticHostConfig\nname: 127.0.0.1\nhostnames: [a.example]\n";
        let unit = format!("{UNIT}{hosts}");
        assert!(strip(&unit).unwrap().contains("a.example"));
        let out = parse(&merge(&unit, PATCH).unwrap()).unwrap();
        assert!(doc(&out, "StaticHostConfig", "127.0.0.1").is_none());
        let out = parse(&merge(UNIT, &format!("{PATCH}{hosts}")).unwrap()).unwrap();
        assert!(doc(&out, "StaticHostConfig", "127.0.0.1").is_some());
    }

    #[test]
    fn merge_is_idempotent() {
        let once = merge(UNIT, PATCH).unwrap();
        assert_eq!(merge(&once, PATCH).unwrap(), once);
    }

    #[test]
    fn a_patch_carrying_a_secret_is_refused() {
        for (what, extra) in [
            (
                "machine.token",
                "version: v1alpha1\nmachine:\n  token: evil\n",
            ),
            (
                "machine.ca",
                "version: v1alpha1\nmachine:\n  ca:\n    key: evil\n",
            ),
            (
                "cluster.token",
                "version: v1alpha1\ncluster:\n  token: evil\n",
            ),
            (
                "cluster.etcd.ca",
                "version: v1alpha1\ncluster:\n  etcd:\n    ca: {key: evil}\n",
            ),
            (
                "cluster.secretboxEncryptionSecret",
                "version: v1alpha1\ncluster:\n  secretboxEncryptionSecret: evil\n",
            ),
            (
                "machine.network",
                "version: v1alpha1\nmachine:\n  network: {hostname: evil}\n",
            ),
        ] {
            let e = merge(UNIT, extra).unwrap_err().to_string();
            assert!(e.contains(what), "{what}: {e}");
        }
        for kind in [
            "KubeAPIServerCAConfig",
            "KubeAggregatorCAConfig",
            "KubeServiceAccountConfig",
            "KubeEtcdEncryptionConfig",
            "DiscoveryIdentityConfig",
            "EtcFileConfig",
            "HostnameConfig",
        ] {
            let p = format!(
                "{PATCH}---\napiVersion: v1alpha1\nkind: {kind}\nname: signer/ca.pem\nx: evil\n"
            );
            let e = merge(UNIT, &p).unwrap_err().to_string();
            assert!(e.contains(kind), "{kind}: {e}");
        }
        for (kind, field) in [
            ("UserVolumeConfig", "encryption"),
            ("VolumeConfig", "encryption"),
            ("KubeAPIServerConfig", "certExtraSANs"),
        ] {
            let p = format!(
                "version: v1alpha1\n---\napiVersion: v1alpha1\nkind: {kind}\nname: data\n{field}: evil\n"
            );
            let e = merge(UNIT, &p).unwrap_err().to_string();
            assert!(e.contains(field), "{kind}.{field}: {e}");
        }
    }

    #[test]
    fn strip_leaves_a_patch_merge_accepts() {
        let patch = strip(UNIT).unwrap();
        check_patch(&patch).unwrap();
        for secret in [
            "unit-machine-token",
            "unit-os-ca-key",
            "unit-etcd-key",
            "unit-k8s-ca-key",
            "unit-cluster-secret",
            "unit-recovery-key",
            "unit-signer-ca-key",
            "unit-bootstrap-token",
            "unit-a",
        ] {
            assert!(!patch.contains(secret), "{secret} survived strip:\n{patch}");
        }
        assert!(patch.contains("store:old") && patch.contains("apiserver:old"));
        // Merging a unit's own stripped config gives it back unchanged.
        let back = parse(&merge(UNIT, &patch).unwrap()).unwrap();
        let unit = parse(UNIT).unwrap();
        assert_eq!(back.len(), unit.len());
        for kv in &unit {
            assert!(back.contains(kv), "{:?}", kv.0);
        }
    }

    #[test]
    fn differently_keyed_volumes_leave_a_new_one_unkeyed_refused() {
        let unit = format!(
            "{UNIT}---\napiVersion: v1alpha1\nkind: UserVolumeConfig\nname: other\nencryption: {{provider: luks2, keys: [{{slot: 0, static: {{passphrase: another}}}}]}}\n"
        );
        let e = merge(&unit, PATCH).unwrap_err().to_string();
        assert!(e.contains("fresh"), "{e}");
    }

    #[test]
    fn duplicate_documents_are_refused() {
        let p = format!("{PATCH}---\napiVersion: v1alpha1\nkind: KubeletConfig\nimage: again\n");
        assert!(merge(UNIT, &p).is_err());
    }

    #[test]
    fn a_patch_without_v1alpha1_is_refused() {
        assert!(merge(UNIT, "apiVersion: v1alpha1\nkind: KubeletConfig\n").is_err());
    }

    #[test]
    fn held_names_the_units_secrets() {
        let keys: Vec<String> = held(&parse(UNIT).unwrap())
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for k in [
            "machine.token",
            "cluster.etcd.ca",
            "KubeAPIServerCAConfig",
            "UserVolumeConfig data.encryption",
        ] {
            assert!(keys.iter().any(|h| h == k), "{k} not held: {keys:?}");
        }
    }

    #[test]
    fn fields_are_held_only_in_the_kinds_that_hold_them() {
        let p = "version: v1alpha1\n---\napiVersion: v1alpha1\nkind: KubeletConfig\nencryption: kept\ncertExtraSANs: [kept]\n";
        let out = parse(&merge(UNIT, p).unwrap()).unwrap();
        let k = doc(&out, "KubeletConfig", "").unwrap();
        assert_eq!(s(get(k, &["encryption"])), "kept\n");
        assert_eq!(s(get(k, &["certExtraSANs"])), "- kept\n");
    }

    #[test]
    fn a_volume_the_unit_has_keeps_its_own_keying() {
        let unit = format!(
            "{UNIT}---\napiVersion: v1alpha1\nkind: UserVolumeConfig\nname: plain\nprovisioning: {{minSize: 1GB}}\n"
        );
        let p = "version: v1alpha1\n---\napiVersion: v1alpha1\nkind: UserVolumeConfig\nname: plain\nprovisioning: {minSize: 2GB}\n";
        let out = parse(&merge(&unit, p).unwrap()).unwrap();
        assert!(
            get(
                doc(&out, "UserVolumeConfig", "plain").unwrap(),
                &["encryption"]
            )
            .is_none()
        );
    }

    #[test]
    fn serving_rotation_waits_for_the_running_config_to_have_it() {
        let on = "version: v1alpha1\n---\napiVersion: v1alpha1\nkind: KubeletConfig\nconfig:\n  serverTLSBootstrap: true\n  x: 1\n";
        let off =
            "version: v1alpha1\n---\napiVersion: v1alpha1\nkind: KubeletConfig\nconfig:\n  x: 1\n";
        assert!(serving_rotation(on).unwrap());
        assert!(!serving_rotation(off).unwrap());
        let (os, held) = rotation_as_running(on, off).unwrap();
        assert!(held);
        assert!(!serving_rotation(&os).unwrap());
        assert!(os.contains("x: 1"));
        assert_eq!(
            rotation_as_running(on, on).unwrap(),
            (on.to_string(), false)
        );
        assert_eq!(
            rotation_as_running(off, on).unwrap(),
            (off.to_string(), false)
        );
    }
}
