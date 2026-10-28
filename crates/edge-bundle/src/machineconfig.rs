//! A bundle carries the build's machine config without the unit's secrets and
//! identity (a patch). The unit's next config is the patch with the unit's own
//! material put back, so the unit's secrets never travel. Its ingress
//! firewall is neither: it is derived from the config itself ([`with_firewall`]).

use anyhow::{Context, bail, ensure};
use std::collections::BTreeMap;

use serde_json::{Map, Value};

mod firewall;

pub use firewall::management;

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

/// Named documents the unit keeps: edge-dhcp's, with the unit's LAN address
/// and domain, and the firewall's rule for the networks it is managed from.
const HELD_NAMED: &[(&str, &str)] = &[
    ("ExtensionServiceConfig", "operator-lan"),
    ("NetworkRuleConfig", firewall::MANAGEMENT),
];

/// Volumes a merge drops whole, keys and all, when the build stops rendering them.
const DROPPED_WHOLE: &[&str] = &["UserVolumeConfig", "RawVolumeConfig", "SwapVolumeConfig"];

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
        .as_object()
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
    for doc in crate::yaml::documents(text).context("the config is not YAML")? {
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
        out.push_str(&serde_saphyr::to_string(doc)?);
    }
    Ok(out)
}

fn get<'a>(doc: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(doc, |v, k| v.as_object()?.get(*k))
}

fn remove(doc: &mut Value, path: &[&str]) -> Option<Value> {
    let (last, parents) = path.split_last()?;
    let mut v = doc;
    for k in parents {
        v = v.as_object_mut()?.get_mut(*k)?;
    }
    v.as_object_mut()?.remove(*last)
}

fn set(doc: &mut Value, path: &[&str], value: Value) -> anyhow::Result<()> {
    let (last, parents) = path.split_last().context("empty path")?;
    let mut v = doc;
    for k in parents {
        let m = v.as_object_mut().context("not a mapping")?;
        v = m.entry(*k).or_insert_with(|| Value::Object(Map::new()));
    }
    v.as_object_mut()
        .context("not a mapping")?
        .insert((*last).into(), value);
    Ok(())
}

fn held_kind(k: &Key) -> bool {
    matches!(k, Key::Typed(kind, name) if HELD_KINDS.contains(&kind.as_str())
        || HELD_NAMED.contains(&(kind.as_str(), name.as_str()))
        || (kind == USER_VOLUME && Provisioned::is(name)))
}

const USER_VOLUME: &str = "UserVolumeConfig";

/// A Talos user volume edge's storage provisioner made for a claim: the
/// unit's, kept whole by every merge, never in a build's patch. Named
/// `pv-<24 hex>` from the claim's uid, within Talos's 34 characters, so no
/// build's volume is one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Provisioned(String);

impl Provisioned {
    const PREFIX: &str = "pv-";

    /// The volume for the claim with uid `uid`.
    pub fn for_claim(uid: &str) -> Self {
        use sha2::Digest as _;
        let h = hex::encode(sha2::Sha256::digest(uid.as_bytes()));
        Self(format!("{}{}", Self::PREFIX, &h[..24]))
    }

    /// A name the provisioner gave, read back.
    pub fn parse(name: &str) -> Option<Self> {
        Self::is(name).then(|| Self(name.into()))
    }

    fn is(name: &str) -> bool {
        name.strip_prefix(Self::PREFIX).is_some_and(|h| {
            h.len() == 24
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    }

    pub fn name(&self) -> &str {
        &self.0
    }

    /// Where Talos mounts it.
    pub fn path(&self) -> String {
        format!("/var/mnt/{}", self.0)
    }
}

/// The provisioned volumes `config` holds, with their sizes in MiB.
pub fn provisioned(config: &str) -> anyhow::Result<BTreeMap<Provisioned, u64>> {
    let mut out = BTreeMap::new();
    for (k, doc) in parse(config)? {
        if let Key::Typed(kind, name) = &k
            && kind == USER_VOLUME
            && let Some(p) = Provisioned::parse(name)
        {
            let size = get(&doc, &["provisioning", "maxSize"])
                .and_then(Value::as_str)
                .and_then(|s| s.strip_suffix("MiB"))
                .and_then(|s| s.parse().ok())
                .with_context(|| format!("{} has no size in MiB", p.name()))?;
            out.insert(p, size);
        }
    }
    Ok(out)
}

/// `config` with the provisioned volume `v` of `mib` MiB, ext4 on the system
/// disk: one filesystem for every claim, since XFS refuses a small one. It
/// is keyed as the unit's other user volumes are.
pub fn with_provisioned(config: &str, v: &Provisioned, mib: u64) -> anyhow::Result<String> {
    let mut docs = parse(config)?;
    let k = Key::Typed(USER_VOLUME.into(), v.name().into());
    ensure!(
        !docs.iter().any(|(d, _)| *d == k),
        "the config already has {}",
        v.name()
    );
    ensure!(mib > 0, "a volume of no size");
    let size = format!("{mib}MiB");
    let encryption = new_volume_encryption(&docs, &k)?;
    let mut doc = serde_json::json!({
            "apiVersion": "v1alpha1",
            "kind": USER_VOLUME,
            "name": v.name(),
            "provisioning": {
                "diskSelector": { "match": "system_disk" },
                "minSize": size,
                "maxSize": size,
            },
            "filesystem": { "type": "ext4" },
    });
    if let Some(e) = encryption {
        doc["encryption"] = e;
    }
    docs.push((k, doc));
    render(&docs)
}

/// `config` without the provisioned volume `v`. Talos unmounts it; its
/// partition stays on the disk.
pub fn without_provisioned(config: &str, v: &Provisioned) -> anyhow::Result<String> {
    let mut docs = parse(config)?;
    let k = Key::Typed(USER_VOLUME.into(), v.name().into());
    docs.retain(|(d, _)| *d != k);
    render(&docs)
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

/// What the unit keeps, for building a patch: the rest of `full`, without
/// the firewall, which the unit derives.
pub fn strip(full: &str) -> anyhow::Result<String> {
    let mut docs = parse(full)?;
    docs.retain(|(k, _)| !held_kind(k) && !firewall::is(k));
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
        ensure!(
            !firewall::is(k),
            "the patch carries {}, which the unit derives",
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
        // A volume the build no longer renders goes whole: Talos takes none
        // without its provisioning, and its data stays on the disk.
        if matches!(k, Key::Typed(kind, _) if DROPPED_WHOLE.contains(&kind.as_str())) {
            let gone = describe(k);
            expected.retain(|(f, _)| !f.strip_prefix(&gone).is_some_and(|r| r.starts_with('.')));
            continue;
        }
        // A document the build no longer renders goes, unless it holds the unit's.
        let fields: Vec<_> = held_fields(k)
            .filter_map(|f| get(doc, &[f]).map(|v| (f, v.clone())))
            .collect();
        if fields.is_empty() {
            continue;
        }
        let mut kept = Map::new();
        for h in ["apiVersion", "kind", "name"] {
            if let Some(v) = doc.as_object().and_then(|m| m.get(h)) {
                kept.insert(h.to_string(), v.clone());
            }
        }
        for (f, v) in fields {
            kept.insert(f.to_string(), v);
        }
        out.push((k.clone(), Value::Object(kept)));
    }

    // Whatever the rules above say, the unit's own material leaves unchanged.
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    if expected != held(&out) {
        bail!("merging would change what the unit keeps");
    }
    out.retain(|(k, _)| !firewall::is(k));
    out.extend(firewall::derive(&out)?);
    render(&out)
}

/// `config` with its ingress firewall derived from it (the `firewall` module): a
/// config as provisioning renders it, and as every merge leaves it. Any
/// firewall it held is replaced.
pub fn with_firewall(config: &str) -> anyhow::Result<String> {
    let mut docs = parse(config)?;
    docs.retain(|(k, _)| !firewall::is(k));
    docs.extend(firewall::derive(&docs)?);
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
    use serde_json::json;

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
kind: ExtensionServiceConfig
name: operator-lan
environment: [EDGE_DHCP_ADDR=10.50.0.1/24]
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

    fn s(v: Option<&Value>) -> Value {
        v.cloned().unwrap_or(Value::Null)
    }

    #[test]
    fn build_wins_where_it_owns() {
        let out = parse(&merge(UNIT, PATCH).unwrap()).unwrap();
        let v1 = doc(&out, "v1alpha1", "").unwrap();
        assert_eq!(
            s(get(v1, &["cluster", "etcd", "image"])),
            json!("store:new")
        );
        assert_eq!(
            s(get(v1, &["machine", "sysctls", "vm.dirty_ratio"])),
            json!("10")
        );
        let api = doc(&out, "KubeAPIServerConfig", "").unwrap();
        assert_eq!(s(get(api, &["image"])), json!("apiserver:new"));
        assert!(doc(&out, "KubeletConfig", "").is_some());
        let data = doc(&out, "UserVolumeConfig", "data").unwrap();
        assert_eq!(s(get(data, &["provisioning", "minSize"])), json!("2GB"));
    }

    #[test]
    fn unit_keeps_its_secrets_and_identity() {
        let unit = parse(UNIT).unwrap();
        let out = parse(&merge(UNIT, PATCH).unwrap()).unwrap();
        let mut kept = held(&out);
        kept.retain(|(k, _)| k != "UserVolumeConfig fresh.encryption");
        assert_eq!(held(&unit), kept);
        let v1 = doc(&out, "v1alpha1", "").unwrap();
        assert_eq!(
            s(get(v1, &["machine", "token"])),
            json!("unit-machine-token")
        );
        assert_eq!(
            s(get(v1, &["cluster", "etcd", "ca", "key"])),
            json!("unit-etcd-key")
        );
        assert!(get(v1, &["machine", "network", "interfaces"]).is_some());
        assert!(doc(&out, "KubeAPIServerCAConfig", "").is_some());
        assert!(doc(&out, "EtcFileConfig", "signer/ca.pem").is_some());
        assert!(doc(&out, "ExtensionServiceConfig", "operator-lan").is_some());
        let api = doc(&out, "KubeAPIServerConfig", "").unwrap();
        assert_eq!(
            s(get(api, &["certExtraSANs"])),
            json!(["unit-a", "10.50.0.1"])
        );
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
    fn a_volume_the_build_stopped_rendering_goes_whole() {
        let unit = parse(UNIT).unwrap();
        let patch: Vec<_> = parse(PATCH)
            .unwrap()
            .into_iter()
            .filter(|(k, _)| *k != Key::Typed("UserVolumeConfig".into(), "data".into()))
            .collect();
        assert!(doc(&unit, "UserVolumeConfig", "data").is_some());
        let out = parse(&merge(UNIT, &render(&patch).unwrap()).unwrap()).unwrap();
        assert!(doc(&out, "UserVolumeConfig", "data").is_none());
        assert!(doc(&out, "VolumeConfig", "STATE").is_some());
    }

    #[test]
    fn a_provisioned_volume_is_the_units_through_every_merge() {
        let v = Provisioned::for_claim("6a2f0c4e-8d5b-4f3a-9c1e-0b7d2e4f6a8c");
        assert_eq!(v.name().len(), 27);
        assert_eq!(Provisioned::parse(v.name()), Some(v.clone()));
        assert_eq!(Provisioned::parse("fusion-data"), None);
        assert_eq!(Provisioned::parse("pv-NOTHEX0000000000000000"), None);
        assert_eq!(v.path(), format!("/var/mnt/{}", v.name()));

        let unit = with_provisioned(UNIT, &v, 2048).unwrap();
        assert!(with_provisioned(&unit, &v, 2048).is_err(), "twice");
        assert_eq!(provisioned(&unit).unwrap(), [(v.clone(), 2048)].into());
        let doc_of = |c: &str| doc(&parse(c).unwrap(), "UserVolumeConfig", v.name()).cloned();
        let ours = doc_of(&unit).unwrap();
        assert_eq!(ours["filesystem"]["type"], "ext4");
        let keyed = |c: &str, name: &str| {
            doc(&parse(c).unwrap(), "UserVolumeConfig", name).unwrap()["encryption"].clone()
        };
        assert_eq!(
            keyed(&unit, v.name()),
            keyed(UNIT, "data"),
            "keyed as the unit's"
        );
        assert_eq!(ours["provisioning"]["maxSize"], "2048MiB");

        // A build never renders it, yet the next config keeps it whole.
        let merged = merge(&unit, PATCH).unwrap();
        assert_eq!(doc_of(&merged).unwrap(), ours);
        assert!(!strip(&unit).unwrap().contains(v.name()));
        let carrying = format!("{PATCH}---\n{}", serde_saphyr::to_string(&ours).unwrap());
        let e = check_patch(&carrying).unwrap_err();
        assert!(format!("{e:#}").contains("which the unit keeps"), "{e:#}");

        let gone = without_provisioned(&merged, &v).unwrap();
        assert!(doc_of(&gone).is_none());
        assert!(provisioned(&gone).unwrap().is_empty());
        assert!(with_provisioned(UNIT, &v, 0).is_err());
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
        // Merging a unit's own stripped config gives it back unchanged, with
        // the firewall it derives.
        let back = parse(&merge(UNIT, &patch).unwrap()).unwrap();
        let unit = parse(&with_firewall(UNIT).unwrap()).unwrap();
        assert_eq!(back.len(), unit.len());
        for kv in &unit {
            assert!(back.contains(kv), "{:?}", kv.0);
        }
    }

    /// A unit as provisioning renders it: managed from its island.
    const ISLAND: &str = r#"version: v1alpha1
machine:
  network:
    interfaces:
      - deviceSelector: {busPath: "0000:02:00.0"}
        dhcp: true
      - deviceSelector: {busPath: "0000:01:00.0"}
        addresses: [10.50.0.1/24, fe80::ed6e:1/64]
        dhcp: false
      - interface: dummy1
        dummy: true
        addresses: [10.70.0.1/32]
---
apiVersion: v1alpha1
kind: KubeClusterConfig
endpoint: https://10.50.0.1:6443
---
apiVersion: v1alpha1
kind: KubeNetworkConfig
podSubnets: [10.244.0.0/16]
serviceSubnets: [10.96.0.0/12]
"#;

    fn rule(docs: &[(Key, Value)], name: &str) -> (Value, Vec<String>) {
        let r = doc(docs, "NetworkRuleConfig", name).unwrap_or_else(|| panic!("no {name}"));
        let from = r["ingress"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["subnet"].as_str().unwrap().to_string())
            .collect();
        (r["portSelector"].clone(), from)
    }

    #[test]
    fn the_firewall_denies_all_but_what_it_derives() {
        let out = parse(&with_firewall(ISLAND).unwrap()).unwrap();
        let block = doc(&out, "NetworkDefaultActionConfig", "").unwrap();
        assert_eq!(block["ingress"], json!("block"));
        let names: Vec<_> = out
            .iter()
            .filter_map(|(k, _)| match k {
                Key::Typed(kind, name) if kind == "NetworkRuleConfig" => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            [
                "cluster-tcp",
                "cluster-udp",
                "console-tcp",
                "console-udp",
                "operator-tcp",
                "operator-udp",
                "operator-dhcp"
            ]
        );
        let pods = ["10.244.0.0/16", "10.96.0.0/12"].map(String::from).to_vec();
        let all = json!(["1-65535"]);
        assert_eq!(
            rule(&out, "cluster-udp"),
            (json!({"ports": all, "protocol": "udp"}), pods)
        );
        let anywhere = ["0.0.0.0/0", "::/0"].map(String::from).to_vec();
        assert_eq!(
            rule(&out, "console-udp"),
            (json!({"ports": [443], "protocol": "udp"}), anywhere)
        );
        // The island's network, not its address; the management port's lease
        // and the dummy links are none of it.
        assert_eq!(
            rule(&out, "operator-tcp"),
            (
                json!({"ports": [50000, 6443], "protocol": "tcp"}),
                ["10.50.0.0/24", "fe80::/10"].map(String::from).to_vec()
            )
        );
        assert_eq!(
            rule(&out, "operator-dhcp").1,
            ["0.0.0.0/32", "10.50.0.0/24"]
        );
    }

    #[test]
    fn the_firewall_is_the_units_own_never_a_patchs() {
        // Derived again, not kept: a merge replaces what the unit held.
        let mut unit = with_firewall(&format!(
            "{UNIT}---\n{}",
            ISLAND.split_once("---\n").unwrap().1
        ))
        .unwrap();
        unit.push_str("---\napiVersion: v1alpha1\nkind: NetworkRuleConfig\nname: by-hand\nportSelector: {ports: [7600], protocol: udp}\ningress: [{subnet: 0.0.0.0/0}]\n");
        let managed = management(&["192.168.122.71/24".into()], 6443).unwrap();
        unit.push_str(&format!(
            "---\n{}",
            serde_saphyr::to_string(&managed).unwrap()
        ));
        let out = parse(&merge(&unit, PATCH).unwrap()).unwrap();
        assert!(doc(&out, "NetworkRuleConfig", "by-hand").is_none());
        assert_eq!(rule(&out, "operator-tcp").0["ports"], json!([50000, 6443]));
        // The networks it is managed from are the unit's, kept as they are.
        assert_eq!(rule(&out, "management").1, ["192.168.122.0/24"]);
        let e = check_patch(&format!(
            "{PATCH}---\n{}",
            serde_saphyr::to_string(&managed).unwrap()
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("which the unit keeps"), "{e}");
        // A patch never carries one, and a stripped config holds none.
        let carried = format!(
            "{PATCH}---\napiVersion: v1alpha1\nkind: NetworkDefaultActionConfig\ningress: accept\n"
        );
        let e = check_patch(&carried).unwrap_err().to_string();
        assert!(e.contains("which the unit derives"), "{e}");
        assert!(!strip(&unit).unwrap().contains("NetworkRuleConfig"));
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
        assert_eq!(s(get(k, &["encryption"])), json!("kept"));
        assert_eq!(s(get(k, &["certExtraSANs"])), json!(["kept"]));
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
