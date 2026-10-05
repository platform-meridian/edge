//! The engine against a simulated unit: Talos with sd-boot's trial and
//! boot-commit, Flux with the stack judge, and a registry. Every run is
//! interrupted everywhere it can be: a restart after each recorded phase, a
//! power cut after each, and a crash straight after each change to the unit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::*;
use crate::bundle::components::Components;
use crate::bundle::testkit;
use crate::judge::CheckState;
use crate::unit::{Ref, Stack};

pub(crate) const OLD_TAG: &str = "update-old";
const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

const UNIT_CONFIG: &str = "version: v1alpha1
machine:
  type: init
  token: unit-machine-token
  ca: {crt: unit-os-ca, key: unit-os-ca-key}
cluster:
  etcd:
    image: store:old
---
apiVersion: v1alpha1
kind: KubeAPIServerCAConfig
issuingCA: {cert: unit-k8s-ca, key: unit-k8s-ca-key}
";

fn patch(tag: &str) -> String {
    format!(
        "version: v1alpha1\nmachine:\n  type: init\ncluster:\n  etcd:\n    image: store:{tag}\n"
    )
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Verdict {
    Good,
    Bad,
    WrongDigest,
}

pub(crate) struct World {
    version: String,
    /// sd-boot's entries by id: version, and boot tries left while counted.
    entries: BTreeMap<String, (String, Option<u32>)>,
    default: String,
    selected: String,
    count_path: String,
    /// The boot boot-commit's record names.
    blessed_boot: Option<u64>,
    /// The record is torn.
    bless_torn: bool,
    boot_id: u64,
    secure_boot: bool,
    active: String,
    staged: Option<String>,
    store: Vec<u8>,
    /// Boot reads on trial before boot-commit decides.
    trial_ticks: u32,
    trial_fails: bool,

    url: String,
    tag: String,
    lock: BTreeMap<String, String>,
    /// The running stack's record of its modules.
    modules: BTreeMap<String, String>,
    pub(crate) judge: BTreeMap<String, String>,
    judge_ticks: u32,
    verdict: Verdict,
    seeded: bool,
    /// What the seeded judge runs; it pulls only what the registry holds.
    judge_image: String,
    /// Images other workloads run.
    running: BTreeSet<String>,

    held: BTreeSet<String>,
    /// What the registry holds by content: each ref's digest, and blobs.
    digests: BTreeMap<String, String>,
    blobs: BTreeMap<String, Vec<u8>>,
    last_installed: String,
    /// The unit already runs the bundle's OS.
    os_current: bool,
    /// Talos refuses a config without a reboot.
    apply_refused: bool,
    no_store: bool,
    install_fails: bool,

    /// Every change to the unit, in order.
    log: Vec<String>,
    /// Every call, reads included.
    calls: usize,
    changes: usize,
    crash_at: Option<usize>,
    /// The crash is a power cut too.
    cut_on_crash: bool,
    never_ready: bool,
    seed_stuck: bool,
    judge_idle: bool,
    apid_down: bool,
    apiserver_down: bool,
    registry_free: u64,
    /// Every config staged for a boot.
    staged_configs: Vec<String>,
    /// The FluxInstance applied, and the stack it applied on.
    instance: Option<(String, String)>,
}

impl World {
    fn new() -> Self {
        Self {
            version: "v1.14.1".into(),
            entries: BTreeMap::from([("talos-v1.14.1.efi".into(), ("v1.14.1".into(), None))]),
            default: "Talos-v1.14.1.efi".into(),
            selected: "Talos-v1.14.1.efi".into(),
            count_path: String::new(),
            blessed_boot: None,
            bless_torn: false,
            boot_id: 1,
            secure_boot: true,
            active: UNIT_CONFIG.into(),
            staged: None,
            store: b"store log".to_vec(),
            trial_ticks: 0,
            trial_fails: false,
            url: "oci://127.0.0.1:3172/stack".into(),
            tag: OLD_TAG.into(),
            lock: BTreeMap::from([
                ("built_epoch".into(), "1000".into()),
                ("PROFILE".into(), "edge".into()),
            ]),
            modules: BTreeMap::from([("MODULES".into(), String::new())]),
            judge: BTreeMap::from([("good".into(), OLD_TAG.into())]),
            judge_ticks: 0,
            verdict: Verdict::Good,
            seeded: false,
            judge_image: String::new(),
            running: BTreeSet::new(),
            held: BTreeSet::new(),
            digests: BTreeMap::new(),
            blobs: BTreeMap::new(),
            last_installed: String::new(),
            os_current: false,
            apply_refused: false,
            no_store: false,
            install_fails: false,
            log: Vec::new(),
            staged_configs: Vec::new(),
            instance: None,
            calls: 0,
            changes: 0,
            crash_at: None,
            cut_on_crash: false,
            never_ready: false,
            seed_stuck: false,
            judge_idle: false,
            apid_down: false,
            apiserver_down: false,
            registry_free: 1 << 40,
        }
    }

    fn change(&mut self, what: String) -> anyhow::Result<()> {
        self.log.push(what);
        self.changes += 1;
        if self.crash_at == Some(self.changes) {
            if self.cut_on_crash {
                self.power_cycle();
            }
            anyhow::bail!("crash after change {}", self.changes);
        }
        Ok(())
    }

    fn on_trial(&self) -> bool {
        !self.count_path.is_empty() && self.blessed_boot != Some(self.boot_id)
    }

    fn judge_pulls(&self) -> bool {
        self.judge_image.is_empty() || self.held.contains(&self.judge_image)
    }

    fn committed_new(&self) -> bool {
        !self.on_trial()
            && (self.os_current && self.last_installed.is_empty()
                || !self.last_installed.is_empty()
                    && self.default.eq_ignore_ascii_case(&self.last_installed)
                    && self.selected.eq_ignore_ascii_case(&self.last_installed))
    }

    /// sd-boot: the default, counting its boot while it has tries, else the
    /// uncounted entry; a staged config applies.
    fn power_cycle(&mut self) {
        self.boot_id += 1;
        let id = self.default.to_lowercase();
        let (selected, count_path) = match self.entries.get_mut(&id) {
            Some((_, Some(left))) if *left > 0 => {
                *left -= 1;
                (id.clone(), format!("\\EFI\\Linux\\{id}+{left}"))
            }
            Some((_, None)) => (id.clone(), String::new()),
            _ => (
                self.entries
                    .iter()
                    .find(|(_, (_, tries))| tries.is_none())
                    .map(|(id, _)| id.clone())
                    .expect("a good entry"),
                String::new(),
            ),
        };
        (self.selected, self.count_path) = (selected, count_path);
        self.version = self.entries[&self.selected].0.clone();
        if let Some(c) = self.staged.take() {
            self.active = c;
        }
        self.trial_ticks = 0;
    }

    /// boot-commit: after a few looks, a healthy trial commits and a bad one resets.
    fn tick_trial(&mut self) {
        if !self.on_trial() {
            return;
        }
        self.trial_ticks += 1;
        if self.trial_ticks < 3 {
            return;
        }
        if self.trial_fails {
            self.power_cycle();
        } else {
            self.bless();
        }
    }

    /// boot-commit's bless: the running UKI loses its counter, and the record names this
    /// boot; LoaderBootCountPath stays set until the next boot, as firmware keeps it.
    fn bless(&mut self) {
        if let Some((_, tries)) = self.entries.get_mut(&self.selected.to_lowercase()) {
            *tries = None;
        }
        self.blessed_boot = Some(self.boot_id);
    }

    /// The stack judge: a new ref is committed or rolled back after a few
    /// looks, or at once when asked.
    fn tick_judge(&mut self) {
        let good = self.judge.get("good").cloned().unwrap_or_default();
        let asked = self.judge.insert("request".into(), String::new());
        match asked.as_deref().and_then(|r| r.split_once(' ')) {
            Some((what, tag)) if tag == self.tag && tag != good => {
                if what == "commit" {
                    self.judge.insert("previous".into(), good);
                    self.judge.insert("good".into(), self.tag.clone());
                } else {
                    self.judge
                        .insert("rolled_back".into(), format!("{} 12:00", self.tag));
                    self.tag = good;
                }
                return;
            }
            _ => {}
        }
        if self.tag == good || self.judge_idle {
            return;
        }
        self.judge_ticks += 1;
        if self.judge_ticks < 3 {
            return;
        }
        self.judge_ticks = 0;
        match self.verdict {
            Verdict::Good | Verdict::WrongDigest => {
                self.judge.insert("previous".into(), good);
                self.judge.insert("good".into(), self.tag.clone());
                self.lock.insert("built_epoch".into(), "2000".into());
            }
            Verdict::Bad => {
                self.judge
                    .insert("rolled_back".into(), format!("{} 12:00", self.tag));
                self.tag = good;
            }
        }
    }
}

type Shared = Arc<Mutex<World>>;

struct FakeTalos(Shared);
struct FakeCluster(Shared);
struct FakeRegistry(Shared);

fn utf16(s: &str) -> Vec<u8> {
    let mut v = vec![7, 0, 0, 0];
    for u in s.encode_utf16().chain([0]) {
        v.extend(u.to_le_bytes());
    }
    v
}

#[async_trait]
impl Talos for FakeTalos {
    async fn version(&self) -> anyhow::Result<String> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        anyhow::ensure!(!w.apid_down, "apid is not answering");
        Ok(w.version.clone())
    }
    async fn read(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let var = |v: &str| (!v.is_empty()).then(|| utf16(v));
        Ok(match path {
            p if p.contains("/SecureBoot-") => Some(vec![6, 0, 0, 0, w.secure_boot as u8]),
            p if p.contains("/LoaderEntrySelected-") => {
                w.tick_trial();
                var(&w.selected)
            }
            p if p.contains("/LoaderEntryDefault-") => var(&w.default),
            p if p.contains("/LoaderBootCountPath-") => var(&w.count_path),
            BOOT_ID => Some(format!("{}\n", w.boot_id).into_bytes()),
            BLESS if w.bless_torn => w
                .blessed_boot
                .map(|b| format!(r#"{{"boot_id": "{b}"#).into_bytes()),
            BLESS => w.blessed_boot.map(|b| {
                format!(r#"{{"boot_id": "{b}\n", "uki": "Talos-v1.14.1~1.efi"}}"#).into_bytes()
            }),
            _ => None,
        })
    }
    async fn size(&self, path: &str) -> anyhow::Result<Option<u64>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok((path == "/var/lib/etcd/state.log" && !w.no_store).then_some(w.store.len() as u64))
    }
    async fn copy(&self, _: &str, dest: &Path) -> anyhow::Result<u64> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        std::fs::write(dest, &w.store)?;
        // The live log grows under the copy.
        w.store.extend(b" more");
        Ok(w.store.len() as u64 - 5)
    }
    async fn machine_config(&self) -> anyhow::Result<String> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(w.staged.clone().unwrap_or_else(|| w.active.clone()))
    }
    async fn running_config(&self) -> anyhow::Result<String> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(w.active.clone())
    }
    async fn stage_config(&self, config: &str, dry_run: bool) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        assert!(config.contains("unit-machine-token") && config.contains("unit-k8s-ca-key"));
        if dry_run {
            return Ok(());
        }
        w.staged = Some(config.into());
        w.staged_configs.push(config.into());
        w.change("stage".into())
    }
    async fn apply_config(&self, config: &str) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        anyhow::ensure!(!w.apply_refused, "the change needs a reboot");
        w.active = config.into();
        w.staged = None;
        w.change("apply".into())
    }
    async fn install(&self, image: &str) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        assert!(
            w.staged.is_some() || w.active.contains("store:update-new"),
            "installed before staging"
        );
        assert!(image.ends_with(&format!("@{DIGEST}")) && !image.contains(":update-new@"));
        anyhow::ensure!(!w.install_fails, "pulling {image}: not found");
        let entry = format!("Talos-v1.14.1~{}.efi", w.entries.len());
        w.entries
            .insert(entry.to_lowercase(), ("v1.14.1".into(), Some(3)));
        w.default = entry.clone();
        w.last_installed = entry;
        w.seeded = false;
        w.change("install".into())
    }
    async fn reboot(&self) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        w.power_cycle();
        w.change("reboot".into())
    }
    async fn rollback(&self) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let previous = w
            .entries
            .iter()
            .find(|(id, (_, tries))| tries.is_none() && !id.eq_ignore_ascii_case(&w.default))
            .map(|(id, _)| id.clone())
            .context("no previous entry")?;
        w.default = previous;
        w.power_cycle();
        w.change("rollback".into())
    }
    async fn shutdown(&self) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        // Off, then on again whenever someone powers it.
        w.power_cycle();
        w.change("shutdown".into())
    }
}

#[async_trait]
impl Cluster for FakeCluster {
    async fn config_map(&self, at: &Ref) -> anyhow::Result<Option<BTreeMap<String, String>>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(match at.name.as_str() {
            "lock" => Some(w.lock.clone()),
            "modules" => Some(w.modules.clone()),
            "judge" => {
                w.tick_judge();
                Some(w.judge.clone())
            }
            _ => None,
        })
    }
    async fn set_key(&self, at: &Ref, key: &str, value: &str) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        assert_eq!(at.name, "judge");
        w.judge.insert(key.into(), value.into());
        w.change(format!("judge {key}={value}"))
    }
    async fn flux_version(&self, _: &Ref) -> anyhow::Result<String> {
        Ok("v2.6.4".into())
    }
    async fn sync(&self, _: &Ref) -> anyhow::Result<(String, String)> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        anyhow::ensure!(!w.apiserver_down, "the apiserver is not answering");
        Ok((w.url.clone(), w.tag.clone()))
    }
    async fn repoint(&self, _: &Ref, url: &str, tag: &str, _: Option<&str>) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        if tag != w.judge["good"] && tag != w.tag {
            assert!(
                w.committed_new(),
                "the stack moved before the OS was committed"
            );
            assert!(w.seeded, "the stack moved before the judge was updated");
            assert_eq!(
                w.judge["good"], w.tag,
                "the stack moved with nothing to roll back to"
            );
        }
        w.url = url.into();
        w.tag = tag.into();
        w.judge_ticks = 0;
        w.change(format!("repoint {tag}"))
    }
    async fn reconcile(&self, _: &Ref) -> anyhow::Result<()> {
        Ok(())
    }
    async fn applied(&self, _: &Ref) -> anyhow::Result<Option<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let composed = w.digests.get(&stack_ref(&w.tag));
        let digest = if w.verdict == Verdict::WrongDigest && w.tag != OLD_TAG {
            "sha256:evil"
        } else {
            composed.map_or(DIGEST, String::as_str)
        };
        Ok(Some(format!("{}@{digest}", w.tag)))
    }
    async fn apply(&self, manifests: &str) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        if manifests.contains("kind: FluxInstance") {
            let on = w.tag.clone();
            w.instance = Some((manifests.into(), on));
            return w.change("instance".into());
        }
        assert!(
            w.committed_new(),
            "the judge was updated before the OS was committed"
        );
        w.judge_image = manifests
            .lines()
            .find_map(|l| l.trim().strip_prefix("image: "))
            .expect("the seed names the judge's image")
            .into();
        w.seeded = true;
        w.change("seed".into())
    }
    async fn not_rolled_out(&self, _: &str) -> anyhow::Result<Vec<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(if w.seeded && !w.seed_stuck && w.judge_pulls() {
            vec![]
        } else {
            vec!["judge".into()]
        })
    }
    async fn not_ready(&self) -> anyhow::Result<Vec<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let mut waiting = Vec::new();
        if w.never_ready {
            waiting.push("deployment app/web".into());
        }
        if !w.judge_pulls() {
            waiting.push("deployment flux-system/stack-commit".into());
        }
        Ok(waiting)
    }
    async fn images_in_use(&self) -> anyhow::Result<BTreeSet<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        anyhow::ensure!(!w.apiserver_down, "the apiserver is not answering");
        let mut images = w.running.clone();
        images.extend(
            [w.judge_image.clone()]
                .into_iter()
                .filter(|i| !i.is_empty()),
        );
        Ok(images)
    }
}

impl Registry for FakeRegistry {
    fn import(&self, layout: &Path) -> anyhow::Result<()> {
        let images = crate::bundle::layout_images(layout)?;
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        for e in std::fs::read_dir(layout.join("blobs/sha256"))? {
            let e = e?;
            let d = format!("sha256:{}", e.file_name().to_string_lossy());
            w.blobs.insert(d, std::fs::read(e.path())?);
        }
        for (r, d) in images {
            w.held.insert(r.clone());
            if d.starts_with("sha256:") {
                w.digests.insert(r, d);
            }
        }
        w.change("import".into())
    }
    fn retain(&self, keep: &BTreeSet<String>) -> anyhow::Result<u64> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let before = w.held.len();
        w.held.retain(|r| keep.contains(r));
        w.digests.retain(|r, _| keep.contains(r));
        if w.held.len() != before {
            w.change("collect".into())?;
        }
        Ok(((before - w.held.len()) * 100) as u64)
    }
    fn reclaimable(&self, keep: &BTreeSet<String>) -> anyhow::Result<u64> {
        let w = self.0.lock().unwrap();
        Ok((w.held.iter().filter(|r| !keep.contains(*r)).count() * 100) as u64)
    }
    fn usage(&self) -> anyhow::Result<(u64, u64)> {
        let w = self.0.lock().unwrap();
        Ok(((w.held.len() * 100) as u64, w.registry_free))
    }
    fn missing(&self, layout: &Path) -> anyhow::Result<u64> {
        let refs = crate::bundle::layout_refs(layout)?;
        let w = self.0.lock().unwrap();
        Ok((refs.iter().filter(|r| !w.held.contains(*r)).count() * 100) as u64)
    }
    fn digest(&self, image: &str) -> Option<String> {
        let w = self.0.lock().unwrap();
        w.held.contains(image).then(|| {
            w.digests
                .get(image)
                .cloned()
                .unwrap_or_else(|| format!("sha256:{}", image.len()))
        })
    }
    fn read(&self, digest: &str) -> anyhow::Result<Vec<u8>> {
        let w = self.0.lock().unwrap();
        w.blobs
            .get(digest)
            .cloned()
            .context("the store holds no such blob")
    }
}

pub(crate) struct Harness {
    pub(crate) world: Shared,
    dir: tempfile::TempDir,
    key: PathBuf,
    public: String,
    clock: Arc<AtomicI64>,
    pub(crate) engine: Option<Engine>,
}

pub(crate) struct Spec {
    tag: String,
    epoch: i64,
    talos: String,
    secureboot: &'static str,
    extra: String,
    patch: String,
    format: &'static str,
    /// What the layout carries: by default the release's app and judge, and a shared base.
    carried: Vec<String>,
    /// Every ref the release runs, signed as `refs`: by default what it carries.
    refs: Option<Vec<String>>,
    notes: Option<String>,
    instance: Option<String>,
    /// What the bundle brings; with a base, a real stack artifact `reg/stack:<tag>`.
    components: Option<Components>,
}

impl Spec {
    pub(crate) fn new(tag: &str) -> Self {
        Self {
            tag: tag.into(),
            epoch: 2000,
            talos: "v1.14.1".into(),
            secureboot: "1",
            extra: "LOCK_PROFILE=edge\nSTACK_PATH=./base\n".into(),
            patch: patch(tag),
            format: crate::bundle::FORMAT,
            carried: vec![
                format!("reg/app:{tag}"),
                format!("reg/judge:{tag}"),
                BASE.into(),
            ],
            refs: None,
            notes: None,
            instance: None,
            components: None,
        }
    }

    /// The base, with `modules`.
    fn base(tag: &str, modules: &[&str]) -> Self {
        let c = Components {
            base: Some(
                [
                    format!("reg/app:{tag}"),
                    format!("reg/judge:{tag}"),
                    stack_ref(tag),
                ]
                .into(),
            ),
            modules: modules.iter().map(|m| (m.to_string(), module(m))).collect(),
            remove: BTreeSet::new(),
        };
        Self {
            carried: c.refs().into_iter().collect(),
            components: Some(c),
            // The unit installs the installer the base names, and runs it after.
            patch: format!(
                "{}---\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n  image: reg/installer:{tag}@{DIGEST}\n",
                patch(tag)
            ),
            ..Self::new(tag)
        }
    }

    /// No base: `modules` brought, and `remove` removed.
    fn modules(tag: &str, epoch: i64, modules: &[&str], remove: &[&str]) -> Self {
        let c = Components {
            base: None,
            modules: modules.iter().map(|m| (m.to_string(), module(m))).collect(),
            remove: remove.iter().map(|m| m.to_string()).collect(),
        };
        Self {
            epoch,
            carried: c.refs().into_iter().collect(),
            components: Some(c),
            ..Self::new(tag)
        }
    }

    /// Carries its app and judge, and relies on the shared base it lists.
    fn partial(tag: &str) -> Self {
        let own = [format!("reg/app:{tag}"), format!("reg/judge:{tag}")];
        let mut refs = own.to_vec();
        refs.push(BASE.into());
        Self {
            carried: own.to_vec(),
            refs: Some(refs),
            ..Self::new(tag)
        }
    }
}

const BASE: &str = "reg/base@sha256:shared";

fn stack_ref(tag: &str) -> String {
    format!("reg/stack:{tag}")
}

fn module(name: &str) -> crate::bundle::components::Module {
    crate::bundle::components::Module {
        manifest: [(
            format!("MODULE_{}", name.to_uppercase()),
            format!("reg/modules/{name}:1@sha256:{name}"),
        )]
        .into(),
        refs: [format!("reg/{name}:1")].into(),
        flux: format!("kind: Kustomization\nmetadata: {{name: module-{name}}}\n"),
        machine: format!("apiVersion: v1alpha1\nkind: UserVolumeConfig\nname: {name}-data\n"),
    }
}

fn gzip_tar(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut b = tar::Builder::new(Vec::new());
    for (name, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        b.append_data(&mut h, name, body.as_bytes()).unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&b.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

/// A Flux artifact in `blobs`; its index entry.
fn stack_artifact(blobs: &Path, tag: &str) -> serde_json::Value {
    use sha2::Digest;
    let put = |b: &[u8]| {
        let h = hex::encode(sha2::Sha256::digest(b));
        std::fs::write(blobs.join(&h), b).unwrap();
        format!("sha256:{h}")
    };
    let layer = gzip_tar(&[
        ("base/kustomization.yaml", "resources:\n  - ../modules\n"),
        ("base/tag", tag),
        ("modules/kustomization.yaml", "resources: []\n"),
    ]);
    let config = b"{}";
    let m = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.cncf.flux.config.v1+json", "digest": put(config), "size": 2},
        "layers": [{"mediaType": "application/vnd.cncf.flux.content.v1.tar+gzip", "digest": put(&layer), "size": layer.len()}],
    });
    let bytes = serde_json::to_vec(&m).unwrap();
    serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": put(&bytes),
        "size": bytes.len(),
        "annotations": {"io.containerd.image.name": stack_ref(tag)},
    })
}

/// The files of the stack the registry holds at `tag`, composed by the unit.
fn composed_stack(h: &Harness, tag: &str) -> BTreeMap<String, String> {
    use std::io::Read;
    let w = h.w();
    let d = &w.digests[&stack_ref(tag)];
    let m: serde_json::Value = serde_json::from_slice(&w.blobs[d]).unwrap();
    let layer = &w.blobs[m["layers"][0]["digest"].as_str().unwrap()];
    let mut a = tar::Archive::new(flate2::read::GzDecoder::new(layer.as_slice()));
    let mut out = BTreeMap::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        if e.header().entry_type().is_file() {
            let mut t = String::new();
            e.read_to_string(&mut t).unwrap();
            out.insert(e.path().unwrap().display().to_string(), t);
        }
    }
    out
}

fn seed(tag: &str) -> String {
    format!(
        "apiVersion: apps/v1
kind: Deployment
metadata: {{name: stack-commit, namespace: flux-system}}
spec:
  template:
    spec:
      containers:
        - name: judge
          image: reg/judge:{tag}
"
    )
}

const BLESS: &str = "/var/mnt/edge-evidence/boot-commit/blessed";

fn settings(public: &str) -> Settings {
    let r = |n: &str| Ref::try_from(format!("flux-system/{n}")).unwrap();
    Settings {
        signing_key: public.into(),
        signature_namespace: testkit::NAMESPACE.into(),
        store: "/var/lib/etcd/state.log".into(),
        bless: BLESS.into(),
        stack: Stack {
            url: "oci://127.0.0.1:5000/stack".into(),
            flux_instance: r("flux"),
            kustomization: r("stack"),
            source: r("stack"),
            lock: r("lock"),
            judge: r("judge"),
            modules: Some(r("modules")),
        },
    }
}

impl Harness {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (key, public) = testkit::keygen(dir.path(), "update");
        let mut h = Self {
            world: Arc::new(Mutex::new(World::new())),
            dir,
            key,
            public,
            clock: Arc::new(AtomicI64::new(1_000_000)),
            engine: None,
        };
        h.reopen();
        h
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn saved(&self) -> PathBuf {
        self.state().join(SAVED_CONFIG)
    }

    fn reopen(&mut self) {
        let w = self.world.clone();
        let clock = self.clock.clone();
        self.engine = Some(
            Engine::open(
                &self.state(),
                settings(&self.public),
                Arc::new(FakeTalos(w.clone())),
                Arc::new(FakeCluster(w.clone())),
                Arc::new(FakeRegistry(w)),
                Arc::new(move || clock.load(Ordering::SeqCst)),
            )
            .unwrap(),
        );
    }

    fn e(&mut self) -> &mut Engine {
        self.engine.as_mut().unwrap()
    }

    fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// Builds, signs and uploads a bundle; returns its sha256.
    fn upload(&mut self, s: &Spec) -> String {
        self.upload_signed(s, &self.key.clone())
    }

    fn upload_signed(&mut self, s: &Spec, key: &Path) -> String {
        let src = self.dir.path().join(format!("src-{}", s.tag));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("images/blobs/sha256")).unwrap();
        let base = s.components.as_ref().is_none_or(|c| c.base.is_some());
        let mut manifests: Vec<serde_json::Value> = Vec::new();
        let mut stack = DIGEST.to_string();
        if s.components.is_some() && base {
            let e = stack_artifact(&src.join("images/blobs/sha256"), &s.tag);
            stack = e["digest"].as_str().unwrap().into();
            manifests.push(e);
        }
        let mut mf = if base {
            format!(
                "FORMAT={}\nSTACK_TAG={}\nSTACK_DIGEST={stack}\nINSTALLER_REF=reg/installer:{}@{DIGEST}\n\
                 TALOS_VERSION={}\nBUILT_EPOCH={}\nSECUREBOOT={}\n{}",
                s.format, s.tag, s.tag, s.talos, s.epoch, s.secureboot, s.extra
            )
        } else {
            format!(
                "FORMAT={}\nSTACK_TAG={}\nBUILT_EPOCH={}\nLOCK_PROFILE=edge\n",
                crate::bundle::FORMAT,
                s.tag,
                s.epoch
            )
        };
        if let Some(c) = &s.components {
            for m in c.modules.values() {
                for (k, v) in &m.manifest {
                    mf.push_str(&format!("{k}={v}\n"));
                }
            }
            let names: Vec<&str> = c.modules.keys().map(String::as_str).collect();
            if !names.is_empty() {
                mf.push_str(&format!("MODULES={}\n", names.join(" ")));
            }
            std::fs::write(
                src.join(crate::bundle::components::COMPONENTS),
                serde_json::to_vec(c).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(src.join("MANIFEST"), mf).unwrap();
        if base {
            let mut patch = s.patch.clone();
            for m in s.components.iter().flat_map(|c| c.modules.values()) {
                patch.push_str(&format!("---\n{}", m.machine));
            }
            std::fs::write(src.join("config-patch.yaml"), patch).unwrap();
            std::fs::write(src.join("seed.yaml"), seed(&s.tag)).unwrap();
        }
        if let Some(n) = &s.notes {
            std::fs::write(src.join(crate::bundle::NOTES), n).unwrap();
        }
        if let Some(i) = &s.instance {
            std::fs::write(src.join(crate::bundle::INSTANCE), i).unwrap();
        }
        std::fs::write(src.join("images/oci-layout"), "{}").unwrap();
        manifests.extend(
            s.carried
                .iter()
                .filter(|r| s.components.is_none() || **r != stack_ref(&s.tag))
                .map(|r| serde_json::json!({"annotations": {"io.containerd.image.name": r}})),
        );
        let index = serde_json::json!({ "manifests": manifests });
        std::fs::write(src.join("images/index.json"), index.to_string()).unwrap();
        // A bundle of the formats before lists no refs.
        if s.format == crate::bundle::FORMAT {
            let refs = s.refs.as_ref().unwrap_or(&s.carried);
            let mut refs: Vec<&String> = refs.iter().collect();
            refs.sort();
            refs.dedup();
            let text: String = refs.iter().map(|r| format!("{r}\n")).collect();
            std::fs::write(src.join(crate::bundle::REFS), text).unwrap();
        }
        std::fs::write(src.join("images/blobs/sha256/aa"), &s.tag).unwrap();
        testkit::seal(&src, key, testkit::NAMESPACE);
        let tar = self.dir.path().join("bundle.tar");
        testkit::pack(&src, &tar, testkit::HEAD);
        let data = std::fs::read(&tar).unwrap();
        let sha = crate::upload::hash_file(&tar).unwrap();
        let up = self.e().uploads();
        up.begin(data.len() as u64, &sha, "").unwrap();
        let chunk = crate::upload::CHUNK as usize;
        for (i, c) in data.chunks(chunk).enumerate() {
            use sha2::Digest;
            // A bundle refused as it arrives is sent no further.
            if up.put(&sha, i as u32, c, &sha2::Sha256::digest(c)).is_err() {
                break;
            }
        }
        sha
    }

    /// Runs to idle, calling `interrupt` after each recorded phase with its count.
    async fn run(&mut self, mut interrupt: impl FnMut(&mut Harness, usize)) {
        let mut moved = 0;
        for _ in 0..500 {
            match self.e().step().await {
                Ok(Tick::Idle) => return,
                Ok(Tick::Moved) => {
                    moved += 1;
                    interrupt(self, moved);
                }
                Ok(Tick::Wait(d)) => {
                    self.clock.fetch_add(d.as_secs() as i64, Ordering::SeqCst);
                }
                // A crash: the process is gone, and a new one reads the record.
                Err(_) => {
                    self.clock.fetch_add(60, Ordering::SeqCst);
                    self.reopen();
                }
            }
        }
        panic!("the engine did not settle: {:?}", self.e().record.phase);
    }

    pub(crate) async fn verify(&mut self, s: &Spec) -> Option<Entry> {
        let sha = self.upload(s);
        self.e().request_verify(&sha).unwrap();
        self.run(|_, _| {}).await;
        let r = &self.e().record;
        (r.release.is_none()).then(|| r.history[0].clone())
    }

    async fn update(&mut self, s: &Spec, interrupt: impl FnMut(&mut Harness, usize)) -> Entry {
        assert!(
            self.verify(s).await.is_none(),
            "refused: {:?}",
            self.e().record.history.first()
        );
        self.e().request_apply(&s.tag, "").await.unwrap();
        self.run(interrupt).await;
        self.e().record.history[0].clone()
    }

    fn committed(&self, tag: &str) {
        let w = self.w();
        assert!(w.committed_new(), "the new OS is not committed");
        assert!(
            w.active.contains(&format!("store:{tag}")),
            "the new config is not active"
        );
        assert!(
            w.active.contains("unit-machine-token"),
            "the unit's secrets were lost"
        );
        assert_eq!(w.tag, tag);
        assert_eq!(w.url, "oci://127.0.0.1:5000/stack");
        assert_eq!(w.judge["good"], tag);
        assert!(w.held.contains(&format!("reg/app:{tag}")));
    }
}

/// The unit's config names `installer`, as a provisioned one does.
fn running_installer(h: &Harness, installer: &str) {
    let mut w = h.w();
    w.active = format!(
        "{UNIT_CONFIG}---\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n  image: {installer}\n"
    );
    w.os_current = true;
}

#[tokio::test]
async fn the_os_the_unit_runs_is_not_installed_again() {
    let mut h = Harness::new();
    running_installer(&h, &format!("reg/installer:provisioned@{DIGEST}"));
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    let w = h.w();
    assert_eq!(
        w.log,
        ["import", "stage", "apply", "seed", "repoint update-new"]
    );
    assert_eq!(w.boot_id, 1, "rebooted");
}

#[test]
fn the_running_installer_is_the_unattended_installs_else_machine_installs() {
    let unattended = "version: v1alpha1\nmachine:\n  install:\n    image: old@sha256:1\n---\n\
                      apiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n  image: new@sha256:2\n";
    assert_eq!(installer_of(unattended), "new@sha256:2");
    assert_eq!(
        installer_of("version: v1alpha1\nmachine:\n  install:\n    image: old@sha256:1\n"),
        "old@sha256:1"
    );
    assert_eq!(installer_of(UNIT_CONFIG), "");
}

#[tokio::test]
async fn the_os_is_installed_unless_the_unit_runs_it_already() {
    let other =
        "reg/installer@sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let same = format!("reg/installer@{DIGEST}");
    let cases: [(&str, &str, bool); 4] = [
        (other, "v1.14.1", false),
        (&same, "v1.14.0", false),
        ("reg/installer:update-new", "v1.14.1", false),
        (&same, "v1.14.1", true),
    ];
    for (installer, version, apply_refused) in cases {
        let mut h = Harness::new();
        running_installer(&h, installer);
        {
            let mut w = h.w();
            w.os_current = false;
            w.version = version.into();
            w.entries
                .insert("talos-v1.14.1.efi".into(), (version.into(), None));
            w.apply_refused = apply_refused;
        }
        let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
        assert_eq!(e.outcome, Outcome::Committed, "{installer}: {}", e.detail);
        h.committed("update-new");
        assert_eq!(
            h.w().log,
            [
                "import",
                "stage",
                "install",
                "reboot",
                "seed",
                "repoint update-new"
            ],
            "{installer} {version}"
        );
    }
}

async fn happy() -> (Harness, usize, usize) {
    let mut h = Harness::new();
    let mut moved = 0;
    let e = h.update(&Spec::new("update-new"), |_, n| moved = n).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    let changes = h.w().changes;
    (h, moved, changes)
}

#[tokio::test]
async fn an_update_commits_in_order() {
    let (h, _, _) = happy().await;
    let w = h.w();
    assert_eq!(
        w.log,
        [
            "import",
            "stage",
            "install",
            "reboot",
            "seed",
            "repoint update-new"
        ]
    );
    let e = &h.engine.as_ref().unwrap().record.history[0];
    assert!(e.snapshot.is_some());
    let snaps = std::fs::read_dir(h.state().join("snapshots"))
        .unwrap()
        .count();
    assert_eq!(snaps, 1);
}

#[tokio::test]
async fn a_restart_after_any_phase_resumes() {
    let (_, phases, _) = happy().await;
    for k in 1..=phases {
        let mut h = Harness::new();
        let e = h
            .update(&Spec::new("update-new"), |h, n| {
                if n == k {
                    h.reopen()
                }
            })
            .await;
        assert_eq!(
            e.outcome,
            Outcome::Committed,
            "restart after phase {k}: {}",
            e.detail
        );
        h.committed("update-new");
        assert_eq!(
            h.w().log.iter().filter(|l| *l == "install").count(),
            1,
            "restart after phase {k}"
        );
    }
}

#[tokio::test]
async fn a_crash_after_any_change_resumes() {
    let (_, _, changes) = happy().await;
    for n in 1..=changes {
        let mut h = Harness::new();
        h.w().crash_at = Some(n);
        let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
        assert_eq!(
            e.outcome,
            Outcome::Committed,
            "crash after change {n}: {}",
            e.detail
        );
        h.committed("update-new");
    }
}

#[tokio::test]
async fn a_power_cut_after_any_phase_converges() {
    let (_, phases, _) = happy().await;
    for k in 1..=phases {
        let mut h = Harness::new();
        let e = h
            .update(&Spec::new("update-new"), |h, n| {
                if n == k {
                    h.w().power_cycle();
                    h.reopen();
                }
            })
            .await;
        if e.outcome != Outcome::Committed {
            // A cut on trial reverts the OS; nothing else may have moved.
            assert_eq!(e.outcome, Outcome::RolledBack);
            assert!(
                e.detail.contains("previous OS"),
                "cut after phase {k}: {}",
                e.detail
            );
            assert_eq!(h.w().tag, OLD_TAG, "cut after phase {k}");
            assert_eq!(h.w().active, UNIT_CONFIG, "cut after phase {k}");
            assert!(!h.w().committed_new());
            h.e().request_apply("update-new", "").await.unwrap();
            h.run(|_, _| {}).await;
            let e = h.e().record.history[0].clone();
            assert_eq!(
                e.outcome,
                Outcome::Committed,
                "retry after cut at phase {k}: {}",
                e.detail
            );
        }
        h.committed("update-new");
    }
}

#[tokio::test]
async fn a_new_os_that_does_not_stay_up_stops_the_update() {
    let mut h = Harness::new();
    h.w().trial_fails = true;
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::RolledBack);
    assert!(e.detail.contains("did not stay up"), "{}", e.detail);
    assert!(
        e.detail
            .contains("its machine config from before the update is back"),
        "{}",
        e.detail
    );
    assert!(!h.saved().exists(), "the saved config outlived the update");
    let w = h.w();
    assert_eq!(
        (w.active.as_str(), w.staged.as_deref()),
        (UNIT_CONFIG, None)
    );
    assert_eq!(w.tag, OLD_TAG);
    assert!(!w.seeded);
    assert!(!w.log.iter().any(|l| l.starts_with("repoint")));
}

#[tokio::test]
async fn cut_after_saving_keeps_unit_config() {
    // The import, then the staging: the old OS boots on the update's config.
    for n in [1, 2] {
        let mut h = Harness::new();
        {
            let mut w = h.w();
            w.trial_fails = true;
            w.crash_at = Some(n);
            w.cut_on_crash = true;
        }
        let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
        assert_eq!(e.outcome, Outcome::RolledBack, "cut after change {n}");
        assert!(
            e.detail.contains("is back"),
            "cut after change {n}: {}",
            e.detail
        );
        assert_eq!(h.w().active, UNIT_CONFIG, "cut after change {n}");
    }
}

#[tokio::test]
async fn crash_in_restore_restores_again() {
    let mut h = Harness::new();
    h.w().trial_fails = true;
    h.update(&Spec::new("update-new"), |_, _| {}).await;
    let apply = h.w().log.iter().position(|l| l == "apply").unwrap() + 1;
    for cut in [false, true] {
        let mut h = Harness::new();
        {
            let mut w = h.w();
            w.trial_fails = true;
            w.crash_at = Some(apply);
            w.cut_on_crash = cut;
        }
        let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
        assert_eq!(e.outcome, Outcome::RolledBack);
        assert!(e.detail.contains("is back"), "{}", e.detail);
        assert!(!h.saved().exists());
        let w = h.w();
        assert_eq!(w.log.iter().filter(|l| *l == "apply").count(), 2);
        assert_eq!(
            (w.active.as_str(), w.staged.as_deref()),
            (UNIT_CONFIG, None)
        );
    }
}

#[tokio::test]
async fn commit_deletes_saved_config() {
    use std::os::unix::fs::PermissionsExt;
    let mut h = Harness::new();
    let mut seen = false;
    let e = h
        .update(&Spec::new("update-new"), |h, _| {
            if h.e().record.phase == Phase::Trial {
                let p = h.saved();
                assert_eq!(std::fs::read_to_string(&p).unwrap(), UNIT_CONFIG);
                let mode = std::fs::metadata(&p).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
                seen = true;
            }
        })
        .await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    assert!(seen);
    assert!(!h.saved().exists(), "the saved config outlived the update");
}

#[tokio::test]
async fn a_stack_the_judge_rolls_back_fails_the_update() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::Bad;
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::RolledBack);
    assert!(e.detail.contains("rolled the stack back"), "{}", e.detail);
    assert_eq!(h.w().tag, OLD_TAG);
    assert!(
        h.e().record.release.is_some(),
        "a failed update stays applicable"
    );
}

#[tokio::test]
async fn a_stack_with_another_digest_is_rolled_back() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::WrongDigest;
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Failed);
    assert!(e.detail.contains("not the signed"), "{}", e.detail);
    assert_eq!(h.w().tag, OLD_TAG);
}

#[tokio::test]
async fn registry_keeps_two_releases_and_what_runs() {
    let mut h = Harness::new();
    for (i, tag) in ["update-a", "update-b", "update-c"].into_iter().enumerate() {
        let mut s = Spec::new(tag);
        s.epoch = 2000 + i as i64 * 10;
        h.w()
            .lock
            .insert("built_epoch".into(), (s.epoch - 1).to_string());
        let e = h.update(&s, |_, _| {}).await;
        assert_eq!(e.outcome, Outcome::Committed, "{tag}: {}", e.detail);
        if i == 0 {
            h.w().running.insert("reg/app:update-a".into());
        }
    }
    let held = h.w().held.clone();
    assert_eq!(
        held,
        [
            "reg/app:update-a",
            "reg/app:update-b",
            "reg/app:update-c",
            "reg/base@sha256:shared",
            "reg/judge:update-b",
            "reg/judge:update-c",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
}

#[tokio::test]
async fn partial_bundles_keep_what_they_rely_on() {
    let mut h = Harness::new();
    for (i, s) in [
        Spec::new("update-a"),
        Spec::partial("update-b"),
        Spec::partial("update-c"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut s = s;
        s.epoch = 2000 + i as i64 * 10;
        h.w()
            .lock
            .insert("built_epoch".into(), (s.epoch - 1).to_string());
        let e = h.update(&s, |_, _| {}).await;
        assert_eq!(e.outcome, Outcome::Committed, "{}: {}", s.tag, e.detail);
        assert!(h.w().held.contains(BASE), "{} collected the base", s.tag);
    }
    let c = h.e().record.history[0].release.clone().unwrap();
    assert!(c.refs.contains(BASE));
    assert!(!h.w().held.contains("reg/app:update-a"));
}

#[tokio::test]
async fn a_partial_bundle_needs_what_it_does_not_carry() {
    let mut h = Harness::new();
    refused(
        &mut h,
        &Spec::partial("update-new"),
        &format!("does not hold: {BASE}"),
    )
    .await;

    h.w().held.insert(BASE.into());
    let e = h.update(&Spec::partial("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
}

#[tokio::test]
async fn a_partial_bundle_keeps_what_a_failed_release_left_it() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::Bad;
    let e = h.update(&Spec::new("update-a"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert!(h.w().held.contains(BASE));

    h.w().verdict = Verdict::Good;
    let mut s = Spec::partial("update-b");
    s.epoch = 2010;
    let e = h.update(&s, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    assert!(
        h.w().held.contains(BASE),
        "the import collected what it runs on"
    );
}

#[tokio::test]
async fn a_bundle_of_an_old_format_is_refused_as_it_arrives() {
    let mut h = Harness::new();
    for f in ["2", "3"] {
        let mut s = Spec::new("update-new");
        s.format = f;
        let sha = h.upload(&s);
        let up = h.e().uploads().current().unwrap();
        let want = format!("the bundle is format {f}, and only format 4 is read: rebuild it");
        assert!(up.refused.contains(&want), "{}", up.refused);
        assert!(h.e().request_verify(&sha).is_err());
        assert!(h.w().log.is_empty());
    }
}

#[tokio::test]
async fn failed_update_keeps_its_judge_image() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::Bad;
    let e = h.update(&Spec::new("update-a"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert_eq!(h.w().judge_image, "reg/judge:update-a");

    h.w().verdict = Verdict::Good;
    let mut next = Spec::new("update-b");
    next.epoch = 2010;
    let mut kept = None;
    let e = h
        .update(&next, |h, _| {
            if h.e().record.phase == Phase::Snapshotting {
                kept = Some(h.w().held.contains("reg/judge:update-a"));
            }
        })
        .await;
    assert_eq!(kept, Some(true), "the import collected the running judge");
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-b");
}

#[tokio::test]
async fn broken_judge_is_replaced_not_awaited() {
    let mut h = Harness::new();
    h.w().judge_image = "reg/judge:gone".into();
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    assert_eq!(h.w().judge_image, "reg/judge:update-new");
}

async fn refused(h: &mut Harness, s: &Spec, why: &str) {
    let e = h.verify(s).await.expect("the bundle was accepted");
    assert_eq!(e.outcome, Outcome::Refused);
    assert!(e.detail.contains(why), "want {why:?}: {}", e.detail);
    assert!(
        h.w().log.is_empty(),
        "a refused bundle changed the unit: {:?}",
        h.w().log
    );
    assert!(h.e().record.release.is_none());
}

#[tokio::test]
async fn refusals_change_nothing() {
    let mut h = Harness::new();
    let mut s = Spec::new("update-new");
    s.epoch = 1000;
    refused(&mut h, &s, "REFUSING A DOWNGRADE").await;

    let mut s = Spec::new("update-new");
    s.talos = "v1.13.9".into();
    refused(&mut h, &s, "REFUSING A DOWNGRADE").await;

    let mut s = Spec::new("update-new");
    s.secureboot = "0";
    refused(&mut h, &s, "Secure Boot").await;

    let mut s = Spec::new("update-new");
    s.extra = "LOCK_PROFILE=other\n".into();
    refused(&mut h, &s, "PROFILE").await;

    let mut s = Spec::new("update-new");
    s.patch = "version: v1alpha1\ncluster:\n  token: evil\n".into();
    refused(&mut h, &s, "cluster.token").await;

    h.w().no_store = true;
    refused(&mut h, &Spec::new("update-new"), "no store").await;
    h.w().no_store = false;

    h.w().lock.remove("built_epoch");
    refused(&mut h, &Spec::new("update-new"), "built_epoch").await;
}

#[tokio::test]
async fn a_unit_on_trial_verifies_but_waits_to_apply() {
    let mut h = Harness::new();
    {
        let mut w = h.w();
        w.entries
            .insert("talos-v1.14.1~9.efi".into(), ("v1.14.1".into(), Some(2)));
        w.default = "Talos-v1.14.1~9.efi".into();
        w.power_cycle();
    }
    let s = Spec::new("update-new");
    assert_eq!(h.verify(&s).await, None, "verify was refused");
    let e = h.e().request_apply(&s.tag, "").await.unwrap_err();
    assert!(e.to_string().contains("on trial"), "{e}");
    assert_eq!(h.e().record.phase, Phase::Idle);
    assert!(h.e().record.history.is_empty());

    // Its tries spent, sd-boot falls back: the default still names it.
    h.w().power_cycle();
    h.w().power_cycle();
    assert_eq!(h.w().selected, "talos-v1.14.1.efi");
    h.e().request_apply(&s.tag, "").await.unwrap();
    h.run(|_, _| {}).await;
    assert_eq!(h.e().record.history[0].outcome, Outcome::Committed);
}

#[tokio::test]
async fn a_bless_recorded_on_an_earlier_boot_is_not_this_ones() {
    let mut h = Harness::new();
    {
        let mut w = h.w();
        w.entries
            .insert("talos-v1.14.1~9.efi".into(), ("v1.14.1".into(), Some(2)));
        w.default = "Talos-v1.14.1~9.efi".into();
        w.power_cycle();
        w.blessed_boot = Some(w.boot_id - 1);
    }
    let s = Spec::new("update-new");
    assert_eq!(h.verify(&s).await, None, "verify was refused");
    let e = h.e().request_apply(&s.tag, "").await.unwrap_err();
    assert!(e.to_string().contains("on trial"), "{e}");

    // The record names this boot: blessed, while LoaderBootCountPath stays set.
    {
        let mut w = h.w();
        w.blessed_boot = Some(w.boot_id);
        assert!(!w.count_path.is_empty());
    }
    h.e().request_apply(&s.tag, "").await.unwrap();
}

#[tokio::test]
async fn an_unreadable_bless_record_is_no_bless() {
    let mut h = Harness::new();
    {
        let mut w = h.w();
        w.entries
            .insert("talos-v1.14.1~9.efi".into(), ("v1.14.1".into(), Some(2)));
        w.default = "Talos-v1.14.1~9.efi".into();
        w.power_cycle();
        w.blessed_boot = Some(w.boot_id);
        w.bless_torn = true;
    }
    h.e().refresh_unit().await;
    assert!(h.e().unit.os_trial);
    h.w().bless_torn = false;
    h.e().refresh_unit().await;
    assert!(!h.e().unit.os_trial);
}

#[tokio::test]
async fn a_bundle_signed_by_another_key_is_refused_before_any_call() {
    let mut h = Harness::new();
    let (other, _) = testkit::keygen(h.dir.path(), "other");
    let sha = h.upload_signed(&Spec::new("update-new"), &other);
    let up = h.e().uploads().current().unwrap();
    assert!(up.refused.contains("pinned update key"), "{}", up.refused);
    assert!(h.e().request_verify(&sha).is_err());
    assert!(h.e().record.history.is_empty());
    assert_eq!(
        h.w().calls,
        0,
        "the unit was asked something before the signature verified"
    );
    assert!(!h.state().join("releases").join(&sha).exists());
}

#[tokio::test]
async fn the_same_bundle_again_is_a_rerun() {
    let (mut h, _, _) = happy().await;
    // The unit already follows it: its own epoch is not newer than itself.
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
}

#[tokio::test]
async fn an_unreadable_record_starts_afresh() {
    let mut h = Harness::new();
    std::fs::create_dir_all(h.state()).unwrap();
    std::fs::write(h.state().join("state.json"), b"{torn").unwrap();
    h.reopen();
    assert_eq!(h.e().record, Record::default());
    assert!(h.state().join("state.json.corrupt").exists());
}

#[test]
fn installer_is_pinned_by_digest_alone() {
    assert_eq!(
        installer_pin("127.0.0.1:5999/talos-installer:t1@sha256:ab"),
        "127.0.0.1:5999/talos-installer@sha256:ab"
    );
    assert_eq!(
        installer_pin("reg/installer@sha256:ab"),
        "reg/installer@sha256:ab"
    );
    assert_eq!(
        installer_pin("installer:t1@sha256:ab"),
        "installer@sha256:ab"
    );
}

#[test]
fn versions_compare_numerically() {
    assert!(version_ge("v1.14.10", "v1.14.9"));
    assert!(version_ge("v1.14.1", "v1.14.1"));
    assert!(!version_ge("v1.13.9", "v1.14.0"));
    assert!(!version_ge("garbage", "v1.0.0"));
}

#[test]
fn trial_is_read_as_boot_commit_reads_it() {
    let b = |s: &str, d: &str, o: &str, c: &str| Boot {
        selected: s.into(),
        default: d.into(),
        one_shot: o.into(),
        count_path: c.into(),
        blessed: false,
    };
    let counted = "\\EFI\\Linux\\Talos-b+2-1.efi";
    assert!(b("talos-b.efi", "Talos-b.efi", "", counted).trial());
    assert!(
        !Boot {
            blessed: true,
            ..b("talos-b.efi", "Talos-b.efi", "", counted)
        }
        .trial(),
        "blessed this boot"
    );
    assert!(
        !b("talos-a.efi", "Talos-b.efi", "", "").trial(),
        "fell back"
    );
    assert!(!b("talos-b.efi", "Talos-b.efi", "kexec reboot", counted).trial());
    assert_eq!(
        b("talos-a.efi", "Talos-b.efi", "", "").running(),
        "talos-a.efi"
    );
    assert_eq!(
        b("talos-a.efi", "Talos-b.efi", "kexec reboot", "").running(),
        "Talos-b.efi"
    );
    assert_eq!(b("", "Talos-b.efi", "", "").running(), "Talos-b.efi");
    assert_eq!(decode_efivar(&utf16("Talos-v1.efi")), "Talos-v1.efi");
}

/// Fails in `phase`, strictly after `limit` and within a poll or so of it.
async fn times_out(set: impl FnOnce(&mut World), phase: Phase, limit: i64, why: &str) -> Harness {
    let mut h = Harness::new();
    set(&mut h.w());
    let mut began = None;
    let e = h
        .update(&Spec::new("update-new"), |h, _| {
            if h.e().record.phase == phase {
                began = Some(h.e().record.since);
            }
        })
        .await;
    assert_eq!(e.outcome, Outcome::Failed, "{}", e.detail);
    assert!(e.detail.contains(why), "{}", e.detail);
    let waited = e.finished - began.expect("never reached the phase");
    assert!(
        waited > limit && waited <= limit + 60,
        "failed after {waited}s"
    );
    assert_eq!(h.w().tag, OLD_TAG, "the stack moved");
    assert!(h.e().record.error.contains(why), "{}", h.e().record.error);
    h
}

#[tokio::test]
async fn an_install_that_never_succeeds_stops_it() {
    let mut h = times_out(
        |w| w.install_fails = true,
        Phase::Installing,
        30 * 60,
        "did not install",
    )
    .await;
    {
        let w = h.w();
        assert_eq!(w.staged.as_deref().unwrap_or(&w.active), w.active);
        assert!(!w.active.contains("store:update-new"));
        assert_eq!(
            (w.selected.as_str(), w.default.as_str()),
            ("Talos-v1.14.1.efi", "Talos-v1.14.1.efi")
        );
    }
    assert!(h.e().record.history[0].snapshot.is_some());

    h.w().install_fails = false;
    h.e().request_apply("update-new", "").await.unwrap();
    assert!(
        h.e().record.error.is_empty(),
        "a new apply kept the old error"
    );
    h.run(|_, _| {}).await;
    assert_eq!(h.e().record.history[0].outcome, Outcome::Committed);
    h.committed("update-new");
}

#[tokio::test]
async fn an_operator_moving_the_stack_ends_the_judging() {
    let mut h = Harness::new();
    h.w().judge_idle = true;
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| matches!(p, Phase::Judging { .. })).await;
    h.w().tag = OLD_TAG.into();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Failed);
    assert!(
        e.detail
            .contains("an operator moved the stack to update-old"),
        "{}",
        e.detail
    );
}

#[tokio::test]
async fn workloads_that_never_settle_stop_it_before_the_stack() {
    let mut h = times_out(
        |w| w.never_ready = true,
        Phase::Settling,
        20 * 60,
        "not ready: deployment app/web. NOT moving the stack",
    )
    .await;
    let error = &h.e().record.error;
    assert!(error.contains("applying again carries on"), "{error}");
}

#[tokio::test]
async fn a_judge_that_never_rolls_out_stops_it() {
    times_out(
        |w| w.seed_stuck = true,
        Phase::Seeding,
        10 * 60,
        "did not roll out",
    )
    .await;
}

#[tokio::test]
async fn a_judge_with_nothing_to_roll_back_to_stops_it() {
    times_out(
        |w| {
            w.judge_idle = true;
            w.judge.insert("good".into(), "update-older".into());
        },
        Phase::AwaitingGood,
        20 * 60,
        "never recorded",
    )
    .await;
}

#[tokio::test]
async fn nothing_else_is_taken_while_an_update_runs() {
    let mut h = Harness::new();
    let mut refused = false;
    let e = h
        .update(&Spec::new("update-new"), |h, n| {
            if n == 1 {
                let sha = h.e().record.release.clone().unwrap().sha256;
                refused = futures::executor::block_on(h.e().request_apply("update-new", ""))
                    .is_err()
                    && h.e().request_verify(&sha).is_err();
            }
        })
        .await;
    assert!(refused, "a second request was taken mid-update");
    assert_eq!(e.outcome, Outcome::Committed);
    assert!(h.e().record.error.is_empty());
    let left = std::fs::read_dir(h.state().join("releases")).map_or(0, |d| d.count());
    assert_eq!(left, 0, "the unpacked release outlived its commit");
}

#[tokio::test]
async fn a_cut_between_install_and_its_record_does_not_install_twice() {
    let mut h = Harness::new();
    {
        let mut w = h.w();
        // import, stage, install: the cut lands straight after the install.
        w.crash_at = Some(3);
        w.cut_on_crash = true;
    }
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    assert_eq!(h.w().log.iter().filter(|l| *l == "install").count(), 1);
}

#[tokio::test]
async fn a_unit_that_committed_while_the_engine_was_away_carries_on() {
    let mut h = Harness::new();
    let e = h
        .update(&Spec::new("update-new"), |h, _| {
            if matches!(h.e().record.phase, Phase::Rebooting { .. }) {
                let mut w = h.w();
                w.power_cycle();
                w.bless();
                drop(w);
                h.reopen();
            }
        })
        .await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
}

#[tokio::test]
async fn revert_while_away_restores_config() {
    let mut h = Harness::new();
    let e = h
        .update(&Spec::new("update-new"), |h, _| {
            if matches!(h.e().record.phase, Phase::Rebooting { .. }) {
                let mut w = h.w();
                // Three counted boots, then sd-boot falls back.
                for _ in 0..4 {
                    w.power_cycle();
                }
                drop(w);
                h.reopen();
            }
        })
        .await;
    assert_eq!(e.outcome, Outcome::RolledBack);
    assert!(
        e.detail.contains("went back to its previous OS"),
        "{}",
        e.detail
    );
    assert!(e.detail.contains("is back"), "{}", e.detail);
    assert_eq!(h.w().active, UNIT_CONFIG);
}

#[tokio::test]
async fn a_stack_rolled_back_once_can_be_applied_again() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::Bad;
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::RolledBack);
    assert!(e.detail.contains("rolled the stack back"), "{}", e.detail);
    assert_eq!(h.w().tag, OLD_TAG);
    h.w().verdict = Verdict::Good;
    h.e().request_apply("update-new", "").await.unwrap();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    assert_eq!(
        h.w().log.iter().filter(|l| *l == "install").count(),
        1,
        "the committed OS was installed again"
    );
}

/// Steps until `phase` is reached, waiting as the engine asks.
async fn step_until(h: &mut Harness, at: impl Fn(&Phase) -> bool) {
    for _ in 0..500 {
        if at(&h.e().record.phase) {
            return;
        }
        match h.e().step().await.unwrap() {
            Tick::Wait(d) => {
                h.clock.fetch_add(d.as_secs() as i64, Ordering::SeqCst);
            }
            Tick::Idle => panic!("idle before the phase"),
            Tick::Moved => {}
        }
    }
    panic!("never reached the phase");
}

async fn applied(h: &mut Harness, s: &Spec) {
    assert!(h.verify(s).await.is_none());
    h.e().request_apply(&s.tag, "").await.unwrap();
}

#[tokio::test]
async fn the_unit_is_read_whatever_the_engine_does() {
    let mut h = Harness::new();
    {
        let mut w = h.w();
        w.judge.insert("previous".into(), "update-older".into());
        w.judge.insert("trial".into(), "update-next".into());
        w.judge.insert(
            "rolled_back".into(),
            "update-bad 2026-09-01T00:00:00Z".into(),
        );
    }
    assert!(h.e().refresh_unit().await);
    let read = Unit {
        talos_version: "v1.14.1".into(),
        stack_tag: OLD_TAG.into(),
        good: OLD_TAG.into(),
        previous: "update-older".into(),
        trial: "update-next".into(),
        rolled_back: "update-bad 2026-09-01T00:00:00Z".into(),
        os_trial: false,
        ..h.e().unit.clone()
    };
    assert_eq!(h.e().unit, read);
    let u = &h.e().unit;
    assert_eq!(
        (
            u.flux_version.as_str(),
            u.judge.trial.as_str(),
            u.components.len()
        ),
        ("v2.6.4", "update-next", 0)
    );
    assert!(!h.e().refresh_unit().await, "nothing changed");

    {
        let mut w = h.w();
        w.count_path = "\\EFI\\Linux\\Talos-v1.14.1~9+2-1.efi".into();
        w.tag = "update-next".into();
        w.apiserver_down = true;
    }
    assert!(h.e().refresh_unit().await);
    assert!(h.e().unit.os_trial);
    assert_eq!(
        h.e().unit.stack_tag,
        OLD_TAG,
        "an unread part keeps its reading"
    );

    {
        let mut w = h.w();
        w.apiserver_down = false;
        w.apid_down = true;
    }
    assert!(h.e().refresh_unit().await);
    let u = h.e().unit.clone();
    assert_eq!(u.stack_tag, "update-next");
    assert_eq!(
        (u.talos_version.as_str(), u.os_trial),
        ("v1.14.1", true),
        "an unread part keeps its reading"
    );
}

#[tokio::test]
async fn power_is_refused_while_an_update_runs() {
    let mut h = Harness::new();
    applied(&mut h, &Spec::new("update-new")).await;
    for at in [Phase::Importing, Phase::Settling] {
        step_until(&mut h, |p| *p == at).await;
        for p in [Power::Reboot, Power::Shutdown] {
            let e = h.e().power(p).await.unwrap_err();
            assert!(
                e.to_string().contains("update-new is under way"),
                "{at:?}: {e}"
            );
        }
    }
    h.run(|_, _| {}).await;
    assert_eq!(h.e().record.history[0].outcome, Outcome::Committed);
    let w = h.w();
    assert!(!w.log.iter().any(|l| l == "shutdown"));
    assert_eq!(w.log.iter().filter(|l| *l == "reboot").count(), 1);
}

#[tokio::test]
async fn a_reboot_on_the_os_trial_spends_a_try_and_the_trial_goes_on() {
    let mut h = Harness::new();
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| *p == Phase::Trial).await;
    let said = h.e().power(Power::Reboot).await.unwrap();
    assert_eq!(
        said,
        "rebooting: the OS on trial, talos-v1.14.1~1.efi, spends one of its boot tries"
    );
    assert_eq!(h.w().entries["talos-v1.14.1~1.efi"].1, Some(1));
    h.reopen();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
}

#[tokio::test]
async fn power_when_idle_says_what_boots_next() {
    let mut h = Harness::new();
    assert_eq!(h.e().power(Power::Shutdown).await.unwrap(), "shutting down");
    assert_eq!(h.w().log, ["shutdown"]);
    {
        let mut w = h.w();
        w.selected = "talos-v1.14.1~9.efi".into();
        w.count_path = "\\EFI\\Linux\\Talos-v1.14.1~9+2-1.efi".into();
    }
    let said = h.e().power(Power::Reboot).await.unwrap();
    assert!(
        said.starts_with("rebooting: the OS on trial, talos-v1.14.1~9.efi, spends one"),
        "{said}"
    );
    assert!(h.e().record.before.is_none());
}

fn judge_takes_requests(h: &Harness) {
    let mut w = h.w();
    w.judge_idle = true;
    w.judge.insert("requests".into(), "commit rollback".into());
}

fn newer() -> Spec {
    let mut s = Spec::new("update-newer");
    s.epoch = 3000;
    s
}

fn steps_of(e: &Entry) -> Vec<(Step, State)> {
    e.steps.iter().map(|t| (t.step, t.state)).collect()
}

#[tokio::test]
async fn steps_and_a_log_are_kept_as_the_update_goes() {
    let (h, _, _) = happy().await;
    let e = &h.engine.as_ref().unwrap().record.history[0];
    use State::Done;
    assert_eq!(
        steps_of(e),
        [
            (Step::Upload, Done),
            (Step::Verify, Done),
            (Step::Stage, Done),
            (Step::Install, Done),
            (Step::Reboot, Done),
            (Step::OsTrial, Done),
            (Step::Stack, Done),
            (Step::Trial, Done),
            (Step::Commit, Done),
        ]
    );
    assert!(
        e.steps
            .iter()
            .all(|t| t.started > 0 && t.finished >= t.started)
    );
    assert!(e.steps.windows(2).all(|w| w[0].finished <= w[1].started));
    let log: Vec<&str> = e.log.iter().map(|l| l.text.as_str()).collect();
    assert!(log.contains(&"installing the OS"), "{log:?}");
    assert_eq!(log.last(), Some(&"update-new committed"));
}

#[tokio::test]
async fn an_update_without_a_new_os_skips_its_steps() {
    let mut h = Harness::new();
    running_installer(&h, &format!("reg/installer:provisioned@{DIGEST}"));
    assert!(h.verify(&Spec::new("update-new")).await.is_none());
    let d = h.e().record.release.clone().unwrap().diff.unwrap();
    assert!(!d.reboot && d.downtime_secs == 0);
    h.e().request_apply("update-new", "ann").await.unwrap();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    assert_eq!(e.by, "ann");
    use State::{Done, Skipped};
    assert_eq!(
        steps_of(&e),
        [
            (Step::Upload, Done),
            (Step::Verify, Done),
            (Step::Stage, Done),
            (Step::Install, Skipped),
            (Step::Stack, Done),
            (Step::Trial, Done),
            (Step::Commit, Done),
        ]
    );
}

#[tokio::test]
async fn verification_says_what_applying_changes() {
    let (mut h, _, _) = happy().await;
    let mut s = newer();
    s.notes = Some("# 2\n- faster\n".into());
    assert!(h.verify(&s).await.is_none());
    let r = h.e().record.release.clone().unwrap();
    assert_eq!(r.notes.as_deref(), Some("# 2\n- faster\n"));
    let checks: Vec<(&str, CheckState)> = r
        .checks
        .iter()
        .map(|c| (c.name.as_str(), c.state))
        .collect();
    assert_eq!(
        checks,
        [
            ("signature", CheckState::Pass),
            ("compatible", CheckState::Pass),
            ("space", CheckState::Pass),
            ("reboot", CheckState::Note),
            ("downtime", CheckState::Note),
        ]
    );
    assert!(r.signer.starts_with("SHA256:"));
    let d = r.diff.unwrap();
    assert_eq!(
        d.stack,
        ("update-new".to_string(), "update-newer".to_string())
    );
    assert!(d.removals_known && d.reboot && d.config_changes);
    // The last reboot through an update, as the clock saw it.
    let rebooted = h.e().record.history[0]
        .steps
        .iter()
        .find(|t| t.step == Step::Reboot)
        .map(|t| t.finished - t.started)
        .unwrap();
    assert!(rebooted > 1 && rebooted != REBOOT);
    assert_eq!(d.downtime_secs, rebooted);
    let changes: Vec<(&str, diff::Change)> = d
        .components
        .iter()
        .map(|c| (c.name.as_str(), c.change))
        .collect();
    assert_eq!(
        changes,
        [
            ("reg/app", diff::Change::Changed),
            ("reg/base", diff::Change::Unchanged),
            ("reg/judge", diff::Change::Changed),
        ]
    );
    assert_eq!(
        h.e().unit.components.len(),
        3,
        "the running release names what runs"
    );
}

#[tokio::test]
async fn images_that_will_not_fit_are_refused() {
    let mut h = Harness::new();
    h.w().registry_free = 150;
    refused(
        &mut h,
        &Spec::new("update-new"),
        "the image store has 150 free",
    )
    .await;
}

#[tokio::test]
async fn a_stack_on_trial_commits_when_asked() {
    let mut h = Harness::new();
    judge_takes_requests(&h);
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| matches!(p, Phase::Judging { .. })).await;
    assert!(h.e().request_commit("update-other", "ann").await.is_err());
    h.e().request_commit("update-new", "ann").await.unwrap();
    assert_eq!(h.w().judge["request"], "commit update-new");
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    assert!(
        e.log
            .iter()
            .any(|l| l.text == "ann asked to commit update-new")
    );
}

#[tokio::test]
async fn a_judge_that_takes_no_requests_is_not_asked() {
    let mut h = Harness::new();
    h.w().judge_idle = true;
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| matches!(p, Phase::Judging { .. })).await;
    let e = h.e().request_commit("update-new", "ann").await.unwrap_err();
    assert!(e.to_string().contains("takes no commit"), "{e}");
    assert!(h.w().judge.get("request").is_none_or(String::is_empty));
}

#[tokio::test]
async fn a_stack_on_trial_rolls_back_when_asked() {
    let mut h = Harness::new();
    judge_takes_requests(&h);
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| matches!(p, Phase::Judging { .. })).await;
    h.e().request_rollback("update-new", "ann").await.unwrap();
    assert_eq!(h.w().judge["request"], "rollback update-new");
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert_eq!(e.rollback_reason, "ann asked");
    assert_eq!(h.w().tag, OLD_TAG);
    assert!(h.e().record.release.is_some(), "it can be applied again");
}

#[tokio::test]
async fn without_the_judge_a_rollback_moves_the_stack_itself() {
    let mut h = Harness::new();
    h.w().judge_idle = true;
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| matches!(p, Phase::Judging { .. })).await;
    h.e().request_rollback("update-new", "ann").await.unwrap();
    assert_eq!(h.w().tag, OLD_TAG);
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert_eq!(e.rollback_reason, "ann asked");
}

#[tokio::test]
async fn the_new_os_rolls_back_when_asked() {
    let mut h = Harness::new();
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| *p == Phase::Trial).await;
    assert!(h.e().request_rollback("update-other", "ann").await.is_err());
    let said = h.e().request_rollback("update-new", "ann").await.unwrap();
    assert_eq!(
        said,
        "rolling the new OS, talos-v1.14.1~1.efi, back: the unit boots Talos-v1.14.1.efi again"
    );
    assert!(h.w().log.contains(&"rollback".to_string()));
    h.reopen();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert!(e.detail.contains("an operator rolled"), "{}", e.detail);
    assert_eq!(e.rollback_reason, "ann asked");
    let w = h.w();
    assert_eq!(w.active, UNIT_CONFIG);
    assert_eq!(
        (w.tag.as_str(), w.selected.as_str()),
        (OLD_TAG, "talos-v1.14.1.efi")
    );
}

#[tokio::test]
async fn after_a_commit_the_previous_good_release_is_a_rollback_away() {
    let (mut h, _, _) = happy().await;
    assert!(h.e().request_rollback("update-older", "ann").await.is_err());
    let said = h.e().request_rollback(OLD_TAG, "ann").await.unwrap();
    assert_eq!(said, format!("update-new rolled back to {OLD_TAG}"));
    assert_eq!(h.w().tag, OLD_TAG);
    assert_eq!(h.w().url, "oci://127.0.0.1:5000/stack");
    let e = h.e().record.history[0].clone();
    assert_eq!((e.outcome, e.by.as_str()), (Outcome::RolledBack, "ann"));
    // Now on trial of the judge's, not its good release: no further back.
    assert!(h.e().request_rollback(OLD_TAG, "ann").await.is_err());
}

#[tokio::test]
async fn storage_counts_what_a_collection_frees() {
    let (mut h, _, _) = happy().await;
    let e = h.update(&newer(), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.w().held.insert("reg/app:stale".into());
    h.e().refresh_unit().await;
    let s = h.e().storage().await.unwrap();
    // The fake holds 100 bytes an image: the previous release's app and judge.
    assert_eq!((s.reclaimable, s.previous), (100, 200));
    assert_eq!(h.e().collect(false).await.unwrap(), 100);
    assert!(h.w().held.contains("reg/app:update-new"));
    assert_eq!(h.e().collect(true).await.unwrap(), 200);
    assert!(!h.w().held.contains("reg/app:update-new"));
    assert!(h.w().held.contains("reg/app:update-newer"));
    let e = h
        .e()
        .request_rollback("update-new", "ann")
        .await
        .unwrap_err();
    assert!(e.to_string().contains("were collected"), "{e}");
}

#[tokio::test]
async fn only_a_whole_upload_of_that_bundle_is_verified() {
    let mut h = Harness::new();
    let sha = h.upload(&Spec::new("update-new"));
    let e = h.e().request_verify(&"0".repeat(64)).unwrap_err();
    assert!(e.to_string().contains("no complete upload"), "{e}");
    // The same bundle begun again, nothing held yet.
    h.e().uploads().discard();
    h.e().uploads().begin(10_000, &sha, "").unwrap();
    assert!(h.e().request_verify(&sha).is_err());
}

#[tokio::test]
async fn an_update_refused_at_apply_is_dated_from_the_apply() {
    let mut h = Harness::new();
    assert!(h.verify(&Spec::new("update-new")).await.is_none());
    h.w().lock.insert("built_epoch".into(), "5000".into());
    let at = h.clock.fetch_add(3, Ordering::SeqCst) + 3;
    h.e().request_apply("update-new", "").await.unwrap();
    h.clock.fetch_add(7, Ordering::SeqCst);
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Refused, "{}", e.detail);
    assert_eq!((e.started, e.finished), (at, at + 7));
}

#[test]
fn progress_is_counted_only_while_started() {
    let p = Progress::default();
    assert_eq!(p.now(), None);
    p.start(100, 7);
    p.done.fetch_add(40, Ordering::Relaxed);
    assert_eq!(p.now(), Some((40, 100, 7)));
    p.start(50, 9);
    assert_eq!(p.now(), Some((0, 50, 9)), "a new start counts afresh");
    p.stop();
    assert_eq!(p.now(), None);
}

#[tokio::test]
async fn a_trial_the_judge_holds_with_the_engine_idle_is_asked_of_it() {
    let (mut h, _, _) = happy().await;
    judge_takes_requests(&h);
    h.e().refresh_unit().await;
    let e = h.e().request_commit("update-new", "ann").await.unwrap_err();
    assert!(e.to_string().contains("no stack is on trial"), "{e}");
    {
        let mut w = h.w();
        w.judge.insert("trial".into(), "update-other".into());
        w.tag = "update-new".into();
    }
    h.e().refresh_unit().await;
    assert!(
        h.e().request_commit("update-other", "ann").await.is_err(),
        "the unit runs another"
    );
    h.w().tag = "update-other".into();
    h.e().refresh_unit().await;
    h.e().request_commit("update-other", "ann").await.unwrap();
    assert_eq!(h.w().judge["request"], "commit update-other");
    h.w().judge.insert("request".into(), String::new());
    h.e().request_rollback("update-other", "ann").await.unwrap();
    assert_eq!(h.w().judge["request"], "rollback update-other");
}

#[tokio::test]
async fn the_same_release_again_changes_no_config() {
    let (mut h, _, _) = happy().await;
    assert!(h.verify(&Spec::new("update-new")).await.is_none());
    let d = h.e().record.release.clone().unwrap().diff.unwrap();
    assert!(!d.config_changes);
    assert!(
        d.components
            .iter()
            .all(|c| c.change == diff::Change::Unchanged)
    );
}

const INSTANCE: &str = "apiVersion: fluxcd.controlplane.io/v1\nkind: FluxInstance\nmetadata: {name: flux, namespace: flux-system}\nspec:\n  distribution: {version: 2.9.6}\n";

#[tokio::test]
async fn the_bundles_flux_instance_is_applied_once_its_stack_is() {
    let mut h = Harness::new();
    let s = Spec {
        instance: Some(INSTANCE.into()),
        ..Spec::new("update-new")
    };
    let e = h.update(&s, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    let w = h.w();
    assert_eq!(w.instance, Some((INSTANCE.into(), "update-new".into())));
    let at = |what: &str| w.log.iter().position(|l| l == what).unwrap();
    assert!(at("repoint update-new") < at("instance"), "{:?}", w.log);
}

#[tokio::test]
async fn a_flux_instance_waits_for_the_signed_stack() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::WrongDigest;
    let s = Spec {
        instance: Some(INSTANCE.into()),
        ..Spec::new("update-new")
    };
    let e = h.update(&s, |_, _| {}).await;
    assert_ne!(e.outcome, Outcome::Committed);
    assert_eq!(h.w().instance, None);
}

#[tokio::test]
async fn serving_rotation_is_turned_on_once_the_stack_is_committed() {
    let mut h = Harness::new();
    let s = Spec {
        patch: format!(
            "{}---\napiVersion: v1alpha1\nkind: KubeletConfig\nconfig:\n  serverTLSBootstrap: true\n",
            patch("update-new")
        ),
        ..Spec::new("update-new")
    };
    let e = h.update(&s, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    let w = h.w();
    assert!(!w.staged_configs.is_empty());
    assert!(
        w.staged_configs
            .iter()
            .all(|c| !c.contains("serverTLSBootstrap")),
        "the OS step turned rotation on"
    );
    assert!(w.active.contains("serverTLSBootstrap: true"));
    let at = |what: &str| w.log.iter().rposition(|l| l == what).unwrap();
    assert!(at("repoint update-new") < at("apply"), "{:?}", w.log);
}

/// A unit given a base with module `a`, without an OS step.
async fn with_a() -> Harness {
    let mut h = Harness::new();
    running_installer(&h, &format!("reg/installer:provisioned@{DIGEST}"));
    let e = h.update(&Spec::base("update-a", &["a"]), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h
}

fn manifest_of(e: &Entry) -> Manifest {
    e.release.as_ref().unwrap().manifest.clone()
}

#[tokio::test]
async fn a_bundle_without_a_base_keeps_the_base_and_the_modules_it_does_not_name() {
    let mut h = with_a().await;
    h.w().log.clear();
    let e = h
        .update(&Spec::modules("update-b", 3000, &["b"], &[]), |h, _| {
            h.reopen()
        })
        .await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    let m = manifest_of(&e);
    assert_eq!(m["MODULES"], "a b");
    assert_eq!(m["MODULE_A"], "reg/modules/a:1@sha256:a");
    assert_eq!(
        m["INSTALLER_REF"],
        format!("reg/installer:update-a@{DIGEST}")
    );
    assert_eq!(m["STACK_PATH"], "./base");
    {
        let w = h.w();
        assert!(
            !w.log.iter().any(|l| l == "install" || l == "reboot"),
            "{:?}",
            w.log
        );
        assert!(
            !w.log.iter().any(|l| l == "seed"),
            "a bundle without a base seeds nothing"
        );
        assert_eq!(w.tag, "update-b");
        for want in [
            "store:update-a",
            "name: a-data",
            "name: b-data",
            "unit-machine-token",
        ] {
            assert!(w.active.contains(want), "the config lacks {want}");
        }
        assert!(w.held.contains("reg/a:1") && w.held.contains("reg/app:update-a"));
    }
    let stack = composed_stack(&h, "update-b");
    assert_eq!(
        stack["base/tag"], "update-a",
        "the base is the one the unit ran"
    );
    assert!(stack["modules/kustomization.yaml"].contains("  - a.yaml\n  - b.yaml\n"));
    let record: serde_yaml::Value = serde_yaml::from_str(&stack["modules/installed.yaml"]).unwrap();
    assert_eq!(record["metadata"]["name"], "modules");
    assert_eq!(record["data"]["MODULES"], "a b");
}

#[tokio::test]
async fn a_bundle_with_a_base_keeps_the_modules_it_does_not_name() {
    let mut h = with_a().await;
    let mut s = Spec::base("update-b", &[]);
    s.epoch = 3000;
    let e = h.update(&s, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    assert_eq!(manifest_of(&e)["MODULES"], "a");
    let stack = composed_stack(&h, "update-b");
    assert_eq!(stack["base/tag"], "update-b");
    assert!(stack.contains_key("modules/a.yaml"));
    let w = h.w();
    assert!(w.active.contains("store:update-b") && w.active.contains("name: a-data"));
}

#[tokio::test]
async fn a_module_goes_only_by_an_explicit_remove() {
    let mut h = with_a().await;
    let e = h
        .update(&Spec::modules("update-b", 3000, &["b"], &[]), |_, _| {})
        .await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    let e = h
        .update(&Spec::modules("update-c", 4000, &[], &["a"]), |_, _| {})
        .await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    let m = manifest_of(&e);
    assert_eq!(m["MODULES"], "b");
    assert!(!m.contains_key("MODULE_A"));
    let rel = e.release.unwrap();
    assert!(!rel.refs.contains("reg/a:1") && rel.refs.contains("reg/b:1"));
    let stack = composed_stack(&h, "update-c");
    assert!(!stack.contains_key("modules/a.yaml") && stack.contains_key("modules/b.yaml"));
    let w = h.w();
    assert!(!w.active.contains("name: a-data") && w.active.contains("name: b-data"));
}

#[tokio::test]
async fn a_bundle_without_a_base_needs_a_set_the_unit_installed() {
    let mut h = Harness::new();
    refused(
        &mut h,
        &Spec::modules("update-b", 3000, &["b"], &[]),
        "bring a base and every module it runs",
    )
    .await;
}

#[tokio::test]
async fn a_rolled_back_bundle_leaves_the_set_it_was_composed_on() {
    let mut h = with_a().await;
    h.w().verdict = Verdict::Bad;
    let e = h
        .update(&Spec::modules("update-b", 3000, &["b"], &[]), |_, _| {})
        .await;
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert_eq!(h.w().tag, "update-a");
    h.e().refresh_unit().await;
    assert_eq!(h.e().unit.manifest["MODULES"], "a");

    h.w().verdict = Verdict::Good;
    let e = h
        .update(&Spec::modules("update-c", 4000, &["c"], &[]), |_, _| {})
        .await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    assert_eq!(manifest_of(&e)["MODULES"], "a c");
}

#[tokio::test]
async fn a_set_composed_on_another_stack_is_verified_again() {
    let mut h = with_a().await;
    let s = Spec::modules("update-b", 3000, &["b"], &[]);
    assert!(h.verify(&s).await.is_none());
    h.w().tag = OLD_TAG.into();
    h.e().request_apply("update-b", "").await.unwrap();
    h.run(|_, _| {}).await;
    let e = &h.e().record.history[0];
    assert_eq!(e.outcome, Outcome::Refused);
    assert!(e.detail.contains("verify it again"), "{}", e.detail);
}

#[tokio::test]
async fn with_no_recorded_set_a_bundle_brings_a_base_and_every_module_the_unit_runs() {
    let mut h = with_a().await;
    // As an engine before installed sets leaves the unit: no record of its set.
    std::fs::remove_dir_all(h.state().join("installed")).unwrap();
    h.reopen();
    h.w().log.clear();
    let partial = Spec {
        epoch: 3000,
        ..Spec::base("update-b", &["b"])
    };
    refused(
        &mut h,
        &partial,
        "bring a base and every module it runs (this bundle lacks a)",
    )
    .await;
    refused(
        &mut h,
        &Spec::modules("update-b", 3000, &["a", "b"], &[]),
        "bring a base and every module it runs",
    )
    .await;

    let whole = Spec {
        epoch: 3000,
        ..Spec::base("update-b", &["a", "b"])
    };
    let e = h.update(&whole, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    assert_eq!(e.release.unwrap().manifest["MODULES"], "a b");
}

#[tokio::test]
async fn a_unit_with_no_record_of_what_it_runs_takes_no_bundle_of_components() {
    let mut h = Harness::new();
    h.w().modules.clear();
    refused(
        &mut h,
        &Spec::base("update-a", &["a"]),
        "this unit's installed modules are unknown",
    )
    .await;
}
