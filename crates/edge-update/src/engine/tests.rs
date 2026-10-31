//! The engine against a simulated unit: Talos with sd-boot's trial and
//! boot-commit, the cluster's workloads, and a registry. Every run is
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
use crate::checks::CheckState;

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

pub(crate) struct World {
    pub(crate) version: String,
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

    /// Images the workloads run.
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
    /// Reboot requests are taken but the unit stays up.
    reboot_hangs: bool,

    /// Every change to the unit, in order.
    log: Vec<String>,
    /// Every call, reads included.
    calls: usize,
    changes: usize,
    crash_at: Option<usize>,
    /// The crash is a power cut too.
    cut_on_crash: bool,
    never_ready: bool,
    apid_down: bool,
    apiserver_down: bool,
    registry_free: u64,
    /// Every config staged for a boot.
    staged_configs: Vec<String>,
    /// The apps layouts imported, and the name they were relocated under.
    apps: Vec<(BTreeSet<String>, String)>,
    /// The host's boot signing directory: a reboot signs what is staged there.
    boot_signing: Option<PathBuf>,
    /// The boot refuses what is staged, saying why.
    sign_refuses: Option<String>,
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
            apps: Vec::new(),
            boot_signing: None,
            sign_refuses: None,
            calls: 0,
            changes: 0,
            crash_at: None,
            cut_on_crash: false,
            never_ready: false,
            apid_down: false,
            apiserver_down: false,
            registry_free: 1 << 40,
            reboot_hangs: false,
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
        let derived = w.boot_signing.is_some();
        assert!(
            image.ends_with(&format!("@{DIGEST}")) != derived && !image.contains(":update-new@"),
            "{image}"
        );
        if w.install_fails {
            return Err(crate::unit::InstallerFailed("it exited 1".into()).into());
        }
        let entry = format!("Talos-v1.14.1~{}.efi", w.entries.len());
        w.entries
            .insert(entry.to_lowercase(), ("v1.14.1".into(), Some(3)));
        w.default = entry.clone();
        w.last_installed = entry;
        w.change("install".into())
    }
    async fn reboot(&self) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        if !w.reboot_hangs {
            w.power_cycle();
            if let Some(dir) = &w.boot_signing {
                boot_sign(dir, w.sign_refuses.as_deref());
            }
        }
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
    async fn volume(&self, _: &str) -> anyhow::Result<Option<crate::unit::Volume>> {
        Ok(None)
    }
    async fn drop_partition(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Cluster for FakeCluster {
    async fn not_ready(&self) -> anyhow::Result<Vec<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        anyhow::ensure!(!w.apiserver_down, "the apiserver is not answering");
        Ok(match w.never_ready {
            true => vec!["deployment app/web".into()],
            false => Vec::new(),
        })
    }
    async fn workloads(&self) -> anyhow::Result<BTreeSet<String>> {
        Ok(["deployment app/web".to_string()].into())
    }
    async fn images_in_use(&self) -> anyhow::Result<BTreeSet<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        anyhow::ensure!(!w.apiserver_down, "the apiserver is not answering");
        Ok(w.running.clone())
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
    fn import_apps(&self, layout: &Path, host: &str) -> anyhow::Result<()> {
        let refs = crate::bundle::layout_refs(layout)?;
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        w.apps.push((refs, host.into()));
        w.change("import apps".into())
    }
    fn forget(&self, drop: &BTreeSet<String>) -> anyhow::Result<u64> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let before = w.held.len();
        w.held.retain(|r| !drop.contains(r));
        w.digests.retain(|r, _| !drop.contains(r));
        if w.held.len() != before {
            w.change("collect".into())?;
        }
        Ok(((before - w.held.len()) * 100) as u64)
    }
    fn forgettable(&self, drop: &BTreeSet<String>) -> anyhow::Result<u64> {
        let w = self.0.lock().unwrap();
        Ok((w.held.iter().filter(|r| drop.contains(*r)).count() * 100) as u64)
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
    clock: Arc<AtomicI64>,
    /// The id the engine mints next: the tag of the spec uploaded last.
    next: Arc<Mutex<String>>,
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
    carried: Vec<String>,
    notes: Option<String>,
    /// An apps layout it carries, by the refs its index names.
    apps: Vec<String>,
    /// The OS's refs.
    components: Components,
    /// `components.json` as written, in place of `components`.
    raw_components: Option<String>,
}

impl Spec {
    /// An OS running its own image and a shared one.
    pub(crate) fn new(tag: &str) -> Self {
        let carried = vec![
            format!("reg/app:{tag}"),
            format!("reg/cni:{tag}"),
            BASE.into(),
        ];
        let runs: BTreeSet<String> = carried.iter().cloned().collect();
        Self {
            tag: tag.into(),
            epoch: 2000,
            talos: "v1.14.1".into(),
            secureboot: "1",
            extra: "LOCK_PROFILE=edge\n".into(),
            patch: patch(tag),
            format: crate::bundle::FORMAT,
            carried,
            notes: None,
            apps: Vec::new(),
            components: Components { base: runs },
            raw_components: None,
        }
    }

    /// Carries its own images, and relies on the shared one it lists.
    fn partial(tag: &str) -> Self {
        Self {
            carried: vec![format!("reg/app:{tag}"), format!("reg/cni:{tag}")],
            ..Self::new(tag)
        }
    }
}

const BASE: &str = "reg/base@sha256:shared";

const BLESS: &str = "/var/mnt/edge-evidence/boot-commit/blessed";

fn settings() -> Settings {
    Settings {
        trusted_root: "/etc/edge-update/trusted_root.json".into(),
        trust_policy: Default::default(),
        store: "/var/lib/etcd/state.log".into(),
        bless: BLESS.into(),
        registry: "127.0.0.1:5000".into(),
        boot_signing: None,
    }
}

impl Harness {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut h = Self {
            world: Arc::new(Mutex::new(World::new())),
            dir,
            clock: Arc::new(AtomicI64::new(1_000_000)),
            next: Arc::default(),
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
        let mut settings = settings();
        settings.boot_signing = self
            .w()
            .boot_signing
            .clone()
            .map(|dir| crate::boot::Settings {
                dir,
                uki: "/usr/install/amd64/vmlinuz.efi".into(),
                bootloader: "/usr/install/amd64/systemd-boot.efi".into(),
            });
        let mut e = Engine::open(
            &self.state(),
            settings,
            Arc::new(testkit::trust()),
            Arc::new(FakeTalos(w.clone())),
            Arc::new(FakeCluster(w.clone())),
            Arc::new(FakeRegistry(w)),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        )
        .unwrap();
        let next = self.next.clone();
        e.mint = Arc::new(move || next.lock().unwrap().clone());
        self.engine = Some(e);
    }

    fn e(&mut self) -> &mut Engine {
        self.engine.as_mut().unwrap()
    }

    fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// Builds, signs and uploads a bundle; returns its sha256.
    fn upload(&mut self, s: &Spec) -> String {
        self.upload_signed(s, testkit::SIGNER)
    }

    fn upload_signed(&mut self, s: &Spec, signer: &str) -> String {
        let r = &self.e().record;
        let taken = r.release.iter().chain(
            r.history
                .iter()
                .filter(|e| e.outcome != Outcome::Refused)
                .filter_map(|e| e.release.as_ref()),
        );
        let id = match taken.map(|r| r.id.as_str()).any(|id| id == s.tag) {
            false => s.tag.clone(),
            true => format!("{}-again", s.tag),
        };
        *self.next.lock().unwrap() = id;
        let src = self.dir.path().join(format!("src-{}", s.tag));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("images/blobs/sha256")).unwrap();
        let c = &s.components;
        let mut manifests: Vec<serde_json::Value> = Vec::new();
        let mut mf = format!("FORMAT={}\n", s.format);
        mf.push_str(&format!(
            "INSTALLER_REF=reg/installer:{}@{DIGEST}\n\
             TALOS_VERSION={}\nBUILT_EPOCH={}\nSECUREBOOT={}\n{}",
            s.tag, s.talos, s.epoch, s.secureboot, s.extra
        ));
        let components = match &s.raw_components {
            Some(raw) => raw.clone().into_bytes(),
            None => serde_json::to_vec(c).unwrap(),
        };
        std::fs::write(src.join(crate::bundle::components::COMPONENTS), components).unwrap();
        std::fs::write(src.join("MANIFEST"), mf).unwrap();
        std::fs::write(src.join("config-patch.yaml"), &s.patch).unwrap();
        if let Some(n) = &s.notes {
            std::fs::write(src.join(crate::bundle::NOTES), n).unwrap();
        }
        if !s.apps.is_empty() {
            let apps = src.join(crate::bundle::APPS);
            std::fs::create_dir_all(apps.join("blobs/sha256")).unwrap();
            std::fs::write(apps.join("oci-layout"), "{}").unwrap();
            let named: Vec<_> = s
                .apps
                .iter()
                .map(|r| serde_json::json!({"annotations": {"io.containerd.image.name": r}}))
                .collect();
            std::fs::write(
                apps.join("index.json"),
                serde_json::json!({ "manifests": named }).to_string(),
            )
            .unwrap();
        }
        std::fs::write(src.join("images/oci-layout"), "{}").unwrap();
        manifests.extend(
            s.carried
                .iter()
                .map(|r| serde_json::json!({"annotations": {"io.containerd.image.name": r}})),
        );
        let index = serde_json::json!({ "manifests": manifests });
        std::fs::write(src.join("images/index.json"), index.to_string()).unwrap();
        std::fs::write(src.join("images/blobs/sha256/aa"), &s.tag).unwrap();
        testkit::sign_tree(&src, signer);
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
        self.e().request_verify(&sha).await.unwrap();
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
        let id = self.e().release().unwrap().id.clone();
        self.e().request_apply(&id, "").await.unwrap();
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
        assert!(w.held.contains(&format!("reg/app:{tag}")));
    }
}

/// The unit's config names `installer`, as a provisioned one does.
/// The host's boot: signs what is staged, or says why not.
fn boot_sign(dir: &Path, refuses: Option<&str>) {
    let staged = dir.join("staged");
    let Ok(manifest) = std::fs::read_to_string(staged.join(crate::bundle::MANIFEST)) else {
        return;
    };
    match refuses {
        Some(why) => std::fs::write(dir.join("refused"), why).unwrap(),
        None => {
            let signed = dir.join("signed");
            std::fs::create_dir_all(&signed).unwrap();
            for f in ["vmlinuz.efi", "systemd-boot.efi"] {
                std::fs::write(signed.join(f), format!("signed {f}")).unwrap();
            }
            let installer = manifest
                .lines()
                .find_map(|l| l.strip_prefix("INSTALLER_REF="))
                .unwrap();
            std::fs::write(signed.join("INSTALLER_REF"), format!("{installer}\n")).unwrap();
        }
    }
    std::fs::remove_dir_all(staged).unwrap();
}

impl Harness {
    /// A unit with boot keys, and the installer image the bundles name.
    fn with_boot_keys(&mut self) {
        let dir = self.dir.path().join("boot-signing");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("keys"), "").unwrap();
        let layer = b"layer".to_vec();
        let config = br#"{"rootfs":{"type":"layers","diff_ids":["sha256:aa"]}}"#.to_vec();
        let manifest = serde_json::json!({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:c0", "size": config.len()},
            "layers": [{"digest": "sha256:1a", "size": layer.len()}],
        });
        let mut w = self.w();
        w.blobs
            .insert(DIGEST.into(), manifest.to_string().into_bytes());
        w.blobs.insert("sha256:c0".into(), config);
        w.blobs.insert("sha256:1a".into(), layer);
        w.boot_signing = Some(dir);
        drop(w);
        self.reopen();
    }
}

#[tokio::test]
async fn a_new_os_is_signed_at_a_reboot_then_installed_with_the_signed_files() {
    let mut h = Harness::new();
    h.with_boot_keys();
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    h.committed("update-new");
    assert_eq!(
        h.w().log,
        ["import", "reboot", "stage", "import", "install", "reboot",]
    );
}

#[tokio::test]
async fn a_release_the_boot_refuses_installs_nothing() {
    let mut h = Harness::new();
    h.with_boot_keys();
    h.w().sign_refuses = Some("the release is unsigned".into());
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Failed);
    assert!(e.detail.contains("the release is unsigned"), "{}", e.detail);
    assert!(!h.w().log.iter().any(|l| l == "install" || l == "stage"));
}

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
    assert_eq!(w.log, ["import", "stage", "apply"]);
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
            ["import", "stage", "install", "reboot"],
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
    assert_eq!(w.log, ["import", "stage", "install", "reboot"]);
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
}

#[tokio::test]
async fn cut_after_saving_keeps_unit_config() {
    // The imports, then the staging: the old OS boots on the update's config.
    for n in [2, 3] {
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
async fn registry_keeps_two_releases_and_what_runs() {
    let mut h = Harness::new();
    for (i, tag) in ["update-a", "update-b", "update-c"].into_iter().enumerate() {
        let mut s = Spec::new(tag);
        s.epoch = 2000 + i as i64 * 10;
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
            "reg/cni:update-b",
            "reg/cni:update-c",
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
    h.w().trial_fails = true;
    let e = h.update(&Spec::new("update-a"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert!(h.w().held.contains(BASE));

    h.w().trial_fails = false;
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
    for f in ["4", "5"] {
        let mut s = Spec::new("update-new");
        s.format = f;
        let sha = h.upload(&s);
        let up = h.e().uploads().current().unwrap();
        let want = format!("the bundle is format {f}, and only format 6 is read: rebuild it");
        assert!(up.refused.contains(&want), "{}", up.refused);
        assert!(h.e().request_verify(&sha).await.is_err());
        assert!(h.w().log.is_empty());
    }
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
    // The release the unit runs is what a bundle is checked against.
    let (mut h, _, _) = happy().await;
    h.w().log.clear();
    let mut s = Spec::new("update-new");
    s.epoch = 1000;
    refused(&mut h, &s, "Downgrade:").await;

    let mut s = Spec::new("update-new");
    s.talos = "v1.13.9".into();
    refused(&mut h, &s, "Downgrade:").await;

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
}

#[tokio::test]
async fn a_unit_that_has_run_no_release_takes_the_one_it_is_provisioned_with() {
    let mut h = Harness::new();
    let mut s = Spec::new("update-first");
    s.epoch = 1;
    s.extra = "LOCK_PROFILE=any\n".into();
    let e = h.update(&s, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
}

#[tokio::test]
async fn a_bundles_apps_are_imported_under_the_registrys_name() {
    let mut h = Harness::new();
    let mut s = Spec::new("update-new");
    s.apps = vec!["127.0.0.1:5999/platform-meridian/platform-core/app:v1".into()];
    let e = h.update(&s, |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    let w = h.w();
    assert_eq!(w.apps.len(), 1);
    assert_eq!(w.apps[0].1, "127.0.0.1:5000");
    assert!(
        w.apps[0]
            .0
            .contains("127.0.0.1:5999/platform-meridian/platform-core/app:v1")
    );
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
    let sha = h.upload_signed(&Spec::new("update-new"), "a stranger");
    let up = h.e().uploads().current().unwrap();
    assert!(
        up.refused.contains("not a signer this unit trusts"),
        "{}",
        up.refused
    );
    assert!(h.e().request_verify(&sha).await.is_err());
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

/// Waits in `phase` however long, saying `why`, until a person rolls it back:
/// then the unit runs what it ran before.
async fn waits_until_rolled_back(set: impl FnOnce(&mut World), phase: Phase, why: &str) {
    let mut h = Harness::new();
    set(&mut h.w());
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| *p == phase).await;
    for _ in 0..100 {
        match h.e().step().await.unwrap() {
            Tick::Wait(d) => {
                h.clock.fetch_add(d.as_secs() as i64 * 10, Ordering::SeqCst);
            }
            t => panic!("{t:?} in {phase:?}"),
        }
    }
    assert_eq!(h.e().record.phase, phase, "a wait ended by itself");
    assert!(h.e().detail.contains(why), "{}", h.e().detail);
    h.e().request_rollback("update-new", "ann").await.unwrap();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::RolledBack, "{}", e.detail);
    assert_eq!(
        h.w().default.to_lowercase(),
        "talos-v1.14.1.efi",
        "the new OS stayed the default"
    );
}

#[tokio::test]
async fn an_installer_that_fails_stops_it() {
    let mut h = Harness::new();
    h.w().install_fails = true;
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Failed, "{}", e.detail);
    assert!(e.detail.contains("did not install"), "{}", e.detail);
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
async fn workloads_that_never_settle_wait_until_rolled_back() {
    waits_until_rolled_back(
        |w| w.never_ready = true,
        Phase::Settling,
        "waiting for deployment app/web",
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
                    && futures::executor::block_on(h.e().request_verify(&sha)).is_err();
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
        // Two imports, stage, install: the cut lands straight after the install.
        w.crash_at = Some(4);
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

#[tokio::test]
async fn a_reboot_underway_is_not_requested_again() {
    let mut h = Harness::new();
    h.w().reboot_hangs = true;
    applied(&mut h, &Spec::new("update-new")).await;
    step_until(&mut h, |p| matches!(p, Phase::Rebooting { .. })).await;
    let reboots = |h: &Harness| h.w().log.iter().filter(|l| *l == "reboot").count();
    let start = h.clock.load(Ordering::SeqCst);
    while h.clock.load(Ordering::SeqCst) - start <= 2 * REBOOT {
        let Tick::Wait(d) = h.e().step().await.unwrap() else {
            panic!("left the phase");
        };
        assert_eq!(reboots(&h), 1, "requested again while rebooting");
        h.clock.fetch_add(d.as_secs() as i64, Ordering::SeqCst);
        h.reopen();
    }
    h.e().step().await.unwrap();
    assert_eq!(
        reboots(&h),
        2,
        "a reboot that never came is not requested again"
    );
}

async fn applied(h: &mut Harness, s: &Spec) {
    assert!(h.verify(s).await.is_none());
    h.e().request_apply(&s.tag, "").await.unwrap();
}

#[tokio::test]
async fn the_unit_is_read_whatever_the_engine_does() {
    let mut h = Harness::new();
    h.w().running.insert("reg/app:running".into());
    assert!(h.e().refresh_unit().await);
    let u = h.e().unit.clone();
    assert_eq!((u.talos_version.as_str(), u.os_trial), ("v1.14.1", false));
    assert!(!h.e().refresh_unit().await, "nothing changed");

    {
        let mut w = h.w();
        w.count_path = "\\EFI\\Linux\\Talos-v1.14.1~9+2-1.efi".into();
        w.apiserver_down = true;
    }
    assert!(h.e().refresh_unit().await);
    assert!(h.e().unit.os_trial);
    assert_eq!(
        h.e().unit.components,
        u.components,
        "an unread part keeps its reading"
    );

    {
        let mut w = h.w();
        w.apiserver_down = false;
        w.apid_down = true;
        w.version = "v1.14.2".into();
    }
    h.e().refresh_unit().await;
    let u = h.e().unit.clone();
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
    assert_eq!(r.signer, testkit::SIGNER);
    let d = r.diff.unwrap();
    assert_eq!(
        d.release,
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
            ("reg/cni", diff::Change::Changed),
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
    assert_eq!(
        e.steps.last().map(|t| (t.step, t.state)),
        Some((Step::OsTrial, State::Aborted)),
        "a rollback a person asked for aborts the trial, never fails it"
    );
    let w = h.w();
    assert_eq!(w.active, UNIT_CONFIG);
    assert_eq!(w.selected, "talos-v1.14.1.efi");
}

#[tokio::test]
async fn storage_counts_what_a_collection_frees() {
    let (mut h, _, _) = happy().await;
    let e = h.update(&newer(), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Committed, "{}", e.detail);
    // What no release of this engine named is another writer's: an app core uploaded.
    h.w().held.insert("reg/app:uploaded".into());
    h.e().refresh_unit().await;
    let s = h.e().storage().await.unwrap();
    // The fake holds 100 bytes an image: the previous release's own two.
    assert_eq!((s.reclaimable, s.previous), (0, 200));
    assert_eq!(h.e().collect(false).await.unwrap(), 0);
    assert!(h.w().held.contains("reg/app:update-new"));
    assert_eq!(h.e().collect(true).await.unwrap(), 200);
    assert!(!h.w().held.contains("reg/app:update-new"));
    assert!(h.w().held.contains("reg/app:update-newer"));
    assert!(h.w().held.contains("reg/app:uploaded"));
    let e = h
        .e()
        .request_rollback("update-new", "ann")
        .await
        .unwrap_err();
    assert!(e.to_string().contains("nothing is on trial"), "{e}");
}

#[tokio::test]
async fn only_a_whole_upload_of_that_bundle_is_verified() {
    let mut h = Harness::new();
    let sha = h.upload(&Spec::new("update-new"));
    let e = h.e().request_verify(&"0".repeat(64)).await.unwrap_err();
    assert!(e.to_string().contains("no complete upload"), "{e}");
    // The same bundle begun again, nothing held yet.
    h.e().uploads().discard();
    h.e().uploads().begin(10_000, &sha, "").unwrap();
    assert!(h.e().request_verify(&sha).await.is_err());
}

#[tokio::test]
async fn an_update_refused_at_apply_is_dated_from_the_apply() {
    let mut h = Harness::new();
    assert!(h.verify(&Spec::new("update-new")).await.is_none());
    h.w().no_store = true;
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

#[tokio::test]
async fn serving_rotation_is_turned_on_once_the_workloads_settle() {
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
    assert!(at("reboot") < at("apply"), "{:?}", w.log);
}

#[tokio::test]
async fn a_provisioned_volume_is_added_while_idle_and_kept_by_every_update() {
    use crate::bundle::machineconfig::Provisioned;
    let mut h = Harness::new();
    let v = Provisioned::for_claim("6a2f0c4e-8d5b-4f3a-9c1e-0b7d2e4f6a8c");
    h.e()
        .edit_volume(VolumeEdit::Add(v.clone(), 64))
        .await
        .unwrap();
    assert!(h.w().active.contains(v.name()));
    let applies = |h: &Harness| h.w().log.iter().filter(|l| *l == "apply").count();
    let before = applies(&h);
    h.e()
        .edit_volume(VolumeEdit::Add(v.clone(), 64))
        .await
        .unwrap();
    assert_eq!(applies(&h), before, "the same volume again changes nothing");
    let e = h
        .e()
        .edit_volume(VolumeEdit::Add(v.clone(), 128))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not resized"), "{e}");

    // An update holds the machine config: a claim waits it out.
    let u = Provisioned::for_claim("another");
    assert!(h.verify(&Spec::new("update-new")).await.is_none());
    h.e().request_apply("update-new", "").await.unwrap();
    let e = h
        .e()
        .edit_volume(VolumeEdit::Add(u.clone(), 8))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("in progress"), "{e}");
    h.run(|_, _| {}).await;
    h.committed("update-new");
    let active = h.w().active.clone();
    assert!(active.contains(v.name()), "the update dropped the volume");
    assert!(active.contains("store:update-new"));

    h.w().staged = Some(active.replace("store:update-new", "store:next"));
    let e = h
        .e()
        .edit_volume(VolumeEdit::Add(u.clone(), 8))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("staged"), "{e}");
    h.w().staged = None;

    h.e()
        .edit_volume(VolumeEdit::Remove(v.clone()))
        .await
        .unwrap();
    assert!(!h.w().active.contains(v.name()));
    h.e().edit_volume(VolumeEdit::Remove(v)).await.unwrap();
}

#[test]
fn an_unsigned_bundle_is_a_note_never_a_pass() {
    assert_eq!(signature(bundle::UNSIGNED).state, CheckState::Note);
    assert_eq!(signature(testkit::SIGNER).state, CheckState::Pass);
}

#[test]
fn a_build_instant_reads_as_a_utc_date() {
    assert_eq!(built(0), "1970-01-01 00:00Z");
    assert_eq!(built(1_793_401_338), "2026-10-30 23:02Z");
}

#[test]
fn the_release_booted_is_the_one_on_trial_while_it_is() {
    let committed = Release {
        id: "s1".into(),
        ..Release::default()
    };
    let mut r = Record {
        history: vec![Entry {
            release: Some(committed),
            outcome: Outcome::Committed,
            detail: String::new(),
            started: 0,
            finished: 0,
            snapshot: None,
            steps: Vec::new(),
            log: Vec::new(),
            by: String::new(),
            rollback_reason: String::new(),
        }],
        release: Some(Release {
            id: "s2".into(),
            ..Release::default()
        }),
        ..Record::default()
    };
    r.phase = Phase::Rebooting {
        boot_id: String::new(),
        asked: None,
    };
    assert_eq!(r.booted().map(|r| r.id.as_str()), Some("s1"));
    for p in [Phase::Trial, Phase::Settling] {
        r.phase = p;
        assert_eq!(r.booted().map(|r| r.id.as_str()), Some("s2"));
    }
    r.phase = Phase::Idle;
    assert_eq!(r.booted().map(|r| r.id.as_str()), Some("s1"));
}
