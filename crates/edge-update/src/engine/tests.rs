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
use crate::bundle::testkit;
use crate::unit::{Ref, Stack};

const OLD_TAG: &str = "update-old";
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

struct World {
    version: String,
    entries: BTreeMap<String, String>,
    default: String,
    selected: String,
    one_shot: String,
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
    judge: BTreeMap<String, String>,
    judge_ticks: u32,
    verdict: Verdict,
    seeded: bool,

    held: BTreeSet<String>,
    last_installed: String,
    no_store: bool,

    /// Every change to the unit, in order.
    log: Vec<String>,
    /// Every call, reads included.
    calls: usize,
    changes: usize,
    crash_at: Option<usize>,
}

impl World {
    fn new() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert("talos-v1.14.1.efi".to_string(), "v1.14.1".to_string());
        Self {
            version: "v1.14.1".into(),
            entries,
            default: "Talos-v1.14.1.efi".into(),
            selected: "Talos-v1.14.1.efi".into(),
            one_shot: String::new(),
            boot_id: 1,
            secure_boot: true,
            active: UNIT_CONFIG.into(),
            staged: None,
            store: b"store log".to_vec(),
            trial_ticks: 0,
            trial_fails: false,
            url: "oci://127.0.0.1:3172/stack".into(),
            tag: OLD_TAG.into(),
            lock: [("built_epoch", "1000"), ("PROFILE", "edge")]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            judge: [("good", OLD_TAG)]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            judge_ticks: 0,
            verdict: Verdict::Good,
            seeded: false,
            held: BTreeSet::new(),
            last_installed: String::new(),
            no_store: false,
            log: Vec::new(),
            calls: 0,
            changes: 0,
            crash_at: None,
        }
    }

    fn change(&mut self, what: String) -> anyhow::Result<()> {
        self.log.push(what);
        self.changes += 1;
        if self.crash_at == Some(self.changes) {
            anyhow::bail!("crash after change {}", self.changes);
        }
        Ok(())
    }

    fn on_trial(&self) -> bool {
        !self.selected.eq_ignore_ascii_case(&self.default)
    }

    fn committed_new(&self) -> bool {
        !self.on_trial()
            && !self.last_installed.is_empty()
            && self.default.eq_ignore_ascii_case(&self.last_installed)
    }

    /// sd-boot: the one-shot once, else the default; a staged config applies.
    fn power_cycle(&mut self) {
        self.boot_id += 1;
        self.selected = if self.one_shot.is_empty() {
            self.default.clone()
        } else {
            std::mem::take(&mut self.one_shot)
        };
        self.version = self.entries[&self.selected.to_lowercase()].clone();
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
            self.default = self.selected.clone();
        }
    }

    /// The stack judge: a new ref is committed or rolled back after a few looks.
    fn tick_judge(&mut self) {
        let good = self.judge.get("good").cloned().unwrap_or_default();
        if self.tag == good {
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
            p if p.contains("/LoaderEntryOneShot-") => var(&w.one_shot),
            BOOT_ID => Some(format!("{}\n", w.boot_id).into_bytes()),
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
    async fn stage_config(&self, config: &str, dry_run: bool) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        assert!(config.contains("unit-machine-token") && config.contains("unit-k8s-ca-key"));
        if dry_run {
            return Ok(());
        }
        w.staged = Some(config.into());
        w.change("stage".into())
    }
    async fn install(&self, image: &str) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        assert!(
            w.staged.is_some() || w.active.contains("store:update-new"),
            "installed before staging"
        );
        assert!(image.ends_with(&format!("@{DIGEST}")) && !image.contains(":update-new@"));
        let entry = format!("Talos-v1.14.1~{}.efi", w.entries.len());
        w.entries.insert(entry.to_lowercase(), "v1.14.1".into());
        w.one_shot = entry.clone();
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
}

#[async_trait]
impl Cluster for FakeCluster {
    async fn config_map(&self, at: &Ref) -> anyhow::Result<Option<BTreeMap<String, String>>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(match at.name.as_str() {
            "lock" => Some(w.lock.clone()),
            "judge" => {
                w.tick_judge();
                Some(w.judge.clone())
            }
            _ => None,
        })
    }
    async fn sync(&self, _: &Ref) -> anyhow::Result<(String, String)> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
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
        let digest = if w.verdict == Verdict::WrongDigest && w.tag != OLD_TAG {
            "sha256:evil"
        } else {
            DIGEST
        };
        Ok(Some(format!("{}@{digest}", w.tag)))
    }
    async fn apply(&self, manifests: &str) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        assert!(
            w.committed_new(),
            "the judge was updated before the OS was committed"
        );
        assert_eq!(manifests, "kind: Judge\n");
        w.seeded = true;
        w.change("seed".into())
    }
    async fn not_rolled_out(&self, _: &str) -> anyhow::Result<Vec<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(if w.seeded {
            vec![]
        } else {
            vec!["judge".into()]
        })
    }
    async fn not_ready(&self) -> anyhow::Result<Vec<String>> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        Ok(vec![])
    }
}

impl Registry for FakeRegistry {
    fn import(&self, layout: &Path) -> anyhow::Result<()> {
        let refs = crate::bundle::layout_refs(layout)?;
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        w.held.extend(refs);
        w.change("import".into())
    }
    fn retain(&self, keep: &BTreeSet<String>) -> anyhow::Result<()> {
        let mut w = self.0.lock().unwrap();
        w.calls += 1;
        let before = w.held.len();
        w.held.retain(|r| keep.contains(r));
        if w.held.len() != before {
            w.change("collect".into())?;
        }
        Ok(())
    }
}

struct Harness {
    world: Shared,
    dir: tempfile::TempDir,
    key: PathBuf,
    public: String,
    clock: Arc<AtomicI64>,
    engine: Option<Engine>,
}

struct Spec {
    tag: String,
    epoch: i64,
    talos: String,
    secureboot: &'static str,
    extra: String,
    patch: String,
}

impl Spec {
    fn new(tag: &str) -> Self {
        Self {
            tag: tag.into(),
            epoch: 2000,
            talos: "v1.14.1".into(),
            secureboot: "1",
            extra: "LOCK_PROFILE=edge\nSTACK_PATH=./base\n".into(),
            patch: patch(tag),
        }
    }
}

fn settings(public: &str) -> Settings {
    let r = |n: &str| Ref::try_from(format!("flux-system/{n}")).unwrap();
    Settings {
        signing_key: public.into(),
        signature_namespace: testkit::NAMESPACE.into(),
        store: "/var/lib/etcd/state.log".into(),
        stack: Stack {
            url: "oci://127.0.0.1:5000/stack".into(),
            flux_instance: r("flux"),
            kustomization: r("stack"),
            source: r("stack"),
            lock: r("lock"),
            judge: r("judge"),
        },
    }
}

impl Harness {
    fn new() -> Self {
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
        let mf = format!(
            "FORMAT=2\nSTACK_TAG={}\nSTACK_DIGEST={DIGEST}\nINSTALLER_REF=reg/installer:{}@{DIGEST}\n\
             TALOS_VERSION={}\nBUILT_EPOCH={}\nSECUREBOOT={}\n{}",
            s.tag, s.tag, s.talos, s.epoch, s.secureboot, s.extra
        );
        std::fs::write(src.join("MANIFEST"), mf).unwrap();
        std::fs::write(src.join("config-patch.yaml"), &s.patch).unwrap();
        std::fs::write(src.join("seed.yaml"), "kind: Judge\n").unwrap();
        std::fs::write(src.join("images/oci-layout"), "{}").unwrap();
        let index = serde_json::json!({"manifests": [
            {"annotations": {"io.containerd.image.name": format!("reg/app:{}", s.tag)}},
            {"annotations": {"io.containerd.image.name": "reg/base@sha256:shared"}},
        ]});
        std::fs::write(src.join("images/index.json"), index.to_string()).unwrap();
        std::fs::write(src.join("images/blobs/sha256/aa"), &s.tag).unwrap();
        testkit::seal(&src, key, testkit::NAMESPACE);
        let tar = self.dir.path().join("bundle.tar");
        testkit::pack(&src, &tar, testkit::HEAD);
        let data = std::fs::read(&tar).unwrap();
        let sha = crate::upload::hash_file(&tar).unwrap();
        let up = self.e().uploads();
        up.begin(data.len() as u64, &sha).unwrap();
        let chunk = crate::upload::CHUNK as usize;
        for (i, c) in data.chunks(chunk).enumerate() {
            use sha2::Digest;
            up.put(&sha, i as u32, c, &sha2::Sha256::digest(c)).unwrap();
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
                Err(_) => self.reopen(),
            }
        }
        panic!("the engine did not settle: {:?}", self.e().record.phase);
    }

    async fn verify(&mut self, s: &Spec) -> Option<Entry> {
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
        self.e().request_apply(&s.tag).unwrap();
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
            assert_eq!(e.outcome, Outcome::Failed);
            assert!(
                e.detail.contains("previous OS"),
                "cut after phase {k}: {}",
                e.detail
            );
            assert_eq!(h.w().tag, OLD_TAG, "cut after phase {k}");
            assert!(!h.w().committed_new());
            h.e().request_apply("update-new").unwrap();
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
    assert_eq!(e.outcome, Outcome::Failed);
    assert!(e.detail.contains("did not stay up"), "{}", e.detail);
    let w = h.w();
    assert_eq!(w.tag, OLD_TAG);
    assert!(!w.seeded);
    assert!(!w.log.iter().any(|l| l.starts_with("repoint")));
}

#[tokio::test]
async fn a_stack_the_judge_rolls_back_fails_the_update() {
    let mut h = Harness::new();
    h.w().verdict = Verdict::Bad;
    let e = h.update(&Spec::new("update-new"), |_, _| {}).await;
    assert_eq!(e.outcome, Outcome::Failed);
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
async fn the_registry_keeps_the_current_and_previous_releases() {
    let mut h = Harness::new();
    for (i, tag) in ["update-a", "update-b", "update-c"].into_iter().enumerate() {
        let mut s = Spec::new(tag);
        s.epoch = 2000 + i as i64 * 10;
        h.w()
            .lock
            .insert("built_epoch".into(), (s.epoch - 1).to_string());
        let e = h.update(&s, |_, _| {}).await;
        assert_eq!(e.outcome, Outcome::Committed, "{tag}: {}", e.detail);
    }
    let held = h.w().held.clone();
    assert_eq!(
        held,
        [
            "reg/app:update-b",
            "reg/app:update-c",
            "reg/base@sha256:shared"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
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
    s.extra = "LOCK_PROFILE=appliance\n".into();
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
async fn a_unit_on_trial_is_refused() {
    let mut h = Harness::new();
    h.w().selected = "Talos-v1.14.1~9.efi".into();
    refused(&mut h, &Spec::new("update-new"), "on trial").await;
}

#[tokio::test]
async fn a_bundle_signed_by_another_key_is_refused_before_any_call() {
    let mut h = Harness::new();
    let (other, _) = testkit::keygen(h.dir.path(), "other");
    let sha = h.upload_signed(&Spec::new("update-new"), &other);
    h.e().request_verify(&sha).unwrap();
    h.run(|_, _| {}).await;
    let e = h.e().record.history[0].clone();
    assert_eq!(e.outcome, Outcome::Refused);
    assert!(e.detail.contains("pinned update key"), "{}", e.detail);
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
    let b = |s: &str, d: &str, o: &str| Boot {
        selected: s.into(),
        default: d.into(),
        one_shot: o.into(),
    };
    assert!(b("Talos-b.efi", "Talos-a.efi", "").trial());
    assert!(!b("Talos-A.efi", "talos-a.efi", "").trial());
    assert!(!b("Talos-b.efi", "Talos-a.efi", "kexec reboot").trial());
    assert!(!b("", "Talos-a.efi", "").trial());
    assert_eq!(decode_efivar(&utf16("Talos-v1.efi")), "Talos-v1.efi");
}
