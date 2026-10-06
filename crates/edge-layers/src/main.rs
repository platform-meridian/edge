//! Rewrites unpacked image files a power cut truncated, from the intact layer blob:
//! edge-registry's copy, else containerd's or the image cache's. containerd treats
//! "a snapshot exists for this chainID" as "unpacked" and never re-checks, so a torn
//! snapshot survives re-pulls and GC.

mod blobs;
mod bolt;
mod budget;
mod cache;
mod layers;
mod meta;
mod repair;
mod snapshots;
#[cfg(test)]
mod testutil;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::blobs::{Blobs, Kind};
use crate::budget::Halt;
use crate::cache::IndexCache;
use crate::snapshots::Unverifiable;

const DEFAULT_ROOT: &str = "/var/lib/containerd";
const DEFAULT_STATE: &str = "/var/lib/edge-layers";
/// edge-registry's own default root.
const DEFAULT_REGISTRY: &str = "/var/lib/edge-registry";
const IMAGE_CACHES: [&str; 2] = [
    "/system/imagecache/disk",
    "/system/imagecache/iso/imagecache",
];
const INDEX_CACHE: &str = "index";
const LEGACY_INDEX_CACHE: &str = "edge-layers";
const DEFAULT_DEADLINE_SECS: u64 = 300;

const STORE_WAIT_TICKS: u32 = 30;
const STORE_WAIT_STEP: Duration = Duration::from_secs(2);

/// A blob containerd is still writing usually lands within seconds, so an
/// unrepaired pass is retried in-process rather than by a service restart.
const REPAIR_PASSES: u32 = 3;
const REPAIR_PASS_PAUSE: Duration = Duration::from_secs(10);

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();
    if let Err(e) = edge_common::install() {
        tracing::warn!(error = %e, "could not install the SIGTERM handler");
    }
    let (repair_mode, r) = run();
    finish(repair_mode, r)
}

/// `repair` always exits 0: a restart would re-walk the same disk and fix nothing.
/// `verify`'s exit status is its answer.
fn finish(repair_mode: bool, r: anyhow::Result<()>) -> anyhow::Result<()> {
    match r {
        Err(e) if e.downcast_ref::<Halt>() == Some(&Halt::Signal) => {
            tracing::info!("SIGTERM: stopping between files");
            Ok(())
        }
        Err(e) if repair_mode => {
            tracing::error!(
                error = %format!("{e:#}"),
                "could not finish; exiting 0"
            );
            Ok(())
        }
        r => r,
    }
}

fn deadline_or_default(v: Option<&str>) -> Duration {
    let default = Duration::from_secs(DEFAULT_DEADLINE_SECS);
    let Some(v) = v else { return default };
    match v.trim().parse::<u64>() {
        Ok(n) if n >= 1 => Duration::from_secs(n),
        _ => {
            tracing::error!(
                value = v,
                default_secs = DEFAULT_DEADLINE_SECS,
                "invalid EDGE_LAYERS_DEADLINE_SECS; using the default"
            );
            default
        }
    }
}

fn poll(until: Instant, mut ready: impl FnMut() -> anyhow::Result<bool>) -> anyhow::Result<bool> {
    for _ in 0..STORE_WAIT_TICKS {
        budget::check(until)?;
        if edge_common::sleep(STORE_WAIT_STEP) {
            return Err(Halt::Signal.into());
        }
        if ready()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// On a first boot this runs before containerd has created its directories.
fn wait_for_dir(what: &str, p: &Path, until: Instant) -> anyhow::Result<()> {
    if p.is_dir() {
        return Ok(());
    }
    anyhow::ensure!(
        poll(until, || Ok(p.is_dir()))?,
        "no {what} at {} after waiting; is this the containerd root?",
        p.display()
    );
    tracing::info!(%what, "appeared while waiting");
    Ok(())
}

struct Paths {
    containerd_root: PathBuf,
    state: PathBuf,
    registry: PathBuf,
    image_caches: Vec<PathBuf>,
}

fn run() -> (bool, anyhow::Result<()>) {
    let env_or = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()));
    let paths = Paths {
        containerd_root: env_or("EDGE_LAYERS_ROOT", DEFAULT_ROOT),
        state: env_or("EDGE_LAYERS_STATE_DIR", DEFAULT_STATE),
        registry: env_or("EDGE_LAYERS_REGISTRY", DEFAULT_REGISTRY),
        image_caches: IMAGE_CACHES.iter().map(PathBuf::from).collect(),
    };
    edge_common::sandbox::restrict(&edge_common::sandbox::layers(
        &paths.containerd_root,
        &paths.state,
        Path::new("/system/imagecache"),
        &paths.registry,
    ));
    let until = Instant::now()
        + deadline_or_default(std::env::var("EDGE_LAYERS_DEADLINE_SECS").ok().as_deref());

    let repair_mode = match std::env::args().nth(1).as_deref() {
        Some("verify") | None => false,
        Some("repair") => true,
        Some(other) => {
            return (
                false,
                Err(anyhow::anyhow!(
                    "unknown command {other:?}; expected verify or repair"
                )),
            );
        }
    };
    (
        repair_mode,
        execute(&paths, repair_mode, until, REPAIR_PASS_PAUSE),
    )
}

#[derive(Debug)]
struct Unrepaired(String);

impl std::fmt::Display for Unrepaired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unrepaired {}

fn drop_legacy_cache(root: &Path) {
    let old = root.join(LEGACY_INDEX_CACHE);
    if !old.exists() {
        return;
    }
    match std::fs::remove_dir_all(&old) {
        Ok(()) => tracing::info!(dir = %old.display(), "removed the index cache's old location"),
        Err(e) => {
            tracing::warn!(dir = %old.display(), error = %e, "could not remove the index cache's old location")
        }
    }
}

fn execute(
    paths: &Paths,
    repair_mode: bool,
    until: Instant,
    pass_pause: Duration,
) -> anyhow::Result<()> {
    if repair_mode {
        drop_legacy_cache(&paths.containerd_root);
    }
    let mut pass = 1;
    loop {
        match one_pass(paths, repair_mode, until) {
            Err(e)
                if repair_mode
                    && pass < REPAIR_PASSES
                    && e.downcast_ref::<Unrepaired>().is_some() =>
            {
                tracing::warn!(pass, of = REPAIR_PASSES, retry_in = ?pass_pause, "{e:#}; trying again");
                budget::check(until)?;
                if edge_common::sleep(pass_pause) {
                    return Err(Halt::Signal.into());
                }
                pass += 1;
            }
            r => return r,
        }
    }
}

fn index_or_empty(
    blobs: &Blobs,
    until: Instant,
    only: Option<&HashSet<String>>,
    cache: &IndexCache,
) -> anyhow::Result<(Vec<layers::Layer>, usize)> {
    match layers::index_store(blobs, until, only, Some(cache)) {
        Err(e) if e.downcast_ref::<Halt>().is_some() => Err(e),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), dir = %blobs.content_store_dir().display(), "could not read the content store");
            Ok((Vec::new(), 0))
        }
        ok => ok,
    }
}

/// Unreadable metadata is not fatal: matching falls back to path sets.
fn provenance(snapshotter: &Path, indexes: &[meta::Index]) -> Option<meta::Provenance> {
    match meta::read(snapshotter, indexes) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                "snapshot metadata unreadable; matching layers by path set"
            );
            None
        }
    }
}

fn blobs_to_index(
    snaps: &[snapshots::Snapshot],
    prov: Option<&meta::Provenance>,
) -> Option<HashSet<String>> {
    let prov = prov?;
    Some(
        snaps
            .iter()
            .filter(|s| !s.files.is_empty())
            .filter_map(|s| match prov.get(&s.id) {
                Some(meta::Origin::Layer { blobs, .. }) => Some(blobs),
                _ => None,
            })
            .flatten()
            .cloned()
            .collect(),
    )
}

/// Snapshots whose blob is in no source, while no image cache is mounted yet and
/// no edge-registry store holds the host's images: then only a cache keeps them.
fn awaiting_image_cache(cov: &snapshots::Coverage, blobs: &Blobs) -> bool {
    blobs.has(Kind::ImageCache)
        && blobs.present(Kind::Registry) == 0
        && blobs.present(Kind::ImageCache) == 0
        && !no_layer_blob(cov).is_empty()
}

/// Snapshots of images no source holds, such as one pulled from outside a release
/// once containerd discarded its layers: unverifiable, never repaired from nowhere.
fn no_layer_blob(cov: &snapshots::Coverage) -> Vec<&str> {
    cov.unmatched
        .iter()
        .filter(|u| u.why == Unverifiable::NoLayerBlob)
        .map(|u| u.id.as_str())
        .collect()
}

fn one_pass(paths: &Paths, repair_mode: bool, until: Instant) -> anyhow::Result<()> {
    let root = &paths.containerd_root;
    let blobs = Blobs::content_store(root.join("io.containerd.content.v1.content/blobs/sha256"))
        .with_registry(&paths.registry)
        .with_image_caches(&paths.image_caches);
    let snapshotter = root.join("io.containerd.snapshotter.v1.overlayfs");
    let snaps = snapshotter.join("snapshots");

    for (what, p) in [
        ("content store", blobs.content_store_dir()),
        ("snapshots", &snaps),
    ] {
        wait_for_dir(what, p, until)?;
    }

    let snapshot_set = snapshots::walk(&snaps)?;
    let files: usize = snapshot_set.iter().map(|s| s.files.len()).sum();
    tracing::info!(
        snapshots = snapshot_set.len(),
        files,
        "walked the unpacked layers"
    );

    let stale: usize = snapshot_set.iter().map(|s| s.stale_temps.len()).sum();
    if stale > 0 {
        if repair_mode {
            snapshots::remove_stale_temps(&snapshot_set);
        } else {
            tracing::warn!(
                stale,
                "leftover repair temp files inside snapshots; `repair` removes them"
            );
        }
    }

    if files == 0 {
        tracing::info!(outcome = "verified clean", "no unpacked files yet");
        return Ok(());
    }

    let indexes = [
        meta::Index::registry(&paths.registry),
        meta::Index::content_store(blobs.content_store_dir()),
    ];
    let prov = provenance(&snapshotter, &indexes);
    let only = blobs_to_index(&snapshot_set, prov.as_ref());
    if only.as_ref().is_some_and(HashSet::is_empty) {
        tracing::info!(
            outcome = "verified clean",
            "no image layer among the snapshots with files"
        );
        return Ok(());
    }

    let cache = IndexCache::new(paths.state.join(INDEX_CACHE), repair_mode);
    cache.prune(&blobs);

    // Early in boot an empty store means containerd is still importing.
    let (mut index, mut from_cache) = index_or_empty(&blobs, until, only.as_ref(), &cache)?;
    if index.is_empty()
        && poll(until, || {
            (index, from_cache) = index_or_empty(&blobs, until, only.as_ref(), &cache)?;
            Ok(!index.is_empty())
        })?
    {
        tracing::info!("content store filled while waiting");
    }

    // Nothing to verify against is not a clean pass.
    anyhow::ensure!(
        !index.is_empty(),
        "no layers in the registry at {}, under {} or in an image cache to verify against: \
         point EDGE_LAYERS_REGISTRY at edge-registry's store, or set `discard_unpacked_layers = false`",
        paths.registry.display(),
        blobs.content_store_dir().display()
    );

    let (mut torn, mut cov) = snapshots::find_torn(&snapshot_set, &index, prov.as_ref());
    if awaiting_image_cache(&cov, &blobs)
        && poll(until, || Ok(blobs.present(Kind::ImageCache) > 0))?
    {
        tracing::info!("image cache appeared while waiting");
        (index, from_cache) = index_or_empty(&blobs, until, only.as_ref(), &cache)?;
        (torn, cov) = snapshots::find_torn(&snapshot_set, &index, prov.as_ref());
    }
    let held_by = |k| {
        index
            .iter()
            .filter(|l| blobs.find(&l.digest).is_some_and(|(_, at)| at == k))
            .count()
    };
    tracing::info!(
        layers = index.len(),
        from_cache,
        in_registry = held_by(Kind::Registry),
        in_content_store = held_by(Kind::ContentStore),
        in_image_cache = held_by(Kind::ImageCache),
        registry = blobs.present(Kind::Registry) > 0,
        image_caches = blobs.present(Kind::ImageCache),
        "indexed"
    );

    let why = |w| cov.unmatched.iter().filter(|u| u.why == w).count();
    tracing::info!(
        by_chain_id = cov.by_chain_id,
        by_path_set = cov.by_path_set,
        layers_verified = cov.layers_verified,
        layers_indexed = cov.layers_indexed,
        snapshots_empty = cov.empty,
        rw_layers = why(Unverifiable::NotALayer),
        no_layer_blob = why(Unverifiable::NoLayerBlob),
        unrecorded = why(Unverifiable::Unrecorded),
        no_unique_path_set = why(Unverifiable::NoUniquePathSet),
        incomplete = why(Unverifiable::Incomplete),
        "coverage"
    );
    if prov.is_none() && cov.layers_verified < cov.layers_indexed {
        tracing::info!(
            unaccounted = cov.layers_indexed - cov.layers_verified,
            "layers with no snapshot to compare against; usually not unpacked yet"
        );
    }

    let unheld = no_layer_blob(&cov);
    if !unheld.is_empty() {
        tracing::warn!(
            snapshots = ?unheld,
            "unverifiable: no layer blob in the registry, the content store or an image cache"
        );
    }

    // Unmatched snapshots are mostly container read-write layers and cannot be
    // repaired from the store, so they are reported, never failed on.
    let suspect: Vec<_> = cov.suspect().collect();
    if !suspect.is_empty() {
        tracing::info!(
            snapshots = suspect.len(),
            empty_files = suspect.iter().map(|u| u.empty).sum::<usize>(),
            "unverifiable snapshots hold empty files; not repairable from the store, usually benign"
        );
    }

    if torn.is_empty() {
        tracing::info!(
            outcome = "verified clean",
            checked = cov.checked(),
            "every checked file matches its layer"
        );
        return Ok(());
    }

    for t in &torn {
        tracing::warn!(
            snapshot = %t.snapshot, namespace = %t.namespace, path = %t.path,
            on_disk = t.on_disk, expected = t.expected,
            layer = %t.layer_digest, matched_by = %t.matched_by,
            "truncated"
        );
    }

    if !repair_mode {
        anyhow::bail!(
            "{} torn file(s) found; run `edge-layers repair`",
            torn.len()
        );
    }

    let r = repair::repair_all(&blobs, &torn, until);
    tracing::info!(
        outcome = if r.failed == 0 {
            "repaired"
        } else {
            "unrepaired"
        },
        fixed = r.fixed,
        failed = r.failed,
        bytes = r.bytes,
        snapshots = torn
            .iter()
            .map(|t| &t.snapshot)
            .collect::<HashSet<_>>()
            .len(),
        checked = cov.checked(),
        "repair complete"
    );
    if r.halted == Some(Halt::Signal) {
        return Err(Halt::Signal.into());
    }
    if r.failed > 0 {
        return Err(Unrepaired(format!(
            "{} of {} torn file(s) could not be repaired{}",
            r.failed,
            torn.len(),
            r.halted.map(|h| format!(" ({h})")).unwrap_or_default()
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{
        BLOBS, CA, IMAGECACHE, SNAPS, SNAPSHOTTER, discard_layers, fixture_root, images,
        layer_blob, registry_from,
    };
    use std::os::unix::fs::PermissionsExt;

    fn root_with(content: &[u8], on_disk: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let blobs = d.path().join(BLOBS);
        let bin = d.path().join(SNAPS).join("1/fs/bin");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(blobs.join("aa11"), layer_blob(&[("./bin/tool", content)])).unwrap();
        std::fs::write(bin.join("tool"), on_disk).unwrap();
        (d, bin.join("tool"))
    }

    fn at(d: &Path) -> Paths {
        Paths {
            containerd_root: d.to_path_buf(),
            state: d.join("edge-layers-state"),
            registry: d.join(REGISTRY),
            image_caches: vec![d.join(IMAGECACHE)],
        }
    }

    /// No image cache: the fixture's holds every layer, a unit's only Talos's own.
    fn uncached(d: &Path) -> Paths {
        Paths {
            image_caches: vec![],
            ..at(d)
        }
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    const CA_SNAPSHOTS: [&str; 3] = ["2", "4", "6"];
    const REGISTRY: &str = "registry";

    fn in_snapshot(root: &Path, id: &str, path: &str) -> PathBuf {
        root.join(SNAPS).join(id).join("fs").join(path)
    }

    fn truncate_every_ca(root: &Path) -> Vec<Vec<u8>> {
        CA_SNAPSHOTS
            .iter()
            .map(|id| {
                let f = in_snapshot(root, id, CA);
                let whole = std::fs::read(&f).unwrap();
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&f)
                    .unwrap()
                    .set_len(whole.len() as u64 / 2)
                    .unwrap();
                whole
            })
            .collect()
    }

    #[test]
    fn shared_path_set_repaired_per_layer() {
        let d = fixture_root();
        let originals = truncate_every_ca(d.path());
        let sizes: Vec<_> = originals.iter().map(Vec::len).collect();
        assert!(sizes[0] != sizes[1] && sizes[1] != sizes[2], "{sizes:?}");

        let e = execute(&at(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("3 torn file"), "{e:#}");

        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        for (id, want) in CA_SNAPSHOTS.iter().zip(&originals) {
            assert!(
                std::fs::read(in_snapshot(d.path(), id, CA)).unwrap() == *want,
                "snapshot {id} does not hold its own layer's bytes"
            );
        }
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
    }

    #[test]
    fn matches_by_chain_id_else_path_set() {
        let d = fixture_root();
        let blobs = d.path().join(BLOBS);
        let snapshotter = d.path().join(SNAPSHOTTER);
        let walked = snapshots::walk(&d.path().join(SNAPS)).unwrap();
        let (index, _) =
            layers::index_store(&Blobs::content_store(blobs.clone()), far(), None, None).unwrap();
        truncate_every_ca(d.path());
        let walked_torn = snapshots::walk(&d.path().join(SNAPS)).unwrap();

        let cs = [meta::Index::content_store(&blobs)];
        let prov = provenance(&snapshotter, &cs);
        assert!(prov.is_some());
        let (torn, cov) = snapshots::find_torn(&walked_torn, &index, prov.as_ref());
        assert_eq!(
            (cov.by_chain_id, cov.by_path_set),
            (8, 0),
            "k8s.io and system's copy of img1"
        );
        assert_eq!(
            torn.iter().map(|t| t.snapshot.as_str()).collect::<Vec<_>>(),
            CA_SNAPSHOTS
        );
        assert!(
            torn.iter()
                .all(|t| t.matched_by == snapshots::MatchedBy::ChainId)
        );

        let only = blobs_to_index(&walked, prov.as_ref()).unwrap();
        assert_eq!(only.len(), 8);

        std::fs::write(snapshotter.join("metadata.db"), b"torn").unwrap();
        let prov = provenance(&snapshotter, &cs);
        assert!(prov.is_none());
        assert_eq!(blobs_to_index(&walked, None), None);
        let (torn, cov) = snapshots::find_torn(&walked_torn, &index, None);
        assert_eq!(
            (cov.by_chain_id, cov.by_path_set),
            (0, 4),
            "the three bases and system's copy of one"
        );
        assert!(torn.is_empty(), "path sets cannot tell the ca layers apart");
        assert!(
            cov.unmatched
                .iter()
                .all(|u| u.why == snapshots::Unverifiable::NoUniquePathSet)
        );
        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
    }

    /// The layer blob each ca snapshot was unpacked from.
    fn ca_blobs(root: &Path) -> Vec<String> {
        let p = provenance(
            &root.join(SNAPSHOTTER),
            &[meta::Index::content_store(&root.join(BLOBS))],
        )
        .unwrap();
        CA_SNAPSHOTS
            .iter()
            .map(|id| match &p[*id] {
                meta::Origin::Layer { blobs, .. } => blobs[0].clone(),
                o => panic!("{id}: {o:?}"),
            })
            .collect()
    }

    fn assert_restored(root: &Path, originals: &[Vec<u8>]) {
        for (id, want) in CA_SNAPSHOTS.iter().zip(originals) {
            assert!(
                std::fs::read(in_snapshot(root, id, CA)).unwrap() == *want,
                "snapshot {id} does not hold its own layer's bytes"
            );
        }
    }

    #[test]
    fn repairs_from_registry_once_layers_discarded() {
        let d = fixture_root();
        assert_eq!(
            registry_from(d.path(), &d.path().join(REGISTRY), |_| true),
            3
        );
        discard_layers(d.path());
        let originals = truncate_every_ca(d.path());

        let e = execute(&uncached(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("3 torn file"), "{e:#}");
        execute(&uncached(d.path()), true, far(), Duration::ZERO).unwrap();
        assert_restored(d.path(), &originals);
        execute(&uncached(d.path()), false, far(), Duration::ZERO).unwrap();
    }

    #[test]
    fn registry_index_alone_names_the_layer() {
        let d = fixture_root();
        registry_from(d.path(), &d.path().join(REGISTRY), |_| true);
        for e in std::fs::read_dir(d.path().join(BLOBS)).unwrap().flatten() {
            std::fs::remove_file(e.path()).unwrap();
        }
        let originals = truncate_every_ca(d.path());

        execute(&uncached(d.path()), true, far(), Duration::ZERO).unwrap();
        assert_restored(d.path(), &originals);
    }

    #[test]
    fn content_store_covers_images_the_registry_lacks() {
        let d = fixture_root();
        let first = ca_blobs(d.path()).remove(0);
        let released = |layers: &[String]| layers.contains(&first);
        assert_eq!(
            registry_from(d.path(), &d.path().join(REGISTRY), released),
            1
        );
        for (_, layers) in images(d.path()).iter().filter(|(_, l)| released(l)) {
            for l in layers {
                std::fs::remove_file(d.path().join(BLOBS).join(l)).unwrap();
            }
        }
        let originals = truncate_every_ca(d.path());

        let e = execute(&uncached(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("3 torn file"), "{e:#}");
        execute(&uncached(d.path()), true, far(), Duration::ZERO).unwrap();
        assert_restored(d.path(), &originals);
    }

    #[test]
    fn unverifiable_when_no_source_holds_the_layer() {
        let d = fixture_root();
        let first = ca_blobs(d.path()).remove(0);
        let reg = d.path().join(REGISTRY);
        registry_from(d.path(), &reg, |l| l.contains(&first));
        discard_layers(d.path());
        let originals = truncate_every_ca(d.path());

        let e = execute(&uncached(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("1 torn file"), "{e:#}");
        execute(&uncached(d.path()), true, far(), Duration::ZERO).unwrap();
        assert_restored(d.path(), &originals[..1]);
        for (id, whole) in CA_SNAPSHOTS.iter().zip(&originals).skip(1) {
            let f = in_snapshot(d.path(), id, CA);
            assert_eq!(
                std::fs::metadata(f).unwrap().len(),
                whole.len() as u64 / 2,
                "{id}"
            );
        }

        let blobs = Blobs::content_store(d.path().join(BLOBS)).with_registry(&reg);
        let (index, _) = layers::index_store(&blobs, far(), None, None).unwrap();
        let prov = provenance(
            &d.path().join(SNAPSHOTTER),
            &[
                meta::Index::registry(&reg),
                meta::Index::content_store(&d.path().join(BLOBS)),
            ],
        );
        let walked = snapshots::walk(&d.path().join(SNAPS)).unwrap();
        let (_, cov) = snapshots::find_torn(&walked, &index, prov.as_ref());
        let mut unheld = no_layer_blob(&cov);
        unheld.sort();
        assert_eq!(unheld, ["10", "11", "3", "4", "5", "6"]);
    }

    #[test]
    fn rerun_uses_index_cache() {
        let d = fixture_root();
        let cache = at(d.path()).state.join(INDEX_CACHE);
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
        assert!(!cache.exists(), "verify wrote");
        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 8);

        for e in std::fs::read_dir(d.path().join(BLOBS)).unwrap() {
            let p = e.unwrap().path();
            if std::fs::read(&p).unwrap().starts_with(&[0x1f, 0x8b]) {
                std::fs::remove_file(&p).unwrap();
                std::fs::write(&p, b"not a layer").unwrap();
            }
        }
        truncate_every_ca(d.path());
        let e = execute(&at(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("3 torn file"), "{e:#}");
    }

    /// Every copy of the ca bundle, in both namespaces; snapshot 11's layer blob was
    /// deleted by containerd's GC.
    const EVERY_CA: [&str; 5] = ["2", "4", "6", "9", "11"];
    const KUBELET: (&str, &str) = ("10", "usr/local/bin/kubelet");

    fn cut(f: &Path, to: u64) -> Vec<u8> {
        let whole = std::fs::read(f).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(f)
            .unwrap()
            .set_len(to)
            .unwrap();
        whole
    }

    #[test]
    fn repairs_from_image_cache() {
        let d = fixture_root();
        let mut originals: Vec<(PathBuf, Vec<u8>)> = EVERY_CA
            .iter()
            .map(|id| {
                let f = in_snapshot(d.path(), id, CA);
                let half = std::fs::metadata(&f).unwrap().len() / 2;
                (f.clone(), cut(&f, half))
            })
            .collect();
        let kubelet = in_snapshot(d.path(), KUBELET.0, KUBELET.1);
        originals.push((kubelet.clone(), cut(&kubelet, 0)));

        let without_cache = Paths {
            image_caches: vec![],
            ..at(d.path())
        };
        let e = execute(&without_cache, false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("4 torn file"), "{e:#}");
        execute(&without_cache, true, far(), Duration::ZERO).unwrap();
        assert!(
            std::fs::read(&kubelet).unwrap().is_empty(),
            "no source, yet written"
        );

        let e = execute(&at(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("2 torn file"), "{e:#}");
        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        for (f, want) in &originals {
            assert!(std::fs::read(f).unwrap() == *want, "{}", f.display());
        }
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
    }

    #[test]
    fn waits_for_late_image_cache() {
        // The cache is mounted after the first poll, so a wait that ends early is caught.
        let d = fixture_root();
        let kubelet = in_snapshot(d.path(), KUBELET.0, KUBELET.1);
        let whole = cut(&kubelet, 100);
        let mounted = d.path().join(IMAGECACHE);
        let later = d.path().join("not-yet-mounted");
        std::fs::rename(&mounted, &later).unwrap();

        let appear = std::thread::spawn(move || {
            std::thread::sleep(STORE_WAIT_STEP + Duration::from_millis(500));
            std::fs::rename(&later, &mounted).unwrap();
        });
        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        appear.join().unwrap();
        assert!(std::fs::read(&kubelet).unwrap() == whole);
    }

    #[test]
    fn registry_store_skips_image_cache_wait() {
        let d = fixture_root();
        let first = ca_blobs(d.path()).remove(0);
        registry_from(d.path(), &d.path().join(REGISTRY), |l| l.contains(&first));
        discard_layers(d.path());
        std::fs::remove_dir_all(d.path().join(IMAGECACHE)).unwrap();

        let start = Instant::now();
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
        assert!(start.elapsed() < STORE_WAIT_STEP * STORE_WAIT_TICKS / 2);
    }

    #[test]
    fn repair_drops_old_index_cache() {
        let d = fixture_root();
        let old = d.path().join(LEGACY_INDEX_CACHE).join("index");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("aa.json"), b"{}").unwrap();

        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
        assert!(old.exists(), "verify removed");
        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        assert!(!d.path().join(LEGACY_INDEX_CACHE).exists());
        assert!(at(d.path()).state.join(INDEX_CACHE).is_dir());
    }

    #[test]
    fn rw_layer_never_repaired() {
        let d = fixture_root();
        for p in ["usr/lib/os-release", "bin/tool1"] {
            let f = in_snapshot(d.path(), "7", p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, b"edited").unwrap();
        }
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
        std::fs::remove_file(d.path().join(SNAPSHOTTER).join("metadata.db")).unwrap();
        let e = execute(&at(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("2 torn file"), "{e:#}");
    }

    #[test]
    fn verify_reports_repair_fixes() {
        let content = vec![7u8; 50_000];
        let (d, f) = root_with(&content, &content[..40_960]);
        let e = execute(&at(d.path()), false, far(), Duration::ZERO).unwrap_err();
        assert!(format!("{e:#}").contains("1 torn file"), "{e:#}");
        assert_eq!(std::fs::metadata(&f).unwrap().len(), 40_960, "verify wrote");

        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), content);
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
    }

    #[test]
    fn repair_removes_leftover_temp() {
        let (d, f) = root_with(b"twelve bytes", b"twelve bytes");
        let tmp = f.with_file_name("tool.edge-layers-tmp");
        std::fs::write(&tmp, b"half").unwrap();
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
        assert!(tmp.exists());
        execute(&at(d.path()), true, far(), Duration::ZERO).unwrap();
        assert!(!tmp.exists());
    }

    #[test]
    fn expired_deadline_errors() {
        let (d, _) = root_with(b"abc", b"abc");
        let e = execute(&at(d.path()), false, Instant::now(), Duration::ZERO).unwrap_err();
        assert_eq!(e.downcast_ref::<Halt>(), Some(&Halt::Deadline), "{e:#}");
    }

    #[test]
    fn nothing_unpacked_passes_at_once() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(BLOBS)).unwrap();
        std::fs::create_dir_all(d.path().join(SNAPS)).unwrap();
        execute(
            &at(d.path()),
            false,
            Instant::now() + Duration::from_millis(500),
            Duration::ZERO,
        )
        .unwrap();
    }

    #[test]
    fn store_without_layers_fails() {
        let (d, _) = root_with(b"abc", b"abc");
        std::fs::write(d.path().join(BLOBS).join("aa11"), b"{}").unwrap();
        let e = execute(
            &at(d.path()),
            true,
            Instant::now() + Duration::from_secs(1),
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(e.downcast_ref::<Halt>(), Some(&Halt::Deadline), "{e:#}");
    }

    #[test]
    fn unreadable_store_waited_on() {
        let (d, _) = root_with(b"abc", b"abc");
        let blobs = d.path().join(BLOBS);
        std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(&blobs).is_err();
        let r = execute(
            &at(d.path()),
            false,
            Instant::now() + Duration::from_secs(1),
            Duration::ZERO,
        );
        std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755)).unwrap();
        if unreadable {
            let e = r.unwrap_err();
            assert_eq!(e.downcast_ref::<Halt>(), Some(&Halt::Deadline), "{e:#}");
        }
    }

    #[test]
    fn store_filled_while_waiting_used() {
        let content = vec![3u8; 1000];
        let (d, _) = root_with(&content, &content[..10]);
        let blob = d.path().join(BLOBS).join("aa11");
        let bytes = std::fs::read(&blob).unwrap();
        std::fs::remove_file(&blob).unwrap();
        let fill = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            std::fs::write(&blob, bytes).unwrap();
        });
        let e = execute(&at(d.path()), false, far(), Duration::ZERO).unwrap_err();
        fill.join().unwrap();
        assert!(format!("{e:#}").contains("1 torn file"), "{e:#}");
    }

    #[test]
    fn waits_for_missing_dir() {
        let (d, _) = root_with(b"abc", b"abc");
        let snaps = d.path().join(SNAPS);
        let moved = d.path().join("later");
        std::fs::rename(&snaps, &moved).unwrap();

        let e = execute(
            &at(d.path()),
            false,
            Instant::now() + Duration::from_secs(1),
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(e.downcast_ref::<Halt>(), Some(&Halt::Deadline), "{e:#}");

        let appear = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            std::fs::rename(&moved, &snaps).unwrap();
        });
        execute(&at(d.path()), false, far(), Duration::ZERO).unwrap();
        appear.join().unwrap();
    }

    #[test]
    fn bad_deadline_uses_default() {
        assert_eq!(deadline_or_default(None), Duration::from_secs(300));
        assert_eq!(deadline_or_default(Some(" 45 ")), Duration::from_secs(45));
        for bad in ["soon", "0", "-5", ""] {
            assert_eq!(
                deadline_or_default(Some(bad)),
                Duration::from_secs(300),
                "{bad}"
            );
        }
    }

    #[test]
    fn repair_always_exits_zero() {
        for e in [
            anyhow::anyhow!("no layers found"),
            anyhow::Error::from(Halt::Deadline),
            anyhow::Error::from(Unrepaired("1 of 1".into())),
        ] {
            let msg = format!("{e:#}");
            assert!(finish(true, Err(e)).is_ok(), "{msg}");
        }
        assert!(finish(false, Err(anyhow::anyhow!("1 torn file(s) found"))).is_err());
        assert!(finish(false, Err(Halt::Deadline.into())).is_err());
        assert!(finish(false, Err(Halt::Signal.into())).is_ok());
    }

    fn read_only(f: &Path) -> bool {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::OpenOptions::new().write(true).open(f).is_err()
    }

    #[test]
    fn failed_pass_retried() {
        let content = vec![9u8; 30_000];
        let (d, f) = root_with(&content, &content[..10_000]);
        if !read_only(&f) {
            return; // root
        }
        let f2 = f.clone();
        let unblock = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            std::fs::set_permissions(&f2, std::fs::Permissions::from_mode(0o644)).unwrap();
        });
        execute(&at(d.path()), true, far(), Duration::from_millis(200)).unwrap();
        unblock.join().unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), content);
    }

    #[test]
    fn repair_gives_up_after_passes() {
        let content = vec![9u8; 30_000];
        let (d, f) = root_with(&content, &content[..10_000]);
        if !read_only(&f) {
            return;
        }
        let started = Instant::now();
        let e = execute(&at(d.path()), true, far(), Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.to_string(), "1 of 1 torn file(s) could not be repaired");
        assert!(e.downcast_ref::<Unrepaired>().is_some());
        let took = started.elapsed();
        assert!(
            (Duration::from_millis(100)..Duration::from_secs(5)).contains(&took),
            "{took:?}: two pauses between three passes"
        );
    }
}
