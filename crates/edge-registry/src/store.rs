use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use edge_common::{durable_write, durable_write_with, sync_dir};
use nix::fcntl::{Flock, FlockArg};

use crate::digest::copy_hashing;
use crate::manifest::{Descriptor, Manifest};
use crate::reference::{repo_dir, repo_from_dir, valid_tag};
use crate::{Digest, ImageRef};

const BLOBS: &str = "blobs/sha256";
const MANIFESTS: &str = "manifests/sha256";
const TAGS: &str = "tags";
const LOCK: &str = "lock";

/// A content-addressed image store: `blobs/sha256/<hex>`, `manifests/sha256/<hex>`
/// and `tags/<repo>/<tag>` holding a digest.
///
/// Writes land whole, children first, and removals go parents first, so after a
/// power cut every tag resolves to a manifest whose blobs are all present.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub images: Vec<ImageRef>,
    pub manifests: usize,
    pub blobs: usize,
    pub bytes: u64,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Store> {
        let store = Store { root: root.into() };
        for dir in [BLOBS, MANIFESTS, TAGS] {
            store.create_dir(Path::new(dir))?;
        }
        Ok(store)
    }

    fn create_dir(&self, rel: &Path) -> io::Result<()> {
        let mut dir = self.root.clone();
        for part in rel {
            dir.push(part);
            if !dir.is_dir() {
                std::fs::create_dir_all(&dir)?;
                sync_dir(dir.parent().unwrap_or(&self.root))?;
            }
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join(BLOBS).join(digest.hex())
    }

    fn manifest_path(&self, digest: &Digest) -> PathBuf {
        self.root.join(MANIFESTS).join(digest.hex())
    }

    fn tag_path(&self, repo: &str, tag: &str) -> PathBuf {
        self.root.join(TAGS).join(repo_dir(repo)).join(tag)
    }

    /// The manifest's media type and bytes.
    pub fn manifest(&self, digest: &Digest) -> io::Result<Option<(String, Vec<u8>)>> {
        let bytes = match std::fs::read(self.manifest_path(digest)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let media_type = Manifest::parse(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .media_type;
        Ok(Some((media_type, bytes)))
    }

    /// `reference` is a tag or a digest; `repo` a normalised repository.
    pub fn resolve(&self, repo: &str, reference: &str) -> Option<Digest> {
        let digest = match reference.parse::<Digest>() {
            Ok(d) => d,
            Err(_) if valid_tag(reference) && repo_from_dir(&repo_dir(repo)).is_some() => {
                std::fs::read_to_string(self.tag_path(repo, reference))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()?
            }
            Err(_) => return None,
        };
        self.manifest_path(&digest).is_file().then_some(digest)
    }

    /// The repositories held, under any registry, whose path is `path`, as Talos's registryd finds them.
    pub fn repos_at_path(&self, path: &str) -> Vec<String> {
        let mut repos: Vec<String> = entries(&self.tag_dir())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(dir, _)| repo_from_dir(&dir))
            .filter(|r| r.split_once('/').is_some_and(|(_, p)| p == path))
            .collect();
        repos.sort();
        repos
    }

    pub fn list(&self) -> io::Result<Listing> {
        let mut listing = Listing {
            images: self.tags()?,
            ..Listing::default()
        };
        for (dir, count) in [
            (MANIFESTS, &mut listing.manifests),
            (BLOBS, &mut listing.blobs),
        ] {
            for (_, path) in entries(&self.root.join(dir))? {
                *count += 1;
                listing.bytes += path.metadata().map_or(0, |m| m.len());
            }
        }
        Ok(listing)
    }

    pub(crate) fn tags(&self) -> io::Result<Vec<ImageRef>> {
        let mut images = Vec::new();
        for (dir, path) in entries(&self.root.join(TAGS))? {
            let Some(repo) = repo_from_dir(&dir) else {
                continue;
            };
            for (tag, path) in entries(&path).unwrap_or_default() {
                let digest = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|s| s.trim().parse().ok());
                if valid_tag(&tag)
                    && let Some(digest) = digest
                {
                    images.push(ImageRef {
                        repo: repo.clone(),
                        tag: Some(tag),
                        digest: Some(digest),
                    });
                }
            }
        }
        images.sort();
        Ok(images)
    }

    pub(crate) fn set_tag(&self, repo: &str, tag: &str, digest: &Digest) -> io::Result<()> {
        self.create_dir(&Path::new(TAGS).join(repo_dir(repo)))?;
        durable_write(&self.tag_path(repo, tag), format!("{digest}\n").as_bytes())
    }

    pub(crate) fn remove_tag(&self, repo: &str, tag: &str) -> io::Result<()> {
        std::fs::remove_file(self.tag_path(repo, tag))
    }

    /// Visible only once `from` hashes to the descriptor's digest and size.
    pub(crate) fn put_blob(&self, want: &Descriptor, from: impl Read) -> io::Result<()> {
        durable_write_with(&self.blob_path(&want.digest), |f| {
            let (digest, size) = copy_hashing(from, f)?;
            if digest != want.digest || size != want.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "content is {digest} ({size} bytes), expected {} ({} bytes)",
                        want.digest, want.size
                    ),
                ));
            }
            Ok(())
        })
    }

    pub(crate) fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).is_file()
    }

    pub(crate) fn has_manifest(&self, digest: &Digest) -> bool {
        self.manifest_path(digest).is_file()
    }

    pub(crate) fn put_manifest(&self, digest: &Digest, bytes: &[u8]) -> io::Result<()> {
        durable_write(&self.manifest_path(digest), bytes)
    }

    pub(crate) fn children_and_blobs(&self, digest: &Digest) -> Option<(Vec<Digest>, Vec<Digest>)> {
        let m = Manifest::parse(&std::fs::read(self.manifest_path(digest)).ok()?).ok()?;
        let digests = |ds: Vec<Descriptor>| ds.into_iter().map(|d| d.digest).collect();
        Some((digests(m.children), digests(m.blobs)))
    }

    pub(crate) fn blob_dir(&self) -> PathBuf {
        self.root.join(BLOBS)
    }

    pub(crate) fn manifest_dir(&self) -> PathBuf {
        self.root.join(MANIFESTS)
    }

    pub(crate) fn tag_dir(&self) -> PathBuf {
        self.root.join(TAGS)
    }

    /// Serialises writers: imports, sweeps and repairs.
    pub(crate) fn lock(&self) -> io::Result<Flock<File>> {
        Flock::lock(self.lock_file()?, FlockArg::LockExclusive).map_err(|(_, e)| e.into())
    }

    fn try_lock(&self) -> io::Result<Option<Flock<File>>> {
        match Flock::lock(self.lock_file()?, FlockArg::LockExclusiveNonblock) {
            Ok(l) => Ok(Some(l)),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, e)) => Err(e.into()),
        }
    }

    fn lock_file(&self) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(LOCK))
    }

    /// Removes what a power cut can leave: temp files, then manifests missing a
    /// blob, then tags naming a missing manifest. Skipped while a writer holds
    /// the store; [`Store::verify`] catches rot.
    pub fn repair(&self) -> io::Result<usize> {
        let Some(_lock) = self.try_lock()? else {
            tracing::info!("store busy with a writer; not repairing");
            return Ok(0);
        };
        self.drop_incomplete()
    }

    fn drop_incomplete(&self) -> io::Result<usize> {
        let blobs = self.remove_where(&self.blob_dir(), |name, path| {
            Digest::from_hex(name).ok_or("not a digest")?;
            path.is_file().then_some(()).ok_or("not a file")
        })?;
        let manifests = self.remove_where(&self.manifest_dir(), |name, path| {
            Digest::from_hex(name).ok_or("not a digest")?;
            let bytes = std::fs::read(path).map_err(|_| "unreadable")?;
            let m = Manifest::parse(&bytes).map_err(|_| "not a manifest")?;
            match m.blobs.iter().all(|b| self.has_blob(&b.digest)) {
                true => Ok(()),
                false => Err("missing a blob"),
            }
        })?;
        let mut tags = self.remove_where(&self.tag_dir(), |name, path| {
            repo_from_dir(name).ok_or("not a repository")?;
            path.is_dir().then_some(()).ok_or("not a directory")
        })?;
        for (_, repo) in entries(&self.tag_dir())? {
            tags += self.remove_where(&repo, |tag, path| {
                if !valid_tag(tag) {
                    return Err("not a tag");
                }
                let digest: Digest = std::fs::read_to_string(path)
                    .map_err(|_| "unreadable")?
                    .trim()
                    .parse()
                    .map_err(|_| "not a digest")?;
                match self.has_manifest(&digest) {
                    true => Ok(()),
                    false => Err("names a missing manifest"),
                }
            })?;
        }
        Ok(blobs + manifests + tags)
    }

    /// Hashes every blob and manifest and removes any that does not match its
    /// name, with what then lacks it. Hashing runs unlocked; only removal waits.
    pub fn verify(&self) -> io::Result<usize> {
        let mut removed = 0;
        for dir in [self.blob_dir(), self.manifest_dir()] {
            for (name, path) in entries(&dir)? {
                let Some(digest) = Digest::from_hex(&name) else {
                    continue;
                };
                if hashes_to(&path, &digest) != Some(false) {
                    continue;
                }
                let _lock = self.lock()?;
                // A writer may have replaced it with good content meanwhile.
                if hashes_to(&path, &digest) == Some(false) {
                    tracing::warn!(path = %path.display(), "removing: content does not match");
                    remove(&path)?;
                    sync_dir(&dir)?;
                    removed += 1 + self.drop_incomplete()?;
                }
            }
        }
        Ok(removed)
    }

    fn remove_where(
        &self,
        dir: &Path,
        check: impl Fn(&str, &Path) -> Result<(), &'static str>,
    ) -> io::Result<usize> {
        let mut removed = 0;
        for (name, path) in entries(dir)? {
            if let Err(why) = check(&name, &path) {
                tracing::warn!(path = %path.display(), why, "removing");
                remove(&path)?;
                removed += 1;
            }
        }
        sync_dir(dir)?;
        Ok(removed)
    }
}

/// None when the file is gone.
fn hashes_to(path: &Path, digest: &Digest) -> Option<bool> {
    let file = File::open(path).ok()?;
    Some(copy_hashing(file, &mut io::sink()).is_ok_and(|(got, _)| got == *digest))
}

// A name that is not UTF-8 comes back lossy, and so never valid.
pub(crate) fn entries(dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        out.push((e.file_name().to_string_lossy().into_owned(), e.path()));
    }
    Ok(out)
}

pub(crate) fn remove(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        _ => std::fs::remove_file(path),
    }
}
