//! The write side (ADR-0015, finding C): the instance registry takes what core
//! uploads, and deletes what the platform controller collects, from them alone.
//!
//! Pushed content lives in a store of its own, beside the base's: the base's
//! store is collected by what the unit's releases keep, this one by the
//! controller's deletes, so neither collection can take the other's.
//!
//! A caller is a Kubernetes ServiceAccount: it presents a projected token for
//! the audience [`AUDIENCE`], verified offline against the keys the
//! apiserver signs ServiceAccount tokens with (Talos's
//! `service-account.pub`). A token for that audience opens nothing at the
//! apiserver, and lives minutes. Core's account may push; the controller's
//! may delete; any other, or none, is refused.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::manifest::{Descriptor, Manifest};
use crate::reference::valid_tag;
use crate::server::{Body, DOCKER_CONTENT_DIGEST, Write, error, full};
use crate::{Digest, Store};

/// The audience a token must be for.
pub const AUDIENCE: &str = "edge-registry";
/// The largest manifest taken.
pub const MAX_MANIFEST: usize = 4 << 20;

/// What a caller may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Upload blobs and put manifests: core.
    Push,
    /// Delete manifests: the platform controller.
    Delete,
}

/// Who may push and who may delete, and the keys that say who a caller is.
pub struct Authority {
    keys: Vec<(DecodingKey, Algorithm)>,
    pusher: String,
    deleter: String,
}

#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
}

impl Authority {
    /// `keys`: PEM public keys (EC P-256 or RSA), as many as the file holds.
    /// `pusher` and `deleter`: `system:serviceaccount:<namespace>:<name>`.
    pub fn new(keys: &[u8], pusher: &str, deleter: &str) -> anyhow::Result<Self> {
        let mut out = Vec::new();
        for block in pem::parse_many(keys).context("the keys are not PEM")? {
            let one = pem::encode(&block);
            let key = DecodingKey::from_ec_pem(one.as_bytes())
                .map(|k| (k, Algorithm::ES256))
                .or_else(|_| {
                    DecodingKey::from_rsa_pem(one.as_bytes()).map(|k| (k, Algorithm::RS256))
                })
                .with_context(|| {
                    format!("a {} block is not an EC or RSA public key", block.tag())
                })?;
            out.push(key);
        }
        anyhow::ensure!(!out.is_empty(), "no key");
        for who in [pusher, deleter] {
            anyhow::ensure!(
                who.strip_prefix("system:serviceaccount:")
                    .is_some_and(|r| r.split(':').count() == 2 && !r.contains("::")),
                "{who:?} is not system:serviceaccount:<namespace>:<name>"
            );
        }
        Ok(Self {
            keys: out,
            pusher: pusher.into(),
            deleter: deleter.into(),
        })
    }

    pub fn load(keys: &Path, pusher: &str, deleter: &str) -> anyhow::Result<Self> {
        let bytes = std::fs::read(keys).with_context(|| format!("reading {}", keys.display()))?;
        Self::new(&bytes, pusher, deleter)
    }

    /// The role of the caller whose `Authorization` header this is.
    pub fn role(&self, authorization: Option<&str>) -> Result<Role, String> {
        let token = authorization
            .and_then(|a| a.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or("no bearer token")?;
        let sub = self
            .keys
            .iter()
            .find_map(|(key, alg)| {
                let mut v = Validation::new(*alg);
                v.set_audience(&[AUDIENCE]);
                v.set_required_spec_claims(&["exp", "aud", "sub"]);
                jsonwebtoken::decode::<Claims>(token, key, &v).ok()
            })
            .map(|t| t.claims.sub)
            .ok_or("the token is not the apiserver's, or not for this registry, or expired")?;
        if sub == self.pusher {
            Ok(Role::Push)
        } else if sub == self.deleter {
            Ok(Role::Delete)
        } else {
            Err(format!("{sub} may neither push nor delete"))
        }
    }
}

/// Where the keys are, and whose accounts may push and delete. The keys are
/// read at each write: Talos writes them once the control plane is rendered,
/// after this registry is up, and rotates them in place.
pub struct Accounts {
    pub keys: PathBuf,
    pub pusher: String,
    pub deleter: String,
}

impl Accounts {
    pub fn role(&self, authorization: Option<&str>) -> Result<Role, String> {
        Authority::load(&self.keys, &self.pusher, &self.deleter)
            .map_err(|e| format!("no authority to check a caller against: {e:#}"))?
            .role(authorization)
    }
}

/// The pushed store, and the uploads under way into it.
pub struct Pushed {
    pub store: Store,
    pub accounts: Accounts,
    uploads: PathBuf,
    next: AtomicU64,
}

impl Pushed {
    pub fn open(root: &Path, accounts: Accounts) -> anyhow::Result<Arc<Self>> {
        let store = Store::open(root)?;
        let uploads = root.join("uploads");
        // An upload does not outlive the process that took it.
        let _ = std::fs::remove_dir_all(&uploads);
        std::fs::create_dir_all(&uploads)?;
        Ok(Arc::new(Self {
            store,
            accounts,
            uploads,
            next: AtomicU64::new(0),
        }))
    }

    /// A new upload's id.
    pub fn begin(&self) -> std::io::Result<String> {
        let id = format!(
            "{}-{}",
            std::process::id(),
            self.next.fetch_add(1, Ordering::Relaxed)
        );
        std::fs::File::create(
            self.upload(&id)
                .ok_or_else(|| std::io::Error::other("bad id"))?,
        )?;
        Ok(id)
    }

    /// The file an upload's bytes accumulate in; `None` for a name that is not one.
    pub fn upload(&self, id: &str) -> Option<PathBuf> {
        let ours = !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit() || b == b'-');
        ours.then(|| self.uploads.join(id))
    }

    /// The upload `id` taken as the blob `digest`, if it hashes to it.
    pub fn finish(&self, id: &str, digest: &Digest) -> anyhow::Result<()> {
        let path = self.upload(id).context("no such upload")?;
        let size = std::fs::metadata(&path).context("no such upload")?.len();
        let r = if self.store.has_blob(digest) {
            Ok(())
        } else {
            let want = Descriptor {
                digest: digest.clone(),
                size,
                annotations: Default::default(),
            };
            self.store
                .put_blob(&want, std::fs::File::open(&path)?)
                .map_err(anyhow::Error::from)
        };
        let _ = std::fs::remove_file(&path);
        r
    }

    /// Puts a manifest under `reference` in `repo`: a tag, or the digest it
    /// hashes to. Everything it names must be held already. Returns its digest.
    pub fn put_manifest(
        &self,
        repo: &str,
        reference: &str,
        bytes: &[u8],
    ) -> anyhow::Result<Digest> {
        anyhow::ensure!(bytes.len() <= MAX_MANIFEST, "the manifest is too large");
        let digest = Digest::of(bytes);
        let tag = match reference.parse::<Digest>() {
            Ok(d) => {
                anyhow::ensure!(d == digest, "the manifest is {digest}, not {d}");
                None
            }
            Err(_) => {
                anyhow::ensure!(valid_tag(reference), "{reference:?} is not a tag");
                Some(reference)
            }
        };
        let m = Manifest::parse(bytes).map_err(|e| anyhow::anyhow!("not a manifest: {e}"))?;
        let _lock = self.store.lock()?;
        for b in &m.blobs {
            anyhow::ensure!(
                self.store.has_blob(&b.digest),
                "blob {} is not held",
                b.digest
            );
        }
        for c in &m.children {
            anyhow::ensure!(
                self.store.has_manifest(&c.digest),
                "manifest {} is not held",
                c.digest
            );
        }
        self.store.put_manifest(&digest, bytes)?;
        if let Some(tag) = tag {
            self.store.set_tag(repo, tag, &digest)?;
        }
        Ok(digest)
    }

    /// Deletes the manifest `digest` and the tags in `repo` naming it, then
    /// the blobs no manifest names that were pushed over a day ago: a younger
    /// one may belong to an upload whose manifest is still to come.
    pub fn delete_manifest(&self, repo: &str, digest: &Digest) -> anyhow::Result<bool> {
        let _lock = self.store.lock()?;
        if !self.store.has_manifest(digest) {
            return Ok(false);
        }
        self.store.untag(repo, digest)?;
        self.store.remove_manifest(digest)?;
        self.store
            .sweep_unnamed_blobs(std::time::Duration::from_secs(24 * 3600))?;
        Ok(true)
    }
}

/// The largest upload taken.
const MAX_BLOB: u64 = 32 << 30;

/// Appends a request body to the upload `id`; its size after.
async fn append(p: &Pushed, id: &str, mut body: hyper::body::Incoming) -> anyhow::Result<u64> {
    use http_body_util::BodyExt as _;
    use tokio::io::AsyncWriteExt as _;
    let path = p.upload(id).context("no such upload")?;
    anyhow::ensure!(path.is_file(), "no such upload");
    let mut f = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .await?;
    let mut size = f.metadata().await?.len();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            size += data.len() as u64;
            anyhow::ensure!(size <= MAX_BLOB, "the blob is larger than {MAX_BLOB} bytes");
            f.write_all(&data).await?;
        }
    }
    f.flush().await?;
    Ok(size)
}

fn located(status: http::StatusCode, location: &str) -> http::response::Builder {
    http::Response::builder()
        .status(status)
        .header(http::header::LOCATION, location)
        .header(http::header::CONTENT_LENGTH, 0)
}

/// Carries out `w`, which the caller's role allows, for the registry named `host`.
pub(crate) async fn write(
    p: &Arc<Pushed>,
    host: &str,
    w: Write,
    body: hyper::body::Incoming,
) -> anyhow::Result<http::Response<Body>> {
    use http::StatusCode;
    let empty = || full(bytes::Bytes::new());
    let finish = |p: Arc<Pushed>, id: String, digest: Digest| async move {
        tokio::task::spawn_blocking(move || p.finish(&id, &digest)).await?
    };
    Ok(match w {
        Write::Begin { name, digest } => {
            let id = p.begin()?;
            match digest {
                Some(d) => {
                    append(p, &id, body).await?;
                    finish(p.clone(), id, d.clone()).await?;
                    located(StatusCode::CREATED, &format!("/v2/{name}/blobs/{d}"))
                        .header(DOCKER_CONTENT_DIGEST, d.to_string())
                        .body(empty())?
                }
                None => located(
                    StatusCode::ACCEPTED,
                    &format!("/v2/{name}/blobs/uploads/{id}"),
                )
                .header("docker-upload-uuid", &id)
                .header(http::header::RANGE, "0-0")
                .body(empty())?,
            }
        }
        Write::Append { name, id } => {
            let size = append(p, &id, body).await?;
            located(
                StatusCode::ACCEPTED,
                &format!("/v2/{name}/blobs/uploads/{id}"),
            )
            .header("docker-upload-uuid", &id)
            .header(http::header::RANGE, format!("0-{}", size.saturating_sub(1)))
            .body(empty())?
        }
        Write::Finish { name, id, digest } => {
            append(p, &id, body).await?;
            finish(p.clone(), id, digest.clone()).await?;
            located(StatusCode::CREATED, &format!("/v2/{name}/blobs/{digest}"))
                .header(DOCKER_CONTENT_DIGEST, digest.to_string())
                .body(empty())?
        }
        Write::Manifest { name, reference } => {
            use http_body_util::BodyExt as _;
            let limited = http_body_util::Limited::new(body, MAX_MANIFEST);
            let bytes = limited
                .collect()
                .await
                .map_err(|e| anyhow::anyhow!("reading the manifest: {e}"))?
                .to_bytes();
            let repo = format!("{host}/{name}");
            let (p2, r2) = (p.clone(), reference.clone());
            let digest =
                tokio::task::spawn_blocking(move || p2.put_manifest(&repo, &r2, &bytes)).await??;
            tracing::info!(repo = %format!("{host}/{name}"), %reference, %digest, "manifest pushed");
            located(
                StatusCode::CREATED,
                &format!("/v2/{name}/manifests/{digest}"),
            )
            .header(DOCKER_CONTENT_DIGEST, digest.to_string())
            .body(empty())?
        }
        Write::Delete { name, digest } => {
            let repo = format!("{host}/{name}");
            let (p2, d2) = (p.clone(), digest.clone());
            let gone =
                tokio::task::spawn_blocking(move || p2.delete_manifest(&repo, &d2)).await??;
            if gone {
                tracing::info!(repo = %format!("{host}/{name}"), %digest, "manifest deleted");
                http::Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(empty())?
            } else {
                error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "not held")
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    // A P-256 key, as Talos's service-account key is.
    const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDK331EumFEcyY/Kp
DFarwEZgsBaO7lvVZUP/DrVEDl+hRANCAASajR7Pu+b0+jKpDws8nNwjs0O3ULbv
fQFUbupG9+wIul6vIcLW84AWpP7HSp30rZY38vcnoobbgL24T1v1v0RL
-----END PRIVATE KEY-----
";
    const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmo0ez7vm9PoyqQ8LPJzcI7NDt1C2
730BVG7qRvfsCLperyHC1vOAFqT+x0qd9K2WN/L3J6KG24C9uE9b9b9ESw==
-----END PUBLIC KEY-----
";
    const CORE: &str = "system:serviceaccount:meridian:platform-core";
    const CONTROLLER: &str = "system:serviceaccount:meridian-system:platform-controller";

    fn token(sub: &str, aud: &str, exp_in: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = serde_json::json!({"sub": sub, "aud": [aud], "exp": now + exp_in, "iss": "https://kubernetes.default.svc"});
        let key = EncodingKey::from_ec_pem(KEY.as_bytes()).unwrap();
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap()
    }

    fn authority() -> Authority {
        Authority::new(PUBLIC.as_bytes(), CORE, CONTROLLER).unwrap()
    }

    #[test]
    fn only_core_pushes_and_only_the_controller_deletes() {
        let a = authority();
        let bearer = |t: String| format!("Bearer {t}");
        assert_eq!(
            a.role(Some(&bearer(token(CORE, AUDIENCE, 600)))),
            Ok(Role::Push)
        );
        assert_eq!(
            a.role(Some(&bearer(token(CONTROLLER, AUDIENCE, 600)))),
            Ok(Role::Delete)
        );
        for (t, why) in [
            (None, "no bearer token"),
            (
                Some(bearer(token(CORE, "https://kubernetes.default.svc", 600))),
                "not for this registry",
            ),
            (Some(bearer(token(CORE, AUDIENCE, -600))), "expired"),
            (
                Some(bearer(token(
                    "system:serviceaccount:meridian:app-fusion",
                    AUDIENCE,
                    600,
                ))),
                "may neither push nor delete",
            ),
            (Some("Basic dTpw".into()), "no bearer token"),
        ] {
            let e = a.role(t.as_deref()).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        // Another key's token.
        let mut forged = token(CORE, AUDIENCE, 600);
        forged.replace_range(forged.len() - 4.., "AAAA");
        assert!(a.role(Some(&bearer(forged))).is_err());
    }

    #[test]
    fn an_authority_needs_a_key_and_accounts() {
        assert!(Authority::new(b"", CORE, CONTROLLER).is_err());
        assert!(Authority::new(PUBLIC.as_bytes(), "platform-core", CONTROLLER).is_err());
        let two = format!("{PUBLIC}{PUBLIC}");
        assert!(Authority::new(two.as_bytes(), CORE, CONTROLLER).is_ok());
    }

    fn pushed() -> (tempfile::TempDir, Arc<Pushed>) {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("sa.pub"), PUBLIC).unwrap();
        let accounts = Accounts {
            keys: d.path().join("sa.pub"),
            pusher: CORE.into(),
            deleter: CONTROLLER.into(),
        };
        let p = Pushed::open(&d.path().join("pushed"), accounts).unwrap();
        (d, p)
    }

    #[test]
    fn the_keys_are_read_at_each_write() {
        let (d, p) = pushed();
        let core = format!("Bearer {}", token(CORE, AUDIENCE, 600));
        assert_eq!(p.accounts.role(Some(&core)), Ok(Role::Push));
        std::fs::remove_file(d.path().join("sa.pub")).unwrap();
        let e = p.accounts.role(Some(&core)).unwrap_err();
        assert!(e.contains("no authority"), "{e}");
    }

    fn upload(p: &Pushed, bytes: &[u8]) -> Digest {
        let id = p.begin().unwrap();
        std::fs::write(p.upload(&id).unwrap(), bytes).unwrap();
        let d = Digest::of(bytes);
        p.finish(&id, &d).unwrap();
        d
    }

    fn image(config: &Digest, layer: &Digest) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": crate::manifest::OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config.to_string(), "size": 2},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer.to_string(), "size": 5}],
        }))
        .unwrap()
    }

    #[test]
    fn a_blob_lands_only_as_what_it_hashes_to() {
        let (_d, p) = pushed();
        let id = p.begin().unwrap();
        std::fs::write(p.upload(&id).unwrap(), b"layer").unwrap();
        assert!(p.finish(&id, &Digest::of(b"other")).is_err());
        assert!(!p.store.has_blob(&Digest::of(b"other")));
        assert!(p.upload("../x").is_none() && p.upload("").is_none());
        let d = upload(&p, b"layer");
        assert!(p.store.has_blob(&d));
    }

    #[test]
    fn a_manifest_is_taken_once_what_it_names_is_held() {
        let (_d, p) = pushed();
        let (config, layer) = (Digest::of(b"{}"), Digest::of(b"layer"));
        let m = image(&config, &layer);
        let repo = "127.0.0.1:5000/platform-meridian/app-fusion";
        let e = p.put_manifest(repo, "1.5.0", &m).unwrap_err();
        assert!(format!("{e:#}").contains("is not held"), "{e:#}");
        upload(&p, b"{}");
        upload(&p, b"layer");
        let digest = p.put_manifest(repo, "1.5.0", &m).unwrap();
        assert_eq!(p.store.resolve(repo, "1.5.0"), Some(digest.clone()));
        assert_eq!(
            p.put_manifest(repo, &digest.to_string(), &m).unwrap(),
            digest
        );
        assert!(
            p.put_manifest(repo, &Digest::of(b"x").to_string(), &m)
                .is_err()
        );
        assert!(p.put_manifest(repo, "bad tag!", &m).is_err());
        assert!(p.put_manifest(repo, "t", b"not json").is_err());

        // Deleting it takes its tag; its blobs are young, so they stay a day.
        assert!(p.delete_manifest(repo, &digest).unwrap());
        assert!(!p.store.has_manifest(&digest));
        assert_eq!(p.store.resolve(repo, "1.5.0"), None);
        assert!(p.store.has_blob(&layer));
        assert!(!p.delete_manifest(repo, &digest).unwrap(), "gone already");
    }
}
