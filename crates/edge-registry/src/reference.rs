use std::fmt;
use std::str::FromStr;

use crate::Digest;

/// An image reference, its repository normalised as the Docker CLI does:
/// `nginx` is `docker.io/library/nginx`. A tag or digest or both.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImageRef {
    pub repo: String,
    pub tag: Option<String>,
    pub digest: Option<Digest>,
}

impl FromStr for ImageRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || format!("not an image reference: {s:?}");
        let (name, digest) = match s.split_once('@') {
            Some((n, d)) => (n, Some(d.parse::<Digest>()?)),
            None => (s, None),
        };
        let last = name.rsplit('/').next().unwrap_or(name);
        let (name, tag) = match last.split_once(':') {
            Some((_, tag)) => (&name[..name.len() - tag.len() - 1], Some(tag)),
            None => (name, None),
        };
        if tag.is_some_and(|t| !valid_tag(t)) {
            return Err(bad());
        }
        let tag = match (tag, &digest) {
            (None, None) => Some("latest"),
            (t, _) => t,
        };
        Ok(ImageRef {
            repo: normalize_repo(name).ok_or_else(bad)?,
            tag: tag.map(str::to_owned),
            digest,
        })
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.repo)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

pub fn normalize_repo(name: &str) -> Option<String> {
    let (host, path) = match name.split_once('/') {
        Some((h, p)) if h.contains(['.', ':']) || h == "localhost" => (h, p),
        _ => ("docker.io", name),
    };
    let host = if host == "index.docker.io" {
        "docker.io"
    } else {
        host
    };
    let library = host == "docker.io" && !path.contains('/');
    let valid = valid_host(host) && path.split('/').all(valid_path_component);
    valid.then(|| match library {
        true => format!("{host}/library/{path}"),
        false => format!("{host}/{path}"),
    })
}

fn alnum_ends(s: &str) -> bool {
    s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric())
}

fn valid_host(h: &str) -> bool {
    alnum_ends(h)
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

fn valid_path_component(c: &str) -> bool {
    alnum_ends(c)
        && c.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

pub fn valid_tag(t: &str) -> bool {
    (1..=128).contains(&t.len())
        && t.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A repository as one directory name: `/` cannot appear in a file name, and `%`
/// cannot appear in a repository.
pub(crate) fn repo_dir(repo: &str) -> String {
    repo.replace('/', "%")
}

pub(crate) fn repo_from_dir(dir: &str) -> Option<String> {
    let repo = dir.replace('%', "/");
    (normalize_repo(&repo).as_deref() == Some(repo.as_str())).then_some(repo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn r(s: &str) -> String {
        s.parse::<ImageRef>().unwrap().to_string()
    }

    const D: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn normalises_like_docker() {
        assert_eq!(r("nginx"), "docker.io/library/nginx:latest");
        assert_eq!(r("index.docker.io/nginx:1"), "docker.io/library/nginx:1");
        assert_eq!(r("user/app:v2"), "docker.io/user/app:v2");
        assert_eq!(
            r("registry.k8s.io/pause:3.10"),
            "registry.k8s.io/pause:3.10"
        );
        assert_eq!(
            r("localhost:5000/a/b/c:x_1.2-y"),
            "localhost:5000/a/b/c:x_1.2-y"
        );
        assert_eq!(r("localhost/app"), "localhost/app:latest");
        assert_eq!(r("ghcr.io/org2/app-1x:v1"), "ghcr.io/org2/app-1x:v1");
        assert_eq!(r(&format!("ghcr.io/o/i@{D}")), format!("ghcr.io/o/i@{D}"));
        assert_eq!(
            r(&format!("ghcr.io/o/i:v1@{D}")),
            format!("ghcr.io/o/i:v1@{D}")
        );
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "Nginx",
            "ghcr.io/",
            "ghcr.io//x",
            "ghcr.io/../x",
            "ghcr.io/./x",
            "ghcr.io/x/.",
            "ghcr.io/x:",
            "ghcr.io/x:.tag",
            "ghcr.io/x@sha256:abc",
            "-bad.io/x",
            "ghcr.io/x y",
            "ghcr.io/x%y",
        ] {
            assert!(bad.parse::<ImageRef>().is_err(), "{bad:?}");
        }
        assert!(!valid_tag(&"t".repeat(129)));
        assert!(valid_tag(&"t".repeat(128)));
    }

    #[test]
    fn repo_dir_round_trips() {
        let repo = "localhost:5000/a/b";
        assert_eq!(repo_dir(repo), "localhost:5000%a%b");
        assert_eq!(repo_from_dir(&repo_dir(repo)).as_deref(), Some(repo));
        assert_eq!(repo_from_dir("nginx"), None);
        assert_eq!(repo_from_dir(".."), None);
    }

    proptest! {
        #[test]
        fn parsed_names_stay_in_their_directory(s in "[a-zA-Z0-9./:_%-]{0,40}") {
            if let Ok(r) = s.parse::<ImageRef>() {
                let dir = repo_dir(&r.repo);
                prop_assert!(!dir.contains('/') && dir != "." && dir != "..");
                prop_assert_eq!(repo_from_dir(&dir), Some(r.repo.clone()));
                prop_assert!(r.tag.as_deref().is_none_or(|t| !t.contains('/') && !t.starts_with('.')));
                prop_assert_eq!(r.to_string().parse::<ImageRef>(), Ok(r));
            }
        }
    }
}
