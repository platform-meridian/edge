//! Replace a file so the replacement survives a power cut: write a temp beside
//! it, fsync it (else a cut leaves a named, zero-length file), rename it over
//! the target, then fsync the directory (else the rename itself can be lost).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const TMP_SUFFIX: &str = ".edge-tmp";

fn tmp_path(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable_write: path has no file name",
        )
    })?;
    let mut n = name.to_os_string();
    n.push(TMP_SUFFIX);
    Ok(path.with_file_name(n))
}

pub fn durable_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    durable_write_with(path, |f| f.write_all(bytes))
}

pub fn durable_write_with(
    path: &Path,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let tmp = tmp_path(path)?;
    clear_the_way(path, &tmp);
    let r = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        fill(&mut f)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = r {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_parent(path)
}

fn clear_the_way(path: &Path, tmp: &Path) {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // The nearest existing ancestor must be a directory; anything else
        // (a file, a dangling symlink) at any level blocks create_dir_all.
        let blocker = dir
            .ancestors()
            .find(|a| std::fs::symlink_metadata(a).is_ok())
            .filter(|a| !std::fs::metadata(a).is_ok_and(|m| m.is_dir()));
        if let Some(blocker) = blocker {
            set_aside(blocker);
        }
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::symlink_metadata(tmp).is_ok_and(|m| m.is_dir()) {
        let _ = std::fs::remove_dir_all(tmp);
    }
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        set_aside(path);
    }
}

pub fn set_aside(path: &Path) -> Option<PathBuf> {
    std::fs::symlink_metadata(path).ok()?;
    let mut n = path.as_os_str().to_os_string();
    n.push(".corrupt");
    let dest = PathBuf::from(n);
    if std::fs::rename(path, &dest).is_ok() {
        return Some(dest);
    }
    if let Ok(m) = std::fs::symlink_metadata(&dest) {
        let _ = if m.is_dir() {
            std::fs::remove_dir_all(&dest)
        } else {
            std::fs::remove_file(&dest)
        };
    }
    if std::fs::rename(path, &dest).is_ok() {
        return Some(dest);
    }
    let _ = if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    None
}

fn sync_parent(path: &Path) -> io::Result<()> {
    sync_dir(
        path.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
}

// EINVAL/ENOTSUP: the filesystem cannot sync directories.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    match File::open(dir).and_then(|d| d.sync_all()) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(nix::libc::EINVAL) | Some(nix::libc::ENOTSUP)
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_without_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("state.json");
        durable_write(&p, b"one").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        durable_write(&p, b"two, longer").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two, longer");
        assert_eq!(
            std::fs::read_dir(d).unwrap().count(),
            1,
            "only the target remains"
        );
    }

    #[test]
    fn stale_temp_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("resume.json");
        std::fs::write(
            tmp_path(&p).unwrap(),
            b"half written garbage that is much longer than the new content",
        )
        .unwrap();
        durable_write(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert!(!tmp_path(&p).unwrap().exists());
    }

    #[test]
    fn failed_fill_keeps_target() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("f");
        durable_write(&p, b"keep me").unwrap();
        let e = durable_write_with(&p, |f| {
            f.write_all(b"partial")?;
            Err(io::Error::other("disk on fire"))
        });
        assert!(e.is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"keep me");
        assert!(!tmp_path(&p).unwrap().exists());
    }

    #[test]
    fn clears_blockers() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("a/b/state.json");
        durable_write(&p, b"x").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"x");

        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("state.json");
        std::fs::create_dir_all(tmp_path(&p).unwrap().join("inner")).unwrap();
        durable_write(&p, b"y").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"y");

        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("state.json");
        std::fs::create_dir_all(p.join("inner")).unwrap();
        durable_write(&p, b"z").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"z");
        assert!(d.join("state.json.corrupt/inner").is_dir());

        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let sd = d.join("state");
        std::fs::write(&sd, b"i am not a directory").unwrap();
        durable_write(&sd.join("s.json"), b"w").unwrap();
        assert_eq!(std::fs::read(sd.join("s.json")).unwrap(), b"w");
        assert_eq!(
            std::fs::read(d.join("state.corrupt")).unwrap(),
            b"i am not a directory"
        );

        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::write(d.join("state"), b"i am not a directory either").unwrap();
        let p = d.join("state/sub/s.json");
        durable_write(&p, b"v").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"v");
        assert_eq!(
            std::fs::read(d.join("state.corrupt")).unwrap(),
            b"i am not a directory either"
        );
    }

    #[test]
    fn sync_parent_dir_or_cwd() {
        assert!(sync_parent(Path::new("x")).is_ok());
        assert!(sync_parent(Path::new("/nonexistent-edge-common-dir/x")).is_err());
    }
}
