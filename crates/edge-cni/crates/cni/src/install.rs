use std::path::Path;
use std::time::Duration;

use anyhow::Context;

const CNI_BIN: &str = "/opt/cni/bin/edge-cni";
const CNI_CONF: &str = "/etc/cni/net.d/10-edge.conflist";

// The installed files live on a tmpfs.
const RECHECK_INTERVAL: Duration = Duration::from_secs(30);

const FIRST_INSTALL_GRACE: Duration = Duration::from_secs(60);
const FIRST_INSTALL_RETRY: Duration = Duration::from_millis(500);

pub fn conflist(pod_cidr: Option<&str>) -> String {
    let pod_cidr = pod_cidr
        .map(|c| format!(r#" "podCIDR": "{c}","#))
        .unwrap_or_default();
    format!(
        r#"{{
  "cniVersion": "1.0.0",
  "name": "edge",
  "plugins": [
    {{ "type": "edge-cni",{pod_cidr} "mtu": 1500 }}
  ]
}}
"#
    )
}

fn conflist_pod_cidr(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v["plugins"][0]["podCIDR"].as_str().map(str::to_owned)
}

pub fn installed_pod_cidr() -> Option<String> {
    conflist_pod_cidr(&std::fs::read_to_string(CNI_CONF).ok()?)
}

pub fn install_cni(pod_cidr: Option<&str>) -> anyhow::Result<()> {
    let this = std::env::current_exe().context("find this binary")?;
    install_cni_at(&this, Path::new(CNI_BIN), Path::new(CNI_CONF), pod_cidr)
}

// Durable: kubelet may exec the plugin at any moment.
pub fn install_cni_at(
    exe: &Path,
    bin: &Path,
    conf: &Path,
    pod_cidr: Option<&str>,
) -> anyhow::Result<()> {
    edge_common::durable_write_with(bin, |f| {
        use std::os::unix::fs::PermissionsExt;
        let mut src = std::fs::File::open(exe)?;
        std::io::copy(&mut src, f)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))
    })
    .with_context(|| format!("install the plugin at {}", bin.display()))?;
    edge_common::durable_write(conf, conflist(pod_cidr).as_bytes())
        .with_context(|| format!("write the conflist at {}", conf.display()))?;
    tracing::info!(conf = %conf.display(), "CNI installed");
    Ok(())
}

fn cni_is_installed(pod_cidr: Option<&str>) -> bool {
    cni_is_installed_at(Path::new(CNI_BIN), Path::new(CNI_CONF), pod_cidr)
}

// The plugin's length is not compared: the floor and the daemon are different builds.
fn cni_is_installed_at(bin: &Path, conf: &Path, pod_cidr: Option<&str>) -> bool {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    let bin_ok = std::fs::metadata(bin)
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0 && m.len() > 4)
        && std::fs::File::open(bin).is_ok_and(|mut f| {
            let mut magic = [0u8; 4];
            f.read_exact(&mut magic).is_ok() && &magic == b"\x7fELF"
        });
    bin_ok
        && std::fs::read_to_string(conf).is_ok_and(|c| match pod_cidr {
            Some(_) => c == conflist(pod_cidr),
            None => c == conflist(conflist_pod_cidr(&c).as_deref()),
        })
}

pub(crate) async fn install_task(pod_cidr: &str) {
    let mut delay = Duration::from_secs(1);
    loop {
        let wait = if cni_is_installed(Some(pod_cidr)) {
            delay = Duration::from_secs(1);
            RECHECK_INTERVAL
        } else {
            match install_cni(Some(pod_cidr)) {
                Ok(()) => {
                    delay = Duration::from_secs(1);
                    RECHECK_INTERVAL
                }
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), retry_in = ?delay, "cannot install the CNI files; node stays NotReady until this works");
                    let d = delay;
                    delay = (delay * 2).min(RECHECK_INTERVAL);
                    d
                }
            }
        };
        tokio::time::sleep(wait).await;
    }
}

// Run by containerd directly, with no kubelet in the path: sandbox teardown needs
// the conflist, so a conflist written only by a pod can deadlock with kubelet.
pub fn floor() -> anyhow::Result<()> {
    if let Err(e) = edge_common::install() {
        tracing::warn!(error = %e, "could not install the SIGTERM handler");
    }
    // /opt may still be read-only when this starts, so the first attempts get EROFS.
    let mut waited = Duration::ZERO;
    loop {
        // A restarted floor must not replace the daemon's conflist with its own.
        let installed = if cni_is_installed(None) {
            Ok(())
        } else {
            install_cni(None)
        };
        match installed {
            Ok(()) => break,
            Err(e) if waited >= FIRST_INSTALL_GRACE => {
                tracing::error!(error = %format!("{e:#}"), "cni floor install failed; retrying every {RECHECK_INTERVAL:?}");
                break;
            }
            Err(_) => {
                if edge_common::sleep(FIRST_INSTALL_RETRY) {
                    return Ok(());
                }
                waited += FIRST_INSTALL_RETRY;
            }
        }
    }
    loop {
        if edge_common::sleep(RECHECK_INTERVAL) {
            tracing::info!("floor exiting on SIGTERM");
            return Ok(());
        }
        if !cni_is_installed(None) {
            tracing::warn!("cni files missing or stale; reinstalling");
            if let Err(e) = install_cni(None) {
                tracing::error!(error = %format!("{e:#}"), "reinstall failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("edge-cni-install-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn me() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    #[test]
    fn conflist_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(&conflist(Some("10.244.0.0/24"))).unwrap();
        assert_eq!(v["cniVersion"], "1.0.0");
        assert_eq!(v["name"], "edge");
        assert_eq!(v["plugins"][0]["type"], "edge-cni");
        assert_eq!(v["plugins"][0]["podCIDR"], "10.244.0.0/24");
        let floor: serde_json::Value = serde_json::from_str(&conflist(None)).unwrap();
        assert_eq!(floor["plugins"][0]["type"], "edge-cni");
        assert!(floor["plugins"][0].get("podCIDR").is_none());
    }

    #[test]
    fn install_replaces_leftovers() {
        let d = scratch("install");
        let bin = d.join("opt/cni/bin/edge-cni");
        let conf = d.join("etc/cni/net.d/10-edge.conflist");
        let cidr = Some("10.244.0.0/24");

        assert!(!cni_is_installed_at(&bin, &conf, cidr));
        install_cni_at(&me(), &bin, &conf, cidr).unwrap();
        assert!(cni_is_installed_at(&bin, &conf, cidr));

        std::fs::write(&bin, b"").unwrap();
        assert!(
            !cni_is_installed_at(&bin, &conf, cidr),
            "an empty plugin is not installed"
        );
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        assert!(
            !cni_is_installed_at(&bin, &conf, cidr),
            "a script that is not our binary is not installed"
        );
        install_cni_at(&me(), &bin, &conf, cidr).unwrap();
        assert!(cni_is_installed_at(&bin, &conf, cidr));

        std::fs::write(&conf, conflist(Some("10.9.0.0/24"))).unwrap();
        assert!(
            !cni_is_installed_at(&bin, &conf, cidr),
            "a stale conflist is not installed"
        );
        std::fs::create_dir_all(format!("{}{}/x", conf.display(), edge_common::TMP_SUFFIX))
            .unwrap();
        std::fs::remove_file(&conf).unwrap();
        std::fs::create_dir_all(conf.join("junk")).unwrap();
        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir_all(bin.join("junk")).unwrap();
        install_cni_at(&me(), &bin, &conf, cidr).unwrap();
        assert!(cni_is_installed_at(&bin, &conf, cidr));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn unwritable_dir_is_error() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("ro");
        std::fs::create_dir_all(d.join("net.d")).unwrap();
        std::fs::set_permissions(d.join("net.d"), std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(d.join("net.d/probe"), b"x").is_ok() {
            return; // root ignores the mode bits
        }
        let install = || {
            install_cni_at(
                &me(),
                &d.join("bin/edge-cni"),
                &d.join("net.d/10-edge.conflist"),
                Some("10.244.0.0/24"),
            )
        };
        assert!(install().is_err());
        std::fs::set_permissions(d.join("net.d"), std::fs::Permissions::from_mode(0o755)).unwrap();
        install().expect("and it works once the directory does");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn floor_defers_to_daemon_conflist() {
        let d = scratch("floor");
        let bin = d.join("opt/cni/bin/edge-cni");
        let conf = d.join("etc/cni/net.d/10-edge.conflist");
        let node = Some("10.244.0.0/24");

        install_cni_at(&me(), &bin, &conf, None).unwrap();
        assert!(cni_is_installed_at(&bin, &conf, None));
        assert!(
            !cni_is_installed_at(&bin, &conf, node),
            "the daemon replaces the floor's conflist"
        );
        assert_eq!(
            conflist_pod_cidr(&std::fs::read_to_string(&conf).unwrap()),
            None
        );

        install_cni_at(&me(), &bin, &conf, node).unwrap();
        assert!(
            cni_is_installed_at(&bin, &conf, None),
            "the floor keeps the daemon's conflist"
        );
        assert_eq!(
            conflist_pod_cidr(&std::fs::read_to_string(&conf).unwrap()).as_deref(),
            node
        );

        std::fs::write(&conf, r#"{"plugins":[{"type":"edge-cni","podCIDR":"x"}]}"#).unwrap();
        assert!(
            !cni_is_installed_at(&bin, &conf, None),
            "a conflist that is not ours is replaced"
        );
        std::fs::remove_dir_all(&d).ok();
    }
}
