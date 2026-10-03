//! Talos service state changes as machined announces them, one record each.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::ring::{Entry, Ring};

pub const FILE: &str = "services.bin";
pub const RECORD_SIZE: usize = 512;
/// Several boots: machined keeps its last 1000 events of every kind.
const SLOTS: u64 = 4096;
const PAYLOAD: usize = RECORD_SIZE - crate::ring::HEADER;
const MAX_NAME: usize = 64;
const WARN_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// When machined announced it, in seconds since the epoch.
    pub t: u64,
    #[serde(default)]
    pub boot: String,
    /// machined's event id, unique within a boot.
    #[serde(default)]
    pub id: String,
    pub svc: String,
    /// As Talos names it: `Running`, `Waiting`, `Finished`, `Failed`, ...
    pub state: String,
    /// Absent while unchecked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthy: Option<bool>,
    #[serde(default)]
    pub msg: String,
}

#[derive(Serialize)]
struct Stored<'a> {
    k: &'static str,
    #[serde(flatten)]
    t: &'a Transition,
}

fn capped(s: &str) -> String {
    s[..crate::logline::floor_char_boundary(s, MAX_NAME)].to_string()
}

fn encode(t: &Transition) -> Option<Vec<u8>> {
    let t = Transition {
        id: capped(&t.id),
        svc: capped(&t.svc),
        state: capped(&t.state),
        ..t.clone()
    };
    crate::logline::fit_msg(
        |msg| {
            let t = Transition {
                msg: msg.to_string(),
                ..t.clone()
            };
            serde_json::to_vec(&Stored { k: "svc", t: &t }).ok()
        },
        &t.msg,
        PAYLOAD,
    )
}

fn parse(entry: &Entry) -> Option<Transition> {
    let end = entry
        .payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(entry.payload.len());
    let v: serde_json::Value = serde_json::from_slice(&entry.payload[..end]).ok()?;
    if v.get("k")?.as_str()? != "svc" {
        return None;
    }
    serde_json::from_value(v).ok()
}

/// Every transition kept, oldest first.
pub fn read(path: &Path) -> anyhow::Result<Vec<Transition>> {
    let entries = Ring::open_read_only_with(path, RECORD_SIZE)?.read_all()?;
    Ok(entries.iter().filter_map(parse).collect())
}

/// Each service's last transition of `boot`.
pub fn latest<'a>(all: &'a [Transition], boot: &str) -> BTreeMap<&'a str, &'a Transition> {
    all.iter()
        .filter(|t| t.boot == boot)
        .map(|t| (t.svc.as_str(), t))
        .collect()
}

pub struct Store {
    path: PathBuf,
    boot: String,
    ring: Option<Ring>,
    seen: HashSet<String>,
    lost: u64,
    next_warning: Instant,
}

impl Store {
    pub fn new(path: PathBuf, boot: String) -> Self {
        Self {
            path,
            boot,
            ring: None,
            seen: HashSet::new(),
            lost: 0,
            next_warning: Instant::now(),
        }
    }

    /// Warned of once a minute: the log may be on the same failing disk.
    fn lose(&mut self, why: &anyhow::Error) -> bool {
        self.ring = None;
        self.lost += 1;
        let now = Instant::now();
        if now < self.next_warning {
            return false;
        }
        self.next_warning = now + WARN_EVERY;
        tracing::warn!(error = %format!("{why:#}"), lost = self.lost, "cannot record a service transition");
        true
    }

    fn open(&mut self) -> anyhow::Result<()> {
        if self.ring.is_some() {
            return Ok(());
        }
        let mut r = Ring::open_with(&self.path, SLOTS, RECORD_SIZE)?;
        if let Some(why) = r.take_recovered() {
            let note = serde_json::json!({ "note": "ring recreated", "why": why });
            let mut b = serde_json::to_vec(&note).unwrap_or_default();
            b.truncate(PAYLOAD);
            r.append(&b).ok();
        }
        self.seen = r
            .read_all()?
            .iter()
            .filter_map(parse)
            .filter(|t| t.boot == self.boot)
            .map(|t| t.id)
            .collect();
        self.ring = Some(r);
        Ok(())
    }

    fn append(&mut self, t: &Transition) -> anyhow::Result<()> {
        self.open()?;
        if !t.id.is_empty() && self.seen.contains(&t.id) {
            return Ok(());
        }
        let payload = encode(t).context("no room for the record")?;
        let ring = self.ring.as_mut().context("no ring")?;
        ring.append(&payload)?;
        self.seen.insert(t.id.clone());
        Ok(())
    }

    /// Once per event: machined replays its backlog to each new subscriber.
    pub fn record(&mut self, mut t: Transition) {
        t.boot.clone_from(&self.boot);
        if let Err(e) = self.append(&t) {
            self.lose(&e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;

    fn tr(id: &str, svc: &str, state: &str, healthy: Option<bool>, msg: &str) -> Transition {
        Transition {
            t: 1_790_000_000,
            id: id.into(),
            svc: svc.into(),
            state: state.into(),
            healthy,
            msg: msg.into(),
            ..Default::default()
        }
    }

    fn ids(all: &[Transition]) -> Vec<&str> {
        all.iter().map(|t| t.id.as_str()).collect()
    }

    #[test]
    fn latest_per_service_this_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join(FILE);
        let mut old = Store::new(p.clone(), "boot1".into());
        old.record(tr("a", "etcd", "Failed", None, "gone"));
        old.record(tr("b", "gone", "Running", None, ""));
        drop(old);
        let mut s = Store::new(p.clone(), "boot2".into());
        s.record(tr("c", "etcd", "Running", None, "Process started"));
        s.record(tr("d", "kubelet", "Waiting", None, "Waiting for etcd"));
        s.record(tr(
            "e",
            "etcd",
            "Running",
            Some(true),
            "Health check successful",
        ));
        let all = read(&p).unwrap();
        assert_eq!(ids(&all), ["a", "b", "c", "d", "e"]);
        let now = latest(&all, "boot2");
        assert_eq!(now.keys().copied().collect::<Vec<_>>(), ["etcd", "kubelet"]);
        assert_eq!(
            (now["etcd"].id.as_str(), now["etcd"].healthy),
            ("e", Some(true))
        );
        assert_eq!(latest(&all, "boot1")["etcd"].state, "Failed");
    }

    #[test]
    fn replay_recorded_once_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join(FILE);
        let mut s = Store::new(p.clone(), "b".into());
        for id in ["1", "2", "1", "2", "3"] {
            s.record(tr(id, "etcd", "Running", None, ""));
        }
        drop(s);
        let mut s = Store::new(p.clone(), "b".into());
        for id in ["1", "2", "3", "4"] {
            s.record(tr(id, "etcd", "Running", None, ""));
        }
        drop(s);
        let mut next_boot = Store::new(p.clone(), "c".into());
        next_boot.record(tr("1", "etcd", "Running", None, ""));
        assert_eq!(ids(&read(&p).unwrap()), ["1", "2", "3", "4", "1"]);
    }

    #[test]
    fn torn_record_skipped_rest_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join(FILE);
        let mut s = Store::new(p.clone(), "b".into());
        for id in ["1", "2", "3"] {
            s.record(tr(id, "etcd", "Running", None, "m"));
        }
        drop(s);
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.write_all_at(b"XXXX", RECORD_SIZE as u64 + 40).unwrap();
        assert_eq!(ids(&read(&p).unwrap()), ["1", "3"]);
        let mut s = Store::new(p.clone(), "b".into());
        s.record(tr("3", "etcd", "Running", None, "m"));
        s.record(tr("4", "etcd", "Failed", None, "m"));
        assert_eq!(ids(&read(&p).unwrap()), ["1", "3", "4"]);
        assert!(!d.join(format!("{FILE}.corrupt")).exists());
    }

    #[test]
    fn truncated_ring_keeps_whole_records() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join(FILE);
        let mut s = Store::new(p.clone(), "b".into());
        for id in ["1", "2", "3"] {
            s.record(tr(id, "etcd", "Running", None, "m"));
        }
        drop(s);
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len(RECORD_SIZE as u64 * 5 / 2).unwrap();
        assert_eq!(ids(&read(&p).unwrap()), ["1", "2"]);
        let mut s = Store::new(p.clone(), "b".into());
        s.record(tr("2", "etcd", "Running", None, "m"));
        s.record(tr("4", "etcd", "Failed", None, "m"));
        let all = read(&p).unwrap();
        assert_eq!(ids(&all), ["2", "4"], "the ring keeps its new size");
        assert_eq!(latest(&all, "b")["etcd"].state, "Failed");
        drop(s);

        f.set_len(RECORD_SIZE as u64 / 2).unwrap();
        assert!(read(&p).is_err());
        let mut s = Store::new(p.clone(), "b".into());
        s.record(tr("4", "etcd", "Running", None, "m"));
        assert_eq!(ids(&read(&p).unwrap()), ["4"]);
    }

    #[test]
    fn long_message_cut_names_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join(FILE);
        let mut s = Store::new(p.clone(), "b".into());
        let mut t = tr(
            &"i".repeat(500),
            &"s".repeat(500),
            "Failed",
            None,
            &"é\"".repeat(400),
        );
        t.state = "S".repeat(500);
        s.record(t);
        let all = read(&p).unwrap();
        assert_eq!(all.len(), 1);
        let got = &all[0];
        assert_eq!(
            (got.id.len(), got.svc.len(), got.state.len()),
            (MAX_NAME, MAX_NAME, MAX_NAME)
        );
        assert!(
            got.msg.ends_with('…') && got.msg.starts_with("é\""),
            "{}",
            got.msg
        );
    }

    #[test]
    fn unwritable_dir_loses_records_not_process() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { nix::libc::geteuid() } == 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut s = Store::new(d.join("sub").join(FILE), "b".into());
        s.record(tr("1", "etcd", "Running", None, ""));
        assert_eq!(s.lost, 1);
        assert!(s.next_warning >= Instant::now() + WARN_EVERY - Duration::from_secs(1));
        let again = anyhow::anyhow!("again");
        assert!(!s.lose(&again), "quiet for a minute");
        s.next_warning = Instant::now();
        assert!(s.lose(&again));
        assert_eq!(s.lost, 3);
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        s.record(tr("2", "etcd", "Running", None, ""));
        assert_eq!(ids(&read(&d.join("sub").join(FILE)).unwrap()), ["2"]);
    }

    #[test]
    fn other_records_not_transitions() {
        let entry = |json: &str| {
            let mut payload = json.as_bytes().to_vec();
            payload.resize(PAYLOAD, 0);
            Entry {
                seq: 0,
                payload,
                version: 2,
            }
        };
        for other in [
            r#"{"note":"ring recreated","why":"x"}"#,
            r#"{"k":"log","src":"etcd","msg":"x"}"#,
            r#"{"k":"svc","t":1}"#,
            "not json",
        ] {
            assert_eq!(parse(&entry(other)), None, "{other}");
        }
        let t = parse(&entry(
            r#"{"k":"svc","t":1,"svc":"etcd","state":"Running","later":1}"#,
        ));
        assert_eq!(t.map(|t| t.svc), Some("etcd".into()));
    }
}
