use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Short field names: every byte is repeated in each 240-byte record.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// Unreliable across an unsynced RTC; `up` and `boot` delimit and order boots.
    pub t: u64,
    #[serde(default)]
    pub up: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub boot: String,
    /// PSI "some" avg10 x100.
    pub cpu: u32,
    pub io: u32,
    pub mem: u32,
    /// PSI "full" avg10 x100 (cpu has no system-level "full").
    pub iof: u32,
    pub memf: u32,
    pub avail_mb: u32,
    /// Load average x100.
    pub load: u32,
    pub procs_run: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fl: u64,
    /// The kernel reports the clock NTP/PTP-synced.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sy: bool,
    /// Hottest sensor per hwmon device name, degrees C.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub temp: BTreeMap<String, i32>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn psi(path: &Path) -> (u32, u32) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (0, 0);
    };
    let mut some = 0;
    let mut full = 0;
    for line in text.lines() {
        let Some(avg10) = line
            .split_whitespace()
            .find_map(|f| f.strip_prefix("avg10="))
            .and_then(|v| v.parse::<f32>().ok())
        else {
            continue;
        };
        let v = (avg10 * 100.0) as u32;
        if line.starts_with("some") {
            some = v;
        } else if line.starts_with("full") {
            full = v;
        }
    }
    (some, full)
}

fn mem_available_mb(proc_dir: &Path) -> u32 {
    std::fs::read_to_string(proc_dir.join("meminfo"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| (kb / 1024) as u32)
        .unwrap_or(0)
}

/// (load x100, running processes)
fn loadavg(proc_dir: &Path) -> (u32, u32) {
    let Ok(t) = std::fs::read_to_string(proc_dir.join("loadavg")) else {
        return (0, 0);
    };
    let f: Vec<&str> = t.split_whitespace().collect();
    let load = f
        .first()
        .and_then(|v| v.parse::<f32>().ok())
        .map(|v| (v * 100.0) as u32)
        .unwrap_or(0);
    let running = f
        .get(3)
        .and_then(|v| v.split('/').next())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    (load, running)
}

pub fn uptime_secs(proc_dir: &Path) -> u64 {
    std::fs::read_to_string(proc_dir.join("uptime"))
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| v as u64)
        .unwrap_or(0)
}

pub fn boot_id(proc_dir: &Path) -> String {
    std::fs::read_to_string(proc_dir.join("sys/kernel/random/boot_id"))
        .ok()
        .map(|t| t.chars().filter(char::is_ascii_hexdigit).take(8).collect())
        .unwrap_or_default()
}

const MAX_HWMON: usize = 4;
const PREFERRED_HWMON: [&str; 3] = ["coretemp", "k10temp", "nvme"];

pub fn hwmon(sys_dir: &Path) -> BTreeMap<String, i32> {
    let mut out: BTreeMap<String, i32> = BTreeMap::new();
    let Ok(devs) = std::fs::read_dir(sys_dir.join("class/hwmon")) else {
        return out;
    };
    let mut devs: Vec<_> = devs.flatten().map(|e| e.path()).collect();
    devs.sort();
    for d in devs {
        let Some(name) = std::fs::read_to_string(d.join("name"))
            .ok()
            .map(|n| n.trim().chars().take(MAX_NAME).collect::<String>())
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let hottest = std::fs::read_dir(&d)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("temp") && n.ends_with("_input")
            })
            .filter_map(|e| {
                std::fs::read_to_string(e.path())
                    .ok()?
                    .trim()
                    .parse::<i64>()
                    .ok()
            })
            .max();
        let Some(milli) = hottest else { continue };
        let c = i32::try_from(milli / 1000).unwrap_or(i32::MAX);
        let e = out.entry(name).or_insert(c);
        *e = (*e).max(c);
    }
    let mut names: Vec<String> = out.keys().cloned().collect();
    names.sort_by_key(|n| (!PREFERRED_HWMON.contains(&n.as_str()), n.clone()));
    for n in names.into_iter().skip(MAX_HWMON) {
        out.remove(&n);
    }
    out
}

const MAX_NAME: usize = 24;

/// Failing-check names are cut to `MAX_NAME` chars, then dropped from the end with a
/// trailing "+N" count.
pub fn to_payload(s: &Sample, budget: usize) -> Vec<u8> {
    let names: Vec<String> = s
        .failing
        .iter()
        .map(|n| n.chars().take(MAX_NAME).collect())
        .collect();
    let mut kept = names.len();
    loop {
        let mut t = s.clone();
        t.failing = names[..kept].to_vec();
        if kept < names.len() {
            t.failing.push(format!("+{}", names.len() - kept));
        }
        let b = serde_json::to_vec(&t).unwrap_or_default();
        if b.len() <= budget {
            return b;
        }
        if kept == 0 {
            t.failing.clear();
            let b = serde_json::to_vec(&t).unwrap_or_default();
            if b.len() <= budget {
                return b;
            }
            t.temp.clear();
            return serde_json::to_vec(&t).unwrap_or_default();
        }
        kept -= 1;
    }
}

pub fn take(proc_dir: &Path, now: u64, failing: Vec<String>) -> Sample {
    let (cpu, _) = psi(&proc_dir.join("pressure/cpu"));
    let (io, iof) = psi(&proc_dir.join("pressure/io"));
    let (mem, memf) = psi(&proc_dir.join("pressure/memory"));
    let (load, procs_run) = loadavg(proc_dir);
    Sample {
        t: now,
        up: uptime_secs(proc_dir),
        boot: boot_id(proc_dir),
        cpu,
        io,
        mem,
        iof,
        memf,
        avail_mb: mem_available_mb(proc_dir),
        load,
        procs_run,
        failing,
        ..Sample::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::PAYLOAD;

    fn fixture() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for (f, text) in [
            (
                "pressure/cpu",
                "some avg10=12.34 avg60=1.00 avg300=0.50 total=123\n",
            ),
            (
                "pressure/io",
                "some avg10=50.00 avg60=1.00 avg300=0.50 total=1\nfull avg10=25.50 avg60=0.10 avg300=0.00 total=2\n",
            ),
            (
                "pressure/memory",
                "some avg10=3.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=1.00 avg60=0.00 avg300=0.00 total=0\n",
            ),
            (
                "meminfo",
                "MemTotal: 16000000 kB\nMemAvailable: 2097152 kB\n",
            ),
            ("loadavg", "1.50 1.00 0.75 3/456 789\n"),
            ("uptime", "12345.67 54321.00\n"),
            (
                "sys/kernel/random/boot_id",
                "3f2a91bc-0d4e-4c1a-9b7e-5a6d8e1f2a3b\n",
            ),
        ] {
            let p = d.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        tmp
    }

    #[test]
    fn sample_reads_proc() {
        let tmp = fixture();
        let d = tmp.path();
        let s = take(d, 42, vec![]);
        assert_eq!(
            s,
            Sample {
                t: 42,
                up: 12345,
                boot: "3f2a91bc".into(),
                cpu: 1234,
                io: 5000,
                mem: 300,
                iof: 2550,
                memf: 100,
                avail_mb: 2048,
                load: 150,
                procs_run: 3,
                ..Sample::default()
            }
        );
        let j = serde_json::to_string(&s).unwrap();
        for absent in ["failing", "fl", "sy", "temp"] {
            assert!(!j.contains(absent), "{j}");
        }
    }

    #[test]
    fn missing_proc_files_give_zeros() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let s = take(d, 1, vec![]);
        assert_eq!(
            s,
            Sample {
                t: 1,
                ..Sample::default()
            }
        );
        assert!(!serde_json::to_string(&s).unwrap().contains("boot"));
    }

    #[test]
    fn v1_record_parses() {
        let old = r#"{"t":1788172340,"cpu":1,"io":2,"mem":3,"iof":4,"memf":5,"avail_mb":6,"load":7,"procs_run":8}"#;
        let s: Sample = serde_json::from_str(old).unwrap();
        assert_eq!(
            (s.t, s.up, s.boot.as_str(), s.procs_run),
            (1788172340, 0, "", 8)
        );
    }

    #[test]
    fn fitting_sample_unchanged() {
        let tmp = fixture();
        let d = tmp.path();
        let s = take(d, 1_800_000_000, vec!["app".into(), "telemetry".into()]);
        assert_eq!(to_payload(&s, PAYLOAD), serde_json::to_vec(&s).unwrap());
    }

    #[test]
    fn excess_failures_cut_with_count() {
        let tmp = fixture();
        let d = tmp.path();
        let names: Vec<String> = (0..30)
            .map(|i| format!("mission-path-check-{i:02}"))
            .collect();
        let s = take(d, 1_800_000_000, names.clone());
        assert!(serde_json::to_vec(&s).unwrap().len() > PAYLOAD, "premise");

        let p = to_payload(&s, PAYLOAD);
        assert!(p.len() <= PAYLOAD);
        let back: Sample = serde_json::from_slice(&p).unwrap();
        let (marker, kept) = back.failing.split_last().unwrap();
        let dropped: usize = marker.strip_prefix('+').unwrap().parse().unwrap();
        assert_eq!(kept, &names[..kept.len()]);
        assert_eq!(kept.len() + dropped, names.len());
        // The most that fits: one more name would not.
        let mut more = back.clone();
        more.failing = names[..kept.len() + 1].to_vec();
        more.failing.push(format!("+{}", dropped - 1));
        assert!(serde_json::to_vec(&more).unwrap().len() > PAYLOAD);
        assert_eq!(
            Sample {
                failing: vec![],
                ..back
            },
            Sample {
                failing: vec![],
                ..s
            }
        );
    }

    #[test]
    fn long_names_cut_on_char_boundary() {
        let tmp = fixture();
        let d = tmp.path();
        let s = take(
            d,
            1,
            vec!["x".repeat(5000), "é".repeat(100), "second".into()],
        );
        let back: Sample = serde_json::from_slice(&to_payload(&s, PAYLOAD)).unwrap();
        assert_eq!(
            back.failing,
            ["x".repeat(24), "é".repeat(24), "second".into()]
        );
    }

    #[test]
    fn names_dropped_when_marker_does_not_fit() {
        let s = Sample {
            failing: vec!["a".into()],
            ..Sample::default()
        };
        let bare = serde_json::to_vec(&Sample::default()).unwrap();
        assert_eq!(to_payload(&s, bare.len()), bare);

        let hot = Sample {
            failing: vec!["a".into()],
            temp: [("coretemp".to_string(), 90)].into(),
            ..Sample::default()
        };
        assert_eq!(to_payload(&hot, bare.len()), bare, "temperatures go last");
        let with_temp = Sample {
            failing: vec![],
            ..hot.clone()
        };
        let fits = serde_json::to_vec(&with_temp).unwrap();
        assert_eq!(
            to_payload(&hot, fits.len()),
            fits,
            "names go before temperatures"
        );
    }

    #[test]
    fn hwmon_keeps_hottest_per_device() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let dev = |n: &str, name: &str, temps: &[(&str, &str)]| {
            let p = d.join("class/hwmon").join(n);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("name"), name).unwrap();
            for (f, v) in temps {
                std::fs::write(p.join(f), v).unwrap();
            }
        };
        dev(
            "hwmon0",
            "coretemp\n",
            &[
                ("temp1_input", "45000\n"),
                ("temp2_input", "61999\n"),
                ("temp2_max", "100000\n"),
            ],
        );
        dev(
            "hwmon1",
            "nvme",
            &[("temp1_input", "38000"), ("temp2_input", "garbage")],
        );
        dev("hwmon2", "acpitz", &[("temp1_input", "-5000")]);
        dev("hwmon3", "fan-only", &[("fan1_input", "1200")]);
        dev("hwmon4", "", &[("temp1_input", "1000")]);
        dev("hwmon5", "coretemp", &[("temp1_input", "70000")]);
        let got = hwmon(d);
        assert_eq!(
            got,
            [
                ("acpitz".to_string(), -5),
                ("coretemp".into(), 70),
                ("nvme".into(), 38)
            ]
            .into()
        );
        assert!(hwmon(&d.join("missing")).is_empty());
    }

    #[test]
    fn hwmon_names_are_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for i in 0..10 {
            let p = d.join(format!("class/hwmon/hwmon{i}"));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("name"), format!("sensor{i}")).unwrap();
            std::fs::write(p.join("temp1_input"), "1000").unwrap();
        }
        for (i, name) in [(10, "nvme"), (11, "coretemp")] {
            let p = d.join(format!("class/hwmon/hwmon{i}"));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("name"), name).unwrap();
            std::fs::write(p.join("temp1_input"), "50000").unwrap();
        }
        assert_eq!(
            hwmon(d).into_keys().collect::<Vec<_>>(),
            ["coretemp", "nvme", "sensor0", "sensor1"]
        );
    }
}
