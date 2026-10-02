//! The stack judge's record, as its ConfigMap holds it (see the README): its
//! verdicts, and what it says of the trial it is judging.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Fail,
    /// Neither: what applying does, for a person to weigh.
    Note,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub state: CheckState,
    pub detail: String,
}

impl Check {
    pub fn new(name: &str, state: CheckState, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Judge {
    pub good: String,
    pub previous: String,
    pub trial: String,
    /// `<tag> <time>` of the last rollback.
    pub rolled_back: String,
    pub window_secs: i64,
    pub fail_after_secs: i64,
    pub unhealthy_secs: i64,
    /// Unix seconds; 0 while unhealthy or unsaid.
    pub healthy_since: i64,
    pub checks: Vec<Check>,
    /// What [`request`]s it honours: `commit`, `rollback`.
    pub requests: BTreeSet<String>,
}

pub const REQUEST: &str = "request";

impl Judge {
    pub fn read(data: &BTreeMap<String, String>) -> Self {
        let get = |k: &str| {
            data.get(k)
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        let secs = |k: &str| get(k).parse().unwrap_or(0);
        Self {
            good: get("good"),
            previous: get("previous"),
            trial: get("trial"),
            rolled_back: get("rolled_back"),
            window_secs: secs("commit_after_secs"),
            fail_after_secs: secs("fail_after_secs"),
            unhealthy_secs: secs("unhealthy_secs"),
            healthy_since: unix(&get("healthy_since")).unwrap_or(0),
            checks: get("checks").lines().filter_map(check).collect(),
            requests: get("requests")
                .split_whitespace()
                .map(String::from)
                .collect(),
        }
    }

    pub fn takes(&self, what: &str) -> bool {
        self.requests.contains(what)
    }
}

/// `pass <name>` or `fail <name>: <detail>`.
fn check(line: &str) -> Option<Check> {
    let (state, rest) = line.trim().split_once(' ')?;
    let state = match state {
        "pass" => CheckState::Pass,
        "fail" => CheckState::Fail,
        _ => return None,
    };
    let (name, detail) = rest.split_once(':').unwrap_or((rest, ""));
    Some(Check::new(name.trim(), state, detail.trim()))
}

/// The value a judge's `request` key takes: `commit <tag>` or `rollback <tag>`.
pub fn request(what: &str, tag: &str) -> String {
    format!("{what} {tag}")
}

/// Unix seconds of an RFC 3339 UTC time, `2026-10-02T11:00:00Z`.
pub fn unix(t: &str) -> Option<i64> {
    let t = t.strip_suffix('Z')?;
    let (date, time) = t.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let time = time.split('.').next()?;
    let mut h = time.split(':').map(|p| p.parse::<i64>().ok());
    let (hh, mm, ss) = (h.next()??, h.next()??, h.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from the civil date, Howard Hinnant's algorithm.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_times_read_as_unix_seconds() {
        assert_eq!(unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix("2026-09-01T00:00:10Z"), Some(1_788_220_810));
        assert_eq!(unix("2000-02-29T12:30:45.5Z"), Some(951_827_445));
        assert_eq!(unix("2026-09-01T00:00:10+08:00"), None);
        assert_eq!(unix("2026-13-01T00:00:00Z"), None);
        assert_eq!(unix(""), None);
    }

    #[test]
    fn a_judge_says_its_window_its_streak_and_its_checks() {
        let data: BTreeMap<String, String> = [
            ("good", "s1"),
            ("previous", "s0"),
            ("trial", "s2"),
            ("commit_after_secs", "300"),
            ("fail_after_secs", "900"),
            ("unhealthy_secs", "30"),
            ("healthy_since", "2026-09-01T00:00:10Z"),
            (
                "checks",
                "pass applied\npass ready\nfail workloads: deployment a/b, daemonset c/d\nodd line\n",
            ),
            ("requests", "commit rollback"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let j = Judge::read(&data);
        assert_eq!(
            (j.good.as_str(), j.previous.as_str(), j.trial.as_str()),
            ("s1", "s0", "s2")
        );
        assert_eq!(
            (
                j.window_secs,
                j.fail_after_secs,
                j.unhealthy_secs,
                j.healthy_since
            ),
            (300, 900, 30, 1_788_220_810)
        );
        assert_eq!(
            j.checks,
            [
                Check::new("applied", CheckState::Pass, ""),
                Check::new("ready", CheckState::Pass, ""),
                Check::new(
                    "workloads",
                    CheckState::Fail,
                    "deployment a/b, daemonset c/d"
                ),
            ]
        );
        assert!(j.takes("commit") && j.takes("rollback") && !j.takes("other"));
    }

    #[test]
    fn a_judge_that_says_nothing_more_reads_as_unknown() {
        let j = Judge::read(&BTreeMap::from([("good".into(), "s1".into())]));
        assert_eq!(
            (
                j.window_secs,
                j.healthy_since,
                j.checks.len(),
                j.requests.len()
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(request("commit", "s2"), "commit s2");
    }
}
