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
    /// Not yet passed, and not failed.
    Wait,
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
        Self {
            good: get("good"),
            previous: get("previous"),
            trial: get("trial"),
            rolled_back: get("rolled_back"),
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

/// `pass <name>`, `wait <name>: <detail>` or `fail <name>: <detail>`.
fn check(line: &str) -> Option<Check> {
    let (state, rest) = line.trim().split_once(' ')?;
    let state = match state {
        "pass" => CheckState::Pass,
        "wait" => CheckState::Wait,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_judge_says_its_trial_and_its_checks() {
        let data: BTreeMap<String, String> = [
            ("good", "s1"),
            ("previous", "s0"),
            ("trial", "s2"),
            (
                "checks",
                "pass applied\nwait ready: progressing\nfail workloads: deployment a/b, daemonset c/d\nodd line\n",
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
            j.checks,
            [
                Check::new("applied", CheckState::Pass, ""),
                Check::new("ready", CheckState::Wait, "progressing"),
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
        assert_eq!((j.checks.len(), j.requests.len()), (0, 0));
        assert_eq!(request("commit", "s2"), "commit s2");
    }
}
