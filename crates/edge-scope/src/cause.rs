use serde::Serialize;

use crate::nvme::Smart;
use crate::record::Past;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cause {
    PowerCut,
    WatchdogReset,
    Clean,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Last {
    Nothing,
    Stop,
    Running { watch_failing: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsafe {
    Rose,
    /// Unchanged and non-zero, so known to count.
    Same,
    Unknown,
}

pub const LONGEST_WHY: &str = "no power loss, no stop, no watchdog record";

/// The watchdog outranks a power cut: a unit that stopped petting would have
/// reset anyway.
pub fn classify(last: Last, watch_pending: bool, unsafe_: Unsafe) -> (Cause, &'static str) {
    match (last, unsafe_) {
        (Last::Stop, Unsafe::Rose) => (Cause::PowerCut, "power lost after the recorder stopped"),
        (Last::Stop, _) => (Cause::Clean, "the recorder was stopped"),
        _ if watch_pending => (Cause::WatchdogReset, "edge-watch reset pending"),
        (
            Last::Running {
                watch_failing: true,
            },
            _,
        ) => (Cause::WatchdogReset, "edge-watch had stopped petting"),
        (_, Unsafe::Rose) => (Cause::PowerCut, "unsafe shutdown count rose"),
        (_, Unsafe::Same) => (Cause::Unknown, LONGEST_WHY),
        (Last::Running { .. }, Unsafe::Unknown) => (Cause::PowerCut, "recording ended unannounced"),
        (Last::Nothing, Unsafe::Unknown) => (Cause::Unknown, "no record of the previous boot"),
    }
}

/// `past` is oldest first.
pub fn evidence(past: &[Past], boot: &str, now: &[Smart]) -> (Last, Unsafe) {
    let before: Vec<&Past> = past
        .iter()
        .filter(|p| p.boot != boot || boot.is_empty())
        .collect();
    let last = match before.last() {
        None => Last::Nothing,
        Some(p) if p.k == "stop" => Last::Stop,
        Some(p) => Last::Running {
            watch_failing: before
                .iter()
                .rev()
                .find(|p| p.k.is_empty())
                .is_some_and(|s| !s.failing.is_empty() && s.boot == p.boot),
        },
    };

    let mut unsafe_ = Unsafe::Unknown;
    for s in now {
        let prev = before
            .iter()
            .rev()
            .find(|p| p.k == "nvme" && p.dev == s.dev)
            .and_then(|p| p.unsafe_shutdowns);
        match prev {
            Some(p) if s.unsafe_shutdowns > p => return (last, Unsafe::Rose),
            Some(p) if s.unsafe_shutdowns == p && p > 0 => unsafe_ = Unsafe::Same,
            _ => {}
        }
    }
    (last, unsafe_)
}

#[cfg(test)]
mod tests {
    use super::*;

    use Cause::*;
    use Last::*;
    use Unsafe::*;

    #[test]
    fn every_combination_classifies() {
        let running = Running {
            watch_failing: false,
        };
        let failing = Running {
            watch_failing: true,
        };
        let rows = [
            (Stop, false, Unsafe::Unknown, Clean),
            (Stop, false, Same, Clean),
            (Stop, true, Unsafe::Unknown, Clean),
            (Stop, false, Rose, PowerCut),
            (Stop, true, Rose, PowerCut),
            (running, true, Unsafe::Unknown, WatchdogReset),
            (running, true, Rose, WatchdogReset),
            (Nothing, true, Same, WatchdogReset),
            (failing, false, Unsafe::Unknown, WatchdogReset),
            (failing, false, Rose, WatchdogReset),
            (failing, false, Same, WatchdogReset),
            (running, false, Rose, PowerCut),
            (Nothing, false, Rose, PowerCut),
            (running, false, Same, Cause::Unknown),
            (Nothing, false, Same, Cause::Unknown),
            (running, false, Unsafe::Unknown, PowerCut),
            (Nothing, false, Unsafe::Unknown, Cause::Unknown),
        ];
        for (last, pending, u, want) in rows {
            let (got, why) = classify(last, pending, u);
            assert_eq!(got, want, "{last:?} pending={pending} {u:?}: {why}");
        }
        assert_eq!(
            serde_json::to_string(&WatchdogReset).unwrap(),
            "\"watchdog-reset\""
        );
    }

    fn sample(boot: &str, failing: &[&str]) -> Past {
        Past {
            t: Some(1),
            boot: boot.into(),
            failing: failing.iter().map(|s| s.to_string()).collect(),
            ..Past::default()
        }
    }

    fn kind(k: &str, boot: &str) -> Past {
        Past {
            k: k.into(),
            ..sample(boot, &[])
        }
    }

    fn nvme(boot: &str, dev: &str, count: u64) -> Past {
        Past {
            dev: dev.into(),
            unsafe_shutdowns: Some(count),
            ..kind("nvme", boot)
        }
    }

    fn smart(dev: &str, count: u64) -> Smart {
        Smart {
            dev: dev.into(),
            unsafe_shutdowns: count,
            ..Smart::default()
        }
    }

    #[test]
    fn previous_boot_last_record_counts() {
        let run = Running {
            watch_failing: false,
        };
        let cases: Vec<(&str, Vec<Past>, Last)> = vec![
            ("empty ring", vec![], Nothing),
            ("only this boot", vec![sample("cc", &[])], Nothing),
            ("stopped", vec![sample("aa", &[]), kind("stop", "aa")], Stop),
            (
                "stopped, then restarted and cut",
                vec![kind("stop", "aa"), sample("aa", &[])],
                run,
            ),
            (
                "this boot's records are not the previous boot's",
                vec![sample("aa", &[]), kind("stop", "cc")],
                run,
            ),
            (
                "failing at the end",
                vec![sample("aa", &["x"]), kind("nvme", "aa")],
                Running {
                    watch_failing: true,
                },
            ),
            (
                "failing earlier then recovered",
                vec![sample("aa", &["x"]), sample("aa", &[])],
                run,
            ),
            (
                "failing in an older boot only",
                vec![sample("zz", &["x"]), sample("aa", &[]), kind("time", "aa")],
                run,
            ),
            (
                "failing in an older boot, none since",
                vec![sample("zz", &["x"]), kind("boot", "aa")],
                run,
            ),
            ("records without a boot id", vec![sample("", &[])], run),
        ];
        for (case, past, want) in cases {
            assert_eq!(evidence(&past, "cc", &[]).0, want, "{case}");
        }
        assert_eq!(
            evidence(&[sample("", &[])], "", &[]).0,
            run,
            "this boot unknown"
        );
    }

    #[test]
    fn unsafe_count_per_controller() {
        let past = vec![
            nvme("zz", "nvme0", 1),
            nvme("aa", "nvme0", 7),
            nvme("aa", "nvme1", 0),
            sample("aa", &[]),
        ];
        let cases: Vec<(&str, Vec<Smart>, Unsafe)> = vec![
            ("rose", vec![smart("nvme0", 8)], Rose),
            ("same", vec![smart("nvme0", 7)], Same),
            (
                "a counter that never counted",
                vec![smart("nvme1", 0)],
                Unsafe::Unknown,
            ),
            (
                "any controller rising",
                vec![smart("nvme1", 0), smart("nvme0", 9)],
                Rose,
            ),
            (
                "fell: a replaced device",
                vec![smart("nvme0", 2)],
                Unsafe::Unknown,
            ),
            (
                "no previous reading",
                vec![smart("nvme5", 3)],
                Unsafe::Unknown,
            ),
            ("no SMART now", vec![], Unsafe::Unknown),
        ];
        for (case, now, want) in cases {
            assert_eq!(evidence(&past, "cc", &now).1, want, "{case}");
        }
        let this_boot = vec![nvme("aa", "nvme0", 7), nvme("cc", "nvme0", 8)];
        assert_eq!(
            evidence(&this_boot, "cc", &[smart("nvme0", 8)]).1,
            Rose,
            "this boot's own reading is not the baseline"
        );
    }
}
