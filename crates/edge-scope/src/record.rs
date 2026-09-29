//! Records other than samples, told apart by `k`; samples have none, so older rings
//! read the same.

use serde::{Deserialize, Serialize};

use crate::cause::Cause;
use crate::clock::{Mark, Source};
use crate::nvme::Smart;
use crate::ring::Entry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Boot,
    Time,
    Nvme,
    Stop,
    Cri,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Head {
    pub t: u64,
    pub up: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub boot: String,
    pub fl: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Body {
    Boot {
        prev: Cause,
        why: &'static str,
        src: Source,
        sy: bool,
        floor: u64,
        step: u64,
    },
    Time {
        src: Source,
        sy: bool,
    },
    Nvme(Smart),
    /// Written on SIGTERM: the recorder was stopped, not cut off.
    Stop {},
    /// `ahead`: how far in the future the furthest was, in seconds.
    Cri {
        ctr: u32,
        sbx: u32,
        ahead: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub k: Kind,
    #[serde(flatten)]
    pub head: Head,
    #[serde(flatten)]
    pub body: Body,
}

impl Event {
    pub fn to_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct Past {
    #[serde(default)]
    pub k: String,
    #[serde(default)]
    pub t: Option<u64>,
    #[serde(default)]
    pub up: u64,
    #[serde(default)]
    pub boot: String,
    #[serde(default)]
    pub fl: u64,
    #[serde(default)]
    pub failing: Vec<String>,
    #[serde(default)]
    pub dev: String,
    #[serde(default, rename = "unsafe")]
    pub unsafe_shutdowns: Option<u64>,
}

pub fn history(entries: &[Entry]) -> Vec<Past> {
    entries
        .iter()
        .filter_map(|e| {
            let end = e
                .payload
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(e.payload.len());
            serde_json::from_slice::<Past>(&e.payload[..end]).ok()
        })
        .filter(|p| p.t.is_some())
        .collect()
}

pub fn marks(past: &[Past]) -> Vec<Mark> {
    past.iter()
        .map(|p| Mark {
            boot: p.boot.clone(),
            up: p.up,
            fl: p.fl,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::PAYLOAD;

    fn entry(seq: u64, json: &str) -> Entry {
        let mut payload = json.as_bytes().to_vec();
        payload.resize(PAYLOAD, 0);
        Entry {
            seq,
            payload,
            version: 2,
        }
    }

    fn head() -> Head {
        Head {
            t: 1_790_000_000,
            up: 12,
            boot: "3f2a91bc".into(),
            fl: 1_790_000_012,
        }
    }

    #[test]
    fn events_serialise_flat() {
        let e = Event {
            k: Kind::Boot,
            head: head(),
            body: Body::Boot {
                prev: Cause::WatchdogReset,
                why: "edge-watch had stopped petting",
                src: Source::Floor,
                sy: false,
                floor: 1_790_000_000,
                step: 31_536_000,
            },
        };
        assert_eq!(
            String::from_utf8(e.to_payload()).unwrap(),
            r#"{"k":"boot","t":1790000000,"up":12,"boot":"3f2a91bc","fl":1790000012,"prev":"watchdog-reset","why":"edge-watch had stopped petting","src":"floor","sy":false,"floor":1790000000,"step":31536000}"#
        );
        let stop = Event {
            k: Kind::Stop,
            head: head(),
            body: Body::Stop {},
        };
        assert_eq!(
            String::from_utf8(stop.to_payload()).unwrap(),
            r#"{"k":"stop","t":1790000000,"up":12,"boot":"3f2a91bc","fl":1790000012}"#
        );
        let cri = Event {
            k: Kind::Cri,
            head: head(),
            body: Body::Cri {
                ctr: 11,
                sbx: 4,
                ahead: 31_535_000,
            },
        };
        assert_eq!(
            String::from_utf8(cri.to_payload()).unwrap(),
            r#"{"k":"cri","t":1790000000,"up":12,"boot":"3f2a91bc","fl":1790000012,"ctr":11,"sbx":4,"ahead":31535000}"#
        );
    }

    #[test]
    fn largest_records_fit_slot() {
        let big = Head {
            t: 9_999_999_999,
            up: 999_999_999,
            boot: "ffffffff".into(),
            fl: 9_999_999_999,
        };
        let nvme = Event {
            k: Kind::Nvme,
            head: big.clone(),
            body: Body::Nvme(Smart {
                dev: "nvme99".into(),
                warn: 255,
                temp_c: -273,
                spare: 255,
                spare_min: 255,
                used: 255,
                media_err: 999_999_999_999,
                power_cycles: 999_999_999_999,
                unsafe_shutdowns: 999_999_999_999,
                hours: 999_999_999_999,
            }),
        };
        let boot = Event {
            k: Kind::Boot,
            head: big,
            body: Body::Boot {
                prev: Cause::WatchdogReset,
                why: crate::cause::LONGEST_WHY,
                src: Source::Floor,
                sy: false,
                floor: 9_999_999_999,
                step: 9_999_999_999,
            },
        };
        for e in [nvme, boot] {
            let n = e.to_payload().len();
            assert!(n <= PAYLOAD, "{n} bytes: {e:?}");
        }
    }

    #[test]
    fn history_skips_notes_and_garbage() {
        let all = [
            entry(1, r#"{"note":"ring recreated","why":"x"}"#),
            entry(
                2,
                r#"{"t":5,"cpu":1,"io":2,"mem":3,"iof":4,"memf":5,"avail_mb":6,"load":7,"procs_run":8}"#,
            ),
            entry(
                3,
                r#"{"t":6,"up":9,"boot":"aa","fl":70,"failing":["meridian"],"cpu":0}"#,
            ),
            entry(
                4,
                r#"{"k":"nvme","t":7,"up":10,"boot":"aa","fl":71,"dev":"nvme0","unsafe":4}"#,
            ),
            entry(5, "not json"),
            entry(
                6,
                r#"{"k":"stop","t":8,"up":11,"boot":"aa","fl":72,"future_field":true}"#,
            ),
        ];
        let h = history(&all);
        assert_eq!(h.len(), 4);
        assert_eq!((h[0].k.as_str(), h[0].boot.as_str(), h[0].fl), ("", "", 0));
        assert_eq!(h[1].failing, ["meridian"]);
        assert_eq!(
            (h[2].dev.as_str(), h[2].unsafe_shutdowns),
            ("nvme0", Some(4))
        );
        assert_eq!(h[3].k, "stop");
        assert_eq!(
            marks(&h)[1],
            Mark {
                boot: "aa".into(),
                up: 9,
                fl: 70
            }
        );
    }
}
