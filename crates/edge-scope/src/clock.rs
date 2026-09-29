//! The clock floor: a proven lower bound on the true time, stepped to at boot. An
//! unsynced clock never raises it, so a far-future RTC cannot poison it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub boot: String,
    pub up: u64,
    pub fl: u64,
}

/// A mark from an earlier boot is credited this boot's whole uptime, one from this
/// boot the uptime since it; with the boot unknown, nothing.
pub fn floor(build: u64, marks: &[Mark], boot: &str, up_now: u64) -> u64 {
    let known = !boot.is_empty();
    let mut f = if known {
        build.saturating_add(up_now)
    } else {
        build
    };
    for m in marks {
        let elapsed = match (known, m.boot == boot) {
            (false, _) => 0,
            (true, true) => up_now.saturating_sub(m.up),
            (true, false) if m.boot.is_empty() => 0,
            (true, false) => up_now,
        };
        f = f.max(m.fl.saturating_add(elapsed));
    }
    f
}

#[derive(Debug, Clone, Copy)]
pub struct Credit {
    wall: u64,
    up: u64,
}

impl Credit {
    pub fn new(floor: u64, up: u64) -> Self {
        Self { wall: floor, up }
    }

    pub fn at(&mut self, t: u64, up: u64, synced: bool) -> u64 {
        if synced {
            *self = Self { wall: t, up };
            return t;
        }
        self.wall.saturating_add(up.saturating_sub(self.up))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Rtc,
    Floor,
    Ntp,
}

pub fn source(stepped_by: u64, synced: bool) -> Source {
    if synced {
        Source::Ntp
    } else if stepped_by > 0 {
        Source::Floor
    } else {
        Source::Rtc
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quality {
    pub boot: String,
    pub source: Source,
    pub synced: bool,
    pub floor: u64,
    pub stepped_by: u64,
}

pub fn build_epoch(runtime: Option<&str>) -> u64 {
    let embedded = option_env!("SOURCE_DATE_EPOCH")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0u64);
    let given = runtime.and_then(|v| v.trim().parse().ok()).unwrap_or(0u64);
    embedded.max(given)
}

pub fn synced() -> bool {
    let mut tx: nix::libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: modes = 0 only reads.
    let state = unsafe { nix::libc::adjtimex(&mut tx) };
    state >= 0 && state != nix::libc::TIME_ERROR
}

pub fn set(to: std::time::Duration) -> nix::Result<()> {
    nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, to.into())
}

/// A clock stepped to the floor is bounded below, not synchronised.
pub fn mark_unsynced() -> nix::Result<()> {
    let mut tx: nix::libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: modes = 0 only reads.
    if unsafe { nix::libc::adjtimex(&mut tx) } < 0 {
        return Err(nix::Error::last());
    }
    tx.modes = nix::libc::ADJ_STATUS;
    tx.status |= nix::libc::STA_UNSYNC;
    // SAFETY: a timex read from the kernel, with only the status changed.
    if unsafe { nix::libc::adjtimex(&mut tx) } < 0 {
        return Err(nix::Error::last());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: u64 = 1_790_000_000;
    const YEAR: u64 = 365 * 86_400;

    fn mark(boot: &str, up: u64, fl: u64) -> Mark {
        Mark {
            boot: boot.into(),
            up,
            fl,
        }
    }

    /// (case, marks, this boot, uptime now, rtc now, expected floor, expected step)
    type Row = (&'static str, Vec<Mark>, &'static str, u64, u64, u64, u64);

    #[test]
    fn floor_and_step() {
        let cut = BUILD + 30 * 86_400;
        let rows: &[Row] = &[
            (
                "rtc behind the last record",
                vec![mark("aa", 900, cut)],
                "bb",
                10,
                BUILD - YEAR,
                cut + 10,
                cut + 10 - (BUILD - YEAR),
            ),
            (
                "rtc ahead is left alone",
                vec![mark("aa", 900, cut)],
                "bb",
                10,
                cut + YEAR,
                cut + 10,
                0,
            ),
            (
                "rtc equal to the floor",
                vec![mark("aa", 900, cut)],
                "bb",
                10,
                cut + 10,
                cut + 10,
                0,
            ),
            (
                "no records: the build time",
                vec![],
                "bb",
                10,
                0,
                BUILD + 10,
                BUILD + 10,
            ),
            (
                "records older than the build",
                vec![mark("aa", 1, BUILD - YEAR)],
                "bb",
                0,
                0,
                BUILD,
                BUILD,
            ),
            (
                "the newest mark wins",
                vec![
                    mark("aa", 1, cut),
                    mark("aa", 2, cut - 100),
                    mark("cc", 3, cut - 5),
                ],
                "bb",
                0,
                0,
                cut,
                cut,
            ),
            (
                "v1/v2 records carry no floor",
                vec![mark("", 0, 0), mark("aa", 5, 0)],
                "bb",
                7,
                0,
                BUILD + 7,
                BUILD + 7,
            ),
            (
                "a restart within this boot credits only the time since",
                vec![mark("bb", 100, cut)],
                "bb",
                160,
                0,
                cut + 60,
                cut + 60,
            ),
            (
                "a mark from a boot of unknown id is credited nothing",
                vec![mark("", 100, cut)],
                "bb",
                160,
                0,
                cut,
                cut,
            ),
            (
                "this boot unknown: nothing is credited",
                vec![mark("aa", 100, cut)],
                "",
                160,
                0,
                cut,
                cut,
            ),
            (
                "a mark with uptime past now is not a negative credit",
                vec![mark("bb", 500, cut)],
                "bb",
                10,
                0,
                cut,
                cut,
            ),
            (
                "saturates, never wraps",
                vec![mark("aa", 0, u64::MAX - 1)],
                "bb",
                10,
                0,
                u64::MAX,
                u64::MAX,
            ),
        ];
        for (case, marks, boot, up, rtc, want_floor, want_step) in rows {
            let f = floor(BUILD, marks, boot, *up);
            assert_eq!(f, *want_floor, "{case}");
            assert_eq!(f.saturating_sub(*rtc), *want_step, "{case}");
        }
        assert_eq!(
            floor(0, &[], "bb", 10),
            10,
            "no build time still counts uptime"
        );
    }

    #[test]
    fn future_unsynced_clock_keeps_floor() {
        let f0 = floor(BUILD, &[], "aa", 5);
        let mut c = Credit::new(f0, 5);
        let future = BUILD + 10 * YEAR;
        let fl = c.at(future + 600, 605, false);
        assert_eq!(fl, f0 + 600);
        let next = floor(BUILD, &[mark("aa", 605, fl)], "bb", 3);
        assert_eq!(next, f0 + 603);
        assert_eq!(next.saturating_sub(BUILD - YEAR), next - (BUILD - YEAR));
    }

    #[test]
    fn synced_clock_sets_floor() {
        let mut c = Credit::new(BUILD, 0);
        assert_eq!(c.at(BUILD + 50, 10, false), BUILD + 10);
        assert_eq!(c.at(BUILD + 1_000, 20, true), BUILD + 1_000);
        assert_eq!(c.at(BUILD + 9_999, 30, false), BUILD + 1_010);
        assert_eq!(c.at(BUILD - 5, 40, true), BUILD - 5);
        assert_eq!(c.at(0, 41, false), BUILD - 4);
    }

    #[test]
    fn source_names_clock_setter() {
        assert_eq!(source(0, false), Source::Rtc);
        assert_eq!(source(9, false), Source::Floor);
        assert_eq!(source(9, true), Source::Ntp);
        assert_eq!(source(0, true), Source::Ntp);
        let q = Quality {
            boot: "aa".into(),
            source: Source::Floor,
            synced: false,
            floor: 7,
            stepped_by: 3,
        };
        assert_eq!(
            serde_json::to_string(&q).unwrap(),
            r#"{"boot":"aa","source":"floor","synced":false,"floor":7,"stepped_by":3}"#
        );
    }

    #[test]
    fn build_epoch_takes_later() {
        let embedded = build_epoch(None);
        assert_eq!(build_epoch(Some("not a number")), embedded);
        assert_eq!(build_epoch(Some("-5")), embedded);
        assert_eq!(
            build_epoch(Some(" 4102444800 ")),
            4_102_444_800.max(embedded)
        );
    }
}
