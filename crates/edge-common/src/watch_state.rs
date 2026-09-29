//! Written by edge-watch; edge-scope and boot-commit read it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Cleared only by sustained health, never by merely booting.
    #[serde(default)]
    pub consecutive_resets: u32,
    /// Seen set at startup: the last reset was ours.
    #[serde(default)]
    pub reset_pending: bool,
    #[serde(default)]
    pub last_failure: Vec<String>,
    #[serde(default)]
    pub last_failure_at: Option<String>,
    #[serde(default)]
    pub repairs: u32,
    #[serde(default)]
    pub last_repair_at: Option<String>,
    /// The watchdog stays disarmed until the checks pass for the recovery period.
    #[serde(default)]
    pub exhausted: bool,
    #[serde(default)]
    pub healthy_since: Option<HealthySince>,
}

/// CLOCK_BOOTTIME, which no clock step moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthySince {
    pub boot_id: String,
    pub boottime_secs: u64,
}

impl State {
    pub fn failing_now(&self) -> &[String] {
        if self.reset_pending {
            &self.last_failure
        } else {
            &[]
        }
    }

    /// Unknown fields are ignored so a newer writer does not blind an older reader.
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failing_now_only_while_pending() {
        let text =
            r#"{"consecutive_resets":2,"reset_pending":true,"last_failure":["a"],"future":1}"#;
        let mut s = State::parse(text).unwrap();
        assert_eq!(s.consecutive_resets, 2);
        assert_eq!(s.failing_now(), ["a"]);
        s.reset_pending = false;
        assert!(s.failing_now().is_empty());
        assert!(State::parse("").is_err());
    }
}
