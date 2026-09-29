use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Healthy,
    Degraded(Vec<String>),
    Reset(Vec<String>),
}

/// Failing time is wall-clock: a failure count would drift with the interval.
pub struct Supervisor {
    failing_since: HashMap<String, Instant>,
    passed: HashSet<String>,
    startup_grace: Duration,
}

impl Supervisor {
    pub fn new(startup_grace: Duration) -> Self {
        Self {
            failing_since: HashMap::new(),
            passed: HashSet::new(),
            startup_grace,
        }
    }

    pub fn observe(&mut self, now: Instant, results: &[(String, bool, Duration)]) -> Verdict {
        let mut degraded = Vec::new();
        let mut expired = Vec::new();

        for (name, ok, grace) in results {
            if *ok {
                self.failing_since.remove(name);
                self.passed.insert(name.clone());
                continue;
            }
            let grace = if self.passed.contains(name) {
                *grace
            } else {
                (*grace).max(self.startup_grace)
            };
            let since = *self.failing_since.entry(name.clone()).or_insert(now);
            if now.duration_since(since) >= grace {
                expired.push(name.clone());
            } else {
                degraded.push(name.clone());
            }
        }

        if !expired.is_empty() {
            expired.sort();
            Verdict::Reset(expired)
        } else if !degraded.is_empty() {
            degraded.sort();
            Verdict::Degraded(degraded)
        } else {
            Verdict::Healthy
        }
    }
}

pub struct Probation {
    need: Duration,
    healthy_since: Option<Instant>,
}

impl Probation {
    pub fn new(need: Duration) -> Self {
        Self {
            need,
            healthy_since: None,
        }
    }

    pub fn observe(&mut self, now: Instant, verdict: &Verdict) -> bool {
        match verdict {
            Verdict::Healthy => {
                let since = *self.healthy_since.get_or_insert(now);
                now.saturating_duration_since(since) >= self.need
            }
            _ => {
                self.healthy_since = None;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(name: &str, ok: bool, grace: u64) -> (String, bool, Duration) {
        (name.to_string(), ok, Duration::from_secs(grace))
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn degraded_within_grace_then_reset() {
        let mut s = Supervisor::new(Duration::ZERO);
        let t = Instant::now();
        assert_eq!(s.observe(t, &[r("a", true, 60)]), Verdict::Healthy);
        let round = [
            r("quick", false, 10),
            r("slow", false, 300),
            r("a", true, 60),
        ];
        assert_eq!(
            s.observe(t, &round),
            Verdict::Degraded(names(&["quick", "slow"]))
        );
        assert_eq!(
            s.observe(t + Duration::from_secs(9), &round),
            Verdict::Degraded(names(&["quick", "slow"]))
        );
        assert_eq!(
            s.observe(t + Duration::from_secs(10), &round),
            Verdict::Reset(names(&["quick"]))
        );
        assert_eq!(
            Supervisor::new(Duration::ZERO).observe(t, &[r("zero", false, 0)]),
            Verdict::Reset(names(&["zero"]))
        );
    }

    #[test]
    fn startup_grace_until_first_pass() {
        let mut s = Supervisor::new(Duration::from_secs(1200));
        let t = Instant::now();
        let down = [r("a", false, 60), r("b", false, 60)];
        s.observe(t, &down);
        assert_eq!(
            s.observe(t + Duration::from_secs(1199), &down),
            Verdict::Degraded(names(&["a", "b"]))
        );
        assert_eq!(
            s.observe(t + Duration::from_secs(1200), &down),
            Verdict::Reset(names(&["a", "b"]))
        );

        let mut s = Supervisor::new(Duration::from_secs(1200));
        s.observe(t, &[r("a", true, 60), r("b", false, 60)]);
        let down = [r("a", false, 60), r("b", false, 600)];
        s.observe(t + Duration::from_secs(10), &down);
        assert_eq!(
            s.observe(t + Duration::from_secs(70), &down),
            Verdict::Reset(names(&["a"])),
            "a passed once, so its own grace applies"
        );
        assert_eq!(
            s.observe(t + Duration::from_secs(1200), &[r("b", false, 1500)]),
            Verdict::Degraded(names(&["b"])),
            "a grace longer than the startup grace is kept"
        );
    }

    #[test]
    fn flapping_never_accumulates() {
        let mut s = Supervisor::new(Duration::ZERO);
        let t = Instant::now();
        s.observe(t, &[r("a", false, 60)]);
        s.observe(t + Duration::from_secs(59), &[r("a", true, 60)]);
        let v = s.observe(t + Duration::from_secs(100), &[r("a", false, 60)]);
        assert_eq!(v, Verdict::Degraded(names(&["a"])));
    }

    #[test]
    fn probation_needs_unbroken_health() {
        let mut p = Probation::new(Duration::from_secs(600));
        let t = Instant::now();
        assert!(!p.observe(t, &Verdict::Healthy));
        assert!(!p.observe(t + Duration::from_secs(599), &Verdict::Healthy));
        assert!(!p.observe(
            t + Duration::from_secs(700),
            &Verdict::Degraded(names(&["a"]))
        ));
        assert!(!p.observe(t + Duration::from_secs(710), &Verdict::Healthy));
        assert!(!p.observe(t + Duration::from_secs(1309), &Verdict::Healthy));
        assert!(p.observe(t + Duration::from_secs(1310), &Verdict::Healthy));
    }
}
