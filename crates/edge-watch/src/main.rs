//! Bad config, storage or device trouble never stops the watchdog arming: each
//! degrades and retries.

mod checks;
mod repair;
mod state;
mod supervise;
mod watchdog;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::state::{Gate, ResetGate, Rung};
use crate::supervise::{Probation, Supervisor, Verdict};
use crate::watchdog::Backoff;

/// Armed for the repair: the reset sequence must reboot within this, or the
/// watchdog does it.
const REPAIR_TIMEOUT_SECS: u32 = 300;

struct Paths {
    config_dir: PathBuf,
    device: PathBuf,
    state: PathBuf,
    machined: PathBuf,
}

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();

    let var = |name: &str, default: &str| -> PathBuf {
        std::env::var(name)
            .unwrap_or_else(|_| default.into())
            .into()
    };
    let paths = Paths {
        config_dir: var("EDGE_WATCH_CONFIG", "/etc/edge-watch"),
        device: var("EDGE_WATCH_DEVICE", "/dev/watchdog0"),
        state: var("EDGE_WATCH_STATE", "/var/lib/edge-watch"),
        machined: var("EDGE_WATCH_MACHINED", "/system/run/machined/machine.sock"),
    };
    // Before the sandbox: Landlock grants the inode a path names now.
    edge_common::mount::await_evidence_volume();
    let sys = watchdog::sys_dir(&paths.device);
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .inspect_err(|e| tracing::warn!(error = %e, "no boot id; health is not recorded"))
        .ok();
    edge_common::sandbox::restrict(&edge_common::sandbox::watch(edge_common::sandbox::Watch {
        config_dir: &paths.config_dir,
        device: &paths.device,
        sys: sys.as_deref(),
        state: &paths.state,
        machined_socket: &paths.machined,
    }));
    run(paths, sys, boot_id)
}

#[tokio::main]
async fn run(paths: Paths, sys: Option<PathBuf>, boot_id: Option<String>) -> anyhow::Result<()> {
    // Before anything is armed: a default-disposition SIGTERM would skip the magic close.
    let mut term = edge_common::Terminator::new();

    let (mut cfg, mut cfg_degraded) = checks::Config::load_or_fallback(&paths.config_dir);

    let store = state::Store::new(&paths.state);
    let mut st = state::fold_boot(store.load());
    if let Err(e) = store.save(&st) {
        tracing::error!(
            error = %format!("{e:#}"), dir = %paths.state.display(),
            "cannot write the state record; arming anyway, due resets are deferred until it can be written"
        );
    }

    if let Some(bs) = sys.as_deref().and_then(watchdog::boot_status)
        && bs != 0
    {
        tracing::warn!(
            bootstatus = bs,
            "the driver reports the last reset was the watchdog"
        );
    }

    // Decided before opening the device, because opening arms it.
    let rung = next_rung(&cfg, &st);
    let mut health = Health {
        boot_id,
        write_failed: false,
    };
    if rung != Rung::Arm
        && !unarmed(rung, &cfg, &paths, &store, &mut st, &mut health, &mut term).await
    {
        return Ok(());
    }

    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let mut wd = loop {
        match watchdog::Watchdog::open(&paths.device, cfg.timeout_secs) {
            Ok(w) => break w,
            Err(e) => {
                let wait = backoff.next_delay();
                tracing::error!(
                    error = %format!("{e:#}"), retry_in = ?wait,
                    "watchdog not armed; retrying"
                );
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = term.wait() => {
                        tracing::info!("SIGTERM before the watchdog was armed; exiting");
                        return Ok(());
                    }
                }
            }
        }
    };

    let mut sup = Supervisor::new(Duration::from_secs(cfg.startup_grace_secs));
    let mut probation = Probation::new(Duration::from_secs(cfg.recovery_secs));
    let interval_secs = watchdog::effective_interval(cfg.interval_secs, wd.timeout_secs);
    let interval = Duration::from_secs(interval_secs);
    // Worst gap between pets is interval + round deadline = 1.75x interval,
    // under the 2x the config validation guarantees.
    let probe_timeout = interval / 2;
    let round_deadline = interval * 3 / 4;
    let mut gate = ResetGate::new(Duration::from_secs(cfg.unrecorded_reset_after_secs));

    tracing::info!(
        checks = cfg.checks.len(),
        interval_secs,
        timeout_secs = wd.timeout_secs,
        "edge-watch supervising the mission path"
    );

    let mut was_degraded = false;
    let mut clear_failed = false;
    let mut pet_failed = false;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = term.wait() => return orderly_stop(&mut wd, &mut st, &store),
        }

        // Adopt only the checks: the timer is already armed with fallback timing.
        if cfg_degraded && let Ok(real) = checks::Config::load(&paths.config_dir) {
            tracing::warn!(
                checks = real.checks.len(),
                "valid config appeared; checking the mission path"
            );
            cfg.checks = real.checks;
            cfg_degraded = false;
        }

        let results = tokio::select! {
            r = checks::run_round(&cfg.checks, probe_timeout, round_deadline) => r,
            _ = term.wait() => return orderly_stop(&mut wd, &mut st, &store),
        };

        let verdict = sup.observe(Instant::now(), &results);
        health.observe(&store, &mut st, &cfg, &verdict);
        if probation.observe(Instant::now(), &verdict) && state::on_ladder(&st) {
            let (resets, repairs) = (st.consecutive_resets, st.repairs);
            match state::recovered(&store, &mut st) {
                Ok(()) => {
                    tracing::info!(
                        resets,
                        repairs,
                        "mission path recovered; clearing the ladder"
                    );
                    clear_failed = false;
                }
                Err(e) if !clear_failed => {
                    tracing::warn!(error = %format!("{e:#}"), "could not persist clearing the ladder; retrying");
                    clear_failed = true;
                }
                Err(_) => {}
            }
        }
        match verdict {
            Verdict::Healthy => {
                gate.clear();
                if was_degraded {
                    tracing::info!("mission path healthy again");
                    was_degraded = false;
                }
                pet(&mut wd, &mut pet_failed);
            }
            Verdict::Degraded(names) => {
                gate.clear();
                if !was_degraded {
                    tracing::warn!(failing = ?names, "degraded but within grace; still petting");
                    was_degraded = true;
                }
                pet(&mut wd, &mut pet_failed);
            }
            Verdict::Reset(names) => {
                // Record before the pets stop: after, the machine is going down.
                let recorded = state::arm_reset(&store, &mut st, names.clone(), epoch_timestamp());
                let decision = gate.decide(Instant::now(), recorded.is_ok());
                match decision {
                    Gate::Proceed | Gate::ProceedUnrecorded => {
                        if decision == Gate::ProceedUnrecorded {
                            tracing::error!(
                                error = ?recorded.err().map(|e| format!("{e:#}")),
                                "resetting without a flight record: storage unwritable past unrecorded_reset_after_secs; the breaker cannot count this reset"
                            );
                        }
                        tracing::error!(
                            failing = ?names,
                            in_secs = wd.timeout_secs,
                            "mission path down past grace; stopped petting, the machine will reset"
                        );
                        loop {
                            term.wait().await;
                            tracing::warn!("SIGTERM ignored: a watchdog reset is pending");
                        }
                    }
                    Gate::Defer { log, remaining } => {
                        if log {
                            tracing::error!(
                                failing = ?names,
                                error = ?recorded.err().map(|e| format!("{e:#}")),
                                retry_reset_in = ?remaining,
                                "mission path down past grace but the flight record cannot be written; deferring the reset"
                            );
                        }
                        pet(&mut wd, &mut pet_failed);
                    }
                }
            }
        }
    }
}

/// With no checks (the fallback) only a wedged kernel can stop the pets, so
/// there is no loop for the breaker to break.
fn next_rung(cfg: &checks::Config, st: &state::State) -> Rung {
    if cfg.checks.is_empty() {
        Rung::Arm
    } else {
        state::rung(st, cfg.max_consecutive_resets)
    }
}

/// The checks run disarmed. Returns true to arm once sustained health clears
/// the ladder, false on SIGTERM.
async fn unarmed(
    rung: Rung,
    cfg: &checks::Config,
    paths: &Paths,
    store: &state::Store,
    st: &mut state::State,
    health: &mut Health,
    term: &mut edge_common::Terminator,
) -> bool {
    tracing::error!(
        consecutive_resets = st.consecutive_resets,
        limit = cfg.max_consecutive_resets,
        repairs = st.repairs,
        failed = ?st.last_failure,
        at = ?st.last_failure_at,
        next = ?rung,
        "boot-loop breaker tripped; not arming until the checks pass for recovery_secs"
    );
    if rung == Rung::Exhausted
        && !st.exhausted
        && let Err(e) = state::mark_exhausted(store, st)
    {
        tracing::warn!(error = %format!("{e:#}"), "could not record the exhausted ladder");
    }
    let interval = Duration::from_secs(cfg.interval_secs);
    let mut sup = Supervisor::new(Duration::from_secs(cfg.startup_grace_secs));
    let mut probation = Probation::new(Duration::from_secs(cfg.recovery_secs));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = term.wait() => {
                tracing::info!("SIGTERM: exiting unarmed");
                return false;
            }
        }
        let results = tokio::select! {
            r = checks::run_round(&cfg.checks, interval / 2, interval * 3 / 4) => r,
            _ = term.wait() => {
                tracing::info!("SIGTERM: exiting unarmed");
                return false;
            }
        };
        let verdict = sup.observe(Instant::now(), &results);
        health.observe(store, st, cfg, &verdict);
        if probation.observe(Instant::now(), &verdict) {
            tracing::warn!(
                resets = st.consecutive_resets,
                repairs = st.repairs,
                "mission path recovered; clearing the ladder and arming"
            );
            if let Err(e) = state::recovered(store, st) {
                tracing::warn!(error = %format!("{e:#}"), "could not persist clearing the ladder; arming anyway");
            }
            return true;
        }
        if rung == Rung::Repair
            && let Verdict::Reset(names) = verdict
        {
            match state::begin_repair(store, st, names.clone(), epoch_timestamp()) {
                Ok(()) => {
                    repair(&paths.device, &paths.machined, names, term).await;
                    return false;
                }
                Err(e) => tracing::error!(
                    error = %format!("{e:#}"),
                    "cannot record the repair; not taking it until the record can be written"
                ),
            }
        }
    }
}

async fn repair(
    device: &Path,
    machined: &Path,
    failing: Vec<String>,
    term: &mut edge_common::Terminator,
) {
    let _backstop = watchdog::Watchdog::open(device, REPAIR_TIMEOUT_SECS)
        .inspect_err(
            |e| tracing::error!(error = %format!("{e:#}"), "no watchdog behind the repair"),
        )
        .ok();
    tracing::error!(failing = ?failing, "mission path down past grace again; repairing: wiping EPHEMERAL and rebooting");
    if let Err(e) = repair::reset_ephemeral(machined).await {
        tracing::error!(error = %format!("{e:#}"), "machined did not take the repair; the watchdog will reset the machine");
    }
    term.wait().await;
    tracing::info!("SIGTERM during the repair; exiting with the watchdog armed");
}

struct Health {
    boot_id: Option<String>,
    write_failed: bool,
}

impl Health {
    fn observe(
        &mut self,
        store: &state::Store,
        st: &mut state::State,
        cfg: &checks::Config,
        verdict: &Verdict,
    ) {
        let since = match &self.boot_id {
            Some(id) if *verdict == Verdict::Healthy && !cfg.checks.is_empty() => {
                st.healthy_since.clone().or_else(|| {
                    Some(state::HealthySince {
                        boot_id: id.clone(),
                        boottime_secs: boottime_secs(),
                    })
                })
            }
            _ => None,
        };
        match state::set_healthy(store, st, since) {
            Ok(()) => self.write_failed = false,
            Err(e) if !self.write_failed => {
                tracing::warn!(error = %format!("{e:#}"), "could not record the mission path's health; retrying");
                self.write_failed = true;
            }
            Err(_) => {}
        }
    }
}

fn boottime_secs() -> u64 {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
        .map(|t| t.tv_sec().max(0) as u64)
        .unwrap_or(0)
}

fn pet(wd: &mut watchdog::Watchdog, failed: &mut bool) {
    match wd.pet() {
        Ok(()) => *failed = false,
        Err(e) if !*failed => {
            tracing::error!(error = %format!("{e:#}"), "could not pet the watchdog; retrying");
            *failed = true;
        }
        Err(_) => {}
    }
}

/// An orderly stop must not look like a wedge.
fn orderly_stop(
    wd: &mut watchdog::Watchdog,
    st: &mut state::State,
    store: &state::Store,
) -> anyhow::Result<()> {
    tracing::info!("SIGTERM: disarming and exiting");
    if let Err(e) = wd.disarm() {
        tracing::error!(error = %format!("{e:#}"), "could not disarm; the machine may reset after this process exits");
    }
    st.reset_pending = false;
    if let Err(e) = store.save(st) {
        tracing::warn!(error = %format!("{e:#}"), "could not persist the clean stop");
    }
    Ok(())
}

fn epoch_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rung_needs_checks() {
        let with_checks = checks::Config::parse(
            "max_consecutive_resets: 3\nchecks: [ { name: a, kind: tcp, addr: '127.0.0.1:1' } ]",
        )
        .unwrap();
        let resets = |n| state::State {
            consecutive_resets: n,
            ..Default::default()
        };
        assert_eq!(next_rung(&with_checks, &resets(2)), Rung::Arm);
        assert_eq!(next_rung(&with_checks, &resets(3)), Rung::Repair);
        let unlimited = checks::Config {
            max_consecutive_resets: 0,
            ..with_checks.clone()
        };
        assert_eq!(next_rung(&unlimited, &resets(9)), Rung::Arm);
        assert_eq!(next_rung(&checks::Config::default(), &resets(9)), Rung::Arm);
    }

    #[test]
    fn orderly_stop_disarms() {
        let d = std::env::temp_dir().join(format!("edge-watch-stop-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        let dev = d.join("watchdog");
        std::fs::write(&dev, b"").unwrap();
        let mut wd = watchdog::Watchdog::open(&dev, 30).unwrap();
        let store = state::Store::new(&d.join("state"));
        let mut st = state::State {
            consecutive_resets: 1,
            reset_pending: true,
            ..Default::default()
        };
        orderly_stop(&mut wd, &mut st, &store).unwrap();
        assert_eq!(std::fs::read(&dev).unwrap(), b"V");
        let saved = store.load();
        assert!(!saved.reset_pending);
        assert_eq!(saved.consecutive_resets, 1);
        std::fs::remove_dir_all(&d).ok();
    }
}
