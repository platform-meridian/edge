//! Flight recorder into a power-cut-safe ring on flash. `edge-scope dump` prints
//! the ring, the services ring, then each log ring, oldest first, one JSON
//! object per line.

mod cri;
mod ntp;
mod shutdown;

use edge_scope::{cause, clock, logs, nvme, record, ring, sample, services};

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use record::{Body, Event, Head, Kind};

const DEFAULT_SLOTS: u64 = 900;
const MAX_SLOTS: u64 = 1_000_000;

const REOPEN_AFTER: u32 = 5;

/// Inside the default ring's fifteen minutes, so the next boot always finds
/// a reading to compare the unsafe-shutdown count against.
const SMART_EVERY: Duration = Duration::from_secs(600);
const HWMON_EVERY: Duration = Duration::from_secs(10);

/// A time sync that has not asked by then is not coming; the floor is set directly.
const TAKE_FLOOR_WITHIN: Duration = Duration::from_secs(20);

fn env_or_default(name: &str, raw: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    let Some(raw) = raw else { return default };
    match raw.trim().parse::<u64>() {
        Ok(n) if (min..=max).contains(&n) => n,
        _ => {
            tracing::error!(
                name,
                value = raw,
                default,
                min,
                max,
                "out of range; using the default"
            );
            default
        }
    }
}

struct Recorder {
    path: PathBuf,
    slots: u64,
    ring: Option<ring::Ring>,
    failures: u32,
    next_open: Instant,
    next_check: Instant,
    retry_every: Duration,
    check_every: Duration,
    logged: u32,
}

impl Recorder {
    fn new(path: PathBuf, slots: u64, retry_every: Duration, check_every: Duration) -> Self {
        let now = Instant::now();
        Self {
            path,
            slots,
            ring: None,
            failures: 0,
            next_open: now,
            next_check: now + check_every,
            retry_every,
            check_every,
            logged: 0,
        }
    }

    fn open(&mut self, now: Instant) {
        match ring::Ring::open(&self.path, self.slots) {
            Ok(mut r) => {
                tracing::info!(ring = %self.path.display(), slots = r.slots(), "edge-scope recording");
                if let Some(why) = r.take_recovered() {
                    let note = serde_json::json!({ "note": "ring recreated", "why": why });
                    let mut bytes = serde_json::to_vec(&note).unwrap_or_default();
                    bytes.truncate(ring::PAYLOAD);
                    if let Err(e) = r.append(&bytes) {
                        tracing::warn!(error = %e, "could not write the recovery note");
                    }
                }
                self.ring = Some(r);
                self.failures = 0;
            }
            Err(e) => {
                tracing::error!(
                    error = %format!("{e:#}"), ring = %self.path.display(), retry_in = ?self.retry_every,
                    "cannot open the ring; sampling without recording until it opens"
                );
                self.ring = None;
                self.next_open = now + self.retry_every;
            }
        }
    }

    fn ready(&mut self, now: Instant) -> bool {
        if self.ring.is_none() {
            if now < self.next_open {
                return false;
            }
            self.open(now);
        } else if now >= self.next_check {
            self.next_check = now + self.check_every;
            if self
                .ring
                .as_ref()
                .is_some_and(|r| !r.is_current(&self.path))
            {
                tracing::error!(ring = %self.path.display(), "ring file removed or replaced; reopening");
                self.ring = None;
                self.open(now);
            }
        }
        self.ring.is_some()
    }

    fn entries(&mut self) -> Vec<ring::Entry> {
        self.ring
            .as_mut()
            .and_then(|r| r.read_all().ok())
            .unwrap_or_default()
    }

    fn record(&mut self, now: Instant, payload: &[u8]) {
        if !self.ready(now) {
            return;
        }
        let Some(r) = self.ring.as_mut() else { return };
        match r.append(payload) {
            Ok(_) => {
                self.failures = 0;
                self.logged = 0;
            }
            Err(e) => {
                self.failures += 1;
                // Once a minute: the log may be on the same full disk.
                if self.logged.is_multiple_of(60) {
                    tracing::warn!(error = %e, bytes = payload.len(), failures = self.failures, "could not append a sample");
                }
                self.logged += 1;
                if self.failures >= REOPEN_AFTER {
                    self.failures = 0;
                    self.ring = None;
                    self.next_open = now + self.retry_every;
                }
            }
        }
    }
}

struct Sources {
    proc_dir: PathBuf,
    sys_dir: PathBuf,
    dev_dir: PathBuf,
    watch_state: PathBuf,
    time_file: PathBuf,
}

struct Scope {
    rec: Recorder,
    src: Sources,
    boot: String,
    credit: clock::Credit,
    floor: u64,
    stepped_by: u64,
    smart: Vec<nvme::Smart>,
    read_smart: fn(&Path) -> Vec<nvme::Smart>,
    booted: bool,
    published: Option<clock::Quality>,
    temps: std::collections::BTreeMap<String, i32>,
    next_hwmon: Instant,
    next_smart: Instant,
    swept: Option<Receiver<cri::Stale>>,
}

impl Scope {
    fn head(&mut self, t: u64, up: u64, synced: bool) -> Head {
        Head {
            t,
            up,
            boot: self.boot.clone(),
            fl: self.credit.at(t, up, synced),
        }
    }

    fn event(&mut self, now: Instant, head: Head, k: Kind, body: Body) {
        let e = Event { k, head, body };
        self.rec.record(now, &e.to_payload());
    }

    fn begin_boot(&mut self, now: Instant, head: &Head, synced: bool) {
        if self.booted || !self.rec.ready(now) {
            return;
        }
        self.booted = true;
        let past = record::history(&self.rec.entries());
        if !self.boot.is_empty() && past.iter().any(|p| p.boot == self.boot) {
            return;
        }
        let (last, unsafe_) = cause::evidence(&past, &self.boot, &self.smart);
        let pending = watch_pending(&self.src.watch_state);
        let (prev, why) = cause::classify(last, pending, unsafe_);
        if !worth_a_warning(prev) {
            tracing::info!(previous_boot = ?prev, why, ?last, watch_pending = pending, ?unsafe_, "how the last boot ended");
        } else {
            tracing::warn!(previous_boot = ?prev, why, ?last, watch_pending = pending, ?unsafe_, "how the last boot ended");
        }
        let body = Body::Boot {
            prev,
            why,
            src: clock::source(self.stepped_by, synced),
            sy: synced,
            floor: self.floor,
            step: self.stepped_by,
        };
        self.event(now, head.clone(), Kind::Boot, body);
        for s in self.smart.clone() {
            self.event(now, head.clone(), Kind::Nvme, Body::Nvme(s));
        }
    }

    fn publish(&mut self, now: Instant, head: &Head, synced: bool) {
        if self.rec.ring.is_none() {
            return;
        }
        let q = clock::Quality {
            boot: self.boot.clone(),
            source: clock::source(self.stepped_by, synced),
            synced,
            floor: self.floor,
            stepped_by: self.stepped_by,
        };
        if self.published.as_ref() == Some(&q) {
            return;
        }
        let bytes = serde_json::to_vec(&q).unwrap_or_default();
        if let Err(e) = edge_common::durable_write(&self.src.time_file, &bytes) {
            tracing::warn!(error = %e, file = %self.src.time_file.display(), "could not publish the time quality");
        }
        if self.published.is_some() {
            tracing::info!(source = ?q.source, synced, "time quality changed");
            let body = Body::Time {
                src: q.source,
                sy: synced,
            };
            self.event(now, head.clone(), Kind::Time, body);
        }
        self.published = Some(q);
    }

    fn tick(&mut self, now: Instant, t: u64, synced: bool) {
        let up = sample::uptime_secs(&self.src.proc_dir);
        let head = self.head(t, up, synced);
        self.begin_boot(now, &head, synced);
        self.publish(now, &head, synced);
        if now >= self.next_hwmon {
            self.temps = sample::hwmon(&self.src.sys_dir);
            self.next_hwmon = now + HWMON_EVERY;
        }
        while let Some(done) = self.swept.as_ref().and_then(|rx| rx.try_recv().ok()) {
            let body = Body::Cri {
                ctr: done.containers.len() as u32,
                sbx: done.sandboxes.len() as u32,
                ahead: done.ahead_secs,
            };
            self.event(now, head.clone(), Kind::Cri, body);
        }
        let mut s = sample::take(&self.src.proc_dir, t, failing_checks(&self.src.watch_state));
        s.fl = head.fl;
        s.sy = synced;
        s.temp = self.temps.clone();
        self.rec.record(now, &sample::to_payload(&s, ring::PAYLOAD));
        if now >= self.next_smart {
            self.next_smart = now + SMART_EVERY;
            for s in (self.read_smart)(&self.src.dev_dir) {
                self.event(now, head.clone(), Kind::Nvme, Body::Nvme(s));
            }
        }
    }

    fn stop(&mut self, now: Instant, t: u64, synced: bool) {
        let up = sample::uptime_secs(&self.src.proc_dir);
        let head = self.head(t, up, synced);
        self.event(now, head, Kind::Stop, Body::Stop {});
    }

    fn release(&mut self, now: Instant, t: u64, synced: bool) {
        self.stop(now, t, synced);
        self.rec.ring = None;
    }
}

fn worth_a_warning(prev: cause::Cause) -> bool {
    prev != cause::Cause::Clean
}

fn wall() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A clock behind the floor is left for the host's time sync to step from the
/// NTP answer, so the host sees a time change; failing that within `wait`, it is
/// set directly.
fn reach_floor(
    clock: &dyn ntp::Clock,
    floor: ntp::Floor,
    served: Option<&AtomicU64>,
    wait: Duration,
    set: impl Fn(Duration) -> nix::Result<()>,
    unsync: impl Fn() -> nix::Result<()>,
) -> u64 {
    let was = clock.wall();
    let fl = floor.now(clock);
    if !ntp::behind(was, fl) {
        tracing::info!(
            now = was.as_secs(),
            floor = fl.as_secs(),
            "the clock is at or past the floor"
        );
        return 0;
    }
    let by = (fl - was).as_secs();
    let (was, fl_s) = (was.as_secs(), fl.as_secs());
    if let Some(served) = served {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if !ntp::behind(clock.wall(), floor.now(clock)) {
                if served.load(Ordering::SeqCst) == 0 {
                    tracing::info!(
                        was,
                        floor = fl_s,
                        "the clock was behind the floor; time sync moved it past"
                    );
                    return by;
                }
                if let Err(e) = unsync() {
                    tracing::warn!(error = %e, "could not mark the clock unsynchronised");
                }
                tracing::warn!(
                    was,
                    floor = fl_s,
                    stepped_by = by,
                    "the clock was behind the floor; time sync stepped it forward from edge-scope's answer"
                );
                return by;
            }
            if edge_common::sleep(Duration::from_millis(50)) {
                return 0;
            }
        }
    }
    match set(floor.now(clock)) {
        Ok(()) => {
            tracing::warn!(
                was,
                floor = fl_s,
                stepped_by = by,
                "the clock was behind the floor and time sync did not take it; set it directly"
            );
            by
        }
        Err(e) => {
            tracing::error!(error = %e, was, floor = fl_s, "the clock is behind the floor and could not be set");
            0
        }
    }
}

fn past_marks(path: &Path) -> Vec<clock::Mark> {
    match ring::Ring::open_read_only(path).and_then(|mut r| r.read_all()) {
        Ok(all) => record::marks(&record::history(&all)),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "no ring to take a clock floor from; using the build time");
            Vec::new()
        }
    }
}

fn main() -> anyhow::Result<()> {
    edge_common::init_tracing();

    let path: PathBuf = std::env::var("EDGE_SCOPE_RING")
        .unwrap_or_else(|_| "/var/lib/edge-scope/ring.bin".into())
        .into();

    let logs_dir = path.with_file_name("logs");
    let services_ring = path.with_file_name(services::FILE);

    if std::env::args().nth(1).as_deref() == Some("dump") {
        return dump(
            &path,
            &services_ring,
            &logs_dir,
            &mut std::io::stdout().lock(),
        );
    }
    // Before the ring is read and the sandbox grants its directory.
    edge_common::mount::await_evidence_volume();

    let slots = env_or_default(
        "EDGE_SCOPE_SLOTS",
        std::env::var("EDGE_SCOPE_SLOTS").ok().as_deref(),
        DEFAULT_SLOTS,
        1,
        MAX_SLOTS,
    );
    let interval = Duration::from_secs(env_or_default(
        "EDGE_SCOPE_INTERVAL",
        std::env::var("EDGE_SCOPE_INTERVAL").ok().as_deref(),
        1,
        1,
        3600,
    ));
    let var = |name: &str, default: &str| -> PathBuf {
        std::env::var(name)
            .unwrap_or_else(|_| default.into())
            .into()
    };
    let src = Sources {
        proc_dir: var("EDGE_SCOPE_PROC", "/proc"),
        sys_dir: var("EDGE_SCOPE_SYS", "/sys"),
        dev_dir: var("EDGE_SCOPE_DEV", "/dev"),
        watch_state: var("EDGE_WATCH_STATE", "/var/lib/edge-watch"),
        time_file: std::env::var("EDGE_SCOPE_TIME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| path.with_file_name("time.json")),
    };
    let cri_sock = var("EDGE_SCOPE_CRI", "/run/containerd/containerd.sock");
    let machined = var("EDGE_SCOPE_MACHINED", "/system/run/machined/machine.sock");
    edge_common::sandbox::restrict(&edge_common::sandbox::scope(edge_common::sandbox::Scope {
        ring: &path,
        time_file: &src.time_file,
        proc_dir: &src.proc_dir,
        sys_dir: &src.sys_dir,
        dev_dir: &src.dev_dir,
        watch_state: &src.watch_state,
        cri_socket: &cri_sock,
        machined_socket: &machined,
    }));

    if let Err(e) = edge_common::install() {
        tracing::warn!(error = %e, "could not install the SIGTERM handler");
    }

    let boot = sample::boot_id(&src.proc_dir);
    // Before the slow start steps: the sender drops lines until something listens.
    let logs_addr = std::env::var("EDGE_SCOPE_LOGS").unwrap_or_else(|_| "127.0.0.1:6051".into());
    let logs = match logs::spawn(&logs_addr, logs_dir, boot.clone()) {
        Ok(l) => {
            tracing::info!(addr = %l.addr, "keeping Talos service and kernel logs");
            Some(l)
        }
        Err(e) => {
            tracing::error!(error = %e, addr = logs_addr, "cannot receive Talos logs");
            None
        }
    };
    let up = sample::uptime_secs(&src.proc_dir);
    let build = clock::build_epoch(std::env::var("EDGE_SCOPE_BUILD_EPOCH").ok().as_deref());
    let floor = clock::floor(build, &past_marks(&path), &boot, up);
    let carried = ntp::Floor::new(floor, up);
    let sys: Arc<dyn ntp::Clock> = Arc::new(ntp::System);
    let ntp_addr = std::env::var("EDGE_SCOPE_NTP").unwrap_or_else(|_| "127.0.0.1:123".into());
    let server = match ntp::spawn(&ntp_addr, carried, sys.clone()) {
        Ok(s) => {
            tracing::info!(addr = %s.addr, "answering NTP with the floor whenever the clock is behind it");
            Some(s)
        }
        Err(e) => {
            tracing::warn!(error = %e, addr = ntp_addr, "cannot answer NTP; a clock behind the floor is set directly");
            None
        }
    };
    let stepped_by = reach_floor(
        sys.as_ref(),
        carried,
        server.as_ref().map(|s| s.served.as_ref()),
        TAKE_FLOOR_WITHIN,
        clock::set,
        clock::mark_unsynced,
    );

    let (tx, rx) = std::sync::mpsc::channel();
    let swept = match cri::spawn(cri_sock, tx) {
        Ok(()) => Some(rx),
        Err(e) => {
            tracing::error!(error = %e, "cannot start the CRI sweep");
            None
        }
    };

    let (tx, going_down) = std::sync::mpsc::channel();
    let transitions = services::Store::new(services_ring, boot.clone());
    if let Err(e) = shutdown::spawn(machined, transitions, tx) {
        tracing::error!(error = %e, "cannot watch machined; the ring stays open to the end");
    }

    let start = Instant::now();
    let mut scope = Scope {
        rec: Recorder::new(
            path,
            slots,
            Duration::from_secs(30),
            Duration::from_secs(60),
        ),
        boot,
        credit: clock::Credit::new(floor, up),
        floor,
        stepped_by,
        smart: nvme::read_all(&src.dev_dir),
        read_smart: nvme::read_all,
        src,
        booted: false,
        published: None,
        temps: Default::default(),
        next_hwmon: start,
        next_smart: start + SMART_EVERY,
        swept,
    };

    loop {
        if let Ok(sequence) = going_down.try_recv() {
            scope.release(Instant::now(), wall(), clock::synced());
            if let Some(l) = &logs {
                l.close();
            }
            tracing::info!(sequence, "the unit is going down; recording stopped");
            while !edge_common::sleep(Duration::from_secs(3600)) {}
            return Ok(());
        }
        scope.tick(Instant::now(), wall(), clock::synced());
        if edge_common::sleep(interval) {
            scope.stop(Instant::now(), wall(), clock::synced());
            if let Some(l) = &logs {
                l.flush_all();
            }
            tracing::info!("SIGTERM: edge-scope exiting");
            return Ok(());
        }
    }
}

fn watch_state(state_dir: &Path) -> Option<edge_common::watch_state::State> {
    std::fs::read_to_string(state_dir.join("state.json"))
        .ok()
        .and_then(|t| edge_common::watch_state::State::parse(&t).ok())
}

/// The state file, not an API: this matters most when nothing is answering.
fn failing_checks(state_dir: &Path) -> Vec<String> {
    watch_state(state_dir)
        .map(|st| st.failing_now().to_vec())
        .unwrap_or_default()
}

/// Read before edge-watch folds it at its own start.
fn watch_pending(state_dir: &Path) -> bool {
    watch_state(state_dir).is_some_and(|st| st.reset_pending)
}

fn dump(path: &Path, services: &Path, logs_dir: &Path, out: &mut impl Write) -> anyhow::Result<()> {
    let mut all = ring::Ring::open_read_only(path)?.read_all()?;
    match ring::Ring::open_read_only_with(services, services::RECORD_SIZE)
        .and_then(|mut r| r.read_all())
    {
        Ok(entries) => all.extend(entries),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{}: {e:#}", services.display());
        }
    }
    all.extend(logs::read_all(logs_dir));
    match write_records(out, &all) {
        Ok(()) => {}
        // `edge-scope dump | head`
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    let _ = writeln!(std::io::stderr(), "{} record(s)", all.len());
    Ok(())
}

fn write_records(out: &mut impl Write, all: &[ring::Entry]) -> std::io::Result<()> {
    for e in all {
        let text = String::from_utf8_lossy(&e.payload);
        writeln!(out, "{}", text.trim_end_matches('\0'))?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_env_value_uses_default() {
        let slots = |v| env_or_default("EDGE_SCOPE_SLOTS", v, DEFAULT_SLOTS, 1, MAX_SLOTS);
        assert_eq!(slots(None), 900);
        assert_eq!(slots(Some(" 64 ")), 64);
        assert_eq!(slots(Some("1")), 1);
        assert_eq!(slots(Some("1000000")), 1_000_000);
        for bad in [
            "9OO",
            "",
            "-1",
            "1.5",
            "0",
            "99999999999999999999",
            "1000001",
        ] {
            assert_eq!(slots(Some(bad)), DEFAULT_SLOTS, "{bad}");
        }
    }

    fn payloads(p: &Path) -> Vec<String> {
        ring::Ring::open_read_only(p)
            .unwrap()
            .read_all()
            .unwrap()
            .iter()
            .map(|e| {
                String::from_utf8_lossy(&e.payload)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn recorder_recovers_from_bad_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("state/ring.bin");
        std::fs::write(d.join("state"), b"a file, not a directory").unwrap();
        let mut rec = Recorder::new(p.clone(), 4, Duration::ZERO, Duration::ZERO);
        let t = Instant::now();
        rec.open(t);
        rec.record(t, b"{\"t\":1}");
        assert_eq!(payloads(&p), ["{\"t\":1}"]);
        assert_eq!(
            std::fs::read(d.join("state.corrupt")).unwrap(),
            b"a file, not a directory"
        );

        std::fs::remove_file(&p).unwrap();
        rec.record(t, b"{\"t\":2}");
        assert_eq!(payloads(&p), ["{\"t\":2}"]);

        let q = d.join("state2/ring.bin");
        std::fs::create_dir_all(q.join("junk")).unwrap();
        let mut rec2 = Recorder::new(q.clone(), 4, Duration::ZERO, Duration::ZERO);
        rec2.open(t);
        rec2.record(t, b"{\"t\":9}");
        let got = payloads(&q);
        assert_eq!(got.len(), 2);
        assert!(got[0].contains("ring recreated"), "{}", got[0]);
    }

    #[test]
    fn failed_open_retried_on_schedule() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("ring.bin");
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut rec = Recorder::new(
            p.clone(),
            4,
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        let t = Instant::now();
        rec.open(t);
        if unsafe { nix::libc::geteuid() } != 0 {
            assert!(rec.ring.is_none());
            rec.record(t, b"{}");
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
            rec.record(t + Duration::from_secs(5), b"{}");
            assert!(rec.ring.is_none(), "retried early");
            rec.record(t + Duration::from_secs(10), b"{\"t\":3}");
            assert_eq!(payloads(&p), ["{\"t\":3}"]);
        }
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn append_failures_reopen_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("ring.bin");
        let mut rec = Recorder::new(
            p.clone(),
            4,
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        let t = Instant::now();
        rec.open(t);
        let too_big = vec![b'x'; ring::PAYLOAD + 1];
        for _ in 1..REOPEN_AFTER {
            rec.record(t, &too_big);
            assert!(rec.ring.is_some());
        }
        rec.record(t, &too_big);
        assert!(rec.ring.is_none());
        rec.record(t + Duration::from_secs(9), b"{}");
        assert!(rec.ring.is_none());
        rec.record(t + Duration::from_secs(10), b"{\"t\":4}");
        assert_eq!(payloads(&p), ["{\"t\":4}"]);
    }

    struct Refuses(std::io::ErrorKind);
    impl Write for Refuses {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn dump_prints_lines_and_ignores_epipe() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let p = d.join("ring.bin");
        let logs_dir = d.join("logs");
        let svc = d.join(services::FILE);
        assert!(
            dump(&p, &svc, &logs_dir, &mut Vec::new()).is_err(),
            "no ring"
        );
        {
            let mut r = ring::Ring::open(&p, 4).unwrap();
            r.append(b"{\"t\":1}").unwrap();
            r.append(b"{\"t\":2}").unwrap();
        }
        let mut out = Vec::new();
        dump(&p, &svc, &logs_dir, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "{\"t\":1}\n{\"t\":2}\n");
        ring::Ring::open_with(&svc, 4, services::RECORD_SIZE)
            .unwrap()
            .append(b"{\"k\":\"svc\"}")
            .unwrap();
        for (source, line) in [
            ("kubelet", "{\"k\":\"log\",\"src\":\"kubelet\"}"),
            ("kernel", "{\"k\":\"log\",\"src\":\"kernel\"}"),
        ] {
            ring::Ring::open_with(
                &logs_dir.join(format!("{source}.bin")),
                4,
                logs::RECORD_SIZE,
            )
            .unwrap()
            .append(line.as_bytes())
            .unwrap();
        }
        let mut out = Vec::new();
        dump(&p, &svc, &logs_dir, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"t\":1}\n{\"t\":2}\n{\"k\":\"svc\"}\n{\"k\":\"log\",\"src\":\"kernel\"}\n{\"k\":\"log\",\"src\":\"kubelet\"}\n"
        );
        dump(
            &p,
            &svc,
            &logs_dir,
            &mut Refuses(std::io::ErrorKind::BrokenPipe),
        )
        .unwrap();
        assert!(dump(&p, &svc, &logs_dir, &mut Refuses(std::io::ErrorKind::Other)).is_err());
    }

    #[test]
    fn failing_checks_from_watch_state() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let st = edge_common::watch_state::State {
            consecutive_resets: 1,
            reset_pending: true,
            last_failure: vec!["meridian".into(), "telemetry".into()],
            last_failure_at: Some("epoch:1".into()),
            ..Default::default()
        };
        let mut text = serde_json::to_string_pretty(&st).unwrap();
        text.push_str(&" ".repeat(600));
        std::fs::write(d.join("state.json"), text).unwrap();
        assert_eq!(failing_checks(d), ["meridian", "telemetry"]);

        let calm = edge_common::watch_state::State {
            reset_pending: false,
            ..st
        };
        std::fs::write(d.join("state.json"), serde_json::to_string(&calm).unwrap()).unwrap();
        assert!(failing_checks(d).is_empty());
        std::fs::write(d.join("state.json"), "not json").unwrap();
        assert!(failing_checks(d).is_empty());
    }

    fn scope_in(d: &Path, boot: &str, up: u64, floor: u64, stepped_by: u64) -> Scope {
        let proc_dir = d.join("proc");
        std::fs::create_dir_all(proc_dir.join("sys/kernel/random")).unwrap();
        std::fs::write(proc_dir.join("uptime"), format!("{up}.50 1.00\n")).unwrap();
        std::fs::write(
            proc_dir.join("sys/kernel/random/boot_id"),
            format!("{boot}-0000-0000\n"),
        )
        .unwrap();
        let t = Instant::now();
        Scope {
            rec: Recorder::new(
                d.join("ring.bin"),
                64,
                Duration::ZERO,
                Duration::from_secs(60),
            ),
            src: Sources {
                proc_dir,
                sys_dir: d.join("sys"),
                dev_dir: d.join("dev"),
                watch_state: d.join("watch"),
                time_file: d.join("time.json"),
            },
            boot: boot.into(),
            credit: clock::Credit::new(floor, up),
            floor,
            stepped_by,
            smart: vec![],
            read_smart: |_| vec![],
            booted: false,
            published: None,
            temps: Default::default(),
            next_hwmon: t,
            next_smart: t + SMART_EVERY,
            swept: None,
        }
    }

    fn set_up(d: &Path, up: u64) {
        std::fs::write(d.join("proc/uptime"), format!("{up}.00 1.00\n")).unwrap();
    }

    fn records(d: &Path) -> Vec<serde_json::Value> {
        payloads(&d.join("ring.bin"))
            .iter()
            .map(|p| serde_json::from_str(p).unwrap())
            .collect()
    }

    fn boot_records(d: &Path, boot: &str) -> Vec<serde_json::Value> {
        records(d)
            .into_iter()
            .filter(|r| r["k"] == "boot" && r["boot"] == boot)
            .collect()
    }

    fn watch(d: &Path, pending: bool, failing: &[&str]) {
        std::fs::create_dir_all(d.join("watch")).unwrap();
        let st = edge_common::watch_state::State {
            reset_pending: pending,
            last_failure: failing.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        std::fs::write(d.join("watch/state.json"), serde_json::to_vec(&st).unwrap()).unwrap();
    }

    fn previous_boot(d: &Path, end: &str) {
        let mut s = scope_in(d, "aaaaaaaa", 20, 1_000, 0);
        for i in 0..3 {
            s.tick(Instant::now(), 1_000 + i, false);
        }
        match end {
            "stop" => s.stop(Instant::now(), 1_003, false),
            "release" => s.release(Instant::now(), 1_003, false),
            "watchdog" => {
                watch(d, true, &["meridian"]);
                s.tick(Instant::now(), 1_004, false);
            }
            _ => {}
        }
    }

    #[test]
    fn boot_end_recorded_next_boot() {
        for (end, pending_at_boot, want) in [
            ("stop", false, "clean"),
            ("release", false, "clean"),
            ("cut", false, "power-cut"),
            ("watchdog", true, "watchdog-reset"),
            // edge-watch already folded its record; the ring still says it.
            ("watchdog", false, "watchdog-reset"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let d = tmp.path();
            previous_boot(d, end);
            watch(d, pending_at_boot, &[]);
            let before = records(d).len();
            let mut s = scope_in(d, "bbbbbbbb", 5, 2_000, 0);
            s.tick(Instant::now(), 2_000, false);
            let all = records(d);
            let first = &all[before];
            assert_eq!(first["k"], "boot", "{end}: {first}");
            assert_eq!(first["prev"], want, "{end}/{pending_at_boot}: {first}");
            assert_eq!(first["boot"], "bbbbbbbb");
        }
    }

    #[test]
    fn release_closes_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let open_in = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .flatten()
                .filter(|e| std::fs::read_link(e.path()).is_ok_and(|t| t.starts_with(d)))
                .count()
        };
        let mut s = scope_in(d, "aaaaaaaa", 20, 1_000, 0);
        s.tick(Instant::now(), 1_000, false);
        assert!(open_in() > 0);
        s.release(Instant::now(), 1_001, false);
        assert_eq!(open_in(), 0);
        assert_eq!(records(d).last().unwrap()["k"], "stop");
    }

    #[test]
    fn smart_and_temps_on_schedule() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let hw = d.join("sys/class/hwmon/hwmon0");
        std::fs::create_dir_all(&hw).unwrap();
        std::fs::write(hw.join("name"), "coretemp").unwrap();
        std::fs::write(hw.join("temp1_input"), "40000").unwrap();
        let mut s = scope_in(d, "bbbbbbbb", 5, 2_000, 0);
        s.smart = vec![nvme::Smart {
            dev: "nvme0".into(),
            unsafe_shutdowns: 3,
            ..Default::default()
        }];
        s.read_smart = |_| {
            vec![nvme::Smart {
                dev: "nvme0".into(),
                unsafe_shutdowns: 3,
                temp_c: 61,
                ..Default::default()
            }]
        };
        let t0 = Instant::now();
        s.next_hwmon = t0;
        s.next_smart = t0 + SMART_EVERY;
        let at = |secs| t0 + Duration::from_secs(secs);
        let temps = |d: &Path| -> Vec<Option<u64>> {
            records(d)
                .iter()
                .filter(|r| r.get("k").is_none())
                .map(|r| r["temp"]["coretemp"].as_u64())
                .collect()
        };
        let smart = |d: &Path| -> Vec<Option<u64>> {
            records(d)
                .iter()
                .filter(|r| r["k"] == "nvme")
                .map(|r| r["temp"].as_u64())
                .collect()
        };

        s.tick(at(0), 2_000, false);
        assert_eq!(
            smart(d),
            [Some(0)],
            "the boot reading, with the boot record"
        );
        std::fs::write(hw.join("temp1_input"), "70000").unwrap();
        s.tick(at(9), 2_009, false);
        s.tick(at(10), 2_010, false);
        assert_eq!(temps(d), [Some(40), Some(40), Some(70)]);

        s.tick(at(599), 2_599, false);
        assert_eq!(smart(d).len(), 1);
        s.tick(at(600), 2_600, false);
        s.tick(at(601), 2_601, false);
        assert_eq!(smart(d), [Some(0), Some(61)]);
        s.tick(at(1_200), 3_200, false);
        assert_eq!(smart(d).len(), 3);
    }

    #[test]
    fn unclean_boot_warns() {
        use cause::Cause::*;
        assert!(!worth_a_warning(Clean));
        for c in [PowerCut, WatchdogReset, Unknown] {
            assert!(worth_a_warning(c), "{c:?}");
        }
    }

    #[test]
    fn restart_does_not_reclassify() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        previous_boot(d, "stop");
        let mut s = scope_in(d, "bbbbbbbb", 5, 2_000, 0);
        s.tick(Instant::now(), 2_000, false);
        s.stop(Instant::now(), 2_001, false);
        drop(s);
        let mut again = scope_in(d, "bbbbbbbb", 9, 2_000, 0);
        again.tick(Instant::now(), 2_004, false);
        assert_eq!(boot_records(d, "bbbbbbbb").len(), 1);
        assert_eq!(boot_records(d, "bbbbbbbb")[0]["prev"], "clean");
    }

    #[test]
    fn writes_only_while_holding_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        previous_boot(d, "cut");
        std::fs::remove_file(d.join("time.json")).unwrap();
        let holder = ring::Ring::open(&d.join("ring.bin"), 64).unwrap();
        let mut s = scope_in(d, "bbbbbbbb", 5, 2_000, 0);
        s.rec.retry_every = Duration::from_secs(30);
        let t = Instant::now();
        s.tick(t, 2_000, false);
        assert!(boot_records(d, "bbbbbbbb").is_empty());
        assert!(!d.join("time.json").exists(), "only the holder publishes");
        drop(holder);
        s.tick(t + Duration::from_secs(30), 2_030, false);
        let b = boot_records(d, "bbbbbbbb");
        assert_eq!((b.len(), b[0]["prev"].as_str()), (1, Some("power-cut")));
        assert!(d.join("time.json").exists());
    }

    #[test]
    fn time_quality_published_on_change() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let mut s = scope_in(d, "bbbbbbbb", 5, 2_000, 700);
        let read = |d: &Path| -> clock::Quality {
            serde_json::from_slice(&std::fs::read(d.join("time.json")).unwrap()).unwrap()
        };
        s.tick(Instant::now(), 2_000, false);
        let q = read(d);
        assert_eq!(
            q,
            clock::Quality {
                boot: "bbbbbbbb".into(),
                source: clock::Source::Floor,
                synced: false,
                floor: 2_000,
                stepped_by: 700,
            }
        );
        let b = &boot_records(d, "bbbbbbbb")[0];
        assert_eq!(
            (b["src"].as_str(), b["sy"].as_bool(), b["step"].as_u64()),
            (Some("floor"), Some(false), Some(700))
        );

        std::fs::write(d.join("time.json"), b"sentinel").unwrap();
        s.tick(Instant::now(), 2_001, false);
        assert_eq!(
            std::fs::read(d.join("time.json")).unwrap(),
            b"sentinel",
            "unchanged is not rewritten"
        );

        s.tick(Instant::now(), 2_002, true);
        let q = read(d);
        assert_eq!((q.source, q.synced), (clock::Source::Ntp, true));
        let times: Vec<_> = records(d)
            .into_iter()
            .filter(|r| r["k"] == "time")
            .collect();
        assert_eq!(times.len(), 1);
        assert_eq!(
            (times[0]["src"].as_str(), times[0]["sy"].as_bool()),
            (Some("ntp"), Some(true))
        );
    }

    #[test]
    fn samples_carry_next_floor() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let far = 4_000_000_000;
        let mut s = scope_in(d, "aaaaaaaa", 10, 2_000, 0);
        s.tick(Instant::now(), far, false);
        set_up(d, 70);
        s.tick(Instant::now(), far + 60, false);
        let last = records(d)
            .into_iter()
            .rev()
            .find(|r| r.get("k").is_none())
            .unwrap();
        assert_eq!(
            (last["t"].as_u64(), last["fl"].as_u64()),
            (Some(far + 60), Some(2_060))
        );
        assert!(last.get("sy").is_none());

        set_up(d, 3);
        let marks = past_marks(&d.join("ring.bin"));
        assert_eq!(clock::floor(0, &marks, "bbbbbbbb", 3), 2_063);

        set_up(d, 80);
        s.tick(Instant::now(), 5_000, true);
        let synced = records(d)
            .into_iter()
            .rev()
            .find(|r| r.get("k").is_none())
            .unwrap();
        assert_eq!(
            (synced["fl"].as_u64(), synced["sy"].as_bool()),
            (Some(5_000), Some(true))
        );
    }

    #[test]
    fn bad_ring_gives_no_marks() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        assert!(past_marks(&d.join("ring.bin")).is_empty());
        std::fs::write(d.join("ring.bin"), vec![0xAB; 4 * ring::RECORD_SIZE]).unwrap();
        assert!(past_marks(&d.join("ring.bin")).is_empty());
    }

    #[test]
    fn bad_watch_record_not_pending() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        assert!(!watch_pending(&d.join("watch")));
        watch(d, true, &[]);
        assert!(watch_pending(&d.join("watch")));
        std::fs::write(d.join("watch/state.json"), "{\"reset_pending\":tr").unwrap();
        assert!(!watch_pending(&d.join("watch")));
    }

    mod reach {
        use super::*;
        use crate::ntp::Clock;
        use crate::ntp::tests::{Fake, client_offset, request};
        use std::net::UdpSocket;
        use std::sync::Mutex;

        const FLOOR: u64 = 1_790_537_906;
        const YEAR: u64 = 31_536_000;

        struct Calls {
            set: Mutex<Vec<u64>>,
            unsync: AtomicU64,
        }

        fn calls() -> Arc<Calls> {
            Arc::new(Calls {
                set: Mutex::new(vec![]),
                unsync: AtomicU64::new(0),
            })
        }

        fn run(c: &Arc<Fake>, served: Option<&AtomicU64>, wait: Duration, k: &Arc<Calls>) -> u64 {
            let (k1, k2, c1) = (k.clone(), k.clone(), c.clone());
            reach_floor(
                c.as_ref(),
                ntp::Floor::new(FLOOR, 3),
                served,
                wait,
                move |to| {
                    k1.set.lock().unwrap().push(to.as_secs());
                    *c1.wall.lock().unwrap() = to;
                    Ok(())
                },
                move || {
                    k2.unsync.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
        }

        #[test]
        fn clock_past_floor_untouched() {
            for wall in [FLOOR - 1, FLOOR, FLOOR + YEAR] {
                let (c, k) = (Fake::new(wall, 3), calls());
                let served = AtomicU64::new(0);
                assert_eq!(
                    run(&c, Some(&served), Duration::from_secs(5), &k),
                    0,
                    "{wall}"
                );
                assert!(k.set.lock().unwrap().is_empty());
                assert_eq!(k.unsync.load(Ordering::SeqCst), 0);
            }
        }

        #[test]
        fn no_server_sets_floor() {
            let (c, k) = (Fake::new(FLOOR - YEAR, 3), calls());
            c.pass(Duration::from_secs(4));
            assert_eq!(run(&c, None, Duration::from_secs(5), &k), YEAR);
            assert_eq!(*k.set.lock().unwrap(), [FLOOR + 4]);
        }

        #[test]
        fn untaken_floor_set_after_wait() {
            let (c, k) = (Fake::new(FLOOR - YEAR, 3), calls());
            let served = AtomicU64::new(0);
            let t = Instant::now();
            assert_eq!(run(&c, Some(&served), Duration::from_millis(300), &k), YEAR);
            assert!(t.elapsed() >= Duration::from_millis(300));
            assert_eq!(*k.set.lock().unwrap(), [FLOOR]);
            assert_eq!(k.unsync.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn other_source_not_marked_unsynced() {
            let (c, k) = (Fake::new(FLOOR - YEAR, 3), calls());
            let served = AtomicU64::new(0);
            let c2 = c.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                c2.step(Duration::from_secs(YEAR + 3600));
            });
            assert_eq!(run(&c, Some(&served), Duration::from_secs(10), &k), YEAR);
            assert!(k.set.lock().unwrap().is_empty());
            assert_eq!(k.unsync.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn client_takes_floor_over_udp() {
            let (c, k) = (Fake::new(FLOOR - YEAR, 3), calls());
            let server = ntp::spawn("127.0.0.1:0", ntp::Floor::new(FLOOR, 3), c.clone()).unwrap();
            let (c2, addr) = (c.clone(), server.addr);
            let client = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let req = request(42);
                let sent = c2.wall().as_secs_f64();
                sock.send_to(&req, addr).unwrap();
                let mut buf = [0u8; 512];
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let off = client_offset(&req, &buf[..n], sent, c2.wall().as_secs_f64()).unwrap();
                c2.step(Duration::from_secs_f64(off));
                off
            });
            let by = run(&c, Some(&server.served), Duration::from_secs(10), &k);
            let off = client.join().unwrap();
            assert!((off - YEAR as f64).abs() < 1.0, "{off}");
            assert_eq!(by, YEAR);
            assert!(
                k.set.lock().unwrap().is_empty(),
                "the client stepped it, not edge-scope"
            );
            assert_eq!(k.unsync.load(Ordering::SeqCst), 1);
            assert_eq!(server.served.load(Ordering::SeqCst), 1);
        }
    }
}
