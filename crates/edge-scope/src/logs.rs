//! One ring per source, so a chatty service overwrites only its own history.
//! Nothing here logs per datagram: edge-scope's own output comes back as a source.

use std::collections::{BTreeMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::logline::{self, Line};
use crate::ring::Ring;

pub const RECORD_SIZE: usize = 512;
pub const SLOTS: u64 = 1024;
/// Several boots: one boot's kernel log alone is most of `SLOTS`.
pub const KERNEL_SLOTS: u64 = 4096;
pub const MAX_SOURCES: usize = 32;
/// A client retrying two servers alternates two lines forever.
const RECENT_SHAPES: usize = 2;
const REPEAT_PERIOD: Duration = Duration::from_secs(60);
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const WARN_EVERY: Duration = Duration::from_secs(60);
/// Room for the sender's backlog replay at boot while a flush is syncing.
const RECEIVE_BUFFER: usize = 4 << 20;
const PAYLOAD: usize = RECORD_SIZE - crate::ring::HEADER;
/// One slot short of the ring, so a flush's dropped-lines note is kept too.
const QUEUE: usize = SLOTS as usize - 1;

#[derive(Default)]
pub struct Pending {
    queues: BTreeMap<String, Queue>,
    refused: u64,
    unparsed: u64,
}

#[derive(Default)]
struct Queue {
    lines: VecDeque<Vec<u8>>,
    dropped: u64,
    recent: VecDeque<Run>,
}

/// Lines that differ only in their numbers (times, ports, counters) repeat.
struct Run {
    shape: Vec<u8>,
    last: Vec<u8>,
    repeats: u64,
    since: Instant,
}

fn shape(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    for &b in payload {
        if !b.is_ascii_digit() {
            out.push(b);
        } else if out.last() != Some(&b'#') {
            out.push(b'#');
        }
    }
    out
}

impl Queue {
    fn enqueue(&mut self, payload: Vec<u8>) {
        if self.lines.len() >= QUEUE {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(payload);
    }

    fn summarise(&mut self, now: Instant, due: impl Fn(&Run) -> bool) {
        for i in 0..self.recent.len() {
            let run = &mut self.recent[i];
            if run.repeats == 0 || !due(run) {
                continue;
            }
            let summary = logline::repeated(&run.last, run.repeats, PAYLOAD);
            (run.repeats, run.since) = (0, now);
            if let Some(summary) = summary {
                self.enqueue(summary);
            }
        }
    }
}

impl Pending {
    pub fn push(&mut self, line: Line, now: Instant) {
        if !self.queues.contains_key(&line.source) && self.queues.len() >= MAX_SOURCES {
            self.refused += 1;
            return;
        }
        let q = self.queues.entry(line.source).or_default();
        let shape = shape(&line.payload);
        if let Some(run) = q.recent.iter_mut().find(|r| r.shape == shape) {
            run.repeats += 1;
            run.last = line.payload;
            return;
        }
        q.summarise(now, |_| true);
        q.enqueue(line.payload);
        q.recent.push_back(Run {
            shape,
            last: Vec::new(),
            repeats: 0,
            since: now,
        });
        if q.recent.len() > RECENT_SHAPES {
            q.recent.pop_front();
        }
    }

    pub fn take(&mut self, now: Instant) -> Pending {
        let mut out = Pending {
            refused: std::mem::take(&mut self.refused),
            unparsed: std::mem::take(&mut self.unparsed),
            ..Pending::default()
        };
        for (source, q) in &mut self.queues {
            q.summarise(now, |r| {
                now.saturating_duration_since(r.since) >= REPEAT_PERIOD
            });
            if q.lines.is_empty() && q.dropped == 0 {
                continue;
            }
            let taken = Queue {
                lines: std::mem::take(&mut q.lines),
                dropped: std::mem::take(&mut q.dropped),
                recent: VecDeque::new(),
            };
            out.queues.insert(source.clone(), taken);
        }
        out
    }
}

pub struct Store {
    dir: PathBuf,
    boot: String,
    rings: BTreeMap<String, Ring>,
    lost: u64,
    unparsed: u64,
    reported: (u64, u64),
    next_warning: Instant,
    closed: bool,
}

fn ring_path(dir: &Path, source: &str) -> PathBuf {
    dir.join(format!("{source}.bin"))
}

fn ring_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    v.sort();
    v
}

impl Store {
    pub fn new(dir: PathBuf, boot: String) -> Self {
        Self {
            dir,
            boot,
            rings: BTreeMap::new(),
            lost: 0,
            unparsed: 0,
            reported: (0, 0),
            next_warning: Instant::now(),
            closed: false,
        }
    }

    fn note(&self, source: &str, fields: serde_json::Value) -> Vec<u8> {
        let mut rec = serde_json::json!({ "k": "log", "src": source, "boot": self.boot });
        if let (Some(r), Some(f)) = (rec.as_object_mut(), fields.as_object()) {
            r.extend(f.clone());
        }
        let mut b = serde_json::to_vec(&rec).unwrap_or_default();
        b.truncate(PAYLOAD);
        b
    }

    fn ring(&mut self, source: &str) -> Option<&mut Ring> {
        if !self.rings.contains_key(source) {
            let path = ring_path(&self.dir, source);
            if !path.exists() && ring_files(&self.dir).len() >= MAX_SOURCES {
                return None;
            }
            let slots = if source == "kernel" {
                KERNEL_SLOTS
            } else {
                SLOTS
            };
            let mut r = match Ring::open_with(&path, slots, RECORD_SIZE) {
                Ok(r) => r,
                Err(e) => {
                    self.warn(|| tracing::warn!(error = %format!("{e:#}"), source, "cannot open a log ring"));
                    return None;
                }
            };
            if let Some(why) = r.take_recovered() {
                let note = self.note(
                    source,
                    serde_json::json!({ "note": "ring recreated", "why": why }),
                );
                r.append(&note).ok();
            }
            self.rings.insert(source.to_string(), r);
        }
        self.rings.get_mut(source)
    }

    fn warn(&mut self, emit: impl FnOnce()) -> bool {
        let now = Instant::now();
        if now < self.next_warning {
            return false;
        }
        self.next_warning = now + WARN_EVERY;
        emit();
        true
    }

    pub fn write(&mut self, pending: Pending) {
        if self.closed {
            return;
        }
        self.lost += pending.refused;
        self.unparsed += pending.unparsed;
        for (source, q) in pending.queues {
            let mut batch = Vec::with_capacity(q.lines.len() + 1);
            if q.dropped > 0 {
                batch.push(self.note(&source, serde_json::json!({ "dropped": q.dropped })));
            }
            batch.extend(q.lines);
            let Some(ring) = self.ring(&source) else {
                self.lost += batch.len() as u64;
                continue;
            };
            if let Err(e) = ring.append_all(&batch) {
                self.rings.remove(&source);
                self.lost += batch.len() as u64;
                self.warn(
                    || tracing::warn!(error = %format!("{e:#}"), source, "cannot append log lines"),
                );
            }
        }
        let (lost, unparsed) = (self.lost, self.unparsed);
        if (lost, unparsed) != self.reported
            && self.warn(|| tracing::warn!(lost, unparsed, "log lines not kept since start"))
        {
            self.reported = (lost, unparsed);
        }
    }
}

pub struct Logs {
    pub addr: SocketAddr,
    pending: Arc<Mutex<Pending>>,
    store: Arc<Mutex<Store>>,
}

impl Logs {
    pub fn flush_all(&self) {
        flush(&self.pending, &self.store, Instant::now() + REPEAT_PERIOD);
    }

    pub fn close(&self) {
        self.flush_all();
        let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
        store.rings.clear();
        store.closed = true;
    }
}

fn flush(pending: &Mutex<Pending>, store: &Mutex<Store>, now: Instant) {
    let batch = pending.lock().unwrap_or_else(|p| p.into_inner()).take(now);
    store.lock().unwrap_or_else(|p| p.into_inner()).write(batch);
}

fn enlarge_receive_buffer(sock: &UdpSocket) {
    use nix::sys::socket::{setsockopt, sockopt};
    if setsockopt(sock, sockopt::RcvBufForce, &RECEIVE_BUFFER).is_err() {
        setsockopt(sock, sockopt::RcvBuf, &RECEIVE_BUFFER).ok();
    }
}

pub fn spawn(addr: &str, dir: PathBuf, boot: String) -> std::io::Result<Logs> {
    let sock = UdpSocket::bind(addr)?;
    enlarge_receive_buffer(&sock);
    let logs = Logs {
        addr: sock.local_addr()?,
        pending: Arc::default(),
        store: Arc::new(Mutex::new(Store::new(dir, boot.clone()))),
    };
    let pending = logs.pending.clone();
    std::thread::Builder::new()
        .name("logs-receive".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok(n) = sock.recv(&mut buf) else {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                };
                let line = logline::parse(&buf[..n], &boot, PAYLOAD);
                let mut p = pending.lock().unwrap_or_else(|p| p.into_inner());
                match line {
                    Some(l) => p.push(l, Instant::now()),
                    None => p.unparsed += 1,
                }
            }
        })?;
    let (pending, store) = (logs.pending.clone(), logs.store.clone());
    std::thread::Builder::new()
        .name("logs-flush".into())
        .spawn(move || {
            loop {
                std::thread::sleep(FLUSH_EVERY);
                flush(&pending, &store, Instant::now());
            }
        })?;
    Ok(logs)
}

pub fn read_all(dir: &Path) -> Vec<crate::ring::Entry> {
    let mut all = Vec::new();
    for path in ring_files(dir) {
        match Ring::open_read_only_with(&path, RECORD_SIZE).and_then(|mut r| r.read_all()) {
            Ok(entries) => all.extend(entries),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), ring = %path.display(), "cannot read a log ring")
            }
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("edge-scope-logs-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn line(source: &str, msg: &str) -> Line {
        let d = serde_json::json!({ "talos-service": source, "msg": msg, "talos-level": "info" });
        logline::parse(d.to_string().as_bytes(), "b", PAYLOAD).unwrap()
    }

    fn msgs(dir: &Path, source: &str) -> Vec<String> {
        Ring::open_read_only_with(&ring_path(dir, source), RECORD_SIZE)
            .unwrap()
            .read_all()
            .unwrap()
            .iter()
            .map(|e| {
                let v: serde_json::Value =
                    serde_json::from_slice(e.payload.split(|b| *b == 0).next().unwrap()).unwrap();
                match (v["msg"].as_str(), v["dropped"].as_u64()) {
                    (Some(m), _) => m.to_string(),
                    (None, Some(n)) => format!("dropped {n}"),
                    _ => v.to_string(),
                }
            })
            .collect()
    }

    fn nth(i: u64) -> String {
        i.to_string()
            .bytes()
            .map(|d| char::from(d - b'0' + b'a'))
            .collect()
    }

    fn taken(batch: &Pending, source: &str) -> Vec<(String, u64)> {
        let Some(q) = batch.queues.get(source) else {
            return Vec::new();
        };
        q.lines
            .iter()
            .map(|b| {
                let v: serde_json::Value = serde_json::from_slice(b).unwrap();
                (
                    v["msg"].as_str().unwrap().to_string(),
                    v["repeated"].as_u64().unwrap_or(0),
                )
            })
            .collect()
    }

    fn kernel(p: &mut Pending, now: Instant) -> Vec<(String, u64)> {
        taken(&p.take(now), "kernel")
    }

    fn want(lines: &[(&str, u64)]) -> Vec<(String, u64)> {
        lines.iter().map(|(m, n)| (m.to_string(), *n)).collect()
    }

    #[test]
    fn shape_masks_numbers() {
        assert_eq!(shape(b"at 2026-09-29 from :40000"), b"at #-#-# from :#");
        assert_ne!(shape(b"loop1 up"), shape(b"loop up"));
    }

    #[test]
    fn alternating_repeats_collapse() {
        let t = Instant::now();
        let mut p = Pending::default();
        for i in 0..50 {
            p.push(line("kernel", &format!("refused from :{i}")), t);
            p.push(line("kernel", &format!("bad stratum {i}")), t);
        }
        assert_eq!(
            kernel(&mut p, t),
            want(&[("refused from :0", 0), ("bad stratum 0", 0)])
        );
        p.push(line("kernel", "link up"), t);
        assert_eq!(
            kernel(&mut p, t),
            want(&[
                ("refused from :49", 49),
                ("bad stratum 49", 49),
                ("link up", 0)
            ])
        );
        p.push(line("kernel", "bad stratum 50"), t);
        assert!(
            !p.take(t).queues.contains_key("kernel"),
            "still recent, and no empty batch"
        );
    }

    #[test]
    fn long_run_summarised_each_period() {
        let t = Instant::now();
        let mut p = Pending::default();
        p.push(line("kernel", "error 1"), t);
        p.push(line("kernel", "error 2"), t);
        assert_eq!(kernel(&mut p, t), want(&[("error 1", 0)]));
        p.push(line("kernel", "error 3"), t + REPEAT_PERIOD);
        assert!(kernel(&mut p, t + REPEAT_PERIOD / 2).is_empty());
        assert_eq!(kernel(&mut p, t + REPEAT_PERIOD), want(&[("error 3", 2)]));
        p.push(line("kernel", "error 4"), t + REPEAT_PERIOD);
        assert!(kernel(&mut p, t + REPEAT_PERIOD * 3 / 2).is_empty());
        assert_eq!(
            kernel(&mut p, t + REPEAT_PERIOD * 2),
            want(&[("error 4", 1)])
        );
    }

    #[test]
    fn repeats_kept_per_source() {
        let t = Instant::now();
        let mut p = Pending::default();
        for (source, msg) in [
            ("kernel", "x"),
            ("machined", "x"),
            ("kernel", "y"),
            ("kernel", "z"),
            ("kernel", "x"),
        ] {
            p.push(line(source, msg), t);
        }
        let batch = p.take(t);
        assert_eq!(taken(&batch, "machined"), want(&[("x", 0)]));
        assert_eq!(
            taken(&batch, "kernel"),
            want(&[("x", 0), ("y", 0), ("z", 0), ("x", 0)]),
            "only the last two shapes collapse"
        );
    }

    #[test]
    fn kernel_ring_holds_more() {
        let d = scratch("weighted");
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(line("kernel", "k"), Instant::now());
        p.push(line("kubelet", "k"), Instant::now());
        store.write(p.take(Instant::now()));
        assert_eq!(store.rings["kernel"].slots(), KERNEL_SLOTS);
        assert_eq!(store.rings["kubelet"].slots(), SLOTS);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn queue_keeps_newest() {
        let mut p = Pending::default();
        for i in 0..QUEUE as u64 + 3 {
            p.push(line("kubelet", &nth(i)), Instant::now());
        }
        p.push(line("kernel", "k"), Instant::now());
        let q = &p.queues["kubelet"];
        assert_eq!((q.lines.len(), q.dropped), (QUEUE, 3));
        assert!(String::from_utf8_lossy(&q.lines[0]).contains("\"msg\":\"d\""));
        assert_eq!(p.queues["kernel"].lines.len(), 1);
    }

    #[test]
    fn sources_capped_in_queue() {
        let mut p = Pending::default();
        for i in 0..MAX_SOURCES {
            p.push(line(&format!("s{i}"), "x"), Instant::now());
        }
        p.push(line("s0", "again"), Instant::now());
        p.push(line("one-too-many", "x"), Instant::now());
        assert_eq!((p.queues.len(), p.refused), (MAX_SOURCES, 1));
        assert_eq!(p.queues["s0"].lines.len(), 2);
        p.unparsed = 4;
        let batch = p.take(Instant::now());
        assert_eq!((batch.refused, batch.unparsed), (1, 4));
        assert_eq!((p.refused, p.unparsed), (0, 0));
    }

    #[test]
    fn longest_line_fits_a_slot() {
        let d = scratch("longest");
        let long = line("kubelet", &"x".repeat(5000));
        assert_eq!(long.payload.len(), RECORD_SIZE - crate::ring::HEADER);
        let want = long.payload.clone();
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(long, Instant::now());
        store.write(p);
        assert_eq!(store.lost, 0);
        assert_eq!(read_all(&d)[0].payload, want);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn failed_append_loses_batch_and_reopens() {
        let d = scratch("failed");
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(line("kernel", "before"), Instant::now());
        p.push(
            Line {
                source: "kernel".into(),
                payload: vec![b'x'; PAYLOAD + 1],
            },
            Instant::now(),
        );
        store.write(p);
        assert_eq!(store.lost, 2);
        assert!(store.rings.is_empty());
        let mut p = Pending::default();
        p.push(line("kernel", "after"), Instant::now());
        store.write(p);
        assert_eq!(msgs(&d, "kernel"), ["after"]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn warnings_once_a_minute() {
        let mut store = Store::new(PathBuf::from("/nonexistent"), "b".into());
        let mut emitted = 0;
        assert!(store.warn(|| emitted += 1));
        assert!(!store.warn(|| emitted += 1));
        assert_eq!(emitted, 1);
        store.next_warning = Instant::now();
        assert!(store.warn(|| emitted += 1));
        assert!(store.next_warning >= Instant::now() + WARN_EVERY - Duration::from_secs(1));
    }

    #[test]
    fn losses_counted() {
        let d = scratch("losses");
        let mut store = Store::new(d.clone(), "b".into());
        for _ in 0..2 {
            let mut p = Pending::default();
            (p.refused, p.unparsed) = (2, 3);
            store.write(p);
        }
        assert_eq!((store.lost, store.unparsed), (4, 6));
        assert_eq!(
            store.reported,
            (2, 3),
            "reported once, then quiet for a minute"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn chatty_source_evicts_only_itself() {
        let d = scratch("chatty");
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(line("kernel", "oops"), Instant::now());
        store.write(p);
        for round in 0..3 {
            let mut p = Pending::default();
            for i in 0..SLOTS {
                p.push(
                    line("kubelet", &format!("{}-{}", nth(round), nth(i))),
                    Instant::now(),
                );
            }
            store.write(p);
        }
        assert_eq!(msgs(&d, "kernel"), ["oops"]);
        let k = msgs(&d, "kubelet");
        assert_eq!(k.len() as u64, SLOTS);
        assert_eq!(k.last().unwrap(), &format!("c-{}", nth(SLOTS - 1)));
        assert_eq!(k[0], "dropped 1", "a full round drops its oldest line");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn dropped_lines_noted_first() {
        let d = scratch("dropped");
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        for i in 0..SLOTS + 5 {
            p.push(line("kubelet", &nth(i)), Instant::now());
        }
        store.write(p);
        let k = msgs(&d, "kubelet");
        assert_eq!(k.len() as u64, SLOTS);
        assert_eq!((k[0].as_str(), k[1].as_str()), ("dropped 6", "g"));
        assert_eq!(k[k.len() - 1], nth(SLOTS + 4));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn sources_capped_on_disk() {
        let d = scratch("cap");
        for i in 0..MAX_SOURCES - 1 {
            let mut store = Store::new(d.clone(), "b".into());
            let mut p = Pending::default();
            p.push(line(&format!("old{i}"), "x"), Instant::now());
            store.write(p);
        }
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(line("last", "fits"), Instant::now());
        p.push(line("zzz", "refused"), Instant::now());
        p.push(line("old0", "kept"), Instant::now());
        store.write(p);
        assert_eq!(ring_files(&d).len(), MAX_SOURCES);
        assert!(!ring_path(&d, "zzz").exists());
        assert_eq!(msgs(&d, "old0"), ["x", "kept"]);
        assert_eq!(msgs(&d, "last"), ["fits"]);
        assert_eq!(store.lost, 1);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn bad_ring_recreated() {
        let d = scratch("bad");
        std::fs::write(ring_path(&d, "kernel"), vec![0xAB; 3 * RECORD_SIZE]).unwrap();
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(line("kernel", "after"), Instant::now());
        store.write(p);
        let k = msgs(&d, "kernel");
        assert!(k[0].contains("ring recreated"), "{k:?}");
        assert_eq!(k[1], "after");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn unwritable_dir_loses_lines_not_process() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { nix::libc::geteuid() } == 0 {
            return;
        }
        let d = scratch("unwritable");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut store = Store::new(d.join("logs"), "b".into());
        let mut p = Pending::default();
        p.push(line("kernel", "x"), Instant::now());
        store.write(p);
        assert!(store.rings.is_empty());
        assert_eq!(store.lost, 1);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn udp_lines_reach_rings() {
        let d = scratch("udp");
        let logs = spawn("127.0.0.1:0", d.clone(), "abcd1234".into()).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for (svc, msg) in [
            ("kernel", "kern: info: [t]: hello"),
            ("machined", "one"),
            ("machined", "two"),
            ("machined", "two"),
        ] {
            let ev = format!(
                r#"{{"msg":"{msg}","talos-level":"info","talos-service":"{svc}","talos-time":"2026-09-29T10:00:00Z"}}"#
            );
            tx.send_to(ev.as_bytes(), logs.addr).unwrap();
        }
        tx.send_to(b"not json", logs.addr).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while logs.pending.lock().unwrap().unparsed == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(logs.pending.lock().unwrap().unparsed, 1);
        logs.flush_all();
        assert_eq!(msgs(&d, "kernel"), ["kern: info: [t]: hello"]);
        assert_eq!(msgs(&d, "machined"), ["one", "two", "two"]);
        let all = read_all(&d);
        assert_eq!(all.len(), 4);
        assert!(String::from_utf8_lossy(&all[3].payload).contains("\"repeated\":1"));
        assert!(String::from_utf8_lossy(&all[0].payload).contains("\"boot\":\"abcd1234\""));
        std::fs::remove_dir_all(&d).ok();
    }

    fn open_in(dir: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| std::fs::read_link(e.path()).is_ok_and(|t| t.starts_with(dir)))
            .count()
    }

    #[test]
    fn close_releases_rings() {
        let d = scratch("close");
        let logs = spawn("127.0.0.1:0", d.clone(), "b".into()).unwrap();
        logs.pending
            .lock()
            .unwrap()
            .push(line("machined", "before"), Instant::now());
        logs.flush_all();
        assert!(open_in(&d) > 0);
        logs.pending
            .lock()
            .unwrap()
            .push(line("machined", "pending"), Instant::now());
        logs.close();
        assert_eq!(open_in(&d), 0);
        logs.pending
            .lock()
            .unwrap()
            .push(line("machined", "after"), Instant::now());
        logs.flush_all();
        assert_eq!(open_in(&d), 0);
        assert_eq!(msgs(&d, "machined"), ["before", "pending"]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn unreadable_ring_skipped_in_read_all() {
        let d = scratch("readall");
        std::fs::write(d.join("a.bin"), b"short").unwrap();
        let mut store = Store::new(d.clone(), "b".into());
        let mut p = Pending::default();
        p.push(line("b", "x"), Instant::now());
        store.write(p);
        assert_eq!(read_all(&d).len(), 1);
        assert!(read_all(&d.join("missing")).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }
}
