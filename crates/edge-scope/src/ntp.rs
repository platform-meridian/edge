//! A time source of last resort for the host's NTP client: behind the floor it
//! answers with the floor, otherwise unsynchronised, so a real server wins.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PACKET: usize = 48;
const NTP_UNIX: u64 = 2_208_988_800;
/// The floor has whole-second grain: a clock this close is at it.
pub const AT_FLOOR: Duration = Duration::from_secs(2);
/// The lowest stratum a client still accepts: a lower bound, not a reference.
const STRATUM: u8 = 15;
const UNSYNCED: u8 = 16;
const LEAP_UNSYNCED: u8 = 3 << 6;
const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;
/// 2^-20 s, as a signed log2.
const PRECISION: i8 = -20;
/// One second, in NTP short format.
const DISPERSION: u32 = 1 << 16;

pub trait Clock: Send + Sync {
    fn wall(&self) -> Duration;
    fn boottime(&self) -> Duration;
}

pub struct System;

impl Clock for System {
    fn wall(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }

    fn boottime(&self) -> Duration {
        nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
            .map(Duration::from)
            .unwrap_or_default()
    }
}

/// The floor carried forward on the boottime clock, which no step moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floor {
    floor: Duration,
    at: Duration,
}

impl Floor {
    pub fn new(floor: u64, up: u64) -> Self {
        Self {
            floor: Duration::from_secs(floor),
            at: Duration::from_secs(up),
        }
    }

    pub fn at(&self, boottime: Duration) -> Duration {
        self.floor + boottime.saturating_sub(self.at)
    }

    pub fn now(&self, clock: &dyn Clock) -> Duration {
        self.at(clock.boottime())
    }
}

pub fn behind(wall: Duration, floor: Duration) -> bool {
    wall + AT_FLOOR < floor
}

fn ts(unix: Duration) -> u64 {
    let secs = unix.as_secs().wrapping_add(NTP_UNIX) & 0xFFFF_FFFF;
    let frac = (u64::from(unix.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

pub fn answer(req: &[u8], wall: Duration, floor: Duration) -> Option<([u8; PACKET], bool)> {
    if req.len() < PACKET || req[0] & 7 != MODE_CLIENT {
        return None;
    }
    let version = match (req[0] >> 3) & 7 {
        0 => 4,
        v => v.min(4),
    };
    let give = behind(wall, floor);
    let mut p = [0u8; PACKET];
    let (leap, stratum, t) = if give {
        (0, STRATUM, floor)
    } else {
        (LEAP_UNSYNCED, UNSYNCED, wall)
    };
    p[0] = leap | (version << 3) | MODE_SERVER;
    p[1] = stratum;
    p[2] = req[2];
    p[3] = PRECISION as u8;
    p[8..12].copy_from_slice(&DISPERSION.to_be_bytes());
    p[12..16].copy_from_slice(b"FLOR");
    let t = ts(t).to_be_bytes();
    p[16..24].copy_from_slice(&t);
    p[24..32].copy_from_slice(&req[40..48]);
    p[32..40].copy_from_slice(&t);
    p[40..48].copy_from_slice(&t);
    Some((p, give))
}

pub struct Server {
    pub addr: std::net::SocketAddr,
    pub served: Arc<AtomicU64>,
}

pub fn spawn(addr: &str, floor: Floor, clock: Arc<dyn Clock>) -> std::io::Result<Server> {
    let sock = UdpSocket::bind(addr)?;
    let server = Server {
        addr: sock.local_addr()?,
        served: Arc::new(AtomicU64::new(0)),
    };
    let count = server.served.clone();
    std::thread::Builder::new()
        .name("ntp".into())
        .spawn(move || serve(&sock, floor, clock.as_ref(), &count))?;
    Ok(server)
}

fn serve(sock: &UdpSocket, floor: Floor, clock: &dyn Clock, served: &AtomicU64) {
    let mut buf = [0u8; 512];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "NTP receive failed");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let (wall, fl) = (clock.wall(), floor.now(clock));
        let Some((reply, gave)) = answer(&buf[..n], wall, fl) else {
            continue;
        };
        // Counted before it is sent: the client may step the clock at once.
        if gave {
            served.fetch_add(1, Ordering::SeqCst);
            tracing::info!(%from, clock = wall.as_secs(), floor = fl.as_secs(), "answering with the floor");
        }
        if let Err(e) = sock.send_to(&reply, from) {
            tracing::warn!(error = %e, %from, "NTP reply failed");
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    pub struct Fake {
        pub wall: Mutex<Duration>,
        pub boot: Mutex<Duration>,
    }

    impl Fake {
        pub fn new(wall: u64, boot: u64) -> Arc<Self> {
            Arc::new(Self {
                wall: Mutex::new(Duration::from_secs(wall)),
                boot: Mutex::new(Duration::from_secs(boot)),
            })
        }
        pub fn step(&self, by: Duration) {
            *self.wall.lock().unwrap() += by;
        }
        pub fn pass(&self, d: Duration) {
            *self.wall.lock().unwrap() += d;
            *self.boot.lock().unwrap() += d;
        }
    }

    impl Clock for Fake {
        fn wall(&self) -> Duration {
            *self.wall.lock().unwrap()
        }
        fn boottime(&self) -> Duration {
            *self.boot.lock().unwrap()
        }
    }

    fn unix(ts: u64) -> f64 {
        (ts >> 32) as f64 - NTP_UNIX as f64 + (ts & 0xFFFF_FFFF) as f64 / 4_294_967_296.0
    }

    fn be64(b: &[u8]) -> u64 {
        u64::from_be_bytes(b.try_into().unwrap())
    }

    /// As beevik/ntp sends it: v4, mode 3, and a random transmit timestamp it expects
    /// back as the origin.
    pub fn request(nonce: u64) -> [u8; PACKET] {
        let mut r = [0u8; PACKET];
        r[0] = (4 << 3) | MODE_CLIENT;
        r[2] = 6;
        r[40..48].copy_from_slice(&nonce.to_be_bytes());
        r
    }

    /// beevik/ntp's checks, in its order; Err names the check that rejects.
    pub fn client_offset(
        req: &[u8; PACKET],
        reply: &[u8],
        sent: f64,
        got: f64,
    ) -> Result<f64, &'static str> {
        if reply.len() < PACKET || reply[0] & 7 != MODE_SERVER {
            return Err("mode");
        }
        let (refr, org, rec, xmt) = (
            be64(&reply[16..24]),
            be64(&reply[24..32]),
            be64(&reply[32..40]),
            be64(&reply[40..48]),
        );
        if xmt == 0 {
            return Err("transmit");
        }
        if org != be64(&req[40..48]) {
            return Err("origin");
        }
        if rec > xmt {
            return Err("ticked backwards");
        }
        match reply[1] {
            0 => return Err("kiss of death"),
            s if s >= 16 => return Err("stratum"),
            _ => {}
        }
        if unix(xmt) - unix(refr) > 36.0 * 3600.0 || xmt < refr {
            return Err("freshness");
        }
        let root_delay = u32::from_be_bytes(reply[4..8].try_into().unwrap()) as f64 / 65536.0;
        let disp = u32::from_be_bytes(reply[8..12].try_into().unwrap()) as f64 / 65536.0;
        if root_delay / 2.0 + disp > 16.0 {
            return Err("dispersion");
        }
        if reply[0] >> 6 == 3 {
            return Err("leap");
        }
        Ok(((unix(rec) - sent) + (unix(xmt) - got)) / 2.0)
    }

    const FLOOR: u64 = 1_790_537_906;
    const YEAR: u64 = 31_536_000;

    #[test]
    fn behind_floor_answers_floor() {
        let req = request(0xDEAD_BEEF_0123_4567);
        let wall = Duration::from_secs(FLOOR - YEAR);
        let fl = Duration::from_secs(FLOOR) + Duration::from_millis(250);
        let (p, gave) = answer(&req, wall, fl).unwrap();
        assert!(gave);
        let off = client_offset(&req, &p, wall.as_secs_f64(), wall.as_secs_f64()).unwrap();
        assert!((off - (YEAR as f64 + 0.25)).abs() < 1e-3, "{off}");
        assert_eq!(p[0], 4 << 3 | MODE_SERVER, "no leap warning, v4, server");
        assert_eq!(p[1], 15);
        assert_eq!(p[3] as i8, -20, "precision");
        assert_eq!(&p[8..12], &[0, 1, 0, 0], "root dispersion: one second");
    }

    #[test]
    fn behind_beyond_grain() {
        let fl = Duration::from_secs(FLOOR);
        assert!(!behind(fl - AT_FLOOR, fl));
        assert!(behind(fl - AT_FLOOR - Duration::from_nanos(1), fl));
        assert!(!behind(fl + AT_FLOOR, fl));
    }

    #[test]
    fn system_clocks_match_kernel() {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(System.wall().abs_diff(wall) < Duration::from_secs(5));
        let up: f64 = std::fs::read_to_string("/proc/uptime")
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let bt = System.boottime().as_secs_f64();
        assert!((bt - up).abs() < 5.0, "{bt} vs {up}");
    }

    #[test]
    fn at_floor_client_rejects_answer() {
        let req = request(7);
        for wall in [FLOOR, FLOOR - 1, FLOOR + YEAR] {
            let w = Duration::from_secs(wall);
            let (p, gave) = answer(&req, w, Duration::from_secs(FLOOR)).unwrap();
            assert!(!gave, "{wall}");
            assert_eq!(
                client_offset(&req, &p, w.as_secs_f64(), w.as_secs_f64()),
                Err("stratum"),
                "{wall}"
            );
            assert_eq!(p[0] >> 6, 3, "leap: unsynchronised");
        }
        let w = Duration::from_secs(FLOOR - 3);
        assert!(answer(&req, w, Duration::from_secs(FLOOR)).unwrap().1);
    }

    #[test]
    fn answers_clients_echoing_version() {
        let mut req = request(1);
        assert!(answer(&req[..47], Duration::ZERO, Duration::ZERO).is_none());
        for mode in [0u8, 1, 2, 4, 5, 6, 7] {
            req[0] = (4 << 3) | mode;
            assert!(
                answer(&req, Duration::ZERO, Duration::ZERO).is_none(),
                "{mode}"
            );
        }
        for (v, want) in [(0u8, 4u8), (3, 3), (4, 4), (7, 4)] {
            req[0] = (v << 3) | MODE_CLIENT;
            let (p, _) = answer(&req, Duration::ZERO, Duration::ZERO).unwrap();
            assert_eq!((p[0] >> 3) & 7, want, "{v}");
        }
    }

    #[test]
    fn floor_follows_boottime() {
        let f = Floor::new(FLOOR, 5);
        assert_eq!(f.at(Duration::from_secs(5)), Duration::from_secs(FLOOR));
        assert_eq!(
            f.at(Duration::from_millis(65_500)),
            Duration::from_millis(FLOOR * 1000 + 60_500)
        );
        assert_eq!(f.at(Duration::ZERO), Duration::from_secs(FLOOR));
        let c = Fake::new(FLOOR - YEAR, 5);
        c.step(Duration::from_secs(YEAR));
        assert_eq!(f.now(c.as_ref()), Duration::from_secs(FLOOR));
    }

    #[test]
    fn client_stepped_once_over_udp() {
        let c = Fake::new(FLOOR - YEAR, 3);
        let Server {
            addr,
            served: count,
        } = spawn("127.0.0.1:0", Floor::new(FLOOR, 3), c.clone()).unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let query = |nonce: u64| -> Result<f64, &'static str> {
            let req = request(nonce);
            let sent = c.wall().as_secs_f64();
            client.send_to(&req, addr).unwrap();
            let mut buf = [0u8; 512];
            let (n, _) = client.recv_from(&mut buf).unwrap();
            client_offset(&req, &buf[..n], sent, c.wall().as_secs_f64())
        };

        c.pass(Duration::from_secs(2));
        let off = query(11).unwrap();
        assert!((off - YEAR as f64).abs() < 1.0, "{off}");
        c.step(Duration::from_secs_f64(off));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(query(12), Err("stratum"), "at the floor: not a source");
        c.pass(Duration::from_secs(600));
        assert_eq!(query(13), Err("stratum"), "the floor keeps pace");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        client.send_to(b"junk", addr).unwrap();
        assert_eq!(query(14), Err("stratum"), "junk is ignored, not fatal");
    }
}
