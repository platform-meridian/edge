//! A failed forward answers NXDOMAIN: glibc and Go abort the search list on
//! SERVFAIL but step past NXDOMAIN.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, PartialEq)]
pub enum Forwarded {
    Answer(Vec<Record>),
    /// The upstream's authority section rides along so the answer stays cacheable.
    NoData(Vec<Record>),
    NxDomain(Vec<Record>),
    Failed,
}

#[derive(Debug, Clone)]
pub struct ForwardCfg {
    /// Backstop around the resolver's own timeout.
    pub lookup_timeout: Duration,
    pub breaker_open: Duration,
    pub max_in_flight: usize,
}

impl Default for ForwardCfg {
    fn default() -> Self {
        Self {
            lookup_timeout: Duration::from_millis(1500),
            breaker_open: Duration::from_secs(10),
            max_in_flight: 64,
        }
    }
}

/// A half-open probe whose task was dropped must not wedge the breaker.
const PROBE_LEASE: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub struct Breaker {
    open_until: Option<Instant>,
    probe_until: Option<Instant>,
}

impl Breaker {
    pub fn allow(&mut self, now: Instant) -> bool {
        match self.open_until {
            None => true,
            Some(t) if now < t => false,
            Some(_) => match self.probe_until {
                Some(p) if now < p => false,
                _ => {
                    self.probe_until = Some(now + PROBE_LEASE);
                    true
                }
            },
        }
    }

    pub fn failure(&mut self, now: Instant, open_for: Duration) -> bool {
        let newly = self.open_until.is_none();
        self.open_until = Some(now + open_for);
        self.probe_until = None;
        newly
    }

    pub fn success(&mut self) -> bool {
        let was_open = self.open_until.is_some();
        self.open_until = None;
        self.probe_until = None;
        was_open
    }

    #[cfg(test)]
    pub fn is_open(&self, now: Instant) -> bool {
        self.open_until.is_some_and(|t| now < t)
    }
}

/// Only failures that cost time trip the breaker; SERVFAIL or REFUSED comes back at once.
pub fn classify(r: Result<hickory_resolver::lookup::Lookup, NetError>) -> (Forwarded, bool) {
    match r {
        Ok(lookup) => (Forwarded::Answer(lookup.answers().to_vec()), false),
        Err(e) => classify_err(&e),
    }
}

pub fn classify_err(e: &NetError) -> (Forwarded, bool) {
    match e {
        NetError::Dns(DnsError::NoRecordsFound(nr)) => {
            let authorities: Vec<Record> = match (&nr.authorities, &nr.soa) {
                (Some(auth), _) => auth.to_vec(),
                (None, Some(soa)) => vec![(**soa).clone().into_record_of_rdata()],
                (None, None) => Vec::new(),
            };
            if nr.response_code == ResponseCode::NXDomain {
                (Forwarded::NxDomain(authorities), false)
            } else {
                (Forwarded::NoData(authorities), false)
            }
        }
        NetError::Timeout | NetError::Io(_) | NetError::NoConnections | NetError::Busy => {
            (Forwarded::Failed, true)
        }
        _ => (Forwarded::Failed, false),
    }
}

pub struct Forwarder {
    resolver: TokioResolver,
    cfg: ForwardCfg,
    breaker: Mutex<Breaker>,
    permits: Semaphore,
}

impl Forwarder {
    pub fn new(resolver: TokioResolver, cfg: ForwardCfg) -> Self {
        let permits = Semaphore::new(cfg.max_in_flight);
        Self {
            resolver,
            cfg,
            breaker: Mutex::new(Breaker::default()),
            permits,
        }
    }

    pub async fn forward(&self, name: Name, rtype: RecordType) -> Forwarded {
        // Permit first: a request refused for load must not spend the probe.
        let Ok(_permit) = self.permits.try_acquire() else {
            tracing::debug!(%name, "too many forwards in flight -> NXDOMAIN");
            return Forwarded::Failed;
        };
        if !self
            .breaker
            .lock()
            .map_or(true, |mut b| b.allow(Instant::now()))
        {
            tracing::trace!(%name, "upstream breaker open -> NXDOMAIN");
            return Forwarded::Failed;
        }

        let result = tokio::time::timeout(
            self.cfg.lookup_timeout,
            self.resolver.lookup(name.clone(), rtype),
        )
        .await;
        let (out, transport_failure) = match result {
            Ok(r) => classify(r),
            Err(_elapsed) => (Forwarded::Failed, true),
        };

        if let Ok(mut b) = self.breaker.lock() {
            if transport_failure {
                if b.failure(Instant::now(), self.cfg.breaker_open) {
                    tracing::warn!(
                        %name,
                        open_for = ?self.cfg.breaker_open,
                        "upstream resolver unreachable; answering NXDOMAIN until it recovers"
                    );
                }
            } else if b.success() {
                tracing::info!("upstream resolver answering again");
            }
        }
        if matches!(out, Forwarded::Failed) {
            tracing::debug!(%name, "forward failed -> NXDOMAIN");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_resolver::net::NoRecords;

    fn no_records(code: ResponseCode) -> NetError {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            Query::default(),
            code,
        )))
    }

    #[test]
    fn classify_trips_on_slow_failures() {
        let io = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let cases = [
            (
                no_records(ResponseCode::NoError),
                Forwarded::NoData(vec![]),
                false,
            ),
            (
                no_records(ResponseCode::NXDomain),
                Forwarded::NxDomain(vec![]),
                false,
            ),
            (NetError::Timeout, Forwarded::Failed, true),
            (NetError::NoConnections, Forwarded::Failed, true),
            (NetError::Busy, Forwarded::Failed, true),
            (NetError::Io(io.into()), Forwarded::Failed, true),
            (
                NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
                Forwarded::Failed,
                false,
            ),
        ];
        for (e, want, trips) in cases {
            assert_eq!(classify_err(&e), (want, trips), "{e}");
        }
    }

    const OPEN: Duration = Duration::from_secs(10);

    fn tripped(t0: Instant) -> Breaker {
        let mut b = Breaker::default();
        assert!(b.allow(t0), "closed allows");
        assert!(b.failure(t0, OPEN), "the first failure opens it");
        b
    }

    #[test]
    fn open_breaker_refuses() {
        let t0 = Instant::now();
        let mut b = tripped(t0);
        for s in [0, 5, 9] {
            assert!(!b.allow(t0 + Duration::from_secs(s)), "open at +{s}s");
        }
        assert!(b.is_open(t0 + Duration::from_secs(9)));
    }

    #[test]
    fn one_probe_after_window() {
        let t0 = Instant::now();
        let mut b = tripped(t0);
        let t1 = t0 + OPEN;
        assert!(b.allow(t1), "the probe, as the window ends");
        assert!(!b.allow(t1 + Duration::from_secs(1)), "others wait for it");
        assert!(b.allow(t1 + PROBE_LEASE), "a lost probe is replaced");
    }

    #[test]
    fn probe_closes_or_reopens() {
        let t0 = Instant::now();
        let t1 = t0 + OPEN + Duration::from_millis(1);

        let mut b = tripped(t0);
        assert!(b.allow(t1));
        assert!(b.success(), "reports that it closed");
        assert!(!b.success(), "already closed");
        assert!(b.allow(t1) && b.allow(t1));

        let mut b = tripped(t0);
        assert!(b.allow(t1));
        assert!(!b.failure(t1, OPEN), "already open: not a new transition");
        assert!(!b.allow(t1 + Duration::from_secs(9)));
        assert!(b.allow(t1 + OPEN + Duration::from_millis(1)));
    }
}
