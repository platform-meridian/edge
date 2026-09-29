use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Edns, Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, PTR, SOA, SRV};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

use crate::forward::{Forwarded, Forwarder};
use crate::watch::ZoneState;
use crate::zone::{Local, QType, Zone};

/// Short, so a client does not cache a backend that has gone (CoreDNS's value).
const TTL: u32 = 30;

/// The SOA's TTL and MINIMUM, i.e. the negative-caching TTL (RFC 2308).
const NEG_TTL: u32 = 5;

pub const SYNC_WAIT: Duration = Duration::from_secs(3);

/// The DNS-flag-day payload: survives a 1500-byte path unfragmented.
const EDNS_UDP_PAYLOAD: u16 = 1232;

pub struct EdgeDns {
    state: Arc<ZoneState>,
    forwarder: Forwarder,
    sync_wait: Duration,
}

impl EdgeDns {
    pub fn new(state: Arc<ZoneState>, forwarder: Forwarder) -> Self {
        Self {
            state,
            forwarder,
            sync_wait: SYNC_WAIT,
        }
    }

    #[cfg(test)]
    pub fn with_sync_wait(mut self, d: Duration) -> Self {
        self.sync_wait = d;
        self
    }

    async fn wait_synced(&self) -> Arc<Zone> {
        let mut rx = self.state.subscribe();
        let _ = tokio::time::timeout(self.sync_wait, rx.wait_for(|s| *s)).await;
        self.state.zone()
    }
}

fn qtype_of(rt: RecordType) -> QType {
    match rt {
        RecordType::A => QType::A,
        RecordType::AAAA => QType::Aaaa,
        RecordType::SRV => QType::Srv,
        RecordType::PTR => QType::Ptr,
        RecordType::SOA => QType::Soa,
        RecordType::NS => QType::Ns,
        _ => QType::Other,
    }
}

fn soa_record(zone: &Zone) -> Option<Record> {
    let d = zone.domain();
    let apex = Name::from_ascii(format!("{d}.")).ok()?;
    let mname = Name::from_ascii(format!("ns.dns.{d}.")).ok()?;
    let rname = Name::from_ascii(format!("hostmaster.{d}.")).ok()?;
    let soa = SOA::new(mname, rname, zone.serial(), 7200, 1800, 86400, NEG_TTL);
    Some(Record::from_rdata(apex, NEG_TTL, RData::SOA(soa)))
}

fn ns_record(zone: &Zone) -> Option<Record> {
    let d = zone.domain();
    let apex = Name::from_ascii(format!("{d}.")).ok()?;
    let target = Name::from_ascii(format!("ns.dns.{d}.")).ok()?;
    Some(Record::from_rdata(apex, TTL, RData::NS(NS(target))))
}

fn records_for(owner: &Name, local: &Local) -> Vec<Record> {
    match local {
        Local::A(ips) => ips
            .iter()
            .map(|ip| Record::from_rdata(owner.clone(), TTL, RData::A(A(*ip))))
            .collect(),
        Local::Aaaa(ips) => ips
            .iter()
            .map(|ip| Record::from_rdata(owner.clone(), TTL, RData::AAAA(AAAA(*ip))))
            .collect(),
        Local::Srv(entries) => entries
            .iter()
            .filter_map(|(port, target)| {
                let t = Name::from_ascii(format!("{target}.")).ok()?;
                Some(Record::from_rdata(
                    owner.clone(),
                    TTL,
                    RData::SRV(SRV::new(0, 100, *port, t)),
                ))
            })
            .collect(),
        // Chased records are owned by the target, or a resolver rejects them.
        Local::Cname(target, chased) => {
            let Ok(t) = Name::from_ascii(format!("{target}.")) else {
                return Vec::new();
            };
            let mut out = vec![Record::from_rdata(
                owner.clone(),
                TTL,
                RData::CNAME(CNAME(t.clone())),
            )];
            if let Some(inner) = chased {
                out.extend(records_for(&t, inner));
            }
            out
        }
        Local::Ptr(names) => names
            .iter()
            .filter_map(|n| Name::from_ascii(format!("{n}.")).ok())
            .map(|t| Record::from_rdata(owner.clone(), TTL, RData::PTR(PTR(t))))
            .collect(),
        Local::NoData
        | Local::NxDomain
        | Local::Forward
        | Local::Soa
        | Local::Ns
        | Local::NotSynced => Vec::new(),
    }
}

struct Reply {
    rcode: ResponseCode,
    authoritative: bool,
    answers: Vec<Record>,
    authorities: Vec<Record>,
}

impl Reply {
    fn code(rcode: ResponseCode) -> Self {
        Self {
            rcode,
            authoritative: false,
            answers: Vec::new(),
            authorities: Vec::new(),
        }
    }

    fn authoritative(rcode: ResponseCode, answers: Vec<Record>, authorities: Vec<Record>) -> Self {
        Self {
            rcode,
            authoritative: true,
            answers,
            authorities,
        }
    }
}

/// RFC 6891: a request with an OPT gets one back. The payload, clamped to
/// 512..=ours, is also what UDP truncation is measured against.
fn response_edns(request: &Request) -> Option<Edns> {
    let req = request.edns.as_ref()?;
    let mut e = Edns::new();
    e.set_max_payload(req.max_payload().clamp(512, EDNS_UDP_PAYLOAD));
    e.set_version(0);
    Some(e)
}

async fn send<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    reply: Reply,
) -> ResponseInfo {
    let mut builder = MessageResponseBuilder::from_message_request(request);
    let edns = response_edns(request);
    if let Some(e) = edns.as_ref() {
        builder.edns(e);
    }
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = reply.authoritative;
    // It forwards, so say so: some stub resolvers distrust a server that does not.
    metadata.recursion_available = true;
    metadata.response_code = reply.rcode;
    let none: [Record; 0] = [];
    let msg = builder.build(
        metadata,
        reply.answers.iter(),
        reply.authorities.iter(),
        none.iter(),
        none.iter(),
    );
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed to send response");
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.response_code = ResponseCode::ServFail;
            Header {
                metadata,
                counts: HeaderCounts::default(),
            }
            .into()
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for EdgeDns {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        if request.metadata.op_code != OpCode::Query {
            return send(
                request,
                &mut response_handle,
                Reply::code(ResponseCode::NotImp),
            )
            .await;
        }
        // Zero or several questions: answer rather than leave the client waiting.
        let info = match request.request_info() {
            Ok(i) => i,
            Err(e) => {
                debug!(error = %e, "request without exactly one query");
                return send(
                    request,
                    &mut response_handle,
                    Reply::code(ResponseCode::FormErr),
                )
                .await;
            }
        };
        if info.query.query_class() != DNSClass::IN {
            return send(
                request,
                &mut response_handle,
                Reply::code(ResponseCode::Refused),
            )
            .await;
        }

        // The original name keeps the query's casing for the 0x20 echo.
        let name = info.query.name().to_string();
        let rtype = info.query.query_type();
        let owner = info.query.original().name().clone();
        let qtype = qtype_of(rtype);

        let mut zone = self.state.zone();
        let mut decision = zone.resolve(&name, qtype);
        if decision == Local::NotSynced {
            zone = self.wait_synced().await;
            decision = zone.resolve(&name, qtype);
            if decision == Local::NotSynced {
                warn!(%name, waited = ?self.sync_wait, "zone not synced in time; SERVFAIL");
                return send(
                    request,
                    &mut response_handle,
                    Reply::code(ResponseCode::ServFail),
                )
                .await;
            }
        }

        let reply = match decision {
            Local::Forward => match self.forwarder.forward(owner.clone(), rtype).await {
                Forwarded::Answer(answers) => Reply {
                    answers,
                    ..Reply::code(ResponseCode::NoError)
                },
                Forwarded::NoData(authorities) => Reply {
                    authorities,
                    ..Reply::code(ResponseCode::NoError)
                },
                Forwarded::NxDomain(authorities) => Reply {
                    authorities,
                    ..Reply::code(ResponseCode::NXDomain)
                },
                Forwarded::Failed => Reply::code(ResponseCode::NXDomain),
            },
            Local::NxDomain => Reply::authoritative(
                ResponseCode::NXDomain,
                Vec::new(),
                soa_record(&zone).into_iter().collect(),
            ),
            Local::NoData => Reply::authoritative(
                ResponseCode::NoError,
                Vec::new(),
                soa_record(&zone).into_iter().collect(),
            ),
            Local::Soa => Reply::authoritative(
                ResponseCode::NoError,
                soa_record(&zone).into_iter().collect(),
                Vec::new(),
            ),
            Local::Ns => Reply::authoritative(
                ResponseCode::NoError,
                ns_record(&zone).into_iter().collect(),
                Vec::new(),
            ),
            Local::NotSynced => unreachable!("handled above"),
            answer => Reply::authoritative(
                ResponseCode::NoError,
                records_for(&owner, &answer),
                Vec::new(),
            ),
        };
        send(request, &mut response_handle, reply).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use edge_kube::ServiceView;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig,
    };
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_server::Server;
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    use crate::forward::ForwardCfg;

    fn svc(ns: &str, name: &str, ip: &str) -> Service {
        let mut s = Service::default();
        s.metadata.name = Some(name.into());
        s.metadata.namespace = Some(ns.into());
        s.spec = Some(ServiceSpec {
            cluster_ip: Some(ip.into()),
            ports: Some(vec![ServicePort {
                port: 80,
                name: Some("http".into()),
                ..Default::default()
            }]),
            ..Default::default()
        });
        s
    }

    fn headless_view(n: u8) -> ServiceView {
        let mut v = ServiceView::default();
        v.apply_service(svc("db", "fdb", "None"));
        let mut sl = EndpointSlice::default();
        sl.metadata.name = Some("fdb-1".into());
        sl.metadata.namespace = Some("db".into());
        sl.metadata.labels =
            Some([("kubernetes.io/service-name".to_string(), "fdb".to_string())].into());
        sl.endpoints = Some(
            (1..=n)
                .map(|i| Endpoint {
                    addresses: vec![format!("10.244.1.{i}")],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
        );
        v.apply_slice(sl);
        v
    }

    fn basic_view() -> ServiceView {
        let mut v = ServiceView::default();
        v.apply_service(svc("default", "kubernetes", "10.96.0.1"));
        v.apply_service(svc("default", "v6", "fd00::1"));
        v
    }

    fn synced(view: &ServiceView) -> Arc<ZoneState> {
        let st = ZoneState::new("cluster.local");
        st.on_synced(view);
        st
    }

    struct Upstream {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
    }

    fn response_to(req: &Message, rcode: ResponseCode) -> Message {
        let mut m = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.metadata.recursion_desired = true;
        m.metadata.recursion_available = true;
        m.queries = req.queries.clone();
        m
    }

    fn soa(zone: &str) -> Record {
        let z = Name::from_ascii(zone).unwrap();
        Record::from_rdata(
            z.clone(),
            60,
            RData::SOA(SOA::new(z.clone(), z, 1, 3600, 600, 86400, 60)),
        )
    }

    async fn upstream(
        delay: Duration,
        script: impl Fn(&Message) -> Option<Message> + Send + Sync + 'static,
    ) -> Upstream {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let (h, script) = (hits.clone(), Arc::new(script));
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(req) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                h.fetch_add(1, Ordering::SeqCst);
                let (sock, script) = (sock.clone(), script.clone());
                tokio::spawn(async move {
                    if let Some(resp) = script(&req) {
                        tokio::time::sleep(delay).await;
                        let _ = sock.send_to(&resp.to_vec().unwrap(), from).await;
                    }
                });
            }
        });
        Upstream { addr, hits }
    }

    fn resolver(up: SocketAddr, timeout: Duration) -> TokioResolver {
        let mut ns = NameServerConfig::udp(up.ip());
        let mut c = ConnectionConfig::udp();
        c.port = up.port();
        ns.connections = vec![c];
        let mut cfg = ResolverConfig::default();
        cfg.name_servers = vec![ns];
        let mut b = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
        b.options_mut().timeout = timeout;
        b.options_mut().attempts = 0;
        b.options_mut().use_hosts_file = ResolveHosts::Never;
        b.build().unwrap()
    }

    fn no_upstream() -> TokioResolver {
        resolver("127.0.0.1:9".parse().unwrap(), Duration::from_millis(200))
    }

    struct Dns {
        udp: SocketAddr,
        tcp: SocketAddr,
        _server: Server<EdgeDns>,
    }

    async fn serve(handler: EdgeDns) -> Dns {
        let mut server = Server::new(handler);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ua = udp.local_addr().unwrap();
        server.register_socket(udp);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ta = tcp.local_addr().unwrap();
        server.register_listener(tcp, Duration::from_secs(5), 1);
        Dns {
            udp: ua,
            tcp: ta,
            _server: server,
        }
    }

    async fn serve_state(state: Arc<ZoneState>) -> Dns {
        serve(EdgeDns::new(
            state,
            Forwarder::new(no_upstream(), ForwardCfg::default()),
        ))
        .await
    }

    fn query(name: &str, rtype: RecordType, edns: Option<u16>) -> Message {
        let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
        if let Some(payload) = edns {
            let mut e = Edns::new();
            e.set_max_payload(payload);
            m.set_edns(e);
        }
        m
    }

    async fn udp_raw(to: SocketAddr, bytes: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.send_to(bytes, to).await.unwrap();
        let mut buf = vec![0u8; 65535];
        let n = tokio::time::timeout(wait, s.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        buf.truncate(n);
        Some(buf)
    }

    async fn ask_udp(to: SocketAddr, m: &Message) -> (Message, usize) {
        let raw = udp_raw(to, &m.to_vec().unwrap(), Duration::from_secs(3))
            .await
            .expect("no reply");
        (Message::from_vec(&raw).unwrap(), raw.len())
    }

    async fn ask_tcp(to: SocketAddr, m: &Message) -> Message {
        let mut s = TcpStream::connect(to).await.unwrap();
        let bytes = m.to_vec().unwrap();
        s.write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .unwrap();
        s.write_all(&bytes).await.unwrap();
        let mut len = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut len))
            .await
            .unwrap()
            .unwrap();
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.unwrap();
        Message::from_vec(&buf).unwrap()
    }

    fn a_records(m: &Message) -> usize {
        m.answers
            .iter()
            .filter(|r| matches!(r.data, RData::A(_)))
            .count()
    }

    fn has_soa(m: &Message) -> bool {
        m.authorities
            .iter()
            .any(|r| matches!(r.data, RData::SOA(_)))
    }

    #[tokio::test]
    async fn cluster_name_authoritative() {
        let dns = serve_state(synced(&basic_view())).await;
        let q = query("KuBeRnEtEs.DeFaUlT.svc.cluster.local.", RecordType::A, None);
        let (r, _) = ask_udp(dns.udp, &q).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.metadata.authoritative);
        assert!(r.metadata.recursion_available);
        assert_eq!(r.metadata.id, 0x1234);
        assert_eq!(r.answers.len(), 1);
        assert!(matches!(&r.answers[0].data, RData::A(A(ip)) if ip.octets() == [10, 96, 0, 1]));
        assert_eq!(
            r.answers[0].name.to_ascii(),
            "KuBeRnEtEs.DeFaUlT.svc.cluster.local.",
            "0x20 case is echoed"
        );
        assert_eq!(a_records(&ask_tcp(dns.tcp, &q).await), 1);
    }

    #[tokio::test]
    async fn serves_aaaa_srv_ptr() {
        let dns = serve_state(synced(&basic_view())).await;
        let cases = [
            ("v6.default.svc.cluster.local.", RecordType::AAAA),
            (
                "_http._tcp.kubernetes.default.svc.cluster.local.",
                RecordType::SRV,
            ),
            ("1.0.96.10.in-addr.arpa.", RecordType::PTR),
        ];
        for (name, rtype) in cases {
            let (r, _) = ask_udp(dns.udp, &query(name, rtype, None)).await;
            assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{name}");
            assert_eq!(r.answers.len(), 1, "{name}");
            assert_eq!(r.answers[0].record_type(), rtype, "{name}");
        }
    }

    #[tokio::test]
    async fn negative_answers_carry_soa() {
        let dns = serve_state(synced(&basic_view())).await;
        let (nx, _) = ask_udp(
            dns.udp,
            &query("nope.default.svc.cluster.local.", RecordType::A, None),
        )
        .await;
        assert_eq!(nx.metadata.response_code, ResponseCode::NXDomain);
        assert!(nx.metadata.authoritative);
        assert!(has_soa(&nx), "NXDOMAIN needs an SOA");
        let soa = nx
            .authorities
            .iter()
            .find(|r| matches!(r.data, RData::SOA(_)))
            .unwrap();
        assert_eq!(soa.name.to_ascii(), "cluster.local.");

        let (nd, _) = ask_udp(
            dns.udp,
            &query(
                "kubernetes.default.svc.cluster.local.",
                RecordType::AAAA,
                None,
            ),
        )
        .await;
        assert_eq!(nd.metadata.response_code, ResponseCode::NoError);
        assert!(nd.answers.is_empty());
        assert!(has_soa(&nd), "NODATA needs an SOA");
    }

    #[tokio::test]
    async fn apex_answers_soa_and_ns() {
        let dns = serve_state(synced(&basic_view())).await;
        let (soa, _) = ask_udp(dns.udp, &query("cluster.local.", RecordType::SOA, None)).await;
        assert_eq!(soa.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(soa.answers[0].data, RData::SOA(_)));
        let (ns, _) = ask_udp(dns.udp, &query("cluster.local.", RecordType::NS, None)).await;
        assert_eq!(ns.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(ns.answers[0].data, RData::NS(_)));
    }

    #[tokio::test]
    async fn malformed_requests_get_errors() {
        let dns = serve_state(synced(&basic_view())).await;
        let no_question = Message::new(7, MessageType::Query, OpCode::Query);
        let mut two_questions = query("a.default.svc.cluster.local.", RecordType::A, None);
        two_questions.add_query(Query::query(
            Name::from_ascii("b.default.svc.cluster.local.").unwrap(),
            RecordType::A,
        ));
        let mut notify = query("kubernetes.default.svc.cluster.local.", RecordType::A, None);
        notify.metadata.op_code = OpCode::Notify;
        let mut chaos = query("version.bind.", RecordType::TXT, None);
        chaos.queries[0].set_query_class(DNSClass::CH);
        // A header claiming one question, then garbage.
        let garbled = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        ];

        let cases = [
            (
                "no question",
                no_question.to_vec().unwrap(),
                ResponseCode::FormErr,
                7,
            ),
            (
                "two questions",
                two_questions.to_vec().unwrap(),
                ResponseCode::FormErr,
                0x1234,
            ),
            ("garbled", garbled, ResponseCode::FormErr, 0xabcd),
            (
                "notify",
                notify.to_vec().unwrap(),
                ResponseCode::NotImp,
                0x1234,
            ),
            (
                "chaos",
                chaos.to_vec().unwrap(),
                ResponseCode::Refused,
                0x1234,
            ),
        ];
        for (what, bytes, rcode, id) in cases {
            let raw = udp_raw(dns.udp, &bytes, Duration::from_millis(1500))
                .await
                .unwrap_or_else(|| panic!("{what}: silence"));
            let r = Message::from_vec(&raw).unwrap();
            assert_eq!(
                (r.metadata.response_code, r.metadata.id),
                (rcode, id),
                "{what}"
            );
        }
    }

    #[tokio::test]
    async fn edns_payload_clamped() {
        let dns = serve_state(synced(&basic_view())).await;
        let (big, _) = ask_udp(
            dns.udp,
            &query(
                "kubernetes.default.svc.cluster.local.",
                RecordType::A,
                Some(4096),
            ),
        )
        .await;
        let e = big
            .edns
            .as_ref()
            .expect("RFC 6891: a request with OPT gets a response with OPT");
        assert_eq!(
            e.max_payload(),
            1232,
            "the flag-day size, not the client's 4096"
        );
        let (small, _) = ask_udp(
            dns.udp,
            &query(
                "kubernetes.default.svc.cluster.local.",
                RecordType::A,
                Some(100),
            ),
        )
        .await;
        assert_eq!(
            small.edns.as_ref().unwrap().max_payload(),
            512,
            "never below the 512 the protocol guarantees"
        );
        let (plain, _) = ask_udp(
            dns.udp,
            &query("kubernetes.default.svc.cluster.local.", RecordType::A, None),
        )
        .await;
        assert!(plain.edns.is_none());
    }

    #[tokio::test]
    async fn large_answers_truncate_over_udp() {
        // 60 A records (~960 bytes) exceed UDP's 512 but fit EDNS's 1232; 120 fit neither.
        let name = "fdb.db.svc.cluster.local.";
        for (n, fits_edns) in [(60, true), (120, false)] {
            let dns = serve_state(synced(&headless_view(n))).await;

            let (plain, len) = ask_udp(dns.udp, &query(name, RecordType::A, None)).await;
            assert!(
                plain.metadata.truncation,
                "{n}: TC so the client retries over TCP"
            );
            assert!(len <= 512, "{n}: plain UDP reply was {len} bytes");

            let (edns, len) = ask_udp(dns.udp, &query(name, RecordType::A, Some(4096))).await;
            assert_eq!(edns.metadata.truncation, !fits_edns, "{n}");
            assert!(len <= 1232, "{n}: EDNS reply was {len} bytes");
            if fits_edns {
                assert_eq!(a_records(&edns), n as usize);
            }

            let tcp = ask_tcp(dns.tcp, &query(name, RecordType::A, None)).await;
            assert!(!tcp.metadata.truncation);
            assert_eq!(a_records(&tcp), n as usize);
        }
    }

    #[tokio::test]
    async fn query_waits_for_sync() {
        let state = ZoneState::new("cluster.local");
        let dns = serve(
            EdgeDns::new(
                state.clone(),
                Forwarder::new(no_upstream(), ForwardCfg::default()),
            )
            .with_sync_wait(Duration::from_secs(3)),
        )
        .await;
        let q = query("kubernetes.default.svc.cluster.local.", RecordType::A, None);
        let asking = tokio::spawn(async move { ask_udp(dns.udp, &q).await.0 });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !asking.is_finished(),
            "must be held, not answered from an empty zone"
        );
        state.on_synced(&basic_view());
        let r = asking.await.unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(a_records(&r), 1);
    }

    #[tokio::test]
    async fn sync_timeout_is_servfail() {
        let state = ZoneState::new("cluster.local");
        let dns = serve(
            EdgeDns::new(state, Forwarder::new(no_upstream(), ForwardCfg::default()))
                .with_sync_wait(Duration::from_millis(300)),
        )
        .await;
        let t = Instant::now();
        let (r, _) = ask_udp(
            dns.udp,
            &query("kubernetes.default.svc.cluster.local.", RecordType::A, None),
        )
        .await;
        assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
        assert!(!r.metadata.authoritative);
        assert!(t.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn forward_not_held_for_sync() {
        let up = upstream(Duration::ZERO, answer_a).await;
        let state = ZoneState::new("cluster.local");
        let dns = serve(EdgeDns::new(
            state,
            Forwarder::new(
                resolver(up.addr, Duration::from_millis(500)),
                ForwardCfg::default(),
            ),
        ))
        .await;
        let t = Instant::now();
        let (r, _) = ask_udp(dns.udp, &query("example.com.", RecordType::A, None)).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    async fn forwarding(up: &Upstream, timeout: Duration, cfg: ForwardCfg) -> Dns {
        serve(EdgeDns::new(
            synced(&basic_view()),
            Forwarder::new(resolver(up.addr, timeout), cfg),
        ))
        .await
    }

    fn answer_a(req: &Message) -> Option<Message> {
        let mut r = response_to(req, ResponseCode::NoError);
        r.answers.push(Record::from_rdata(
            req.queries[0].name().clone(),
            60,
            RData::A(A("192.0.2.7".parse().unwrap())),
        ));
        Some(r)
    }

    fn negative(rcode: ResponseCode) -> impl Fn(&Message) -> Option<Message> {
        move |req| {
            let mut r = response_to(req, rcode);
            r.authorities.push(soa("example.net."));
            Some(r)
        }
    }

    #[tokio::test]
    async fn relays_upstream_answers() {
        // None: an answer; Some(rcode): a negative response carrying an SOA.
        let cases = [
            (None, ResponseCode::NoError, 1),
            (Some(ResponseCode::NoError), ResponseCode::NoError, 0),
            (Some(ResponseCode::NXDomain), ResponseCode::NXDomain, 0),
        ];
        for (negative_rcode, rcode, answers) in cases {
            let up = upstream(Duration::ZERO, move |req| match negative_rcode {
                None => answer_a(req),
                Some(c) => negative(c)(req),
            })
            .await;
            let dns = forwarding(&up, Duration::from_millis(500), ForwardCfg::default()).await;
            let (r, _) = ask_udp(dns.udp, &query("host.example.net.", RecordType::A, None)).await;
            assert_eq!(r.metadata.response_code, rcode);
            assert!(!r.metadata.authoritative);
            assert_eq!(a_records(&r), answers);
            assert_eq!(has_soa(&r), answers == 0, "{rcode}");
        }
    }

    #[tokio::test]
    async fn upstream_servfail_becomes_nxdomain() {
        let up = upstream(Duration::ZERO, |req| {
            Some(response_to(req, ResponseCode::ServFail))
        })
        .await;
        let dns = forwarding(&up, Duration::from_millis(500), ForwardCfg::default()).await;
        for i in 0..3 {
            let (r, _) = ask_udp(
                dns.udp,
                &query(&format!("q{i}.example.org."), RecordType::A, None),
            )
            .await;
            assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        }
        assert_eq!(
            up.hits.load(Ordering::SeqCst),
            3,
            "a fast error is not a reason to stop asking"
        );
    }

    #[tokio::test]
    async fn silent_upstream_opens_breaker() {
        let up = upstream(Duration::ZERO, |_| None).await;
        let cfg = ForwardCfg {
            breaker_open: Duration::from_secs(30),
            ..ForwardCfg::default()
        };
        let dns = forwarding(&up, Duration::from_millis(250), cfg).await;

        let t = Instant::now();
        let (r, _) = ask_udp(dns.udp, &query("first.example.com.", RecordType::A, None)).await;
        let first = t.elapsed();
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::NXDomain,
            "NXDOMAIN, never SERVFAIL"
        );
        assert!(
            first >= Duration::from_millis(200) && first < Duration::from_millis(1500),
            "took {first:?}"
        );
        assert_eq!(up.hits.load(Ordering::SeqCst), 1, "one attempt, not two");

        let t = Instant::now();
        for i in 0..5 {
            let (r, _) = ask_udp(
                dns.udp,
                &query(&format!("later{i}.example.com."), RecordType::A, None),
            )
            .await;
            assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        }
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "breaker open: five answers took {:?}",
            t.elapsed()
        );
        assert_eq!(
            up.hits.load(Ordering::SeqCst),
            1,
            "and none of them reached the upstream"
        );
    }

    #[tokio::test]
    async fn breaker_closes_on_recovery() {
        let up_alive = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = up_alive.clone();
        let up = upstream(Duration::ZERO, move |req| {
            if !flag.load(Ordering::SeqCst) {
                return None;
            }
            answer_a(req)
        })
        .await;
        let cfg = ForwardCfg {
            breaker_open: Duration::from_millis(400),
            ..ForwardCfg::default()
        };
        let dns = forwarding(&up, Duration::from_millis(150), cfg).await;

        let (r, _) = ask_udp(dns.udp, &query("a.example.com.", RecordType::A, None)).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        up_alive.store(true, Ordering::SeqCst);
        let (r, _) = ask_udp(dns.udp, &query("b.example.com.", RecordType::A, None)).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        tokio::time::sleep(Duration::from_millis(450)).await;
        let (r, _) = ask_udp(dns.udp, &query("c.example.com.", RecordType::A, None)).await;
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::NoError,
            "the probe found the upstream alive"
        );
        assert_eq!(a_records(&r), 1);
    }

    #[tokio::test]
    async fn forwards_in_flight_capped() {
        let up = upstream(Duration::from_millis(400), answer_a).await;
        let cfg = ForwardCfg {
            max_in_flight: 2,
            ..ForwardCfg::default()
        };
        let dns = forwarding(&up, Duration::from_secs(2), cfg).await;
        let mut tasks = Vec::new();
        for i in 0..5 {
            let to = dns.udp;
            tasks.push(tokio::spawn(async move {
                ask_udp(
                    to,
                    &query(&format!("c{i}.example.com."), RecordType::A, None),
                )
                .await
                .0
            }));
        }
        let mut answered = 0;
        let mut refused = 0;
        for t in tasks {
            let r = t.await.unwrap();
            match r.metadata.response_code {
                ResponseCode::NoError => answered += 1,
                ResponseCode::NXDomain => refused += 1,
                other => panic!("{other}"),
            }
        }
        assert_eq!((answered, refused), (2, 3));
    }
}
