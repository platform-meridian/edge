//! One domain: every name under it resolves to the server's address and
//! everything else is refused, with dnsmasq's flags and TTL for
//! `address=/<domain>/<addr>`, `local=/<domain>/` and `no-resolv`.

use std::net::Ipv4Addr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// dnsmasq's EDNS payload size.
const EDNS_PAYLOAD: u16 = 1232;
/// dnsmasq's `local-ttl` default: clients never cache the answer.
const TTL: u32 = 0;

pub fn answer(query: &[u8], domain: &Name, addr: Ipv4Addr) -> Option<Vec<u8>> {
    let q = Message::from_vec(query).ok()?;
    if q.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
    r.metadata.recursion_desired = q.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    // One question echoed at most, so a response stays one small datagram.
    if let [question] = q.queries.as_slice() {
        r.add_query(question.clone());
    }
    if q.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        r.set_edns(edns);
    }
    r.metadata.response_code = match (q.metadata.op_code, q.queries.as_slice()) {
        (OpCode::Query, [question]) if !domain.zone_of(question.name()) => ResponseCode::Refused,
        (OpCode::Query, [question]) => {
            let is_a = matches!(question.query_type(), RecordType::A | RecordType::ANY);
            if is_a && question.query_class() == DNSClass::IN {
                r.metadata.authoritative = true;
                r.add_answer(Record::from_rdata(
                    question.name().clone(),
                    TTL,
                    RData::A(A(addr)),
                ));
            }
            ResponseCode::NoError
        }
        (OpCode::Query, _) => ResponseCode::FormErr,
        _ => ResponseCode::NotImp,
    };
    r.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use hickory_proto::op::Query;

    const ADDR: Ipv4Addr = Ipv4Addr::new(10, 51, 0, 1);

    fn respond(query: &[u8]) -> Option<Vec<u8>> {
        answer(query, &Name::from_ascii("example.lan").unwrap(), ADDR)
    }

    fn query(name: &str, qtype: RecordType, class: DNSClass, edns: bool) -> Vec<u8> {
        let mut q = Message::new(0x1234, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        let mut question = Query::query(Name::from_ascii(name).unwrap(), qtype);
        question.set_query_class(class);
        q.add_query(question);
        if edns {
            q.set_edns(Edns::new());
        }
        q.to_vec().unwrap()
    }

    fn ask(name: &str, qtype: RecordType) -> Message {
        Message::from_vec(&respond(&query(name, qtype, DNSClass::IN, true)).unwrap()).unwrap()
    }

    #[test]
    fn answers_match_dnsmasq() {
        use RecordType::*;
        use ResponseCode::*;
        let table: &[(&str, RecordType, ResponseCode, bool, Option<&str>)] = &[
            ("example.lan.", A, NoError, true, Some("example.lan.")),
            ("EXAMPLE.LAN.", A, NoError, true, Some("EXAMPLE.LAN.")),
            (
                "flux.example.lan.",
                A,
                NoError,
                true,
                Some("flux.example.lan."),
            ),
            (
                "a.b.c.example.lan.",
                A,
                NoError,
                true,
                Some("a.b.c.example.lan."),
            ),
            ("example.lan.", ANY, NoError, true, Some("example.lan.")),
            ("example.lan.", AAAA, NoError, false, None),
            ("flux.example.lan.", AAAA, NoError, false, None),
            ("example.lan.", MX, NoError, false, None),
            ("example.lan.", TXT, NoError, false, None),
            ("example.lan.", SOA, NoError, false, None),
            ("example.lan.", NS, NoError, false, None),
            ("example.lan.", PTR, NoError, false, None),
            ("lan.", A, Refused, false, None),
            ("notexample.lan.", A, Refused, false, None),
            ("example.com.", A, Refused, false, None),
            ("example.com.", AAAA, Refused, false, None),
            ("google.com.", MX, Refused, false, None),
            ("1.0.51.10.in-addr.arpa.", PTR, Refused, false, None),
            ("150.0.51.10.in-addr.arpa.", PTR, Refused, false, None),
            (".", NS, Refused, false, None),
        ];
        for &(name, qtype, rcode, aa, owner) in table {
            let r = ask(name, qtype);
            let what = format!("{name} {qtype}");
            assert_eq!(r.metadata.message_type, MessageType::Response, "{what}");
            assert_eq!(r.metadata.id, 0x1234, "{what}");
            assert_eq!(r.metadata.response_code, rcode, "{what}");
            assert_eq!(r.metadata.authoritative, aa, "{what}");
            assert!(
                r.metadata.recursion_desired && r.metadata.recursion_available,
                "{what}"
            );
            assert_eq!(
                r.queries,
                Message::from_vec(&query(name, qtype, DNSClass::IN, true))
                    .unwrap()
                    .queries,
                "{what}"
            );
            assert_eq!(r.edns.as_ref().map(Edns::max_payload), Some(1232), "{what}");
            match owner {
                Some(owner) => {
                    assert_eq!(r.answers.len(), 1, "{what}");
                    let rr = &r.answers[0];
                    assert_eq!(rr.name.to_ascii(), owner, "{what}");
                    assert_eq!(rr.ttl, 0, "{what}");
                    assert_eq!(rr.data, RData::A(super::A(ADDR)), "{what}");
                }
                None => assert!(r.answers.is_empty(), "{what}"),
            }
            assert!(
                r.authorities.is_empty() && r.additionals.is_empty(),
                "{what}"
            );
        }
    }

    #[test]
    fn serves_configured_domain() {
        for given in ["example.test", "Example.Test."] {
            let domain = Name::from_ascii(given).unwrap();
            let rcode = |name: &str| {
                let q = query(name, RecordType::A, DNSClass::IN, false);
                let r = Message::from_vec(&answer(&q, &domain, ADDR).unwrap()).unwrap();
                (r.metadata.response_code, r.answers.len())
            };
            assert_eq!(
                rcode("www.example.test."),
                (ResponseCode::NoError, 1),
                "{given}"
            );
            assert_eq!(rcode("example.lan."), (ResponseCode::Refused, 0), "{given}");
        }
    }

    #[test]
    fn other_class_empty_or_refused() {
        for (name, rcode) in [
            ("example.lan.", ResponseCode::NoError),
            ("version.bind.", ResponseCode::Refused),
        ] {
            let q = query(name, RecordType::A, DNSClass::CH, false);
            let r = Message::from_vec(&respond(&q).unwrap()).unwrap();
            assert_eq!(r.metadata.response_code, rcode, "{name}");
            assert!(r.answers.is_empty() && !r.metadata.authoritative, "{name}");
        }
    }

    #[test]
    fn edns_only_when_asked() {
        let mut q =
            Message::from_vec(&query("example.lan.", RecordType::A, DNSClass::IN, false)).unwrap();
        q.metadata.recursion_desired = false;
        let r = Message::from_vec(&respond(&q.to_vec().unwrap()).unwrap()).unwrap();
        assert!(r.edns.is_none());
        assert!(!r.metadata.recursion_desired);
        assert_eq!(r.answers.len(), 1);
    }

    #[test]
    fn formerr_and_notimp() {
        let mut none = Message::new(1, MessageType::Query, OpCode::Query);
        let r = Message::from_vec(&respond(&none.to_vec().unwrap()).unwrap()).unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::FormErr);

        let two = Query::query(Name::from_ascii("example.lan.").unwrap(), RecordType::A);
        none.add_query(two.clone()).add_query(two.clone());
        let r = Message::from_vec(&respond(&none.to_vec().unwrap()).unwrap()).unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::FormErr);
        assert!(r.answers.is_empty() && r.queries.is_empty());

        let mut notify = Message::new(1, MessageType::Query, OpCode::Notify);
        notify.add_query(two);
        let r = Message::from_vec(&respond(&notify.to_vec().unwrap()).unwrap()).unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NotImp);
        assert!(r.answers.is_empty());
        assert_eq!(r.queries.len(), 1);
    }

    #[test]
    fn ignores_responses_and_garbage() {
        let mut resp =
            Message::from_vec(&query("example.lan.", RecordType::A, DNSClass::IN, false)).unwrap();
        resp.metadata.message_type = MessageType::Response;
        assert_eq!(respond(&resp.to_vec().unwrap()), None);
        assert_eq!(respond(&[]), None);
        assert_eq!(respond(&[0x12, 0x34, 1, 0, 0, 1]), None);
    }
}
