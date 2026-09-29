#![no_main]

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use edge_dhcp::dns::answer;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::Name;
use libfuzzer_sys::fuzz_target;

static DOMAIN: LazyLock<Name> = LazyLock::new(|| Name::from_ascii("example.test").unwrap());

fuzz_target!(|data: &[u8]| {
    let Some(resp) = answer(data, &DOMAIN, Ipv4Addr::new(10, 51, 0, 1)) else {
        return;
    };
    let m = Message::from_vec(&resp).expect("a response that decodes");
    assert_eq!(m.metadata.message_type, MessageType::Response);
    assert_eq!(m.metadata.id.to_be_bytes(), data[..2]);
    assert!(m.answers.len() <= 1);
    assert!(resp.len() <= 512, "{} bytes", resp.len());
});
