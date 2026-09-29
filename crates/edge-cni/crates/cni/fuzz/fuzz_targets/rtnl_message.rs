#![no_main]

use libfuzzer_sys::fuzz_target;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;

fuzz_target!(|data: &[u8]| {
    let _ = NetlinkMessage::<RouteNetlinkMessage>::deserialize(data);
});
