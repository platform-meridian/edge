#![no_main]

use std::net::Ipv4Addr;

use edge_cni::nft::{decode_exprs, fold_dump, masquerade_intact, matches, split_messages};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let msgs = split_messages(data);
    assert!(msgs.iter().map(|(_, p)| p.len() + 16).sum::<usize>() <= data.len());
    let payloads: Vec<Vec<u8>> = msgs.iter().map(|(_, p)| p.to_vec()).collect();
    let found = fold_dump(&payloads, &payloads);
    assert!(found.chains.len() <= payloads.len() && found.rules.len() <= payloads.len());
    matches(&found, Ipv4Addr::new(10, 244, 0, 0), 24, &[]);
    masquerade_intact(&found, Ipv4Addr::new(10, 244, 0, 0), 24);
    assert!(decode_exprs(data).len() <= data.len() / 4);
});
