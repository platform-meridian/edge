#![no_main]

use edge_state::entry::Entry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = Entry::decode(data) {
        assert_eq!(e.encode(), data);
    }
});
