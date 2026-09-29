#![no_main]

use edge_state::record::{HEADER_LEN, decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = decode(data) {
        assert!(f.total_len <= data.len());
        assert_eq!(f.payload, &data[HEADER_LEN..f.total_len]);
        let mut again = Vec::new();
        encode(f.payload, &mut again);
        assert_eq!(again, &data[..f.total_len]);
    }
});
