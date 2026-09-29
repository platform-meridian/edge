#![no_main]

// edge-scope is a binary: compile the parser in directly.
#[path = "../../src/logline.rs"]
mod logline;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&first, datagram)) = data.split_first() else {
        return;
    };
    for limit in [496, 64 + usize::from(first)] {
        let Some(line) = logline::parse(datagram, "abcd1234", limit) else {
            continue;
        };
        assert!(line.payload.len() <= limit, "{} > {limit}", line.payload.len());
        assert!(logline::valid_source(&line.source), "{:?}", line.source);
        let rec: serde_json::Value = serde_json::from_slice(&line.payload).expect("valid JSON");
        assert_eq!(rec["k"], "log");
        assert_eq!(rec["src"].as_str(), Some(line.source.as_str()));
        assert_eq!(logline::parse(datagram, "abcd1234", limit), Some(line.clone()));
        let n = u64::MAX >> (first % 64);
        let again = logline::repeated(&line.payload, n, limit).expect("a parsed line re-encodes");
        assert!(again.len() <= limit, "{} > {limit}", again.len());
        let again: serde_json::Value = serde_json::from_slice(&again).expect("valid JSON");
        assert_eq!(again["repeated"].as_u64(), Some(n));
        assert_eq!(again["src"], rec["src"]);
    }
});
