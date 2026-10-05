#![no_main]

// edge-gateway is a binary: compile the module in directly.
#[path = "../../src/path.rs"]
mod path;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(h) = path::normalize_host(text) {
        assert_eq!(path::normalize_host(&h).as_ref(), Some(&h), "{text:?}");
    }
    let (prefix, raw) = text.split_once('\n').unwrap_or(("/", text));
    let Ok(c) = path::canonicalize(raw) else {
        return;
    };
    assert!(c.starts_with('/'), "{c:?}");
    assert!(
        !c.contains("//") && !c.contains(';') && !c.contains('\\'),
        "{c:?}"
    );
    assert!(!c.split('/').any(|s| s == "." || s == ".."), "{c:?}");
    let upper = c.to_ascii_uppercase();
    for bad in ["%2F", "%5C", "%3B", "%00", "%2E"] {
        assert!(!upper.contains(bad), "{c:?}");
    }
    assert_eq!(path::canonicalize(&c).as_ref(), Ok(&c));

    let landed = aggressive_backend_segments(&c);
    assert_eq!(landed, aggressive_backend_segments(raw), "{raw:?} -> {c:?}");
    let Ok(p) = path::canonicalize(prefix) else {
        return;
    };
    let want = aggressive_backend_segments(&p);
    let backend_view = landed.len() >= want.len() && landed.iter().zip(&want).all(|(a, b)| a == b);
    assert_eq!(
        path::segment_prefix(&c, &p),
        backend_view,
        "{raw:?} under {p:?}"
    );
});

fn aggressive_backend_segments(p: &str) -> Vec<Vec<u8>> {
    let b = p.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |j: usize| b.get(j).and_then(|d| (*d as char).to_digit(16));
        match (b[i], hex(i + 1), hex(i + 2)) {
            (b'%', Some(h), Some(l)) => {
                bytes.push((h * 16 + l) as u8);
                i += 3;
            }
            (x, _, _) => {
                bytes.push(x);
                i += 1;
            }
        }
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    for seg in bytes.split(|b| *b == b'/') {
        match seg.split(|b| *b == b';').next().unwrap_or_default() {
            b"" | b"." => {}
            b".." => {
                out.pop();
            }
            s => out.push(s.to_vec()),
        }
    }
    out
}
