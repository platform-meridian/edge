//! Routing, authz and the forwarded request share one canonical path on which a
//! backend's own normalisation is a no-op; otherwise `/public/../admin` could
//! match an authz-skip `/public` route and be served as `/admin`.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    NotAbsolute,
    BadEscape,
    /// A separator to backends that decode before splitting, data to others.
    EncodedSlash,
    /// A separator on some backends.
    Backslash,
    Control,
    /// A `;params` delimiter to backends that decode first, data to others.
    EncodedSemicolon,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathError::NotAbsolute => "path is not absolute",
            PathError::BadEscape => "malformed percent-escape",
            PathError::EncodedSlash => "encoded slash in path",
            PathError::Backslash => "backslash in path",
            PathError::Control => "control character in path",
            PathError::EncodedSemicolon => "encoded semicolon in path",
        })
    }
}

impl std::error::Error for PathError {}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Legal unencoded in a path segment (RFC 3986 `pchar`), bar `;`, which starts
/// params.
fn stays_literal(b: u8) -> bool {
    is_unreserved(b) || b"!$&'()*+,=:@".contains(&b)
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// `;params` are dropped because Tomcat, Jetty and Spring route `/admin;x` as
/// `/admin`.
pub fn canonicalize(raw: &str) -> Result<String, PathError> {
    if !raw.starts_with('/') {
        return Err(PathError::NotAbsolute);
    }

    // Split before decoding, so a decoded byte cannot move a segment boundary.
    let mut out: Vec<String> = Vec::new();
    let mut trailing_slash = false;
    let mut segments = raw[1..].split('/').peekable();
    while let Some(seg) = segments.next() {
        let last = segments.peek().is_none();
        let mut bytes = decode_segment(seg)?;
        // An encoded `;` is rejected, so any left here is a literal delimiter.
        if let Some(i) = bytes.iter().position(|&b| b == b';') {
            bytes.truncate(i);
        }
        match bytes.as_slice() {
            b"" | b"." => {
                trailing_slash = last;
            }
            b".." => {
                out.pop();
                trailing_slash = last;
            }
            _ => {
                out.push(encode(&bytes));
                trailing_slash = false;
            }
        }
    }

    let mut s = String::with_capacity(raw.len());
    for seg in &out {
        s.push('/');
        s.push_str(seg);
    }
    if out.is_empty() || trailing_slash {
        s.push('/');
    }
    Ok(s)
}

fn decode_segment(seg: &str) -> Result<Vec<u8>, PathError> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let v = if b[i] == b'%' {
            let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            ) else {
                return Err(PathError::BadEscape);
            };
            i += 3;
            match h * 16 + l {
                b'/' => return Err(PathError::EncodedSlash),
                b';' => return Err(PathError::EncodedSemicolon),
                v => v,
            }
        } else {
            i += 1;
            b[i - 1]
        };
        match v {
            b'\\' => return Err(PathError::Backslash),
            0..=0x1f | 0x7f => return Err(PathError::Control),
            v => out.push(v),
        }
    }
    Ok(out)
}

fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if stays_literal(b) {
            s.push(b as char);
        } else {
            s.push('%');
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 15) as usize] as char);
        }
    }
    s
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn canonical_forms() {
        use PathError::*;
        let table: &[(&str, Result<&str, PathError>)] = &[
            ("/", Ok("/")),
            ("/a", Ok("/a")),
            ("/a/", Ok("/a/")),
            ("/a/b/c", Ok("/a/b/c")),
            ("/public/../admin", Ok("/admin")),
            ("/public/./x", Ok("/public/x")),
            ("/public/..", Ok("/")),
            ("/public/../", Ok("/")),
            ("/a/b/../../..", Ok("/")),
            ("/../../admin", Ok("/admin")),
            ("/a/.", Ok("/a/")),
            ("/a/b/..", Ok("/a/")),
            ("/public/%2e%2e/admin", Ok("/admin")),
            ("/public/%2E%2E/admin", Ok("/admin")),
            ("/public/.%2e/admin", Ok("/admin")),
            ("/public/%2e./admin", Ok("/admin")),
            ("/public/%2e/x", Ok("/public/x")),
            // backends decode once
            ("/public/%252e%252e/admin", Ok("/public/%252e%252e/admin")),
            ("//admin", Ok("/admin")),
            ("///a//b", Ok("/a/b")),
            ("/a//", Ok("/a/")),
            ("//", Ok("/")),
            ("/admin;x=1", Ok("/admin")),
            ("/admin;x=1/y;z", Ok("/admin/y")),
            ("/public;a/../admin", Ok("/admin")),
            ("/public/..;x/admin", Ok("/admin")),
            ("/;x", Ok("/")),
            ("/%41%62c", Ok("/Abc")),
            ("/a%20b", Ok("/a%20b")),
            ("/a%3bb", Err(EncodedSemicolon)),
            ("/a%3Bb", Err(EncodedSemicolon)),
            ("/a%253Bb", Ok("/a%253Bb")),
            ("/a%3Fb", Ok("/a%3Fb")),
            ("/caf%c3%a9", Ok("/caf%C3%A9")),
            ("/caf\u{e9}", Ok("/caf%C3%A9")),
            ("/t/>", Ok("/t/%3E")),
            ("/t/%3E", Ok("/t/%3E")),
            ("/t/%3e", Ok("/t/%3E")),
            ("/a%21b", Ok("/a!b")),
            ("/a!b", Ok("/a!b")),
            ("/a%3Ab@c", Ok("/a:b@c")),
            ("/a%2fb", Err(EncodedSlash)),
            ("/a%2Fb", Err(EncodedSlash)),
            ("/public/..%2fadmin", Err(EncodedSlash)),
            ("/a%5cb", Err(Backslash)),
            ("/a%5Cb", Err(Backslash)),
            ("/a\\b", Err(Backslash)),
            ("/a%00b", Err(Control)),
            ("/a\0b", Err(Control)),
            ("/a%0ab", Err(Control)),
            ("/a%7fb", Err(Control)),
            ("/a%zz", Err(BadEscape)),
            ("/a%", Err(BadEscape)),
            ("/a%4", Err(BadEscape)),
            ("", Err(NotAbsolute)),
            ("admin", Err(NotAbsolute)),
            ("*", Err(NotAbsolute)),
        ];
        for (raw, want) in table {
            let got = canonicalize(raw);
            let want = want.map(str::to_string);
            assert_eq!(got, want, "canonicalize({raw:?})");
        }
    }

    use proptest::prelude::*;

    pub(crate) fn spelling() -> impl Strategy<Value = String> {
        let seg = prop_oneof![
            4 => Just("public".to_string()),
            4 => Just("admin".to_string()),
            2 => Just("a".to_string()),
            2 => Just("b".to_string()),
            3 => Just(".".to_string()),
            3 => Just("..".to_string()),
            2 => Just("%2e".to_string()),
            2 => Just("%2E%2e".to_string()),
            2 => Just(".%2e".to_string()),
            2 => Just("%2e.".to_string()),
            2 => Just(String::new()),
            2 => Just(";x".to_string()),
            2 => Just("admin;p=1".to_string()),
            2 => Just("..;p".to_string()),
            2 => Just("%61dmin".to_string()),
            2 => Just("pub%6Cic".to_string()),
            1 => Just("%252e%252e".to_string()),
            1 => Just("x%20y".to_string()),
            1 => Just("%3f".to_string()),
            1 => Just("%2f".to_string()),
            1 => Just("%5C".to_string()),
            1 => Just("%00".to_string()),
            1 => Just("%3b".to_string()),
            1 => Just("%zz".to_string()),
        ];
        prop::collection::vec(seg, 0..7).prop_map(|v| format!("/{}", v.join("/")))
    }

    fn decode_all(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && let (Some(h), Some(l)) = (
                    b.get(i + 1).copied().and_then(hex),
                    b.get(i + 2).copied().and_then(hex),
                )
            {
                out.push(h * 16 + l);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    pub(crate) fn aggressive_backend_segments(p: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for seg in decode_all(p).split('/') {
            match seg.split(';').next().unwrap() {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                s => out.push(s.to_string()),
            }
        }
        out
    }

    fn assert_canonical_shape(c: &str) {
        assert!(c.starts_with('/'), "{c}");
        assert!(!c.contains("//"), "{c}");
        assert!(
            !c.contains(';') && !c.contains('\\') && !c.contains('\0'),
            "{c}"
        );
        assert!(!c.split('/').any(|s| s == "." || s == ".."), "{c}");
        let low = c.to_ascii_lowercase();
        for bad in ["%2f", "%5c", "%00", "%3b"] {
            assert!(!low.contains(bad), "{c} still carries {bad}");
        }
        let b = c.as_bytes();
        for i in 0..b.len() {
            if b[i] == b'%' {
                let v = hex(b[i + 1]).unwrap() * 16 + hex(b[i + 2]).unwrap();
                assert!(
                    !is_unreserved(v),
                    "{c}: %{:02X} should have been decoded",
                    v
                );
                assert!(
                    b[i + 1..i + 3].iter().all(|d| !d.is_ascii_lowercase()),
                    "{c}"
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn canonical_form_is_clean_fixed_point(raw in prop_oneof![spelling(), "/[ -~]{0,40}"]) {
            if let Ok(c) = canonicalize(&raw) {
                assert_canonical_shape(&c);
                prop_assert_eq!(canonicalize(&c), Ok(c.clone()));
            }
        }

        #[test]
        fn backend_resolves_same_path(raw in spelling()) {
            if let Ok(c) = canonicalize(&raw) {
                prop_assert_eq!(aggressive_backend_segments(&c), aggressive_backend_segments(&raw));
                let landed = aggressive_backend_segments(&c);
                for prefix in ["/public", "/admin", "/"] {
                    let want: Vec<&str> = prefix.split('/').filter(|s| !s.is_empty()).collect();
                    let backend_view = landed.len() >= want.len()
                        && landed.iter().zip(&want).all(|(a, b)| a == b);
                    prop_assert_eq!(
                        crate::config::segment_prefix(&c, prefix),
                        backend_view,
                        "{} vs prefix {} (backend resolves {:?})", raw, prefix, landed
                    );
                }
            }
        }

    }
}
