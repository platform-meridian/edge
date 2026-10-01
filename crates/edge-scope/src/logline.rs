//! One event from a Talos `json_lines` log destination; the kernel's log arrives as
//! service `kernel`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const MAX_SOURCE: usize = 64;
const MAX_LEVEL: usize = 16;
const MAX_TIME: usize = 40;
const CUT: &str = "…";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub source: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Clone, Copy)]
struct Record<'a> {
    k: &'static str,
    src: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    boot: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    time: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    lv: &'a str,
    msg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    repeated: Option<u64>,
}

#[derive(Deserialize)]
struct Stored {
    src: String,
    #[serde(default)]
    boot: String,
    #[serde(default)]
    time: String,
    #[serde(default)]
    lv: String,
    msg: String,
}

/// The source becomes a file name, so it is held to a plain name.
pub fn valid_source(s: &str) -> bool {
    (1..=MAX_SOURCE).contains(&s.len())
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn text<'a>(event: &'a Map<String, Value>, key: &str, max: usize) -> &'a str {
    let s = event.get(key).and_then(Value::as_str).unwrap_or_default();
    &s[..floor_char_boundary(s, max)]
}

pub(crate) fn floor_char_boundary(s: &str, at: usize) -> usize {
    if at >= s.len() {
        return s.len();
    }
    (0..=at).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0)
}

fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        '\0'..='\u{1f}' => 6,
        _ => c.len_utf8(),
    }
}

fn message(event: &Map<String, Value>) -> String {
    let mut msg = event
        .get("msg")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    for (k, v) in event {
        if matches!(
            k.as_str(),
            "msg" | "talos-service" | "talos-level" | "talos-time"
        ) {
            continue;
        }
        let v = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        msg.push_str(&format!(" {k}={v}"));
    }
    msg
}

pub fn parse(datagram: &[u8], boot: &str, limit: usize) -> Option<Line> {
    let event: Map<String, Value> = serde_json::from_slice(datagram).ok()?;
    let src = event.get("talos-service")?.as_str()?;
    if !valid_source(src) {
        return None;
    }
    let record = Record {
        k: "log",
        src,
        boot: &boot[..floor_char_boundary(boot, MAX_SOURCE)],
        time: text(&event, "talos-time", MAX_TIME),
        lv: text(&event, "talos-level", MAX_LEVEL),
        msg: "",
        repeated: None,
    };
    Some(Line {
        source: src.to_string(),
        payload: fit(record, &message(&event), limit)?,
    })
}

pub fn repeated(payload: &[u8], n: u64, limit: usize) -> Option<Vec<u8>> {
    let s: Stored = serde_json::from_slice(payload).ok()?;
    let record = Record {
        k: "log",
        src: &s.src,
        boot: &s.boot,
        time: &s.time,
        lv: &s.lv,
        msg: "",
        repeated: Some(n),
    };
    fit(record, &s.msg, limit)
}

fn fit(record: Record, msg: &str, limit: usize) -> Option<Vec<u8>> {
    fit_msg(
        |msg| serde_json::to_vec(&Record { msg, ..record }).ok(),
        msg,
        limit,
    )
}

/// `encode(msg)`, the message cut short with `…` when the whole is over `limit`.
pub(crate) fn fit_msg(
    encode: impl Fn(&str) -> Option<Vec<u8>>,
    msg: &str,
    limit: usize,
) -> Option<Vec<u8>> {
    let mut payload = encode(msg)?;
    if payload.len() > limit {
        let budget = limit.checked_sub(encode(CUT)?.len())?;
        let (mut used, mut end) = (0, 0);
        for (i, c) in msg.char_indices() {
            used += escaped_len(c);
            if used > budget {
                break;
            }
            end = i + c.len_utf8();
        }
        payload = encode(&format!("{}{CUT}", &msg[..end]))?;
    }
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(line: &Line) -> Value {
        serde_json::from_slice(&line.payload).unwrap()
    }

    fn talos(service: &str, msg: &str, extra: &str) -> Vec<u8> {
        format!(
            r#"{{"msg":{},"talos-level":"warn","talos-service":"{service}","talos-time":"2026-09-29T10:11:12.123456789Z"{extra}}}"#,
            serde_json::to_string(msg).unwrap()
        )
        .into_bytes()
    }

    #[test]
    fn talos_event_kept() {
        let l = parse(&talos("kubelet", "node not ready", ""), "abcd1234", 496).unwrap();
        assert_eq!(l.source, "kubelet");
        assert_eq!(
            record(&l),
            serde_json::json!({
                "k": "log", "src": "kubelet", "boot": "abcd1234",
                "time": "2026-09-29T10:11:12.123456789Z", "lv": "warn",
                "msg": "node not ready",
            })
        );
    }

    #[test]
    fn kernel_line_kept() {
        let msg = "kern: warning: [2026-09-29T10:11:12.5Z]: nvme nvme0: I/O timeout";
        let l = parse(&talos("kernel", msg, ""), "", 496).unwrap();
        let r = record(&l);
        assert_eq!(
            (r["src"].as_str(), r["msg"].as_str()),
            (Some("kernel"), Some(msg))
        );
        assert!(r.get("boot").is_none());
    }

    #[test]
    fn fields_folded_into_message() {
        let extra = r#","component":"controller-runtime","error":"boom","n":3"#;
        let l = parse(&talos("machined", "failed", extra), "b", 496).unwrap();
        assert_eq!(
            record(&l)["msg"],
            "failed component=controller-runtime error=boom n=3"
        );
    }

    #[test]
    fn tcp_newline_accepted() {
        let mut d = talos("apid", "x", "");
        d.push(b'\n');
        assert!(parse(&d, "b", 496).is_some());
    }

    #[test]
    fn long_line_cut_to_fit() {
        for (msg, limit) in [
            ("x".repeat(5000), 496),
            ("é".repeat(3000), 496),
            ("\u{1}\n\"".repeat(900), 496),
            ("y".repeat(300), 200),
        ] {
            let l = parse(&talos("kubelet", &msg, ""), "abcd1234", limit).unwrap();
            assert!(l.payload.len() <= limit, "{}", l.payload.len());
            if msg.is_ascii() && !msg.contains(['\n', '"']) {
                assert_eq!(l.payload.len(), limit, "plain text fills the record");
            }
            assert!(
                l.payload.len() > limit - 12,
                "cut too far: {}",
                l.payload.len()
            );
            let kept = record(&l)["msg"].as_str().unwrap().to_string();
            assert!(kept.ends_with(CUT), "{kept}");
            assert!(msg.starts_with(kept.trim_end_matches(CUT)));
        }
        let whole = parse(&talos("kubelet", "", ""), "b", 496)
            .unwrap()
            .payload
            .len();
        let exact = "w".repeat(496 - whole);
        let l = parse(&talos("kubelet", &exact, ""), "b", 496).unwrap();
        assert_eq!(
            (l.payload.len(), record(&l)["msg"].as_str()),
            (496, Some(exact.as_str()))
        );
        let fits = "z".repeat(100);
        let l = parse(&talos("kubelet", &fits, ""), "b", 496).unwrap();
        assert_eq!(record(&l)["msg"], fits.as_str());
    }

    #[test]
    fn oversized_headers_bounded() {
        let d = format!(
            r#"{{"msg":"m","talos-service":"s","talos-level":"{}","talos-time":"{}"}}"#,
            "L".repeat(1000),
            "T".repeat(1000)
        );
        let r = record(&parse(d.as_bytes(), &"b".repeat(1000), 496).unwrap());
        assert_eq!(r["lv"].as_str().unwrap().len(), MAX_LEVEL);
        assert_eq!(r["time"].as_str().unwrap().len(), MAX_TIME);
        assert_eq!(r["boot"].as_str().unwrap().len(), MAX_SOURCE);
    }

    #[test]
    fn repeated_marks_last_line() {
        let l = parse(&talos("kernel", "time query error", ""), "b", 496).unwrap();
        let r: Value = serde_json::from_slice(&repeated(&l.payload, 7, 496).unwrap()).unwrap();
        let mut want = record(&l);
        want["repeated"] = 7.into();
        assert_eq!(r, want);

        let full = parse(&talos("kernel", &"é\"".repeat(400), ""), "b", 496).unwrap();
        let r = repeated(&full.payload, u64::MAX, 496).unwrap();
        assert!(r.len() <= 496, "{}", r.len());
        let r: Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(r["repeated"], u64::MAX);
        assert!(r["msg"].as_str().unwrap().ends_with(CUT));
        assert!(repeated(b"not a record", 1, 496).is_none());
    }

    #[test]
    fn no_room_is_none() {
        assert!(parse(&talos("kubelet", "hello", ""), "b", 40).is_none());
    }

    #[test]
    fn not_talos_is_none() {
        for d in [
            &b""[..],
            b"plain text",
            b"[1,2]",
            br#"{"msg":"no service"}"#,
            br#"{"talos-service":7}"#,
            br#"{"talos-service":""}"#,
            br#"{"talos-service":"../etc"}"#,
            br#"{"talos-service":".hidden"}"#,
            br#"{"talos-service":"a/b"}"#,
        ] {
            assert!(
                parse(d, "b", 496).is_none(),
                "{}",
                String::from_utf8_lossy(d)
            );
        }
    }

    #[test]
    fn source_names() {
        for ok in ["kernel", "ext-edge-scope", "cri", "a.b_c", &"s".repeat(64)] {
            assert!(valid_source(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a b", "a/b", "é", &"s".repeat(65)] {
            assert!(!valid_source(bad), "{bad}");
        }
    }
}
