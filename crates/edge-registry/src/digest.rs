use std::fmt;
use std::io::{self, Read, Write};
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

/// A sha256 content digest, the only algorithm the store holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct Digest(String);

impl Digest {
    pub fn of(bytes: &[u8]) -> Digest {
        Digest(hex(&Sha256::digest(bytes)))
    }

    pub fn hex(&self) -> &str {
        &self.0
    }

    pub fn from_hex(hex: &str) -> Option<Digest> {
        let valid = hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        valid.then(|| Digest(hex.to_owned()))
    }
}

impl FromStr for Digest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix("sha256:")
            .and_then(Digest::from_hex)
            .ok_or_else(|| format!("not a sha256 digest: {s:?}"))
    }
}

impl TryFrom<String> for Digest {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Hashing<'a, W> {
    hash: Sha256,
    to: &'a mut W,
}

impl<W: Write> Write for Hashing<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.to.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.to.flush()
    }
}

pub(crate) fn copy_hashing(mut from: impl Read, to: &mut impl Write) -> io::Result<(Digest, u64)> {
    let mut sink = Hashing {
        hash: Sha256::new(),
        to,
    };
    let len = io::copy(&mut from, &mut sink)?;
    Ok((Digest(hex(&sink.hash.finalize())), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn hashes_sha256() {
        assert_eq!(Digest::of(b"").hex(), EMPTY);
        let (d, n) = copy_hashing(&b"abc"[..], &mut io::sink()).unwrap();
        assert_eq!(n, 3);
        assert_eq!(d, Digest::of(b"abc"));
        assert_eq!(
            d.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parses_only_sha256() {
        let d: Digest = format!("sha256:{EMPTY}").parse().unwrap();
        assert_eq!(d.hex(), EMPTY);
        for bad in [
            EMPTY.to_string(),
            format!("sha512:{EMPTY}"),
            format!("sha256:{}", EMPTY.to_uppercase()),
            format!("sha256:{}", &EMPTY[1..]),
            format!("sha256:{EMPTY}0"),
            format!("sha256:../{}", &EMPTY[3..]),
        ] {
            assert!(bad.parse::<Digest>().is_err(), "{bad}");
        }
    }
}
