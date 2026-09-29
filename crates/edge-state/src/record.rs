#[derive(Debug, PartialEq)]
pub struct Framed<'a> {
    pub payload: &'a [u8],
    pub total_len: usize,
}

#[derive(Debug, PartialEq)]
pub enum ReadError {
    Torn,
    BadChecksum,
}

pub const HEADER_LEN: usize = 8;

pub const MAX_PAYLOAD: usize = 256 * 1024 * 1024;

pub fn parse_header(h: &[u8; HEADER_LEN]) -> (u32, u32) {
    (
        u32::from_le_bytes(h[0..4].try_into().unwrap()),
        u32::from_le_bytes(h[4..8].try_into().unwrap()),
    )
}

pub fn checksum_ok(payload: &[u8], crc: u32) -> bool {
    crc32fast::hash(payload) == crc
}

pub fn encode(payload: &[u8], out: &mut Vec<u8>) {
    assert!(
        !payload.is_empty(),
        "an empty payload would frame as a torn record"
    );
    let crc = crc32fast::hash(payload);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(payload);
}

pub fn decode(buf: &[u8]) -> Result<Framed<'_>, ReadError> {
    if buf.len() < HEADER_LEN {
        return Err(ReadError::Torn);
    }
    let (len, crc) = parse_header(buf[..HEADER_LEN].try_into().unwrap());
    let len = len as usize;
    // Zeros are what a filesystem returns when a file's size reached disk but its data
    // did not, and an all-zero header is self-consistent (crc32 of nothing is 0).
    if len == 0 {
        return Err(ReadError::Torn);
    }
    let end = HEADER_LEN.saturating_add(len);
    if buf.len() < end || len > MAX_PAYLOAD {
        return Err(ReadError::Torn);
    }
    let payload = &buf[HEADER_LEN..end];
    if !checksum_ok(payload, crc) {
        return Err(ReadError::BadChecksum);
    }
    Ok(Framed {
        payload,
        total_len: end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_pack_back_to_back() {
        let mut buf = Vec::new();
        encode(b"one", &mut buf);
        encode(b"three", &mut buf);
        let a = decode(&buf).unwrap();
        assert_eq!((a.payload, a.total_len), (&b"one"[..], HEADER_LEN + 3));
        let b = decode(&buf[a.total_len..]).unwrap();
        assert_eq!((b.payload, b.total_len), (&b"three"[..], HEADER_LEN + 5));
    }

    #[test]
    fn every_truncation_is_torn() {
        let mut buf = Vec::new();
        encode(b"a durable value", &mut buf);
        for cut in 0..buf.len() {
            assert_eq!(decode(&buf[..cut]), Err(ReadError::Torn), "cut at {cut}");
        }
    }

    #[test]
    fn corrupt_payload_bad_checksum() {
        let mut buf = Vec::new();
        encode(b"payload", &mut buf);
        *buf.last_mut().unwrap() ^= 0xff;
        assert_eq!(decode(&buf), Err(ReadError::BadChecksum));
    }

    #[test]
    fn zero_fill_is_torn() {
        for n in 0..300 {
            assert_eq!(decode(&vec![0u8; n]), Err(ReadError::Torn), "{n} zeros");
        }
    }

    #[test]
    #[should_panic]
    fn empty_payload_panics() {
        encode(b"", &mut Vec::new());
    }
}
