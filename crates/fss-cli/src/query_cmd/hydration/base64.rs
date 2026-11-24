#![forbid(unsafe_code)]
//! Pure-Rust RFC 4648 standard Base64 codec (zero third-party dependencies).

use super::HydrationError;

/// Pure-Rust RFC 4648 standard Base64 encoder (zero third-party dependencies).
#[must_use]
pub fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(a >> 2)]));
        output.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    output
}

/// Pure-Rust RFC 4648 standard Base64 decoder (strict padding and canonical trailing bits).
pub fn decode_base64(input: &str) -> Result<Vec<u8>, HydrationError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(HydrationError::InvalidRequest(
            "base64 input length must be a multiple of four".into(),
        ));
    }
    let val = |byte: u8| -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let total_chunks = bytes.len() / 4;
    for (idx, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let is_last = idx + 1 == total_chunks;
        let a = val(chunk[0])
            .ok_or_else(|| HydrationError::InvalidRequest("invalid base64 character".into()))?;
        let b = val(chunk[1])
            .ok_or_else(|| HydrationError::InvalidRequest("invalid base64 character".into()))?;
        if chunk[2] == b'=' {
            if !is_last || chunk[3] != b'=' || (b & 0x0f) != 0 {
                return Err(HydrationError::InvalidRequest(
                    "malformed base64 padding".into(),
                ));
            }
            out.push((a << 2) | (b >> 4));
        } else if chunk[3] == b'=' {
            if !is_last {
                return Err(HydrationError::InvalidRequest(
                    "malformed base64 padding".into(),
                ));
            }
            let c = val(chunk[2])
                .ok_or_else(|| HydrationError::InvalidRequest("invalid base64 character".into()))?;
            if (c & 0x03) != 0 {
                return Err(HydrationError::InvalidRequest(
                    "non-canonical base64 trailing bits".into(),
                ));
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        } else {
            let c = val(chunk[2])
                .ok_or_else(|| HydrationError::InvalidRequest("invalid base64 character".into()))?;
            let d = val(chunk[3])
                .ok_or_else(|| HydrationError::InvalidRequest("invalid base64 character".into()))?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}
