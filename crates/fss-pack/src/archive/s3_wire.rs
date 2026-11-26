#![forbid(unsafe_code)]
//! Bounded HTTP/1.1 wire codec, AWS SigV4 (`AWS4-HMAC-SHA256`) request signing, and narrow flat
//! S3 XML parsing for [`crate::archive::s3_pack::S3CompatiblePackTransport`].

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;

use fss_core::{ContentDigest, TimestampNs};
use fss_vault::hmac_sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::archive::s3_pack::{ColdS3Credentials, ColdS3Endpoint};
use crate::crypto::envelope::encode_hex_lower;
use crate::error::PackError;

pub(super) struct HttpReply {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl HttpReply {
    pub(super) fn unique_header(&self, name: &str) -> Result<&str, PackError> {
        let mut iter = self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str());
        let first = iter.next().ok_or_else(|| PackError::ArchiveTransport {
            detail: format!("HTTP response missing required header '{name}'"),
        })?;
        if iter.next().is_some() {
            return Err(PackError::ArchiveTransport {
                detail: format!("HTTP response contains duplicate header '{name}'"),
            });
        }
        Ok(first)
    }

    /// A 206 body is evidence for a byte interval only if the provider declares that interval.
    pub(super) fn verify_content_range(&self, start: u64, end: u64) -> Result<(), PackError> {
        let invalid = || PackError::ArchiveIntegrity {
            detail: "Range-GET Content-Range does not identify the requested interval".to_owned(),
        };
        let value = self.unique_header("content-range").map_err(|_| invalid())?;
        let (unit, spec) = value.split_once(' ').ok_or_else(invalid)?;
        let (interval, total) = spec.split_once('/').ok_or_else(invalid)?;
        let (first, last) = interval.split_once('-').ok_or_else(invalid)?;
        let decimal = |digits: &str| -> Option<u64> {
            if digits.bytes().all(|c| c.is_ascii_digit()) {
                digits.parse().ok()
            } else {
                None
            }
        };
        if !unit.eq_ignore_ascii_case("bytes")
            || decimal(first) != Some(start)
            || decimal(last) != Some(end)
            || (total != "*" && decimal(total).is_none_or(|len| len <= end))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn validate_object_key(key: &str) -> Result<(), PackError> {
    if key.is_empty() || key.len() > 1024 || key.chars().any(char::is_control) {
        return Err(PackError::InvalidConfig {
            detail: "invalid cold S3 object key".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn write_socket_all(stream: &mut TcpStream, mut bytes: &[u8]) -> Result<(), PackError> {
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => {
                return Err(PackError::ArchiveTransport {
                    detail: "cold S3 socket closed during write".to_owned(),
                });
            }
            Ok(n) => bytes = &bytes[n..],
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(PackError::ArchiveTransport {
                    detail: "cold S3 socket write error".to_owned(),
                });
            }
        }
    }
    Ok(())
}

pub(super) fn read_http1_response(
    stream: &mut TcpStream,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<HttpReply, PackError> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 8192];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if raw.len() > max_header_bytes {
            return Err(PackError::ArchiveTransport {
                detail: "HTTP response headers exceeded configured limit".to_owned(),
            });
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(PackError::ArchiveTransport {
                    detail: "unexpected EOF while reading HTTP response headers".to_owned(),
                });
            }
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(PackError::ArchiveTransport {
                    detail: "socket error reading HTTP response headers".to_owned(),
                });
            }
        }
    };

    let head_str =
        std::str::from_utf8(&raw[..header_end - 4]).map_err(|_| PackError::ArchiveTransport {
            detail: "HTTP response headers are not valid UTF-8".to_owned(),
        })?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().ok_or_else(|| PackError::ArchiveTransport {
        detail: "missing HTTP status line".to_owned(),
    })?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts
        .next()
        .ok_or_else(|| PackError::ArchiveTransport {
            detail: "malformed HTTP status line".to_owned(),
        })?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(PackError::ArchiveTransport {
            detail: "unsupported HTTP response version".to_owned(),
        });
    }
    let status = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| PackError::ArchiveTransport {
            detail: "invalid HTTP status code".to_owned(),
        })?;
    if (300..400).contains(&status) {
        return Err(PackError::ArchiveTransport {
            detail: format!("HTTP redirect {status} is explicitly refused"),
        });
    }

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| PackError::ArchiveTransport {
                detail: "malformed HTTP header line".to_owned(),
            })?;
        let name_trimmed = name.trim();
        let val_trimmed = value.trim();
        if name_trimmed.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(PackError::ArchiveTransport {
                    detail: "duplicate Content-Length header refused".to_owned(),
                });
            }
            let parsed = val_trimmed
                .parse::<usize>()
                .map_err(|_| PackError::ArchiveTransport {
                    detail: "invalid Content-Length value".to_owned(),
                })?;
            content_length = Some(parsed);
        } else if name_trimmed.eq_ignore_ascii_case("transfer-encoding")
            && val_trimmed.eq_ignore_ascii_case("chunked")
        {
            is_chunked = true;
        }
        headers.push((name_trimmed.to_ascii_lowercase(), val_trimmed.to_owned()));
    }

    if content_length.is_some() && is_chunked {
        return Err(PackError::ArchiveTransport {
            detail: "ambiguous Content-Length + Transfer-Encoding refused".to_owned(),
        });
    }

    let trailing = &raw[header_end..];
    let body = if let Some(expected_len) = content_length {
        if expected_len > max_body_bytes {
            return Err(PackError::ArchiveTransport {
                detail: format!(
                    "HTTP response Content-Length {expected_len} exceeds max {max_body_bytes}"
                ),
            });
        }
        let mut buf = Vec::with_capacity(expected_len);
        buf.extend_from_slice(trailing);
        if buf.len() > expected_len {
            return Err(PackError::ArchiveTransport {
                detail: "HTTP response body exceeded Content-Length".to_owned(),
            });
        }
        while buf.len() < expected_len {
            let need = (expected_len - buf.len()).min(chunk.len());
            match stream.read(&mut chunk[..need]) {
                Ok(0) => {
                    return Err(PackError::ArchiveTransport {
                        detail: "unexpected EOF before Content-Length completed".to_owned(),
                    });
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return Err(PackError::ArchiveTransport {
                        detail: "socket read error while reading HTTP body".to_owned(),
                    });
                }
            }
        }
        buf
    } else if is_chunked {
        let mut wire = trailing.to_vec();
        loop {
            if wire.len() > max_body_bytes.saturating_add(64 * 1024) {
                return Err(PackError::ArchiveTransport {
                    detail: "chunked HTTP response exceeded wire bound".to_owned(),
                });
            }
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => wire.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return Err(PackError::ArchiveTransport {
                        detail: "socket read error during chunked HTTP body".to_owned(),
                    });
                }
            }
        }
        decode_chunked_body(&wire, max_body_bytes)?
    } else {
        let mut buf = trailing.to_vec();
        loop {
            if buf.len() > max_body_bytes {
                return Err(PackError::ArchiveTransport {
                    detail: "HTTP response body exceeded configured bound".to_owned(),
                });
            }
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len().saturating_add(n) > max_body_bytes {
                        return Err(PackError::ArchiveTransport {
                            detail: "HTTP response body exceeded configured bound".to_owned(),
                        });
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return Err(PackError::ArchiveTransport {
                        detail: "socket read error reading close-delimited body".to_owned(),
                    });
                }
            }
        }
        buf
    };

    Ok(HttpReply {
        status,
        headers,
        body,
    })
}

fn decode_chunked_body(wire: &[u8], max_body_bytes: usize) -> Result<Vec<u8>, PackError> {
    let mut pos = 0_usize;
    let mut out = Vec::new();
    loop {
        let rel_crlf = wire[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| PackError::ArchiveTransport {
                detail: "malformed chunked HTTP encoding".to_owned(),
            })?;
        let size_str = std::str::from_utf8(&wire[pos..pos + rel_crlf])
            .map_err(|_| PackError::ArchiveTransport {
                detail: "invalid UTF-8 in HTTP chunk size".to_owned(),
            })?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size =
            usize::from_str_radix(size_str, 16).map_err(|_| PackError::ArchiveTransport {
                detail: "invalid hex HTTP chunk size".to_owned(),
            })?;
        pos += rel_crlf + 2;
        if size == 0 {
            break;
        }
        if out.len().saturating_add(size) > max_body_bytes {
            return Err(PackError::ArchiveTransport {
                detail: "decoded chunked body exceeded configured limit".to_owned(),
            });
        }
        if pos.saturating_add(size).saturating_add(2) > wire.len() {
            return Err(PackError::ArchiveTransport {
                detail: "truncated HTTP chunk payload".to_owned(),
            });
        }
        out.extend_from_slice(&wire[pos..pos + size]);
        pos += size;
        if &wire[pos..pos + 2] != b"\r\n" {
            return Err(PackError::ArchiveTransport {
                detail: "missing CRLF after HTTP chunk".to_owned(),
            });
        }
        pos += 2;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_sigv4_request_head(
    endpoint: &ColdS3Endpoint,
    credentials: &ColdS3Credentials,
    now: TimestampNs,
    method: &str,
    object_key: &str,
    query: &str,
    extra: &[(&'static str, String)],
    payload_digest: ContentDigest,
    payload_len: usize,
    max_header_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, PackError> {
    let timestamp = format_sigv4_timestamp(now)?;
    let path = format!("/{}/{}", endpoint.bucket(), uri_encode(object_key, true));

    let mut headers: BTreeMap<&'static str, Zeroizing<String>> = BTreeMap::new();
    headers.insert("host", Zeroizing::new(endpoint.host().to_owned()));
    headers.insert("x-amz-date", Zeroizing::new(timestamp.clone()));
    headers.insert(
        "x-amz-content-sha256",
        Zeroizing::new(encode_hex_lower(&payload_digest.bytes())),
    );
    headers.insert("content-length", Zeroizing::new(payload_len.to_string()));
    if let Some(tok) = credentials.session_token() {
        let tok_str =
            std::str::from_utf8(tok.as_slice()).map_err(|_| PackError::InvalidConfig {
                detail: "S3 session token must be valid UTF-8".to_owned(),
            })?;
        headers.insert("x-amz-security-token", Zeroizing::new(tok_str.to_owned()));
    }
    for (name, value) in extra {
        if value.is_empty()
            || value.bytes().any(|b| !(33..=126).contains(&b))
            || headers
                .insert(name, Zeroizing::new(value.clone()))
                .is_some()
        {
            return Err(PackError::InvalidConfig {
                detail: "invalid or duplicate HTTP header in S3 request".to_owned(),
            });
        }
    }

    let auth = compute_sigv4_authorization(
        credentials,
        endpoint.region(),
        &timestamp,
        method,
        &path,
        query,
        &headers,
        payload_digest,
    )?;

    let target = if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    };
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    out.extend_from_slice(format!("{method} {target} HTTP/1.1\r\n").as_bytes());
    for (name, value) in &headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"authorization: ");
    out.extend_from_slice(auth.as_bytes());
    out.extend_from_slice(b"\r\nconnection: close\r\n\r\n");
    if out.len() > max_header_bytes {
        return Err(PackError::ArchiveTransport {
            detail: "signed HTTP request head exceeded limit".to_owned(),
        });
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_sigv4_authorization(
    credentials: &ColdS3Credentials,
    region: &str,
    timestamp: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query_str: &str,
    headers: &BTreeMap<&'static str, Zeroizing<String>>,
    payload_digest: ContentDigest,
) -> Result<Zeroizing<String>, PackError> {
    if timestamp.len() < 8 {
        return Err(PackError::InvalidConfig {
            detail: "invalid SigV4 timestamp".to_owned(),
        });
    }
    let mut canonical = Zeroizing::new(format!(
        "{method}\n{canonical_uri}\n{canonical_query_str}\n"
    ));
    let mut signed_headers = String::new();
    for (name, value) in headers {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(value.as_str());
        canonical.push('\n');
        if !signed_headers.is_empty() {
            signed_headers.push(';');
        }
        signed_headers.push_str(name);
    }
    canonical.push('\n');
    canonical.push_str(&signed_headers);
    canonical.push('\n');
    canonical.push_str(&encode_hex_lower(&payload_digest.bytes()));

    let date_stamp = &timestamp[..8];
    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let canonical_hash = encode_hex_lower(&ContentDigest::sha256(canonical.as_bytes()).bytes());
    let string_to_sign = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{canonical_hash}"
    ));

    let secret = credentials.secret_access_key();
    let mut initial = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    initial.extend_from_slice(b"AWS4");
    initial.extend_from_slice(secret.as_slice());

    let date_key = Zeroizing::new(hmac_sha256(&initial, date_stamp.as_bytes()));
    let region_key = Zeroizing::new(hmac_sha256(&*date_key, region.as_bytes()));
    let service_key = Zeroizing::new(hmac_sha256(&*region_key, b"s3"));
    let signing_key = Zeroizing::new(hmac_sha256(&*service_key, b"aws4_request"));
    let mut signature = hmac_sha256(&*signing_key, string_to_sign.as_bytes());
    let sig_hex = encode_hex_lower(&signature);
    signature.zeroize();

    Ok(Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={sig_hex}",
        credentials.access_key_id()
    )))
}

fn format_sigv4_timestamp(now: TimestampNs) -> Result<String, PackError> {
    if now.0 < 0 || now.0 > 253_402_300_799_999_999_999 {
        return Err(PackError::InvalidConfig {
            detail: "SigV4 timestamp out of supported UTC range".to_owned(),
        });
    }
    let seconds = (now.0 / 1_000_000_000) as u64;
    let days = seconds / 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + u64::from(month <= 2);
    let time = seconds % 86_400;
    Ok(format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time / 3600,
        (time / 60) % 60,
        time % 60
    ))
}

fn uri_encode(value: &str, preserve_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || b"-._~".contains(&byte)
            || (preserve_slash && byte == b'/')
        {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    out
}

pub(super) fn canonical_query(values: &[(&str, &str)]) -> String {
    let mut fields: Vec<(String, String)> = values
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    fields.sort();
    fields
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn encode_base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(DIGITS[usize::from(a >> 2)]));
        out.push(char::from(DIGITS[usize::from(((a & 3) << 4) | (b >> 4))]));
        out.push(if chunk.len() > 1 {
            char::from(DIGITS[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(DIGITS[usize::from(c & 63)])
        } else {
            '='
        });
    }
    out
}

pub(super) fn build_complete_multipart_xml(
    parts: &[(u32, String, ContentDigest)],
) -> Result<Vec<u8>, PackError> {
    let mut out = Vec::with_capacity(parts.len() * 128 + 128);
    out.extend_from_slice(
        b"<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for (part_num, etag, sha) in parts {
        out.extend_from_slice(b"<Part><PartNumber>");
        out.extend_from_slice(part_num.to_string().as_bytes());
        out.extend_from_slice(b"</PartNumber><ETag>");
        escape_xml(etag, &mut out);
        out.extend_from_slice(b"</ETag><ChecksumSHA256>");
        out.extend_from_slice(encode_base64(&sha.bytes()).as_bytes());
        out.extend_from_slice(b"</ChecksumSHA256></Part>");
    }
    out.extend_from_slice(b"</CompleteMultipartUpload>");
    Ok(out)
}

fn escape_xml(value: &str, out: &mut Vec<u8>) {
    for ch in value.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\'' => out.extend_from_slice(b"&apos;"),
            c => {
                let mut buf = [0_u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

pub(super) fn parse_flat_s3_xml(
    bytes: &[u8],
    expected_root: &str,
) -> Result<BTreeMap<String, String>, PackError> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(PackError::ArchiveTransport {
            detail: "S3 XML response empty or oversized".to_owned(),
        });
    }
    let mut text = std::str::from_utf8(bytes)
        .map_err(|_| PackError::ArchiveTransport {
            detail: "S3 XML response is not valid UTF-8".to_owned(),
        })?
        .trim();
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err(PackError::ArchiveTransport {
            detail: "DTD/ENTITY declarations in S3 XML refused".to_owned(),
        });
    }
    if text.starts_with("<?xml") {
        let end = text.find("?>").ok_or_else(|| PackError::ArchiveTransport {
            detail: "unterminated XML declaration".to_owned(),
        })?;
        text = text[end + 2..].trim_start();
    }
    let open_end = text.find('>').ok_or_else(|| PackError::ArchiveTransport {
        detail: "malformed XML root open tag".to_owned(),
    })?;
    let open_tag = text[1..open_end].trim();
    let root_name = open_tag.split_whitespace().next().unwrap_or("");
    if !text.starts_with('<') || root_name != expected_root {
        return Err(PackError::ArchiveTransport {
            detail: format!("unexpected S3 XML root element (expected {expected_root})"),
        });
    }
    let closing = format!("</{expected_root}>");
    let mut inner = text[open_end + 1..]
        .trim()
        .strip_suffix(&closing)
        .ok_or_else(|| PackError::ArchiveTransport {
            detail: "missing S3 XML closing root tag".to_owned(),
        })?;

    let mut fields = BTreeMap::new();
    while !inner.is_empty() {
        inner = inner.trim_start();
        if inner.is_empty() {
            break;
        }
        if fields.len() >= 32 {
            return Err(PackError::ArchiveTransport {
                detail: "too many elements in flat S3 XML response".to_owned(),
            });
        }
        let rest = inner
            .strip_prefix('<')
            .ok_or_else(|| PackError::ArchiveTransport {
                detail: "expected XML child open tag".to_owned(),
            })?;
        let gt = rest.find('>').ok_or_else(|| PackError::ArchiveTransport {
            detail: "unterminated XML child tag".to_owned(),
        })?;
        let tag = &rest[..gt];
        if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(PackError::ArchiveTransport {
                detail: "invalid XML child tag name".to_owned(),
            });
        }
        let after_open = &rest[gt + 1..];
        let child_close = format!("</{tag}>");
        let close_pos =
            after_open
                .find(&child_close)
                .ok_or_else(|| PackError::ArchiveTransport {
                    detail: "missing XML child closing tag".to_owned(),
                })?;
        let raw_val = &after_open[..close_pos];
        if raw_val.contains('<') {
            return Err(PackError::ArchiveTransport {
                detail: "nested XML child element refused".to_owned(),
            });
        }
        let decoded = raw_val
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        if fields.insert(tag.to_owned(), decoded).is_some() {
            return Err(PackError::ArchiveTransport {
                detail: "duplicate XML child element refused".to_owned(),
            });
        }
        inner = &after_open[close_pos + child_close.len()..];
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_vault::{AdapterFamily, SecretBytes, SecretScope};

    #[test]
    fn range_receipts_require_one_matching_content_range() {
        let mut reply = HttpReply {
            status: 206,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(reply.verify_content_range(8, 11).is_err());
        for (value, valid) in [
            ("bytes 8-11/12", true),
            ("BYTES 08-11/*", true),
            ("bytes 0-3/12", false),
            ("bytes 8-11/11", false),
            ("bytes 8-11/+12", false),
            ("bytes 8-11/18446744073709551616", false),
            ("items 8-11/12", false),
            ("bytes */12", false),
        ] {
            reply.headers = vec![("content-range".to_owned(), value.to_owned())];
            assert_eq!(reply.verify_content_range(8, 11).is_ok(), valid, "{value}");
        }
        reply.headers = vec![("content-range".to_owned(), "bytes 8-11/12".to_owned()); 2];
        assert!(reply.verify_content_range(8, 11).is_err());
    }

    #[test]
    fn sigv4_matches_aws_published_get_vector() -> Result<(), Box<dyn std::error::Error>> {
        let scope = SecretScope::new(AdapterFamily::ArchiveS3, "archive-test", "examplebucket")?;
        let secret = SecretBytes::from_slice(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")?;
        let creds = ColdS3Credentials::new("AKIAIOSFODNN7EXAMPLE", secret, None, scope)?;
        let payload = ContentDigest::sha256(b"");
        let headers = BTreeMap::from([
            (
                "host",
                Zeroizing::new("examplebucket.s3.amazonaws.com".to_owned()),
            ),
            ("range", Zeroizing::new("bytes=0-9".to_owned())),
            (
                "x-amz-content-sha256",
                Zeroizing::new(encode_hex_lower(&payload.bytes())),
            ),
            ("x-amz-date", Zeroizing::new("20130524T000000Z".to_owned())),
        ]);
        let auth = compute_sigv4_authorization(
            &creds,
            "us-east-1",
            "20130524T000000Z",
            "GET",
            "/test.txt",
            "",
            &headers,
            payload,
        )?;
        assert!(auth.ends_with(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        ));
        Ok(())
    }
}
