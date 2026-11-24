#![forbid(unsafe_code)]
//! S3 SigV4 wire canonicalization, using the already admitted HMAC primitive.
//! No ambient clock, credential lookup, redirects or network operations occur here.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, TimestampNs};
use fss_tutk::digest::hmac_sha256;
use zeroize::{Zeroize, Zeroizing};

use super::{S3Credentials, S3Endpoint, S3Error};

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

pub(super) fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(DIGITS[usize::from(a >> 2)]));
        out.push(char::from(DIGITS[usize::from((a & 3) << 4 | b >> 4)]));
        out.push(if chunk.len() > 1 {
            char::from(DIGITS[usize::from((b & 15) << 2 | c >> 6)])
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

/// S3 keys are UTF-8 bytes, not normalized URLs. Preserve slash, dot segments
/// and repeated slashes in a key; encode slash in query components.
pub(super) fn encode(value: &str, path: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || path && byte == b'/' {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
    }
    out
}

pub(super) fn query(values: &[(&str, &str)]) -> String {
    let mut fields: Vec<_> = values
        .iter()
        .map(|(name, value)| (encode(name, false), encode(value, false)))
        .collect();
    fields.sort();
    fields
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Exact Unix UTC conversion; the authority's supplied time is never clamped.
pub(super) fn date(now: TimestampNs) -> Result<String, S3Error> {
    if now.0 < 0 || now.0 > 253_402_300_799_999_999_999 {
        return Err(S3Error::Clock);
    }
    let seconds = (now.0 / 1_000_000_000) as u64;
    let days = seconds / 86_400;
    // Gregorian civil-from-days, with only nonnegative intermediates in this range.
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
        time / 60 % 60,
        time % 60
    ))
}

struct Headers(BTreeMap<&'static str, String>);
impl Drop for Headers {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn authorization(
    credentials: &S3Credentials,
    region: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<&str, String>,
    payload: ContentDigest,
) -> Zeroizing<String> {
    let mut canonical = Zeroizing::new(format!("{method}\n{path}\n{query}\n"));
    let mut names = String::new();
    for (name, value) in headers {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(value);
        canonical.push('\n');
        if !names.is_empty() {
            names.push(';');
        }
        names.push_str(name);
    }
    canonical.push('\n');
    canonical.push_str(&names);
    canonical.push('\n');
    canonical.push_str(&hex(&payload.bytes()));
    let scope = format!("{}/{region}/s3/aws4_request", &timestamp[..8]);
    let to_sign = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex(&ContentDigest::sha256(canonical.as_bytes()).bytes())
    ));
    let initial = Zeroizing::new(format!("AWS4{}", credentials.secret_key.as_str()));
    let date_key = Zeroizing::new(hmac_sha256(initial.as_bytes(), &timestamp.as_bytes()[..8]));
    let region_key = Zeroizing::new(hmac_sha256(&date_key[..], region.as_bytes()));
    let service_key = Zeroizing::new(hmac_sha256(&region_key[..], b"s3"));
    let signing_key = Zeroizing::new(hmac_sha256(&service_key[..], b"aws4_request"));
    let signature = Zeroizing::new(hmac_sha256(&signing_key[..], to_sign.as_bytes()));
    Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={names},Signature={}",
        credentials.access_key.as_str(),
        hex(&signature[..]),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn request_head(
    endpoint: &S3Endpoint,
    credentials: &S3Credentials,
    now: TimestampNs,
    method: &str,
    query: &str,
    extra: &[(&'static str, String)],
    payload: ContentDigest,
    payload_length: usize,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, S3Error> {
    let timestamp = date(now)?;
    let path = format!("/{}/{}", endpoint.bucket, encode(&endpoint.key, true));
    let mut headers = Headers(BTreeMap::new());
    headers.0.insert("host", endpoint.host.clone());
    headers.0.insert("x-amz-date", timestamp.clone());
    headers
        .0
        .insert("x-amz-content-sha256", hex(&payload.bytes()));
    headers
        .0
        .insert("content-length", payload_length.to_string());
    if let Some(token) = &credentials.session_token {
        headers.0.insert("x-amz-security-token", token.to_string());
    }
    for (name, value) in extra {
        if value.is_empty()
            || value.bytes().any(|byte| !(33..=126).contains(&byte))
            || headers.0.insert(name, value.clone()).is_some()
        {
            return Err(S3Error::Configuration);
        }
    }
    let auth = authorization(
        credentials,
        &endpoint.region,
        &timestamp,
        method,
        &path,
        query,
        &headers.0,
        payload,
    );
    let target = if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    };
    let mut out = Zeroizing::new(Vec::with_capacity(maximum));
    out.extend_from_slice(format!("{method} {target} HTTP/1.1\r\n").as_bytes());
    for (name, value) in &headers.0 {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"authorization: ");
    out.extend_from_slice(auth.as_bytes());
    out.extend_from_slice(b"\r\nconnection: close\r\n\r\n");
    if out.len() > maximum {
        return Err(S3Error::Limit);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn aws_published_get_vector() {
        // Public, deliberately nonsecret test credentials and signature:
        // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
        let credentials = S3Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        )
        .unwrap();
        let payload = ContentDigest::sha256(b"");
        let headers = BTreeMap::from([
            ("host", "examplebucket.s3.amazonaws.com".to_owned()),
            ("range", "bytes=0-9".to_owned()),
            ("x-amz-content-sha256", hex(&payload.bytes())),
            ("x-amz-date", "20130524T000000Z".to_owned()),
        ]);
        let auth = authorization(
            &credentials,
            "us-east-1",
            "20130524T000000Z",
            "GET",
            "/test.txt",
            "",
            &headers,
            payload,
        );
        assert!(auth.ends_with(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        ));
    }

    #[test]
    fn key_bytes_query_order_and_clock_boundaries() {
        assert_eq!(encode("a//../b %/é", true), "a//../b%20%25/%C3%A9");
        assert_eq!(
            query(&[("uploadId", "a/+="), ("partNumber", "1")]),
            "partNumber=1&uploadId=a%2F%2B%3D"
        );
        assert_eq!(query(&[("uploads", "")]), "uploads=");
        assert_eq!(date(TimestampNs(0)).unwrap(), "19700101T000000Z");
        assert_eq!(
            date(TimestampNs(1_369_353_600_000_000_000)).unwrap(),
            "20130524T000000Z"
        );
        assert_eq!(
            date(TimestampNs(951_782_400_000_000_000)).unwrap(),
            "20000229T000000Z"
        );
        assert!(date(TimestampNs(-1)).is_err());
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }
}
