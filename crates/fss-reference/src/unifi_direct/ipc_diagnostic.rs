#![forbid(unsafe_code)]
//! Experimental framing for one camera-local diagnostic operation.
//!
//! The observed client sends a length-prefixed name and a length-prefixed
//! JSON request; a synthetic server returned a single framed JSON response on
//! that same connection. The camera's actual streamer has not been tested with
//! this implementation. This module performs no I/O, authenticates no peer,
//! grants no authority and cannot reconcile a prior camera effect. Response
//! fields are untrusted claims, even when they correlate with the request.

use fss_core::json_input::{self, Value};
use std::fmt;

/// Maximum payload in a diagnostic frame. This is an FSS bound, not a camera limit.
pub const MAX_FRAME: usize = 262_144;
const STREAMER: &str = "ubnt_streamer";

/// Payload-free refusal; it never includes camera data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A name, timestamp, request ID, or frame length violates the local bound.
    InvalidInput,
    /// A framed response is not a strict JSON object with the expected fields.
    InvalidResponse,
    /// The untrusted response does not match this exact request and peer claim.
    Correlation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi diagnostic refusal: {self:?}")
    }
}

impl std::error::Error for Error {}

/// One complete frame borrowed from the caller's buffer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Frame<'a> {
    payload: &'a [u8],
    consumed: usize,
}

impl<'a> Frame<'a> {
    /// Untrusted framed bytes, whose disclosure remains the caller's responsibility.
    pub fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Bytes consumed, leaving any following frame with the caller.
    pub fn consumed(self) -> usize {
        self.consumed
    }
}

impl fmt::Debug for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

/// Parse one bounded big-endian frame. `None` means more bytes are needed.
pub fn parse_frame(input: &[u8]) -> Result<Option<Frame<'_>>, Error> {
    let Some(header) = input.get(..4) else {
        return Ok(None);
    };
    let size = u32::from_be_bytes(header.try_into().map_err(|_| Error::InvalidInput)?) as usize;
    if !(1..=MAX_FRAME).contains(&size) {
        return Err(Error::InvalidInput);
    }
    let end = 4usize.checked_add(size).ok_or(Error::InvalidInput)?;
    let Some(payload) = input.get(4..end) else {
        return Ok(None);
    };
    Ok(Some(Frame {
        payload,
        consumed: end,
    }))
}

fn append_frame(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if !(1..=MAX_FRAME).contains(&bytes.len()) {
        return Err(Error::InvalidInput);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| Error::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

/// Identity and request number supplied by an independently authorized owner.
/// Neither identifies a physical device or supplies randomness.
pub struct Request {
    name: String,
    id: u64,
    bytes: Vec<u8>,
}

impl Request {
    /// Build exactly one non-queued `GetVideoSettings` request and its identity
    /// handshake. The caller supplies a fresh endpoint name, ID and timestamp;
    /// this method does not read a clock or contact a camera.
    pub fn new(name: &str, id: u64, timestamp: &str) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || id == 0
            || id > i64::MAX as u64
            || !(20..=35).contains(&timestamp.len())
            || !timestamp
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'.' | b'+' | b'T' | b'Z'))
        {
            return Err(Error::InvalidInput);
        }
        let message = format!(
            "{{\"from\":\"{name}\",\"functionName\":\"GetVideoSettings\",\"id\":{id},\"isBroadcast\":false,\"queueIfDestUnavailable\":false,\"responseExpected\":true,\"timeStamp\":\"{timestamp}\",\"to\":\"{STREAMER}\",\"transactionId\":-1}}"
        );
        let mut bytes = Vec::with_capacity(8 + name.len() + message.len());
        append_frame(&mut bytes, name.as_bytes())?;
        append_frame(&mut bytes, message.as_bytes())?;
        Ok(Self {
            name: name.to_owned(),
            id,
            bytes,
        })
    }

    /// Framed request bytes; the caller owns transport, admission and accounting.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Check strict JSON and correlation against this exact request. A match is
    /// an untrusted peer claim, not authentication or effect reconciliation.
    pub fn response(&self, payload: &[u8]) -> Result<Response, Error> {
        if !(1..=MAX_FRAME).contains(&payload.len()) {
            return Err(Error::InvalidResponse);
        }
        let text = std::str::from_utf8(payload).map_err(|_| Error::InvalidResponse)?;
        let value = json_input::parse(text).map_err(|_| Error::InvalidResponse)?;
        let fields = value.object().ok_or(Error::InvalidResponse)?;
        let text_field = |key: &str| fields.get(key).and_then(Value::text);
        if text_field("functionName") != Some("__response__")
            || text_field("from") != Some(STREAMER)
            || text_field("to") != Some(self.name.as_str())
            || !matches!(fields.get("requestId"), Some(Value::Number(_)))
            || fields.get("requestId").and_then(Value::integer) != Some(i128::from(self.id))
        {
            return Err(Error::Correlation);
        }
        let status = match fields.get("statusCode") {
            Some(Value::Number(_)) => fields.get("statusCode").and_then(Value::integer),
            _ => None,
        }
        .and_then(|v| i32::try_from(v).ok())
        .ok_or(Error::InvalidResponse)?;
        if status == 0 && !matches!(fields.get("payload"), Some(Value::Object(_))) {
            return Err(Error::InvalidResponse);
        }
        Ok(Response { status, value })
    }
}

/// A correlated, still-untrusted response. Debug output cannot reveal settings.
pub struct Response {
    status: i32,
    value: Value,
}

impl Response {
    /// The remote status claim; zero was accepted in the synthetic laboratory.
    pub fn status(&self) -> i32 {
        self.status
    }

    /// Settings payload, only after the caller has admitted its disclosure.
    pub fn payload(&self) -> Option<&Value> {
        self.value.object().and_then(|fields| fields.get("payload"))
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request::new(
            "fss_probe_123",
            7_081_064_040_696_687_241,
            "2026-11-16T03:14:22.905+00:00",
        )
        .unwrap()
    }

    #[test]
    fn request_contains_two_independent_framed_messages() {
        let req = request();
        let first = parse_frame(req.bytes()).unwrap().unwrap();
        assert_eq!(first.payload(), b"fss_probe_123");
        let second = parse_frame(&req.bytes()[first.consumed()..])
            .unwrap()
            .unwrap();
        // The isolated vendor IPC listener accepted this exact synthetic request.
        // This is not evidence that the physical streamer accepts it.
        assert_eq!(
            second.payload(),
            br#"{"from":"fss_probe_123","functionName":"GetVideoSettings","id":7081064040696687241,"isBroadcast":false,"queueIfDestUnavailable":false,"responseExpected":true,"timeStamp":"2026-11-16T03:14:22.905+00:00","to":"ubnt_streamer","transactionId":-1}"#
        );
        let message = json_input::parse(std::str::from_utf8(second.payload()).unwrap()).unwrap();
        let fields = message.object().unwrap();
        assert_eq!(fields["functionName"].text(), Some("GetVideoSettings"));
        assert_eq!(fields["id"].integer(), Some(7_081_064_040_696_687_241));
        assert_eq!(fields["queueIfDestUnavailable"].boolean(), Some(false));
        assert_eq!(fields["responseExpected"].boolean(), Some(true));
        assert_eq!(first.consumed() + second.consumed(), req.bytes().len());
    }

    #[test]
    fn framing_waits_for_all_bytes_and_bounds_before_allocation() {
        let req = request();
        let first = parse_frame(req.bytes()).unwrap().unwrap();
        for end in 0..first.consumed() {
            assert!(parse_frame(&req.bytes()[..end]).unwrap().is_none());
        }
        assert_eq!(parse_frame(&[0, 0, 0, 0]), Err(Error::InvalidInput));
        assert_eq!(
            parse_frame(&u32::MAX.to_be_bytes()),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn checks_exact_identity_and_request_even_when_vendor_client_did_not() {
        let req = request();
        let reply = r#"{"from":"ubnt_streamer","functionName":"__response__","requestId":7081064040696687241,"statusCode":0,"to":"fss_probe_123","payload":{"synthetic":true}}"#;
        let response = req.response(reply.as_bytes()).unwrap();
        assert_eq!(response.status(), 0);
        assert!(response.payload().unwrap().object().is_some());
        assert!(!format!("{response:?}").contains("synthetic"));
        assert_eq!(
            req.response(reply.replace("ubnt_streamer", "unexpected_peer").as_bytes())
                .err(),
            Some(Error::Correlation)
        );
        assert_eq!(
            req.response(
                reply
                    .replace("7081064040696687241", "7081064040696687242")
                    .as_bytes()
            )
            .err(),
            Some(Error::Correlation)
        );
        assert_eq!(
            req.response(reply.replace("fss_probe_123", "other").as_bytes())
                .err(),
            Some(Error::Correlation)
        );
    }

    #[test]
    fn refuses_duplicate_fields_bad_json_and_unescaped_inputs() {
        let req = request();
        let duplicate = br#"{"from":"ubnt_streamer","from":"other"}"#;
        assert_eq!(req.response(duplicate).err(), Some(Error::InvalidResponse));
        assert_eq!(req.response(&[0xff]).err(), Some(Error::InvalidResponse));
        assert!(Request::new("bad\"name", 1, "2026-11-16T03:14:22Z").is_err());
        assert!(Request::new("good", 0, "2026-11-16T03:14:22Z").is_err());
    }
}
