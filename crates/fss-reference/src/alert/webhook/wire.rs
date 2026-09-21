#![forbid(unsafe_code)]
//! Narrow HTTP/1 response-head profile. No redirects, cookies, authentication,
//! body processing or provider-delivery interpretation. Raw prefixes stay owned.
use super::{WebhookDenial, WebhookEndpoint, WebhookError, WebhookInterruption, WebhookOutcome};
use fss_core::{CanonicalEncoder, ContentDigest};
use crate::ReferenceAlertPlan;

pub(super) fn hex(value: ContentDigest) -> String {
    value.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn request(plan: &ReferenceAlertPlan, endpoint: &WebhookEndpoint) -> Result<Vec<u8>, WebhookError> {
    // Only fixed ASCII and digests enter HTTP/JSON. Neither an arbitrary event
    // description nor an unescaped operation/idempotency identifier becomes syntax.
    let key = hex(ContentDigest::sha256(plan.intent.idempotency_key.as_str().as_bytes()));
    let operation = hex(ContentDigest::sha256(plan.intent.operation_id.as_str().as_bytes()));
    let body = format!(concat!("{{\"schema\":\"fss.webhook-alert.v1\",",
        "\"text\":\"FSS policy-authorized alert; inspect linked event evidence.\",",
        "\"operation_sha256\":\"{}\",\"request_sha256\":\"{}\",",
        "\"precondition_sha256\":\"{}\",\"event_root_sha256\":\"{}\",",
        "\"event_revision_sha256\":\"{}\"}}"), operation,
        hex(plan.intent.request_digest), hex(plan.intent.precondition_digest),
        hex(plan.event_root), hex(plan.event_revision_digest));
    let request = format!(concat!("POST {} HTTP/1.1\r\nHost: {}\r\n",
        "Content-Type: application/json\r\nIdempotency-Key: {}\r\n",
        "Content-Length: {}\r\nConnection: close\r\n\r\n{}"),
        endpoint.target(), endpoint.peer(), key, body.len(), body);
    if request.len() > 4096 { return Err(WebhookError::Configuration); }
    Ok(request.into_bytes())
}
fn token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}
fn trim(mut b: &[u8]) -> &[u8] {
    while matches!(b.first(), Some(b' ' | b'\t')) { b = &b[1..]; }
    while matches!(b.last(), Some(b' ' | b'\t')) { b = &b[..b.len()-1]; }
    b
}
fn decimal(bytes: &[u8]) -> Result<u64, ()> {
    if bytes.is_empty() { return Err(()); }
    bytes.iter().try_fold(0_u64, |n, &b| {
        if !b.is_ascii_digit() { return Err(()); }
        n.checked_mul(10).and_then(|n| n.checked_add(u64::from(b - b'0'))).ok_or(())
    })
}
/// None is an incomplete prefix, never a successful empty response. A status is
/// returned only after a complete final head. Same-read body bytes remain evidence
/// but are not parsed, awaited, or interpreted as a terminal delivery proof.
pub(super) fn response(bytes: &[u8]) -> Result<Option<u16>, ()> {
    if bytes.len() > 16384 { return Err(()); }
    let mut offset = 0;
    let mut interim = 0;
    loop {
        let tail = &bytes[offset..];
        let Some(end) = tail.windows(4).position(|b| b == b"\r\n\r\n") else {
            // Reject invalid line endings/control bytes immediately, while allowing
            // one trailing CR split across reads. Only headers, not body, reach here.
            for (i, b) in tail.iter().copied().enumerate() {
                if b == b'\n' && (i == 0 || tail[i-1] != b'\r')
                    || b == b'\r' && i + 1 < tail.len() && tail[i+1] != b'\n'
                    || b < 32 && !matches!(b, b'\r' | b'\n' | b'\t') || b > 126 {
                    return Err(());
                }
            }
            return Ok(None);
        };
        let head = &tail[..end];
        if head.iter().any(|b| *b > 126 || (*b < 32 && !matches!(b, b'\r' | b'\n' | b'\t'))) {
            return Err(());
        }
        for (i, b) in head.iter().copied().enumerate() {
            if b == b'\n' && (i == 0 || head[i-1] != b'\r')
                || b == b'\r' && (i + 1 == head.len() || head[i+1] != b'\n') {
                return Err(());
            }
        }
        let mut lines = head.split(|b| *b == b'\n');
        let raw_status = lines.next().ok_or(())?;
        let status = raw_status.strip_suffix(b"\r").unwrap_or(raw_status);
        if status.len() < 13 || ![b"HTTP/1.1 ".as_slice(), b"HTTP/1.0 ".as_slice()].iter()
            .any(|prefix| status.starts_with(prefix)) || status[12] != b' '
            || !status[9..12].iter().all(u8::is_ascii_digit)
            || status[13..].iter().any(|b| *b < 32 || *b > 126) {
            return Err(());
        }
        let code = u16::from(status[9] - b'0') * 100 + u16::from(status[10] - b'0') * 10 + u16::from(status[11] - b'0');
        if !(100..=599).contains(&code) || code == 101 { return Err(()); }
        let mut length = None;
        let mut transfer = false;
        let mut count = 0;
        for raw in lines {
            count += 1; if count > 64 { return Err(()); }
            let line = raw.strip_suffix(b"\r").unwrap_or(raw);
            if line.contains(&b'\r') { return Err(()); }
            let colon = line.iter().position(|b| *b == b':').ok_or(())?;
            let name = &line[..colon]; let value = trim(&line[colon+1..]);
            if !token(name) { return Err(()); }
            if name.eq_ignore_ascii_case(b"content-length") {
                if length.is_some() { return Err(()); }
                length = Some(decimal(value)?);
            } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                if transfer || !value.eq_ignore_ascii_case(b"chunked") { return Err(()); }
                transfer = true;
            }
        }
        if transfer && (length.is_some() || status.starts_with(b"HTTP/1.0 "))
            || (code < 200 || code == 204) && (transfer || length.is_some())
            || code == 205 && length.is_some_and(|n| n != 0) {
            return Err(());
        }
        if code < 200 {
            interim += 1; if interim > 8 { return Err(()); }
            offset += end + 4;
            continue;
        }
        return Ok(Some(code));
    }
}

pub(super) fn encode_outcome(e: &mut CanonicalEncoder, outcome: WebhookOutcome) {
    match outcome {
        WebhookOutcome::ReceiverAccepted(code) => { e.u8(0); e.u32(u32::from(code)); }
        WebhookOutcome::ReceiverStatus(code) => { e.u8(1); e.u32(u32::from(code)); }
        WebhookOutcome::Interrupted(reason) => {
            e.u8(2);
            let (tag, detail) = match reason {
                WebhookInterruption::Deadline => (0, 0),
                WebhookInterruption::Denied(reason) => (1, match reason {
                    WebhookDenial::Unauthorized => 0, WebhookDenial::Revoked => 1,
                    WebhookDenial::Cancelled => 2, WebhookDenial::Deadline => 3, WebhookDenial::Budget => 4,
                }),
                WebhookInterruption::ClockReversed => (8, 0),
                WebhookInterruption::EventAuthorityRefused => (2, 0), WebhookInterruption::Limit => (3, 0),
                WebhookInterruption::Io => (4, 0), WebhookInterruption::Disconnected => (5, 0),
                WebhookInterruption::InvalidResponse => (6, 0), WebhookInterruption::Retired => (7, 0),
            };
            e.u8(tag); e.u8(detail);
        }
    }
}
