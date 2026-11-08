#![forbid(unsafe_code)]
//! Private bounded decoding into read-only data, never into a live WebhookEvidence.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    EffectIntent,
};

use super::{MAX_WEBHOOK_OBSERVATION_BYTES, WebhookRetentionError};
use crate::webhook::{WebhookDenial, WebhookInterruption, WebhookOutcome, wire};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Observation {
    pub(super) intent: EffectIntent,
    pub(super) route: ContentDigest,
    pub(super) commitment_root: ContentDigest,
    pub(super) request: Vec<u8>,
    pub(super) response: Vec<u8>,
    pub(super) sent: usize,
    pub(super) calls: u64,
    pub(super) committed_ns: u64,
    pub(super) deadline_ns: u64,
    pub(super) last_admission_ns: u64,
    pub(super) outcome: WebhookOutcome,
}

impl Observation {
    pub(super) fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http-webhook-observation.v1");
        self.intent.encode_canonical(&mut e);
        e.digest(self.route);
        e.digest(self.commitment_root);
        e.bytes(&self.request);
        e.u64(self.sent as u64);
        e.bytes(&self.response);
        e.u64(self.calls);
        e.u64(self.committed_ns);
        e.u64(self.deadline_ns);
        e.u64(self.last_admission_ns);
        wire::encode_outcome(&mut e, self.outcome);
        ContentDigest::sha256(&e.finish())
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Observation, WebhookRetentionError> {
    if bytes.len() > MAX_WEBHOOK_OBSERVATION_BYTES {
        return Err(WebhookRetentionError::Budget);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.http-webhook-observation.v1" {
        return Err(WebhookRetentionError::Invalid);
    }
    let intent = EffectIntent::decode_canonical(&mut d)?;
    let route = d.digest()?;
    let commitment_root = d.digest()?;
    let request = d.bytes()?;
    let sent = usize::try_from(d.u64()?).map_err(|_| WebhookRetentionError::Invalid)?;
    let response = d.bytes()?;
    let calls = d.u64()?;
    let committed_ns = d.u64()?;
    let deadline_ns = d.u64()?;
    let last_admission_ns = d.u64()?;
    let outcome = outcome(&mut d)?;
    d.ensure_finished()?;
    if intent.effect_class != "alert.dispatch"
        || request.is_empty()
        || request.len() > 4096
        || response.len() > 16_384
        || sent > request.len()
        || calls > 4096
        || (calls == 0 && (sent != 0 || !response.is_empty()))
        || (!response.is_empty() && (sent != request.len() || calls < 4))
        || committed_ns >= deadline_ns
        || deadline_ns - committed_ns > 60_000_000_000
        || last_admission_ns < committed_ns
    {
        return Err(WebhookRetentionError::Invalid);
    }
    if let WebhookOutcome::ReceiverAccepted(status) | WebhookOutcome::ReceiverStatus(status) =
        outcome
    {
        if sent != request.len() || wire::response(response) != Ok(Some(status)) {
            return Err(WebhookRetentionError::Invalid);
        }
    }
    Ok(Observation {
        intent,
        route,
        commitment_root,
        request: request.to_vec(),
        response: response.to_vec(),
        sent,
        calls,
        committed_ns,
        deadline_ns,
        last_admission_ns,
        outcome,
    })
}

fn outcome(d: &mut CanonicalDecoder<'_>) -> Result<WebhookOutcome, WebhookRetentionError> {
    match d.u8()? {
        0 => {
            let code = d.u32()?;
            if !(200..=299).contains(&code) {
                return Err(WebhookRetentionError::Invalid);
            }
            Ok(WebhookOutcome::ReceiverAccepted(code as u16))
        }
        1 => {
            let code = d.u32()?;
            if !(300..=599).contains(&code) {
                return Err(WebhookRetentionError::Invalid);
            }
            Ok(WebhookOutcome::ReceiverStatus(code as u16))
        }
        2 => {
            let tag = d.u8()?;
            let detail = d.u8()?;
            let interruption = match (tag, detail) {
                (0, 0) => WebhookInterruption::Deadline,
                (1, 0) => WebhookInterruption::Denied(WebhookDenial::Unauthorized),
                (1, 1) => WebhookInterruption::Denied(WebhookDenial::Revoked),
                (1, 2) => WebhookInterruption::Denied(WebhookDenial::Cancelled),
                (1, 3) => WebhookInterruption::Denied(WebhookDenial::Deadline),
                (1, 4) => WebhookInterruption::Denied(WebhookDenial::Budget),
                (2, 0) => WebhookInterruption::EventAuthorityRefused,
                (3, 0) => WebhookInterruption::Limit,
                (4, 0) => WebhookInterruption::Io,
                (5, 0) => WebhookInterruption::Disconnected,
                (6, 0) => WebhookInterruption::InvalidResponse,
                (7, 0) => WebhookInterruption::Retired,
                (8, 0) => WebhookInterruption::ClockReversed,
                _ => return Err(WebhookRetentionError::Invalid),
            };
            Ok(WebhookOutcome::Interrupted(interruption))
        }
        _ => Err(WebhookRetentionError::Invalid),
    }
}
