#![forbid(unsafe_code)]
//! Frozen canonical renewal records, distinct from Create and terminal observations.

use super::{RENEW_INTENT_DOMAIN, RENEWED_DOMAIN, RenewIntentBinding, RenewOutcomeBinding};
use crate::onvif::control::{MAX_CONTROL_RECORD_BYTES, PARSER_GENERATION};
use crate::onvif::http::HttpRoute;
use crate::onvif::metadata::{MAX_SOURCE_BYTES, MetadataError};
use crate::onvif::pullpoint::MAX_RENEWALS;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs};
use std::net::SocketAddr;

#[derive(Clone)]
pub(super) struct IntentRecord {
    pub(super) subscription: ContentDigest,
    pub(super) binding: RenewIntentBinding,
}
#[derive(Clone)]
pub(super) struct OutcomeRecord {
    pub(super) intent: ContentDigest,
    pub(super) binding: RenewOutcomeBinding,
    pub(super) source: ContentDigest,
    pub(super) source_bytes: usize,
}

pub(super) fn encode_intent(record: &IntentRecord) -> Result<Vec<u8>, MetadataError> {
    digest(record.subscription)?;
    let binding = &record.binding;
    if binding.message_id.len() > 256
        || binding.renewal_index >= MAX_RENEWALS
        || !(1..=3600).contains(&binding.lifetime_seconds)
    {
        return Err(MetadataError::InvalidBinding);
    }
    let mut e = CanonicalEncoder::new();
    e.text(RENEW_INTENT_DOMAIN);
    e.text(PARSER_GENERATION);
    e.digest(record.subscription);
    e.text(&binding.route.peer().to_string());
    e.text(binding.route.authority());
    e.text(binding.route.target());
    e.u64(binding.route.generation());
    e.digest(binding.route.plaintext_approval());
    e.text(&binding.message_id);
    e.u64(binding.started_ns);
    e.i128(binding.receive_time.0);
    e.u64(u64::from(binding.lifetime_seconds));
    e.u64(u64::from(binding.renewal_index));
    bounded(e)
}
pub(super) fn decode_intent(bytes: &[u8]) -> Result<IntentRecord, MetadataError> {
    let mut d = decoder(bytes, RENEW_INTENT_DOMAIN)?;
    let subscription = d.digest()?;
    let peer = d
        .text()?
        .parse::<SocketAddr>()
        .map_err(|_| MetadataError::Custody)?;
    let authority = d.text()?.to_owned();
    let target = d.text()?.to_owned();
    let generation = d.u64()?;
    let approval = d.digest()?;
    let route = HttpRoute::event_service(peer, &authority, &target, generation, approval)
        .map_err(|_| MetadataError::Custody)?;
    let record = IntentRecord {
        subscription,
        binding: RenewIntentBinding {
            route,
            message_id: d.text()?.to_owned(),
            started_ns: d.u64()?,
            receive_time: TimestampNs(d.i128()?),
            lifetime_seconds: u32::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
            renewal_index: u32::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
        },
    };
    d.ensure_finished()?;
    if encode_intent(&record)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(record)
}
pub(super) fn encode_outcome(record: &OutcomeRecord) -> Result<Vec<u8>, MetadataError> {
    digest(record.intent)?;
    digest(record.source)?;
    if record.source_bytes > MAX_SOURCE_BYTES || !(100..=599).contains(&record.binding.http_status)
    {
        return Err(MetadataError::InvalidBinding);
    }
    let mut e = CanonicalEncoder::new();
    e.text(RENEWED_DOMAIN);
    e.text(PARSER_GENERATION);
    e.digest(record.intent);
    e.bool(record.binding.completed_ns.is_some());
    if let Some(completed) = record.binding.completed_ns {
        e.u64(completed);
    }
    e.bool(record.binding.client_authenticated);
    e.u64(u64::from(record.binding.http_status));
    e.bool(record.binding.soap_content_type);
    e.digest(record.source);
    e.u64(record.source_bytes as u64);
    bounded(e)
}
pub(super) fn decode_outcome(bytes: &[u8]) -> Result<OutcomeRecord, MetadataError> {
    let mut d = decoder(bytes, RENEWED_DOMAIN)?;
    let intent = d.digest()?;
    let completed_ns = if d.bool()? { Some(d.u64()?) } else { None };
    let record = OutcomeRecord {
        intent,
        binding: RenewOutcomeBinding {
            completed_ns,
            client_authenticated: d.bool()?,
            http_status: u16::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
            soap_content_type: d.bool()?,
        },
        source: d.digest()?,
        source_bytes: usize::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
    };
    d.ensure_finished()?;
    if encode_outcome(&record)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(record)
}
fn decoder<'a>(bytes: &'a [u8], domain: &str) -> Result<CanonicalDecoder<'a>, MetadataError> {
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != domain || d.text()? != PARSER_GENERATION {
        return Err(MetadataError::Custody);
    }
    Ok(d)
}
fn digest(digest: ContentDigest) -> Result<(), MetadataError> {
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        Err(MetadataError::InvalidBinding)
    } else {
        Ok(())
    }
}
fn bounded(e: CanonicalEncoder) -> Result<Vec<u8>, MetadataError> {
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}
