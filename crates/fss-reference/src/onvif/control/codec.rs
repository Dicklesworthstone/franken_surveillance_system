#![forbid(unsafe_code)]
//! Frozen canonical subscription-control records. No JSON or implicit reinterpretation.

use std::net::SocketAddr;

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm, SensorId,
    TimestampNs,
};

use super::{
    CREATED_DOMAIN, CreateIntentBinding, INTENT_DOMAIN, MAX_CONTROL_RECORD_BYTES, PARSER_GENERATION,
};
use crate::onvif::http::HttpRoute;
use crate::onvif::metadata::{MAX_SOURCE_BYTES, MetadataError, SourceBinding};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct IntentRecord {
    pub(super) site: String,
    pub(super) binding: CreateIntentBinding,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct CreatedRecord {
    pub(super) intent: ContentDigest,
    pub(super) completed_ns: u64,
    pub(super) client_authenticated: bool,
    pub(super) source: ContentDigest,
    pub(super) source_bytes: usize,
}

pub(super) fn encode_intent(record: &IntentRecord) -> Result<Vec<u8>, MetadataError> {
    record.binding.validate()?;
    if record.site.is_empty()
        || record.site.len() > 256
        || record.site.trim() != record.site
        || record.site.chars().any(char::is_control)
    {
        return Err(MetadataError::InvalidBinding);
    }
    let binding = &record.binding;
    let mut e = CanonicalEncoder::new();
    e.text(INTENT_DOMAIN);
    e.text(PARSER_GENERATION);
    e.text(&record.site);
    e.text(binding.source.sensor_id.as_str());
    e.digest(binding.source.device_generation);
    e.digest(binding.source.profile_generation);
    e.text(&binding.source.profile_token);
    e.i128(binding.source.receive_interval.earliest.0);
    e.text(&binding.events.peer().to_string());
    e.text(binding.events.authority());
    e.text(binding.events.target());
    e.u64(binding.events.generation());
    e.digest(binding.events.plaintext_approval());
    e.text(&binding.service_root);
    e.text(&binding.message_id);
    e.u64(binding.started_ns);
    e.u64(u64::from(binding.lifetime_seconds));
    bounded(e)
}

pub(super) fn decode_intent(bytes: &[u8]) -> Result<IntentRecord, MetadataError> {
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != INTENT_DOMAIN || d.text()? != PARSER_GENERATION {
        return Err(MetadataError::Custody);
    }
    let site = d.text()?.to_owned();
    let sensor_id = SensorId::parse(d.text()?)?;
    let device_generation = d.digest()?;
    let profile_generation = d.digest()?;
    let profile_token = d.text()?.to_owned();
    let time = TimestampNs(d.i128()?);
    let source = SourceBinding {
        sensor_id,
        device_generation,
        profile_generation,
        profile_token,
        receive_interval: CaptureInterval::new(time, time)?,
    };
    let peer = d
        .text()?
        .parse::<SocketAddr>()
        .map_err(|_| MetadataError::Custody)?;
    let authority = d.text()?.to_owned();
    let target = d.text()?.to_owned();
    let generation = d.u64()?;
    let approval = d.digest()?;
    let events = HttpRoute::event_service(peer, &authority, &target, generation, approval)
        .map_err(|_| MetadataError::Custody)?;
    let service_root = d.text()?.to_owned();
    let message_id = d.text()?.to_owned();
    let started_ns = d.u64()?;
    let lifetime_seconds = u32::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?;
    d.ensure_finished()?;
    let record = IntentRecord {
        site,
        binding: CreateIntentBinding {
            source,
            events,
            service_root,
            message_id,
            started_ns,
            lifetime_seconds,
        },
    };
    if encode_intent(&record)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(record)
}

pub(super) fn encode_created(record: &CreatedRecord) -> Result<Vec<u8>, MetadataError> {
    if record.intent.algorithm() != DigestAlgorithm::Sha256
        || record.intent.bytes() == [0; 32]
        || record.source.algorithm() != DigestAlgorithm::Sha256
        || record.source.bytes() == [0; 32]
        || record.source_bytes == 0
        || record.source_bytes > MAX_SOURCE_BYTES
    {
        return Err(MetadataError::InvalidBinding);
    }
    let mut e = CanonicalEncoder::new();
    e.text(CREATED_DOMAIN);
    e.text(PARSER_GENERATION);
    e.digest(record.intent);
    e.u64(record.completed_ns);
    e.bool(record.client_authenticated);
    e.digest(record.source);
    e.u64(record.source_bytes as u64);
    bounded(e)
}

pub(super) fn decode_created(bytes: &[u8]) -> Result<CreatedRecord, MetadataError> {
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != CREATED_DOMAIN || d.text()? != PARSER_GENERATION {
        return Err(MetadataError::Custody);
    }
    let record = CreatedRecord {
        intent: d.digest()?,
        completed_ns: d.u64()?,
        client_authenticated: d.bool()?,
        source: d.digest()?,
        source_bytes: usize::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
    };
    d.ensure_finished()?;
    if encode_created(&record)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(record)
}

fn bounded(encoder: CanonicalEncoder) -> Result<Vec<u8>, MetadataError> {
    let bytes = encoder.finish_checked()?;
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}
