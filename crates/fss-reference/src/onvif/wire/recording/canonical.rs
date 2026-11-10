#![forbid(unsafe_code)]
//! Bounded canonical information for a private, separately approved replay handoff.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use super::*;

fn invalid<T>(result: Result<T, fss_core::ContractError>) -> Result<T, WireError> {
    result.map_err(|_| WireError::InvalidField)
}
fn valid_uri(value: &str) -> Result<(), WireError> {
    if value.is_empty() || value.len() > super::super::MAX_URI_BYTES
        || value.chars().any(|c| c.is_control() || c.is_whitespace() || !xml::valid_char(c))
    { return Err(WireError::InvalidField); }
    Ok(())
}
fn validate_source(source: &RecordingSource) -> Result<(), WireError> {
    valid_uri(&source.source_id)?;
    valid_uri(&source.address)?;
    for text in [&source.name, &source.location, &source.description] { validate_text(text)?; }
    if let Some(token) = &source.video_source_token { reference(token)?; }
    Ok(())
}
fn validate_range(range: AdvertisedRecordingRange) -> Result<(), WireError> {
    if range.earliest_ns.into_iter().chain(range.latest_ns)
        .any(|n| !(0..=range::MAX_RECORDING_UTC_NS).contains(&n)) {
        return Err(WireError::InvalidField);
    }
    // Reversed bounds remain an explicit device contradiction.
    Ok(())
}
fn put_optional(e: &mut CanonicalEncoder, value: Option<i128>) {
    e.bool(value.is_some());
    if let Some(value) = value { e.i128(value); }
}
fn put_range(e: &mut CanonicalEncoder, range: AdvertisedRecordingRange) {
    put_optional(e, range.earliest_ns);
    put_optional(e, range.latest_ns);
}
fn put_source(e: &mut CanonicalEncoder, source: &RecordingSource) {
    for text in [&source.source_id, &source.name, &source.location, &source.description, &source.address] {
        e.text(text);
    }
    e.bool(source.video_source_token.is_some());
    if let Some(token) = &source.video_source_token { e.text(token); }
}
fn read_text(d: &mut CanonicalDecoder<'_>, bound: usize) -> Result<String, WireError> {
    let text = invalid(d.text())?;
    if text.len() > bound { return Err(WireError::InvalidField); }
    Ok(text.to_owned())
}
fn read_optional(d: &mut CanonicalDecoder<'_>) -> Result<Option<i128>, WireError> {
    if invalid(d.bool())? { Ok(Some(invalid(d.i128())?)) } else { Ok(None) }
}
fn read_range(d: &mut CanonicalDecoder<'_>) -> Result<AdvertisedRecordingRange, WireError> {
    Ok(AdvertisedRecordingRange { earliest_ns: read_optional(d)?, latest_ns: read_optional(d)? })
}
fn read_token(d: &mut CanonicalDecoder<'_>) -> Result<String, WireError> {
    let token = read_text(d, super::super::MAX_REFERENCE_CHARS * 4)?;
    reference(&token)?;
    Ok(token)
}
fn read_source(d: &mut CanonicalDecoder<'_>) -> Result<RecordingSource, WireError> {
    Ok(RecordingSource {
        source_id: read_text(d, super::super::MAX_URI_BYTES)?,
        name: read_text(d, MAX_RECORDING_DESCRIPTION_BYTES)?,
        location: read_text(d, MAX_RECORDING_DESCRIPTION_BYTES)?,
        description: read_text(d, MAX_RECORDING_DESCRIPTION_BYTES)?,
        address: read_text(d, super::super::MAX_URI_BYTES)?,
        video_source_token: if invalid(d.bool())? { Some(read_token(d)?) } else { None },
    })
}

impl RecordingInformation {
    fn validate_projection(&self) -> Result<(), WireError> {
        reference(&self.token)?;
        validate_source(&self.source)?;
        validate_text(&self.content)?;
        validate_range(self.range)?;
        if self.response_body_digest.algorithm() != DigestAlgorithm::Sha256
            || self.response_body_digest.bytes() == [0; 32] {
            return Err(WireError::InvalidField);
        }
        if self.tracks.len() > MAX_RECORDING_TRACKS { return Err(WireError::RecordingLimitExceeded); }
        for (at, track) in self.tracks.iter().enumerate() {
            reference(&track.token)?;
            validate_text(&track.description)?;
            validate_range(track.range)?;
            if self.tracks[..at].iter().any(|other| other.token == track.token) {
                return Err(WireError::DuplicateField);
            }
        }
        Ok(())
    }

    /// Exact bounded projection plus original SOAP-body identity. This does not retain remote
    /// extensions or elevate the device's state/timestamps to source evidence.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WireError> {
        self.validate_projection()?;
        let mut e = CanonicalEncoder::new();
        e.text(RECORDING_INFORMATION_DOMAIN);
        e.u32(1);
        e.digest(self.response_body_digest);
        e.text(&self.token);
        put_source(&mut e, &self.source);
        e.text(&self.content);
        put_range(&mut e, self.range);
        e.text(self.status.as_str());
        e.u32(self.tracks.len() as u32);
        for track in &self.tracks {
            e.text(&track.token);
            e.text(track.kind.as_str());
            e.text(&track.description);
            put_range(&mut e, track.range);
        }
        let bytes = invalid(e.finish_checked())?;
        if bytes.len() > MAX_RECORDING_INFORMATION_BYTES { return Err(WireError::InputTooLarge); }
        Ok(bytes)
    }

    /// Revalidate bounds, duplicates, enums and canonical equality on cold load.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_RECORDING_INFORMATION_BYTES { return Err(WireError::InputTooLarge); }
        let mut d = CanonicalDecoder::new(bytes);
        if invalid(d.text())? != RECORDING_INFORMATION_DOMAIN || invalid(d.u32())? != 1 {
            return Err(WireError::InvalidField);
        }
        let response_body_digest = invalid(d.digest())?;
        let token = read_token(&mut d)?;
        let source = read_source(&mut d)?;
        let content = read_text(&mut d, MAX_RECORDING_DESCRIPTION_BYTES)?;
        let range = read_range(&mut d)?;
        let status = status(invalid(d.text())?)?;
        let count = invalid(d.u32())? as usize;
        if count > MAX_RECORDING_TRACKS { return Err(WireError::RecordingLimitExceeded); }
        let mut tracks = Vec::with_capacity(count);
        for _ in 0..count {
            tracks.push(RecordingTrackInformation {
                token: read_token(&mut d)?,
                kind: track_type(invalid(d.text())?)?,
                description: read_text(&mut d, MAX_RECORDING_DESCRIPTION_BYTES)?,
                range: read_range(&mut d)?,
            });
        }
        invalid(d.ensure_finished())?;
        let result = Self { token, source, content, range, tracks, status, response_body_digest };
        if result.canonical_bytes()? != bytes { return Err(WireError::InvalidField); }
        Ok(result)
    }

    /// Canonical projection identity, including the exact original response-body identity.
    pub fn digest(&self) -> Result<ContentDigest, WireError> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }
}

impl RecordingServices {
    /// Bind selected advertisements and the complete original inventory body identity.
    pub fn digest(&self) -> Result<ContentDigest, WireError> {
        if self.response_body_digest.algorithm() != DigestAlgorithm::Sha256
            || self.response_body_digest.bytes() == [0; 32] {
            return Err(WireError::InvalidField);
        }
        let mut e = CanonicalEncoder::new();
        e.text(RECORDING_SERVICES_DOMAIN);
        e.digest(self.response_body_digest);
        for service in [&self.recording, &self.search, &self.replay] {
            e.bool(service.is_some());
            if let Some(service) = service {
                valid_uri(&service.xaddr)?;
                e.text(&service.xaddr);
                e.u32(u32::from(service.version.major));
                e.u32(u32::from(service.version.minor));
            }
        }
        Ok(ContentDigest::sha256(&invalid(e.finish_checked())?))
    }
}
