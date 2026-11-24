#![forbid(unsafe_code)]
//! Compact, reconstructible custody receipts for the finite MPEG-TS profile.
//!
//! The receipt commits to every original byte, the exact extracted elementary
//! stream, the parsing policy, and all PES timestamps and source mappings. It
//! carries no source bytes or effect authority. Loading a receipt checks its
//! canonical framing and checksum; only verification against the original
//! transport bytes establishes its extraction claims.
//!
//! Mapping tables are hashed in native order and reconstructed by the bounded
//! parser instead of duplicated in a potentially enormous metadata object.
//! Timestamps remain raw wrapping media values, never capture time.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm, Sha256Hasher};

use super::{MpegTsVideo, TsError, TsFraming, TsLimits, TsSelection, media_pid};
use crate::video_codec::VideoCodec;

/// Original 188-byte extraction contract; its canonical bytes remain unchanged.
pub const RECEIPT_SCHEMA: &str = "fss.mpeg_ts.extraction_receipt.v1";
/// Explicit M2TS physical framing contract. Standard TS continues to encode as v1.
pub const FRAMED_RECEIPT_SCHEMA: &str = "fss.mpeg_ts.extraction_receipt.v2";
const MAPPING_DOMAIN: &str = "fss.mpeg_ts.extraction_mapping.v1";
/// Hard ceiling for the fixed-size receipt, independent of source/map length.
pub const MAX_RECEIPT_BYTES: usize = 512;
const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Canonical extraction commitment; source custody is established separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TsExtractionReceipt {
    framing: TsFraming,
    source_digest: ContentDigest,
    source_bytes: u64,
    elementary_digest: ContentDigest,
    elementary_bytes: u64,
    mapping_digest: ContentDigest,
    codec: VideoCodec,
    program: u16,
    video_pid: u16,
    pcr_pid: u16,
    selection: TsSelection,
    limits: TsLimits,
    packets: u64,
    psi_sections: u64,
    duplicates: u64,
    pes_count: u64,
    span_count: u64,
}

impl TsExtractionReceipt {
    /// Commit to an extraction and the exact policy actually used to parse it.
    pub fn from_extraction(video: &MpegTsVideo<'_>) -> Result<Self, TsError> {
        Self::from_extraction_with_checkpoint(video, &mut || Ok(()))
    }

    /// Check cancellation between hash chunks and each PES/source-mapping row.
    pub fn from_extraction_with_checkpoint(
        video: &MpegTsVideo<'_>,
        checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
    ) -> Result<Self, TsError> {
        checkpoint()?;
        let receipt = Self {
            framing: video.framing(),
            source_digest: hash_bytes(video.source(), checkpoint)?,
            source_bytes: video.source().len() as u64,
            elementary_digest: hash_bytes(video.elementary_stream(), checkpoint)?,
            elementary_bytes: video.elementary_stream().len() as u64,
            mapping_digest: hash_mapping(video, checkpoint)?,
            codec: video.codec(),
            program: video.program(),
            video_pid: video.video_pid(),
            pcr_pid: video.pcr_pid(),
            selection: video.selection(),
            limits: video.limits(),
            packets: video.packets_inspected() as u64,
            psi_sections: video.psi_sections_inspected() as u64,
            duplicates: video.duplicate_packets() as u64,
            pes_count: video.pes().len() as u64,
            span_count: video.payload_spans().len() as u64,
        };
        receipt.validate()?;
        checkpoint()?;
        Ok(receipt)
    }

    /// Explicit physical framing of the committed source bytes.
    pub fn framing(&self) -> TsFraming {
        self.framing
    }
    /// Exact original-byte identity, including prefixes, unselected PIDs and duplicates.
    pub fn source_digest(&self) -> ContentDigest {
        self.source_digest
    }
    /// Number of original transport bytes.
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
    /// Exact reconstructed elementary-stream identity.
    pub fn elementary_digest(&self) -> ContentDigest {
        self.elementary_digest
    }
    /// Number of reconstructed elementary bytes.
    pub fn elementary_bytes(&self) -> u64 {
        self.elementary_bytes
    }
    /// Commitment to every PES boundary, raw PTS/DTS and exact payload mapping.
    pub fn mapping_digest(&self) -> ContentDigest {
        self.mapping_digest
    }
    /// Codec declared by the PMT; not a decoder qualification.
    pub fn codec(&self) -> VideoCodec {
        self.codec
    }
    /// Selected program number.
    pub fn program(&self) -> u16 {
        self.program
    }
    /// Selected elementary video PID.
    pub fn video_pid(&self) -> u16 {
        self.video_pid
    }
    /// Declared PCR PID; no clock accuracy or capture-time claim.
    pub fn pcr_pid(&self) -> u16 {
        self.pcr_pid
    }
    /// Exact original selection policy, including automatic versus explicit selection.
    pub fn selection(&self) -> TsSelection {
        self.selection
    }
    /// Historical parser ceilings; these do not grant current read authority.
    pub fn limits(&self) -> TsLimits {
        self.limits
    }
    /// Total inspected packets, including unselected PIDs and duplicates.
    pub fn packets_inspected(&self) -> u64 {
        self.packets
    }
    /// Number of PES records; a PES is not a frame.
    pub fn pes_count(&self) -> u64 {
        self.pes_count
    }
    /// Number of exact original-to-elementary spans.
    pub fn payload_span_count(&self) -> u64 {
        self.span_count
    }

    /// Encode a bounded canonical payload followed by its SHA-256 checksum.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TsError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        match self.framing {
            TsFraming::Ts188 => e.text(RECEIPT_SCHEMA),
            TsFraming::M2ts192 => {
                e.text(FRAMED_RECEIPT_SCHEMA);
                e.u8(2);
            }
        }
        encode_selection(&mut e, self.selection);
        encode_limits(&mut e, self.limits);
        e.digest(self.source_digest);
        e.u64(self.source_bytes);
        e.digest(self.elementary_digest);
        e.u64(self.elementary_bytes);
        e.digest(self.mapping_digest);
        e.u8(match self.codec {
            VideoCodec::Avc => 1,
            VideoCodec::Hevc => 2,
        });
        for value in [self.program, self.video_pid, self.pcr_pid] {
            e.u32(u32::from(value));
        }
        for value in [
            self.packets,
            self.psi_sections,
            self.duplicates,
            self.pes_count,
            self.span_count,
        ] {
            e.u64(value);
        }
        let mut bytes = e.finish_checked().map_err(|_| TsError::Receipt)?;
        if bytes.len() > MAX_RECEIPT_BYTES - 32 {
            return Err(TsError::Limit);
        }
        let checksum = ContentDigest::sha256(&bytes);
        bytes
            .try_reserve_exact(32)
            .map_err(|_| TsError::Allocation)?;
        bytes.extend_from_slice(&checksum.bytes());
        Ok(bytes)
    }

    /// Check canonical framing, fixed resource bounds and checksum without reading source.
    ///
    /// A valid encoding is not proof that the declared extraction occurred.
    /// Call a verification method before using its provenance claims.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TsError> {
        if bytes.len() < 32 || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(TsError::Receipt);
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if ContentDigest::sha256(payload).bytes().as_slice() != checksum {
            return Err(TsError::Receipt);
        }
        let mut d = CanonicalDecoder::new(payload);
        let framing = match d.text().map_err(|_| TsError::Receipt)? {
            RECEIPT_SCHEMA => TsFraming::Ts188,
            FRAMED_RECEIPT_SCHEMA => match d.u8().map_err(|_| TsError::Receipt)? {
                2 => TsFraming::M2ts192,
                // No alternate v2 encoding of v1 TS: each policy has one identity.
                _ => return Err(TsError::Receipt),
            },
            _ => return Err(TsError::Receipt),
        };
        let selection = TsSelection {
            program: decode_optional_u16(&mut d)?,
            video_pid: decode_optional_u16(&mut d)?,
        };
        let limits = TsLimits {
            max_input_bytes: decode_usize(&mut d)?,
            max_packets: decode_usize(&mut d)?,
            max_psi_sections: decode_usize(&mut d)?,
            max_pes: decode_usize(&mut d)?,
            max_pes_bytes: decode_usize(&mut d)?,
            max_payload_spans: decode_usize(&mut d)?,
            max_elementary_bytes: decode_usize(&mut d)?,
        };
        let source_digest = decode_digest(&mut d)?;
        let source_bytes = decode_u64(&mut d)?;
        let elementary_digest = decode_digest(&mut d)?;
        let elementary_bytes = decode_u64(&mut d)?;
        let mapping_digest = decode_digest(&mut d)?;
        let codec = match d.u8().map_err(|_| TsError::Receipt)? {
            1 => VideoCodec::Avc,
            2 => VideoCodec::Hevc,
            _ => return Err(TsError::Receipt),
        };
        let receipt = Self {
            framing,
            source_digest,
            source_bytes,
            elementary_digest,
            elementary_bytes,
            mapping_digest,
            codec,
            program: decode_u16(&mut d)?,
            video_pid: decode_u16(&mut d)?,
            pcr_pid: decode_u16(&mut d)?,
            selection,
            limits,
            packets: decode_u64(&mut d)?,
            psi_sections: decode_u64(&mut d)?,
            duplicates: decode_u64(&mut d)?,
            pes_count: decode_u64(&mut d)?,
            span_count: decode_u64(&mut d)?,
        };
        d.ensure_finished().map_err(|_| TsError::Receipt)?;
        receipt.validate()?;
        // The fixed field grammar is injective; this also guards later changes.
        if receipt.to_bytes()? != bytes {
            return Err(TsError::Receipt);
        }
        Ok(receipt)
    }

    /// Reconstruct and verify under the recorded limits.
    ///
    /// The caller must separately authorize the original read and admit these
    /// historical limits. Use the bounded variant to narrow present resource policy.
    pub fn verify_with_checkpoint<'a>(
        &self,
        source: &'a [u8],
        checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
    ) -> Result<MpegTsVideo<'a>, TsError> {
        self.verify_bounded_with_checkpoint(source, self.limits, checkpoint)
    }

    /// Reconstruct under the intersection of historical and current ceilings.
    ///
    /// The entire original, elementary output, selection, tables and map must
    /// match. A narrower current allowance cannot be enlarged by receipt data.
    /// No result is returned after cancellation or a failed final comparison.
    pub fn verify_bounded_with_checkpoint<'a>(
        &self,
        source: &'a [u8],
        current_limits: TsLimits,
        checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
    ) -> Result<MpegTsVideo<'a>, TsError> {
        self.validate()?;
        current_limits.validate()?;
        checkpoint()?;
        if source.len() as u64 != self.source_bytes {
            return Err(TsError::Receipt);
        }
        let limits = intersect(self.limits, current_limits);
        let video = MpegTsVideo::parse_framed_with_checkpoint(
            source,
            self.framing,
            self.selection,
            limits,
            checkpoint,
        )?;
        let mut observed = Self::from_extraction_with_checkpoint(&video, checkpoint)?;
        // The historical policy remains part of receipt identity. Successful
        // parsing above independently proves admission under the current ceiling.
        observed.limits = self.limits;
        if observed != *self {
            return Err(TsError::Receipt);
        }
        checkpoint()?;
        Ok(video)
    }

    fn validate(&self) -> Result<(), TsError> {
        self.limits.validate().map_err(|_| TsError::Receipt)?;
        if self.source_digest.algorithm() != DigestAlgorithm::Sha256
            || self.elementary_digest.algorithm() != DigestAlgorithm::Sha256
            || self.mapping_digest.algorithm() != DigestAlgorithm::Sha256
            || self.source_bytes == 0
            || self.source_bytes > self.limits.max_input_bytes as u64
            || !self
                .source_bytes
                .is_multiple_of(self.framing.packet_bytes() as u64)
            || self.packets != self.source_bytes / self.framing.packet_bytes() as u64
            || self.packets > self.limits.max_packets as u64
            || self.psi_sections < 2
            || self.psi_sections > self.limits.max_psi_sections as u64
            || self.duplicates >= self.packets
            || self.elementary_bytes == 0
            || self.elementary_bytes >= self.source_bytes
            || self.elementary_bytes > self.limits.max_elementary_bytes as u64
            || self.pes_count == 0
            || self.pes_count > self.limits.max_pes as u64
            || self.span_count < self.pes_count
            || self.span_count > self.limits.max_payload_spans as u64
            || self.span_count > self.packets
            || self.program == 0
            || !media_pid(self.video_pid)
            || !(media_pid(self.pcr_pid) || self.pcr_pid == 0x1fff)
            || self
                .selection
                .program
                .is_some_and(|value| value != self.program)
            || self
                .selection
                .video_pid
                .is_some_and(|value| value != self.video_pid)
        {
            return Err(TsError::Receipt);
        }
        Ok(())
    }
}

fn intersect(a: TsLimits, b: TsLimits) -> TsLimits {
    TsLimits {
        max_input_bytes: a.max_input_bytes.min(b.max_input_bytes),
        max_packets: a.max_packets.min(b.max_packets),
        max_psi_sections: a.max_psi_sections.min(b.max_psi_sections),
        max_pes: a.max_pes.min(b.max_pes),
        max_pes_bytes: a.max_pes_bytes.min(b.max_pes_bytes),
        max_payload_spans: a.max_payload_spans.min(b.max_payload_spans),
        max_elementary_bytes: a.max_elementary_bytes.min(b.max_elementary_bytes),
    }
}

fn encode_selection(e: &mut CanonicalEncoder, selection: TsSelection) {
    for value in [selection.program, selection.video_pid] {
        e.bool(value.is_some());
        if let Some(value) = value {
            e.u32(u32::from(value));
        }
    }
}

fn encode_limits(e: &mut CanonicalEncoder, limits: TsLimits) {
    for value in [
        limits.max_input_bytes,
        limits.max_packets,
        limits.max_psi_sections,
        limits.max_pes,
        limits.max_pes_bytes,
        limits.max_payload_spans,
        limits.max_elementary_bytes,
    ] {
        e.u64(value as u64);
    }
}

fn decode_u64(d: &mut CanonicalDecoder<'_>) -> Result<u64, TsError> {
    d.u64().map_err(|_| TsError::Receipt)
}
fn decode_usize(d: &mut CanonicalDecoder<'_>) -> Result<usize, TsError> {
    usize::try_from(decode_u64(d)?).map_err(|_| TsError::Receipt)
}
fn decode_u16(d: &mut CanonicalDecoder<'_>) -> Result<u16, TsError> {
    u16::try_from(d.u32().map_err(|_| TsError::Receipt)?).map_err(|_| TsError::Receipt)
}
fn decode_optional_u16(d: &mut CanonicalDecoder<'_>) -> Result<Option<u16>, TsError> {
    if d.bool().map_err(|_| TsError::Receipt)? {
        Ok(Some(decode_u16(d)?))
    } else {
        Ok(None)
    }
}
fn decode_digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, TsError> {
    let value = d.digest().map_err(|_| TsError::Receipt)?;
    if value.algorithm() != DigestAlgorithm::Sha256 {
        return Err(TsError::Receipt);
    }
    Ok(value)
}

fn finish_hash(hasher: Sha256Hasher) -> Result<ContentDigest, TsError> {
    hasher
        .finalize()
        .map(|bytes| ContentDigest::new(DigestAlgorithm::Sha256, bytes))
        .map_err(|_| TsError::Limit)
}

fn hash_bytes(
    bytes: &[u8],
    checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
) -> Result<ContentDigest, TsError> {
    let mut hasher = Sha256Hasher::new();
    for chunk in bytes.chunks(HASH_CHUNK_BYTES) {
        checkpoint()?;
        hasher.update(chunk);
    }
    finish_hash(hasher)
}

fn hash_mapping(
    video: &MpegTsVideo<'_>,
    checkpoint: &mut dyn FnMut() -> Result<(), TsError>,
) -> Result<ContentDigest, TsError> {
    let mut header = CanonicalEncoder::new();
    header.text(MAPPING_DOMAIN);
    header.u64(video.pes().len() as u64);
    let mut hasher = Sha256Hasher::new();
    hasher.update(&header.finish_checked().map_err(|_| TsError::Receipt)?);
    for pes in video.pes() {
        checkpoint()?;
        for value in [
            pes.elementary.start,
            pes.elementary.end,
            pes.source_spans.start,
            pes.source_spans.end,
        ] {
            hasher.update(&(value as u64).to_be_bytes());
        }
        for time in [pes.pts, pes.dts] {
            hasher.update(&[u8::from(time.is_some())]);
            if let Some(time) = time {
                hasher.update(&time.to_be_bytes());
            }
        }
    }
    hasher.update(&(video.payload_spans().len() as u64).to_be_bytes());
    for span in video.payload_spans() {
        checkpoint()?;
        for value in [
            span.source.start,
            span.source.end,
            span.elementary.start,
            span.elementary.end,
            span.pes,
        ] {
            hasher.update(&(value as u64).to_be_bytes());
        }
    }
    finish_hash(hasher)
}

#[cfg(test)]
mod tests;
