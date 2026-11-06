#![forbid(unsafe_code)]
//! Bounded, source-linked FLV segment publication preparation.
//!
//! Preparation is entirely in memory: it neither stores data nor authorizes
//! storage, attests the camera, proves stream continuity, or supplies capture
//! time. The selected FLV framing policy remains an untrusted heuristic.

use std::{collections::BTreeSet, fmt};

use fss_container::InitializationSegment;
use fss_core::{CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;
use fss_packet::extended_flv::stream::{RecordKind, SourceRecord};

use super::recording::Segment;

pub(super) const DOMAIN: &str = "fss.unifi-direct.flv-segment-evidence.v1";
pub(super) const KIND: &str = "unifi-direct-flv-segment-v1";

/// Independently chosen ceilings for processing one in-memory segment.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Total original, witness, and derivative bytes hashed; at most 256 MiB.
    pub max_bytes: usize,
    /// Number of source and witness records; at most 8,192.
    pub max_records: usize,
    /// Number of mapped NALs; at most 65,536.
    pub max_nals: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 128 * 1024 * 1024,
            max_records: 8_192,
            max_nals: 65_536,
        }
    }
}

/// Payload-free refusal to prepare an internally consistent evidence graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input exceeds a bound, including the manifest child limit.
    Limit,
    /// Configuration, source continuity, or a source-to-derivative mapping differs.
    Mismatch,
    /// Canonical encoding or object-manifest construction failed.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi FLV evidence preparation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A graph candidate borrowing all source and derivative bytes. It is not a
/// durable receipt and cannot confer permission to retain or disclose media.
pub struct Prepared<'a> {
    segment: &'a Segment,
    configuration: &'a SourceRecord,
    initialization: &'a InitializationSegment,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
    retention: ContentDigest,
    capture: Option<CaptureInterval>,
}
impl fmt::Debug for Prepared<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("root", &self.manifest.root())
            .finish_non_exhaustive()
    }
}
impl<'a> Prepared<'a> {
    /// Verify and describe exact borrowed originals and derivatives. `retention`
    /// identifies a separate policy decision; a digest is not itself authority.
    pub fn new(
        segment: &'a Segment,
        configuration: &'a SourceRecord,
        initialization: &'a InitializationSegment,
        retention: ContentDigest,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new_with_capture(
            segment,
            configuration,
            initialization,
            retention,
            None,
            limits,
        )
    }
    /// Prepare with independently established physical capture bounds. Receive
    /// time and the FLV media clock do not establish these bounds. `None`
    /// preserves uncertainty and cannot be committed to the capture ledger.
    pub fn new_with_capture(
        segment: &'a Segment,
        configuration: &'a SourceRecord,
        initialization: &'a InitializationSegment,
        retention: ContentDigest,
        capture: Option<CaptureInterval>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if capture.is_some_and(|v| v.earliest > v.latest) {
            return Err(Error::Mismatch);
        }
        if !(1..=256 * 1024 * 1024).contains(&limits.max_bytes)
            || !(1..=8_192).contains(&limits.max_records)
            || !(1..=65_536).contains(&limits.max_nals)
            || retention.algorithm() != DigestAlgorithm::Sha256
            || retention.bytes() == [0; 32]
            || retention.is_laboratory()
        {
            return Err(Error::Limit);
        }
        let fragment = segment.fragment();
        let binding = segment.configuration();
        if configuration.offset() != binding.source_offset
            || configuration.bytes().len() != binding.source_bytes
            || ContentDigest::sha256(configuration.bytes()) != binding.source_digest
            || ContentDigest::sha256(initialization.bytes()) != binding.initialization_digest
        {
            return Err(Error::Mismatch);
        }
        let source = segment.source();
        let witness = segment.lookahead_copies();
        if source.is_empty()
            || witness.is_empty()
            || source
                .len()
                .checked_add(witness.len())
                .is_none_or(|n| n > limits.max_records)
            || fragment.nals().len() > limits.max_nals
        {
            return Err(Error::Limit);
        }
        let mut total = configuration
            .bytes()
            .len()
            .checked_add(initialization.bytes().len())
            .and_then(|n| n.checked_add(fragment.bytes().len()))
            .ok_or(Error::Limit)?;
        let mut next = source[0].offset();
        for record in source.iter().chain(witness) {
            if record.offset() != next || record.bytes().is_empty() {
                return Err(Error::Mismatch);
            }
            next = next
                .checked_add(u64::try_from(record.bytes().len()).map_err(|_| Error::Limit)?)
                .ok_or(Error::Limit)?;
            total = total
                .checked_add(record.bytes().len())
                .ok_or(Error::Limit)?;
        }
        if total > limits.max_bytes {
            return Err(Error::Limit);
        }
        let mut record_index = 0;
        for nal in fragment.nals() {
            while record_index < source.len() {
                let record = &source[record_index];
                let end = record
                    .offset()
                    .checked_add(record.bytes().len() as u64)
                    .ok_or(Error::Limit)?;
                if nal.source.start < end {
                    break;
                }
                record_index += 1;
            }
            let record = source.get(record_index).ok_or(Error::Mismatch)?;
            let begin = usize::try_from(
                nal.source
                    .start
                    .checked_sub(record.offset())
                    .ok_or(Error::Mismatch)?,
            )
            .map_err(|_| Error::Limit)?;
            let end = usize::try_from(
                nal.source
                    .end
                    .checked_sub(record.offset())
                    .ok_or(Error::Mismatch)?,
            )
            .map_err(|_| Error::Limit)?;
            if begin >= end
                || record.bytes().get(begin..end) != fragment.bytes().get(nal.target.clone())
                || fragment.bytes().get(nal.target.clone()).is_none()
            {
                return Err(Error::Mismatch);
            }
        }
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.digest(retention);
        match capture {
            Some(v) => {
                e.bool(true);
                e.i128(v.earliest.0);
                e.i128(v.latest.0);
            }
            None => e.bool(false),
        }
        let key = fragment.key();
        e.u64(key.connection);
        e.u64(key.generation);
        e.u32(fragment.sequence());
        encode_record(&mut e, configuration);
        e.digest(ContentDigest::sha256(initialization.bytes()));
        e.u64(initialization.bytes().len() as u64);
        e.digest(ContentDigest::sha256(fragment.bytes()));
        e.u64(fragment.bytes().len() as u64);
        e.u64(source.len() as u64);
        for record in source {
            encode_record(&mut e, record);
        }
        e.u64(witness.len() as u64);
        for record in witness {
            encode_record(&mut e, record);
        }
        e.u64(fragment.samples().len() as u64);
        for sample in fragment.samples() {
            e.u64(sample.target.start as u64);
            e.u64(sample.target.end as u64);
            e.u64(sample.decode_time_ms);
            e.i128(i128::from(sample.composition_offset_ms));
            e.u32(sample.duration_ms);
            e.bool(sample.idr);
            e.u64(sample.nals.start as u64);
            e.u64(sample.nals.end as u64);
        }
        e.u64(fragment.nals().len() as u64);
        for nal in fragment.nals() {
            e.u64(nal.sample as u64);
            e.u64(nal.source.start);
            e.u64(nal.source.end);
            e.u64(nal.target.start as u64);
            e.u64(nal.target.end as u64);
        }
        match fragment.timeline_gap() {
            Some(gap) => {
                e.bool(true);
                e.u64(gap.start);
                e.u64(gap.end);
            }
            None => e.bool(false),
        }
        let metadata = e.finish_checked().map_err(|_| Error::Encoding)?;
        let metadata_digest = ContentDigest::sha256(&metadata);
        let mut children = BTreeSet::new();
        children.insert(binding.source_digest);
        children.insert(binding.initialization_digest);
        children.insert(ContentDigest::sha256(fragment.bytes()));
        for record in source.iter().chain(witness) {
            children.insert(ContentDigest::sha256(record.bytes()));
        }
        children.remove(&metadata_digest);
        let manifest = ObjectManifest::new(KIND, children, Some(metadata_digest))
            .map_err(|_| Error::Encoding)?;
        Ok(Self {
            segment,
            configuration,
            initialization,
            metadata,
            manifest,
            retention,
            capture,
        })
    }
    pub(super) fn retention(&self) -> ContentDigest {
        self.retention
    }
    pub(super) fn capture(&self) -> Option<CaptureInterval> {
        self.capture
    }
    pub(super) fn segment(&self) -> &Segment {
        self.segment
    }
    pub(super) fn initialization(&self) -> &InitializationSegment {
        self.initialization
    }
    pub(super) fn payloads(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.configuration.bytes())
            .chain(
                self.segment
                    .source()
                    .iter()
                    .chain(self.segment.lookahead_copies())
                    .map(SourceRecord::bytes),
            )
            .chain([
                self.initialization.bytes(),
                self.segment.fragment().bytes(),
                self.metadata.as_slice(),
            ])
    }
    /// Candidate graph. Publication and a durable receipt require separate work.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    /// Canonical source descriptions, timing and exact source-to-MP4 mappings.
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
    /// Visit every graph payload. This does not authorize or perform I/O.
    /// Identical payloads may be visited more than once.
    pub fn visit_objects(&self, mut visitor: impl FnMut(ContentDigest, &[u8])) {
        let mut visit = |bytes: &[u8]| visitor(ContentDigest::sha256(bytes), bytes);
        visit(self.configuration.bytes());
        for record in self
            .segment
            .source()
            .iter()
            .chain(self.segment.lookahead_copies())
        {
            visit(record.bytes());
        }
        visit(self.initialization.bytes());
        visit(self.segment.fragment().bytes());
        visit(&self.metadata);
    }
}

pub(super) fn encode_record(e: &mut CanonicalEncoder, record: &SourceRecord) {
    e.u64(record.offset());
    e.u64(record.bytes().len() as u64);
    e.digest(ContentDigest::sha256(record.bytes()));
    match record.kind() {
        RecordKind::Header => e.u8(0),
        RecordKind::FirstTag {
            tag_kind,
            timestamp_ms,
        } => {
            e.u8(1);
            e.u8(tag_kind);
            e.u32(timestamp_ms);
        }
        RecordKind::Candidate {
            trailer_bytes,
            tag_kind,
            timestamp_ms,
            earlier_incomplete,
            provisional,
            policy,
        } => {
            e.u8(2);
            e.u64(trailer_bytes as u64);
            e.u8(tag_kind);
            e.u32(timestamp_ms);
            e.bool(earlier_incomplete);
            e.bool(provisional);
            e.u8(policy.evidence_id());
        }
    }
}
