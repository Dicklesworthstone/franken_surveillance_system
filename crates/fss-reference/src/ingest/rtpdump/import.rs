#![forbid(unsafe_code)]
//! Recorded-RTP source custody, access-unit sensor capsules, and ledger publication.
//!
//! NAL reconstruction is NOT picture decoding. Every capsule here explicitly has
//! frame_count == 0 and binds exact ORIGINAL record bytes, not synthesized NALs.

use super::{RtpDumpError, RtpDumpFault, RtpDumpKind, replay::*};
use crate::ingest::file_adapter::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};
use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CapsuleId, CaptureInterval, ClockBasis,
    ContentDigest, ContractError, EvidenceDelta, LedgerAnchor, ObjectId, Plane, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::{ObjectManifest, SpoolError};
use fss_packet::{
    ContinuityError, FragmentDiscard, H264Error, H264Mode, H264Status, PacketError, RtcpMode,
    SequenceClass, SequenceObservation, SequenceStats,
};
use fss_publication::{LocalPublicationError, LocalPublicationState, SlotName};
use std::{
    fs::File,
    io::{ErrorKind, Read},
    ops::Range,
};

/// Independent limits for retained derivatives, mappings, index and source-object staging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpImportLimits {
    /// Exact original-file custody chunk size (1 byte..16 MiB).
    pub chunk_bytes: usize,
    /// Maximum complete transport NALs/capsules (1..2,048), not decoded pictures.
    pub max_nals: usize,
    /// Maximum total source spans across complete NALs (1..65,536).
    pub max_source_spans: usize,
    /// Maximum retained reconstructed NAL bytes (1 byte..64 MiB).
    pub max_derived_bytes: usize,
    /// Maximum canonical report bytes (1 byte..16 MiB).
    pub max_report_bytes: usize,
    /// Sum of candidate payload bytes including duplicate envelopes (1 byte..256 MiB).
    /// Not a physical storage or RSS promise; it bounds conservative staging work.
    pub max_payload_bytes: usize,
}
impl Default for RtpImportLimits {
    fn default() -> Self {
        Self {
            chunk_bytes: 1024 * 1024,
            max_nals: 1024,
            max_source_spans: 65536,
            max_derived_bytes: 32 * 1024 * 1024,
            max_report_bytes: 8 * 1024 * 1024,
            max_payload_bytes: 128 * 1024 * 1024,
        }
    }
}
impl RtpImportLimits {
    fn validate(self) -> Result<(), RtpImportError> {
        if !(1..=16 * 1024 * 1024).contains(&self.chunk_bytes)
            || !(1..=2048).contains(&self.max_nals)
            || !(1..=65536).contains(&self.max_source_spans)
            || !(1..=64 * 1024 * 1024).contains(&self.max_derived_bytes)
            || !(1..=16 * 1024 * 1024).contains(&self.max_report_bytes)
            || !(1..=256 * 1024 * 1024).contains(&self.max_payload_bytes)
        {
            return Err(RtpImportError::Limit);
        }
        Ok(())
    }
}

/// Time and stream identities supplied by the owner, not learned from capture headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpImportScope {
    /// Canonical sensor identity.
    pub sensor: SensorId,
    /// Canonical stream identity; generation is additionally bound by replay configuration.
    pub stream: StreamId,
    /// Owner receive time. The capture interval stays unknown, [0, receive_time].
    pub receive_time: TimestampNs,
}

/// Refusal deliberately avoids echoing filenames, endpoint strings, or packet contents.
pub enum RtpImportError {
    /// Explicit configuration, source count or byte reservation cannot admit this import.
    Limit,
    /// Source time/stream/root/slot or requested media hint conflicts.
    Binding,
    /// Actual stored bytes disagree with their pinned identity or replay result.
    Digest,
    /// Owner cancelled; prior staged/published source is retained for reconciliation.
    Cancelled,
    /// The request names no owner receive time. None is invented: the receive time bounds the
    /// capture interval and enters the durable import identity.
    MissingReceiveTime,
    /// I/O failed, without disclosing the source path.
    Io(ErrorKind),
    /// Container or real packet kernel could not construct/progress the replay.
    Replay(RtpReplayError),
    /// Existing semantic owner rejected a value.
    Contract(ContractError),
    /// Existing rooted storage owner failed; inspect the typed error for recovery.
    Publication(LocalPublicationError),
    /// Existing spool rejected verified readback.
    Spool(SpoolError),
    /// Existing deployment/ledger failed; partial effects are not reclassified as no effect.
    Reference(ReferenceError),
}
impl std::fmt::Debug for RtpImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit => f.write_str("Limit"),
            Self::Binding => f.write_str("Binding"),
            Self::Digest => f.write_str("Digest"),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::MissingReceiveTime => f.write_str("MissingReceiveTime"),
            Self::Io(e) => f.debug_tuple("Io").field(e).finish(),
            Self::Replay(e) => f.debug_tuple("Replay").field(e).finish(),
            Self::Contract(_) => f.write_str("Contract"),
            Self::Publication(_) => f.write_str("Publication"),
            Self::Spool(_) => f.write_str("Spool"),
            Self::Reference(_) => f.write_str("Reference"),
        }
    }
}
impl std::fmt::Display for RtpImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recorded RTP import refusal: {self:?}")
    }
}
impl std::error::Error for RtpImportError {}
impl From<ContractError> for RtpImportError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}
impl From<RtpReplayError> for RtpImportError {
    fn from(e: RtpReplayError) -> Self {
        Self::Replay(e)
    }
}
impl From<LocalPublicationError> for RtpImportError {
    fn from(e: LocalPublicationError) -> Self {
        Self::Publication(e)
    }
}
impl From<SpoolError> for RtpImportError {
    fn from(e: SpoolError) -> Self {
        Self::Spool(e)
    }
}
impl From<ReferenceError> for RtpImportError {
    fn from(e: ReferenceError) -> Self {
        Self::Reference(e)
    }
}
type Result<T, E = RtpImportError> = std::result::Result<T, E>;

/// Retained typed outcome per original record. Codec reasons never hide the original bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDisposition {
    /// Snaplen-limited original, not submitted as a complete packet.
    CapturedPrefix,
    /// Structurally validated recorded RTCP, not sender-clock truth.
    Rtcp,
    /// Packet validation refused this original.
    PacketRefused(PacketError),
    /// Expected owner SSRC/payload/epoch refused this original.
    StreamRefused(ContinuityError),
    /// Probation, duplicate, before-baseline, or restart-required observation.
    SequenceOnly,
    /// Complete/pending/ignored result of the actual H.264 reconstruction owner.
    H264(H264Status),
    /// Malformed/unsupported/interrupted codec input.
    CodecRefused(H264Error),
}
/// Metadata only; the original packet is retained in the complete source chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordReport {
    /// Exact record envelope in the imported file.
    pub source: Range<usize>,
    /// Recorded transport kind, including malformed RTCP and capture-limited RTP.
    pub kind: RtpDumpKind,
    /// Untrusted original recorder offset in milliseconds.
    pub offset_ms: u32,
    /// Complete captured datagram content identity, including refused inputs.
    pub packet_digest: ContentDigest,
    /// Recorder offset reversed; not a trusted-clock reset or new epoch.
    pub offset_reversed: bool,
    /// Stream generation in force when the record was processed (owner epoch, then + 1 per
    /// restart). The process-local ingress handle is deliberately not retained.
    pub generation: u64,
    /// SSRC bound to that generation.
    pub ssrc: u32,
    /// RTP media timestamp when the record parsed as RTP; sender media clock, not capture time.
    pub timestamp: Option<u32>,
    /// The generation opened at this record, if any; its record is always a gap fence.
    pub restart: Option<RestartCause>,
    /// Sequence observation only when the owner accepted its binding.
    pub sequence: Option<SequenceObservation>,
    /// Typed disposition.
    pub disposition: RecordDisposition,
    /// NAL indices generated by this input, empty when nothing was reconstructed.
    pub nals: Range<usize>,
    /// Derivative-continuity fence from a gap, refusal or unadmitted baseline.
    pub gap_before: bool,
    /// A pending FU expired before this packet arrived.
    pub expired: Option<FragmentDiscard>,
    /// Pending FU retired because of this packet.
    pub discarded: Option<FragmentDiscard>,
}
/// Each NAL is a derivative of its exact original-record envelope and explicit spans.
/// NALs carry no capsule of their own: the source capsule is per access unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NalReport {
    /// SHA-256 of the reconstructed NAL bytes, without invented Annex-B prefix.
    pub digest: ContentDigest,
    /// Whole original record envelope; intervening records are not cropped out.
    pub source: Range<usize>,
    /// Index of the access unit (and so of the capsule) this NAL belongs to.
    pub access_unit: usize,
    /// Uninterpreted RTP media timestamp of the NAL (sender clock, not capture time).
    pub timestamp: u32,
    /// Sender marker bit on the NAL's final packet; a sender claim, not completeness.
    pub marker: bool,
    /// Absolute input copy/synthesis ranges, independent of local filesystem paths.
    pub spans: Vec<FileNalSource>,
}
/// Why a recorded access unit's NAL run was closed. Only [`AccessUnitEnd::Marker`] carries the
/// sender's own end-of-access-unit claim; the others record that the run was cut without it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessUnitEnd {
    /// The final NAL carried the RTP marker bit (RFC 6184 §5.1). A sender claim, not a decoded
    /// primary-picture completeness certificate.
    Marker,
    /// The next complete NAL carried another RTP timestamp or stream generation first.
    TimestampChange,
    /// A continuity fence (sequence gap, refusal, restart, retired fragment) came first. NALs
    /// after a fence never join the earlier access unit.
    Fence,
    /// Input ended (clean EOF or framing refusal) first.
    InputEnd,
}
impl AccessUnitEnd {
    /// Stable label of the closure.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Marker => "marker",
            Self::TimestampChange => "timestamp_change",
            Self::Fence => "fence",
            Self::InputEnd => "input_end",
        }
    }
}
/// One recorded access unit: a maximal run of consecutive complete NALs of one stream generation
/// and one RTP timestamp, with no continuity fence inside, closed by the marker bit or by the
/// first event that cuts it. Its capsule binds the exact ORIGINAL record bytes that carried it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessUnitReport {
    /// Indices into [`RtpImportReport::nals`], nonempty and contiguous.
    pub nals: Range<usize>,
    /// Stream generation of every NAL in the unit.
    pub generation: u64,
    /// SSRC of that generation.
    pub ssrc: u32,
    /// Shared RTP media timestamp (sender clock, not capture time).
    pub timestamp: u32,
    /// Whole original record envelopes from the first to the last carrying record, inclusive;
    /// intervening records (RTCP, duplicates) are not cropped out.
    pub source: Range<usize>,
    /// Why the run was closed.
    pub end: AccessUnitEnd,
    /// Source capsule over `source`; explicitly zero decoded frames.
    pub capsule: SensorCapsule,
    /// RAW content-addressed object identity of capsule encoding, not its semantic fingerprint.
    pub capsule_object: ContentDigest,
}
/// EOF and malformed framing remain distinguishable even after durable import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportEnd {
    /// Clean container EOF; incomplete media may still have been retired.
    Ended,
    /// The suffix is retained but parsing stopped; this is not a successful clean parse.
    FramingRefused(RtpDumpError),
}
/// Immutable report returned by a successful import, not a live-camera coverage certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpImportReport {
    input: ContentDigest,
    input_bytes: usize,
    chunks: Vec<ContentDigest>,
    records: Vec<RecordReport>,
    nals: Vec<NalReport>,
    access_units: Vec<AccessUnitReport>,
    end: ImportEnd,
    final_discard: Option<FragmentDiscard>,
    stats: SequenceStats,
}
impl RtpImportReport {
    /// Entire original file, including header, probation, RTCP and any bad suffix.
    pub fn input_digest(&self) -> ContentDigest {
        self.input
    }
    /// Complete original bytes retained; not just selected media.
    pub fn input_bytes(&self) -> usize {
        self.input_bytes
    }
    /// Typed receipt for every completely framed record.
    pub fn records(&self) -> &[RecordReport] {
        &self.records
    }
    /// Exact source-linked complete transport NALs, not picture certificates.
    pub fn nals(&self) -> &[NalReport] {
        &self.nals
    }
    /// Ordered custody chunk digests of the entire original file.
    pub fn chunk_digests(&self) -> &[ContentDigest] {
        &self.chunks
    }
    /// Recorded access units, one source capsule each, in reconstruction order.
    pub fn access_units(&self) -> &[AccessUnitReport] {
        &self.access_units
    }
    /// Terminal container outcome, preserving a framing fault separately from EOF.
    pub fn end(&self) -> &ImportEnd {
        &self.end
    }
    /// Incomplete FU explicitly retired at terminal input.
    pub fn final_discard(&self) -> Option<&FragmentDiscard> {
        self.final_discard.as_ref()
    }
    /// Final provisional sequence accounting, not a continuity witness.
    pub fn stats(&self) -> SequenceStats {
        self.stats
    }
}

/// Immutable prepared import. Source remains borrowed and no I/O has occurred.
/// Each source envelope is staged alongside (never replaced by) the reconstructed NAL.
pub struct PreparedRtpImport<'a> {
    input: &'a [u8],
    scope: RtpImportScope,
    config: RtpReplayConfig,
    limits: RtpImportLimits,
    nals: Vec<ReplayedNal>,
    capsule_bytes: Vec<Vec<u8>>,
    report: RtpImportReport,
    report_bytes: Vec<u8>,
    manifest: ObjectManifest,
    payload_bytes: usize,
}
impl std::fmt::Debug for PreparedRtpImport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRtpImport")
            .field("root", &self.manifest.root())
            .field("records", &self.report.records.len())
            .field("nals", &self.nals.len())
            .finish_non_exhaustive()
    }
}
impl PreparedRtpImport<'_> {
    /// Root manifest includes original custody chunks, source envelopes, NALs and capsule objects.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    /// Exact immutable per-record and source-link report.
    pub fn report(&self) -> &RtpImportReport {
        &self.report
    }
    /// Sealed canonical report bytes; may reveal packet timing and identifiers to an authorized reader.
    pub fn report_bytes(&self) -> &[u8] {
        &self.report_bytes
    }
    /// Conservatively summed staging payload; repeated source envelopes count again.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}

/// Object-manifest kind of a published recorded-RTP import root. Version 2 holds one source
/// capsule per recorded access unit; version 1 (one per NAL) is no longer produced or recovered.
pub const MANIFEST_KIND: &str = "rtpdump_import_v2";
/// Digest domain of the durable import identity (version 2: capsules are per access unit, so
/// the capsule identities this names differ in meaning from version 1).
pub const IMPORT_IDENTITY_DOMAIN: &str = "fss.rtpdump.import.identity.v2";
/// Digest domain of the canonical import report (version 2 adds the access-unit section).
pub const IMPORT_REPORT_DOMAIN: &str = "fss.rtpdump.import.report.v2";

/// An access unit still accepting NALs.
struct OpenUnit {
    first_nal: usize,
    generation: u64,
    ssrc: u32,
    timestamp: u32,
    source: Range<usize>,
    gap_before: bool,
}

/// Closes access units into source capsules and accounts their staged bytes.
struct UnitSink<'s> {
    input: &'s [u8],
    scope: &'s RtpImportScope,
    capture: CaptureInterval,
    hex: &'s str,
    units: Vec<AccessUnitReport>,
    capsule_bytes: Vec<Vec<u8>>,
    payload_bytes: usize,
    max_payload_bytes: usize,
}
impl UnitSink<'_> {
    /// Adds staged bytes to the conservative payload total, refusing past the ceiling.
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.payload_bytes = self
            .payload_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.max_payload_bytes)
            .ok_or(RtpImportError::Limit)?;
        Ok(())
    }
    /// Seals `unit` (NALs `unit.first_nal..nal_end`) into its capsule.
    ///
    /// Clock basis: `Estimated`. The capsule's capture interval is the unknown `[0, receive]`,
    /// and RTP media timestamps are a sender clock with an unknown origin (no RTCP sender-report
    /// mapping is trusted here), so `DeviceMonotonic` would claim a device-clock placement the
    /// recording never witnessed. The RTP timestamp is retained on the access unit as relative
    /// sender timing only.
    fn close(&mut self, unit: OpenUnit, nal_end: usize, end: AccessUnitEnd) -> Result<()> {
        if unit.first_nal >= nal_end {
            return Err(RtpImportError::Digest);
        }
        let original = self
            .input
            .get(unit.source.clone())
            .ok_or(RtpImportError::Digest)?;
        let index = self.units.len();
        // Zero decoded frames is intentional: a transported access unit is not a
        // primary-picture completeness or macroblock-decode claim.
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse(format!("capsule:rtp:{}:{index:06}", self.hex))?,
            sensor_id: self.scope.sensor.clone(),
            stream_id: self.scope.stream.clone(),
            sequence: index as u64,
            capture: self.capture,
            receive_time: self.scope.receive_time,
            clock_basis: ClockBasis::Estimated,
            source: original,
            frame_count: 0,
            gap_before: unit.gap_before,
        })?;
        let encoded = capsule.try_canonical_bytes()?;
        self.charge(
            original
                .len()
                .checked_add(encoded.len())
                .ok_or(RtpImportError::Limit)?,
        )?;
        self.units.push(AccessUnitReport {
            nals: unit.first_nal..nal_end,
            generation: unit.generation,
            ssrc: unit.ssrc,
            timestamp: unit.timestamp,
            source: unit.source,
            end,
            capsule,
            capsule_object: hash(&encoded)?,
        });
        self.capsule_bytes.push(encoded);
        Ok(())
    }
}

/// Prepare a complete original-file import. Framing damage can produce an explicit
/// degraded report; budget/cancellation failures never produce a partial success.
/// Packet stream binding must be supplied by the owner, not extracted from a header.
pub fn prepare_rtp_import<'a>(
    input: &'a [u8],
    scope: RtpImportScope,
    config: RtpReplayConfig,
    limits: RtpImportLimits,
    cx: &ReplayCx,
) -> Result<PreparedRtpImport<'a>> {
    checkpoint(cx, "rtpdump:prepare")?;
    limits.validate()?;
    if scope.receive_time.0 < 0 {
        return Err(RtpImportError::Binding);
    }
    if input.len() > limits.max_payload_bytes {
        return Err(RtpImportError::Limit);
    }
    let mut replay = RtpDumpReplay::new(input, config)?;
    let mut identity = CanonicalEncoder::new();
    identity.text(IMPORT_IDENTITY_DOMAIN);
    let input_digest = hash(input)?;
    identity.digest(input_digest);
    encode_scope(&mut identity, &scope);
    encode_config(&mut identity, config);
    encode_limits(&mut identity, limits);
    let id = hash(&identity.finish_checked()?)?;
    let hex = id
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut records = Vec::new();
    let mut reports = Vec::new();
    let mut nals = Vec::new();
    let mut units = UnitSink {
        input,
        scope: &scope,
        capture: CaptureInterval::new(TimestampNs(0), scope.receive_time)?,
        hex: &hex,
        units: Vec::new(),
        capsule_bytes: Vec::new(),
        payload_bytes: input.len(),
        max_payload_bytes: limits.max_payload_bytes,
    };
    let mut open: Option<OpenUnit> = None;
    let mut derived = 0_usize;
    let mut span_count = 0_usize;
    let mut gap_pending = true; // File entry has no witnessed predecessor.
    // Admission counts are bounded before any allocation. A report-vector capacity
    // reservation is independent from the later exact canonical-report byte check.
    records
        .try_reserve_exact(config.dump.max_records)
        .map_err(|_| RtpImportError::Limit)?;
    reports
        .try_reserve_exact(limits.max_nals)
        .map_err(|_| RtpImportError::Limit)?;
    nals.try_reserve_exact(limits.max_nals)
        .map_err(|_| RtpImportError::Limit)?;
    units
        .units
        .try_reserve_exact(limits.max_nals)
        .map_err(|_| RtpImportError::Limit)?;
    units
        .capsule_bytes
        .try_reserve_exact(limits.max_nals)
        .map_err(|_| RtpImportError::Limit)?;
    let (end, final_discard) = loop {
        match replay.step(cx)? {
            RtpReplayStep::Record(record) => {
                let first = nals.len();
                let record_span = record.source.span();
                let (sequence, disposition, output, gap) = match record.outcome {
                    RtpRecordOutcome::CapturedPrefix => {
                        (None, RecordDisposition::CapturedPrefix, Vec::new(), true)
                    }
                    RtpRecordOutcome::Rtcp => (None, RecordDisposition::Rtcp, Vec::new(), false),
                    RtpRecordOutcome::PacketRefused(e) => {
                        (None, RecordDisposition::PacketRefused(e), Vec::new(), true)
                    }
                    RtpRecordOutcome::StreamRefused(e) => {
                        (None, RecordDisposition::StreamRefused(e), Vec::new(), true)
                    }
                    RtpRecordOutcome::SequenceOnly(o) => (
                        Some(o),
                        RecordDisposition::SequenceOnly,
                        Vec::new(),
                        !matches!(o.class, SequenceClass::Duplicate),
                    ),
                    RtpRecordOutcome::CodecRefused {
                        observation,
                        failure,
                    } => (
                        Some(observation),
                        RecordDisposition::CodecRefused(failure.reason),
                        Vec::new(),
                        true,
                    ),
                    RtpRecordOutcome::H264 {
                        observation,
                        status,
                        nals,
                        gap_before,
                    } => (
                        Some(observation),
                        RecordDisposition::H264(status),
                        nals,
                        gap_before,
                    ),
                };
                let gap = gap || record.restart.is_some();
                let fence = gap || record.expired.is_some() || record.discarded.is_some();
                if fence && let Some(unit) = open.take() {
                    units.close(unit, nals.len(), AccessUnitEnd::Fence)?;
                }
                gap_pending |= fence;
                for n in output {
                    if nals.len() == limits.max_nals
                        || n.nal.bytes().len() > limits.max_derived_bytes.saturating_sub(derived)
                        || n.sources.len() > limits.max_source_spans.saturating_sub(span_count)
                    {
                        return Err(RtpImportError::Limit);
                    }
                    let first_record = n.sources.first().ok_or(RtpImportError::Digest)?.record;
                    let last_record = n.sources.last().ok_or(RtpImportError::Digest)?.record;
                    let envelope = |index: usize| -> Result<Range<usize>> {
                        if index == record.source.index() {
                            Ok(record_span.clone())
                        } else {
                            records
                                .get(index)
                                .map(|r: &RecordReport| r.source.clone())
                                .ok_or(RtpImportError::Digest)
                        }
                    };
                    let source = envelope(first_record)?.start..envelope(last_record)?.end;
                    if source.start >= source.end || source.end > input.len() {
                        return Err(RtpImportError::Digest);
                    }
                    let key = n.nal.key();
                    let timestamp = n.nal.timestamp();
                    let marker = n.nal.marker();
                    if open.as_ref().is_some_and(|u| {
                        u.generation != key.generation
                            || u.ssrc != key.ssrc
                            || u.timestamp != timestamp
                    }) && let Some(unit) = open.take()
                    {
                        units.close(unit, nals.len(), AccessUnitEnd::TimestampChange)?;
                    }
                    let unit = open.get_or_insert(OpenUnit {
                        first_nal: nals.len(),
                        generation: key.generation,
                        ssrc: key.ssrc,
                        timestamp,
                        source: source.clone(),
                        gap_before: gap_pending,
                    });
                    unit.source.start = unit.source.start.min(source.start);
                    unit.source.end = unit.source.end.max(source.end);
                    units.charge(n.nal.bytes().len())?;
                    derived += n.nal.bytes().len();
                    span_count += n.sources.len();
                    reports.push(NalReport {
                        digest: hash(n.nal.bytes())?,
                        source,
                        access_unit: units.units.len(),
                        timestamp,
                        marker,
                        spans: n.sources.clone(),
                    });
                    nals.push(n);
                    gap_pending = false;
                    if marker && let Some(unit) = open.take() {
                        units.close(unit, nals.len(), AccessUnitEnd::Marker)?;
                    }
                }
                records.push(RecordReport {
                    source: record_span,
                    kind: record.source.kind(),
                    offset_ms: record.source.offset_ms(),
                    packet_digest: hash(record.source.packet())?,
                    offset_reversed: record.offset_reversed,
                    generation: record.key.generation,
                    ssrc: record.key.ssrc,
                    timestamp: record.timestamp,
                    restart: record.restart.map(|r| r.cause),
                    sequence,
                    disposition,
                    nals: first..nals.len(),
                    gap_before: gap,
                    expired: record.expired,
                    discarded: record.discarded,
                });
            }
            RtpReplayStep::Ended { discarded, .. } => break (ImportEnd::Ended, discarded),
            RtpReplayStep::FramingRefused { error, .. }
                if matches!(
                    error.fault,
                    RtpDumpFault::Limit | RtpDumpFault::Configuration
                ) =>
            {
                return Err(RtpImportError::Limit);
            }
            RtpReplayStep::FramingRefused { error, discarded } => {
                break (ImportEnd::FramingRefused(error), discarded);
            }
            RtpReplayStep::Cancelled { .. } => return Err(RtpImportError::Cancelled),
            RtpReplayStep::Exhausted => return Err(RtpImportError::Digest),
        }
    };
    if let Some(unit) = open.take() {
        units.close(unit, nals.len(), AccessUnitEnd::InputEnd)?;
    }
    let UnitSink {
        units: access_units,
        capsule_bytes,
        mut payload_bytes,
        ..
    } = units;
    checkpoint(cx, "rtpdump:seal")?;
    let chunk_count = input.len().div_ceil(limits.chunk_bytes);
    // Every access unit holds at least one NAL, so NAL digests plus two objects per unit stay
    // within three objects per NAL.
    if chunk_count + nals.len() * 3 + 1 > fss_object::MAX_MANIFEST_CHILDREN {
        return Err(RtpImportError::Limit);
    }
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(chunk_count)
        .map_err(|_| RtpImportError::Limit)?;
    for c in input.chunks(limits.chunk_bytes) {
        chunks.push(hash(c)?);
    }
    let report = RtpImportReport {
        input: input_digest,
        input_bytes: input.len(),
        chunks,
        records,
        nals: reports,
        access_units,
        end,
        final_discard,
        stats: replay.stats(),
    };
    let report_bytes = encode_report(&report, &scope, config, limits)?;
    payload_bytes = payload_bytes
        .checked_add(report_bytes.len())
        .ok_or(RtpImportError::Limit)?;
    let mut children = report.chunks.clone();
    children
        .try_reserve_exact(report.nals.len() + report.access_units.len() * 2)
        .map_err(|_| RtpImportError::Limit)?;
    children.extend(report.nals.iter().map(|n| n.digest));
    for u in &report.access_units {
        children.extend([u.capsule.source_digest, u.capsule_object]);
    }
    children.sort_unstable();
    children.dedup();
    let manifest = ObjectManifest::new(MANIFEST_KIND, children, Some(hash(&report_bytes)?))
        .map_err(|_| RtpImportError::Limit)?;
    payload_bytes = payload_bytes
        .checked_add(manifest.canonical_bytes().len())
        .ok_or(RtpImportError::Limit)?;
    if payload_bytes > limits.max_payload_bytes {
        return Err(RtpImportError::Limit);
    }
    Ok(PreparedRtpImport {
        input,
        scope,
        config,
        limits,
        nals,
        capsule_bytes,
        report,
        report_bytes,
        manifest,
        payload_bytes,
    })
}

/// Successful source publication AND capsule-ledger receipt. Captured media may
/// have an explicitly degraded parsing outcome. This never certifies absence.
pub struct RtpFileImportReceipt {
    slot: SlotName,
    root: ContentDigest,
    anchor: LedgerAnchor,
    report: RtpImportReport,
    scope: RtpImportScope,
    config: RtpReplayConfig,
    limits: RtpImportLimits,
    report_bytes: Vec<u8>,
    manifest: ObjectManifest,
}
impl std::fmt::Debug for RtpFileImportReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtpFileImportReceipt")
            .field("root", &self.root)
            .field("records", &self.report.records.len())
            .field("nals", &self.report.nals.len())
            .finish_non_exhaustive()
    }
}
impl RtpFileImportReceipt {
    /// Exact root at which all original and derivative children were published.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Content-derived slot; no source filesystem path enters it.
    pub fn slot(&self) -> &SlotName {
        &self.slot
    }
    /// Actual ledger anchor after capsule publication.
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Source/packet/NAL accounting, including any unparsed suffix and retired FU.
    pub fn report(&self) -> &RtpImportReport {
        &self.report
    }
    /// Sealed canonical report bytes (the published root's metadata object).
    pub fn report_bytes(&self) -> &[u8] {
        &self.report_bytes
    }
}

/// Stage original chunks FIRST, then exact source envelopes and derivatives, then
/// report/root. Only after root publication append the deterministic capsule batch.
/// A retry uses the same identities and re-verifies all bytes; prior effects are
/// never deleted or replaced. Errors can leave staged or published custody intact.
pub fn publish_rtp_import(
    plan: PreparedRtpImport<'_>,
    cx: &ReplayCx,
    deployment: &mut ReferenceDeployment,
) -> Result<RtpFileImportReceipt> {
    checkpoint(cx, "rtpdump:preflight")?;
    let root = plan.manifest.root();
    let hex = root
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let slot = SlotName::parse(&format!("rtp-{hex}")).map_err(|_| RtpImportError::Binding)?;
    if deployment
        .publisher()
        .root(&slot)
        .is_some_and(|r| r.root != root)
    {
        return Err(RtpImportError::Binding);
    }
    let object_limit = deployment.publisher().spool().limits().max_object_bytes;
    let manifest_bytes = plan.manifest.canonical_bytes();
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(
            plan.report.chunks.len() + plan.nals.len() + plan.report.access_units.len() * 2 + 2,
        )
        .map_err(|_| RtpImportError::Limit)?;
    objects.extend(
        plan.input
            .chunks(plan.limits.chunk_bytes)
            .zip(&plan.report.chunks)
            .map(|(b, d)| (*d, b)),
    );
    for (n, report) in plan.nals.iter().zip(&plan.report.nals) {
        objects.push((report.digest, n.nal.bytes()));
    }
    for (unit, encoded) in plan.report.access_units.iter().zip(&plan.capsule_bytes) {
        objects.push((unit.capsule.source_digest, &plan.input[unit.source.clone()]));
        objects.push((unit.capsule_object, encoded.as_slice()));
    }
    objects.push((hash(&plan.report_bytes)?, &plan.report_bytes));
    objects.push((root, &manifest_bytes));
    if objects.iter().any(|(_, b)| b.len() > object_limit)
        || plan.manifest.children().len() > deployment.publisher().limits().max_children
    {
        return Err(RtpImportError::Limit);
    }
    // Conservative preflight: count unique new objects, never silently expand spool quotas.
    let mut seen = std::collections::BTreeSet::new();
    let mut new_bytes = 0_u64;
    let mut new_count = 0;
    for (d, b) in &objects {
        if seen.insert(*d) && deployment.publisher().spool().state(*d).is_none() {
            new_count += 1;
            new_bytes = new_bytes
                .checked_add(b.len() as u64)
                .ok_or(RtpImportError::Limit)?;
        }
    }
    let spool = deployment.publisher().spool();
    let bounds = spool.limits();
    if new_bytes
        > bounds
            .max_total_bytes
            .saturating_sub(spool.occupied_bytes()?)
        || new_count > bounds.max_objects.saturating_sub(spool.object_count())
    {
        return Err(RtpImportError::Limit);
    }
    for (d, b) in objects {
        checkpoint(cx, "rtpdump:stage")?;
        if deployment.publisher_mut().stage_object(b)? != d {
            return Err(RtpImportError::Digest);
        }
        deployment.publisher_mut().verify_object(d)?;
    }
    let validity = CaptureInterval::new(TimestampNs(0), plan.scope.receive_time)?;
    deployment.publish_and_commit(&slot, &plan.manifest, validity, cx)?;
    checkpoint(cx, "rtpdump:ledger")?;
    // Fixed partitions are independent of owner capacity/attempt, so retry never
    // changes batch identities. Each batch has at most 64 capsule deltas.
    for (part, group) in plan.report.access_units.chunks(64).enumerate() {
        checkpoint(cx, "rtpdump:ledger_capsules")?;
        let mut deltas = Vec::new();
        let mut children = Vec::new();
        deltas
            .try_reserve_exact(group.len())
            .map_err(|_| RtpImportError::Limit)?;
        children
            .try_reserve_exact(group.len() * 2)
            .map_err(|_| RtpImportError::Limit)?;
        for n in group {
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:{}", n.capsule.capsule_id.as_str()),
                family: "sensor_capsule".into(),
                object_id: ObjectId::parse(format!("object:{}", n.capsule.capsule_id.as_str()))?,
                prior_generation: None,
                new_generation: 1,
                validity,
                plane: Plane::Authority,
                payload_digest: n.capsule_object,
                witness_digest: Some(n.capsule.source_digest),
                operation_id: None,
            });
            children.push(n.capsule_object);
            children.push(n.capsule.source_digest);
        }
        children.sort_unstable();
        children.dedup();
        deployment.append_batch(
            BatchId::parse(format!("batch:rtp:{hex}:c{part}"))?,
            deltas,
            children,
            cx,
        )?;
    }
    checkpoint(cx, "rtpdump:ledger_complete")?;
    let batch = BatchId::parse(format!("batch:rtp:{hex}"))?;
    let report_digest = hash(&plan.report_bytes)?;
    let deltas = vec![EvidenceDelta {
        delta_id: format!("delta:rtp:{hex}"),
        family: "rtpdump_import".into(),
        object_id: ObjectId::parse(format!("object:rtp:{hex}"))?,
        prior_generation: None,
        new_generation: 1,
        validity,
        plane: Plane::Authority,
        payload_digest: report_digest,
        witness_digest: Some(root),
        operation_id: None,
    }];
    let mut children = vec![root, report_digest];
    children.sort_unstable();
    children.dedup();
    let anchor = deployment.append_batch(batch, deltas, children, cx)?;
    // Do not reclassify a successfully committed terminal ledger batch as cancelled.
    Ok(RtpFileImportReceipt {
        slot,
        root,
        anchor,
        report: plan.report,
        scope: plan.scope,
        config: plan.config,
        limits: plan.limits,
        report_bytes: plan.report_bytes,
        manifest: plan.manifest,
    })
}

/// Fully re-read import. Holding this value proves a completed point-in-time read,
/// not durable future availability, live continuity or decoded frame completeness.
pub struct VerifiedRtpImport {
    source: Vec<u8>,
    nals: Vec<ReplayedNal>,
    report: RtpImportReport,
}
impl VerifiedRtpImport {
    /// Entire original snapshot, including inputs refused by packet/codec parsing.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Replayed NALs, each checked against both retained original and staged derivative.
    pub fn nals(&self) -> &[ReplayedNal] {
        &self.nals
    }
    /// Reverified report, identical to the pinned publication receipt.
    pub fn report(&self) -> &RtpImportReport {
        &self.report
    }
}
impl std::fmt::Debug for VerifiedRtpImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRtpImport")
            .field("source_bytes", &self.source.len())
            .field("nals", &self.nals.len())
            .finish()
    }
}
/// Reopen/read using a caller-retained exact receipt. Reconstruct the original
/// file from ordered chunks, replay the real packet kernel, then compare EVERY
/// source envelope, derivative, capsule and canonical report before returning.
/// The receipt is not inferred from an ambient directory scan or guessed root.
pub fn load_rtp_import(
    receipt: &RtpFileImportReceipt,
    cx: &ReplayCx,
    deployment: &ReferenceDeployment,
) -> Result<VerifiedRtpImport> {
    checkpoint(cx, "rtpdump:readback")?;
    let hex = receipt
        .root
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let batch = BatchId::parse(format!("batch:rtp:{hex}"))?;
    if !deployment
        .ledger()
        .batches()
        .iter()
        .any(|b| b.batch_id == batch && b.new_anchor == receipt.anchor)
    {
        return Err(RtpImportError::Binding);
    }
    let p = deployment.publisher();
    if p.is_poisoned() {
        return Err(RtpImportError::Binding);
    }
    let root = p.root(&receipt.slot).ok_or(RtpImportError::Binding)?;
    if root.root != receipt.root || root.state != LocalPublicationState::Durable {
        return Err(RtpImportError::Binding);
    }
    // The spool checks sizes before allocation; refuse a wider owner than this API's bounded read.
    if p.spool().limits().max_object_bytes > 64 * 1024 * 1024 {
        return Err(RtpImportError::Limit);
    }
    let read = |digest| -> Result<Vec<u8>> {
        checkpoint(cx, "rtpdump:read_object")?;
        if p.tombstones().any(|d| *d == digest) {
            return Err(RtpImportError::Binding);
        }
        Ok(p.spool().read(digest)?)
    };
    if read(receipt.root)? != receipt.manifest.canonical_bytes()
        || read(hash(&receipt.report_bytes)?)? != receipt.report_bytes
    {
        return Err(RtpImportError::Digest);
    }
    let mut source = Vec::new();
    source
        .try_reserve_exact(receipt.report.input_bytes)
        .map_err(|_| RtpImportError::Limit)?;
    for (i, d) in receipt.report.chunks.iter().enumerate() {
        let chunk = read(*d)?;
        let expected = receipt
            .limits
            .chunk_bytes
            .min(receipt.report.input_bytes - source.len());
        if chunk.len() != expected
            || (i + 1 < receipt.report.chunks.len() && chunk.len() != receipt.limits.chunk_bytes)
        {
            return Err(RtpImportError::Digest);
        }
        source.extend_from_slice(&chunk);
    }
    if source.len() != receipt.report.input_bytes || hash(&source)? != receipt.report.input {
        return Err(RtpImportError::Digest);
    }
    let (nals, report) = {
        let plan = prepare_rtp_import(
            &source,
            receipt.scope.clone(),
            receipt.config,
            receipt.limits,
            cx,
        )?;
        if plan.manifest != receipt.manifest || plan.report_bytes != receipt.report_bytes {
            return Err(RtpImportError::Digest);
        }
        for (n, r) in plan.nals.iter().zip(&plan.report.nals) {
            if read(r.digest)?.as_slice() != n.nal.bytes() {
                return Err(RtpImportError::Digest);
            }
        }
        for (u, encoded) in plan.report.access_units.iter().zip(&plan.capsule_bytes) {
            if read(u.capsule.source_digest)?.as_slice() != &source[u.source.clone()]
                || read(u.capsule_object)?.as_slice() != encoded.as_slice()
            {
                return Err(RtpImportError::Digest);
            }
        }
        (plan.nals, plan.report)
    };
    checkpoint(cx, "rtpdump:read_complete")?;
    Ok(VerifiedRtpImport {
        source,
        nals,
        report,
    })
}

/// Owner binding and bounds of one recorded-RTP file request, validated before any source byte
/// is read: the effective replay configuration and import limits, and the input byte ceiling.
fn admit_rtp_request(
    request: &FileIngestRequest,
    mut config: RtpReplayConfig,
    mut limits: RtpImportLimits,
) -> Result<(RtpReplayConfig, RtpImportLimits, usize)> {
    if request.capture_hint.is_some()
        || request
            .format_hint
            .is_some_and(|h| h != FileFormatHint::RtpPlay)
        || request.limits.max_file_bytes == 0
        || request.limits.max_segments == 0
        || request.limits.chunk_bytes == 0
    {
        return Err(RtpImportError::Binding);
    }
    limits.validate()?;
    limits.chunk_bytes = limits
        .chunk_bytes
        .min(usize::try_from(request.limits.chunk_bytes).map_err(|_| RtpImportError::Limit)?);
    let max = usize::try_from(request.limits.max_file_bytes)
        .map_err(|_| RtpImportError::Limit)?
        .min(config.dump.max_input_bytes)
        .min(limits.max_payload_bytes);
    config.dump.max_input_bytes = max;
    config.validate()?;
    if limits.max_nals > request.limits.max_segments {
        return Err(RtpImportError::Limit);
    }
    Ok((config, limits, max))
}

/// Import an already read, already sniffed `#!rtpplay1.0` snapshot for the generic file adapter
/// (`FileIngestAdapter::ingest_file`). The owner binding comes from the request
/// (`FileIngestRequest::rtp_binding`) and its absence is refused by the caller; the receive time
/// is required and never invented; the same identities as [`FileIngestAdapter::ingest_rtp`]
/// result for the same bytes, scope, binding and limits.
pub(crate) fn import_rtp_snapshot(
    request: &FileIngestRequest,
    config: RtpReplayConfig,
    input: &[u8],
    cx: &ReplayCx,
    deployment: &mut ReferenceDeployment,
) -> Result<RtpFileImportReceipt> {
    let (config, limits, max) = admit_rtp_request(request, config, RtpImportLimits::default())?;
    let receive_time = request
        .receive_time
        .ok_or(RtpImportError::MissingReceiveTime)?;
    if input.len() > max {
        return Err(RtpImportError::Limit);
    }
    let scope = RtpImportScope {
        sensor: request.sensor_id.clone(),
        stream: request.stream_id.clone(),
        receive_time,
    };
    let plan = prepare_rtp_import(input, scope, config, limits, cx)?;
    publish_rtp_import(plan, cx, deployment)
}

impl FileIngestAdapter {
    /// Explicit recorded-RTP path. Unlike generic sniffing, this requires the
    /// owner to provide PT/SSRC/mode/epoch before any packet can be interpreted.
    /// Source timing is unknown; a per-frame CaptureHint is refused because this
    /// path reconstructs NALs and groups them into access units but does not
    /// count or decode pictures. `FileIngestAdapter::ingest_file` routes a sniffed
    /// `#!rtpplay1.0` file here when the request carries an owner binding.
    pub fn ingest_rtp(
        request: FileIngestRequest,
        config: RtpReplayConfig,
        limits: RtpImportLimits,
        cx: &ReplayCx,
        deployment: &mut ReferenceDeployment,
    ) -> Result<RtpFileImportReceipt> {
        let (config, limits, max) = admit_rtp_request(&request, config, limits)?;
        let receive_time = request
            .receive_time
            .ok_or(RtpImportError::MissingReceiveTime)?;
        checkpoint(cx, "rtpdump:open")?;
        let meta =
            std::fs::symlink_metadata(&request.path).map_err(|e| RtpImportError::Io(e.kind()))?;
        if !meta.file_type().is_file() {
            return Err(RtpImportError::Binding);
        }
        let file = File::open(&request.path).map_err(|e| RtpImportError::Io(e.kind()))?;
        let input = read_rtp_snapshot(file, max, cx)?;
        let scope = RtpImportScope {
            sensor: request.sensor_id,
            stream: request.stream_id,
            receive_time,
        };
        let plan = prepare_rtp_import(&input, scope, config, limits, cx)?;
        publish_rtp_import(plan, cx, deployment)
    }
}
/// Read one already opened regular-file capability, never allocate from an
/// untrusted stale stat size alone. Growth is limited by max_bytes + one probe
/// byte, with cancellation checked between bounded reads. This is a reference
/// host-file boundary, not a race-proof path sandbox or an Asupersync adapter.
pub fn read_rtp_snapshot(file: File, max_bytes: usize, cx: &ReplayCx) -> Result<Vec<u8>> {
    checkpoint(cx, "rtpdump:read")?;
    if !(1..=512 * 1024 * 1024).contains(&max_bytes) {
        return Err(RtpImportError::Limit);
    }
    let meta = file.metadata().map_err(|e| RtpImportError::Io(e.kind()))?;
    if !meta.is_file() {
        return Err(RtpImportError::Binding);
    }
    if meta.len() > max_bytes as u64 {
        return Err(RtpImportError::Limit);
    }
    let mut reader = file.take(max_bytes as u64 + 1);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut interrupted = 0;
    loop {
        checkpoint(cx, "rtpdump:read")?;
        let count = match reader.read(&mut buffer) {
            Ok(n) => {
                interrupted = 0;
                n
            }
            Err(e) if e.kind() == ErrorKind::Interrupted && interrupted < 8 => {
                interrupted += 1;
                continue;
            }
            Err(e) => return Err(RtpImportError::Io(e.kind())),
        };
        if count == 0 {
            break;
        }
        if count > max_bytes.saturating_sub(bytes.len()) {
            return Err(RtpImportError::Limit);
        }
        bytes
            .try_reserve_exact(count)
            .map_err(|_| RtpImportError::Limit)?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| RtpImportError::Cancelled)
}
fn hash(b: &[u8]) -> Result<ContentDigest> {
    Ok(ContentDigest::try_sha256(b)?)
}
fn encode_scope(e: &mut CanonicalEncoder, s: &RtpImportScope) {
    e.text(s.sensor.as_str());
    e.text(s.stream.as_str());
    e.i128(s.receive_time.0);
    e.text("capture_unknown");
}
fn encode_config(e: &mut CanonicalEncoder, c: RtpReplayConfig) {
    // A process-local ingress handle deliberately does not enter durable identities.
    e.u64(c.key.generation);
    e.u32(c.key.ssrc);
    e.u8(c.payload_type);
    e.u8(match c.mode {
        H264Mode::SingleNal => 0,
        H264Mode::NonInterleaved => 1,
    });
    e.u8(match c.rtcp {
        RtcpMode::Compound => 0,
        RtcpMode::ReducedSize => 1,
    });
    for n in [
        c.dump.max_input_bytes,
        c.dump.max_records,
        c.dump.max_packet_bytes,
        c.packet.max_packet_bytes,
        c.packet.max_extension_bytes,
        c.packet.max_rtcp_packets,
        c.codec.max_nal_bytes,
        c.codec.max_packet_nals,
        c.codec.max_fragment_packets,
    ] {
        e.u64(n as u64);
    }
    e.u64(c.codec.max_pending_age_ns);
}
fn encode_limits(e: &mut CanonicalEncoder, l: RtpImportLimits) {
    for n in [
        l.chunk_bytes,
        l.max_nals,
        l.max_source_spans,
        l.max_derived_bytes,
        l.max_report_bytes,
        l.max_payload_bytes,
    ] {
        e.u64(n as u64);
    }
}
fn span(e: &mut CanonicalEncoder, r: &Range<usize>) {
    e.u64(r.start as u64);
    e.u64(r.end as u64);
}
fn stats(e: &mut CanonicalEncoder, s: SequenceStats) {
    e.u64(s.expected);
    e.u64(s.received);
    e.u64(s.unique);
    e.u64(s.missing);
}
fn discard(e: &mut CanonicalEncoder, d: Option<&FragmentDiscard>) {
    e.bool(d.is_some());
    if let Some(d) = d {
        e.u64(d.key.generation);
        e.u32(d.key.ssrc);
        e.text(&format!("{:?}", d.reason));
        e.u64(d.first_sequence);
        e.u64(d.last_sequence);
        e.u64(d.byte_len as u64);
        e.u64(d.fragments as u64);
    }
}
fn encode_report(
    r: &RtpImportReport,
    s: &RtpImportScope,
    c: RtpReplayConfig,
    l: RtpImportLimits,
) -> Result<Vec<u8>> {
    // Calculate a conservative wire bound BEFORE building an encoder. Diagnostic
    // spellings below come only from closed payload-free kernel enums, never wire strings.
    let upper = 2048_usize
        .checked_add(
            r.records
                .len()
                .checked_mul(512)
                .ok_or(RtpImportError::Limit)?,
        )
        .and_then(|n| n.checked_add(r.nals.len() * 1024))
        .and_then(|n| n.checked_add(r.access_units.len() * 512))
        .and_then(|n| n.checked_add(r.chunks.len() * 33))
        .and_then(|n| n.checked_add(r.nals.iter().map(|n| n.spans.len() * 64).sum::<usize>()))
        .ok_or(RtpImportError::Limit)?;
    if upper > l.max_report_bytes {
        return Err(RtpImportError::Limit);
    }
    let mut e = CanonicalEncoder::new();
    e.text(IMPORT_REPORT_DOMAIN);
    e.u64(2);
    e.digest(r.input);
    e.u64(r.input_bytes as u64);
    encode_scope(&mut e, s);
    encode_config(&mut e, c);
    encode_limits(&mut e, l);
    e.u64(r.chunks.len() as u64);
    for d in &r.chunks {
        e.digest(*d);
    }
    e.u64(r.records.len() as u64);
    for record in &r.records {
        span(&mut e, &record.source);
        e.u8(match record.kind {
            RtpDumpKind::Rtp => 1,
            RtpDumpKind::Rtcp => 2,
            RtpDumpKind::CapturedPrefix => 3,
        });
        e.u32(record.offset_ms);
        e.digest(record.packet_digest);
        e.bool(record.offset_reversed);
        e.u64(record.generation);
        e.u32(record.ssrc);
        e.bool(record.timestamp.is_some());
        if let Some(t) = record.timestamp {
            e.u32(t);
        }
        e.bool(record.restart.is_some());
        if let Some(cause) = record.restart {
            e.text(cause.as_str());
        }
        e.bool(record.sequence.is_some());
        if let Some(o) = record.sequence {
            e.text(&format!("{:?}", o.class));
            e.bool(o.extended_sequence.is_some());
            if let Some(n) = o.extended_sequence {
                e.u64(n);
            }
            stats(&mut e, o.stats);
        }
        e.text(&format!("{:?}", record.disposition));
        span(&mut e, &record.nals);
        e.bool(record.gap_before);
        discard(&mut e, record.expired.as_ref());
        discard(&mut e, record.discarded.as_ref());
    }
    e.u64(r.nals.len() as u64);
    for nal in &r.nals {
        e.digest(nal.digest);
        span(&mut e, &nal.source);
        e.u64(nal.access_unit as u64);
        e.u32(nal.timestamp);
        e.bool(nal.marker);
        e.u64(nal.spans.len() as u64);
        for s in &nal.spans {
            e.u64(s.record as u64);
            span(&mut e, &s.wire);
            span(&mut e, &s.nal);
            e.bool(s.fragment_header.is_some());
            if let Some(r) = &s.fragment_header {
                span(&mut e, r);
            }
        }
    }
    e.u64(r.access_units.len() as u64);
    for unit in &r.access_units {
        span(&mut e, &unit.nals);
        e.u64(unit.generation);
        e.u32(unit.ssrc);
        e.u32(unit.timestamp);
        span(&mut e, &unit.source);
        e.text(unit.end.as_str());
        e.bool(unit.capsule.gap_before);
        e.digest(unit.capsule_object);
        e.digest(unit.capsule.source_digest);
        e.text(unit.capsule.capsule_id.as_str());
    }
    match &r.end {
        ImportEnd::Ended => e.u8(0),
        ImportEnd::FramingRefused(f) => {
            e.u8(1);
            e.text(&format!("{:?}", f.fault));
            span(&mut e, &f.span);
        }
    }
    discard(&mut e, r.final_discard.as_ref());
    stats(&mut e, r.stats);
    let bytes = e.finish_checked()?;
    if bytes.len() > l.max_report_bytes {
        return Err(RtpImportError::Limit);
    }
    Ok(bytes)
}
