#![forbid(unsafe_code)]
//! Cold, privacy-projected AVC decoding from an already verified retained RTP root.
//!
//! The recovery owner verifies the complete source graph before this API can be opened.
//! This layer borrows that immutable snapshot, restores only its recorded stream binding,
//! selects parameters from its own source spans, and serves only masked planes. It does not
//! rewrite legacy import reports, append frame claims, or certify live source availability.
//! A changed authority anchor or a tombstone anywhere in the selected graph fences even
//! queued output. Physical corruption is checked by a fresh recovery inspection; a frozen
//! in-memory snapshot is not a continuous disk-scrub or future-availability promise.

use super::{RecoveredRtpImport, RtpImportError, RtpRecoveryState, root_slot};
use crate::ingest::privacy_mask::{MaskBinding, PrivacyMaskError, current_mask};
use crate::ingest::rtpdump::avc::{AvcDumpAdmission, AvcDumpConfig, AvcDumpStep};
use crate::ingest::rtpdump::decode::{
    RecordedRtpH264Decoder, RtpDecodeEffect, RtpDecodeError, RtpDecodeLimits, RtpDecodeStep,
    RtpDecodedPicture, RtpDecodedPictureSource,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{CaptureInterval, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_packet::avc::AvcReceiveLimits;
use fss_publication::LocalPublicationState;

/// Distinct in-source parameter candidates of the original owner-bound generation.
/// Candidate listing is not syntax admission; opening the decoder validates the exact pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedAvcParameters {
    /// Complete SPS NAL identities, sorted and deduplicated.
    pub sequence: Vec<ContentDigest>,
    /// Complete PPS NAL identities, sorted and deduplicated.
    pub picture: Vec<ContentDigest>,
}
impl RetainedAvcParameters {
    /// Select only an unambiguous pair. Multiple generations are never guessed or ranked.
    pub fn unique_pair(&self) -> Option<[ContentDigest; 2]> {
        match (self.sequence.as_slice(), self.picture.as_slice()) {
            ([sps], [pps]) => Some([*sps, *pps]),
            _ => None,
        }
    }
}

/// Independent admission for a new derivative, not authority inherited from a stored recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRtpDecodeRequest {
    /// Exact SPS and PPS identities from this root's original generation, in that order.
    pub parameters: [ContentDigest; 2],
    /// Bounded ordered receiver, syntax and assembly policy for the new derivative.
    pub receiver: AvcReceiveLimits,
    /// Native decode and cumulative recovery/output ceilings.
    pub decode: RtpDecodeLimits,
}
impl RetainedRtpDecodeRequest {
    /// Explicit parameter selection with the existing receiver and decoder default bounds.
    pub fn new(parameters: [ContentDigest; 2]) -> Self {
        Self {
            parameters,
            receiver: AvcReceiveLimits::default(),
            decode: RtpDecodeLimits::default(),
        }
    }
}

/// Payload-free refusal. In particular, errors never contain an unmasked picture or packet.
#[derive(Debug)]
pub enum RetainedRtpDecodeError {
    /// Source/anchor/publication consistency failed; re-inspect the selected root.
    Source(Box<RtpImportError>),
    /// The import's capsule/terminal ledger work has not completed.
    ImportPending,
    /// Exact requested parameters are absent from this source generation or have a wrong kind.
    ParametersUnavailable,
    /// A bounded allocation or parameter size was refused.
    Limit,
    /// Native ordered-receiver or decoder refusal.
    Decode(RtpDecodeError),
    /// The current sensor privacy policy could not be resolved or applied.
    Privacy(PrivacyMaskError),
    /// Cancellation fenced the attempt before further disclosure.
    Cancelled,
}
impl std::fmt::Display for RetainedRtpDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained RTP decode refusal: {self:?}")
    }
}
impl std::error::Error for RetainedRtpDecodeError {}
impl From<RtpImportError> for RetainedRtpDecodeError {
    fn from(error: RtpImportError) -> Self {
        Self::Source(Box::new(error))
    }
}
impl From<RtpDecodeError> for RetainedRtpDecodeError {
    fn from(error: RtpDecodeError) -> Self {
        Self::Decode(error)
    }
}
impl From<PrivacyMaskError> for RetainedRtpDecodeError {
    fn from(error: PrivacyMaskError) -> Self {
        Self::Privacy(error)
    }
}
type Result<T> = std::result::Result<T, RetainedRtpDecodeError>;

/// A payload-free projection of the underlying receiver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedRtpEvent {
    /// One original record was considered; this is not a frame or continuity claim.
    Record {
        /// Zero-based original record index.
        index: usize,
        /// Recorded offset decreased; no trusted clock is inferred from it.
        offset_reversed: bool,
    },
    /// A source admission or RTCP parse refused this original record.
    RecordRefused {
        /// Exact original record index without its private wire bytes.
        index: usize,
    },
    /// One bounded reconstruction/assembly step; its decode consequence is returned separately.
    Progress,
    /// Physical recording EOF, independently of decoder flush.
    InputEnded,
    /// Framing failed; never treated as clean EOF.
    FramingRefused,
    /// Receiver state failed or was cancelled.
    ReceiverRefused,
    /// The receiver was already exhausted (for example cancellation after pixel flush).
    ReceiverExhausted,
}

/// Progress counters are not evidence of absence or camera coverage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedRtpDecodeStats {
    /// Original records visited, including refused inputs.
    pub records: usize,
    /// Complete masked pictures actually returned to the caller.
    pub frames: usize,
    /// Refused or fenced steps; not a count of missing pictures.
    pub refusals: usize,
    /// Observed groups skipped while waiting for an IDR.
    pub skipped_groups: usize,
    /// The original file's framing reached EOF.
    pub input_ended: bool,
    /// The native decoder completed its flush; queued pictures may still remain.
    pub native_finished: bool,
    /// Both source enumeration and pixel delivery have ended.
    pub ended: bool,
}
impl RetainedRtpDecodeStats {
    /// Every observed group decoded and all output drained, with no refusal or skipped group.
    /// This says nothing about physical observability, capture precision, or unseen source data.
    pub fn complete(&self) -> bool {
        self.ended
            && self.input_ended
            && self.native_finished
            && self.frames > 0
            && self.refusals == 0
            && self.skipped_groups == 0
    }
}

/// Only masked native planes leave this retained-source boundary.
/// No accessor returns the raw codec picture retained by the lower-level decoder.
pub struct RetainedRtpH264Frame {
    root: ContentDigest,
    sensor: SensorId,
    stream: StreamId,
    capture: CaptureInterval,
    source: RtpDecodedPictureSource,
    dimensions: [u32; 2],
    luma: Vec<u8>,
    cb: Vec<u8>,
    cr: Vec<u8>,
    mask: MaskBinding,
}
impl RetainedRtpH264Frame {
    /// Original immutable import root; no new publication is implied.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Sensor restored from the verified source recipe, never supplied as a caller override.
    pub fn sensor(&self) -> &SensorId {
        &self.sensor
    }
    /// Stable source stream identity restored from that same recipe.
    pub fn stream(&self) -> &StreamId {
        &self.stream
    }
    /// Original unknown capture interval [0, owner receive time]; RTP time never narrows it.
    pub fn capture(&self) -> CaptureInterval {
        self.capture
    }
    /// Exact original picture-group provenance. Process-local ingress is not a durable ID.
    pub fn source(&self) -> &RtpDecodedPictureSource {
        &self.source
    }
    /// Visible luma width and height.
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// Tight masked luma plane.
    pub fn pixels(&self) -> &[u8] {
        &self.luma
    }
    /// Tight masked Cb plane.
    pub fn cb(&self) -> &[u8] {
        &self.cb
    }
    /// Tight masked Cr plane.
    pub fn cr(&self) -> &[u8] {
        &self.cr
    }
    /// Current-at-open policy bound to every served plane; anchor drift fences the decoder.
    pub fn mask(&self) -> &MaskBinding {
        &self.mask
    }
}
impl std::fmt::Debug for RetainedRtpH264Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedRtpH264Frame")
            .field("root", &self.root)
            .field("group", &self.source.group)
            .field("dimensions", &self.dimensions)
            .finish_non_exhaustive()
    }
}

/// Exactly one payload-free progress step or one privacy-projected picture.
#[derive(Debug)]
pub enum RetainedRtpDecodeStep {
    /// Source/receiver facts and decode consequences are both preserved without wire bytes.
    Progress {
        /// Payload-free receiver event.
        event: RetainedRtpEvent,
        /// Native decode outcome, including recovery and retirement counts.
        effect: RtpDecodeEffect,
    },
    /// A complete masked picture and its own source-group provenance.
    Frame(RetainedRtpH264Frame),
    /// Terminal counters distinguish complete decoding from partial/recovered output.
    Ended(RetainedRtpDecodeStats),
}

/// Request-owned decoder over one cold-verified source snapshot and one exact authority anchor.
pub struct RetainedRtpH264Decoder<'a> {
    retained: &'a RecoveredRtpImport,
    decoder: Option<RecordedRtpH264Decoder<'a>>,
    mask: MaskBinding,
    protected: Vec<ContentDigest>,
    stats: RetainedRtpDecodeStats,
    stopped: bool,
}
impl std::fmt::Debug for RetainedRtpH264Decoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedRtpH264Decoder")
            .field("root", &self.retained.root)
            .field("stats", &self.stats)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

impl RecoveredRtpImport {
    /// Inventory distinct in-source SPS/PPS digests of the initial generation only.
    /// Later source generations cannot silently supply the initial decoder configuration.
    pub fn h264_parameters(&self, cx: &ReplayCx) -> Result<RetainedAvcParameters> {
        let mut result = RetainedAvcParameters {
            sequence: Vec::new(),
            picture: Vec::new(),
        };
        for nal in self.report.nals() {
            check_cancel(cx)?;
            let Some(unit) = self.report.access_units().get(nal.access_unit) else {
                return Err(RtpImportError::Digest.into());
            };
            if unit.generation != self.recipe.config.key.generation
                || unit.ssrc != self.recipe.config.key.ssrc
            {
                continue;
            }
            let Some(first) = nal.spans.first() else {
                return Err(RtpImportError::Digest.into());
            };
            let header = if let Some(range) = &first.fragment_header {
                let bytes = self
                    .source
                    .get(range.clone())
                    .ok_or(RtpImportError::Digest)?;
                if bytes.len() != 2 {
                    return Err(RtpImportError::Digest.into());
                }
                (bytes[0] & 0xe0) | (bytes[1] & 31)
            } else {
                *self
                    .source
                    .get(first.wire.start)
                    .ok_or(RtpImportError::Digest)?
            };
            let destination = match header & 31 {
                7 => &mut result.sequence,
                8 => &mut result.picture,
                _ => continue,
            };
            if !destination.contains(&nal.digest) {
                destination
                    .try_reserve(1)
                    .map_err(|_| RetainedRtpDecodeError::Limit)?;
                destination.push(nal.digest);
            }
        }
        result.sequence.sort_unstable();
        result.picture.sort_unstable();
        Ok(result)
    }

    /// Open only a completed import at the exact inspection anchor. This creates no objects,
    /// ledger rows, network sessions, generation changes, or implicit recovery writes.
    pub fn decode_h264<'a>(
        &'a self,
        request: RetainedRtpDecodeRequest,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RetainedRtpH264Decoder<'a>> {
        check_cancel(cx)?;
        let RtpRecoveryState::Complete { anchor } = &self.state else {
            return Err(RetainedRtpDecodeError::ImportPending);
        };
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|batch| &batch.new_anchor == anchor)
            .ok_or(RtpImportError::Binding)?;
        let [delta] = batch.deltas.as_slice() else {
            return Err(RtpImportError::Binding.into());
        };
        if delta.family != "rtpdump_import" || delta.witness_digest != Some(self.root) {
            return Err(RtpImportError::Binding.into());
        }
        let count = self
            .report
            .chunk_digests()
            .len()
            .checked_add(self.report.nals().len())
            .and_then(|n| n.checked_add(self.report.access_units().len().checked_mul(2)?))
            .and_then(|n| n.checked_add(2))
            .ok_or(RetainedRtpDecodeError::Limit)?;
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(count)
            .map_err(|_| RetainedRtpDecodeError::Limit)?;
        protected.extend([self.root, delta.payload_digest]);
        protected.extend(self.report.chunk_digests());
        protected.extend(self.report.nals().iter().map(|nal| nal.digest));
        for unit in self.report.access_units() {
            protected.extend([unit.capsule_object, unit.capsule.source_digest]);
        }
        protected.sort_unstable();
        protected.dedup();
        guard(self, &protected, deployment, cx)?;
        let candidates = self.h264_parameters(cx)?;
        if !candidates.sequence.contains(&request.parameters[0])
            || !candidates.picture.contains(&request.parameters[1])
        {
            return Err(RetainedRtpDecodeError::ParametersUnavailable);
        }
        let maximum = request.receiver.syntax.max_parameter_set_bytes.min(65_536);
        let sps = parameter(self, request.parameters[0], maximum, cx)?;
        let pps = parameter(self, request.parameters[1], maximum, cx)?;
        let stored = self.recipe.config;
        let config = AvcDumpConfig {
            key: stored.key,
            payload_type: stored.payload_type,
            mode: stored.mode,
            dump: stored.dump,
            receiver: request.receiver,
            rtcp: stored.rtcp,
        };
        let mask = current_mask(deployment, &self.recipe.scope.sensor)?;
        let decoder =
            RecordedRtpH264Decoder::new(&self.source, config, &sps, &pps, request.decode)?;
        guard(self, &protected, deployment, cx)?;
        Ok(RetainedRtpH264Decoder {
            retained: self,
            decoder: Some(decoder),
            mask,
            protected,
            stats: RetainedRtpDecodeStats::default(),
            stopped: false,
        })
    }
}

impl RetainedRtpH264Decoder<'_> {
    /// Current accounting; completion requires the terminal drain, never just input EOF.
    pub fn stats(&self) -> RetainedRtpDecodeStats {
        self.stats
    }
    /// Useful for scheduling; queued raw pictures still cannot bypass the next guard.
    pub fn queued_pictures(&self) -> usize {
        self.decoder
            .as_ref()
            .map_or(0, RecordedRtpH264Decoder::queued_pictures)
    }
    /// One bounded step. On authority/privacy failure the entire decoder is dropped and cannot
    /// be resumed; a fresh inspection and current privacy binding are required.
    pub fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RetainedRtpDecodeStep> {
        if self.stopped {
            return Ok(RetainedRtpDecodeStep::Ended(self.stats));
        }
        let result = self.advance(deployment, cx);
        if result.is_err() {
            self.decoder = None;
            self.stats.refusals += 1;
            self.stats.ended = true;
            self.stopped = true;
        }
        result
    }
    fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RetainedRtpDecodeStep> {
        guard(self.retained, &self.protected, deployment, cx)?;
        let decoder = self.decoder.as_mut().ok_or(RtpImportError::Binding)?;
        match decoder.step(cx) {
            RtpDecodeStep::Picture(frame) => {
                let frame = self.project(frame)?;
                guard(self.retained, &self.protected, deployment, cx)?;
                self.stats.frames += 1;
                Ok(RetainedRtpDecodeStep::Frame(frame))
            }
            RtpDecodeStep::Replay { event, effect } => {
                let event = project_event(&event);
                match event {
                    RetainedRtpEvent::Record { .. } | RetainedRtpEvent::RecordRefused { .. } => {
                        self.stats.records += 1;
                    }
                    RetainedRtpEvent::InputEnded => self.stats.input_ended = true,
                    _ => {}
                }
                if matches!(
                    event,
                    RetainedRtpEvent::RecordRefused { .. }
                        | RetainedRtpEvent::FramingRefused
                        | RetainedRtpEvent::ReceiverRefused
                ) || matches!(
                    effect,
                    RtpDecodeEffect::Refused { .. } | RtpDecodeEffect::Fenced
                ) {
                    self.stats.refusals += 1;
                }
                if matches!(effect, RtpDecodeEffect::WaitingForIdr { .. }) {
                    self.stats.skipped_groups += 1;
                }
                if matches!(effect, RtpDecodeEffect::Finished) {
                    self.stats.native_finished = true;
                }
                Ok(RetainedRtpDecodeStep::Progress { event, effect })
            }
            RtpDecodeStep::Exhausted => {
                self.stats.ended = true;
                self.stopped = true;
                self.decoder = None;
                Ok(RetainedRtpDecodeStep::Ended(self.stats))
            }
        }
    }
    fn project(&self, frame: RtpDecodedPicture) -> Result<RetainedRtpH264Frame> {
        let picture = frame.picture();
        let dimensions = [picture.width(), picture.height()];
        let mut luma = copy_bytes(picture.luma())?;
        let mut cb = copy_bytes(picture.cb())?;
        let mut cr = copy_bytes(picture.cr())?;
        self.mask.apply_luma(&mut luma, dimensions)?;
        self.mask.apply_chroma420(&mut cb, &mut cr, dimensions)?;
        Ok(RetainedRtpH264Frame {
            root: self.retained.root,
            sensor: self.retained.recipe.scope.sensor.clone(),
            stream: self.retained.recipe.scope.stream.clone(),
            capture: CaptureInterval::new(TimestampNs(0), self.retained.recipe.scope.receive_time)
                .map_err(RtpImportError::from)?,
            source: frame.source().clone(),
            dimensions,
            luma,
            cb,
            cr,
            mask: self.mask.clone(),
        })
    }
}

fn check_cancel(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("rtpdump:retained_decode")
        .map_err(|_| RetainedRtpDecodeError::Cancelled)
}
fn guard(
    retained: &RecoveredRtpImport,
    protected: &[ContentDigest],
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    check_cancel(cx)?;
    let publisher = deployment.publisher();
    if deployment.current_anchor() != &retained.basis
        || publisher.is_poisoned()
        || !publisher
            .root(&root_slot(retained.root)?)
            .is_some_and(|root| {
                root.root == retained.root && root.state == LocalPublicationState::Durable
            })
        || publisher
            .tombstones()
            .any(|digest| protected.binary_search(digest).is_ok())
    {
        return Err(RtpImportError::Binding.into());
    }
    Ok(())
}
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| RetainedRtpDecodeError::Limit)?;
    result.extend_from_slice(bytes);
    Ok(result)
}
fn parameter(
    retained: &RecoveredRtpImport,
    digest: ContentDigest,
    maximum: usize,
    cx: &ReplayCx,
) -> Result<Vec<u8>> {
    let nal = retained
        .report
        .nals()
        .iter()
        .find(|nal| {
            nal.digest == digest
                && retained
                    .report
                    .access_units()
                    .get(nal.access_unit)
                    .is_some_and(|unit| {
                        unit.generation == retained.recipe.config.key.generation
                            && unit.ssrc == retained.recipe.config.key.ssrc
                    })
        })
        .ok_or(RetainedRtpDecodeError::ParametersUnavailable)?;
    let length = nal
        .spans
        .iter()
        .map(|span| span.nal.end)
        .max()
        .ok_or(RtpImportError::Digest)?;
    if length == 0 || length > maximum {
        return Err(RetainedRtpDecodeError::Limit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| RetainedRtpDecodeError::Limit)?;
    bytes.resize(length, 0);
    for span in &nal.spans {
        check_cancel(cx)?;
        let original = retained
            .source
            .get(span.wire.clone())
            .ok_or(RtpImportError::Digest)?;
        let target = bytes
            .get_mut(span.nal.clone())
            .ok_or(RtpImportError::Digest)?;
        if original.len() != target.len() {
            return Err(RtpImportError::Digest.into());
        }
        target.copy_from_slice(original);
        if let Some(range) = &span.fragment_header {
            let header = retained
                .source
                .get(range.clone())
                .ok_or(RtpImportError::Digest)?;
            if header.len() != 2 {
                return Err(RtpImportError::Digest.into());
            }
            bytes[0] = (header[0] & 0xe0) | (header[1] & 31);
        }
    }
    if ContentDigest::sha256(&bytes) != digest {
        return Err(RtpImportError::Digest.into());
    }
    Ok(bytes)
}
fn project_event(event: &AvcDumpStep<'_>) -> RetainedRtpEvent {
    match event {
        AvcDumpStep::Record {
            source,
            offset_reversed,
            admission,
        } => {
            if matches!(
                admission,
                AvcDumpAdmission::CapturedPrefix(_)
                    | AvcDumpAdmission::Refused { .. }
                    | AvcDumpAdmission::Fenced
                    | AvcDumpAdmission::Rtcp(Err(_))
            ) {
                RetainedRtpEvent::RecordRefused {
                    index: source.index(),
                }
            } else {
                RetainedRtpEvent::Record {
                    index: source.index(),
                    offset_reversed: *offset_reversed,
                }
            }
        }
        AvcDumpStep::Progress(_) => RetainedRtpEvent::Progress,
        AvcDumpStep::InputEnded => RetainedRtpEvent::InputEnded,
        AvcDumpStep::FramingRefused { .. } => RetainedRtpEvent::FramingRefused,
        AvcDumpStep::ReceiverRefused { .. } | AvcDumpStep::Cancelled(_) => {
            RetainedRtpEvent::ReceiverRefused
        }
        AvcDumpStep::Exhausted => RetainedRtpEvent::ReceiverExhausted,
    }
}
