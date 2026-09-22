#![forbid(unsafe_code)]
//! Portable reconstruction instructions, not a trusted claim about reconstructed media.
//!
//! The fixed policy uses the existing collector's packet-disjoint IDR cuts and seals completed
//! groups only after PrefixReady. Timing is explicit and matched to the exact ordered request.
//! No manual mid-prefix seal, guessed duration, source fallback, or codec EOF is introduced.

use super::datagram_reconstruction::{AvcReplayBounds, AvcReplaySpec};
use super::datagram_reconstruction::recording::{DatagramRecordingReplay, RecordingReplayError, RecordingReplaySpec};
use crate::rtsp::datagram_archive::{DatagramArchive, DatagramArchiveError, DatagramPin};
use crate::rtsp::recording_capture::PictureTimingRequest;
use crate::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use fss_core::{ContentDigest, ContractError};
use fss_packet::avc::{AvcBoundary, AvcReceiveLimits};
use fss_packet::H264Mode;

mod codec;
mod driver;
pub use driver::{PlannedRecordingReplay, RecipeReplayFailure, RecipeReplayRetirement, RecipeReplayStep};

/// Hard bound on the whole portable recipe, including parameter sets and every timing decision.
pub const MAX_RECORDING_RECIPE_BYTES: usize = 2 * 1024 * 1024;
/// Hard bound on completed-picture timing decisions; no silent top-k or truncation.
pub const MAX_RECORDING_RECIPE_TIMINGS: usize = 4096;
const DOMAIN: &str = "fss.datagram_recording_recipe.v1";
const POLICY: &str = "ordered-explicit-timing;collector-idr-cuts;seal-completed-prefix;never-codec-eof";

/// Independent admission ceilings. A stored recipe cannot widen runtime resource authority.
#[derive(Clone, Copy, Debug)]
pub struct RecordingRecipeLimits {
    /// Complete canonical byte ceiling, at most MAX_RECORDING_RECIPE_BYTES.
    pub max_bytes: usize,
    /// Complete timing-decision ceiling, at most MAX_RECORDING_RECIPE_TIMINGS; zero is valid.
    pub max_timings: usize,
    /// Componentwise ceilings for stored receiver configuration. Tighter bounds refuse, not edit it.
    pub receiver: AvcReceiveLimits,
    /// Componentwise ceilings for stored collection configuration. Tighter bounds refuse it.
    pub collector: CollectorLimits,
}
impl Default for RecordingRecipeLimits {
    fn default() -> Self {
        Self { max_bytes: MAX_RECORDING_RECIPE_BYTES, max_timings: MAX_RECORDING_RECIPE_TIMINGS,
            receiver: AvcReceiveLimits::default(), collector: CollectorLimits::default() }
    }
}
impl RecordingRecipeLimits {
    fn validate(self) -> Result<(), RecordingRecipeError> {
        if self.max_bytes == 0 || self.max_bytes > MAX_RECORDING_RECIPE_BYTES
            || self.max_timings > MAX_RECORDING_RECIPE_TIMINGS {
            return Err(RecordingRecipeError::Limit);
        }
        Ok(())
    }
}

/// One explicit decision for the next ordered timing request, not a timestamp inferred from RTP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingTimingDecision {
    /// Exact number of source observations read when this request appeared.
    pub observations_read: u64,
    /// Exact bounded request, including epoch, RTP timestamp, frame number, boundary and bytes.
    pub picture: PictureTimingRequest,
    /// Owner-supplied media timing, interpreted under the recipe's timing evidence and tick rate.
    pub timing: RecordingTiming,
}

/// Errors contain no source payload, credentials or private filesystem paths.
#[derive(Debug)]
pub enum RecordingRecipeError {
    /// Unsupported domain/policy, malformed encoding or noncanonical bytes.
    Encoding(ContractError),
    /// An input, object or resource ceiling was exceeded.
    Limit,
    /// Exact source, scope, interpretation, root or picture request does not match.
    Mismatch,
    /// A timing decision is structurally invalid, overflowing or out of order.
    Timing,
    /// An observed picture has no corresponding retained timing decision.
    MissingTiming,
    /// The source prefix ended with unconsumed timing decisions.
    UnusedTiming,
    /// Fixed collection limits require a manual seal that this recipe policy does not authorize.
    CollectionPressure,
    /// A native reconstruction operation refused progress; original retirement is returned separately.
    Replay(RecordingReplayError),
    /// Current custody, storage work or cancellation refused progress.
    Source(DatagramArchiveError),
    /// Reconstruction has already transferred terminal ownership.
    Closed,
}
impl std::fmt::Display for RecordingRecipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording recipe refused: {self:?}")
    }
}
impl std::error::Error for RecordingRecipeError {}
impl From<ContractError> for RecordingRecipeError {
    fn from(e: ContractError) -> Self { Self::Encoding(e) }
}
impl From<DatagramArchiveError> for RecordingRecipeError {
    fn from(e: DatagramArchiveError) -> Self { Self::Source(e) }
}

#[derive(Clone)]
struct OwnedAvc {
    payload_type: u8,
    mode: H264Mode,
    sps: Vec<u8>,
    pps: Vec<u8>,
    limits: AvcReceiveLimits,
    reduced_rtcp: bool,
    configuration_evidence: ContentDigest,
}
impl OwnedAvc {
    fn spec(&self) -> AvcReplaySpec<'_> {
        AvcReplaySpec { payload_type: self.payload_type, mode: self.mode, sps: &self.sps,
            pps: &self.pps, limits: self.limits, reduced_rtcp: self.reduced_rtcp,
            configuration_evidence: self.configuration_evidence }
    }
}

/// Owned immutable instructions. Decoding validates structure/configuration, never certifies that
/// timing requests will match or that a recording exists. Execute through PlannedRecordingReplay.
/// Source/interpretation/timing identities are committed; operational deadlines are not serialized.
#[derive(Clone)]
pub struct RecordingRecipe {
    source: DatagramPin,
    avc: OwnedAvc,
    recording: RecordingReplaySpec,
    timings: Vec<RecordingTimingDecision>,
    interpretation: ContentDigest,
    bytes: Vec<u8>,
    identity: ContentDigest,
}
impl std::fmt::Debug for RecordingRecipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingRecipe").field("identity", &self.identity)
            .field("source", &self.source).field("timings", &self.timings.len()).finish_non_exhaustive()
    }
}
impl RecordingRecipe {
    /// Bind explicit inputs without reading storage. The archive's exact prefix must already be
    /// selected by its owner. This does not prove the decisions correspond to future native output.
    pub fn new(archive: &DatagramArchive, avc: AvcReplaySpec<'_>, recording: RecordingReplaySpec,
        timings: Vec<RecordingTimingDecision>, limits: RecordingRecipeLimits)
        -> Result<Self, RecordingRecipeError> {
        limits.validate()?;
        codec::check_limits(avc.limits, recording.limits, limits)?;
        if timings.len() > limits.max_timings || avc.sps.len() > avc.limits.syntax.max_parameter_set_bytes
            || avc.pps.len() > avc.limits.syntax.max_parameter_set_bytes {
            return Err(RecordingRecipeError::Limit);
        }
        let replay = DatagramRecordingReplay::new(archive, avc, recording.clone(),
            AvcReplayBounds { max_source_bytes: archive.pin().payload_bytes, max_steps: 1, deadline_ns: 1 }, 0)
            .map_err(RecordingRecipeError::Replay)?;
        let interpretation = replay.interpretation();
        let mut last_observation = 0;
        let mut last_end = None;
        for decision in &timings {
            let t = decision.timing;
            let end = t.decode_time.checked_add(u64::from(t.duration)).ok_or(RecordingRecipeError::Timing)?;
            if decision.observations_read == 0 || decision.observations_read > archive.pin().datagrams
                || decision.observations_read < last_observation
                || decision.picture.key != archive.scope().binding.key()
                || decision.picture.bytes == 0 || decision.picture.bytes > avc.limits.assembly.max_bytes
                || decision.picture.boundary == AvcBoundary::EndOfInputUnverified
                || t.duration == 0 || last_end.is_some_and(|at| t.decode_time < at)
                || t.decode_time.checked_add_signed(i64::from(t.composition_offset)).is_none() {
                return Err(RecordingRecipeError::Timing);
            }
            last_observation = decision.observations_read;
            last_end = Some(end);
        }
        let bytes = codec::encode(archive.pin(), avc, &recording, &timings, interpretation)?;
        if bytes.len() > limits.max_bytes { return Err(RecordingRecipeError::Limit); }
        let identity = ContentDigest::try_sha256(&bytes)?;
        let copy = |input: &[u8]| -> Result<Vec<u8>, RecordingRecipeError> {
            let mut out = Vec::new();
            out.try_reserve_exact(input.len()).map_err(|_| RecordingRecipeError::Limit)?;
            out.extend_from_slice(input); Ok(out)
        };
        Ok(Self { source: archive.pin(), avc: OwnedAvc { payload_type: avc.payload_type, mode: avc.mode,
            sps: copy(avc.sps)?, pps: copy(avc.pps)?, limits: avc.limits,
            reduced_rtcp: avc.reduced_rtcp, configuration_evidence: avc.configuration_evidence },
            recording, timings, interpretation, bytes, identity })
    }
    /// Decode against a separately selected source and external limits. Unknown versions,
    /// truncated/trailing bytes, altered sources and resource escalation fail closed.
    pub fn from_canonical_bytes(bytes: &[u8], archive: &DatagramArchive, limits: RecordingRecipeLimits)
        -> Result<Self, RecordingRecipeError> {
        limits.validate()?;
        if bytes.len() > limits.max_bytes { return Err(RecordingRecipeError::Limit); }
        codec::decode(bytes, archive, limits)
    }
    /// Complete immutable hand-written version-one encoding; contains no source media payload.
    pub fn canonical_bytes(&self) -> &[u8] { &self.bytes }
    /// Digest of the whole recipe, including the ordered decisions and fixed cut policy.
    pub fn identity(&self) -> ContentDigest { self.identity }
    /// Exact selected source prefix. This is not a declaration of EOF or continuity.
    pub fn source(&self) -> DatagramPin { self.source }
    /// Existing native receiver/recording interpretation, separately from timing choices.
    pub fn interpretation(&self) -> ContentDigest { self.interpretation }
    /// All retained timing decisions, without an implicit missing/default entry.
    pub fn timings(&self) -> &[RecordingTimingDecision] { &self.timings }
    /// Exact codec configuration; its lifetime cannot outlive the recipe's owned parameter bytes.
    pub fn avc_spec(&self) -> AvcReplaySpec<'_> { self.avc.spec() }
    /// Exact retained recording interpretation, not a grant to read or retain footage.
    pub fn recording_spec(&self) -> &RecordingReplaySpec { &self.recording }
}
