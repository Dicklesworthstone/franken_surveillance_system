#![forbid(unsafe_code)]
//! Portable HEVC reconstruction instructions, never source, clock or publication authority.
//!
//! A versioned recipe binds an exact retained prefix, the original VPS/SPS/PPS and native
//! interpretation, and every ordered timing request/decision. Its fixed cut policy uses native
//! collector IDR cuts and explicit final prefix sealing, never a guessed codec EOF.

use crate::rtsp::datagram_archive::{DatagramArchive, DatagramArchiveError, DatagramPin};
use crate::rtsp::datagram_reconstruction::hevc::recording::{
    DatagramHevcRecordingReplay, HevcRecordingReplayError, HevcRecordingReplaySpec,
};
use crate::rtsp::datagram_reconstruction::hevc::{HevcReplayBounds, HevcReplaySpec};
use crate::rtsp::hevc_recording_capture::HevcPictureTimingRequest;
use crate::rtsp::recording::hevc::HevcRecordingTiming;
use crate::rtsp::recording_collector::CollectorLimits;
use fss_core::{ContentDigest, ContractError};
use fss_packet::hevc::{
    HevcAssemblyLimits, HevcBoundary, HevcConfiguration, HevcConfigurationError,
    HevcConfigurationLimits,
};
use fss_packet::{H265Limits, ReorderLimits};

mod codec;
mod driver;
/// Source-closed recipe publication and exact cold loading through the native publisher.
pub mod storage;
pub use driver::{
    PlannedRecordingReplay, RecipeReplayFailure, RecipeReplayRetirement, RecipeReplayStep,
};

pub use super::{MAX_RECORDING_RECIPE_BYTES, MAX_RECORDING_RECIPE_TIMINGS};
const DOMAIN: &str = "fss.datagram_hevc_recording_recipe.v1";
const POLICY: &str =
    "ordered-explicit-timing;native-idr-cuts;seal-verified-prefix;preserve-eob;never-codec-eof";

/// External admission ceilings; stored metadata cannot enlarge resource authority.
#[derive(Clone, Copy, Debug)]
pub struct RecordingRecipeLimits {
    /// Whole canonical metadata, at most two MiB.
    pub max_bytes: usize,
    /// All timing decisions, at most 4096; no truncation or implied default timing.
    pub max_timings: usize,
    /// Componentwise original packet/reordering ceilings.
    pub reorder: ReorderLimits,
    /// Componentwise reconstruction/fragment ceilings.
    pub reconstruction: H265Limits,
    /// Current parameter-set parsing ceilings, not a stored authority grant.
    pub configuration: HevcConfigurationLimits,
    /// Componentwise native grouping ceilings.
    pub assembly: HevcAssemblyLimits,
    /// Componentwise collection ceilings.
    pub collector: CollectorLimits,
}
impl Default for RecordingRecipeLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_RECORDING_RECIPE_BYTES,
            max_timings: MAX_RECORDING_RECIPE_TIMINGS,
            reorder: ReorderLimits::default(),
            reconstruction: H265Limits::default(),
            configuration: HevcConfigurationLimits::default(),
            assembly: HevcAssemblyLimits::default(),
            collector: CollectorLimits::default(),
        }
    }
}
impl RecordingRecipeLimits {
    fn validate(self) -> Result<(), RecordingRecipeError> {
        if self.max_bytes == 0
            || self.max_bytes > MAX_RECORDING_RECIPE_BYTES
            || self.max_timings > MAX_RECORDING_RECIPE_TIMINGS
        {
            return Err(RecordingRecipeError::Limit);
        }
        self.configuration
            .validate()
            .map_err(RecordingRecipeError::Configuration)?;
        Ok(())
    }
}

/// One decision for the exact next native request, not timing inferred from arrival or RTP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingTimingDecision {
    /// Original observation count when the request appeared (several requests may share it).
    pub observations_read: u64,
    /// Exact epoch, timestamp, IDR classification, real boundary and held byte count.
    pub picture: HevcPictureTimingRequest,
    /// Explicit media ticks under the recipe's separate timing-evidence identity.
    pub timing: HevcRecordingTiming,
}

/// Payload/path-free structural and execution refusals. Failure ownership is separate.
#[derive(Debug)]
pub enum RecordingRecipeError {
    /// Unsupported or noncanonical byte encoding.
    Encoding(ContractError),
    /// Current metadata or native resource ceiling exceeded.
    Limit,
    /// Source, codec interpretation, root or exact picture request differs.
    Mismatch,
    /// Invalid, overflowing or unordered timing decision.
    Timing,
    /// A native picture request has no retained decision.
    MissingTiming,
    /// Input reached its real boundary with unconsumed decisions.
    UnusedTiming,
    /// The fixed program would need an unrecorded manual mid-prefix seal.
    CollectionPressure,
    /// Native parameter-set prefix validation refused.
    Configuration(HevcConfigurationError),
    /// Native recording replay refused; all original ownership is retained separately.
    Replay(HevcRecordingReplayError),
    /// Current original-source read, work or custody refused.
    Source(DatagramArchiveError),
    /// Terminal ownership already transferred.
    Closed,
}
impl std::fmt::Display for RecordingRecipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HEVC recording recipe refused: {self:?}")
    }
}
impl std::error::Error for RecordingRecipeError {}
impl From<ContractError> for RecordingRecipeError {
    fn from(e: ContractError) -> Self {
        Self::Encoding(e)
    }
}
impl From<DatagramArchiveError> for RecordingRecipeError {
    fn from(e: DatagramArchiveError) -> Self {
        Self::Source(e)
    }
}

/// Immutable version-one program. Decoding validates instructions, not that media exists.
/// No operational clock, deadline or work allowance is restored from serialized bytes.
pub struct RecordingRecipe {
    source: DatagramPin,
    hevc: HevcReplaySpec,
    recording: HevcRecordingReplaySpec,
    timings: Vec<RecordingTimingDecision>,
    interpretation: ContentDigest,
    bytes: Vec<u8>,
    identity: ContentDigest,
}
impl std::fmt::Debug for RecordingRecipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcRecordingRecipe")
            .field("identity", &self.identity)
            .field("source", &self.source)
            .field("timings", &self.timings.len())
            .finish_non_exhaustive()
    }
}
impl RecordingRecipe {
    /// Bind explicit original parameters and exact timing choices without storage/network I/O.
    pub fn new(
        archive: &DatagramArchive,
        hevc: HevcReplaySpec,
        recording: HevcRecordingReplaySpec,
        timings: Vec<RecordingTimingDecision>,
        limits: RecordingRecipeLimits,
    ) -> Result<Self, RecordingRecipeError> {
        limits.validate()?;
        codec::check_limits(hevc, &recording, limits)?;
        if timings.len() > limits.max_timings {
            return Err(RecordingRecipeError::Limit);
        }
        let replay = DatagramHevcRecordingReplay::new(
            archive,
            hevc,
            copy_spec(&recording, limits.configuration)?,
            HevcReplayBounds {
                max_source_bytes: archive.pin().payload_bytes,
                max_steps: 1,
                deadline_ns: 1,
            },
            0,
        )
        .map_err(RecordingRecipeError::Replay)?;
        let interpretation = replay.interpretation();
        let mut last_observation = 0;
        let mut last_end = None;
        for d in &timings {
            let t = d.timing;
            let end = t
                .decode_time
                .checked_add(u64::from(t.duration))
                .ok_or(RecordingRecipeError::Timing)?;
            if d.observations_read == 0
                || d.observations_read > archive.pin().datagrams
                || d.observations_read < last_observation
                || d.picture.key != archive.scope().binding.key()
                || d.picture.bytes == 0
                || d.picture.bytes > recording.assembly.max_bytes
                || d.picture.boundary == HevcBoundary::EndOfInputUnverified
                || t.duration == 0
                || last_end.is_some_and(|at| t.decode_time < at)
                || t.decode_time
                    .checked_add_signed(i64::from(t.composition_offset))
                    .is_none()
            {
                return Err(RecordingRecipeError::Timing);
            }
            last_observation = d.observations_read;
            last_end = Some(end);
        }
        let bytes = codec::encode(archive.pin(), hevc, &recording, &timings, interpretation)?;
        if bytes.len() > limits.max_bytes {
            return Err(RecordingRecipeError::Limit);
        }
        let identity = ContentDigest::try_sha256(&bytes)?;
        Ok(Self {
            source: archive.pin(),
            hevc,
            recording,
            timings,
            interpretation,
            bytes,
            identity,
        })
    }
    /// Decode the whole canonical program under externally supplied limits and source selection.
    /// Unknown versions, cross-codec input, truncation, trailing bytes and resource escalation refuse.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        archive: &DatagramArchive,
        limits: RecordingRecipeLimits,
    ) -> Result<Self, RecordingRecipeError> {
        limits.validate()?;
        if bytes.len() > limits.max_bytes {
            return Err(RecordingRecipeError::Limit);
        }
        codec::decode(bytes, archive, limits)
    }
    /// Exact immutable encoding, including parameter sets but no original media payload.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Whole program digest, distinct from its source-closed publication root.
    pub fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact retained prefix, never a stream-complete claim.
    pub fn source(&self) -> DatagramPin {
        self.source
    }
    /// Existing native transport/recording interpretation, independent of timing decisions.
    pub fn interpretation(&self) -> ContentDigest {
        self.interpretation
    }
    /// Complete ordered decisions; no mutable timing override.
    pub fn timings(&self) -> &[RecordingTimingDecision] {
        &self.timings
    }
    /// Original negotiated transport interpretation, not read/network authority.
    pub fn hevc_spec(&self) -> HevcReplaySpec {
        self.hevc
    }
    /// Original parameter tuple, clock scope, timing evidence and collection/grouping policy.
    pub fn recording_spec(&self) -> &HevcRecordingReplaySpec {
        &self.recording
    }
}
fn copy_spec(
    spec: &HevcRecordingReplaySpec,
    limits: HevcConfigurationLimits,
) -> Result<HevcRecordingReplaySpec, RecordingRecipeError> {
    Ok(HevcRecordingReplaySpec {
        scope: spec.scope.clone(),
        configuration: HevcConfiguration::parse(
            spec.configuration.vps(),
            spec.configuration.sps(),
            spec.configuration.pps(),
            limits,
        )
        .map_err(RecordingRecipeError::Configuration)?,
        time_scale: spec.time_scale,
        limits: spec.limits,
        assembly: spec.assembly,
        timing_evidence: spec.timing_evidence,
    })
}
