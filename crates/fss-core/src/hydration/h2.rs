#![forbid(unsafe_code)]
//! Realization of hydration ladder level H2: decision_artifact (AGT-H2, fss-x4a.30.82.14).
//!
//! H2 represents an authorized, redacted decision artifact:
//! - keyframes (authorized redacted video keyframes)
//! - crops (authorized redacted bounding spatial crops)
//! - trajectories (authorized redacted spatio-temporal waypoints)
//! - graph neighborhoods (authorized redacted k-hop graph neighborhoods)
//! - audio features (authorized redacted acoustic spectral features)
//!
//! Invariants:
//! - Level is strictly [`HydrationLevel::H2`].
//! - Artifacts must be explicitly authorized with an authorization grant ID.
//! - Artifacts must carry a redaction transform from the internal [`RedactionTransform`] vocabulary
//!   (not a registry; see the drift records in `architecture/agent_contracts.json`) and the only
//!   privacy class fss-core already uses, `private:property`.
//! - Raw unredacted media, raw camera streams, and ungrounded cognition are strictly prohibited.
//! - Proof roots must include both the exact payload digest and the subject digest, and every other
//!   root must come from caller-held [`RetainedProvenance`]; decoding goes only through
//!   [`H2DecisionArtifact::decode_verified`], which re-checks the roots against that provenance.
//! - Completeness must not be Unknown, NotObservable, Unauthorized, or Stale.

use std::collections::BTreeSet;

use super::{
    Completeness, HydrationArtifact, HydrationError, HydrationLevel, MAX_REQUEST_SET_ITEMS,
    SemanticHandle, decode_optional_text, decode_text_set, encode_optional_text, encode_text_set,
    valid_text,
};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::{
    BudgetVector, CaptureInterval, ContentDigest, ContractBasis, LedgerAnchor,
    MAX_CANONICAL_BYTES_LEN, TimestampNs,
};

/// Stable identifier for hydration ladder level H2.
pub const H2_LEVEL_ID: &str = "H2";

/// Stable name for hydration ladder level H2.
pub const H2_LEVEL_NAME: &str = "decision_artifact";

/// Normative content declaration for hydration ladder level H2 from the agent abstraction registry.
pub const H2_CONTENT: &str =
    "authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features";

/// Owning subsystem for hydration ladder level H2 pinned to architecture/semantic_hydration.json.
pub const H2_OWNER: &str = "fss-agent-core";

/// Canonical schema discriminator tag for H2 decision artifact binary envelopes.
pub const H2_SCHEMA: &str = "fss.h2_decision_artifact.v1";

/// Recognized privacy redaction transforms for H2 decision artifacts.
///
/// Drift: the `transform:*` identifiers are not backed by any machine registry in `registries/` or
/// `architecture/` (drift record in `architecture/agent_contracts.json`). They are an internal
/// typed vocabulary and must not be called registered until a canonical registry is ratified.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RedactionTransform {
    /// Face blurring filter.
    FaceBlur,
    /// License plate masking filter.
    PlateMask,
    /// Combined face blurring and license plate masking.
    FaceBlurAndPlateMask,
    /// Bounding-box area obscuration / redaction.
    BoundingBoxRedact,
    /// Pixelation / mosaic transform.
    Pixelate,
    /// Spatial cropping with perimeter redaction.
    CropRedact,
    /// Spatio-temporal trajectory coarsening / dithering.
    TrajectoryCoarsen,
    /// Sub-graph neighborhood attribute masking.
    GraphNeighborhoodRedact,
    /// Acoustic voice masking and feature extraction.
    AudioFeatureExtraction,
}

impl RedactionTransform {
    /// All 9 recognized redaction transforms.
    pub const ALL: [Self; 9] = [
        Self::FaceBlur,
        Self::PlateMask,
        Self::FaceBlurAndPlateMask,
        Self::BoundingBoxRedact,
        Self::Pixelate,
        Self::CropRedact,
        Self::TrajectoryCoarsen,
        Self::GraphNeighborhoodRedact,
        Self::AudioFeatureExtraction,
    ];

    /// Returns the canonical transform URI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FaceBlur => "transform:face_blur",
            Self::PlateMask => "transform:plate_mask",
            Self::FaceBlurAndPlateMask => "transform:face_blur_and_plate_mask",
            Self::BoundingBoxRedact => "transform:bounding_box_redact",
            Self::Pixelate => "transform:pixelate",
            Self::CropRedact => "transform:crop_redact",
            Self::TrajectoryCoarsen => "transform:trajectory_coarsen",
            Self::GraphNeighborhoodRedact => "transform:graph_neighborhood_redact",
            Self::AudioFeatureExtraction => "transform:audio_feature_extraction",
        }
    }

    /// Parses a recognized transform URI with exact matching.
    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "transform:face_blur" => Ok(Self::FaceBlur),
            "transform:plate_mask" => Ok(Self::PlateMask),
            "transform:face_blur_and_plate_mask" => Ok(Self::FaceBlurAndPlateMask),
            "transform:bounding_box_redact" => Ok(Self::BoundingBoxRedact),
            "transform:pixelate" => Ok(Self::Pixelate),
            "transform:crop_redact" => Ok(Self::CropRedact),
            "transform:trajectory_coarsen" => Ok(Self::TrajectoryCoarsen),
            "transform:graph_neighborhood_redact" => Ok(Self::GraphNeighborhoodRedact),
            "transform:audio_feature_extraction" => Ok(Self::AudioFeatureExtraction),
            _ => Err(ContractError::InvalidRedactionTransform),
        }
    }

    /// Returns true if this transform is permitted for the given artifact kind.
    #[must_use]
    pub fn is_compatible_with_kind(&self, kind: &DecisionArtifactKind) -> bool {
        match kind {
            DecisionArtifactKind::Keyframe(_) => matches!(
                self,
                Self::FaceBlur
                    | Self::PlateMask
                    | Self::FaceBlurAndPlateMask
                    | Self::BoundingBoxRedact
                    | Self::Pixelate
            ),
            DecisionArtifactKind::Crop(_) => matches!(
                self,
                Self::CropRedact
                    | Self::FaceBlur
                    | Self::PlateMask
                    | Self::FaceBlurAndPlateMask
                    | Self::BoundingBoxRedact
                    | Self::Pixelate
            ),
            DecisionArtifactKind::Trajectory(_) => matches!(self, Self::TrajectoryCoarsen),
            DecisionArtifactKind::GraphNeighborhood(_) => {
                matches!(self, Self::GraphNeighborhoodRedact)
            }
            DecisionArtifactKind::AudioFeatures(_) => {
                matches!(self, Self::AudioFeatureExtraction)
            }
        }
    }
}

/// Returns the internal [`RedactionTransform`] a token names, if any.
///
/// Crate-internal on purpose: the `transform:*` tokens have no machine registry behind them, so no
/// public predicate may present them as registered.
pub(crate) fn recognized_redaction_transform(s: &str) -> Option<RedactionTransform> {
    RedactionTransform::parse(s).ok()
}

/// Typed privacy class accepted by H2 decision artifacts.
///
/// Reuses the only privacy class fss-core already uses, `private:property`, and invents no other
/// vocabulary. Every other string, raw or unredacted media included, is refused with
/// [`ContractError::InvalidPrivacyClass`]. Drift: no machine registry of privacy classes exists
/// (drift record in `architecture/agent_contracts.json`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H2PrivacyClass {
    /// Private property classification (`private:property`).
    PrivateProperty,
}

impl H2PrivacyClass {
    /// Canonical token of this privacy class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateProperty => "private:property",
        }
    }

    /// Parses an exact privacy class token; anything else is [`ContractError::InvalidPrivacyClass`].
    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "private:property" => Ok(Self::PrivateProperty),
            _ => Err(ContractError::InvalidPrivacyClass),
        }
    }
}

fn is_negative_zero(val: f32) -> bool {
    val.to_bits() == (-0.0_f32).to_bits()
}

fn is_negative_zero_f64(val: f64) -> bool {
    val.to_bits() == (-0.0_f64).to_bits()
}

/// A bounding box with normalized coordinates in range `[0.0, 1.0]`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoundingBox {
    x_min: f32,
    y_min: f32,
    x_max: f32,
    y_max: f32,
}

impl BoundingBox {
    /// Creates and validates a new bounding box.
    pub fn new(x_min: f32, y_min: f32, x_max: f32, y_max: f32) -> Result<Self, ContractError> {
        if is_negative_zero(x_min)
            || is_negative_zero(y_min)
            || is_negative_zero(x_max)
            || is_negative_zero(y_max)
            || !x_min.is_finite()
            || !y_min.is_finite()
            || !x_max.is_finite()
            || !y_max.is_finite()
            || !(0.0..=1.0).contains(&x_min)
            || !(0.0..=1.0).contains(&y_min)
            || !(0.0..=1.0).contains(&x_max)
            || !(0.0..=1.0).contains(&y_max)
            || x_min >= x_max
            || y_min >= y_max
        {
            return Err(ContractError::InvalidSpatialExtent);
        }
        Ok(Self {
            x_min,
            y_min,
            x_max,
            y_max,
        })
    }

    /// Validates the bounding box invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        Self::new(self.x_min, self.y_min, self.x_max, self.y_max).map(|_| ())
    }

    /// Left horizontal boundary normalized to `[0.0, 1.0]`.
    #[must_use]
    pub const fn x_min(&self) -> f32 {
        self.x_min
    }

    /// Top vertical boundary normalized to `[0.0, 1.0]`.
    #[must_use]
    pub const fn y_min(&self) -> f32 {
        self.y_min
    }

    /// Right horizontal boundary normalized to `[0.0, 1.0]`.
    #[must_use]
    pub const fn x_max(&self) -> f32 {
        self.x_max
    }

    /// Bottom vertical boundary normalized to `[0.0, 1.0]`.
    #[must_use]
    pub const fn y_max(&self) -> f32 {
        self.y_max
    }
}

impl CanonicalEncode for BoundingBox {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.x_min.to_bits());
        encoder.u32(self.y_min.to_bits());
        encoder.u32(self.x_max.to_bits());
        encoder.u32(self.y_max.to_bits());
    }
}

impl CanonicalDecode for BoundingBox {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let x_min = f32::from_bits(decoder.u32()?);
        let y_min = f32::from_bits(decoder.u32()?);
        let x_max = f32::from_bits(decoder.u32()?);
        let y_max = f32::from_bits(decoder.u32()?);
        Self::new(x_min, y_min, x_max, y_max)
    }
}

/// A spatial region in a visual artifact that underwent privacy redaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedRegion {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    method: String,
}

impl RedactedRegion {
    /// Creates and validates a new redacted region.
    pub fn new(
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        method: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let method = method.into();
        let region = Self {
            x,
            y,
            width,
            height,
            method,
        };
        region.validate()?;
        Ok(region)
    }

    /// Validates the redacted region invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.width == 0
            || self.height == 0
            || !valid_text(&self.method)
            || self.x.checked_add(self.width).is_none()
            || self.y.checked_add(self.height).is_none()
        {
            return Err(ContractError::InvalidSpatialExtent);
        }
        Ok(())
    }

    /// Left coordinate in pixels.
    #[must_use]
    pub const fn x(&self) -> u32 {
        self.x
    }

    /// Top coordinate in pixels.
    #[must_use]
    pub const fn y(&self) -> u32 {
        self.y
    }

    /// Width in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Height in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Redaction method description.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
}

impl CanonicalEncode for RedactedRegion {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.x);
        encoder.u32(self.y);
        encoder.u32(self.width);
        encoder.u32(self.height);
        encoder.text(&self.method);
    }
}

impl CanonicalDecode for RedactedRegion {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let x = decoder.u32()?;
        let y = decoder.u32()?;
        let width = decoder.u32()?;
        let height = decoder.u32()?;
        let method = decoder.text()?.to_string();
        Self::new(x, y, width, height, method)
    }
}

/// A single spatio-temporal waypoint in an authorized trajectory.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrajectoryWaypoint {
    timestamp_ns: TimestampNs,
    x: f64,
    y: f64,
    z: f64,
}

impl TrajectoryWaypoint {
    /// Creates a validated waypoint.
    pub fn new(timestamp_ns: TimestampNs, x: f64, y: f64, z: f64) -> Result<Self, ContractError> {
        if !x.is_finite()
            || !y.is_finite()
            || !z.is_finite()
            || is_negative_zero_f64(x)
            || is_negative_zero_f64(y)
            || is_negative_zero_f64(z)
        {
            return Err(ContractError::InvalidSpatialExtent);
        }
        Ok(Self {
            timestamp_ns,
            x,
            y,
            z,
        })
    }

    /// Validates waypoint finite coordinates.
    pub fn validate(&self) -> Result<(), ContractError> {
        Self::new(self.timestamp_ns, self.x, self.y, self.z).map(|_| ())
    }

    /// Observation timestamp.
    #[must_use]
    pub const fn timestamp_ns(&self) -> TimestampNs {
        self.timestamp_ns
    }

    /// Coordinate X.
    #[must_use]
    pub const fn x(&self) -> f64 {
        self.x
    }

    /// Coordinate Y.
    #[must_use]
    pub const fn y(&self) -> f64 {
        self.y
    }

    /// Coordinate Z.
    #[must_use]
    pub const fn z(&self) -> f64 {
        self.z
    }
}

impl CanonicalEncode for TrajectoryWaypoint {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.timestamp_ns.encode_canonical(encoder);
        encoder.u64(self.x.to_bits());
        encoder.u64(self.y.to_bits());
        encoder.u64(self.z.to_bits());
    }
}

impl CanonicalDecode for TrajectoryWaypoint {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let timestamp_ns = TimestampNs::decode_canonical(decoder)?;
        let x = f64::from_bits(decoder.u64()?);
        let y = f64::from_bits(decoder.u64()?);
        let z = f64::from_bits(decoder.u64()?);
        Self::new(timestamp_ns, x, y, z)
    }
}

/// An authorized redacted video keyframe artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyframeArtifact {
    timestamp_ns: TimestampNs,
    stream_id: String,
    width: u32,
    height: u32,
    format: String,
    redacted_regions: Vec<RedactedRegion>,
}

impl KeyframeArtifact {
    /// Creates and validates a new keyframe artifact.
    pub fn new(
        timestamp_ns: TimestampNs,
        stream_id: impl Into<String>,
        width: u32,
        height: u32,
        format: impl Into<String>,
        redacted_regions: Vec<RedactedRegion>,
    ) -> Result<Self, ContractError> {
        let artifact = Self {
            timestamp_ns,
            stream_id: stream_id.into(),
            width,
            height,
            format: format.into(),
            redacted_regions,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates keyframe artifact bounds and ensures all redacted regions fit inside the frame.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.stream_id)
            || self.width == 0
            || self.height == 0
            || !valid_text(&self.format)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for r in &self.redacted_regions {
            r.validate()?;
            let x_end = r
                .x()
                .checked_add(r.width())
                .ok_or(ContractError::InvalidSpatialExtent)?;
            let y_end = r
                .y()
                .checked_add(r.height())
                .ok_or(ContractError::InvalidSpatialExtent)?;
            if x_end > self.width || y_end > self.height {
                return Err(ContractError::InvalidSpatialExtent);
            }
        }
        Ok(())
    }

    /// Capture timestamp of the keyframe.
    #[must_use]
    pub const fn timestamp_ns(&self) -> TimestampNs {
        self.timestamp_ns
    }

    /// Sensor or stream identifier.
    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Width in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Height in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Encoding MIME format.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Redacted spatial regions.
    #[must_use]
    pub fn redacted_regions(&self) -> &[RedactedRegion] {
        &self.redacted_regions
    }
}

impl CanonicalEncode for KeyframeArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.timestamp_ns.encode_canonical(encoder);
        encoder.text(&self.stream_id);
        encoder.u32(self.width);
        encoder.u32(self.height);
        encoder.text(&self.format);
        encoder.u64(self.redacted_regions.len() as u64);
        for region in &self.redacted_regions {
            region.encode_canonical(encoder);
        }
    }
}

impl CanonicalDecode for KeyframeArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let timestamp_ns = TimestampNs::decode_canonical(decoder)?;
        let stream_id = decoder.text()?.to_string();
        let width = decoder.u32()?;
        let height = decoder.u32()?;
        let format = decoder.text()?.to_string();
        let region_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if region_count > MAX_REQUEST_SET_ITEMS || decoder.remaining() < region_count {
            return Err(ContractError::InvalidDigest);
        }
        let mut redacted_regions = Vec::with_capacity(region_count);
        for _ in 0..region_count {
            redacted_regions.push(RedactedRegion::decode_canonical(decoder)?);
        }
        let artifact = Self {
            timestamp_ns,
            stream_id,
            width,
            height,
            format,
            redacted_regions,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

/// An authorized redacted bounding crop artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct CropArtifact {
    timestamp_ns: TimestampNs,
    source_stream_id: String,
    bounding_box: BoundingBox,
    target_entity_anchor: Option<String>,
    format: String,
    redacted_regions: Vec<RedactedRegion>,
}

impl CropArtifact {
    /// Creates and validates a new crop artifact.
    pub fn new(
        timestamp_ns: TimestampNs,
        source_stream_id: impl Into<String>,
        bounding_box: BoundingBox,
        target_entity_anchor: Option<String>,
        format: impl Into<String>,
        redacted_regions: Vec<RedactedRegion>,
    ) -> Result<Self, ContractError> {
        let artifact = Self {
            timestamp_ns,
            source_stream_id: source_stream_id.into(),
            bounding_box,
            target_entity_anchor,
            format: format.into(),
            redacted_regions,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates crop artifact bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.source_stream_id) || !valid_text(&self.format) {
            return Err(ContractError::InvalidIdentifier);
        }
        self.bounding_box.validate()?;
        if let Some(ref anchor) = self.target_entity_anchor
            && !valid_text(anchor)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for r in &self.redacted_regions {
            r.validate()?;
        }
        Ok(())
    }

    /// Source timestamp.
    #[must_use]
    pub const fn timestamp_ns(&self) -> TimestampNs {
        self.timestamp_ns
    }

    /// Source stream identifier.
    #[must_use]
    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    /// Normalized bounding box within the source frame.
    #[must_use]
    pub const fn bounding_box(&self) -> BoundingBox {
        self.bounding_box
    }

    /// Associated entity anchor.
    #[must_use]
    pub fn target_entity_anchor(&self) -> Option<&str> {
        self.target_entity_anchor.as_deref()
    }

    /// Image encoding format.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Redacted sub-regions.
    #[must_use]
    pub fn redacted_regions(&self) -> &[RedactedRegion] {
        &self.redacted_regions
    }
}

impl CanonicalEncode for CropArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.timestamp_ns.encode_canonical(encoder);
        encoder.text(&self.source_stream_id);
        self.bounding_box.encode_canonical(encoder);
        encode_optional_text(self.target_entity_anchor.as_deref(), encoder);
        encoder.text(&self.format);
        encoder.u64(self.redacted_regions.len() as u64);
        for region in &self.redacted_regions {
            region.encode_canonical(encoder);
        }
    }
}

impl CanonicalDecode for CropArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let timestamp_ns = TimestampNs::decode_canonical(decoder)?;
        let source_stream_id = decoder.text()?.to_string();
        let bounding_box = BoundingBox::decode_canonical(decoder)?;
        let target_entity_anchor = decode_optional_text(decoder)?.map(|s| s.to_string());
        let format = decoder.text()?.to_string();
        let region_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if region_count > MAX_REQUEST_SET_ITEMS || decoder.remaining() < region_count {
            return Err(ContractError::InvalidDigest);
        }
        let mut redacted_regions = Vec::with_capacity(region_count);
        for _ in 0..region_count {
            redacted_regions.push(RedactedRegion::decode_canonical(decoder)?);
        }
        let artifact = Self {
            timestamp_ns,
            source_stream_id,
            bounding_box,
            target_entity_anchor,
            format,
            redacted_regions,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

/// An authorized redacted spatio-temporal trajectory artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct TrajectoryArtifact {
    entity_anchor: String,
    time_window: CaptureInterval,
    waypoints: Vec<TrajectoryWaypoint>,
    coordinate_frame: String,
    coarsened: bool,
}

impl TrajectoryArtifact {
    /// Creates and validates a new trajectory artifact.
    pub fn new(
        entity_anchor: impl Into<String>,
        time_window: CaptureInterval,
        waypoints: Vec<TrajectoryWaypoint>,
        coordinate_frame: impl Into<String>,
        coarsened: bool,
    ) -> Result<Self, ContractError> {
        let artifact = Self {
            entity_anchor: entity_anchor.into(),
            time_window,
            waypoints,
            coordinate_frame: coordinate_frame.into(),
            coarsened,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates trajectory invariants, requiring strictly increasing waypoints within the time window.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.entity_anchor)
            || !valid_text(&self.coordinate_frame)
            || self.waypoints.is_empty()
            || self.time_window.earliest > self.time_window.latest
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut prev_ts: Option<TimestampNs> = None;
        for wp in &self.waypoints {
            wp.validate()?;
            if wp.timestamp_ns() < self.time_window.earliest
                || wp.timestamp_ns() > self.time_window.latest
            {
                return Err(ContractError::InvertedTimeInterval);
            }
            if let Some(prev) = prev_ts
                && wp.timestamp_ns() <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_ts = Some(wp.timestamp_ns());
        }
        Ok(())
    }

    /// Entity anchor denoted by this trajectory.
    #[must_use]
    pub fn entity_anchor(&self) -> &str {
        &self.entity_anchor
    }

    /// Bounding capture interval.
    #[must_use]
    pub const fn time_window(&self) -> CaptureInterval {
        self.time_window
    }

    /// Spatio-temporal waypoints sequence.
    #[must_use]
    pub fn waypoints(&self) -> &[TrajectoryWaypoint] {
        &self.waypoints
    }

    /// Coordinate frame identifier.
    #[must_use]
    pub fn coordinate_frame(&self) -> &str {
        &self.coordinate_frame
    }

    /// Whether spatial coarsening was applied.
    #[must_use]
    pub const fn coarsened(&self) -> bool {
        self.coarsened
    }
}

impl CanonicalEncode for TrajectoryArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.entity_anchor);
        self.time_window.encode_canonical(encoder);
        encoder.u64(self.waypoints.len() as u64);
        for wp in &self.waypoints {
            wp.encode_canonical(encoder);
        }
        encoder.text(&self.coordinate_frame);
        encoder.bool(self.coarsened);
    }
}

impl CanonicalDecode for TrajectoryArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let entity_anchor = decoder.text()?.to_string();
        let time_window = CaptureInterval::decode_canonical(decoder)?;
        let wp_count = usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if wp_count == 0 || wp_count > MAX_REQUEST_SET_ITEMS || decoder.remaining() < wp_count {
            return Err(ContractError::InvalidDigest);
        }
        let mut waypoints = Vec::with_capacity(wp_count);
        let mut prev_ts: Option<TimestampNs> = None;
        for _ in 0..wp_count {
            let wp = TrajectoryWaypoint::decode_canonical(decoder)?;
            if let Some(prev) = prev_ts
                && wp.timestamp_ns() <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_ts = Some(wp.timestamp_ns());
            waypoints.push(wp);
        }
        let coordinate_frame = decoder.text()?.to_string();
        let coarsened = decoder.bool()?;
        let artifact = Self {
            entity_anchor,
            time_window,
            waypoints,
            coordinate_frame,
            coarsened,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

/// An authorized redacted graph neighborhood artifact (k-hop sub-graph).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphNeighborhoodArtifact {
    center_entity_id: String,
    radius_hops: u8,
    node_count: u32,
    edge_count: u32,
    subgraph_digest: ContentDigest,
    masked_attributes: BTreeSet<String>,
}

impl GraphNeighborhoodArtifact {
    /// Creates and validates a new graph neighborhood artifact.
    pub fn new(
        center_entity_id: impl Into<String>,
        radius_hops: u8,
        node_count: u32,
        edge_count: u32,
        subgraph_digest: ContentDigest,
        masked_attributes: BTreeSet<String>,
    ) -> Result<Self, ContractError> {
        let artifact = Self {
            center_entity_id: center_entity_id.into(),
            radius_hops,
            node_count,
            edge_count,
            subgraph_digest,
            masked_attributes,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates graph neighborhood bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.center_entity_id)
            || self.radius_hops == 0
            || self.node_count == 0
            || self.subgraph_digest.bytes().iter().all(|&b| b == 0)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for attr in &self.masked_attributes {
            if !valid_text(attr) {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        Ok(())
    }

    /// Central entity identifier.
    #[must_use]
    pub fn center_entity_id(&self) -> &str {
        &self.center_entity_id
    }

    /// Radius in topological hops.
    #[must_use]
    pub const fn radius_hops(&self) -> u8 {
        self.radius_hops
    }

    /// Number of nodes in neighborhood.
    #[must_use]
    pub const fn node_count(&self) -> u32 {
        self.node_count
    }

    /// Number of edges in neighborhood.
    #[must_use]
    pub const fn edge_count(&self) -> u32 {
        self.edge_count
    }

    /// Sub-graph canonical digest.
    #[must_use]
    pub const fn subgraph_digest(&self) -> ContentDigest {
        self.subgraph_digest
    }

    /// Masked attribute keys.
    #[must_use]
    pub fn masked_attributes(&self) -> &BTreeSet<String> {
        &self.masked_attributes
    }
}

impl CanonicalEncode for GraphNeighborhoodArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.center_entity_id);
        encoder.u8(self.radius_hops);
        encoder.u32(self.node_count);
        encoder.u32(self.edge_count);
        encoder.digest(self.subgraph_digest);
        encode_text_set(&self.masked_attributes, encoder);
    }
}

impl CanonicalDecode for GraphNeighborhoodArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let center_entity_id = decoder.text()?.to_string();
        let radius_hops = decoder.u8()?;
        let node_count = decoder.u32()?;
        let edge_count = decoder.u32()?;
        let subgraph_digest = decoder.digest()?;
        let masked_attributes = decode_text_set(decoder).map_err(|_| ContractError::InvalidIdentifier)?;
        let artifact = Self {
            center_entity_id,
            radius_hops,
            node_count,
            edge_count,
            subgraph_digest,
            masked_attributes,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

/// An authorized redacted acoustic / audio spectral feature artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioFeaturesArtifact {
    time_window: CaptureInterval,
    source_channel_id: String,
    feature_type: String,
    sample_count: u32,
    band_count: u32,
    voice_activity_masked: bool,
}

impl AudioFeaturesArtifact {
    /// Creates and validates a new audio features artifact.
    pub fn new(
        time_window: CaptureInterval,
        source_channel_id: impl Into<String>,
        feature_type: impl Into<String>,
        sample_count: u32,
        band_count: u32,
        voice_activity_masked: bool,
    ) -> Result<Self, ContractError> {
        let artifact = Self {
            time_window,
            source_channel_id: source_channel_id.into(),
            feature_type: feature_type.into(),
            sample_count,
            band_count,
            voice_activity_masked,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates audio feature bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.source_channel_id)
            || !valid_text(&self.feature_type)
            || self.sample_count == 0
            || self.band_count == 0
            || self.time_window.earliest > self.time_window.latest
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// Capture interval.
    #[must_use]
    pub const fn time_window(&self) -> CaptureInterval {
        self.time_window
    }

    /// Microphone or channel identifier.
    #[must_use]
    pub fn source_channel_id(&self) -> &str {
        &self.source_channel_id
    }

    /// Feature type name.
    #[must_use]
    pub fn feature_type(&self) -> &str {
        &self.feature_type
    }

    /// Temporal samples count.
    #[must_use]
    pub const fn sample_count(&self) -> u32 {
        self.sample_count
    }

    /// Frequency bands or feature dimension count.
    #[must_use]
    pub const fn band_count(&self) -> u32 {
        self.band_count
    }

    /// Whether voice-activity regions were masked.
    #[must_use]
    pub const fn voice_activity_masked(&self) -> bool {
        self.voice_activity_masked
    }
}

impl CanonicalEncode for AudioFeaturesArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.time_window.encode_canonical(encoder);
        encoder.text(&self.source_channel_id);
        encoder.text(&self.feature_type);
        encoder.u32(self.sample_count);
        encoder.u32(self.band_count);
        encoder.bool(self.voice_activity_masked);
    }
}

impl CanonicalDecode for AudioFeaturesArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let time_window = CaptureInterval::decode_canonical(decoder)?;
        let source_channel_id = decoder.text()?.to_string();
        let feature_type = decoder.text()?.to_string();
        let sample_count = decoder.u32()?;
        let band_count = decoder.u32()?;
        let voice_activity_masked = decoder.bool()?;
        let artifact = Self {
            time_window,
            source_channel_id,
            feature_type,
            sample_count,
            band_count,
            voice_activity_masked,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

/// The 5 enumerated kinds of decision artifacts recognized under hydration level H2.
#[derive(Clone, Debug, PartialEq)]
pub enum DecisionArtifactKind {
    /// Authorized redacted video keyframe.
    Keyframe(KeyframeArtifact),
    /// Authorized redacted spatial bounding crop.
    Crop(CropArtifact),
    /// Authorized redacted spatio-temporal trajectory.
    Trajectory(TrajectoryArtifact),
    /// Authorized redacted k-hop graph neighborhood.
    GraphNeighborhood(GraphNeighborhoodArtifact),
    /// Authorized redacted acoustic / audio spectral features.
    AudioFeatures(AudioFeaturesArtifact),
}

impl DecisionArtifactKind {
    /// Returns the discriminator tag for canonical binary encoding.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Keyframe(_) => 1,
            Self::Crop(_) => 2,
            Self::Trajectory(_) => 3,
            Self::GraphNeighborhood(_) => 4,
            Self::AudioFeatures(_) => 5,
        }
    }

    /// Returns the stable media or semantic content type string.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        match self {
            Self::Keyframe(_) => "application/x-fss-h2-keyframe",
            Self::Crop(_) => "application/x-fss-h2-crop",
            Self::Trajectory(_) => "application/x-fss-h2-trajectory",
            Self::GraphNeighborhood(_) => "application/x-fss-h2-graph-neighborhood",
            Self::AudioFeatures(_) => "application/x-fss-h2-audio-features",
        }
    }

    /// Validates the inner artifact kind invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Keyframe(k) => k.validate(),
            Self::Crop(c) => c.validate(),
            Self::Trajectory(t) => t.validate(),
            Self::GraphNeighborhood(g) => g.validate(),
            Self::AudioFeatures(a) => a.validate(),
        }
    }
}

impl CanonicalEncode for DecisionArtifactKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tag());
        match self {
            Self::Keyframe(k) => k.encode_canonical(encoder),
            Self::Crop(c) => c.encode_canonical(encoder),
            Self::Trajectory(t) => t.encode_canonical(encoder),
            Self::GraphNeighborhood(g) => g.encode_canonical(encoder),
            Self::AudioFeatures(a) => a.encode_canonical(encoder),
        }
    }
}

impl CanonicalDecode for DecisionArtifactKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let tag = decoder.u8()?;
        match tag {
            1 => Ok(Self::Keyframe(KeyframeArtifact::decode_canonical(decoder)?)),
            2 => Ok(Self::Crop(CropArtifact::decode_canonical(decoder)?)),
            3 => Ok(Self::Trajectory(TrajectoryArtifact::decode_canonical(
                decoder,
            )?)),
            4 => Ok(Self::GraphNeighborhood(
                GraphNeighborhoodArtifact::decode_canonical(decoder)?,
            )),
            5 => Ok(Self::AudioFeatures(
                AudioFeaturesArtifact::decode_canonical(decoder)?,
            )),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Parameters used to construct an [`H2DecisionArtifact`].
#[derive(Clone, Debug, PartialEq)]
pub struct H2DecisionArtifactParams {
    /// Content-derived handle identifier (e.g. `"semantic-handle:sha256:..."`).
    pub handle_id: String,
    /// Stable canonical subject identity (e.g. `"evidence:stream-42"`).
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Specific typed decision artifact kind (one of the 5 enumerated branches).
    pub artifact_kind: DecisionArtifactKind,
    /// Exact bounded payload bytes.
    pub payload: Vec<u8>,
    /// Proof roots: exactly the payload digest, the subject digest, and a non-empty subset of
    /// [`Self::retained_provenance`].
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Strongly typed retained provenance collection.
    pub retained_provenance: RetainedProvenance,
    /// Completeness of this artifact.
    pub completeness: Completeness,
    /// Authorized privacy class.
    pub privacy_class: String,
    /// Explicit redaction transform applied (a recognized [`RedactionTransform`] token).
    pub applied_redaction_transform: String,
    /// Capability grant proving explicit authorization for H2 materialization.
    pub authorization_grant_id: String,
    /// Authority anchor of this artifact revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative estimated resource cost.
    pub estimated_cost: BudgetVector,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Retention horizon.
    pub retention_until: TimestampNs,
}

/// Maximum number of digests in one [`RetainedProvenance`].
///
/// Two below [`MAX_REQUEST_SET_ITEMS`], so proof roots made of the payload digest, the subject
/// digest and every retained root always stay inside the decoder's proof-root bound.
pub const MAX_H2_RETAINED_PROVENANCE_ROOTS: usize = MAX_REQUEST_SET_ITEMS - 2;

/// Bounded collection of retained provenance roots the caller obtained from the evidence or ledger
/// store (AGT-H2, INV-003).
///
/// Every constructor goes through [`Self::new`]: never empty, at most
/// [`MAX_H2_RETAINED_PROVENANCE_ROOTS`] digests. [`Default`] is the empty collection, which H2
/// construction and [`H2DecisionArtifact::decode_verified`] refuse with
/// [`ContractError::EvidenceRequired`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RetainedProvenance(BTreeSet<ContentDigest>);

impl RetainedProvenance {
    /// Creates a new [`RetainedProvenance`] from an iterator of content digests.
    ///
    /// Refuses more than [`MAX_H2_RETAINED_PROVENANCE_ROOTS`] distinct digests with
    /// [`ContractError::CountBoundExceeded`], stopping as soon as the bound is exceeded, and an
    /// empty collection with [`ContractError::EvidenceRequired`].
    pub fn new(roots: impl IntoIterator<Item = ContentDigest>) -> Result<Self, ContractError> {
        let mut set = BTreeSet::new();
        for root in roots {
            set.insert(root);
            if set.len() > MAX_H2_RETAINED_PROVENANCE_ROOTS {
                return Err(ContractError::CountBoundExceeded);
            }
        }
        if set.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(Self(set))
    }

    /// Creates a [`RetainedProvenance`] from a set through the validating constructor
    /// [`Self::new`].
    pub fn from_set(set: BTreeSet<ContentDigest>) -> Result<Self, ContractError> {
        Self::new(set)
    }

    /// Returns true if the collection contains no digests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of digests in the collection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the collection contains the given digest.
    #[must_use]
    pub fn contains(&self, digest: &ContentDigest) -> bool {
        self.0.contains(digest)
    }

    /// Returns an iterator over the retained provenance digests.
    pub fn iter(&self) -> std::collections::btree_set::Iter<'_, ContentDigest> {
        self.0.iter()
    }

    /// Returns a reference to the underlying [`BTreeSet<ContentDigest>`].
    #[must_use]
    pub const fn as_set(&self) -> &BTreeSet<ContentDigest> {
        &self.0
    }
}

impl TryFrom<BTreeSet<ContentDigest>> for RetainedProvenance {
    type Error = ContractError;

    fn try_from(set: BTreeSet<ContentDigest>) -> Result<Self, Self::Error> {
        Self::new(set)
    }
}

impl<'a> IntoIterator for &'a RetainedProvenance {
    type Item = &'a ContentDigest;
    type IntoIter = std::collections::btree_set::Iter<'a, ContentDigest>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for RetainedProvenance {
    type Item = ContentDigest;
    type IntoIter = std::collections::btree_set::IntoIter<ContentDigest>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Strongly typed representation of the H2 Decision Artifact level of the progressive hydration ladder.
///
/// Encapsulates the content specified by normative row H2:
/// authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features.
#[derive(Clone, Debug, PartialEq)]
pub struct H2DecisionArtifact {
    handle_id: String,
    subject_id: String,
    subject_digest: ContentDigest,
    artifact_kind: DecisionArtifactKind,
    payload: Vec<u8>,
    payload_digest: ContentDigest,
    proof_roots: BTreeSet<ContentDigest>,
    completeness: Completeness,
    privacy_class: String,
    applied_redaction_transform: String,
    authorization_grant_id: String,
    anchor: LedgerAnchor,
    contract_basis: ContractBasis,
    estimated_cost: BudgetVector,
    published_at: TimestampNs,
    retention_until: TimestampNs,
    artifact_digest: ContentDigest,
}

impl H2DecisionArtifact {
    /// Constructs and validates a new [`H2DecisionArtifact`].
    pub fn new(params: H2DecisionArtifactParams) -> Result<Self, HydrationError> {
        // Subject digest must not be zeroed
        if params.subject_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest.into());
        }

        let payload_digest = ContentDigest::sha256(&params.payload);

        // Empty retained_provenance: refuse with EvidenceRequired
        if params.retained_provenance.is_empty() {
            return Err(ContractError::EvidenceRequired.into());
        }

        // proof_roots MUST contain payload_digest and subject_digest
        if !params.proof_roots.contains(&payload_digest)
            || !params.proof_roots.contains(&params.subject_digest)
        {
            return Err(ContractError::EvidenceRequired.into());
        }

        // proof_roots MUST equal {payload_digest, subject_digest} UNION non_empty_subset(retained_provenance)
        // 1. Every root in proof_roots must belong to {payload_digest, subject_digest} U retained_provenance
        let mut has_retained_subset = false;
        for root in &params.proof_roots {
            if *root != payload_digest && *root != params.subject_digest {
                if !params.retained_provenance.contains(root) {
                    return Err(ContractError::EvidenceRequired.into());
                }
                has_retained_subset = true;
            }
        }
        // 2. Must contain at least one retained root (non-empty subset)
        if !has_retained_subset {
            return Err(ContractError::EvidenceRequired.into());
        }

        let mut artifact = Self {
            handle_id: params.handle_id,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            artifact_kind: params.artifact_kind,
            payload: params.payload,
            payload_digest,
            proof_roots: params.proof_roots,
            completeness: params.completeness,
            privacy_class: params.privacy_class,
            applied_redaction_transform: params.applied_redaction_transform,
            authorization_grant_id: params.authorization_grant_id,
            anchor: params.anchor,
            contract_basis: params.contract_basis,
            estimated_cost: params.estimated_cost,
            published_at: params.published_at,
            retention_until: params.retention_until,
            artifact_digest: ContentDigest::sha256(b"unsealed-h2-decision-artifact"),
        };
        artifact.validate()?;
        artifact.artifact_digest = artifact.computed_digest()?;
        Ok(artifact)
    }

    /// Materializes an H2 decision artifact from a published [`SemanticHandle`].
    pub fn from_semantic_handle(
        handle: &SemanticHandle,
        artifact_kind: DecisionArtifactKind,
        payload: Vec<u8>,
        retained_provenance: RetainedProvenance,
        applied_redaction_transform: impl Into<String>,
        authorization_grant_id: impl Into<String>,
        completeness: Completeness,
    ) -> Result<Self, HydrationError> {
        if !handle.levels.contains(&HydrationLevel::H2) {
            return Err(HydrationError::LevelUnavailable);
        }

        let estimated_cost = handle
            .estimated_costs
            .get(&HydrationLevel::H2)
            .copied()
            .ok_or(HydrationError::LevelUnavailable)?;

        let _caps = handle
            .required_capabilities
            .get(&HydrationLevel::H2)
            .ok_or(HydrationError::LevelUnavailable)?;

        handle.verify()?;

        let payload_digest = ContentDigest::sha256(&payload);
        let mut roots = BTreeSet::new();
        roots.insert(payload_digest);
        roots.insert(handle.subject_digest);
        for r in retained_provenance.iter() {
            roots.insert(*r);
        }

        let params = H2DecisionArtifactParams {
            handle_id: handle.handle_id.clone(),
            subject_id: handle.subject_id.clone(),
            subject_digest: handle.subject_digest,
            artifact_kind,
            payload,
            proof_roots: roots,
            retained_provenance,
            completeness,
            privacy_class: handle.privacy_class.clone(),
            applied_redaction_transform: applied_redaction_transform.into(),
            authorization_grant_id: authorization_grant_id.into(),
            anchor: handle.anchor.clone(),
            contract_basis: handle.contract_basis.clone(),
            estimated_cost,
            published_at: handle.published_at,
            retention_until: handle.retention_until,
        };

        Self::new(params)
    }

    /// Validates all H2 decision artifact invariants.
    pub fn validate(&self) -> Result<(), HydrationError> {
        if !valid_text(&self.handle_id)
            || !valid_text(&self.subject_id)
            || !valid_text(&self.privacy_class)
            || !valid_text(&self.applied_redaction_transform)
            || !valid_text(&self.authorization_grant_id)
            || !valid_text(&self.anchor.site_lineage)
            || !valid_text(&self.contract_basis.semantic_protocol)
        {
            return Err(ContractError::InvalidIdentifier.into());
        }

        // Subject digest must not be zeroed
        if self.subject_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest.into());
        }

        // Payload checks: capped at <= MAX_CANONICAL_BYTES_LEN
        if self.payload.is_empty() || self.payload.len() > MAX_CANONICAL_BYTES_LEN {
            return Err(ContractError::EvidenceRequired.into());
        }

        if self.payload_digest != ContentDigest::sha256(&self.payload) {
            return Err(ContractError::DigestMismatch.into());
        }

        // Proof roots must contain payload digest AND subject digest
        if !self.proof_roots.contains(&self.payload_digest)
            || !self.proof_roots.contains(&self.subject_digest)
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        // At least one non-circular retained root must exist
        if !self
            .proof_roots
            .iter()
            .any(|r| *r != self.payload_digest && *r != self.subject_digest)
        {
            return Err(ContractError::EvidenceRequired.into());
        }

        // Completeness checks: H2 cannot be delivered under unknown/unauthorized states
        if matches!(
            self.completeness,
            Completeness::Unknown
                | Completeness::NotObservable
                | Completeness::Unauthorized
                | Completeness::Stale
        ) {
            return Err(ContractError::EvidenceRequired.into());
        }

        // Retention horizon
        if self.retention_until < self.published_at {
            return Err(HydrationError::ContinuationExpired);
        }

        // Validate inner artifact kind
        self.artifact_kind
            .validate()
            .map_err(HydrationError::Contract)?;

        // Enforce authorized redaction from recognized allowlist
        let transform = RedactionTransform::parse(&self.applied_redaction_transform)
            .map_err(HydrationError::Contract)?;
        if !transform.is_compatible_with_kind(&self.artifact_kind) {
            return Err(ContractError::InvalidRedactionTransform.into());
        }
        H2PrivacyClass::parse(&self.privacy_class).map_err(HydrationError::Contract)?;

        Ok(())
    }

    /// Verifies payload integrity and artifact digest.
    pub fn verify(&self) -> Result<(), HydrationError> {
        self.validate()?;
        if self.artifact_digest != self.computed_digest()? {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Recomputes the complete artifact digest from canonical body encoding.
    pub fn computed_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }

    /// Checks whether the artifact is authorized, explicitly redacted using a recognized transform, and contains no raw unredacted media.
    #[must_use]
    pub fn is_authorized_and_redacted(&self) -> bool {
        let Some(transform) = recognized_redaction_transform(&self.applied_redaction_transform)
        else {
            return false;
        };
        if !transform.is_compatible_with_kind(&self.artifact_kind) {
            return false;
        }
        if !valid_text(&self.privacy_class) || !valid_text(&self.authorization_grant_id) {
            return false;
        }
        H2PrivacyClass::parse(&self.privacy_class).is_ok()
    }

    /// Returns the exact hydration level ([`HydrationLevel::H2`]).
    #[must_use]
    pub const fn level(&self) -> HydrationLevel {
        HydrationLevel::H2
    }

    /// Returns the normative level identifier (`"H2"`).
    #[must_use]
    pub const fn level_id(&self) -> &'static str {
        H2_LEVEL_ID
    }

    /// Returns the normative level name (`"decision_artifact"`).
    #[must_use]
    pub const fn level_name(&self) -> &'static str {
        H2_LEVEL_NAME
    }

    /// Returns the exact normative content declaration from the agent abstraction registry.
    #[must_use]
    pub const fn content_declaration(&self) -> &'static str {
        H2_CONTENT
    }

    /// Returns the owning subsystem (`"fss-agent-core"`).
    #[must_use]
    pub const fn owner(&self) -> &'static str {
        H2_OWNER
    }

    /// Returns the stable media or semantic content type.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.artifact_kind.content_type()
    }

    /// Content-derived handle identifier.
    #[must_use]
    pub fn handle_id(&self) -> &str {
        &self.handle_id
    }

    /// Canonical subject identifier.
    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// Exact subject content digest.
    #[must_use]
    pub const fn subject_digest(&self) -> ContentDigest {
        self.subject_digest
    }

    /// Specific typed decision artifact kind.
    #[must_use]
    pub const fn artifact_kind(&self) -> &DecisionArtifactKind {
        &self.artifact_kind
    }

    /// Exact bounded payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// SHA-256 digest of the exact payload.
    #[must_use]
    pub const fn payload_digest(&self) -> ContentDigest {
        self.payload_digest
    }

    /// Retained provenance roots.
    #[must_use]
    pub const fn proof_roots(&self) -> &BTreeSet<ContentDigest> {
        &self.proof_roots
    }

    /// Completeness of this artifact.
    #[must_use]
    pub const fn completeness(&self) -> Completeness {
        self.completeness
    }

    /// Authorized privacy class.
    #[must_use]
    pub fn privacy_class(&self) -> &str {
        &self.privacy_class
    }

    /// Applied redaction transform URI.
    #[must_use]
    pub fn applied_redaction_transform(&self) -> &str {
        &self.applied_redaction_transform
    }

    /// Authorization grant identifier.
    #[must_use]
    pub fn authorization_grant_id(&self) -> &str {
        &self.authorization_grant_id
    }

    /// Authority anchor.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Exact semantic contract basis.
    #[must_use]
    pub const fn contract_basis(&self) -> &ContractBasis {
        &self.contract_basis
    }

    /// Conservative estimated resource cost.
    #[must_use]
    pub const fn estimated_cost(&self) -> BudgetVector {
        self.estimated_cost
    }

    /// Publication timestamp.
    #[must_use]
    pub const fn published_at(&self) -> TimestampNs {
        self.published_at
    }

    /// Retention horizon.
    #[must_use]
    pub const fn retention_until(&self) -> TimestampNs {
        self.retention_until
    }

    /// Digest of the complete artifact envelope.
    #[must_use]
    pub const fn artifact_digest(&self) -> ContentDigest {
        self.artifact_digest
    }

    /// Returns true if this artifact has passed its retention expiration timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: TimestampNs) -> bool {
        now > self.retention_until
    }

    /// Checks whether the estimated cost fits within the provided budget.
    #[must_use]
    pub fn satisfies_budget(&self, budget: &BudgetVector) -> bool {
        self.estimated_cost.fits_within(*budget)
    }

    /// Converts this typed decision artifact into the universal [`HydrationArtifact`] container, re-validating all invariants.
    pub fn to_hydration_artifact(&self) -> Result<HydrationArtifact, HydrationError> {
        self.validate()?;
        Ok(HydrationArtifact {
            level: HydrationLevel::H2,
            content_type: self.content_type().to_string(),
            payload: self.payload.clone(),
            payload_digest: self.payload_digest,
            proof_roots: self.proof_roots.clone(),
            completeness: self.completeness,
            applied_transform: Some(self.applied_redaction_transform.clone()),
            artifact_digest: self.artifact_digest,
        })
    }

    /// Encodes the canonical body of this artifact (excluding the self-referential digest).
    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(H2_SCHEMA);
        encoder.text(&self.handle_id);
        encoder.text(&self.subject_id);
        encoder.digest(self.subject_digest);
        self.artifact_kind.encode_canonical(encoder);
        encoder.bytes(&self.payload);
        encoder.digest(self.payload_digest);
        encoder.u64(self.proof_roots.len() as u64);
        for root in &self.proof_roots {
            encoder.digest(*root);
        }
        encoder.u8(self.completeness.code());
        encoder.text(&self.privacy_class);
        encoder.text(&self.applied_redaction_transform);
        encoder.text(&self.authorization_grant_id);
        self.anchor.encode_canonical(encoder);
        self.contract_basis.encode_canonical(encoder);
        self.estimated_cost.encode_canonical(encoder);
        self.published_at.encode_canonical(encoder);
        self.retention_until.encode_canonical(encoder);
    }

    /// Computes the deterministic canonical digest of this H2 decision artifact.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }

    /// Serializes this artifact to canonical binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish_checked()
    }

    /// Decodes canonical bytes into a validated [`H2DecisionArtifact`], checking its proof roots
    /// against caller truth.
    ///
    /// This is the only decode path; there is deliberately no unverified decode. It refuses:
    /// trailing bytes; every [`Self::validate`] failure; an artifact digest mismatch; an empty
    /// `retained_provenance` ([`ContractError::EvidenceRequired`]); and any proof root outside
    /// {payload digest, subject digest} union `retained_provenance`
    /// ([`ContractError::EvidenceRequired`]). The provenance must be what the caller obtained from
    /// the evidence or ledger store, never something read back out of the bytes.
    pub fn decode_verified(
        bytes: &[u8],
        retained_provenance: &RetainedProvenance,
    ) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let artifact = Self::decode_fields(&mut decoder)?;
        decoder.ensure_finished()?;
        artifact.check_roots_against(retained_provenance)?;
        Ok(artifact)
    }

    /// Refuses an empty provenance and any proof root outside
    /// {payload digest, subject digest} union `retained_provenance`.
    fn check_roots_against(
        &self,
        retained_provenance: &RetainedProvenance,
    ) -> Result<(), ContractError> {
        if retained_provenance.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        let foreign = self.proof_roots.iter().any(|root| {
            *root != self.payload_digest
                && *root != self.subject_digest
                && !retained_provenance.contains(root)
        });
        if foreign {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Decodes and self-validates the fields. Private: the result has not yet been checked against
    /// caller-held provenance, so it must never escape except through [`Self::decode_verified`].
    fn decode_fields(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != H2_SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let handle_id = decoder.text()?.to_string();
        let subject_id = decoder.text()?.to_string();
        let subject_digest = decoder.digest()?;
        let artifact_kind = DecisionArtifactKind::decode_canonical(decoder)?;
        let payload = decoder.bytes()?.to_vec();
        if payload.len() > MAX_CANONICAL_BYTES_LEN {
            return Err(ContractError::EvidenceRequired);
        }
        let payload_digest = decoder.digest()?;

        let root_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if root_count > MAX_REQUEST_SET_ITEMS || decoder.remaining() < root_count {
            return Err(ContractError::InvalidDigest);
        }
        let mut proof_roots = BTreeSet::new();
        let mut prev_root: Option<ContentDigest> = None;
        for _ in 0..root_count {
            let root = decoder.digest()?;
            if let Some(prev) = prev_root
                && prev >= root
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_root = Some(root);
            proof_roots.insert(root);
        }

        let completeness = Completeness::from_code(decoder.u8()?)?;

        let privacy_class = decoder.text()?.to_string();
        let applied_redaction_transform = decoder.text()?.to_string();
        let authorization_grant_id = decoder.text()?.to_string();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let contract_basis = ContractBasis::decode_canonical(decoder)?;
        let estimated_cost = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        let published_at = TimestampNs::decode_canonical(decoder)?;
        let retention_until = TimestampNs::decode_canonical(decoder)?;
        let artifact_digest = decoder.digest()?;

        let artifact = Self {
            handle_id,
            subject_id,
            subject_digest,
            artifact_kind,
            payload,
            payload_digest,
            proof_roots,
            completeness,
            privacy_class,
            applied_redaction_transform,
            authorization_grant_id,
            anchor,
            contract_basis,
            estimated_cost,
            published_at,
            retention_until,
            artifact_digest,
        };

        artifact.validate().map_err(|e| match e {
            HydrationError::Contract(c) => c,
            HydrationError::ContinuationExpired => ContractError::InvertedTimeInterval,
            _ => ContractError::InvalidIdentifier,
        })?;

        if artifact.artifact_digest != artifact.computed_digest()? {
            return Err(ContractError::DigestMismatch);
        }

        Ok(artifact)
    }
}

impl CanonicalEncode for H2DecisionArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.artifact_digest);
    }
}

impl TryFrom<H2DecisionArtifact> for HydrationArtifact {
    type Error = HydrationError;

    fn try_from(artifact: H2DecisionArtifact) -> Result<Self, Self::Error> {
        artifact.to_hydration_artifact()
    }
}
