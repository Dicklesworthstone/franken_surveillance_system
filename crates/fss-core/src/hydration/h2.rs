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
//! - Artifacts must carry certified redaction / privacy transform metadata.
//! - Raw unredacted media, raw camera streams, and ungrounded cognition are strictly prohibited.
//! - Proof roots must retain provenance and include the exact payload digest.
//! - Completeness must not be Unknown, NotObservable, Unauthorized, or Stale.

use std::collections::BTreeSet;

use super::{
    Completeness, HydrationArtifact, HydrationError, HydrationLevel, MAX_ARTIFACT_BYTES,
    MAX_REQUEST_SET_ITEMS, SemanticHandle, decode_optional_text, decode_text_set,
    encode_optional_text, encode_text_set, valid_text,
};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::{
    BudgetVector, CaptureInterval, ContentDigest, ContractBasis, LedgerAnchor, TimestampNs,
};

/// Stable identifier for hydration ladder level H2.
pub const H2_LEVEL_ID: &str = "H2";

/// Stable name for hydration ladder level H2.
pub const H2_LEVEL_NAME: &str = "decision_artifact";

/// Normative content declaration for hydration ladder level H2 from the agent abstraction registry.
pub const H2_CONTENT: &str =
    "authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features";

/// Owning subsystem for hydration ladder level H2.
pub const H2_OWNER: &str = "fss-media/fss-privacy";

/// Canonical schema discriminator tag for H2 decision artifact binary envelopes.
pub const H2_SCHEMA: &str = "fss.h2_decision_artifact.v1";

/// A bounding box with normalized coordinates in range `[0.0, 1.0]`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoundingBox {
    /// Minimum horizontal coordinate (left), normalized `[0.0, 1.0]`.
    pub x_min: f32,
    /// Minimum vertical coordinate (top), normalized `[0.0, 1.0]`.
    pub y_min: f32,
    /// Maximum horizontal coordinate (right), normalized `[0.0, 1.0]`.
    pub x_max: f32,
    /// Maximum vertical coordinate (bottom), normalized `[0.0, 1.0]`.
    pub y_max: f32,
}

impl BoundingBox {
    /// Creates and validates a new bounding box.
    pub fn new(x_min: f32, y_min: f32, x_max: f32, y_max: f32) -> Result<Self, ContractError> {
        if !x_min.is_finite()
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
    /// Left coordinate in pixels.
    pub x: u32,
    /// Top coordinate in pixels.
    pub y: u32,
    /// Region width in pixels.
    pub width: u32,
    /// Region height in pixels.
    pub height: u32,
    /// Method used to redact this region (e.g. `"gaussian_blur"`, `"solid_mask"`).
    pub method: String,
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
        if width == 0 || height == 0 || !valid_text(&method) {
            return Err(ContractError::InvalidSpatialExtent);
        }
        Ok(Self {
            x,
            y,
            width,
            height,
            method,
        })
    }

    /// Validates the redacted region invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.width == 0 || self.height == 0 || !valid_text(&self.method) {
            return Err(ContractError::InvalidSpatialExtent);
        }
        Ok(())
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
    /// Observation timestamp.
    pub timestamp_ns: TimestampNs,
    /// Spatial coordinate X.
    pub x: f64,
    /// Spatial coordinate Y.
    pub y: f64,
    /// Spatial coordinate Z.
    pub z: f64,
}

impl TrajectoryWaypoint {
    /// Creates a validated waypoint.
    pub fn new(timestamp_ns: TimestampNs, x: f64, y: f64, z: f64) -> Result<Self, ContractError> {
        if !x.is_finite() || !y.is_finite() || !z.is_finite() {
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
        if !self.x.is_finite() || !self.y.is_finite() || !self.z.is_finite() {
            return Err(ContractError::InvalidSpatialExtent);
        }
        Ok(())
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
    /// Capture timestamp of the keyframe.
    pub timestamp_ns: TimestampNs,
    /// Stable sensor or camera stream identifier.
    pub stream_id: String,
    /// Keyframe pixel width.
    pub width: u32,
    /// Keyframe pixel height.
    pub height: u32,
    /// Content encoding MIME format (e.g. `"image/jpeg"`, `"image/webp"`).
    pub format: String,
    /// List of spatial regions with applied redaction.
    pub redacted_regions: Vec<RedactedRegion>,
}

impl KeyframeArtifact {
    /// Validates keyframe artifact bounds.
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
        }
        Ok(())
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
    /// Timestamp of the source frame.
    pub timestamp_ns: TimestampNs,
    /// Source stream or camera identifier.
    pub source_stream_id: String,
    /// Normalized bounding box coordinates within the source frame.
    pub bounding_box: BoundingBox,
    /// Associated target entity or track anchor, if identified.
    pub target_entity_anchor: Option<String>,
    /// Image encoding format (e.g. `"image/png"`, `"image/jpeg"`).
    pub format: String,
    /// Sub-regions within the crop that underwent privacy redaction.
    pub redacted_regions: Vec<RedactedRegion>,
}

impl CropArtifact {
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
    /// Entity or track anchor denoted by this trajectory.
    pub entity_anchor: String,
    /// Bounding capture interval of the trajectory.
    pub time_window: CaptureInterval,
    /// Monotonically ordered sequence of spatio-temporal waypoints.
    pub waypoints: Vec<TrajectoryWaypoint>,
    /// Coordinate frame identifier (e.g. `"frame:site_local:enu"`).
    pub coordinate_frame: String,
    /// Whether spatial coarsening or dithering was applied to preserve privacy.
    pub coarsened: bool,
}

impl TrajectoryArtifact {
    /// Validates trajectory invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_text(&self.entity_anchor)
            || !valid_text(&self.coordinate_frame)
            || self.waypoints.is_empty()
            || self.time_window.earliest > self.time_window.latest
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut prev_ts = self.time_window.earliest;
        for wp in &self.waypoints {
            wp.validate()?;
            if wp.timestamp_ns < prev_ts || wp.timestamp_ns > self.time_window.latest {
                return Err(ContractError::InvertedTimeInterval);
            }
            prev_ts = wp.timestamp_ns;
        }
        Ok(())
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
        for _ in 0..wp_count {
            waypoints.push(TrajectoryWaypoint::decode_canonical(decoder)?);
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
    /// Central entity identifier of the neighborhood.
    pub center_entity_id: String,
    /// Radius of the extracted neighborhood in topological hops.
    pub radius_hops: u8,
    /// Number of nodes contained in the neighborhood.
    pub node_count: u32,
    /// Number of edges contained in the neighborhood.
    pub edge_count: u32,
    /// Deterministic canonical digest of the neighborhood sub-graph structure.
    pub subgraph_digest: ContentDigest,
    /// Node or edge attributes masked or removed for privacy projection.
    pub masked_attributes: BTreeSet<String>,
}

impl GraphNeighborhoodArtifact {
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
        let masked_attributes = decode_text_set(decoder)?;
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
    /// Bounding capture interval of the audio features.
    pub time_window: CaptureInterval,
    /// Source microphone or audio channel identifier.
    pub source_channel_id: String,
    /// Feature representation type (e.g. `"log_mel_spectrogram"`, `"mfcc_13"`).
    pub feature_type: String,
    /// Number of temporal feature frames / samples.
    pub sample_count: u32,
    /// Number of spectral frequency bands or feature dimensions per frame.
    pub band_count: u32,
    /// Whether speech / voice-activity regions were masked for privacy.
    pub voice_activity_masked: bool,
}

impl AudioFeaturesArtifact {
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
    /// Retained provenance roots (must include payload digest plus at least one distinct provenance root).
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Completeness of this artifact.
    pub completeness: Completeness,
    /// Authorized privacy class.
    pub privacy_class: String,
    /// Explicit privacy/redaction transform applied (e.g. `"privacy:face_blur+plate_mask"`).
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

/// Strongly typed representation of the H2 Decision Artifact level of the progressive hydration ladder.
///
/// Encapsulates the content specified by normative row H2:
/// authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features.
#[derive(Clone, Debug, PartialEq)]
pub struct H2DecisionArtifact {
    /// Content-derived handle identifier.
    pub handle_id: String,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Specific typed decision artifact kind.
    pub artifact_kind: DecisionArtifactKind,
    /// Exact bounded payload bytes.
    pub payload: Vec<u8>,
    /// SHA-256 digest of the exact payload.
    pub payload_digest: ContentDigest,
    /// Retained provenance roots plus payload digest.
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Completeness of this artifact.
    pub completeness: Completeness,
    /// Authorized privacy class.
    pub privacy_class: String,
    /// Certified redaction/privacy transform applied.
    pub applied_redaction_transform: String,
    /// Authorization grant identifier.
    pub authorization_grant_id: String,
    /// Authority anchor.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative estimated resource cost.
    pub estimated_cost: BudgetVector,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Retention horizon.
    pub retention_until: TimestampNs,
    /// Digest of the complete artifact envelope.
    pub artifact_digest: ContentDigest,
}

impl H2DecisionArtifact {
    /// Constructs and validates a new [`H2DecisionArtifact`].
    pub fn new(params: H2DecisionArtifactParams) -> Result<Self, HydrationError> {
        let payload_digest = ContentDigest::sha256(&params.payload);
        let mut roots = params.proof_roots;
        roots.insert(payload_digest);

        let mut artifact = Self {
            handle_id: params.handle_id,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            artifact_kind: params.artifact_kind,
            payload: params.payload,
            payload_digest,
            proof_roots: roots,
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
        artifact.artifact_digest = artifact.computed_digest();
        Ok(artifact)
    }

    /// Materializes an H2 decision artifact from a published [`SemanticHandle`].
    pub fn from_semantic_handle(
        handle: &SemanticHandle,
        artifact_kind: DecisionArtifactKind,
        payload: Vec<u8>,
        proof_roots: impl IntoIterator<Item = ContentDigest>,
        applied_redaction_transform: impl Into<String>,
        authorization_grant_id: impl Into<String>,
        completeness: Completeness,
    ) -> Result<Self, HydrationError> {
        if !handle.levels.contains(&HydrationLevel::H2) {
            return Err(HydrationError::LevelUnavailable);
        }

        let estimated_cost = match handle.estimated_costs.get(&HydrationLevel::H2) {
            Some(cost) => *cost,
            None => BudgetVector::ZERO,
        };

        let params = H2DecisionArtifactParams {
            handle_id: handle.handle_id.clone(),
            subject_id: handle.subject_id.clone(),
            subject_digest: handle.subject_digest,
            artifact_kind,
            payload,
            proof_roots: proof_roots.into_iter().collect(),
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

        // Payload checks
        if self.payload.is_empty() || self.payload.len() > MAX_ARTIFACT_BYTES {
            return Err(ContractError::EvidenceRequired.into());
        }

        if self.payload_digest != ContentDigest::sha256(&self.payload) {
            return Err(ContractError::DigestMismatch.into());
        }

        // Proof roots must contain payload digest AND at least one non-payload provenance root
        if !self.proof_roots.contains(&self.payload_digest)
            || !self.proof_roots.iter().any(|r| *r != self.payload_digest)
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

        // Enforce authorized redaction and prohibition against raw media exposure
        if !self.is_authorized_and_redacted() {
            return Err(ContractError::ProhibitedEvidencePromotion.into());
        }

        Ok(())
    }

    /// Verifies payload integrity and artifact digest.
    pub fn verify(&self) -> Result<(), HydrationError> {
        self.validate()?;
        if self.artifact_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    /// Recomputes the complete artifact digest from canonical body encoding.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Checks whether the artifact is authorized, explicitly redacted, and contains no raw unredacted media.
    #[must_use]
    pub fn is_authorized_and_redacted(&self) -> bool {
        let prohibited = [
            "unredacted_raw_media",
            "raw_undecoded_stream",
            "raw_camera_packets",
            "unmasked_pii",
            "unredacted",
            "none",
        ];

        let red = self.applied_redaction_transform.to_lowercase();
        let priv_class = self.privacy_class.to_lowercase();

        for p in &prohibited {
            if red == *p || priv_class.contains(p) {
                return false;
            }
        }
        true
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

    /// Returns the owning subsystem (`"fss-media/fss-privacy"`).
    #[must_use]
    pub const fn owner(&self) -> &'static str {
        H2_OWNER
    }

    /// Returns the stable media or semantic content type.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.artifact_kind.content_type()
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

    /// Converts this typed decision artifact into the universal [`HydrationArtifact`] container.
    #[must_use]
    pub fn to_hydration_artifact(&self) -> HydrationArtifact {
        HydrationArtifact {
            level: HydrationLevel::H2,
            content_type: self.content_type().to_string(),
            payload: self.payload.clone(),
            payload_digest: self.payload_digest,
            proof_roots: self.proof_roots.clone(),
            completeness: self.completeness,
            applied_transform: Some(self.applied_redaction_transform.clone()),
            artifact_digest: self.artifact_digest,
        }
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
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Decodes an [`H2DecisionArtifact`] from canonical binary bytes and verifies no trailing bytes exist.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let artifact = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(artifact)
    }
}

impl CanonicalEncode for H2DecisionArtifact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.artifact_digest);
    }
}

impl CanonicalDecode for H2DecisionArtifact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != H2_SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let handle_id = decoder.text()?.to_string();
        let subject_id = decoder.text()?.to_string();
        let subject_digest = decoder.digest()?;
        let artifact_kind = DecisionArtifactKind::decode_canonical(decoder)?;
        let payload = decoder.bytes()?.to_vec();
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

        if artifact.artifact_digest != artifact.computed_digest() {
            return Err(ContractError::DigestMismatch);
        }

        Ok(artifact)
    }
}

impl From<H2DecisionArtifact> for HydrationArtifact {
    fn from(artifact: H2DecisionArtifact) -> Self {
        artifact.to_hydration_artifact()
    }
}
