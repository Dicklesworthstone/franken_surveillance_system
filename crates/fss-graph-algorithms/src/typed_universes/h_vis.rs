#![forbid(unsafe_code)]
//! Visibility and coverage hypergraph `H_vis` (`PROJ-VISIBILITY-001`, `fss-x4a.23.69.2`).
//!
//! Models detection opportunity as a typed 12-dimension factor/hyperedge over:
//! 1. `camera_generation`,
//! 2. `calibration_generation`,
//! 3. `target_cell_id` & `target_class`,
//! 4. `environment_regime`,
//! 5. `sensor_health`,
//! 6. `pose_fov`,
//! 7. `occluder_state`,
//! 8. `illumination_weather`,
//! 9. `lens_health`,
//! 10. `target_height_cm` & `target_direction`,
//! 11. `codec_quality`,
//! 12. `detector_profile` (`model_generation` + `profile_id` + degraded posture).
//!
//! Derives a lossy `CameraCellBipartiteView` for placement algorithms that explicitly retains
//! links to the backing factors, conditioning digest, and uncertainty. Missing, expired, stale,
//! occluded, degraded, or redacted conditions produce `UnknownUncertified` coverage — NEVER
//! evidence of absence.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
    GraphAlgorithmWitness, LedgerAnchor, Plane, TimestampNs,
};

use crate::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};

use super::{
    CURRENT_UNIVERSE_WIRE_VERSION, LEGACY_UNIVERSE_WIRE_VERSION, MAX_UNIVERSE_ITEMS, OpBudget,
    TypedUniverseError, UniverseMigrationReport, build_universe_witness, hash_domain_tag,
    open_wire_envelope, seal_wire_envelope, validate_clean_label,
};

/// Registered digest domain for `H_vis` projections and witnesses (`SCHEMA-DOMAIN-GRAPH-H-VIS-001`).
pub const H_VIS_DIGEST_DOMAIN: &str = "fss.graph.h_vis_projection.v1";
/// Wire magic for durable `H_vis` fixtures (`FSSHVS01`).
pub const H_VIS_WIRE_MAGIC: [u8; 8] = *b"FSSHVS01";
/// Registered algorithm ID emitted in `H_vis` witnesses.
pub const H_VIS_ALGORITHM_ID: &str = "ALG-PROJ-VISIBILITY-001";
/// Implementation generation recorded in `H_vis` witnesses.
pub const H_VIS_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-visibility-001:h-vis-oracle:v2";
/// Policy identity recorded in `H_vis` witnesses.
pub const H_VIS_POLICY_ID: &str =
    "graph-policy:h-vis:12d-factor-hypergraph:fail-closed-unknown-coverage:v2";

/// Operational sensor health posture for a visibility factor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SensorHealthPosture {
    /// Sensor telemetry nominal.
    Nominal = 1,
    /// Sensor operating with degraded fidelity/frame drops.
    Degraded = 2,
    /// Sensor offline or disconnected.
    Offline = 3,
    /// Health unobserved/unknown.
    Unknown = 4,
}

impl SensorHealthPosture {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Nominal),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Offline),
            4 => Ok(Self::Unknown),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown SensorHealthPosture tag {other}"
            ))),
        }
    }
}

/// Camera pose and field-of-view geometric posture.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PoseFovStatus {
    /// Target cell lies cleanly inside verified frustum.
    InFrustumVerified = 1,
    /// Target cell lies near frustum boundary (heightened uncertainty).
    EdgeOfFov = 2,
    /// Target cell is outside the camera frustum.
    OutsideFrustum = 3,
    /// Pose or calibration is stale/unverified.
    StaleCalibration = 4,
}

impl PoseFovStatus {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::InFrustumVerified),
            2 => Ok(Self::EdgeOfFov),
            3 => Ok(Self::OutsideFrustum),
            4 => Ok(Self::StaleCalibration),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown PoseFovStatus tag {other}"
            ))),
        }
    }
}

/// Physical occluder posture between camera and target cell.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OccluderState {
    /// Unobstructed line of sight.
    Clear = 1,
    /// Partial occlusion (e.g., parked vehicle or foliage).
    PartialOcclusion = 2,
    /// Fully occluded.
    Occluded = 3,
    /// Occluder state unknown.
    Unknown = 4,
}

impl OccluderState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Clear),
            2 => Ok(Self::PartialOcclusion),
            3 => Ok(Self::Occluded),
            4 => Ok(Self::Unknown),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown OccluderState tag {other}"
            ))),
        }
    }
}

/// Illumination and weather condition affecting detection opportunity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IlluminationWeather {
    /// Clear daytime visibility.
    DayClear = 1,
    /// Nighttime IR / low-light visibility.
    NightIr = 2,
    /// Glare, rain, snow, or fog reducing effective visibility.
    GlareOrFog = 3,
    /// Severe weather blinding or heavily degrading observation.
    SevereWeather = 4,
    /// Illumination/weather state unknown.
    Unknown = 5,
}

impl IlluminationWeather {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::DayClear),
            2 => Ok(Self::NightIr),
            3 => Ok(Self::GlareOrFog),
            4 => Ok(Self::SevereWeather),
            5 => Ok(Self::Unknown),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown IlluminationWeather tag {other}"
            ))),
        }
    }
}

/// Optical lens condition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LensHealthState {
    /// Clean unobstructed optics.
    Clean = 1,
    /// Wet, smudged, or condensed lens.
    SmudgedOrWet = 2,
    /// Lens physically blocked or frosted.
    Obstructed = 3,
    /// Lens health unknown.
    Unknown = 4,
}

impl LensHealthState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Clean),
            2 => Ok(Self::SmudgedOrWet),
            3 => Ok(Self::Obstructed),
            4 => Ok(Self::Unknown),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown LensHealthState tag {other}"
            ))),
        }
    }
}

/// Codec compression quality posture.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CodecQualityState {
    /// High bitrate / nominal frame quality.
    High = 1,
    /// Heavily compressed / degraded bitrate.
    DegradedBitrate = 2,
    /// Active frame drops or decode gaps.
    DroppedFrames = 3,
    /// Codec quality unknown.
    Unknown = 4,
}

impl CodecQualityState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::High),
            2 => Ok(Self::DegradedBitrate),
            3 => Ok(Self::DroppedFrames),
            4 => Ok(Self::Unknown),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown CodecQualityState tag {other}"
            ))),
        }
    }
}

/// One typed 12-dimension visibility & detection-opportunity factor/hyperedge in `H_vis`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibilityFactor {
    /// Stable unique factor identifier.
    pub factor_id: String,
    /// Observing camera stable identity.
    pub camera_id: String,
    /// Dimension 1: camera hardware/firmware generation.
    pub camera_generation: Generation,
    /// Dimension 2: geometric calibration generation.
    pub calibration_generation: Generation,
    /// Dimension 3a: observed spatial target cell identity.
    pub target_cell_id: String,
    /// Dimension 3b: target object class (`person`, `vehicle`, `animal`, etc.).
    pub target_class: String,
    /// Dimension 4: environment regime label (`driveway_day`, `perimeter_night`, etc.).
    pub environment_regime: String,
    /// Dimension 5: sensor health posture.
    pub sensor_health: SensorHealthPosture,
    /// Dimension 6: camera pose / FOV geometric posture.
    pub pose_fov: PoseFovStatus,
    /// Dimension 7: physical occluder state.
    pub occluder_state: OccluderState,
    /// Dimension 8: illumination and weather condition.
    pub illumination_weather: IlluminationWeather,
    /// Dimension 9: optical lens condition.
    pub lens_health: LensHealthState,
    /// Dimension 10a: target height in centimeters.
    pub target_height_cm: u16,
    /// Dimension 10b: target approach/heading direction label.
    pub target_direction: String,
    /// Dimension 11: codec quality posture.
    pub codec_quality: CodecQualityState,
    /// Dimension 12a: pinned detector model generation.
    pub detector_model_generation: Generation,
    /// Dimension 12b: detector profile label.
    pub detector_profile_id: String,
    /// Dimension 12c: whether the detector profile is currently degraded/abstained.
    pub detector_degraded: bool,
    /// Estimated detection opportunity in basis points (`0..=10_000`).
    pub detection_probability_bps: u16,
    /// Explicit epistemic uncertainty width in basis points (`0..=10_000`).
    pub uncertainty_bps: u16,
    /// Validity window start timestamp (inclusive).
    pub valid_from_ns: TimestampNs,
    /// Validity window end timestamp (inclusive).
    pub valid_until_ns: TimestampNs,
    /// Shared failure-domain assumptions (power/network/clock/host).
    pub failure_domains: BTreeSet<String>,
    /// Semantic plane owning this factor (defaults to `Plane::Cognition`).
    pub plane: Plane,
}

impl VisibilityFactor {
    /// Validates all 12 conditioning dimensions and bounds fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.factor_id, "factor_id")?;
        validate_clean_label(&self.camera_id, "camera_id")?;
        validate_clean_label(&self.target_cell_id, "target_cell_id")?;
        validate_clean_label(&self.target_class, "target_class")?;
        validate_clean_label(&self.environment_regime, "environment_regime")?;
        validate_clean_label(&self.target_direction, "target_direction")?;
        validate_clean_label(&self.detector_profile_id, "detector_profile_id")?;
        if self.camera_generation.0 == 0
            || self.calibration_generation.0 == 0
            || self.detector_model_generation.0 == 0
            || self.target_height_cm == 0
            || self.detection_probability_bps > 10_000
            || self.uncertainty_bps > 10_000
            || self.valid_until_ns.0 < self.valid_from_ns.0
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "invalid conditioning bounds on factor '{}'",
                self.factor_id
            )));
        }
        for dom in &self.failure_domains {
            validate_clean_label(dom, "failure_domain")?;
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment over all 12 dimensions, uncertainty, validity, and failure domains.
    #[must_use]
    pub fn factor_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(H_VIS_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.factor_id);
        enc.text(&self.camera_id);
        enc.u64(self.camera_generation.0);
        enc.u64(self.calibration_generation.0);
        enc.text(&self.target_cell_id);
        enc.text(&self.target_class);
        enc.text(&self.environment_regime);
        enc.u8(self.sensor_health as u8);
        enc.u8(self.pose_fov as u8);
        enc.u8(self.occluder_state as u8);
        enc.u8(self.illumination_weather as u8);
        enc.u8(self.lens_health as u8);
        enc.u32(u32::from(self.target_height_cm));
        enc.text(&self.target_direction);
        enc.u8(self.codec_quality as u8);
        enc.u64(self.detector_model_generation.0);
        enc.text(&self.detector_profile_id);
        enc.u8(u8::from(self.detector_degraded));
        enc.u32(u32::from(self.detection_probability_bps));
        enc.u32(u32::from(self.uncertainty_bps));
        enc.i128(self.valid_from_ns.0);
        enc.i128(self.valid_until_ns.0);
        enc.u64(self.failure_domains.len() as u64);
        for dom in &self.failure_domains {
            enc.text(dom);
        }
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let factor_id = dec.text().map_err(map_err)?.to_owned();
        let camera_id = dec.text().map_err(map_err)?.to_owned();
        let camera_generation = Generation(dec.u64().map_err(map_err)?);
        let calibration_generation = Generation(dec.u64().map_err(map_err)?);
        let target_cell_id = dec.text().map_err(map_err)?.to_owned();
        let target_class = dec.text().map_err(map_err)?.to_owned();
        let environment_regime = dec.text().map_err(map_err)?.to_owned();
        let sensor_health = SensorHealthPosture::from_tag(dec.u8().map_err(map_err)?)?;
        let pose_fov = PoseFovStatus::from_tag(dec.u8().map_err(map_err)?)?;
        let occluder_state = OccluderState::from_tag(dec.u8().map_err(map_err)?)?;
        let illumination_weather = IlluminationWeather::from_tag(dec.u8().map_err(map_err)?)?;
        let lens_health = LensHealthState::from_tag(dec.u8().map_err(map_err)?)?;
        let target_height_cm = u16::try_from(dec.u32().map_err(map_err)?).map_err(|_| {
            TypedUniverseError::MalformedWire("target_height_cm overflow".to_owned())
        })?;
        let target_direction = dec.text().map_err(map_err)?.to_owned();
        let codec_quality = CodecQualityState::from_tag(dec.u8().map_err(map_err)?)?;
        let detector_model_generation = Generation(dec.u64().map_err(map_err)?);
        let detector_profile_id = dec.text().map_err(map_err)?.to_owned();
        let detector_degraded = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid detector_degraded bool".to_owned(),
                ));
            }
        };
        let detection_probability_bps = u16::try_from(dec.u32().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("detection_prob overflow".to_owned()))?;
        let uncertainty_bps = u16::try_from(dec.u32().map_err(map_err)?).map_err(|_| {
            TypedUniverseError::MalformedWire("uncertainty_bps overflow".to_owned())
        })?;
        let valid_from_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let valid_until_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let dom_len = usize::try_from(dec.u64().map_err(map_err)?).map_err(|_| {
            TypedUniverseError::MalformedWire("failure_domains count overflow".to_owned())
        })?;
        if dom_len > 64 || dom_len.saturating_mul(5) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "failure_domains count exceeds bounds".to_owned(),
            ));
        }
        let mut failure_domains = BTreeSet::new();
        for _ in 0..dom_len {
            failure_domains.insert(dec.text().map_err(map_err)?.to_owned());
        }
        let plane = match dec.text().map_err(map_err)? {
            "authority" => Plane::Authority,
            "cognition" => Plane::Cognition,
            "effect" => Plane::Effect,
            other => {
                return Err(TypedUniverseError::MalformedWire(format!(
                    "unknown plane '{other}'"
                )));
            }
        };
        let factor = Self {
            factor_id,
            camera_id,
            camera_generation,
            calibration_generation,
            target_cell_id,
            target_class,
            environment_regime,
            sensor_health,
            pose_fov,
            occluder_state,
            illumination_weather,
            lens_health,
            target_height_cm,
            target_direction,
            codec_quality,
            detector_model_generation,
            detector_profile_id,
            detector_degraded,
            detection_probability_bps,
            uncertainty_bps,
            valid_from_ns,
            valid_until_ns,
            failure_domains,
            plane,
        };
        factor.validate()?;
        Ok(factor)
    }

    /// Returns explicit non-certifying condition reasons if any of the 12 dimensions degrades or
    /// invalidates detection coverage at `now_ns`.
    #[must_use]
    pub fn coverage_defects(
        &self,
        now_ns: TimestampNs,
        expected_calibration_gen: Option<Generation>,
    ) -> Vec<&'static str> {
        let mut defects = Vec::new();
        if now_ns.0 < self.valid_from_ns.0 || now_ns.0 > self.valid_until_ns.0 {
            defects.push("validity_window_expired");
        }
        if let Some(expected) = expected_calibration_gen
            && self.calibration_generation != expected
        {
            defects.push("calibration_generation_stale");
        }
        if self.sensor_health != SensorHealthPosture::Nominal {
            defects.push("sensor_health_degraded_or_offline");
        }
        if self.pose_fov != PoseFovStatus::InFrustumVerified {
            defects.push("pose_fov_unverified_or_outside");
        }
        if self.occluder_state != OccluderState::Clear {
            defects.push("occluder_present_or_unknown");
        }
        if matches!(
            self.illumination_weather,
            IlluminationWeather::GlareOrFog
                | IlluminationWeather::SevereWeather
                | IlluminationWeather::Unknown
        ) {
            defects.push("illumination_weather_degraded");
        }
        if self.lens_health != LensHealthState::Clean {
            defects.push("lens_health_degraded");
        }
        if self.codec_quality != CodecQualityState::High {
            defects.push("codec_quality_degraded");
        }
        if self.detector_degraded {
            defects.push("detector_profile_degraded");
        }
        defects
    }
}

/// Incremental ordered delta applied to an `H_vis` hypergraph projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VisibilityDelta {
    /// Insert or replace a typed 12-dimension factor.
    UpsertFactor(Box<VisibilityFactor>),
    /// Remove an obsolete factor by stable ID.
    RemoveFactor(String),
}

/// One derived lossy camera-to-cell bipartite edge linking back to its native `H_vis` factors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraCellBipartiteEdge {
    /// Camera identifier.
    pub camera_id: String,
    /// Target spatial cell identifier.
    pub target_cell_id: String,
    /// Back-pointers to every native 12-dimension `H_vis` factor aggregated into this edge.
    pub source_factor_ids: Vec<String>,
    /// Combined digest binding all conditioning generations and factor states.
    pub conditioning_digest: ContentDigest,
    /// Conservative minimum detection probability across aggregated factors (bps).
    pub min_detection_probability_bps: u16,
    /// Conservative maximum uncertainty across aggregated factors (bps).
    pub max_uncertainty_bps: u16,
    /// Always `true`: marks this bipartite view as a lossy projection of native `H_vis`.
    pub is_lossy_bipartite_projection: bool,
    /// True ONLY when every underlying factor is clear, current, and unredacted.
    pub certifies_absence: bool,
}

/// Derived camera-to-cell bipartite view for placement algorithms with explicit factor links.
#[derive(Clone, Debug, PartialEq)]
pub struct CameraCellBipartiteView {
    /// Digest of the parent `H_vis` hypergraph.
    pub parent_h_vis_digest: ContentDigest,
    /// Preserved absence boundary from `H_vis`.
    pub absence_boundary: AbsenceBoundary,
    /// Sorted canonical bipartite edges.
    pub edges: Vec<CameraCellBipartiteEdge>,
    /// Certified witness for this bipartite derivation.
    pub witness: GraphAlgorithmWitness,
}

/// Non-collapsed cell coverage verdict distinguishing certified coverage from unknown/uncertified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VisibilityCoverageVerdict {
    /// At least one clear, valid, current, unredacted factor certifies detection opportunity.
    CertifiedObservable {
        /// Certifying factor IDs (sorted).
        certifying_factors: Vec<String>,
        /// Best detection probability among certifying factors (bps).
        best_detection_probability_bps: u16,
        /// Worst uncertainty among certifying factors (bps).
        max_uncertainty_bps: u16,
        /// Union of failure domains shared by certifying factors.
        failure_domains: BTreeSet<String>,
    },
    /// Missing, stale, occluded, degraded, or redacted conditions: NO-DETECTION IS NOT ABSENCE!
    UnknownUncertified {
        /// Machine-readable reason list (`missing_factor`, `calibration_generation_stale`, etc.).
        reasons: Vec<String>,
        /// Matching but degraded/stale factor IDs inspected.
        inspected_factors: Vec<String>,
    },
}

impl VisibilityCoverageVerdict {
    /// Returns `true` ONLY when coverage is certified observable and absence could be reasoned over.
    #[must_use]
    pub const fn certifies_absence(&self) -> bool {
        matches!(self, Self::CertifiedObservable { .. })
    }
}

/// Result of querying cell coverage over `H_vis`, paired with a `GraphAlgorithmWitness`.
#[derive(Clone, Debug, PartialEq)]
pub struct VisibilityCoverageAssessment {
    /// Queried spatial cell identifier.
    pub target_cell_id: String,
    /// Queried target class.
    pub target_class: String,
    /// Non-collapsed verdict.
    pub verdict: VisibilityCoverageVerdict,
    /// Derived cognition only: NEVER authorizes an effect.
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Visibility & Coverage Hypergraph (`H_vis`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibilityHypergraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_factors: BTreeMap<String, VisibilityFactor>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl VisibilityHypergraph {
    /// Builds `H_vis` from ordered `EvidenceDeltaBatch`-derived factors at one pinned anchor.
    ///
    /// Capability and privacy filtering run BEFORE factor expansion via
    /// [`ImmutableGraphProjection::build`]; redacted or plane-excluded factors never leak into
    /// `visible_factors` and downgrade [`AbsenceBoundary`].
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        factors: Vec<VisibilityFactor>,
        requested_absence: AbsenceBoundary,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if is_cancelled() {
            return Err(TypedUniverseError::Cancelled);
        }
        let projection_id = projection_id.into();
        validate_clean_label(&projection_id, "projection_id")?;
        if policy_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(
                "policy_generation must be >= 1".to_owned(),
            ));
        }
        if factors.len() > MAX_UNIVERSE_ITEMS {
            return Err(TypedUniverseError::InvalidInput(format!(
                "factor count {} exceeds maximum {MAX_UNIVERSE_ITEMS}",
                factors.len()
            )));
        }

        let mut raw_factors: BTreeMap<String, VisibilityFactor> = BTreeMap::new();
        for factor in factors {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            factor.validate()?;
            if raw_factors.contains_key(&factor.factor_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate factor_id '{}'",
                    factor.factor_id
                )));
            }
            raw_factors.insert(factor.factor_id.clone(), factor);
        }

        let mut raw_nodes: BTreeMap<String, ProjectionNodeSpec> = BTreeMap::new();
        let mut raw_edges: Vec<ProjectionEdgeSpec> = Vec::new();
        for factor in raw_factors.values() {
            let f_node = format!("factor/{}", factor.factor_id);
            let c_node = format!("camera/{}", factor.camera_id);
            let cell_node = format!("cell/{}", factor.target_cell_id);
            let f_digest = factor.factor_digest();

            raw_nodes.insert(
                f_node.clone(),
                ProjectionNodeSpec {
                    node_id: f_node.clone(),
                    plane: factor.plane,
                    payload_digest: f_digest,
                },
            );
            raw_nodes
                .entry(c_node.clone())
                .or_insert_with(|| ProjectionNodeSpec {
                    node_id: c_node.clone(),
                    plane: Plane::Authority,
                    payload_digest: hash_domain_tag(
                        H_VIS_DIGEST_DOMAIN,
                        2,
                        factor.camera_id.as_bytes(),
                    ),
                });
            raw_nodes
                .entry(cell_node.clone())
                .or_insert_with(|| ProjectionNodeSpec {
                    node_id: cell_node.clone(),
                    plane: Plane::Cognition,
                    payload_digest: hash_domain_tag(
                        H_VIS_DIGEST_DOMAIN,
                        3,
                        factor.target_cell_id.as_bytes(),
                    ),
                });

            raw_edges.push(ProjectionEdgeSpec {
                source_id: c_node,
                target_id: f_node.clone(),
                relation: "observes_factor".to_owned(),
                weight: u64::from(factor.detection_probability_bps),
            });
            raw_edges.push(ProjectionEdgeSpec {
                source_id: f_node.clone(),
                target_id: cell_node,
                relation: "covers_cell".to_owned(),
                weight: u64::from(factor.uncertainty_bps),
            });
            for dom in &factor.failure_domains {
                let d_node = format!("domain/{dom}");
                raw_nodes
                    .entry(d_node.clone())
                    .or_insert_with(|| ProjectionNodeSpec {
                        node_id: d_node.clone(),
                        plane: Plane::Cognition,
                        payload_digest: hash_domain_tag(H_VIS_DIGEST_DOMAIN, 4, dom.as_bytes()),
                    });
                raw_edges.push(ProjectionEdgeSpec {
                    source_id: f_node.clone(),
                    target_id: d_node,
                    relation: "shares_failure_domain".to_owned(),
                    weight: 1,
                });
            }
        }

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::HVis,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            raw_nodes.into_values().collect(),
            raw_edges,
            requested_absence,
            is_cancelled(),
        )?;

        // Retain ONLY factors whose camera, factor, AND target cell survived capability/privacy filtering!
        let mut visible_factors = BTreeMap::new();
        for (fid, factor) in raw_factors {
            let f_node = format!("factor/{fid}");
            let c_node = format!("camera/{}", factor.camera_id);
            let cell_node = format!("cell/{}", factor.target_cell_id);
            if projection.handle_for_node_id(&f_node).is_some()
                && projection.handle_for_node_id(&c_node).is_some()
                && projection.handle_for_node_id(&cell_node).is_some()
            {
                visible_factors.insert(fid, factor);
            }
        }

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_factors,
        );
        Ok(Self {
            projection_id,
            policy_generation,
            projection,
            visible_factors,
            tombstoned_fields: Vec::new(),
            universe_digest,
        })
    }

    /// Incrementally applies ordered `EvidenceDeltaBatch` visibility deltas at `new_anchor`,
    /// guaranteeing exact equivalence to a full rebuild from the resulting factor set.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[VisibilityDelta],
        requested_absence: AbsenceBoundary,
        is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if expected_policy_generation != self.policy_generation {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(format!(
                "policy generation mismatch: expected {}, active {}",
                expected_policy_generation.0, self.policy_generation.0
            )));
        }
        if new_anchor.site_lineage != self.projection.anchor().site_lineage
            || new_anchor.commit_sequence < self.projection.anchor().commit_sequence
        {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "incremental delta anchor must stay on same site_lineage with monotonic sequence"
                    .to_owned(),
            ));
        }
        let mut next = self.visible_factors.clone();
        for delta in deltas {
            match delta {
                VisibilityDelta::UpsertFactor(factor) => {
                    factor.validate()?;
                    next.insert(factor.factor_id.clone(), (**factor).clone());
                }
                VisibilityDelta::RemoveFactor(fid) => {
                    next.remove(fid);
                }
            }
        }
        Self::build(
            self.projection_id.clone(),
            self.policy_generation,
            new_anchor,
            new_history_root,
            authority,
            next.into_values().collect(),
            requested_absence,
            is_cancelled,
        )
    }

    /// Underlying capability-filtered `ImmutableGraphProjection`.
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical digest of this `H_vis` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Visible native 12-dimension factors in canonical sorted order.
    #[must_use]
    pub const fn visible_factors(&self) -> &BTreeMap<String, VisibilityFactor> {
        &self.visible_factors
    }

    /// Tombstoned legacy fields recorded during any `v1 -> v2` migration.
    #[must_use]
    pub fn tombstoned_fields(&self) -> &[String] {
        &self.tombstoned_fields
    }

    /// Derived cognition NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Derives the lossy camera-to-cell bipartite view for placement algorithms while retaining
    /// explicit back-links to every underlying 12-dimension factor and uncertainty bound.
    pub fn derive_camera_cell_bipartite(
        &self,
        now_ns: TimestampNs,
        expected_calibration_gen: Option<Generation>,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<CameraCellBipartiteView, TypedUniverseError> {
        let mut budget = OpBudget::new(max_operations)?;
        let mut grouped: BTreeMap<(String, String), Vec<&VisibilityFactor>> = BTreeMap::new();
        for factor in self.visible_factors.values() {
            budget.charge(1, &mut is_cancelled)?;
            grouped
                .entry((factor.camera_id.clone(), factor.target_cell_id.clone()))
                .or_default()
                .push(factor);
        }

        let mut edges = Vec::with_capacity(grouped.len());
        let mut path_enc = CanonicalEncoder::new();
        for ((camera_id, target_cell_id), factors) in grouped {
            budget.charge(factors.len() as u64, &mut is_cancelled)?;
            let mut source_factor_ids = Vec::with_capacity(factors.len());
            let mut cond_enc = CanonicalEncoder::new();
            let mut min_prob = u16::MAX;
            let mut max_unc = 0_u16;
            let mut all_clear = self.projection.absence_boundary().certifies_absence();
            for f in &factors {
                source_factor_ids.push(f.factor_id.clone());
                cond_enc.digest(f.factor_digest());
                min_prob = min_prob.min(f.detection_probability_bps);
                max_unc = max_unc.max(f.uncertainty_bps);
                if !f
                    .coverage_defects(now_ns, expected_calibration_gen)
                    .is_empty()
                {
                    all_clear = false;
                }
            }
            let conditioning_digest = hash_domain_tag(H_VIS_DIGEST_DOMAIN, 5, &cond_enc.finish());
            path_enc.text(&camera_id);
            path_enc.text(&target_cell_id);
            path_enc.digest(conditioning_digest);
            edges.push(CameraCellBipartiteEdge {
                camera_id,
                target_cell_id,
                source_factor_ids,
                conditioning_digest,
                min_detection_probability_bps: if min_prob == u16::MAX { 0 } else { min_prob },
                max_uncertainty_bps: max_unc,
                is_lossy_bipartite_projection: true,
                certifies_absence: all_clear,
            });
        }

        let decision_path_digest = hash_domain_tag(H_VIS_DIGEST_DOMAIN, 6, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.u64(edges.len() as u64);
        for edge in &edges {
            out_enc.text(&edge.camera_id);
            out_enc.text(&edge.target_cell_id);
            out_enc.digest(edge.conditioning_digest);
            out_enc.u8(u8::from(edge.certifies_absence));
        }
        let output_digest = hash_domain_tag(H_VIS_DIGEST_DOMAIN, 7, &out_enc.finish());
        let witness = build_universe_witness(
            H_VIS_ALGORITHM_ID,
            H_VIS_IMPLEMENTATION_ID,
            GraphUniverse::HVis,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            H_VIS_POLICY_ID,
            budget.used(),
            (edges.len() * 128) as u64,
            decision_path_digest,
            output_digest,
        )?;
        Ok(CameraCellBipartiteView {
            parent_h_vis_digest: self.universe_digest,
            absence_boundary: self.projection.absence_boundary().clone(),
            edges,
            witness,
        })
    }

    /// Evaluates detection coverage for `(target_cell_id, target_class)` at `now_ns`.
    ///
    /// Any missing, stale, expired, occluded, degraded, or redacted condition yields
    /// [`VisibilityCoverageVerdict::UnknownUncertified`] so a no-detection event can NEVER be
    /// promoted into evidence of physical absence.
    pub fn assess_cell_coverage(
        &self,
        target_cell_id: &str,
        target_class: &str,
        now_ns: TimestampNs,
        expected_calibration_gen: Option<Generation>,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<VisibilityCoverageAssessment, TypedUniverseError> {
        validate_clean_label(target_cell_id, "target_cell_id")?;
        validate_clean_label(target_class, "target_class")?;
        let mut budget = OpBudget::new(max_operations)?;

        let mut reasons: BTreeSet<String> = BTreeSet::new();
        let mut inspected_factors = Vec::new();
        let mut certifying_factors = Vec::new();
        let mut best_prob = 0_u16;
        let mut max_unc = 0_u16;
        let mut failure_domains = BTreeSet::new();

        if !self.projection.absence_boundary().certifies_absence() {
            reasons.insert("projection_redacted_or_uncertified_absence_boundary".to_owned());
        }

        let mut path_enc = CanonicalEncoder::new();
        for factor in self.visible_factors.values() {
            budget.charge(1, &mut is_cancelled)?;
            if factor.target_cell_id != target_cell_id || factor.target_class != target_class {
                continue;
            }
            inspected_factors.push(factor.factor_id.clone());
            path_enc.text(&factor.factor_id);
            let defects = factor.coverage_defects(now_ns, expected_calibration_gen);
            if defects.is_empty() && self.projection.absence_boundary().certifies_absence() {
                certifying_factors.push(factor.factor_id.clone());
                best_prob = best_prob.max(factor.detection_probability_bps);
                max_unc = max_unc.max(factor.uncertainty_bps);
                failure_domains.extend(factor.failure_domains.iter().cloned());
            } else {
                for defect in defects {
                    reasons.insert(defect.to_owned());
                }
            }
        }

        let verdict = if !certifying_factors.is_empty()
            && self.projection.absence_boundary().certifies_absence()
        {
            VisibilityCoverageVerdict::CertifiedObservable {
                certifying_factors,
                best_detection_probability_bps: best_prob,
                max_uncertainty_bps: max_unc,
                failure_domains,
            }
        } else {
            if inspected_factors.is_empty() {
                reasons.insert("missing_visibility_factor".to_owned());
            }
            VisibilityCoverageVerdict::UnknownUncertified {
                reasons: reasons.into_iter().collect(),
                inspected_factors,
            }
        };

        let decision_path_digest = hash_domain_tag(H_VIS_DIGEST_DOMAIN, 8, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.text(target_cell_id);
        out_enc.text(target_class);
        out_enc.u8(u8::from(verdict.certifies_absence()));
        match &verdict {
            VisibilityCoverageVerdict::CertifiedObservable {
                certifying_factors: cf,
                best_detection_probability_bps,
                max_uncertainty_bps,
                ..
            } => {
                out_enc.u64(cf.len() as u64);
                out_enc.u32(u32::from(*best_detection_probability_bps));
                out_enc.u32(u32::from(*max_uncertainty_bps));
            }
            VisibilityCoverageVerdict::UnknownUncertified {
                reasons: r,
                inspected_factors: inf,
            } => {
                out_enc.u64(r.len() as u64);
                for item in r {
                    out_enc.text(item);
                }
                out_enc.u64(inf.len() as u64);
            }
        }
        let output_digest = hash_domain_tag(H_VIS_DIGEST_DOMAIN, 9, &out_enc.finish());
        let witness = build_universe_witness(
            H_VIS_ALGORITHM_ID,
            H_VIS_IMPLEMENTATION_ID,
            GraphUniverse::HVis,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            H_VIS_POLICY_ID,
            budget.used(),
            ((self.visible_factors.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;
        Ok(VisibilityCoverageAssessment {
            target_cell_id: target_cell_id.to_owned(),
            target_class: target_class.to_owned(),
            verdict,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes this `H_vis` universe to its current versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, None)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a deprecated `legacy_flat_score_bps`
    /// field so compatibility and migration tests exercise real `v1 -> v2` tombstone migration.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_flat_score_bps: u32,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, Some(legacy_flat_score_bps))
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_flat_score: Option<u32>,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        let proj_bytes = self.projection.to_canonical_bytes()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(&self.projection_id);
        enc.u64(self.policy_generation.0);
        enc.bytes(&proj_bytes);
        enc.u64(self.visible_factors.len() as u64);
        for factor in self.visible_factors.values() {
            factor.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u32(legacy_flat_score.unwrap_or(0));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for tomb in &self.tombstoned_fields {
                enc.text(tomb);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(H_VIS_WIRE_MAGIC, version, H_VIS_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `H_vis` fixture,
    /// quarantining unknown versions and corrupt checksums fail-closed.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) = open_wire_envelope(bytes, H_VIS_WIRE_MAGIC, H_VIS_DIGEST_DOMAIN)?;
        let mut dec = CanonicalDecoder::new(payload);
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let projection_id = dec.text().map_err(map_err)?.to_owned();
        validate_clean_label(&projection_id, "projection_id")?;
        let policy_generation = Generation(dec.u64().map_err(map_err)?);
        if policy_generation.0 == 0 {
            return Err(TypedUniverseError::MalformedWire(
                "zero policy_generation".to_owned(),
            ));
        }
        let proj_bytes = dec.bytes().map_err(map_err)?;
        let projection = ImmutableGraphProjection::from_canonical_bytes(proj_bytes)?;
        if projection.universe() != GraphUniverse::HVis {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not H_vis".to_owned(),
            ));
        }
        let count = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("factor count overflow".to_owned()))?;
        if count > MAX_UNIVERSE_ITEMS || count.saturating_mul(32) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "factor count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_factors = BTreeMap::new();
        for _ in 0..count {
            let factor = VisibilityFactor::decode_body(&mut dec)?;
            if visible_factors.contains_key(&factor.factor_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate factor_id in wire fixture".to_owned(),
                ));
            }
            visible_factors.insert(factor.factor_id.clone(), factor);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flat_score = dec.u32().map_err(map_err)?;
            (
                true,
                vec!["v1.legacy_flat_score_bps:tombstoned_replaced_by_12d_factors".to_owned()],
            )
        } else {
            let t_len = usize::try_from(dec.u64().map_err(map_err)?).map_err(|_| {
                TypedUniverseError::MalformedWire("tombstone count overflow".to_owned())
            })?;
            if t_len > 32 || t_len.saturating_mul(4) > dec.remaining() {
                return Err(TypedUniverseError::MalformedWire(
                    "tombstone count exceeds bounds".to_owned(),
                ));
            }
            let mut tombs = Vec::with_capacity(t_len);
            for _ in 0..t_len {
                let t = dec.text().map_err(map_err)?.to_owned();
                validate_clean_label(&t, "tombstone")?;
                tombs.push(t);
            }
            (false, tombs)
        };
        dec.ensure_finished().map_err(map_err)?;

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_factors,
        );
        let report = UniverseMigrationReport {
            source_version: version,
            target_version: CURRENT_UNIVERSE_WIRE_VERSION,
            migrated,
            tombstoned_fields: tombstoned_fields.clone(),
            universe_digest,
        };
        Ok((
            Self {
                projection_id,
                policy_generation,
                projection,
                visible_factors,
                tombstoned_fields,
                universe_digest,
            },
            report,
        ))
    }

    fn compute_digest(
        projection_id: &str,
        policy_generation: Generation,
        projection: &ImmutableGraphProjection,
        visible_factors: &BTreeMap<String, VisibilityFactor>,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(projection_id);
        enc.u64(policy_generation.0);
        enc.digest(projection.generation().projection_digest);
        enc.u64(visible_factors.len() as u64);
        for factor in visible_factors.values() {
            enc.digest(factor.factor_digest());
        }
        hash_domain_tag(H_VIS_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
