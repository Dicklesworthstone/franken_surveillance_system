//! Deterministic scripted perception oracle and mock model executor (FSS-020).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ContractError,
    KnowledgeState, ModelGeneration, ProbabilityInterval, ProvenanceClass, SensorCapsuleV1,
    SensorId,
};
use fss_object::InMemoryObjectStore;

use crate::{ReferenceCapture, ReferenceError, VirtualClock};

/// Maximum byte length for a model generation identifier string.
pub const MAX_MODEL_GENERATION_BYTES: usize = 256;

/// Maximum payload size in bytes for a single model input frame (1 MiB).
pub const MAX_INPUT_PAYLOAD_BYTES: usize = 1_048_576;

/// Maximum character/byte length for an injected fault reason or diagnostic message.
pub const MAX_FAULT_REASON_LEN: usize = 256;

/// Maximum detections emitted in a single model output.
pub const MAX_DETECTIONS_PER_OUTPUT: usize = 64;

/// Maximum distinct sources permitted in a single corroboration evaluation.
pub const MAX_CORROBORATION_SOURCES: usize = 32;

/// Maximum dimension length for an embedding vector.
pub const MAX_EMBEDDING_DIM: usize = 4096;

/// Normative ADR-0004 identifier.
pub const ADR_0004_ID: &str = "ADR-0004";

/// Normative ADR-0004 title.
pub const ADR_0004_TITLE: &str = "Models are immutable qualified generations, not mutable names";

/// Returns true if the generation identifier attempts to reference a mutable "latest" alias,
/// strictly forbidden by ADR-0004 and AGENTS.md.
#[inline]
#[must_use]
pub fn is_latest_generation(generation: &str) -> bool {
    let trimmed = generation.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "latest" || lower == "latest.weights" {
        return true;
    }
    lower
        .split(|c: char| !c.is_alphanumeric())
        .any(|token| token == "latest")
}

/// Encodes a normalized coordinate [0.0, 1.0] into a deterministic discrete basis point [0, 10_000]
/// using IEEE 754 half-away-from-zero rounding to eliminate float truncation drift (INV-004).
///
/// Fails closed with typed error if `coord` is non-finite or out of range [0.0, 1.0]. Never silently clamps.
#[inline]
pub fn encode_coord_to_basis_point(coord: f64) -> Result<u64, MockModelError> {
    if !coord.is_finite() {
        return Err(MockModelError::InvalidCoordinate);
    }
    if !(0.0..=1.0).contains(&coord) {
        return Err(MockModelError::CoordinateOutOfRange { coord });
    }
    let normalized = if coord == 0.0 { 0.0 } else { coord };
    Ok((normalized * 10_000.0).round() as u64)
}

/// Coarse model-facing label. This is derived cognition, not canonical event truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockSemanticLabel {
    /// Person-like visual evidence.
    PersonLike,
    /// Animal-like visual evidence.
    AnimalLike,
    /// Sensor tamper/replay-like evidence.
    TamperLike,
    /// Evidence does not fit the small reference vocabulary.
    Unknown,
}

impl MockSemanticLabel {
    /// Canonical discriminator tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PersonLike => 1,
            Self::AnimalLike => 2,
            Self::TamperLike => 3,
            Self::Unknown => 4,
        }
    }
}

/// Script controlling the deterministic model oracle.
#[derive(Clone, Debug, PartialEq)]
pub enum MockModelScript {
    /// Emit a fixed derived finding even when transport coverage is degraded.
    Fixed {
        /// Derived label.
        label: MockSemanticLabel,
        /// Explicit probability interval.
        probability: ProbabilityInterval,
    },
    /// Emit the finding only when transport delivery is exact, once, complete, and ordered.
    RequireExactDelivery {
        /// Derived label on admitted input.
        label: MockSemanticLabel,
        /// Explicit probability interval on admitted input.
        probability: ProbabilityInterval,
    },
}

/// Normative ADR-0004 model generation descriptor binding the 9 mandatory facets.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelGenerationDescriptor {
    /// Exact weights content digest.
    pub weights_digest: ContentDigest,
    /// Upstream source revision (commit sha or tag).
    pub source_revision: String,
    /// Applicable license expression (e.g. "Apache-2.0").
    pub license: String,
    /// Target runtime environment (e.g. "pure-rust-v1").
    pub runtime: String,
    /// Target accelerator (e.g. "cpu", "cuda", "simd").
    pub accelerator: String,
    /// Canonical preprocessing pipeline identifier.
    pub preprocessing: String,
    /// Output schema identifier.
    pub output_schema: String,
    /// Maximum resource envelope in bytes.
    pub resource_envelope_bytes: usize,
    /// Qualification bundle digest.
    pub qualification_bundle: ContentDigest,
}

impl ModelGenerationDescriptor {
    /// Constructs a descriptor for an immutable model generation with deterministic defaults.
    #[must_use]
    pub fn for_generation(generation: &str) -> Self {
        let weights_digest = ContentDigest::sha256(format!("weights:{generation}").as_bytes());
        let qual_digest = ContentDigest::sha256(format!("qual:{generation}").as_bytes());
        Self {
            weights_digest,
            source_revision: format!("git:{generation}"),
            license: "Apache-2.0".to_string(),
            runtime: "fss.reference.mock_runtime.v1".to_string(),
            accelerator: "cpu".to_string(),
            preprocessing: "fss.mock_preproc.v1".to_string(),
            output_schema: "fss.mock_model_output.v1".to_string(),
            resource_envelope_bytes: 16 * 1024 * 1024,
            qualification_bundle: qual_digest,
        }
    }
}

/// Immutable model generation/specification used by the reference executor.
#[derive(Clone, Debug, PartialEq)]
pub struct MockModelSpec {
    generation_id: String,
    script: MockModelScript,
    descriptor: ModelGenerationDescriptor,
}

impl MockModelSpec {
    /// Constructs one bounded scripted model generation with default ADR-0004 descriptor.
    pub fn new(
        generation_id: impl Into<String>,
        script: MockModelScript,
    ) -> Result<Self, ReferenceError> {
        let generation_id = generation_id.into();
        let trimmed = generation_id.trim();
        if trimmed.is_empty() || generation_id.len() > MAX_MODEL_GENERATION_BYTES {
            return Err(ReferenceError::InvalidSpec("model_generation_id"));
        }
        if is_latest_generation(&generation_id) {
            return Err(ReferenceError::InvalidSpec(
                "model_generation_latest_prohibited",
            ));
        }
        let descriptor = ModelGenerationDescriptor::for_generation(trimmed);
        Ok(Self {
            generation_id,
            script,
            descriptor,
        })
    }

    /// Constructs one bounded scripted model generation with an explicit ADR-0004 descriptor.
    pub fn with_descriptor(
        generation_id: impl Into<String>,
        script: MockModelScript,
        descriptor: ModelGenerationDescriptor,
    ) -> Result<Self, ReferenceError> {
        let generation_id = generation_id.into();
        let trimmed = generation_id.trim();
        if trimmed.is_empty() || generation_id.len() > MAX_MODEL_GENERATION_BYTES {
            return Err(ReferenceError::InvalidSpec("model_generation_id"));
        }
        if is_latest_generation(&generation_id) {
            return Err(ReferenceError::InvalidSpec(
                "model_generation_latest_prohibited",
            ));
        }
        Ok(Self {
            generation_id,
            script,
            descriptor,
        })
    }

    /// Stable model generation identity.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Frozen deterministic behavior.
    #[must_use]
    pub fn script(&self) -> &MockModelScript {
        &self.script
    }

    /// Normative ADR-0004 model generation descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &ModelGenerationDescriptor {
        &self.descriptor
    }

    /// Content identity of the complete scripted model specification binding all ADR-0004 facets.
    #[must_use]
    pub fn spec_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.mock_model_spec.v1");
        encoder.text(&self.generation_id);
        encode_script(&self.script, &mut encoder);
        encoder.digest(self.descriptor.weights_digest);
        encoder.text(&self.descriptor.source_revision);
        encoder.text(&self.descriptor.license);
        encoder.text(&self.descriptor.runtime);
        encoder.text(&self.descriptor.accelerator);
        encoder.text(&self.descriptor.preprocessing);
        encoder.text(&self.descriptor.output_schema);
        encoder.u64(self.descriptor.resource_envelope_bytes as u64);
        encoder.digest(self.descriptor.qualification_bundle);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Why the scripted model explicitly refused to produce a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockAbstentionReason {
    /// Transport continuity/integrity failed the script's admission rule.
    DeliveryDegraded,
}

impl MockAbstentionReason {
    fn tag(self) -> u8 {
        match self {
            Self::DeliveryDegraded => 1,
        }
    }
}

/// Typed derived model outcome.
#[derive(Clone, Debug, PartialEq)]
pub enum MockModelOutcome {
    /// Model produced a derived label and probability interval.
    /// Deterministic finding with a bounded conservative probability interval.
    Finding {
        /// Semantic label.
        label: MockSemanticLabel,
        /// Calibrated or conservative probability interval.
        probability: ProbabilityInterval,
    },
    /// Explicit deterministic abstention.
    Abstained {
        /// Stable abstention reason.
        reason: MockAbstentionReason,
    },
}

impl MockModelOutcome {
    /// Validates that this model outcome is not being treated as negative evidence.
    ///
    /// Per NEG-003 and AGENTS.md, model abstention is epistemic `Unknown`, never
    /// evidence of absence (which strictly requires a verified `CoverageWitness`).
    pub fn assert_not_negative_evidence(&self) -> Result<(), MockModelError> {
        match self {
            Self::Abstained { reason } => Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                outcome: format!("MockModelOutcome::Abstained({reason:?})"),
            }),
            Self::Finding { .. } => Ok(()),
        }
    }
}

/// Retained deterministic model result.
#[derive(Clone, Debug, PartialEq)]
pub struct MockModelResult {
    /// Stable model generation identity.
    pub generation_id: String,
    /// Sensor identity from which capture was sourced.
    pub sensor_id: SensorId,
    /// Complete scripted model-spec digest.
    pub model_spec_digest: ContentDigest,
    /// Exact capture object graph consumed.
    pub input_capture_root: ContentDigest,
    /// Exact transport-continuity witness consumed.
    pub continuity_digest: ContentDigest,
    /// Typed derived outcome.
    pub outcome: MockModelOutcome,
}

impl MockModelResult {
    /// Canonical object identity for retained result bytes.
    #[must_use]
    pub fn object_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }
}

impl CanonicalEncode for MockModelResult {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.mock_model_result.v1");
        encoder.text(&self.generation_id);
        self.sensor_id.encode_canonical(encoder);
        encoder.digest(self.model_spec_digest);
        encoder.digest(self.input_capture_root);
        encoder.digest(self.continuity_digest);
        match &self.outcome {
            MockModelOutcome::Finding { label, probability } => {
                encoder.u8(1);
                encoder.u8(label.tag());
                probability.encode_canonical(encoder);
            }
            MockModelOutcome::Abstained { reason } => {
                encoder.u8(2);
                encoder.u8(reason.tag());
            }
        }
    }
}

/// Executes and retains one deterministic model result over an exact reference capture.
pub fn execute_mock_model(
    spec: &MockModelSpec,
    capture: &ReferenceCapture,
    objects: &mut InMemoryObjectStore,
) -> Result<MockModelResult, ReferenceError> {
    let outcome = match spec.script() {
        MockModelScript::Fixed { label, probability } => MockModelOutcome::Finding {
            label: *label,
            probability: *probability,
        },
        MockModelScript::RequireExactDelivery { label, probability } => {
            if capture.continuity.exact_once_ordered {
                MockModelOutcome::Finding {
                    label: *label,
                    probability: *probability,
                }
            } else {
                MockModelOutcome::Abstained {
                    reason: MockAbstentionReason::DeliveryDegraded,
                }
            }
        }
    };
    let sensor_id = capture
        .source_packets
        .first()
        .map(|packet| packet.sensor_id.clone())
        .ok_or(ReferenceError::InvalidSpec("capture_has_no_packets"))?;
    let result = MockModelResult {
        generation_id: spec.generation_id().to_string(),
        sensor_id,
        model_spec_digest: spec.spec_digest(),
        input_capture_root: capture.receipt.capture_root,
        continuity_digest: capture.receipt.continuity_digest,
        outcome,
    };
    let bytes = result.canonical_bytes();
    let stored = objects.put_verified(&bytes)?;
    if stored != result.object_digest() {
        return Err(ReferenceError::DigestMismatch);
    }
    Ok(result)
}

fn encode_script(script: &MockModelScript, encoder: &mut CanonicalEncoder) {
    match script {
        MockModelScript::Fixed { label, probability } => {
            encoder.u8(1);
            encoder.u8(label.tag());
            probability.encode_canonical(encoder);
        }
        MockModelScript::RequireExactDelivery { label, probability } => {
            encoder.u8(2);
            encoder.u8(label.tag());
            probability.encode_canonical(encoder);
        }
    }
}

// =========================================================================
// FSS-020 Deterministic Mock Model Executor
// =========================================================================

/// Coarse-grained semantic label from model inference.
#[derive(Clone, Debug, PartialEq)]
pub struct MockDetection {
    /// Derived semantic label.
    pub label: MockSemanticLabel,
    /// Probability interval for the detection.
    pub probability: ProbabilityInterval,
    /// Bounding box normalized coordinates: `[x1, y1, x2, y2]`.
    pub bounding_box: [f64; 4],
}

impl MockDetection {
    /// Constructs and validates a detection with finite normalized bounding box coordinates.
    pub fn new(
        label: MockSemanticLabel,
        probability: ProbabilityInterval,
        bounding_box: [f64; 4],
    ) -> Result<Self, MockModelError> {
        Self::validate_bounding_box(&bounding_box)?;
        Ok(Self {
            label,
            probability,
            bounding_box,
        })
    }

    /// Validates that a bounding box is non-NaN, finite, within [0.0, 1.0], and non-inverted.
    pub fn validate_bounding_box(bounding_box: &[f64; 4]) -> Result<(), MockModelError> {
        for &coord in bounding_box {
            if !coord.is_finite() {
                return Err(MockModelError::InvalidCoordinate);
            }
            if !(0.0..=1.0).contains(&coord) {
                return Err(MockModelError::CoordinateOutOfRange { coord });
            }
        }
        let [x1, y1, x2, y2] = *bounding_box;
        if x1 > x2 || y1 > y2 {
            return Err(MockModelError::InvertedBoundingBox {
                bounding_box: *bounding_box,
            });
        }
        Ok(())
    }

    /// Validates internal bounds and invariants.
    pub fn validate(&self) -> Result<(), MockModelError> {
        Self::validate_bounding_box(&self.bounding_box)
    }

    /// Computes the intersection of two normalized bounding boxes `[x1, y1, x2, y2]`.
    /// Fails closed with typed error if the boxes are disjoint, inverted, or contain non-finite or out-of-range coordinates.
    pub fn compute_bounding_box_intersection(
        box_a: &[f64; 4],
        box_b: &[f64; 4],
    ) -> Result<[f64; 4], MockModelError> {
        compute_bounding_box_intersection(box_a, box_b)
    }
}

/// Computes the intersection of two normalized bounding boxes `[x1, y1, x2, y2]`.
/// Fails closed with typed error if the boxes are disjoint, inverted, or contain non-finite or out-of-range coordinates.
pub fn compute_bounding_box_intersection(
    box_a: &[f64; 4],
    box_b: &[f64; 4],
) -> Result<[f64; 4], MockModelError> {
    MockDetection::validate_bounding_box(box_a)?;
    MockDetection::validate_bounding_box(box_b)?;

    let nx1 = box_a[0].max(box_b[0]);
    let ny1 = box_a[1].max(box_b[1]);
    let nx2 = box_a[2].min(box_b[2]);
    let ny2 = box_a[3].min(box_b[3]);

    if nx1 > nx2 || ny1 > ny2 {
        return Err(MockModelError::DisjointBoundingBoxes {
            box_a: *box_a,
            box_b: *box_b,
        });
    }

    Ok([nx1, ny1, nx2, ny2])
}

/// Corroboration status of a model finding.
///
/// In FSS, a model score is NEVER corroborated on its own (a single camera and single model
/// cannot corroborate itself). Cross-camera or independent source agreement is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorroborationStatus {
    /// Uncorroborated single source/sensor observation.
    UncorroboratedSingleSource {
        /// Sensor identity of the single source.
        sensor_id: SensorId,
        /// Model generation that produced the score.
        model_generation: String,
    },
    /// Multi-camera or multi-source corroborated finding.
    Corroborated {
        /// Distinct contributing sensor identifiers.
        contributing_sensors: Vec<SensorId>,
        /// Model generation identifiers that corroborated the finding.
        contributing_generations: Vec<String>,
    },
}

impl CorroborationStatus {
    /// Validates internal bounds and invariants for corroboration status (NEG-003 / INV-055).
    pub fn validate(&self) -> Result<(), MockModelError> {
        match self {
            Self::UncorroboratedSingleSource { .. } => Ok(()),
            Self::Corroborated {
                contributing_sensors,
                contributing_generations,
            } => {
                if contributing_sensors.len() < 2 {
                    return Err(MockModelError::InsufficientSourcesForCorroboration {
                        count: contributing_sensors.len(),
                        min_required: 2,
                    });
                }
                if contributing_sensors.len() > MAX_CORROBORATION_SOURCES {
                    return Err(MockModelError::TooManyCorroborationSources {
                        actual: contributing_sensors.len(),
                        max: MAX_CORROBORATION_SOURCES,
                    });
                }
                let mut seen = std::collections::BTreeSet::new();
                for s in contributing_sensors {
                    if !seen.insert(s) {
                        return Err(MockModelError::UncorroboratedSingleSensor {
                            sensor_id: s.clone(),
                        });
                    }
                }
                if contributing_generations.is_empty() {
                    return Err(MockModelError::EmptyGenerationId);
                }
                if contributing_generations.len() > MAX_CORROBORATION_SOURCES {
                    return Err(MockModelError::TooManyCorroborationSources {
                        actual: contributing_generations.len(),
                        max: MAX_CORROBORATION_SOURCES,
                    });
                }
                for generation_id in contributing_generations {
                    if is_latest_generation(generation_id) {
                        return Err(MockModelError::LatestGenerationProhibited {
                            generation: generation_id.clone(),
                        });
                    }
                }
                Ok(())
            }
        }
    }
}

/// Deterministic model output carrying explicit provenance, uncertainty, and epistemic state.
#[derive(Clone, Debug, PartialEq)]
pub struct MockModelOutput {
    /// Deterministic canonical digest identifying this output object.
    pub output_digest: ContentDigest,
    /// Immutable model generation identity that produced this output.
    pub generation: ModelGeneration,
    /// Sensor identity from which the input was captured.
    pub sensor_id: SensorId,
    /// Exact content digest of the consumed input (capsule, frame, or capture).
    pub input_digest: ContentDigest,
    /// Temporal capture interval of the input.
    pub capture_interval: CaptureInterval,
    /// Epistemic knowledge state (typically Estimated or Conflicted).
    pub knowledge_state: KnowledgeState,
    /// Provenance class (Predicted for model cognition).
    pub provenance_class: ProvenanceClass,
    /// Bounded list of deterministic detections.
    pub detections: Vec<MockDetection>,
    /// Explicit corroboration status (initially UncorroboratedSingleSource).
    pub corroboration: CorroborationStatus,
    /// Virtual inference latency consumed.
    pub virtual_latency_ns: u64,
}

impl MockModelOutput {
    /// Encodes this model output into canonical form.
    /// Fails closed if any coordinate is non-finite or out of normalized bounds.
    pub fn encode_canonical(&self, encoder: &mut CanonicalEncoder) -> Result<(), MockModelError> {
        self.validate()?;
        encoder.text("fss.mock_model_output.v1");
        encoder.text(self.generation.as_str());
        self.sensor_id.encode_canonical(encoder);
        encoder.digest(self.input_digest);
        self.capture_interval.encode_canonical(encoder);
        encoder.text(self.knowledge_state.as_str());
        encoder.text(provenance_class_str(self.provenance_class));
        encode_corroboration_status(&self.corroboration, encoder);
        encoder.u64(self.detections.len() as u64);
        for det in &self.detections {
            det.validate()?;
            encoder.u8(det.label.tag());
            det.probability.encode_canonical(encoder);
            for &coord in &det.bounding_box {
                let bp = encode_coord_to_basis_point(coord)?;
                encoder.u64(bp);
            }
        }
        encoder.u64(self.virtual_latency_ns);
        Ok(())
    }

    /// Serializes to deterministic canonical bytes.
    /// Fails closed if any detection or coordinate is invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MockModelError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder)?;
        Ok(encoder.finish())
    }

    /// Validates internal bounds and invariants.
    pub fn validate(&self) -> Result<(), MockModelError> {
        self.corroboration.validate()?;
        if self.detections.len() > MAX_DETECTIONS_PER_OUTPUT {
            return Err(MockModelError::TooManyDetections {
                actual: self.detections.len(),
                max: MAX_DETECTIONS_PER_OUTPUT,
            });
        }
        for det in &self.detections {
            det.validate()?;
        }
        Ok(())
    }

    /// Computes the content digest for this output object.
    pub fn compute_digest(&self) -> Result<ContentDigest, MockModelError> {
        let bytes = self.canonical_bytes()?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

fn provenance_class_str(class: ProvenanceClass) -> &'static str {
    class.as_str()
}

fn encode_corroboration_status(status: &CorroborationStatus, encoder: &mut CanonicalEncoder) {
    match status {
        CorroborationStatus::UncorroboratedSingleSource {
            sensor_id,
            model_generation,
        } => {
            encoder.u8(1);
            sensor_id.encode_canonical(encoder);
            encoder.text(model_generation);
        }
        CorroborationStatus::Corroborated {
            contributing_sensors,
            contributing_generations,
        } => {
            encoder.u8(2);
            encoder.u64(contributing_sensors.len() as u64);
            for s in contributing_sensors {
                s.encode_canonical(encoder);
            }
            encoder.u64(contributing_generations.len() as u64);
            for g in contributing_generations {
                encoder.text(g);
            }
        }
    }
}

/// Explicit typed outcome of a mock model execution.
///
/// In FSS, model failures, crashes, and timeouts are explicit typed outcomes;
/// execution NEVER defaults to "no detection" or zero probability.
#[derive(Clone, Debug, PartialEq)]
pub enum MockExecutorOutcome {
    /// Normal successful model inference output.
    Success(Box<MockModelOutput>),
    /// Model process or runtime crashed.
    Crashed {
        /// Diagnostic reason for the crash.
        reason: String,
    },
    /// Model exceeded virtual time budget.
    TimedOut {
        /// Virtual timeout limit configured.
        virtual_timeout_ns: u64,
        /// Virtual elapsed time before termination.
        virtual_elapsed_ns: u64,
    },
    /// Model emitted malformed output bytes or invalid numerical bounds.
    MalformedOutput {
        /// Diagnostic detail.
        detail: String,
    },
}

impl MockExecutorOutcome {
    /// Returns true if the outcome was successful.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns the output if successful, or a typed fault error.
    ///
    /// Execution faults never default to `None` or "no detection" (NEG-003 / INV-056).
    pub fn output(&self) -> Result<&MockModelOutput, MockModelError> {
        match self {
            Self::Success(out) => Ok(out.as_ref()),
            Self::Crashed { reason } => Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                outcome: format!("MockExecutorOutcome::Crashed({reason})"),
            }),
            Self::TimedOut {
                virtual_timeout_ns,
                virtual_elapsed_ns,
            } => Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                outcome: format!(
                    "MockExecutorOutcome::TimedOut({virtual_elapsed_ns}/{virtual_timeout_ns}ns)"
                ),
            }),
            Self::MalformedOutput { detail } => {
                Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                    outcome: format!("MockExecutorOutcome::MalformedOutput({detail})"),
                })
            }
        }
    }

    /// Validates that this executor outcome is not being treated as negative evidence.
    ///
    /// Crashes, timeouts, malformed outputs, and empty detections are failures/gaps,
    /// NEVER negative evidence of absence (NEG-003).
    pub fn assert_not_negative_evidence(&self) -> Result<(), MockModelError> {
        match self {
            Self::Crashed { reason } => Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                outcome: format!("MockExecutorOutcome::Crashed({reason})"),
            }),
            Self::TimedOut {
                virtual_timeout_ns,
                virtual_elapsed_ns,
            } => Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                outcome: format!(
                    "MockExecutorOutcome::TimedOut({virtual_elapsed_ns}/{virtual_timeout_ns}ns)"
                ),
            }),
            Self::MalformedOutput { detail } => {
                Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                    outcome: format!("MockExecutorOutcome::MalformedOutput({detail})"),
                })
            }
            Self::Success(output) => {
                if output.detections.is_empty() {
                    Err(MockModelError::AbstentionCannotBeNegativeEvidence {
                        outcome: "MockExecutorOutcome::Success(empty_detections)".to_string(),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Fault injection schedule for mock model execution.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MockModelFaultSchedule {
    /// Injected crash faults keyed by input content digest.
    pub crashes: BTreeMap<ContentDigest, String>,
    /// Injected virtual timeouts keyed by input content digest.
    pub timeouts: BTreeMap<ContentDigest, u64>,
    /// Injected malformed outputs keyed by input content digest.
    pub malformed_outputs: BTreeMap<ContentDigest, String>,
}

impl MockModelFaultSchedule {
    /// Creates an empty fault schedule.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects a crash fault for a specific input digest.
    pub fn inject_crash(
        &mut self,
        digest: ContentDigest,
        reason: impl Into<String>,
    ) -> Result<(), MockModelError> {
        let reason = reason.into();
        if reason.len() > MAX_FAULT_REASON_LEN {
            return Err(MockModelError::FaultReasonTooLong {
                actual: reason.len(),
                max: MAX_FAULT_REASON_LEN,
            });
        }
        self.crashes.insert(digest, reason);
        Ok(())
    }

    /// Injects a virtual timeout fault for a specific input digest.
    pub fn inject_timeout(&mut self, digest: ContentDigest, elapsed_ns: u64) {
        self.timeouts.insert(digest, elapsed_ns);
    }

    /// Injects a malformed output fault for a specific input digest.
    pub fn inject_malformed_output(
        &mut self,
        digest: ContentDigest,
        detail: impl Into<String>,
    ) -> Result<(), MockModelError> {
        let detail = detail.into();
        if detail.len() > MAX_FAULT_REASON_LEN {
            return Err(MockModelError::FaultReasonTooLong {
                actual: detail.len(),
                max: MAX_FAULT_REASON_LEN,
            });
        }
        self.malformed_outputs.insert(digest, detail);
        Ok(())
    }
}

/// Deterministic mock model executor.
///
/// Consumes sensor capsules, raw frames, or reference captures, emitting bit-identical
/// model outputs deterministically from `(seed, model_generation, input_digest)`.
#[derive(Clone, Debug, PartialEq)]
pub struct MockModelExecutor {
    generation: ModelGeneration,
    prior_generation: Option<ModelGeneration>,
    seed: u64,
    nominal_latency_ns: u64,
    virtual_timeout_ns: u64,
    fault_schedule: MockModelFaultSchedule,
}

impl MockModelExecutor {
    /// Constructs a new mock model executor with default 10ms nominal latency and 50ms timeout.
    pub fn new(generation: ModelGeneration, seed: u64) -> Result<Self, MockModelError> {
        Self::with_latency_and_timeout(generation, seed, 10_000_000, 50_000_000)
    }

    /// Constructs a mock model executor with explicit nominal latency and virtual timeout.
    pub fn with_latency_and_timeout(
        generation: ModelGeneration,
        seed: u64,
        nominal_latency_ns: u64,
        virtual_timeout_ns: u64,
    ) -> Result<Self, MockModelError> {
        if is_latest_generation(generation.as_str()) {
            return Err(MockModelError::LatestGenerationProhibited {
                generation: generation.into_inner(),
            });
        }
        Ok(Self {
            generation,
            prior_generation: None,
            seed,
            nominal_latency_ns,
            virtual_timeout_ns,
            fault_schedule: MockModelFaultSchedule::new(),
        })
    }

    /// Configures an explicit fault schedule.
    #[must_use]
    pub fn with_fault_schedule(mut self, schedule: MockModelFaultSchedule) -> Self {
        self.fault_schedule = schedule;
        self
    }

    /// Returns the active model generation.
    #[must_use]
    pub const fn generation(&self) -> &ModelGeneration {
        &self.generation
    }

    /// Atomically activates a new model generation, retaining the prior generation for rollback (ADR-0004).
    pub fn activate_generation(
        &mut self,
        new_generation: ModelGeneration,
    ) -> Result<(), MockModelError> {
        if is_latest_generation(new_generation.as_str()) {
            return Err(MockModelError::LatestGenerationProhibited {
                generation: new_generation.into_inner(),
            });
        }
        if new_generation == self.generation {
            return Ok(());
        }
        self.prior_generation = Some(self.generation.clone());
        self.generation = new_generation;
        Ok(())
    }

    /// Rolls back to the retained prior generation (ADR-0004).
    pub fn rollback_generation(&mut self) -> Result<ModelGeneration, MockModelError> {
        let prior = self
            .prior_generation
            .take()
            .ok_or(MockModelError::NoPriorGenerationForRollback)?;
        let rolled_back_from = std::mem::replace(&mut self.generation, prior);
        Ok(rolled_back_from)
    }

    /// Returns the currently active model generation.
    #[must_use]
    pub fn current_generation(&self) -> &ModelGeneration {
        &self.generation
    }

    /// Returns the prior generation retained for rollback, if any.
    #[must_use]
    pub fn prior_generation(&self) -> Option<&ModelGeneration> {
        self.prior_generation.as_ref()
    }

    /// Executes inference over a raw frame payload using the explicit virtual clock authority.
    pub fn execute_frame(
        &self,
        frame_bytes: &[u8],
        sensor_id: &SensorId,
        capture_interval: &CaptureInterval,
        clock: &mut VirtualClock,
    ) -> Result<MockExecutorOutcome, MockModelError> {
        if frame_bytes.len() > MAX_INPUT_PAYLOAD_BYTES {
            return Err(MockModelError::InputPayloadTooLarge {
                actual: frame_bytes.len(),
                max: MAX_INPUT_PAYLOAD_BYTES,
            });
        }
        let input_digest = ContentDigest::sha256(frame_bytes);
        self.execute_internal(input_digest, sensor_id, capture_interval, clock)
    }

    /// Executes inference over a canonical SensorCapsuleV1 using the explicit virtual clock authority.
    pub fn execute_capsule(
        &self,
        capsule: &SensorCapsuleV1,
        clock: &mut VirtualClock,
    ) -> Result<MockExecutorOutcome, MockModelError> {
        capsule
            .verify()
            .map_err(|e| MockModelError::InvalidCapsule(format!("{e:?}")))?;
        if let Some(ref dev_gen) = capsule.device_identity.model_generation
            && dev_gen != &self.generation
        {
            return Err(MockModelError::CrossGenerationScoreMixing {
                expected: self.generation.clone(),
                actual: dev_gen.clone(),
            });
        }
        let input_digest = capsule.integrity.metadata_digest;
        self.execute_internal(
            input_digest,
            &capsule.sensor_id,
            &capsule.capture_interval,
            clock,
        )
    }

    /// Executes inference over a complete ReferenceCapture using the explicit virtual clock authority.
    pub fn execute_capture(
        &self,
        capture: &ReferenceCapture,
        clock: &mut VirtualClock,
    ) -> Result<MockExecutorOutcome, MockModelError> {
        let first_packet = capture.source_packets.first().ok_or_else(|| {
            MockModelError::Reference("capture has no source packets".to_string())
        })?;
        let last_packet = capture.source_packets.last().ok_or_else(|| {
            MockModelError::Reference("capture has no source packets".to_string())
        })?;
        let interval =
            CaptureInterval::new(first_packet.capture.earliest, last_packet.capture.latest)
                .map_err(|e| MockModelError::Reference(format!("{e:?}")))?;
        let input_digest = capture.receipt.capture_root;
        self.execute_internal(input_digest, &first_packet.sensor_id, &interval, clock)
    }

    fn execute_internal(
        &self,
        input_digest: ContentDigest,
        sensor_id: &SensorId,
        capture_interval: &CaptureInterval,
        clock: &mut VirtualClock,
    ) -> Result<MockExecutorOutcome, MockModelError> {
        // 1. Check crash fault
        if let Some(reason) = self.fault_schedule.crashes.get(&input_digest) {
            return Ok(MockExecutorOutcome::Crashed {
                reason: reason.clone(),
            });
        }

        // 2. Check injected timeout fault
        if let Some(&timeout_ns) = self.fault_schedule.timeouts.get(&input_digest) {
            clock
                .advance(timeout_ns)
                .map_err(|e| MockModelError::ClockError(format!("{e:?}")))?;
            return Ok(MockExecutorOutcome::TimedOut {
                virtual_timeout_ns: self.virtual_timeout_ns,
                virtual_elapsed_ns: timeout_ns,
            });
        }

        // 3. Check nominal latency exceeding virtual timeout
        if self.nominal_latency_ns > self.virtual_timeout_ns {
            clock
                .advance(self.virtual_timeout_ns)
                .map_err(|e| MockModelError::ClockError(format!("{e:?}")))?;
            return Ok(MockExecutorOutcome::TimedOut {
                virtual_timeout_ns: self.virtual_timeout_ns,
                virtual_elapsed_ns: self.nominal_latency_ns,
            });
        }

        // 4. Check malformed output fault
        if let Some(detail) = self.fault_schedule.malformed_outputs.get(&input_digest) {
            return Ok(MockExecutorOutcome::MalformedOutput {
                detail: detail.clone(),
            });
        }

        // 5. Advance clock by nominal virtual latency
        clock
            .advance(self.nominal_latency_ns)
            .map_err(|e| MockModelError::ClockError(format!("{e:?}")))?;

        // 6. Deterministic PRNG seeded from (seed, generation, input_digest)
        let gen_digest = ContentDigest::sha256(self.generation.as_str().as_bytes());
        let mut prng_state = self.seed
            ^ read_u64_le(&gen_digest.bytes()[..8])
            ^ read_u64_le(&input_digest.bytes()[..8])
            ^ 0x9e37_79b9_7f4a_7c15_u64;
        if prng_state == 0 {
            prng_state = 0xd1b5_4a32_d192_ed03_u64;
        }

        let mut next_u64 = || {
            prng_state ^= prng_state >> 12;
            prng_state ^= prng_state << 25;
            prng_state ^= prng_state >> 27;
            prng_state.wrapping_mul(0x2545_f491_4f6c_dd1d_u64)
        };

        // Generate 1 to 3 deterministic detections
        let num_detections = ((next_u64() % 3) + 1) as usize;
        let mut detections = Vec::with_capacity(num_detections);

        for _ in 0..num_detections {
            let label = match next_u64() % 4 {
                0 => MockSemanticLabel::PersonLike,
                1 => MockSemanticLabel::AnimalLike,
                2 => MockSemanticLabel::TamperLike,
                _ => MockSemanticLabel::Unknown,
            };

            let prob_raw = (next_u64() % 4000) as f64 / 10000.0; // 0.0 .. 0.4
            let low = 0.50 + prob_raw; // 0.50 .. 0.90
            let high = (low + 0.05).min(0.99); // 0.55 .. 0.95
            let probability = ProbabilityInterval::new(low, high)
                .map_err(MockModelError::InvalidProbabilityScore)?;

            let x1 = (next_u64() % 400) as f64 / 1000.0;
            let y1 = (next_u64() % 400) as f64 / 1000.0;
            let w = ((next_u64() % 400) + 100) as f64 / 1000.0;
            let h = ((next_u64() % 400) + 100) as f64 / 1000.0;
            let x2 = (x1 + w).min(1.0);
            let y2 = (y1 + h).min(1.0);
            let bounding_box = [x1, y1, x2, y2];

            detections.push(MockDetection::new(label, probability, bounding_box)?);
        }

        let corroboration = CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_id.clone(),
            model_generation: self.generation.as_str().to_string(),
        };

        let digest_req = MockOutputDigestRequest {
            generation: &self.generation,
            sensor_id,
            input_digest: &input_digest,
            capture_interval,
            knowledge_state: KnowledgeState::Estimated,
            provenance_class: ProvenanceClass::Predicted,
            corroboration: &corroboration,
            detections: &detections,
            virtual_latency_ns: self.nominal_latency_ns,
        };
        let output_digest = compute_output_digest(&digest_req)?;

        let output = MockModelOutput {
            output_digest,
            generation: self.generation.clone(),
            sensor_id: sensor_id.clone(),
            input_digest,
            capture_interval: *capture_interval,
            knowledge_state: KnowledgeState::Estimated,
            provenance_class: ProvenanceClass::Predicted,
            detections,
            corroboration,
            virtual_latency_ns: self.nominal_latency_ns,
        };

        Ok(MockExecutorOutcome::Success(Box::new(output)))
    }
}

fn read_u64_le(slice: &[u8]) -> u64 {
    let mut buf = [0_u8; 8];
    let len = slice.len().min(8);
    buf[..len].copy_from_slice(&slice[..len]);
    u64::from_le_bytes(buf)
}

/// Request parameters for computing a deterministic mock model output digest with full provenance.
#[derive(Clone, Debug)]
pub struct MockOutputDigestRequest<'a> {
    /// Immutable model generation identity.
    pub generation: &'a ModelGeneration,
    /// Sensor identity from which the input was captured.
    pub sensor_id: &'a SensorId,
    /// Exact content digest of the consumed input.
    pub input_digest: &'a ContentDigest,
    /// Temporal capture interval of the input.
    pub capture_interval: &'a CaptureInterval,
    /// Epistemic knowledge state.
    pub knowledge_state: KnowledgeState,
    /// Provenance class.
    pub provenance_class: ProvenanceClass,
    /// Explicit corroboration status.
    pub corroboration: &'a CorroborationStatus,
    /// Bounded list of deterministic detections.
    pub detections: &'a [MockDetection],
    /// Virtual inference latency consumed.
    pub virtual_latency_ns: u64,
}

impl<'a> From<&'a MockModelOutput> for MockOutputDigestRequest<'a> {
    fn from(out: &'a MockModelOutput) -> Self {
        Self {
            generation: &out.generation,
            sensor_id: &out.sensor_id,
            input_digest: &out.input_digest,
            capture_interval: &out.capture_interval,
            knowledge_state: out.knowledge_state,
            provenance_class: out.provenance_class,
            corroboration: &out.corroboration,
            detections: &out.detections,
            virtual_latency_ns: out.virtual_latency_ns,
        }
    }
}

/// Computes deterministic output digest with full provenance and bound checking.
pub fn compute_output_digest(
    req: &MockOutputDigestRequest<'_>,
) -> Result<ContentDigest, MockModelError> {
    if req.detections.len() > MAX_DETECTIONS_PER_OUTPUT {
        return Err(MockModelError::TooManyDetections {
            actual: req.detections.len(),
            max: MAX_DETECTIONS_PER_OUTPUT,
        });
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.mock_model_output.v1");
    encoder.text(req.generation.as_str());
    req.sensor_id.encode_canonical(&mut encoder);
    encoder.digest(*req.input_digest);
    req.capture_interval.encode_canonical(&mut encoder);
    encoder.text(req.knowledge_state.as_str());
    encoder.text(provenance_class_str(req.provenance_class));
    encode_corroboration_status(req.corroboration, &mut encoder);
    encoder.u64(req.detections.len() as u64);
    for det in req.detections {
        det.validate()?;
        encoder.u8(det.label.tag());
        det.probability.encode_canonical(&mut encoder);
        for &coord in &det.bounding_box {
            let bp = encode_coord_to_basis_point(coord)?;
            encoder.u64(bp);
        }
    }
    encoder.u64(req.virtual_latency_ns);
    Ok(ContentDigest::sha256(&encoder.finish()))
}

/// Compares detection scores between two models, enforcing generation compatibility.
///
/// Under AGENTS.md, mixing scores across different model generations is strictly prohibited.
pub fn compare_model_scores(
    score_a: &MockDetection,
    generation_a: &ModelGeneration,
    score_b: &MockDetection,
    generation_b: &ModelGeneration,
) -> Result<std::cmp::Ordering, MockModelError> {
    if generation_a != generation_b {
        return Err(MockModelError::CrossGenerationScoreMixing {
            expected: generation_a.clone(),
            actual: generation_b.clone(),
        });
    }
    let mid_a = (score_a.probability.lower + score_a.probability.upper) / 2.0;
    let mid_b = (score_b.probability.lower + score_b.probability.upper) / 2.0;
    mid_a
        .partial_cmp(&mid_b)
        .ok_or(MockModelError::InvalidProbabilityScore(
            ContractError::InvalidProbabilityInterval,
        ))
}

/// Fuses two detection scores from the same model generation.
///
/// Under AGENTS.md, INV-013, and ADR-0004, mixing scores across different model generations
/// is strictly prohibited and returns [`MockModelError::CrossGenerationScoreMixing`].
pub fn fuse_model_scores(
    score_a: &MockDetection,
    generation_a: &ModelGeneration,
    score_b: &MockDetection,
    generation_b: &ModelGeneration,
) -> Result<ProbabilityInterval, MockModelError> {
    if generation_a != generation_b {
        return Err(MockModelError::CrossGenerationScoreMixing {
            expected: generation_a.clone(),
            actual: generation_b.clone(),
        });
    }
    if score_a.probability.calibration_generation != score_b.probability.calibration_generation {
        return Err(MockModelError::CrossCalibrationScoreMixing {
            expected: score_a.probability.calibration_generation,
            actual: score_b.probability.calibration_generation,
        });
    }
    let fused_lower = score_a.probability.lower.max(score_b.probability.lower);
    let fused_upper = score_a.probability.upper.min(score_b.probability.upper);
    if fused_lower > fused_upper {
        let lower_micro = (fused_lower * 1_000_000.0).round() as u64;
        let upper_micro = (fused_upper * 1_000_000.0).round() as u64;
        return Err(MockModelError::ContradictoryProbabilityIntervals {
            lower_micro,
            upper_micro,
        });
    }
    match score_a.probability.calibration_generation {
        Some(calib) => ProbabilityInterval::with_calibration(fused_lower, fused_upper, calib)
            .map_err(MockModelError::InvalidProbabilityScore),
        None => ProbabilityInterval::new(fused_lower, fused_upper)
            .map_err(MockModelError::InvalidProbabilityScore),
    }
}

/// Bounded deterministic model embedding carrying an immutable generation identity (INV-013).
#[derive(Clone, Debug, PartialEq)]
pub struct MockEmbedding {
    /// Immutable model generation that produced this embedding.
    pub generation: ModelGeneration,
    /// Vector dimensions.
    pub vector: Vec<f64>,
}

impl MockEmbedding {
    /// Constructs a new mock embedding bound to a specific immutable model generation.
    pub fn new(generation: ModelGeneration, vector: Vec<f64>) -> Result<Self, MockModelError> {
        if is_latest_generation(generation.as_str()) {
            return Err(MockModelError::LatestGenerationProhibited {
                generation: generation.into_inner(),
            });
        }
        if vector.is_empty() {
            return Err(MockModelError::EmptyEmbeddingVector);
        }
        if vector.len() > MAX_EMBEDDING_DIM {
            return Err(MockModelError::EmbeddingDimensionTooLarge {
                actual: vector.len(),
                max: MAX_EMBEDDING_DIM,
            });
        }
        let mut norm_sq = 0.0_f64;
        for &val in &vector {
            if !val.is_finite() {
                return Err(MockModelError::InvalidEmbeddingNorm);
            }
            norm_sq += val * val;
        }
        if norm_sq <= 0.0 || !norm_sq.is_finite() {
            return Err(MockModelError::InvalidEmbeddingNorm);
        }
        Ok(Self { generation, vector })
    }

    /// Returns the embedding dimension.
    #[must_use]
    pub fn dim(&self) -> usize {
        self.vector.len()
    }
}

/// Compares two model embeddings using cosine similarity, strictly enforcing generation compatibility.
///
/// Under AGENTS.md, INV-013, and ADR-0004, embeddings from different model generations cannot
/// share a metric space or be compared without an explicit qualified cross-generation transform.
pub fn compare_model_embeddings(
    a: &MockEmbedding,
    b: &MockEmbedding,
) -> Result<f64, MockModelError> {
    if a.generation != b.generation {
        return Err(MockModelError::CrossGenerationEmbeddingMixing {
            expected: a.generation.clone(),
            actual: b.generation.clone(),
        });
    }
    if a.vector.len() != b.vector.len() {
        return Err(MockModelError::EmbeddingDimensionMismatch {
            expected: a.vector.len(),
            actual: b.vector.len(),
        });
    }
    let mut dot = 0.0_f64;
    let mut norm_a_sq = 0.0_f64;
    let mut norm_b_sq = 0.0_f64;
    for (va, vb) in a.vector.iter().zip(b.vector.iter()) {
        dot += va * vb;
        norm_a_sq += va * va;
        norm_b_sq += vb * vb;
    }
    if norm_a_sq <= 0.0 || norm_b_sq <= 0.0 || !dot.is_finite() {
        return Err(MockModelError::InvalidEmbeddingNorm);
    }
    let cos = dot / (norm_a_sq.sqrt() * norm_b_sq.sqrt());
    Ok(cos.clamp(-1.0, 1.0))
}

/// Fuses two model embeddings from the same model generation via normalized mean.
///
/// Under AGENTS.md, INV-013, and ADR-0004, fusing embeddings from different model generations
/// is strictly prohibited.
pub fn fuse_model_embeddings(
    a: &MockEmbedding,
    b: &MockEmbedding,
) -> Result<MockEmbedding, MockModelError> {
    if a.generation != b.generation {
        return Err(MockModelError::CrossGenerationEmbeddingMixing {
            expected: a.generation.clone(),
            actual: b.generation.clone(),
        });
    }
    if a.vector.len() != b.vector.len() {
        return Err(MockModelError::EmbeddingDimensionMismatch {
            expected: a.vector.len(),
            actual: b.vector.len(),
        });
    }
    let mut fused = Vec::with_capacity(a.vector.len());
    let mut norm_sq = 0.0_f64;
    for (va, vb) in a.vector.iter().zip(b.vector.iter()) {
        let val = (va + vb) / 2.0;
        norm_sq += val * val;
        fused.push(val);
    }
    if norm_sq <= 0.0 || !norm_sq.is_finite() {
        return Err(MockModelError::InvalidEmbeddingNorm);
    }
    let norm = norm_sq.sqrt();
    for v in &mut fused {
        *v /= norm;
    }
    Ok(MockEmbedding {
        generation: a.generation.clone(),
        vector: fused,
    })
}

/// A multi-camera corroborated model finding.
#[derive(Clone, Debug, PartialEq)]
pub struct CorroboratedModelFinding {
    /// Common semantic label agreed upon.
    pub label: MockSemanticLabel,
    /// Immutable model generation that produced the corroborated finding.
    pub generation: ModelGeneration,
    /// Contributing distinct sensor identities.
    pub contributing_sensors: Vec<SensorId>,
    /// Input digests from contributing sensors.
    pub contributing_input_digests: Vec<ContentDigest>,
    /// Fused conservative probability interval.
    pub fused_probability: ProbabilityInterval,
    /// Spatial bounding box intersection of corroborated detections.
    pub bounding_box: [f64; 4],
    /// Corroboration status witness.
    pub corroboration: CorroborationStatus,
}

/// Evaluates corroboration across multiple model outputs.
///
/// Enforces:
/// 1. Minimum 2 sources required.
/// 2. Bounded by [`MAX_CORROBORATION_SOURCES`].
/// 3. Model generations must match (cross-generation mixing prohibited).
/// 4. Detections count bounded by [`MAX_DETECTIONS_PER_OUTPUT`].
/// 5. Contributing sensors must be distinct and actually observe the candidate label.
/// 6. Spatial bounding boxes must overlap; disjoint bounding boxes fail closed.
/// 7. Calibration generations must match and be preserved in the fused probability.
/// 8. Contradictory disjoint intervals are rejected with typed errors, never silently clamped.
pub fn evaluate_corroboration(
    outputs: &[MockModelOutput],
) -> Result<CorroboratedModelFinding, MockModelError> {
    if outputs.len() < 2 {
        return Err(MockModelError::InsufficientSourcesForCorroboration {
            count: outputs.len(),
            min_required: 2,
        });
    }
    if outputs.len() > MAX_CORROBORATION_SOURCES {
        return Err(MockModelError::TooManyCorroborationSources {
            actual: outputs.len(),
            max: MAX_CORROBORATION_SOURCES,
        });
    }

    let first = &outputs[0];
    for out in outputs.iter().skip(1) {
        if out.generation != first.generation {
            return Err(MockModelError::CrossGenerationScoreMixing {
                expected: first.generation.clone(),
                actual: out.generation.clone(),
            });
        }
    }

    for out in outputs {
        if out.detections.len() > MAX_DETECTIONS_PER_OUTPUT {
            return Err(MockModelError::TooManyDetections {
                actual: out.detections.len(),
                max: MAX_DETECTIONS_PER_OUTPUT,
            });
        }
    }

    let mut candidate_labels = Vec::new();
    for out in outputs {
        for det in &out.detections {
            if !candidate_labels.contains(&det.label) {
                candidate_labels.push(det.label);
            }
        }
    }
    if candidate_labels.is_empty() {
        return Err(MockModelError::NoDetectionsToCorroborate);
    }
    candidate_labels.sort_by_key(|lbl| match lbl {
        MockSemanticLabel::PersonLike => 0,
        MockSemanticLabel::AnimalLike => 1,
        MockSemanticLabel::TamperLike => 2,
        MockSemanticLabel::Unknown => 3,
    });

    let mut last_disjoint_spatial = None;
    let mut last_single_sensor = None;

    for candidate_label in candidate_labels {
        let mut matching_sensors = BTreeSet::new();
        let mut contributing_input_digests = Vec::new();
        let mut contributing_outputs = Vec::new();
        let mut fused_lower = 0.0_f64;
        let mut fused_upper = 1.0_f64;
        let mut expected_calibration: Option<Option<ContentDigest>> = None;
        let mut bbox_intersection: Option<[f64; 4]> = None;
        let mut calibration_error = None;
        let mut spatial_disjoint = false;

        for out in outputs {
            if let Some(det) = out.detections.iter().find(|d| d.label == candidate_label) {
                for &coord in &det.bounding_box {
                    if !coord.is_finite() {
                        return Err(MockModelError::InvalidCoordinate);
                    }
                }

                if matching_sensors.insert(out.sensor_id.clone()) {
                    contributing_input_digests.push(out.input_digest);
                    contributing_outputs.push(out);
                    fused_lower = fused_lower.max(det.probability.lower);
                    fused_upper = fused_upper.min(det.probability.upper);

                    match expected_calibration {
                        None => {
                            expected_calibration = Some(det.probability.calibration_generation);
                        }
                        Some(expected) => {
                            if det.probability.calibration_generation != expected {
                                calibration_error =
                                    Some(MockModelError::CrossCalibrationScoreMixing {
                                        expected,
                                        actual: det.probability.calibration_generation,
                                    });
                                break;
                            }
                        }
                    }

                    match bbox_intersection {
                        None => {
                            MockDetection::validate_bounding_box(&det.bounding_box)?;
                            bbox_intersection = Some(det.bounding_box);
                        }
                        Some(current_box) => {
                            match compute_bounding_box_intersection(&current_box, &det.bounding_box)
                            {
                                Ok(intersection) => {
                                    bbox_intersection = Some(intersection);
                                }
                                Err(MockModelError::DisjointBoundingBoxes { .. }) => {
                                    spatial_disjoint = true;
                                    break;
                                }
                                Err(err) => return Err(err),
                            }
                        }
                    }
                }
            }
        }

        if let Some(err) = calibration_error {
            return Err(err);
        }

        if spatial_disjoint {
            last_disjoint_spatial = Some(candidate_label);
            continue;
        }

        if matching_sensors.len() < 2 {
            if matching_sensors.len() == 1
                && let Some(sensor_id) = matching_sensors.into_iter().next()
            {
                last_single_sensor = Some(sensor_id);
            }
            continue;
        }

        if fused_lower > fused_upper {
            let lower_micro = (fused_lower * 1_000_000.0).round() as u64;
            let upper_micro = (fused_upper * 1_000_000.0).round() as u64;
            return Err(MockModelError::ContradictoryProbabilityIntervals {
                lower_micro,
                upper_micro,
            });
        }

        let calib_opt = expected_calibration.flatten();
        let fused_probability = match calib_opt {
            Some(calib) => ProbabilityInterval::with_calibration(fused_lower, fused_upper, calib)
                .map_err(MockModelError::InvalidProbabilityScore)?,
            None => ProbabilityInterval::new(fused_lower, fused_upper)
                .map_err(MockModelError::InvalidProbabilityScore)?,
        };

        let bounding_box =
            bbox_intersection.ok_or(MockModelError::DisjointSpatialCorroboration {
                label: candidate_label,
            })?;

        let mut contributing_gens = BTreeSet::new();
        for out in contributing_outputs {
            contributing_gens.insert(out.generation.as_str().to_string());
            match &out.corroboration {
                CorroborationStatus::UncorroboratedSingleSource {
                    model_generation, ..
                } => {
                    contributing_gens.insert(model_generation.clone());
                }
                CorroborationStatus::Corroborated {
                    contributing_generations,
                    ..
                } => {
                    for g in contributing_generations {
                        contributing_gens.insert(g.clone());
                    }
                }
            }
        }
        let contributing_generations: Vec<String> = contributing_gens.into_iter().collect();
        let contributing_sensors: Vec<SensorId> = matching_sensors.into_iter().collect();

        return Ok(CorroboratedModelFinding {
            label: candidate_label,
            generation: first.generation.clone(),
            contributing_sensors: contributing_sensors.clone(),
            contributing_input_digests,
            fused_probability,
            bounding_box,
            corroboration: CorroborationStatus::Corroborated {
                contributing_sensors,
                contributing_generations,
            },
        });
    }

    if let Some(label) = last_disjoint_spatial {
        return Err(MockModelError::DisjointSpatialCorroboration { label });
    }
    if let Some(sensor_id) = last_single_sensor {
        return Err(MockModelError::UncorroboratedSingleSensor { sensor_id });
    }
    Err(MockModelError::InsufficientSourcesForCorroboration {
        count: 0,
        min_required: 2,
    })
}

/// Errors returned by the mock model subsystem.
#[derive(Clone, Debug, PartialEq)]
pub enum MockModelError {
    /// Model generation identifier is empty.
    EmptyGenerationId,
    /// Model generation identifier exceeds maximum declared bound.
    GenerationIdTooLong {
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Input payload exceeds maximum allowed size.
    InputPayloadTooLarge {
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Injected fault reason or detail exceeds maximum allowed length.
    FaultReasonTooLong {
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Prohibited attempt to mix or compare scores across different model generations.
    CrossGenerationScoreMixing {
        /// Expected model generation.
        expected: ModelGeneration,
        /// Actual incompatible model generation.
        actual: ModelGeneration,
    },
    /// Attempt to mix scores calibrated under different calibration generations (ADR-0004).
    CrossCalibrationScoreMixing {
        /// Expected calibration generation digest.
        expected: Option<ContentDigest>,
        /// Actual incompatible calibration generation digest.
        actual: Option<ContentDigest>,
    },
    /// Insufficient sources to evaluate corroboration (minimum 2 required).
    InsufficientSourcesForCorroboration {
        /// Observed source count.
        count: usize,
        /// Minimum required count.
        min_required: usize,
    },
    /// Single camera or sensor cannot corroborate itself.
    UncorroboratedSingleSensor {
        /// Sensor identity of the single source.
        sensor_id: SensorId,
    },
    /// Corroboration sources exceed maximum bound.
    TooManyCorroborationSources {
        /// Observed source count.
        actual: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Detections list exceeds maximum declared bound.
    TooManyDetections {
        /// Actual count observed.
        actual: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Model output contains no detections to corroborate.
    NoDetectionsToCorroborate,
    /// Contradictory disjoint probability intervals between corroborating sources.
    ContradictoryProbabilityIntervals {
        /// Fused lower bound in micro-units.
        lower_micro: u64,
        /// Fused upper bound in micro-units.
        upper_micro: u64,
    },
    /// The sensor capsule is invalid.
    InvalidCapsule(String),
    /// Invalid probability score, preserving inner contract error.
    InvalidProbabilityScore(ContractError),
    /// Bounding box coordinate is non-finite (NaN or Inf).
    InvalidCoordinate,
    /// Bounding box coordinate is outside normalized range [0.0, 1.0].
    CoordinateOutOfRange {
        /// The invalid coordinate value.
        coord: f64,
    },
    /// Bounding box is inverted (x1 > x2 or y1 > y2).
    InvertedBoundingBox {
        /// The inverted bounding box.
        bounding_box: [f64; 4],
    },
    /// Bounding boxes do not intersect.
    DisjointBoundingBoxes {
        /// First bounding box.
        box_a: [f64; 4],
        /// Second bounding box.
        box_b: [f64; 4],
    },
    /// Spatial bounding boxes do not intersect across corroborating sensors.
    DisjointSpatialCorroboration {
        /// The candidate semantic label whose bounding boxes did not intersect.
        label: MockSemanticLabel,
    },
    /// Error from virtual clock authority.
    ClockError(String),
    /// Reference error.
    Reference(String),
    /// Attempt to use a mutable "latest" generation alias, strictly forbidden by ADR-0004 and AGENTS.md.
    LatestGenerationProhibited {
        /// The rejected generation identifier.
        generation: String,
    },
    /// No prior model generation retained for rollback.
    NoPriorGenerationForRollback,
    /// Prohibited attempt to mix or compare embeddings across different model generations (INV-013).
    CrossGenerationEmbeddingMixing {
        /// Expected model generation.
        expected: ModelGeneration,
        /// Actual incompatible model generation.
        actual: ModelGeneration,
    },
    /// Embedding vector dimension mismatch between compared or fused embeddings.
    EmbeddingDimensionMismatch {
        /// Expected dimension.
        expected: usize,
        /// Actual observed dimension.
        actual: usize,
    },
    /// Embedding vector is empty.
    EmptyEmbeddingVector,
    /// Embedding vector dimension exceeds declared maximum bound.
    EmbeddingDimensionTooLarge {
        /// Actual dimension observed.
        actual: usize,
        /// Maximum allowed dimension.
        max: usize,
    },
    /// Embedding vector has invalid norm (zero or non-finite).
    InvalidEmbeddingNorm,
    /// Prohibited attempt to use model abstention or failure as negative evidence (NEG-003, INV-056).
    AbstentionCannotBeNegativeEvidence {
        /// Rejected outcome detail.
        outcome: String,
    },
}

impl fmt::Display for MockModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGenerationId => write!(f, "model generation identifier is empty"),
            Self::GenerationIdTooLong { actual, max } => {
                write!(
                    f,
                    "model generation identifier length {actual} exceeds bound {max}"
                )
            }
            Self::InputPayloadTooLarge { actual, max } => {
                write!(f, "input payload length {actual} exceeds bound {max}")
            }
            Self::FaultReasonTooLong { actual, max } => {
                write!(f, "fault reason length {actual} exceeds bound {max}")
            }
            Self::CrossGenerationScoreMixing { expected, actual } => {
                write!(
                    f,
                    "prohibited cross-generation score mixing: expected {expected}, got {actual}"
                )
            }
            Self::CrossCalibrationScoreMixing { expected, actual } => {
                write!(
                    f,
                    "prohibited cross-calibration score mixing: expected {expected:?}, got {actual:?}"
                )
            }
            Self::InsufficientSourcesForCorroboration {
                count,
                min_required,
            } => {
                write!(
                    f,
                    "insufficient sources for corroboration: got {count}, min {min_required}"
                )
            }
            Self::UncorroboratedSingleSensor { sensor_id } => {
                write!(f, "single sensor {sensor_id} cannot corroborate itself")
            }
            Self::TooManyCorroborationSources { actual, max } => {
                write!(f, "corroboration source count {actual} exceeds bound {max}")
            }
            Self::TooManyDetections { actual, max } => {
                write!(f, "detection count {actual} exceeds bound {max}")
            }
            Self::NoDetectionsToCorroborate => {
                write!(f, "no detections available to evaluate corroboration")
            }
            Self::ContradictoryProbabilityIntervals {
                lower_micro,
                upper_micro,
            } => {
                write!(
                    f,
                    "contradictory disjoint probability intervals: lower {lower_micro} upx > upper {upper_micro} upx"
                )
            }
            Self::InvalidCapsule(reason) => write!(f, "invalid sensor capsule: {reason}"),
            Self::InvalidProbabilityScore(err) => write!(f, "invalid probability score: {err}"),
            Self::InvalidCoordinate => {
                write!(f, "bounding box coordinate is non-finite (NaN or Inf)")
            }
            Self::CoordinateOutOfRange { coord } => {
                write!(
                    f,
                    "bounding box coordinate {coord} is outside normalized range [0.0, 1.0]"
                )
            }
            Self::InvertedBoundingBox { bounding_box } => {
                write!(f, "bounding box is inverted: {bounding_box:?}")
            }
            Self::DisjointBoundingBoxes { box_a, box_b } => {
                write!(f, "bounding boxes {box_a:?} and {box_b:?} do not intersect")
            }
            Self::DisjointSpatialCorroboration { label } => {
                write!(
                    f,
                    "spatial bounding boxes for label {label:?} do not intersect across corroborating sensors"
                )
            }
            Self::ClockError(reason) => write!(f, "clock error: {reason}"),
            Self::Reference(reason) => write!(f, "reference error: {reason}"),
            Self::LatestGenerationProhibited { generation } => {
                write!(
                    f,
                    "mutable 'latest' model generation alias is strictly prohibited by ADR-0004: '{generation}'"
                )
            }
            Self::NoPriorGenerationForRollback => {
                write!(f, "no prior model generation retained for rollback")
            }
            Self::CrossGenerationEmbeddingMixing { expected, actual } => {
                write!(
                    f,
                    "prohibited cross-generation embedding mixing: expected {expected}, got {actual}"
                )
            }
            Self::EmbeddingDimensionMismatch { expected, actual } => {
                write!(
                    f,
                    "embedding dimension mismatch: expected {expected}, got {actual}"
                )
            }
            Self::EmptyEmbeddingVector => write!(f, "embedding vector cannot be empty"),
            Self::EmbeddingDimensionTooLarge { actual, max } => {
                write!(
                    f,
                    "embedding dimension {actual} exceeds maximum bound {max}"
                )
            }
            Self::InvalidEmbeddingNorm => {
                write!(f, "embedding vector has zero or non-finite norm")
            }
            Self::AbstentionCannotBeNegativeEvidence { outcome } => {
                write!(
                    f,
                    "model abstention or failure ({outcome}) cannot be treated as negative evidence; negative evidence requires verified CoverageWitness (NEG-003, INV-056)"
                )
            }
        }
    }
}

impl std::error::Error for MockModelError {}

impl From<ReferenceError> for MockModelError {
    fn from(err: ReferenceError) -> Self {
        Self::ClockError(format!("{err:?}"))
    }
}
