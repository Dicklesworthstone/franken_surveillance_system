//! Deterministic scripted perception oracle for walking-skeleton qualification.

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, ProbabilityInterval};
use fss_object::InMemoryObjectStore;

use crate::{ReferenceCapture, ReferenceError};

const MAX_MODEL_GENERATION_BYTES: usize = 256;

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
    fn tag(self) -> u8 {
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

/// Immutable model generation/specification used by the reference executor.
#[derive(Clone, Debug, PartialEq)]
pub struct MockModelSpec {
    /// Stable model generation identity.
    pub generation_id: String,
    /// Frozen deterministic behavior.
    pub script: MockModelScript,
}

impl MockModelSpec {
    /// Constructs one bounded scripted model generation.
    pub fn new(
        generation_id: impl Into<String>,
        script: MockModelScript,
    ) -> Result<Self, ReferenceError> {
        let generation_id = generation_id.into();
        if generation_id.is_empty() || generation_id.len() > MAX_MODEL_GENERATION_BYTES {
            return Err(ReferenceError::InvalidSpec("model_generation_id"));
        }
        Ok(Self {
            generation_id,
            script,
        })
    }

    /// Content identity of the complete scripted model specification.
    #[must_use]
    pub fn spec_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.mock_model_spec.v1");
        encoder.text(&self.generation_id);
        encode_script(&self.script, &mut encoder);
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
    Finding {
        /// Derived semantic label.
        label: MockSemanticLabel,
        /// Model-local probability interval.
        probability: ProbabilityInterval,
    },
    /// Model declined to classify the input.
    Abstained {
        /// Stable abstention reason.
        reason: MockAbstentionReason,
    },
}

/// Retained deterministic model result.
#[derive(Clone, Debug, PartialEq)]
pub struct MockModelResult {
    /// Stable model generation identity.
    pub generation_id: String,
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
    let outcome = match &spec.script {
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
    let result = MockModelResult {
        generation_id: spec.generation_id.clone(),
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
