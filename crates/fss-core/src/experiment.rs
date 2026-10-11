#![forbid(unsafe_code)]
//! Same-binary A/A and A/B experiment receipt framework (FSS-196, bead
//! fss-x4a.26.16): the typed record that a controlled comparison happened,
//! with the honesty invariants encoded in the types rather than in prose.
//!
//! * **A/A (same binary, same inputs, same seed)** is a determinism proof:
//!   divergent outcomes are an ALARM, not a pass — the comparison carries
//!   [`ComparisonOutcome::Divergent`] and the receipt records it.
//! * **A/B** compares two named variants under the same basis and inputs;
//!   it never judges which is better — it records the exact digests and the
//!   divergence, leaving judgment to the evaluator.
//! * **Indeterminate runs never compare**: a missing or indeterminate outcome
//!   yields [`ComparisonOutcome::Indeterminate`], never a forced verdict.
//! * Mislabeled kind is a typed error: A/A with differing binary identities,
//!   or A/B with identical ones, is refused at construction.
//!
//! Sans-IO and deterministic: callers supply run identities, digests, and
//! intervals; nothing here reads a clock, a socket, or the filesystem.

use crate::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError,
};

/// Registered schema identity for the experiment receipt (the literal lives on
/// `ExperimentReceipt::SCHEMA` so the schema constitution's owner scan resolves
/// the owning type).
pub const SCHEMA_EXPERIMENT_RECEIPT: &str = ExperimentReceipt::SCHEMA;

/// Experiment kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExperimentKind {
    /// Same binary, same inputs, same seed: a determinism proof.
    Aa,
    /// Two named variants under one basis: a comparison record.
    Ab,
}

impl ExperimentKind {
    /// Stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aa => "aa",
            Self::Ab => "ab",
        }
    }
}

impl CanonicalEncode for ExperimentKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Aa => 1,
            Self::Ab => 2,
        });
    }
}

impl CanonicalDecode for ExperimentKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Aa),
            2 => Ok(Self::Ab),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One measured run of an experiment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentRun {
    /// Stable run identity within the experiment.
    pub run_id: String,
    /// Variant label (A/B only; None for same-binary A/A).
    pub variant_id: Option<String>,
    /// Content identity of the exact binary/build that ran.
    pub binary_identity: ContentDigest,
    /// Digest of the exact experiment inputs.
    pub inputs_digest: ContentDigest,
    /// Schedule seed when the run is scheduled (None = unscheduled).
    pub schedule_seed: Option<u64>,
    /// Digest of the run's outcome artifact; None = the run produced no
    /// comparable outcome (indeterminate).
    pub outcome_digest: Option<ContentDigest>,
}

impl CanonicalEncode for ExperimentRun {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.run_id);
        match &self.variant_id {
            Some(v) => {
                encoder.bool(true);
                encoder.text(v);
            }
            None => encoder.bool(false),
        }
        encoder.digest(self.binary_identity);
        encoder.digest(self.inputs_digest);
        match self.schedule_seed {
            Some(seed) => {
                encoder.bool(true);
                encoder.u64(seed);
            }
            None => encoder.bool(false),
        }
        match &self.outcome_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(*d);
            }
            None => encoder.bool(false),
        }
    }
}

/// The honest comparison outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComparisonOutcome {
    /// Outcome digests equal (A/A determinism holds / A/B no observable difference).
    Identical,
    /// Outcome digests differ (A/A: determinism alarm; A/B: a difference exists).
    Divergent,
    /// At least one side produced no comparable outcome — never forced.
    Indeterminate,
}

impl CanonicalEncode for ComparisonOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Identical => 1,
            Self::Divergent => 2,
            Self::Indeterminate => 3,
        });
    }
}

/// Typed construction errors for experiment receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExperimentError {
    /// A/A experiment with differing binary identities (that is an A/B).
    AaRequiresSameBinary,
    /// A/B experiment with identical variant labels.
    AbRequiresDistinctVariants,
    /// A/B run missing its variant label.
    AbRequiresVariantLabels,
    /// fss-core contract violation.
    Contract(ContractError),
}

impl core::fmt::Display for ExperimentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AaRequiresSameBinary => {
                write!(f, "A/A experiment requires identical binary identities")
            }
            Self::AbRequiresDistinctVariants => {
                write!(f, "A/B experiment requires distinct variant labels")
            }
            Self::AbRequiresVariantLabels => write!(f, "A/B runs must carry variant labels"),
            Self::Contract(e) => write!(f, "contract error: {e}"),
        }
    }
}

impl std::error::Error for ExperimentError {}

impl From<ContractError> for ExperimentError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}

/// The immutable comparison record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentReceipt {
    /// Stable experiment identity.
    pub experiment_id: String,
    /// A/A or A/B.
    pub kind: ExperimentKind,
    /// The two runs compared.
    pub runs: [ExperimentRun; 2],
    /// The honest comparison outcome.
    pub comparison: ComparisonOutcome,
    /// Receipt digest computed at construction.
    pub receipt_digest: ContentDigest,
}

impl ExperimentReceipt {
    /// Schema identity constant (`fss.experiment_receipt.v1`).
    pub const SCHEMA: &'static str = "fss.experiment_receipt.v1";

    /// Compares two runs into a receipt, enforcing the kind invariants.
    pub fn compare(
        experiment_id: impl Into<String>,
        kind: ExperimentKind,
        a: ExperimentRun,
        b: ExperimentRun,
    ) -> Result<Self, ExperimentError> {
        match kind {
            ExperimentKind::Aa => {
                if a.binary_identity != b.binary_identity {
                    return Err(ExperimentError::AaRequiresSameBinary);
                }
            }
            ExperimentKind::Ab => {
                match (&a.variant_id, &b.variant_id) {
                    (Some(_), Some(_)) => {}
                    _ => return Err(ExperimentError::AbRequiresVariantLabels),
                }
                if a.variant_id == b.variant_id {
                    return Err(ExperimentError::AbRequiresDistinctVariants);
                }
            }
        }
        let comparison = match (&a.outcome_digest, &b.outcome_digest) {
            (Some(da), Some(db)) => {
                if da == db {
                    ComparisonOutcome::Identical
                } else {
                    ComparisonOutcome::Divergent
                }
            }
            _ => ComparisonOutcome::Indeterminate,
        };
        let mut receipt = Self {
            experiment_id: experiment_id.into(),
            kind,
            runs: [a, b],
            comparison,
            receipt_digest: ContentDigest::sha256(b"uncomputed"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    /// Deterministic digest of the complete receipt.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(&self.experiment_id);
        self.kind.encode_canonical(&mut encoder);
        for run in &self.runs {
            run.encode_canonical(&mut encoder);
        }
        self.comparison.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Whether this receipt records a determinism alarm (A/A divergence).
    #[must_use]
    pub fn is_determinism_alarm(&self) -> bool {
        self.kind == ExperimentKind::Aa && self.comparison == ComparisonOutcome::Divergent
    }
}

impl CanonicalEncode for ExperimentReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.experiment_id);
        self.kind.encode_canonical(encoder);
        for run in &self.runs {
            run.encode_canonical(encoder);
        }
        self.comparison.encode_canonical(encoder);
        encoder.digest(self.receipt_digest);
    }
}
