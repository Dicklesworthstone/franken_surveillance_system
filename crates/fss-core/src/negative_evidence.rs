#![forbid(unsafe_code)]
//! Deterministic, evidence-native negative-evidence ledger and constraints (FSS-012).
//!
//! Enforces the non-negotiable prime directives:
//! 1. Negative evidence requires a certifying [`CoverageWitness`] ([`CoverageContinuity::Continuous`]);
//!    absence during a gap is NEVER evidence.
//! 2. Knowledge state ([`KnowledgeState`]), provenance class ([`ProvenanceClass`]), and
//!    hypothesis disposition ([`HypothesisDisposition`]) remain orthogonal typed fields;
//!    they must never be collapsed or flattened into a confidence score.
//! 3. Canonical binary encoding distinct from JSON with `FSSNEG01` magic, versioning,
//!    canonical ordering, and domain-separated trailing SHA-256 checksum over
//!    domain `fss.negative_evidence.ledger.v1`.
//! 4. Initial seed entries for NEG-001, NEG-002, and NEG-003 preserved verbatim from
//!    `docs/NEGATIVE_EVIDENCE.md` with normative decisions (`Narrow`, `Reject`, `Reject`) and
//!    explicit revival conditions. The seeds were recorded by architecture research, not by a
//!    local experiment ("does not establish"), so they are
//!    [`EvidenceCertification::NotLocallyCertified`], `unknown`, and `disfavored`, with a
//!    `vendor_claimed` finding, a `policy` decision, an explicitly uncovered witness, and no
//!    artifact or proof digest.
//! 5. A certifying witness is bound to its claim: its negative predicate is exactly
//!    `absence-certified:<claimed_domain>:<NEG-id>` and its domain is exactly the claimed domain.
//!    A locally certified entry also carries a proof hash and a retained evidence reference, and
//!    every entry satisfies the core [`KnowledgeCell`] rule.
//! 6. Stable IDs are canonical (`NEG-` plus at least three digits, no leading zeros beyond that
//!    width) and ordered by numeric value.
//! 7. Supersession is linked (`supersedes`) and append-only; revival requires the head of the
//!    evidence chain to be an immutable, locally observed or derived, proven row that re-tests the
//!    target's hypothesis and records it as supported.
//! 8. Tombstoning never exempts a record from validation.
//! 9. Unknown format versions refuse; never guess.

use core::fmt;
use std::collections::BTreeSet;

use crate::acquisition::Neg001ScenarioLog;
use crate::agent::{KnowledgeCell, KnowledgeCellParams};
use crate::contract::{
    Completeness, HypothesisDisposition, KnowledgeState, Plane, ProvenanceClass,
};
use crate::digest::{ContentDigest, Sha256Hasher};
use crate::evidence::{
    CoverageContinuity, CoverageStopReason, CoverageWitness, EvidenceDelta, LedgerAnchor,
};
use crate::ids::{ObjectId, TombstoneReason};
use crate::time::CaptureInterval;
use crate::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError};

/// Canonical schema for negative evidence ledger entries.
pub const SCHEMA_NEGATIVE_EVIDENCE_ENTRY: &str = "fss.negative_evidence.entry.v1";

/// Canonical schema for negative evidence binary ledger envelopes.
pub const SCHEMA_NEGATIVE_EVIDENCE_LEDGER: &str = "fss.negative_evidence.ledger.v1";

/// Magic 8-byte header for canonical negative-evidence binary ledgers.
pub const NEGATIVE_EVIDENCE_LEDGER_MAGIC: [u8; 8] = *b"FSSNEG01";

/// Current format version for negative-evidence binary ledgers.
///
/// Version 1 was the pre-review layout (26f027a). Version 2 adds decision text, decision
/// provenance, claimed domain, certification, supersession link, and evidence reference; a
/// version 1 ledger is refused as an unknown version.
pub const NEGATIVE_EVIDENCE_FORMAT_VERSION: u32 = 2;

/// Pinned freeze digest of the initial canonical binary negative-evidence ledger containing NEG-001, NEG-002, and NEG-003.
pub const INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST: &str =
    "sha256:4f181f09bf03b0e6619b406d2c6dc87e5a620a7e359ab6545413d7083974a1a1";

/// Maximum number of negative evidence entries in a single ledger.
pub const MAX_NEGATIVE_ENTRIES: usize = 1024;

/// Maximum character length of a negative evidence identifier (`NEG-###`).
pub const MAX_NEG_ID_LEN: usize = 64;

/// Maximum character length of free-text fields (hypothesis, reasoning, results, revival).
pub const MAX_NEG_TEXT_LEN: usize = 4096;

/// Maximum number of shared failure domains recorded per entry.
pub const MAX_FAILURE_DOMAINS: usize = 64;

/// Maximum character length of a single failure domain label.
pub const MAX_FAILURE_DOMAIN_LEN: usize = 128;

/// Maximum byte size of a canonical negative-evidence binary ledger file (4 MiB).
pub const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;

/// Minimum byte size of a canonical binary ledger header + trailer (8 magic + 4 ver + 4 count + 32 checksum = 48 bytes).
pub const MIN_LEDGER_BINARY_BYTES: usize = 48;

/// Maximum number of digits in a stable identifier (keeps its numeric value within `u64`).
pub const MAX_NEG_ID_DIGITS: usize = 18;

/// Leading token of every negative predicate: `absence-certified:<claimed_domain>:<NEG-id>`.
pub const NEGATIVE_PREDICATE_PREFIX: &str = "absence-certified";

/// Reproduction command recorded when a result cannot be reproduced by a local command.
pub const NOT_LOCALLY_REPRODUCIBLE: &str = "not-locally-reproducible";

/// Setup coordinate recorded when that coordinate was never evaluated.
pub const NOT_EVALUATED: &str = "not-evaluated";

/// Doctrine document that is the source of truth for the seed entries.
pub const NEGATIVE_EVIDENCE_DOCTRINE_PATH: &str = "docs/NEGATIVE_EVIDENCE.md";

/// Type alias aligning with the semantic specification.
pub type EvidenceAnchor = LedgerAnchor;

/// Returns the stable string representation of a [`ProvenanceClass`].
#[must_use]
pub const fn provenance_class_as_str(p: ProvenanceClass) -> &'static str {
    p.as_str()
}

/// Returns the stable string representation of a [`HypothesisDisposition`].
#[must_use]
pub const fn hypothesis_disposition_as_str(h: HypothesisDisposition) -> &'static str {
    match h {
        HypothesisDisposition::Live => "live",
        HypothesisDisposition::Supported => "supported",
        HypothesisDisposition::Disfavored => "disfavored",
        HypothesisDisposition::Refuted => "refuted",
        HypothesisDisposition::Resolved => "resolved",
        HypothesisDisposition::Superseded => "superseded",
    }
}

/// Normative negative decision outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NegativeDecision {
    /// Candidate rejected; constraint stands.
    Reject = 1,
    /// Candidate retained only as an oracle/lab reference; not for production.
    Oracle = 2,
    /// Candidate scope narrowed to approved bounds.
    Narrow = 3,
    /// Candidate requires revisit under specified experimental conditions.
    Revisit = 4,
}

impl NegativeDecision {
    /// Returns the canonical lower-case string identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Oracle => "oracle",
            Self::Narrow => "narrow",
            Self::Revisit => "revisit",
        }
    }

    /// Parses a decision from its canonical string identity.
    pub fn parse(s: &str) -> Result<Self, NegativeEvidenceError> {
        match s {
            "reject" => Ok(Self::Reject),
            "oracle" => Ok(Self::Oracle),
            "narrow" => Ok(Self::Narrow),
            "revisit" => Ok(Self::Revisit),
            other => Err(NegativeEvidenceError::InvalidIdentifier(format!(
                "unknown negative decision '{other}'"
            ))),
        }
    }
}

impl fmt::Display for NegativeDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for NegativeDecision {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for NegativeDecision {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Reject),
            2 => Ok(Self::Oracle),
            3 => Ok(Self::Narrow),
            4 => Ok(Self::Revisit),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Experimental setup context for a negative evidence evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeEvidenceSetup {
    /// Evaluated corpus or workload name.
    pub corpus: String,
    /// Evaluated device model.
    pub device_model: String,
    /// Evaluated firmware version.
    pub firmware_version: String,
    /// Evaluated host platform/OS.
    pub platform: String,
    /// Applied security/camera policy.
    pub policy: String,
    /// Reproduction command line.
    pub command: String,
    /// Optional digest of setup artifact or registry.
    pub artifact_digest: Option<ContentDigest>,
}

impl NegativeEvidenceSetup {
    /// Validates field bounds.
    pub fn validate(&self) -> Result<(), NegativeEvidenceError> {
        if self.corpus.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("setup corpus exceeds {} bytes", MAX_NEG_TEXT_LEN),
            });
        }
        if self.device_model.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("setup device_model exceeds {} bytes", MAX_NEG_TEXT_LEN),
            });
        }
        if self.firmware_version.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("setup firmware_version exceeds {} bytes", MAX_NEG_TEXT_LEN),
            });
        }
        if self.platform.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("setup platform exceeds {} bytes", MAX_NEG_TEXT_LEN),
            });
        }
        if self.policy.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("setup policy exceeds {} bytes", MAX_NEG_TEXT_LEN),
            });
        }
        if self.command.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("setup command exceeds {} bytes", MAX_NEG_TEXT_LEN),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for NegativeEvidenceSetup {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.corpus);
        encoder.text(&self.device_model);
        encoder.text(&self.firmware_version);
        encoder.text(&self.platform);
        encoder.text(&self.policy);
        encoder.text(&self.command);
        match self.artifact_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for NegativeEvidenceSetup {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let corpus = decoder.text()?.to_string();
        let device_model = decoder.text()?.to_string();
        let firmware_version = decoder.text()?.to_string();
        let platform = decoder.text()?.to_string();
        let policy = decoder.text()?.to_string();
        let command = decoder.text()?.to_string();
        let artifact_digest = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        Ok(Self {
            corpus,
            device_model,
            firmware_version,
            platform,
            policy,
            command,
            artifact_digest,
        })
    }
}

/// How the absence claim of a negative-evidence entry is established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceCertification {
    /// A locally executed experiment whose absence claim is certified by the entry's
    /// [`CoverageWitness`], bound to this entry's identifier and claimed domain.
    LocallyCertified,
    /// Recorded from an external or doctrine source; never executed or certified locally.
    ///
    /// Such an entry must carry an explicitly uncovered witness (continuity unknown, nothing
    /// observed, observed generation 0), must not claim [`KnowledgeState::Known`], and must not
    /// claim [`ProvenanceClass::Observed`].
    NotLocallyCertified {
        /// Secret-free reference to the external source of the result.
        source: String,
    },
}

impl EvidenceCertification {
    /// Returns the stable string identity of the certification kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LocallyCertified => "locally_certified",
            Self::NotLocallyCertified { .. } => "not_locally_certified",
        }
    }
}

impl CanonicalEncode for EvidenceCertification {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::LocallyCertified => encoder.u8(1),
            Self::NotLocallyCertified { source } => {
                encoder.u8(2);
                encoder.text(source);
            }
        }
    }
}

impl CanonicalDecode for EvidenceCertification {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::LocallyCertified),
            2 => Ok(Self::NotLocallyCertified {
                source: decoder.text()?.to_string(),
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One normative negative-evidence entry in the canonical ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeEvidenceEntry {
    /// Stable constraint identifier (`NEG-###`).
    pub neg_id: String,
    /// Date and commit context of the evaluation (or of the doctrine record when no experiment ran).
    pub date_commit: String,
    /// What was expected and why.
    pub hypothesis: String,
    /// Underlying architectural reasoning.
    pub reasoning: String,
    /// Exact evaluated setup.
    pub setup: NegativeEvidenceSetup,
    /// Measured results, divergences, and failures.
    pub measured_result: String,
    /// Normative decision outcome.
    pub decision: NegativeDecision,
    /// Verbatim decision text (for seeds, the doctrine's `Decision` line); may be empty.
    pub decision_text: String,
    /// Shared failure domains preventing promotion.
    pub shared_failure_domains: BTreeSet<String>,
    /// Explicit, falsifiable condition required to repeat or revive this candidate.
    pub revival_condition: String,
    /// Epistemic state (preserved as orthogonal field, never flattened into confidence).
    pub knowledge_state: KnowledgeState,
    /// Provenance of the finding / measured result (preserved as orthogonal field).
    pub provenance_class: ProvenanceClass,
    /// Provenance of the decision, recorded separately from that of the finding.
    pub decision_provenance: ProvenanceClass,
    /// Hypothesis disposition within investigation.
    pub disposition: HypothesisDisposition,
    /// Coverage witness; certifying and bound to this entry when locally certified, explicitly
    /// uncovered otherwise. Absence during a gap is NEVER evidence.
    pub coverage_witness: CoverageWitness,
    /// Domain over which this entry claims absence; the witness domain must be exactly it.
    pub claimed_domain: String,
    /// How the absence claim is established.
    pub certification: EvidenceCertification,
    /// Earlier entry that this entry supersedes (linked, append-only supersession).
    pub supersedes: Option<String>,
    /// Whether this entry has been permanently tombstoned.
    pub is_tombstone: bool,
    /// Semantic tombstone reason if tombstoned.
    pub tombstone_reason: Option<TombstoneReason>,
    /// Digest of a retained proof artifact binding the result; required when locally certified.
    pub proof_hash: Option<ContentDigest>,
    /// Secret-free handle of the retained evidence the proof hash binds; required when locally
    /// certified.
    pub evidence_reference: Option<String>,
    /// Secret-free reproduction command, or [`NOT_LOCALLY_REPRODUCIBLE`].
    pub reproduction_command: String,
}

impl NegativeEvidenceEntry {
    /// Constructs a locally certified NEG-001 entry from an executed [`Neg001ScenarioLog`].
    ///
    /// The hypothesis, decision text, and revival condition are the NEG-001 doctrine verbatim;
    /// the measured result is taken from the log's own observations. `date_commit` must name the
    /// exact date/commit of the run that produced `log`.
    pub fn from_neg001_scenario_log(
        log: &Neg001ScenarioLog,
        coverage_witness: CoverageWitness,
        date_commit: &str,
    ) -> Result<Self, NegativeEvidenceError> {
        let doctrine = &NEG001_DOCTRINE;
        if log.neg_id != doctrine.neg_id {
            return Err(NegativeEvidenceError::Validation {
                detail: format!(
                    "scenario log names '{}', expected '{}'",
                    log.neg_id, doctrine.neg_id
                ),
            });
        }
        let setup = NegativeEvidenceSetup {
            corpus: "reference-architecture".to_string(),
            device_model: log.tuple.device_model.clone(),
            firmware_version: log.tuple.firmware_version.clone(),
            platform: log.tuple.host_platform.clone(),
            policy: doctrine.policy.to_string(),
            command: log.reproduction_command.clone(),
            artifact_digest: Some(log.registry_digest),
        };

        let entry = Self {
            neg_id: log.neg_id.to_string(),
            date_commit: date_commit.to_string(),
            hypothesis: doctrine.hypothesis.to_string(),
            reasoning: doctrine.reasoning.to_string(),
            setup,
            measured_result: format!(
                "scenario run '{}': adapter_accepted={}, streaming={}, expected_readiness={:?}, observed_readiness={:?}",
                log.run_id,
                log.is_adapter_accepted,
                log.is_streaming,
                log.expected_readiness,
                log.observed_readiness,
            ),
            decision: doctrine.decision,
            decision_text: doctrine.decision_text.to_string(),
            shared_failure_domains: label_set(doctrine.failure_domains),
            revival_condition: doctrine.revival_condition.to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance_class: ProvenanceClass::Observed,
            decision_provenance: ProvenanceClass::Policy,
            disposition: HypothesisDisposition::Refuted,
            coverage_witness,
            claimed_domain: ARCHITECTURAL_CONSTRAINTS_DOMAIN.to_string(),
            certification: EvidenceCertification::LocallyCertified,
            supersedes: None,
            is_tombstone: false,
            tombstone_reason: None,
            proof_hash: Some(log.proof_hash),
            evidence_reference: Some(format!("{}:{}", log.schema_version, log.run_id)),
            reproduction_command: log.reproduction_command.clone(),
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Computes the domain-separated canonical digest of this negative evidence entry.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, SCHEMA_NEGATIVE_EVIDENCE_ENTRY)
    }

    /// Validates all field invariants and semantic boundary conditions.
    pub fn validate(&self) -> Result<(), NegativeEvidenceError> {
        validate_neg_id("neg_id", &self.neg_id)?;

        require_text("date_commit", &self.date_commit)?;
        require_text("hypothesis", &self.hypothesis)?;
        require_text("reasoning", &self.reasoning)?;
        require_text("measured_result", &self.measured_result)?;
        require_text("revival_condition", &self.revival_condition)?;
        bound_text("decision_text", &self.decision_text)?;
        bound_text("reproduction_command", &self.reproduction_command)?;
        self.setup.validate()?;

        validate_label_set(
            "shared_failure_domains",
            &self.shared_failure_domains,
            MAX_FAILURE_DOMAINS,
        )?;
        validate_label("claimed_domain", &self.claimed_domain)?;
        if let Some(reference) = &self.evidence_reference {
            require_text("evidence_reference", reference)?;
        }

        // Supersession is linked and append-only: the link must name an earlier entry.
        if let Some(target) = &self.supersedes
            && neg_id_value("supersedes", target)? >= neg_id_value("neg_id", &self.neg_id)?
        {
            return Err(NegativeEvidenceError::Validation {
                detail: format!(
                    "entry '{}' supersedes '{target}', which is not an earlier entry",
                    self.neg_id
                ),
            });
        }

        // Tombstone consistency; every accepted tombstone reason must round-trip canonically.
        match (self.is_tombstone, self.tombstone_reason) {
            (true, None) => {
                return Err(NegativeEvidenceError::Validation {
                    detail: format!(
                        "tombstoned entry '{}' must record a tombstone_reason",
                        self.neg_id
                    ),
                });
            }
            (false, Some(_)) => {
                return Err(NegativeEvidenceError::Validation {
                    detail: format!(
                        "active entry '{}' must not carry a tombstone_reason",
                        self.neg_id
                    ),
                });
            }
            (true, Some(reason)) if TombstoneReason::from_tag(reason.tag()) != reason => {
                return Err(NegativeEvidenceError::Validation {
                    detail: format!(
                        "tombstone reason tag {} of entry '{}' collides with a registered reason and cannot round-trip",
                        reason.tag(),
                        self.neg_id
                    ),
                });
            }
            _ => {}
        }

        // Absence during a gap or uncertified domain is NEVER evidence. Tombstoning keeps the
        // original record immutable, so it is certified exactly as when it was active.
        self.validate_certification()?;
        self.validate_knowledge_cell()
    }

    fn validate_certification(&self) -> Result<(), NegativeEvidenceError> {
        let witness = &self.coverage_witness;
        match &self.certification {
            EvidenceCertification::LocallyCertified => {
                match witness.continuity {
                    CoverageContinuity::Continuous => {}
                    CoverageContinuity::Gapped | CoverageContinuity::Unknown => {
                        return Err(NegativeEvidenceError::CoverageGap {
                            continuity: witness.continuity,
                        });
                    }
                }
                if !witness.certifies_absence() {
                    return Err(NegativeEvidenceError::UncertifiedCoverage {
                        detail: format!(
                            "coverage witness for '{}' does not certify absence (continuity: {:?}, completeness: {:?}, stop_reason: {:?})",
                            self.neg_id,
                            witness.continuity,
                            witness.completeness,
                            witness.stop_reason,
                        ),
                    });
                }
                if self.proof_hash.is_none() || self.evidence_reference.is_none() {
                    return Err(NegativeEvidenceError::MissingProof {
                        detail: format!(
                            "locally certified entry '{}' must carry a proof hash and a retained evidence reference",
                            self.neg_id
                        ),
                    });
                }
            }
            EvidenceCertification::NotLocallyCertified { source } => {
                require_text("certification source", source)?;
                if self.knowledge_state == KnowledgeState::Known {
                    return Err(NegativeEvidenceError::MissingCoverageWitness {
                        detail: format!(
                            "entry '{}' is not locally certified and cannot claim knowledge state 'known'",
                            self.neg_id
                        ),
                    });
                }
                if self.provenance_class == ProvenanceClass::Observed {
                    return Err(NegativeEvidenceError::MissingCoverageWitness {
                        detail: format!(
                            "entry '{}' is not locally certified and cannot claim provenance 'observed'",
                            self.neg_id
                        ),
                    });
                }
                if witness.continuity != CoverageContinuity::Unknown
                    || !witness.observed_domain.is_empty()
                    || witness.observed_generation != 0
                {
                    return Err(NegativeEvidenceError::Validation {
                        detail: format!(
                            "entry '{}' is not locally certified but its witness claims observation (continuity: {:?}, observed domains: {}, observed generation: {}); it must carry an explicitly uncovered witness",
                            self.neg_id,
                            witness.continuity,
                            witness.observed_domain.len(),
                            witness.observed_generation,
                        ),
                    });
                }
            }
        }
        self.check_witness_binding()
    }

    /// Returns the exact negative predicate a witness for this entry must carry.
    #[must_use]
    pub fn expected_negative_predicate(&self) -> String {
        negative_predicate_for(&self.claimed_domain, &self.neg_id)
    }

    /// Binds the witness to this entry's claim: the negative predicate must be exactly
    /// `absence-certified:<claimed_domain>:<NEG-id>` and the witness domain exactly the claimed
    /// domain.
    fn check_witness_binding(&self) -> Result<(), NegativeEvidenceError> {
        let witness = &self.coverage_witness;
        let expected = self.expected_negative_predicate();
        if witness.negative_predicate != expected {
            return Err(NegativeEvidenceError::WitnessNotBound {
                neg_id: self.neg_id.clone(),
                detail: format!(
                    "negative predicate '{}' must be exactly '{expected}'",
                    witness.negative_predicate
                ),
            });
        }
        if witness.authorized_domain.len() != 1
            || !witness.authorized_domain.contains(&self.claimed_domain)
        {
            return Err(NegativeEvidenceError::WitnessNotBound {
                neg_id: self.neg_id.clone(),
                detail: format!(
                    "witness domain {{{}}} does not match claimed domain {{{}}}",
                    join_labels(&witness.authorized_domain),
                    self.claimed_domain
                ),
            });
        }
        Ok(())
    }

    /// Applies the core [`KnowledgeCell`] rule to the entry's finding: `known` requires
    /// non-empty evidence roots for every provenance, observed or derived provenance claiming
    /// present support needs evidence, and states that need a basis (stale, redacted,
    /// indeterminate) are refused because a ledger entry carries none.
    fn validate_knowledge_cell(&self) -> Result<(), NegativeEvidenceError> {
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: self.neg_id.clone(),
            statement: self.measured_result.clone(),
            knowledge_state: self.knowledge_state,
            provenance: self.provenance_class,
            hypothesis: Some(self.disposition),
            evidence: self.proof_hash.into_iter().collect(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        });
        cell.map(|_| ()).map_err(|err| match err {
            ContractError::EvidenceRequired => NegativeEvidenceError::MissingProof {
                detail: format!(
                    "entry '{}' claims '{}' with '{}' provenance but carries no evidence",
                    self.neg_id,
                    self.knowledge_state.as_str(),
                    provenance_class_as_str(self.provenance_class)
                ),
            },
            other => NegativeEvidenceError::Validation {
                detail: format!(
                    "entry '{}' violates the knowledge-cell rule for state '{}': {other}",
                    self.neg_id,
                    self.knowledge_state.as_str()
                ),
            },
        })
    }

    /// Converts this entry into an [`EvidenceDelta`] for canonical ledger publication.
    pub fn to_evidence_delta(
        &self,
        generation: u64,
        plane: Plane,
    ) -> Result<EvidenceDelta, NegativeEvidenceError> {
        let object_id = ObjectId::parse(&self.neg_id).map_err(NegativeEvidenceError::Contract)?;
        let payload_digest = self.canonical_digest();
        let witness_digest = match self.certification {
            EvidenceCertification::LocallyCertified => Some(self.coverage_witness.witness_digest()),
            EvidenceCertification::NotLocallyCertified { .. } => None,
        };
        Ok(EvidenceDelta {
            delta_id: format!("delta:{}", self.neg_id.to_ascii_lowercase()),
            family: "negative_evidence".to_string(),
            object_id,
            prior_generation: if generation > 1 {
                Some(generation - 1)
            } else {
                None
            },
            new_generation: generation,
            validity: CaptureInterval::point(crate::time::TimestampNs(0)),
            plane,
            payload_digest,
            witness_digest,
            operation_id: None,
        })
    }

    /// Formats this entry as a secret-free JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let artifact_str = match self.setup.artifact_digest {
            Some(d) => format!("\"{}\"", d.to_text()),
            None => "null".to_string(),
        };
        let proof_str = match self.proof_hash {
            Some(d) => format!("\"{}\"", d.to_text()),
            None => "null".to_string(),
        };
        let tombstone_reason_str = match self.tombstone_reason {
            Some(r) => format!("\"{}\"", r.as_str()),
            None => "null".to_string(),
        };
        let supersedes_str = match &self.supersedes {
            Some(id) => format!("\"{}\"", escape_json(id)),
            None => "null".to_string(),
        };
        let certification_source = match &self.certification {
            EvidenceCertification::LocallyCertified => "null".to_string(),
            EvidenceCertification::NotLocallyCertified { source } => {
                format!("\"{}\"", escape_json(source))
            }
        };
        let evidence_reference_str = match &self.evidence_reference {
            Some(reference) => format!("\"{}\"", escape_json(reference)),
            None => "null".to_string(),
        };

        format!(
            "{{\"negId\":\"{}\",\"dateCommit\":\"{}\",\"hypothesis\":\"{}\",\"reasoning\":\"{}\",\"setup\":{{\"corpus\":\"{}\",\"deviceModel\":\"{}\",\"firmwareVersion\":\"{}\",\"platform\":\"{}\",\"policy\":\"{}\",\"command\":\"{}\",\"artifactDigest\":{}}},\"measuredResult\":\"{}\",\"decision\":\"{}\",\"decisionText\":\"{}\",\"sharedFailureDomains\":{},\"revivalCondition\":\"{}\",\"knowledgeState\":\"{}\",\"provenanceClass\":\"{}\",\"decisionProvenance\":\"{}\",\"disposition\":\"{}\",\"claimedDomain\":\"{}\",\"certification\":\"{}\",\"certificationSource\":{},\"witnessCertifiesAbsence\":{},\"supersedes\":{},\"isTombstone\":{},\"tombstoneReason\":{},\"proofHash\":{},\"evidenceReference\":{},\"reproductionCommand\":\"{}\"}}",
            escape_json(&self.neg_id),
            escape_json(&self.date_commit),
            escape_json(&self.hypothesis),
            escape_json(&self.reasoning),
            escape_json(&self.setup.corpus),
            escape_json(&self.setup.device_model),
            escape_json(&self.setup.firmware_version),
            escape_json(&self.setup.platform),
            escape_json(&self.setup.policy),
            escape_json(&self.setup.command),
            artifact_str,
            escape_json(&self.measured_result),
            self.decision.as_str(),
            escape_json(&self.decision_text),
            json_string_array(&self.shared_failure_domains),
            escape_json(&self.revival_condition),
            self.knowledge_state.as_str(),
            provenance_class_as_str(self.provenance_class),
            provenance_class_as_str(self.decision_provenance),
            hypothesis_disposition_as_str(self.disposition),
            escape_json(&self.claimed_domain),
            self.certification.as_str(),
            certification_source,
            self.coverage_witness.certifies_absence(),
            supersedes_str,
            self.is_tombstone,
            tombstone_reason_str,
            proof_str,
            evidence_reference_str,
            escape_json(&self.reproduction_command),
        )
    }
}

impl CanonicalEncode for NegativeEvidenceEntry {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.neg_id);
        encoder.text(&self.date_commit);
        encoder.text(&self.hypothesis);
        encoder.text(&self.reasoning);
        self.setup.encode_canonical(encoder);
        encoder.text(&self.measured_result);
        self.decision.encode_canonical(encoder);
        encoder.text(&self.decision_text);
        encode_label_set(&self.shared_failure_domains, encoder);
        encoder.text(&self.revival_condition);
        encoder.text(self.knowledge_state.as_str());
        encoder.text(provenance_class_as_str(self.provenance_class));
        encoder.text(hypothesis_disposition_as_str(self.disposition));
        self.coverage_witness.encode_canonical(encoder);
        encoder.text(&self.claimed_domain);
        self.certification.encode_canonical(encoder);
        encoder.text(provenance_class_as_str(self.decision_provenance));
        match &self.supersedes {
            Some(target) => {
                encoder.bool(true);
                encoder.text(target);
            }
            None => encoder.bool(false),
        }
        encoder.bool(self.is_tombstone);
        match self.tombstone_reason {
            Some(reason) => {
                encoder.bool(true);
                encoder.u8(reason.tag());
            }
            None => encoder.bool(false),
        }
        match self.proof_hash {
            Some(hash) => {
                encoder.bool(true);
                encoder.digest(hash);
            }
            None => encoder.bool(false),
        }
        match &self.evidence_reference {
            Some(reference) => {
                encoder.bool(true);
                encoder.text(reference);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.reproduction_command);
    }
}

impl CanonicalDecode for NegativeEvidenceEntry {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let neg_id = decoder.text()?.to_string();
        let date_commit = decoder.text()?.to_string();
        let hypothesis = decoder.text()?.to_string();
        let reasoning = decoder.text()?.to_string();
        let setup = NegativeEvidenceSetup::decode_canonical(decoder)?;
        let measured_result = decoder.text()?.to_string();
        let decision = NegativeDecision::decode_canonical(decoder)?;
        let decision_text = decoder.text()?.to_string();
        let shared_failure_domains = decode_label_set(decoder, MAX_FAILURE_DOMAINS)?;
        let revival_condition = decoder.text()?.to_string();
        let kstate_str = decoder.text()?;
        let knowledge_state = KnowledgeState::from_name(kstate_str)?;
        let prov_str = decoder.text()?;
        let provenance_class = ProvenanceClass::from_name(prov_str)?;
        let disp_str = decoder.text()?;
        let disposition = match disp_str {
            "live" => HypothesisDisposition::Live,
            "supported" => HypothesisDisposition::Supported,
            "disfavored" => HypothesisDisposition::Disfavored,
            "refuted" => HypothesisDisposition::Refuted,
            "resolved" => HypothesisDisposition::Resolved,
            "superseded" => HypothesisDisposition::Superseded,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let coverage_witness = CoverageWitness::decode_canonical(decoder)?;
        let claimed_domain = decoder.text()?.to_string();
        let certification = EvidenceCertification::decode_canonical(decoder)?;
        let decision_provenance = ProvenanceClass::from_name(decoder.text()?)?;
        let supersedes = if decoder.bool()? {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let is_tombstone = decoder.bool()?;
        let tombstone_reason = if decoder.bool()? {
            let tag = decoder.u8()?;
            Some(TombstoneReason::from_tag(tag))
        } else {
            None
        };
        let proof_hash = if decoder.bool()? {
            Some(decoder.digest()?)
        } else {
            None
        };
        let evidence_reference = if decoder.bool()? {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let reproduction_command = decoder.text()?.to_string();
        Ok(Self {
            neg_id,
            date_commit,
            hypothesis,
            reasoning,
            setup,
            measured_result,
            decision,
            decision_text,
            shared_failure_domains,
            revival_condition,
            knowledge_state,
            provenance_class,
            decision_provenance,
            disposition,
            coverage_witness,
            claimed_domain,
            certification,
            supersedes,
            is_tombstone,
            tombstone_reason,
            proof_hash,
            evidence_reference,
            reproduction_command,
        })
    }
}

/// A collection of canonically ordered, verified negative-evidence entries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NegativeEvidenceLedger {
    entries: Vec<NegativeEvidenceEntry>,
}

impl NegativeEvidenceLedger {
    /// Creates an empty negative-evidence ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns a slice of the canonically ordered entries.
    #[must_use]
    pub fn entries(&self) -> &[NegativeEvidenceEntry] {
        &self.entries
    }

    /// Returns the number of entries in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the ledger contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Finds an entry by its stable `NEG-###` identifier.
    #[must_use]
    pub fn get(&self, neg_id: &str) -> Option<&NegativeEvidenceEntry> {
        self.entries.iter().find(|e| e.neg_id == neg_id)
    }

    /// Returns true if the ledger contains an entry with the given identifier.
    #[must_use]
    pub fn contains(&self, neg_id: &str) -> bool {
        self.get(neg_id).is_some()
    }

    /// Appends a new negative-evidence entry enforcing canonical order, uniqueness, validity,
    /// and linked append-only supersession.
    pub fn append(&mut self, entry: NegativeEvidenceEntry) -> Result<(), NegativeEvidenceError> {
        entry.validate()?;
        if self.entries.len() >= MAX_NEGATIVE_ENTRIES {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("ledger capacity of {MAX_NEGATIVE_ENTRIES} entries reached"),
            });
        }
        for existing in &self.entries {
            if existing.neg_id == entry.neg_id {
                return Err(NegativeEvidenceError::DuplicateEntryId {
                    neg_id: entry.neg_id.clone(),
                });
            }
        }
        let value = neg_id_value("neg_id", &entry.neg_id)?;
        if let Some(last) = self.entries.last()
            && value <= neg_id_value("neg_id", &last.neg_id)?
        {
            return Err(NegativeEvidenceError::NonCanonicalOrder {
                prior: last.neg_id.clone(),
                current: entry.neg_id.clone(),
            });
        }
        check_supersession(&entry, &self.entries)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Verifies that reviving `neg_id` is justified by an immutable evidence row.
    ///
    /// The caller cannot assert the revival condition; it must be evidenced by `evidence_id`, a
    /// row already appended to this ledger (immutable, validated, append-only) that links
    /// `supersedes == neg_id`, is the current head of its own supersession chain (nothing later
    /// supersedes it), is the latest row superseding the target (a later row superseding the
    /// same target, such as a refutation, overrides it), re-tests the target's exact hypothesis,
    /// is locally certified with a proof hash and a retained evidence reference, has `observed`
    /// or `derived` provenance, is `known`, and records the hypothesis as `supported`. A
    /// tombstoned target or evidence row, and a target whose disposition is already `superseded`
    /// or `resolved`, are refused.
    pub fn verify_revival_condition(
        &self,
        neg_id: &str,
        evidence_id: &str,
    ) -> Result<(), NegativeEvidenceError> {
        let target = self.get(neg_id).ok_or_else(|| {
            NegativeEvidenceError::InvalidIdentifier(format!("entry '{neg_id}' not found"))
        })?;
        if target.is_tombstone {
            return Err(NegativeEvidenceError::EntryTombstoned {
                neg_id: neg_id.to_string(),
            });
        }
        if matches!(
            target.disposition,
            HypothesisDisposition::Superseded | HypothesisDisposition::Resolved
        ) {
            return Err(NegativeEvidenceError::Validation {
                detail: format!(
                    "entry '{neg_id}' has disposition '{}' and cannot be revived",
                    hypothesis_disposition_as_str(target.disposition)
                ),
            });
        }
        let unmet = |reason: String| NegativeEvidenceError::RevivalConditionUnmet {
            neg_id: neg_id.to_string(),
            condition: target.revival_condition.clone(),
            reason,
        };
        let Some(evidence) = self.get(evidence_id) else {
            return Err(unmet(format!(
                "no immutable evidence row '{evidence_id}' exists in this ledger"
            )));
        };
        if evidence.supersedes.as_deref() != Some(neg_id) {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' does not supersede '{neg_id}'"
            )));
        }
        if let Some(successor) = self
            .entries
            .iter()
            .find(|entry| entry.supersedes.as_deref() == Some(evidence_id))
        {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' is superseded by '{}' and is not the head of its supersession chain",
                successor.neg_id
            )));
        }
        // Entries are in canonical order, so the last row superseding the target is the latest.
        if let Some(latest) = self
            .entries
            .iter()
            .rev()
            .find(|entry| entry.supersedes.as_deref() == Some(neg_id))
            && latest.neg_id != evidence_id
        {
            return Err(unmet(format!(
                "'{}' supersedes '{neg_id}' after evidence row '{evidence_id}'; revival requires the latest row superseding the target",
                latest.neg_id
            )));
        }
        if evidence.hypothesis != target.hypothesis {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' tests a different hypothesis than '{neg_id}'"
            )));
        }
        if evidence.is_tombstone {
            return Err(NegativeEvidenceError::EntryTombstoned {
                neg_id: evidence_id.to_string(),
            });
        }
        if evidence.certification != EvidenceCertification::LocallyCertified {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' is not locally certified"
            )));
        }
        if evidence.proof_hash.is_none() || evidence.evidence_reference.is_none() {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' carries no proof hash and retained evidence reference"
            )));
        }
        if !matches!(
            evidence.provenance_class,
            ProvenanceClass::Observed | ProvenanceClass::Derived
        ) {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' has '{}' provenance; revival requires locally observed or derived evidence",
                provenance_class_as_str(evidence.provenance_class)
            )));
        }
        if evidence.knowledge_state != KnowledgeState::Known {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' has knowledge state '{}'; revival requires 'known'",
                evidence.knowledge_state.as_str()
            )));
        }
        if evidence.disposition != HypothesisDisposition::Supported {
            return Err(unmet(format!(
                "evidence row '{evidence_id}' records disposition '{}'; revival requires 'supported'",
                hypothesis_disposition_as_str(evidence.disposition)
            )));
        }
        evidence.validate()
    }

    /// Verifies the complete ledger invariants.
    pub fn verify(&self) -> Result<(), NegativeEvidenceError> {
        if self.entries.len() > MAX_NEGATIVE_ENTRIES {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("ledger entry count exceeds {MAX_NEGATIVE_ENTRIES}"),
            });
        }
        for (i, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if i > 0 {
                let prev = &self.entries[i - 1];
                if neg_id_value("neg_id", &entry.neg_id)? <= neg_id_value("neg_id", &prev.neg_id)? {
                    if entry.neg_id == prev.neg_id {
                        return Err(NegativeEvidenceError::DuplicateEntryId {
                            neg_id: entry.neg_id.clone(),
                        });
                    }
                    return Err(NegativeEvidenceError::NonCanonicalOrder {
                        prior: prev.neg_id.clone(),
                        current: entry.neg_id.clone(),
                    });
                }
            }
            check_supersession(entry, &self.entries[..i])?;
        }
        Ok(())
    }

    /// Encodes the ledger into its hand-audited canonical binary format with `FSSNEG01` magic,
    /// version, length-prefixed entries, and domain-separated trailing SHA-256 checksum.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, NegativeEvidenceError> {
        self.verify()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&NEGATIVE_EVIDENCE_LEDGER_MAGIC);
        payload.extend_from_slice(&NEGATIVE_EVIDENCE_FORMAT_VERSION.to_be_bytes());
        payload.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());

        for entry in &self.entries {
            let entry_bytes = entry
                .try_canonical_bytes()
                .map_err(NegativeEvidenceError::Contract)?;
            payload.extend_from_slice(&(entry_bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(&entry_bytes);
        }

        if payload.len() + 32 > MAX_LEDGER_BYTES {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!(
                    "ledger binary size {} exceeds limit of {MAX_LEDGER_BYTES} bytes",
                    payload.len() + 32
                ),
            });
        }

        // Domain-separated trailing SHA-256 checksum over domain `fss.negative_evidence.ledger.v1`
        let mut hasher = Sha256Hasher::new();
        hasher.update(SCHEMA_NEGATIVE_EVIDENCE_LEDGER.as_bytes());
        hasher.update(&payload);
        let checksum_bytes = hasher.finalize().map_err(NegativeEvidenceError::Contract)?;

        payload.extend_from_slice(&checksum_bytes);
        Ok(payload)
    }

    /// Returns the canonical root digest of the ledger.
    pub fn root_digest(&self) -> Result<ContentDigest, NegativeEvidenceError> {
        let binary = self.encode_canonical()?;
        Ok(ContentDigest::sha256(&binary))
    }

    /// Decodes a canonical negative-evidence binary ledger, enforcing checksum integrity,
    /// format version check (refusing unknown versions), bounds, and canonical ordering.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, NegativeEvidenceError> {
        if bytes.len() < MIN_LEDGER_BINARY_BYTES {
            return Err(NegativeEvidenceError::Truncated);
        }
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!(
                    "binary input length {} exceeds {MAX_LEDGER_BYTES}",
                    bytes.len()
                ),
            });
        }

        // 1. Separate payload and trailing 32-byte checksum
        let payload_len = bytes.len() - 32;
        let (payload, trailer) = bytes.split_at(payload_len);

        // 2. Verify domain-separated checksum
        let mut hasher = Sha256Hasher::new();
        hasher.update(SCHEMA_NEGATIVE_EVIDENCE_LEDGER.as_bytes());
        hasher.update(payload);
        let computed = hasher.finalize().map_err(NegativeEvidenceError::Contract)?;

        if computed != trailer {
            let mut trailer_bytes = [0u8; 32];
            trailer_bytes.copy_from_slice(trailer);
            return Err(NegativeEvidenceError::CorruptChecksum {
                expected: ContentDigest::new(crate::digest::DigestAlgorithm::Sha256, trailer_bytes),
                actual: ContentDigest::new(crate::digest::DigestAlgorithm::Sha256, computed),
            });
        }

        // 3. Verify magic header
        if payload[..8] != NEGATIVE_EVIDENCE_LEDGER_MAGIC {
            return Err(NegativeEvidenceError::CorruptMagic);
        }

        // 4. Verify format version (refuse unknown versions; never guess)
        let mut ver_bytes = [0u8; 4];
        ver_bytes.copy_from_slice(&payload[8..12]);
        let version = u32::from_be_bytes(ver_bytes);
        if version != NEGATIVE_EVIDENCE_FORMAT_VERSION {
            return Err(NegativeEvidenceError::UnknownVersion { version });
        }

        // 5. Read entry count
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&payload[12..16]);
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count > MAX_NEGATIVE_ENTRIES {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("entry count {count} exceeds limit {MAX_NEGATIVE_ENTRIES}"),
            });
        }

        // 6. Decode length-prefixed entries
        let mut cursor = 16;
        let mut entries: Vec<NegativeEvidenceEntry> = Vec::with_capacity(count);

        for index in 0..count {
            if cursor + 4 > payload_len {
                return Err(NegativeEvidenceError::Truncated);
            }
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&payload[cursor..cursor + 4]);
            let entry_len = u32::from_be_bytes(len_bytes) as usize;
            cursor += 4;

            if cursor + entry_len > payload_len {
                return Err(NegativeEvidenceError::Truncated);
            }
            let entry_slice = &payload[cursor..cursor + entry_len];
            cursor += entry_len;

            let mut decoder = CanonicalDecoder::new(entry_slice);
            let entry = NegativeEvidenceEntry::decode_canonical(&mut decoder).map_err(|err| {
                match err {
                    ContractError::NonCanonicalOrdering => NegativeEvidenceError::NonCanonicalSet {
                        detail: format!(
                            "entry #{index}: set elements must be strictly increasing without duplicates"
                        ),
                    },
                    other => NegativeEvidenceError::MalformedEntry {
                        detail: format!("entry #{index}: {other}"),
                    },
                }
            })?;
            if !decoder.is_empty() {
                return Err(NegativeEvidenceError::TrailingBytes {
                    detail: format!(
                        "entry #{index} has {} unparsed trailing bytes",
                        decoder.remaining()
                    ),
                });
            }
            entry.validate()?;

            if let Some(prior) = entries
                .last()
                .map(|e: &NegativeEvidenceEntry| e.neg_id.clone())
                && neg_id_value("neg_id", &entry.neg_id)? <= neg_id_value("neg_id", &prior)?
            {
                if entry.neg_id == prior {
                    return Err(NegativeEvidenceError::DuplicateEntryId {
                        neg_id: entry.neg_id.clone(),
                    });
                }
                return Err(NegativeEvidenceError::NonCanonicalOrder {
                    prior,
                    current: entry.neg_id.clone(),
                });
            }
            check_supersession(&entry, &entries)?;
            entries.push(entry);
        }

        if cursor != payload_len {
            return Err(NegativeEvidenceError::TrailingBytes {
                detail: format!(
                    "{} unparsed trailing bytes after the last entry",
                    payload_len - cursor
                ),
            });
        }

        Ok(Self { entries })
    }

    /// Formats the complete ledger as a JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut entries_json = String::from("[");
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                entries_json.push(',');
            }
            entries_json.push_str(&entry.to_json());
        }
        entries_json.push(']');

        format!(
            "{{\"schema\":\"{}\",\"version\":{},\"entryCount\":{},\"entries\":{}}}",
            SCHEMA_NEGATIVE_EVIDENCE_LEDGER,
            NEGATIVE_EVIDENCE_FORMAT_VERSION,
            self.entries.len(),
            entries_json
        )
    }
}

/// Coverage domain claimed by the architectural-constraint seed entries.
const ARCHITECTURAL_CONSTRAINTS_DOMAIN: &str = "domain:negative-evidence:architectural-constraints";

/// Date and commit that recorded the seed doctrine (`docs/NEGATIVE_EVIDENCE.md` was introduced
/// by d82ac04 on 2026-08-31). No implementation experiment produced these results.
const SEED_DATE_COMMIT: &str = "2026-08-31 d82ac04";

/// Verbatim doctrine of one seed entry from `docs/NEGATIVE_EVIDENCE.md`.
struct SeedDoctrine {
    neg_id: &'static str,
    hypothesis: &'static str,
    reasoning: &'static str,
    finding: &'static str,
    decision: NegativeDecision,
    decision_text: &'static str,
    revival_condition: &'static str,
    corpus: &'static str,
    device_model: &'static str,
    policy: &'static str,
    failure_domains: &'static [&'static str],
}

const NEG001_DOCTRINE: SeedDoctrine = SeedDoctrine {
    neg_id: "NEG-001",
    hypothesis: "the drone can be treated as a normal officially supported DJI Mobile SDK source.",
    reasoning: "Architectural dependency on proprietary mobile SDK introduces uncertified hardware and platform coupling.",
    finding: "current public supported-product documentation does not establish DJI Flip support.",
    decision: NegativeDecision::Narrow,
    decision_text: "recorded-file import and authorized capture-bridge experiments only; manual flight; an unsupported result is acceptable.",
    revival_condition: "an official compatible SDK/product listing or a repeatable, owner-authorized, supportable capture surface.",
    corpus: "public supported-product documentation (architecture research)",
    device_model: "DJI Flip",
    policy: "standards-first",
    failure_domains: &["camera-capture", "mobile-sdk", "vendor-coupling"],
};

const NEG002_DOCTRINE: SeedDoctrine = SeedDoctrine {
    neg_id: "NEG-002",
    hypothesis: "a consumer camera advertised with Wi-Fi/cloud viewing has a stable local stream.",
    reasoning: "Proprietary vendor app access lacks open standard guarantees and requires non-standard protocol reverse-engineering.",
    finding: "public owner-facing documentation for target proprietary products does not establish a durable ONVIF/RTSP contract.",
    decision: NegativeDecision::Reject,
    decision_text: "standards-first adapters; vendor paths remain exact-tuple interoperability-lab work.",
    revival_condition: "official local API/profile support or a qualified owner-authorized adapter matrix.",
    corpus: "public owner-facing documentation for target proprietary products (architecture research)",
    device_model: "target proprietary Wi-Fi/cloud consumer cameras",
    policy: "standards-first-adapters",
    failure_domains: &["cloud-relay", "reverse-engineered-protocol", "vendor-api"],
};

const NEG003_DOCTRINE: SeedDoctrine = SeedDoctrine {
    neg_id: "NEG-003",
    hypothesis: "the newest large multimodal model can replace detection, tracking, geometry, and calibrated event policy.",
    reasoning: "One model would couple detection, tracking, geometry, calibrated event policy, latency, licensing, temporal grounding, reproducibility, and isolation into a single failure domain.",
    finding: "latency, licensing, temporal grounding, reproducibility, and failure isolation differ by task; no single current candidate establishes the complete contract.",
    decision: NegativeDecision::Reject,
    decision_text: "progressive model cascade with immutable generations and held-out event gauntlets.",
    revival_condition: "a candidate passes every task, license, cost, privacy, and deterministic boundary against the decomposed incumbent under the same workload.",
    corpus: "architecture research (no sealed workload evaluated)",
    device_model: "frontier multimodal model candidates",
    policy: "decomposed-model-cascade",
    failure_domains: &[
        "deterministic-boundary",
        "monolithic-vlm",
        "temporal-grounding",
    ],
};

const SEED_DOCTRINE: [&SeedDoctrine; 3] = [&NEG001_DOCTRINE, &NEG002_DOCTRINE, &NEG003_DOCTRINE];

/// Builds a seed entry exactly as the doctrine records it: not locally certified, with an
/// explicitly uncovered witness, no artifact or proof digest, and no local reproduction.
fn seed_entry(doctrine: &SeedDoctrine) -> NegativeEvidenceEntry {
    let claimed_domain = ARCHITECTURAL_CONSTRAINTS_DOMAIN.to_string();
    NegativeEvidenceEntry {
        neg_id: doctrine.neg_id.to_string(),
        date_commit: SEED_DATE_COMMIT.to_string(),
        hypothesis: doctrine.hypothesis.to_string(),
        reasoning: doctrine.reasoning.to_string(),
        setup: NegativeEvidenceSetup {
            corpus: doctrine.corpus.to_string(),
            device_model: doctrine.device_model.to_string(),
            firmware_version: NOT_EVALUATED.to_string(),
            platform: NOT_EVALUATED.to_string(),
            policy: doctrine.policy.to_string(),
            command: NOT_LOCALLY_REPRODUCIBLE.to_string(),
            artifact_digest: None,
        },
        measured_result: doctrine.finding.to_string(),
        decision: doctrine.decision,
        decision_text: doctrine.decision_text.to_string(),
        shared_failure_domains: label_set(doctrine.failure_domains),
        revival_condition: doctrine.revival_condition.to_string(),
        // The doctrine records that public documentation "does not establish" support and that no
        // experiment ran: unknown (KSTATE-003) and disfavored, not estimated or refuted. The
        // finding comes from vendor documentation; the decision is policy.
        knowledge_state: KnowledgeState::Unknown,
        provenance_class: ProvenanceClass::VendorClaimed,
        decision_provenance: ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Disfavored,
        coverage_witness: CoverageWitness {
            anchor: LedgerAnchor::genesis("site:fss:negative-evidence"),
            authorized_domain: BTreeSet::from([claimed_domain.clone()]),
            observed_domain: BTreeSet::new(),
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Unknown,
            completeness: Completeness::Unknown,
            negative_predicate: negative_predicate_for(&claimed_domain, doctrine.neg_id),
            stop_reason: CoverageStopReason::Unsupported,
            authorized_generation: 0,
            observed_generation: 0,
        },
        claimed_domain,
        certification: EvidenceCertification::NotLocallyCertified {
            source: format!(
                "{NEGATIVE_EVIDENCE_DOCTRINE_PATH} {} (architecture research recorded at d82ac04; no implementation experiment run)",
                doctrine.neg_id
            ),
        },
        supersedes: None,
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: None,
        evidence_reference: None,
        reproduction_command: NOT_LOCALLY_REPRODUCIBLE.to_string(),
    }
}

/// Constructs the normative initial negative-evidence ledger containing the 3 seed entries:
/// - NEG-001: DJI Flip SDK non-dependency ([`NegativeDecision::Narrow`])
/// - NEG-002: Standards-first camera access ([`NegativeDecision::Reject`])
/// - NEG-003: Decomposed model-cascade constraint ([`NegativeDecision::Reject`])
///
/// Every seed field that `docs/NEGATIVE_EVIDENCE.md` records (hypothesis, finding, decision,
/// revival) is stored verbatim. The seeds are [`EvidenceCertification::NotLocallyCertified`].
pub fn initial_negative_evidence_ledger() -> Result<NegativeEvidenceLedger, NegativeEvidenceError> {
    let mut ledger = NegativeEvidenceLedger::new();
    for doctrine in SEED_DOCTRINE {
        ledger.append(seed_entry(doctrine))?;
    }
    ledger.verify()?;
    Ok(ledger)
}

/// Errors originating within the negative-evidence ledger domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeEvidenceError {
    /// Negative evidence lacks a certifying coverage witness (none supplied, or an entry that is
    /// not locally certified claims certified knowledge).
    MissingCoverageWitness {
        /// Failure detail.
        detail: String,
    },
    /// Negative evidence evaluated during a coverage gap; absence during gap is never evidence.
    CoverageGap {
        /// Continuity classification observed.
        continuity: CoverageContinuity,
    },
    /// Coverage witness does not certify complete absence.
    UncertifiedCoverage {
        /// Failure detail.
        detail: String,
    },
    /// Coverage witness certifies absence for a different claim than this entry's.
    WitnessNotBound {
        /// Entry whose witness is not bound to it.
        neg_id: String,
        /// Failure detail.
        detail: String,
    },
    /// Binary format version is unknown or unsupported (refused; never guessed).
    UnknownVersion {
        /// Encountered format version.
        version: u32,
    },
    /// Binary magic header does not match `FSSNEG01`.
    CorruptMagic,
    /// Binary trailing SHA-256 checksum mismatch.
    CorruptChecksum {
        /// Recorded checksum in trailer.
        expected: ContentDigest,
        /// Computed checksum over header and payload.
        actual: ContentDigest,
    },
    /// Entries are not in strictly increasing canonical order by stable ID.
    NonCanonicalOrder {
        /// Preceding entry identifier.
        prior: String,
        /// Current out-of-order identifier.
        current: String,
    },
    /// A decoded set is not strictly increasing (out-of-order or duplicate element).
    NonCanonicalSet {
        /// Failure detail.
        detail: String,
    },
    /// Duplicate stable identifier encountered in ledger.
    DuplicateEntryId {
        /// Colliding identifier.
        neg_id: String,
    },
    /// Input or field exceeds declared capacity limits.
    InputOversized {
        /// Failure detail.
        detail: String,
    },
    /// Attempted operation on or with a permanently tombstoned negative-evidence entry.
    EntryTombstoned {
        /// Tombstoned identifier.
        neg_id: String,
    },
    /// Candidate retry or promotion refused because revival condition is not evidenced.
    RevivalConditionUnmet {
        /// Candidate identifier.
        neg_id: String,
        /// Documented revival condition that must be met.
        condition: String,
        /// Why the supplied evidence does not satisfy it.
        reason: String,
    },
    /// Binary input truncated.
    Truncated,
    /// Binary input carries unparsed trailing bytes after a complete structure.
    TrailingBytes {
        /// Failure detail.
        detail: String,
    },
    /// Invalid identifier or format string.
    InvalidIdentifier(String),
    /// Entry or ledger semantic validation failed.
    Validation {
        /// Failure detail.
        detail: String,
    },
    /// Locally certified evidence lacks its proof hash, its retained evidence reference, or the
    /// evidence its knowledge state requires.
    MissingProof {
        /// Failure detail.
        detail: String,
    },
    /// Encoded entry bytes carry an unknown tag, an invalid value, or an out-of-bound count.
    MalformedEntry {
        /// Failure detail.
        detail: String,
    },
    /// The ledger file an init would create already exists.
    LedgerExists {
        /// Ledger path.
        path: String,
    },
    /// The ledger file does not exist.
    LedgerNotFound {
        /// Ledger path.
        path: String,
    },
    /// The ledger lock file is held by another writer or left stale; it is never broken
    /// automatically.
    LedgerLocked {
        /// Failure detail.
        detail: String,
    },
    /// The ledger changed between read and publish on every bounded attempt.
    ConcurrentModification {
        /// Failure detail.
        detail: String,
    },
    /// The ledger file has a link count other than one, so an atomic publish would update a
    /// single name and leave every other hard-linked name with the old ledger (a fork).
    LedgerHardLinked {
        /// Ledger path as given.
        path: String,
        /// Observed link count.
        links: u64,
    },
    /// Underlying contract or canonical serialization error.
    Contract(ContractError),
    /// I/O error during file read or write.
    Io(String),
}

impl NegativeEvidenceError {
    /// Returns the stable machine-readable error identity conforming to `registries/ERRORS.md`.
    #[must_use]
    pub const fn error_id(&self) -> &'static str {
        match self {
            Self::MissingCoverageWitness { .. } => "ERR-NEG-MISSING-COVERAGE-001",
            Self::CoverageGap { .. } => "ERR-NEG-COVERAGE-GAP-001",
            Self::UncertifiedCoverage { .. } | Self::WitnessNotBound { .. } => {
                "ERR-NEG-UNCERTIFIED-COVERAGE-001"
            }
            Self::UnknownVersion { .. } => "ERR-NEG-UNKNOWN-VERSION-001",
            Self::CorruptMagic
            | Self::CorruptChecksum { .. }
            | Self::Truncated
            | Self::TrailingBytes { .. } => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::NonCanonicalOrder { .. } | Self::NonCanonicalSet { .. } => {
                "ERR-NEG-NON-CANONICAL-ORDER-001"
            }
            Self::DuplicateEntryId { .. } => "ERR-NEG-DUPLICATE-ID-001",
            Self::InputOversized { .. } => "ERR-NEG-INPUT-OVERSIZED-001",
            Self::EntryTombstoned { .. } => "ERR-NEG-ENTRY-TOMBSTONED-001",
            Self::RevivalConditionUnmet { .. } => "ERR-NEG-REVIVAL-UNMET-001",
            Self::InvalidIdentifier(_) | Self::Validation { .. } => "ERR-NEG-VALIDATION-FAILED-001",
            Self::MissingProof { .. } => "ERR-NEG-MISSING-PROOF-001",
            Self::MalformedEntry { .. } => "ERR-NEG-MALFORMED-ENTRY-001",
            Self::LedgerExists { .. } => "ERR-NEG-LEDGER-EXISTS-001",
            Self::LedgerNotFound { .. } => "ERR-NEG-LEDGER-NOT-FOUND-001",
            Self::LedgerLocked { .. } => "ERR-NEG-LEDGER-LOCKED-001",
            Self::ConcurrentModification { .. } => "ERR-NEG-CONCURRENT-MODIFICATION-001",
            Self::LedgerHardLinked { .. } => "ERR-NEG-LEDGER-HARD-LINKED-001",
            Self::Contract(_) | Self::Io(_) => "ERR-OP-EXECUTION-FAILED-001",
        }
    }
}

impl fmt::Display for NegativeEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCoverageWitness { detail } => {
                write!(
                    f,
                    "negative evidence entry lacks a certifying coverage witness: absence without coverage witness is never evidence ({detail})"
                )
            }
            Self::CoverageGap { continuity } => {
                write!(
                    f,
                    "coverage gap detected ({continuity:?}); absence during a gap is never evidence"
                )
            }
            Self::UncertifiedCoverage { detail } => {
                write!(f, "uncertified coverage: {detail}")
            }
            Self::WitnessNotBound { neg_id, detail } => {
                write!(
                    f,
                    "coverage witness is not bound to entry '{neg_id}': {detail}"
                )
            }
            Self::UnknownVersion { version } => {
                write!(
                    f,
                    "unknown ledger format version {version}; refusing unknown version"
                )
            }
            Self::CorruptMagic => {
                write!(f, "corrupt magic header; expected FSSNEG01")
            }
            Self::CorruptChecksum { expected, actual } => {
                write!(
                    f,
                    "corrupt ledger checksum; expected {expected}, actual {actual}"
                )
            }
            Self::NonCanonicalOrder { prior, current } => {
                write!(
                    f,
                    "entries not in strictly increasing canonical order: '{prior}' followed by '{current}'"
                )
            }
            Self::NonCanonicalSet { detail } => {
                write!(f, "non-canonical set encoding: {detail}")
            }
            Self::DuplicateEntryId { neg_id } => {
                write!(f, "duplicate negative evidence identifier '{neg_id}'")
            }
            Self::InputOversized { detail } => {
                write!(f, "input oversized: {detail}")
            }
            Self::EntryTombstoned { neg_id } => {
                write!(f, "negative evidence entry '{neg_id}' is tombstoned")
            }
            Self::RevivalConditionUnmet {
                neg_id,
                condition,
                reason,
            } => {
                write!(
                    f,
                    "candidate '{neg_id}' revival condition unmet ({reason}); requires: {condition}"
                )
            }
            Self::Truncated => write!(f, "binary ledger input is truncated"),
            Self::TrailingBytes { detail } => {
                write!(f, "non-canonical ledger encoding: {detail}")
            }
            Self::InvalidIdentifier(detail) => write!(f, "invalid identifier: {detail}"),
            Self::Validation { detail } => {
                write!(f, "negative evidence validation failed: {detail}")
            }
            Self::MissingProof { detail } => {
                write!(f, "negative evidence proof missing: {detail}")
            }
            Self::MalformedEntry { detail } => {
                write!(f, "malformed ledger entry: {detail}")
            }
            Self::LedgerExists { path } => {
                write!(
                    f,
                    "ledger file '{path}' already exists; init never overwrites a ledger"
                )
            }
            Self::LedgerNotFound { path } => {
                write!(
                    f,
                    "ledger file '{path}' does not exist; create it with `fss negative-evidence init --path {path}`"
                )
            }
            Self::LedgerLocked { detail } => write!(f, "ledger locked: {detail}"),
            Self::ConcurrentModification { detail } => {
                write!(f, "concurrent ledger modification: {detail}")
            }
            Self::LedgerHardLinked { path, links } => write!(
                f,
                "ledger file '{path}' has {links} hard links; an append would update one name and leave the others with the old ledger, so it is refused (keep a single name and use a symlink for aliases)"
            ),
            Self::Contract(err) => write!(f, "contract error: {err}"),
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for NegativeEvidenceError {}

impl From<ContractError> for NegativeEvidenceError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// Helper function to escape strings for RFC 8259 JSON serialization without external crates.
fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn label_set(labels: &[&str]) -> BTreeSet<String> {
    labels.iter().map(|label| (*label).to_string()).collect()
}

fn join_labels(labels: &BTreeSet<String>) -> String {
    labels
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn json_string_array(labels: &BTreeSet<String>) -> String {
    let items: Vec<String> = labels
        .iter()
        .map(|label| format!("\"{}\"", escape_json(label)))
        .collect();
    format!("[{}]", items.join(","))
}

fn encode_label_set(labels: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u32(labels.len() as u32);
    for label in labels {
        encoder.text(label);
    }
}

fn decode_label_set(
    decoder: &mut CanonicalDecoder<'_>,
    max: usize,
) -> Result<BTreeSet<String>, ContractError> {
    let count = decoder.u32()? as usize;
    if count > max {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut labels = BTreeSet::new();
    for _ in 0..count {
        let label = decoder.text()?.to_string();
        // Canonical sets are encoded strictly increasing. Accepting a duplicate or out-of-order
        // element would let several byte strings decode to the same entry.
        if labels
            .last()
            .is_some_and(|previous: &String| previous >= &label)
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
        labels.insert(label);
    }
    Ok(labels)
}

fn validate_neg_id(field: &str, id: &str) -> Result<(), NegativeEvidenceError> {
    if id.is_empty() {
        return Err(NegativeEvidenceError::InvalidIdentifier(format!(
            "{field} must not be empty"
        )));
    }
    if id.len() > MAX_NEG_ID_LEN {
        return Err(NegativeEvidenceError::InputOversized {
            detail: format!("{field} exceeds {MAX_NEG_ID_LEN} bytes"),
        });
    }
    let Some(digits) = id.strip_prefix("NEG-") else {
        return Err(NegativeEvidenceError::InvalidIdentifier(format!(
            "{field} '{id}' must start with 'NEG-'"
        )));
    };
    if digits.len() < 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NegativeEvidenceError::InvalidIdentifier(format!(
            "{field} '{id}' must be 'NEG-' followed by at least three digits"
        )));
    }
    if digits.len() > 3 && digits.starts_with('0') {
        return Err(NegativeEvidenceError::InvalidIdentifier(format!(
            "{field} '{id}' is not canonical: leading zeros only pad to three digits"
        )));
    }
    if digits.len() > MAX_NEG_ID_DIGITS {
        return Err(NegativeEvidenceError::InputOversized {
            detail: format!("{field} '{id}' has more than {MAX_NEG_ID_DIGITS} digits"),
        });
    }
    Ok(())
}

/// Returns the numeric value of a canonical stable identifier; entries are ordered by it, so
/// `NEG-999` precedes `NEG-1000`.
pub fn neg_id_value(field: &str, id: &str) -> Result<u64, NegativeEvidenceError> {
    validate_neg_id(field, id)?;
    id.get("NEG-".len()..)
        .and_then(|digits| digits.parse::<u64>().ok())
        .ok_or_else(|| NegativeEvidenceError::InputOversized {
            detail: format!("{field} '{id}' exceeds the numeric identifier range"),
        })
}

/// Returns the exact negative predicate `absence-certified:<claimed_domain>:<NEG-id>`.
#[must_use]
pub fn negative_predicate_for(claimed_domain: &str, neg_id: &str) -> String {
    format!("{NEGATIVE_PREDICATE_PREFIX}:{claimed_domain}:{neg_id}")
}

fn validate_label(field: &str, label: &str) -> Result<(), NegativeEvidenceError> {
    if label.len() > MAX_FAILURE_DOMAIN_LEN {
        return Err(NegativeEvidenceError::InputOversized {
            detail: format!(
                "{field} label '{label}' length exceeds {MAX_FAILURE_DOMAIN_LEN} bytes"
            ),
        });
    }
    if label.trim().is_empty() {
        return Err(NegativeEvidenceError::Validation {
            detail: format!("{field} labels must not be empty"),
        });
    }
    Ok(())
}

fn bound_text(field: &str, value: &str) -> Result<(), NegativeEvidenceError> {
    if value.len() > MAX_NEG_TEXT_LEN {
        return Err(NegativeEvidenceError::InputOversized {
            detail: format!("{field} exceeds {MAX_NEG_TEXT_LEN} bytes"),
        });
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<(), NegativeEvidenceError> {
    bound_text(field, value)?;
    if value.trim().is_empty() {
        return Err(NegativeEvidenceError::Validation {
            detail: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_label_set(
    field: &str,
    labels: &BTreeSet<String>,
    max: usize,
) -> Result<(), NegativeEvidenceError> {
    if labels.len() > max {
        return Err(NegativeEvidenceError::InputOversized {
            detail: format!("{field} count exceeds {max}"),
        });
    }
    for label in labels {
        validate_label(field, label)?;
    }
    Ok(())
}

/// Supersession is linked and append-only: the superseded entry must already precede `entry`.
fn check_supersession(
    entry: &NegativeEvidenceEntry,
    earlier: &[NegativeEvidenceEntry],
) -> Result<(), NegativeEvidenceError> {
    if let Some(target) = &entry.supersedes
        && !earlier.iter().any(|prior| &prior.neg_id == target)
    {
        return Err(NegativeEvidenceError::Validation {
            detail: format!(
                "entry '{}' supersedes '{target}', which is not an earlier entry of this ledger",
                entry.neg_id
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(index: usize) -> Result<NegativeEvidenceEntry, Box<dyn std::error::Error>> {
        initial_negative_evidence_ledger()?
            .entries()
            .get(index)
            .cloned()
            .ok_or_else(|| format!("seed #{index} missing").into())
    }

    #[test]
    fn verify_refuses_out_of_order_entries() -> Result<(), Box<dyn std::error::Error>> {
        let ledger = NegativeEvidenceLedger {
            entries: vec![seed(1)?, seed(0)?, seed(2)?],
        };
        assert_eq!(
            ledger.verify(),
            Err(NegativeEvidenceError::NonCanonicalOrder {
                prior: "NEG-002".to_string(),
                current: "NEG-001".to_string(),
            })
        );
        Ok(())
    }

    #[test]
    fn verify_refuses_duplicate_entries() -> Result<(), Box<dyn std::error::Error>> {
        let ledger = NegativeEvidenceLedger {
            entries: vec![seed(0)?, seed(0)?],
        };
        assert_eq!(
            ledger.verify(),
            Err(NegativeEvidenceError::DuplicateEntryId {
                neg_id: "NEG-001".to_string(),
            })
        );
        Ok(())
    }

    fn seed_with_id(
        index: usize,
        id: &str,
    ) -> Result<NegativeEvidenceEntry, Box<dyn std::error::Error>> {
        let mut entry = seed(index)?;
        entry.neg_id = id.to_string();
        entry.coverage_witness.negative_predicate = entry.expected_negative_predicate();
        Ok(entry)
    }

    #[test]
    fn verify_orders_by_numeric_value() -> Result<(), Box<dyn std::error::Error>> {
        let ordered = NegativeEvidenceLedger {
            entries: vec![seed_with_id(0, "NEG-999")?, seed_with_id(1, "NEG-1000")?],
        };
        assert_eq!(ordered.verify(), Ok(()));
        let reversed = NegativeEvidenceLedger {
            entries: vec![seed_with_id(1, "NEG-1000")?, seed_with_id(0, "NEG-999")?],
        };
        assert_eq!(
            reversed.verify(),
            Err(NegativeEvidenceError::NonCanonicalOrder {
                prior: "NEG-1000".to_string(),
                current: "NEG-999".to_string(),
            })
        );
        Ok(())
    }

    #[test]
    fn verify_refuses_dangling_supersession() -> Result<(), Box<dyn std::error::Error>> {
        // NEG-003 claims to supersede NEG-002, but NEG-002 is absent from this ledger.
        let mut superseding = seed(2)?;
        superseding.supersedes = Some("NEG-002".to_string());
        assert!(superseding.validate().is_ok());
        let ledger = NegativeEvidenceLedger {
            entries: vec![seed(0)?, superseding],
        };
        let err = ledger
            .verify()
            .err()
            .ok_or("dangling supersession must be refused")?;
        assert_eq!(err.error_id(), "ERR-NEG-VALIDATION-FAILED-001");
        Ok(())
    }
}
