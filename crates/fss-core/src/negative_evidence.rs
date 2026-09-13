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
//! 4. Initial seed entries for NEG-001, NEG-002, and NEG-003 preserved with normative decisions
//!    (`Narrow`, `Reject`, `Reject`) and explicit revival conditions.
//! 5. Unknown format versions refuse; never guess.

use core::fmt;
use std::collections::BTreeSet;

use crate::acquisition::Neg001ScenarioLog;
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
pub const NEGATIVE_EVIDENCE_FORMAT_VERSION: u32 = 1;

/// Pinned freeze digest of the initial canonical binary negative-evidence ledger containing NEG-001, NEG-002, and NEG-003.
pub const INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST: &str =
    "sha256:a79f59ef08070ea6ba93b06df1a67efabfaaefefa78aaa38c3bbe388f4c1ee8e";

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

/// Type alias aligning with the semantic specification.
pub type EvidenceAnchor = LedgerAnchor;

/// Returns the stable string representation of a [`ProvenanceClass`].
#[must_use]
pub const fn provenance_class_as_str(p: ProvenanceClass) -> &'static str {
    match p {
        ProvenanceClass::Observed => "observed",
        ProvenanceClass::Derived => "derived",
        ProvenanceClass::Predicted => "predicted",
        ProvenanceClass::Remembered => "remembered",
        ProvenanceClass::OperatorAsserted => "operator_asserted",
        ProvenanceClass::VendorClaimed => "vendor_claimed",
        ProvenanceClass::Policy => "policy",
    }
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

/// One normative negative-evidence entry in the canonical ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeEvidenceEntry {
    /// Stable constraint identifier (`NEG-###`).
    pub neg_id: String,
    /// Date and commit context of the evaluation.
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
    /// Shared failure domains preventing promotion.
    pub shared_failure_domains: BTreeSet<String>,
    /// Explicit, falsifiable condition required to repeat or revive this candidate.
    pub revival_condition: String,
    /// Epistemic state (preserved as orthogonal field, never flattened into confidence).
    pub knowledge_state: KnowledgeState,
    /// Provenance classification (preserved as orthogonal field).
    pub provenance_class: ProvenanceClass,
    /// Hypothesis disposition within investigation.
    pub disposition: HypothesisDisposition,
    /// Mandatory certifying witness; absence during a gap is NEVER evidence.
    pub coverage_witness: CoverageWitness,
    /// Whether this entry has been permanently tombstoned.
    pub is_tombstone: bool,
    /// Semantic tombstone reason if tombstoned.
    pub tombstone_reason: Option<TombstoneReason>,
    /// Cryptographic proof hash binding the result.
    pub proof_hash: Option<ContentDigest>,
    /// Secret-free reproduction command.
    pub reproduction_command: String,
}

impl NegativeEvidenceEntry {
    /// Constructs a negative evidence entry bridging from [`Neg001ScenarioLog`].
    pub fn from_neg001_scenario_log(
        log: &Neg001ScenarioLog,
        coverage_witness: CoverageWitness,
    ) -> Result<Self, NegativeEvidenceError> {
        let setup = NegativeEvidenceSetup {
            corpus: "reference-architecture".to_string(),
            device_model: log.tuple.device_model.clone(),
            firmware_version: log.tuple.firmware_version.clone(),
            platform: log.tuple.host_platform.clone(),
            policy: "standards-first".to_string(),
            command: log.reproduction_command.clone(),
            artifact_digest: Some(log.registry_digest),
        };
        let mut domains = BTreeSet::new();
        domains.insert("camera-capture".to_string());
        domains.insert("mobile-sdk".to_string());
        domains.insert("vendor-coupling".to_string());

        let entry = Self {
            neg_id: log.neg_id.to_string(),
            date_commit: "2026-08-31 47ce055".to_string(),
            hypothesis: "The drone can be treated as a normal officially supported DJI Mobile SDK source.".to_string(),
            reasoning: "Architectural dependency on proprietary mobile SDK introduces uncertified hardware and platform coupling.".to_string(),
            setup,
            measured_result: "Current public supported-product documentation does not establish DJI Flip support; adapter accepted = false, streaming = false, readiness = unsupported.".to_string(),
            decision: NegativeDecision::Narrow,
            shared_failure_domains: domains,
            revival_condition: "An official compatible SDK/product listing or a repeatable, owner-authorized, supportable capture surface.".to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance_class: ProvenanceClass::Policy,
            disposition: HypothesisDisposition::Refuted,
            coverage_witness,
            is_tombstone: false,
            tombstone_reason: None,
            proof_hash: Some(log.proof_hash),
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
        // ID format check: must start with "NEG-" followed by digits
        if self.neg_id.is_empty() || self.neg_id.len() > MAX_NEG_ID_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("neg_id length must be between 1 and {MAX_NEG_ID_LEN}"),
            });
        }
        if !self.neg_id.starts_with("NEG-") {
            return Err(NegativeEvidenceError::InvalidIdentifier(format!(
                "neg_id '{}' must start with 'NEG-'",
                self.neg_id
            )));
        }
        let id_suffix = &self.neg_id["NEG-".len()..];
        if id_suffix.is_empty() || !id_suffix.chars().all(|c| c.is_ascii_digit()) {
            return Err(NegativeEvidenceError::InvalidIdentifier(format!(
                "neg_id '{}' must have numeric digits after 'NEG-'",
                self.neg_id
            )));
        }

        // Length checks
        if self.hypothesis.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("hypothesis exceeds {MAX_NEG_TEXT_LEN} bytes"),
            });
        }
        if self.reasoning.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("reasoning exceeds {MAX_NEG_TEXT_LEN} bytes"),
            });
        }
        if self.measured_result.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("measured_result exceeds {MAX_NEG_TEXT_LEN} bytes"),
            });
        }
        if self.revival_condition.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("revival_condition exceeds {MAX_NEG_TEXT_LEN} bytes"),
            });
        }
        if self.reproduction_command.len() > MAX_NEG_TEXT_LEN {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("reproduction_command exceeds {MAX_NEG_TEXT_LEN} bytes"),
            });
        }
        self.setup.validate()?;

        // Shared failure domains bounds
        if self.shared_failure_domains.len() > MAX_FAILURE_DOMAINS {
            return Err(NegativeEvidenceError::InputOversized {
                detail: format!("shared_failure_domains count exceeds {MAX_FAILURE_DOMAINS}"),
            });
        }
        for domain in &self.shared_failure_domains {
            if domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(NegativeEvidenceError::InputOversized {
                    detail: format!(
                        "domain '{domain}' length exceeds {MAX_FAILURE_DOMAIN_LEN} bytes"
                    ),
                });
            }
        }

        // Tombstone consistency
        if self.is_tombstone {
            if self.tombstone_reason.is_none() {
                return Err(NegativeEvidenceError::EntryTombstoned {
                    neg_id: self.neg_id.clone(),
                });
            }
        } else if self.tombstone_reason.is_some() {
            return Err(NegativeEvidenceError::InputOversized {
                detail: "active entry must not have tombstone_reason".to_string(),
            });
        }

        // Coverage witness absence certification:
        // Absence during a gap or uncertified domain is NEVER evidence.
        if !self.is_tombstone {
            match self.coverage_witness.continuity {
                CoverageContinuity::Continuous => {}
                CoverageContinuity::Gapped => {
                    return Err(NegativeEvidenceError::CoverageGap {
                        continuity: CoverageContinuity::Gapped,
                    });
                }
                CoverageContinuity::Unknown => {
                    return Err(NegativeEvidenceError::CoverageGap {
                        continuity: CoverageContinuity::Unknown,
                    });
                }
            }
            if !self.coverage_witness.certifies_absence() {
                return Err(NegativeEvidenceError::UncertifiedCoverage {
                    detail: format!(
                        "coverage witness for '{}' does not certify absence (continuity: {:?}, completeness: {:?}, stop_reason: {:?})",
                        self.neg_id,
                        self.coverage_witness.continuity,
                        self.coverage_witness.completeness,
                        self.coverage_witness.stop_reason,
                    ),
                });
            }
        }

        Ok(())
    }

    /// Converts this entry into an [`EvidenceDelta`] for canonical ledger publication.
    pub fn to_evidence_delta(
        &self,
        generation: u64,
        plane: Plane,
    ) -> Result<EvidenceDelta, NegativeEvidenceError> {
        let object_id = ObjectId::parse(&self.neg_id).map_err(NegativeEvidenceError::Contract)?;
        let payload_digest = self.canonical_digest();
        let witness_digest = Some(self.coverage_witness.witness_digest());
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
        let mut domains_json = String::from("[");
        for (i, d) in self.shared_failure_domains.iter().enumerate() {
            if i > 0 {
                domains_json.push(',');
            }
            domains_json.push('"');
            domains_json.push_str(&escape_json(d));
            domains_json.push('"');
        }
        domains_json.push(']');

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

        format!(
            "{{\"negId\":\"{}\",\"dateCommit\":\"{}\",\"hypothesis\":\"{}\",\"reasoning\":\"{}\",\"setup\":{{\"corpus\":\"{}\",\"deviceModel\":\"{}\",\"firmwareVersion\":\"{}\",\"platform\":\"{}\",\"policy\":\"{}\",\"command\":\"{}\",\"artifactDigest\":{}}},\"measuredResult\":\"{}\",\"decision\":\"{}\",\"sharedFailureDomains\":{},\"revivalCondition\":\"{}\",\"knowledgeState\":\"{}\",\"provenanceClass\":\"{}\",\"disposition\":\"{}\",\"isTombstone\":{},\"tombstoneReason\":{},\"proofHash\":{},\"reproductionCommand\":\"{}\"}}",
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
            domains_json,
            escape_json(&self.revival_condition),
            self.knowledge_state.as_str(),
            provenance_class_as_str(self.provenance_class),
            hypothesis_disposition_as_str(self.disposition),
            self.is_tombstone,
            tombstone_reason_str,
            proof_str,
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
        encoder.u32(self.shared_failure_domains.len() as u32);
        for domain in &self.shared_failure_domains {
            encoder.text(domain);
        }
        encoder.text(&self.revival_condition);
        encoder.text(self.knowledge_state.as_str());
        encoder.text(provenance_class_as_str(self.provenance_class));
        encoder.text(hypothesis_disposition_as_str(self.disposition));
        self.coverage_witness.encode_canonical(encoder);
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
        let domain_count = decoder.u32()? as usize;
        if domain_count > MAX_FAILURE_DOMAINS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut shared_failure_domains = BTreeSet::new();
        for _ in 0..domain_count {
            let domain = decoder.text()?.to_string();
            shared_failure_domains.insert(domain);
        }
        let revival_condition = decoder.text()?.to_string();
        let kstate_str = decoder.text()?;
        let knowledge_state = KnowledgeState::from_name(kstate_str)?;
        let prov_str = decoder.text()?;
        let provenance_class = match prov_str {
            "observed" => ProvenanceClass::Observed,
            "derived" => ProvenanceClass::Derived,
            "predicted" => ProvenanceClass::Predicted,
            "remembered" => ProvenanceClass::Remembered,
            "operator_asserted" => ProvenanceClass::OperatorAsserted,
            "vendor_claimed" => ProvenanceClass::VendorClaimed,
            "policy" => ProvenanceClass::Policy,
            _ => return Err(ContractError::InvalidIdentifier),
        };
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
        let reproduction_command = decoder.text()?.to_string();
        Ok(Self {
            neg_id,
            date_commit,
            hypothesis,
            reasoning,
            setup,
            measured_result,
            decision,
            shared_failure_domains,
            revival_condition,
            knowledge_state,
            provenance_class,
            disposition,
            coverage_witness,
            is_tombstone,
            tombstone_reason,
            proof_hash,
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

    /// Appends a new negative-evidence entry enforcing canonical order, uniqueness, and validity.
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
        if let Some(last) = self.entries.last()
            && entry.neg_id <= last.neg_id
        {
            return Err(NegativeEvidenceError::NonCanonicalOrder {
                prior: last.neg_id.clone(),
                current: entry.neg_id.clone(),
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Evaluates whether a candidate revival request meets the explicit revival condition.
    pub fn verify_revival_condition(
        &self,
        neg_id: &str,
        condition_met: bool,
    ) -> Result<(), NegativeEvidenceError> {
        let entry = self.get(neg_id).ok_or_else(|| {
            NegativeEvidenceError::InvalidIdentifier(format!("entry '{neg_id}' not found"))
        })?;
        if !condition_met {
            return Err(NegativeEvidenceError::RevivalConditionUnmet {
                neg_id: neg_id.to_string(),
                condition: entry.revival_condition.clone(),
            });
        }
        Ok(())
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
                if entry.neg_id <= prev.neg_id {
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
        let mut entries = Vec::with_capacity(count);
        let mut prev_id: Option<String> = None;

        for _ in 0..count {
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

            let entry = NegativeEvidenceEntry::from_canonical_bytes(entry_slice)
                .map_err(NegativeEvidenceError::Contract)?;
            entry.validate()?;

            if let Some(ref prior) = prev_id
                && entry.neg_id <= *prior
            {
                if entry.neg_id == *prior {
                    return Err(NegativeEvidenceError::DuplicateEntryId {
                        neg_id: entry.neg_id.clone(),
                    });
                }
                return Err(NegativeEvidenceError::NonCanonicalOrder {
                    prior: prior.clone(),
                    current: entry.neg_id.clone(),
                });
            }
            prev_id = Some(entry.neg_id.clone());
            entries.push(entry);
        }

        if cursor != payload_len {
            return Err(NegativeEvidenceError::InputOversized {
                detail: "trailing unparsed bytes in payload".to_string(),
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

/// Constructs the normative initial negative-evidence ledger containing the 3 seed entries:
/// - NEG-001: DJI Flip SDK non-dependency ([`NegativeDecision::Narrow`])
/// - NEG-002: Standards-first camera access ([`NegativeDecision::Reject`])
/// - NEG-003: Decomposed model-cascade constraint ([`NegativeDecision::Reject`])
pub fn initial_negative_evidence_ledger() -> Result<NegativeEvidenceLedger, NegativeEvidenceError> {
    let mut ledger = NegativeEvidenceLedger::new();

    // NEG-001
    let neg001_witness = CoverageWitness {
        anchor: LedgerAnchor::genesis("site:fss:negative-evidence"),
        authorized_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        observed_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "architectural-violation-absence:NEG-001".to_string(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    };
    let mut neg001_domains = BTreeSet::new();
    neg001_domains.insert("camera-capture".to_string());
    neg001_domains.insert("mobile-sdk".to_string());
    neg001_domains.insert("vendor-coupling".to_string());
    let neg001 = NegativeEvidenceEntry {
        neg_id: "NEG-001".to_string(),
        date_commit: "2026-08-31 47ce055".to_string(),
        hypothesis: "The drone can be treated as a normal officially supported DJI Mobile SDK source.".to_string(),
        reasoning: "Architectural dependency on proprietary mobile SDK introduces uncertified hardware and platform coupling.".to_string(),
        setup: NegativeEvidenceSetup {
            corpus: "reference-architecture".to_string(),
            device_model: "DJI Flip".to_string(),
            firmware_version: "unestablished".to_string(),
            platform: "android/ios".to_string(),
            policy: "standards-first".to_string(),
            command: "cargo test -p fss-core --test dji_flip_capture_route_contract".to_string(),
            artifact_digest: Some(ContentDigest::sha256(b"NEG-001-setup-digest")),
        },
        measured_result: "Current public supported-product documentation does not establish DJI Flip support; adapter accepted = false, streaming = false, readiness = unsupported.".to_string(),
        decision: NegativeDecision::Narrow,
        shared_failure_domains: neg001_domains,
        revival_condition: "An official compatible SDK/product listing or a repeatable, owner-authorized, supportable capture surface.".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance_class: ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Refuted,
        coverage_witness: neg001_witness,
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: Some(ContentDigest::sha256(b"NEG-001-proof-v1")),
        reproduction_command: "cargo test -p fss-core --test dji_flip_capture_route_contract".to_string(),
    };
    ledger.append(neg001)?;

    // NEG-002
    let neg002_witness = CoverageWitness {
        anchor: LedgerAnchor::genesis("site:fss:negative-evidence"),
        authorized_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        observed_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "architectural-violation-absence:NEG-002".to_string(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    };
    let mut neg002_domains = BTreeSet::new();
    neg002_domains.insert("cloud-relay".to_string());
    neg002_domains.insert("reverse-engineered-protocol".to_string());
    neg002_domains.insert("vendor-api".to_string());
    let neg002 = NegativeEvidenceEntry {
        neg_id: "NEG-002".to_string(),
        date_commit: "2026-08-31 47ce055".to_string(),
        hypothesis: "A consumer camera advertised with Wi-Fi/cloud viewing has a stable local stream.".to_string(),
        reasoning: "Proprietary vendor app access lacks open standard guarantees and requires non-standard protocol reverse-engineering.".to_string(),
        setup: NegativeEvidenceSetup {
            corpus: "consumer-camera-matrix".to_string(),
            device_model: "proprietary-wifi-camera".to_string(),
            firmware_version: "vendor-latest".to_string(),
            platform: "proprietary-app".to_string(),
            policy: "standards-first-adapters".to_string(),
            command: "cargo test -p fss-core --test standards_first_adapter_contract".to_string(),
            artifact_digest: Some(ContentDigest::sha256(b"NEG-002-setup-digest")),
        },
        measured_result: "Public owner-facing documentation for target proprietary products does not establish a durable ONVIF/RTSP contract.".to_string(),
        decision: NegativeDecision::Reject,
        shared_failure_domains: neg002_domains,
        revival_condition: "official local API/profile support or a qualified owner-authorized adapter matrix.".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance_class: ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Refuted,
        coverage_witness: neg002_witness,
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: Some(ContentDigest::sha256(b"NEG-002-proof-v1")),
        reproduction_command: "cargo test -p fss-core --test standards_first_adapter_contract".to_string(),
    };
    ledger.append(neg002)?;

    // NEG-003
    let neg003_witness = CoverageWitness {
        anchor: LedgerAnchor::genesis("site:fss:negative-evidence"),
        authorized_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        observed_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "architectural-violation-absence:NEG-003".to_string(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    };
    let mut neg003_domains = BTreeSet::new();
    neg003_domains.insert("deterministic-boundary".to_string());
    neg003_domains.insert("monolithic-vlm".to_string());
    neg003_domains.insert("temporal-grounding".to_string());
    let neg003 = NegativeEvidenceEntry {
        neg_id: "NEG-003".to_string(),
        date_commit: "2026-08-31 47ce055".to_string(),
        hypothesis: "The newest large multimodal model (frontier VLM) can replace detection, tracking, geometry, and calibrated event policy.".to_string(),
        reasoning: "Monolithic VLM architectures fail deterministic boundaries, temporal grounding, latency constraints, and failure isolation.".to_string(),
        setup: NegativeEvidenceSetup {
            corpus: "frontier-vlm-benchmark".to_string(),
            device_model: "frontier-vlm-monolith".to_string(),
            firmware_version: "model-gen-1".to_string(),
            platform: "heterogeneous-gpu".to_string(),
            policy: "decomposed-model-cascade".to_string(),
            command: "cargo test -p fss-core --test model_cascade_contract".to_string(),
            artifact_digest: Some(ContentDigest::sha256(b"NEG-003-setup-digest")),
        },
        measured_result: "Latency, licensing, temporal grounding, reproducibility, and failure isolation differ by task; no single current candidate establishes the complete contract.".to_string(),
        decision: NegativeDecision::Reject,
        shared_failure_domains: neg003_domains,
        revival_condition: "A candidate passes every task, license, cost, privacy, and deterministic boundary against the decomposed incumbent under the same workload.".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance_class: ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Refuted,
        coverage_witness: neg003_witness,
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: Some(ContentDigest::sha256(b"NEG-003-proof-v1")),
        reproduction_command: "cargo test -p fss-core --test model_cascade_contract".to_string(),
    };
    ledger.append(neg003)?;

    ledger.verify()?;
    Ok(ledger)
}

/// Errors originating within the negative-evidence ledger domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeEvidenceError {
    /// Negative evidence entry lacks a certifying coverage witness.
    MissingCoverageWitness,
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
    /// Candidate retry or promotion refused because revival condition is not satisfied.
    RevivalConditionUnmet {
        /// Candidate identifier.
        neg_id: String,
        /// Documented revival condition that must be met.
        condition: String,
    },
    /// Binary input truncated.
    Truncated,
    /// Invalid identifier or format string.
    InvalidIdentifier(String),
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
            Self::MissingCoverageWitness => "ERR-NEG-MISSING-COVERAGE-001",
            Self::CoverageGap { .. } => "ERR-NEG-COVERAGE-GAP-001",
            Self::UncertifiedCoverage { .. } => "ERR-NEG-UNCERTIFIED-COVERAGE-001",
            Self::UnknownVersion { .. } => "ERR-NEG-UNKNOWN-VERSION-001",
            Self::CorruptMagic | Self::CorruptChecksum { .. } | Self::Truncated => {
                "ERR-NEG-CHECKSUM-MISMATCH-001"
            }
            Self::NonCanonicalOrder { .. } => "ERR-NEG-NON-CANONICAL-ORDER-001",
            Self::DuplicateEntryId { .. } => "ERR-NEG-DUPLICATE-ID-001",
            Self::InputOversized { .. } => "ERR-NEG-INPUT-OVERSIZED-001",
            Self::EntryTombstoned { .. } => "ERR-NEG-ENTRY-TOMBSTONED-001",
            Self::RevivalConditionUnmet { .. } => "ERR-NEG-REVIVAL-UNMET-001",
            Self::InvalidIdentifier(_) => "ERR-NEG-INPUT-OVERSIZED-001",
            Self::Contract(_) | Self::Io(_) => "ERR-OP-EXECUTION-FAILED-001",
        }
    }
}

impl fmt::Display for NegativeEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCoverageWitness => {
                write!(
                    f,
                    "negative evidence entry lacks a certifying coverage witness: absence without coverage witness is never evidence"
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
            Self::DuplicateEntryId { neg_id } => {
                write!(f, "duplicate negative evidence identifier '{neg_id}'")
            }
            Self::InputOversized { detail } => {
                write!(f, "input oversized: {detail}")
            }
            Self::EntryTombstoned { neg_id } => {
                write!(f, "negative evidence entry '{neg_id}' is tombstoned")
            }
            Self::RevivalConditionUnmet { neg_id, condition } => {
                write!(
                    f,
                    "candidate '{neg_id}' revival condition unmet; requires: {condition}"
                )
            }
            Self::Truncated => write!(f, "binary ledger input is truncated"),
            Self::InvalidIdentifier(detail) => write!(f, "invalid identifier: {detail}"),
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
