#![forbid(unsafe_code)]
//! World facts and coverage realization (AGT-LAYER-003, INV-063).
//!
//! Authority plane types:
//! - [`WorldFactKind`]
//! - [`WorldFact`]
//! - [`NegativeReadClaim`]
//! - [`NegativeReadOutcome`]
//! - [`evaluate_negative_read`]

use core::str::FromStr;
use std::collections::BTreeSet;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, Plane, ProvenanceClass};
use crate::evidence::CoverageWitness;
use crate::ids::validate_id;
use crate::{ContentDigest, ContractBasis, Generation, LedgerAnchor};

/// Categories of authoritative facts established or observed at one anchor (AGT-LAYER-003).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorldFactKind {
    /// Sensor or device physical observation or hardware state.
    Device,
    /// Spatial calibration or sensor geometry.
    Geometry,
    /// Sensor calibration parameters and valid intervals.
    Calibration,
    /// Certified sensor coverage window or spatial domain.
    Coverage,
    /// Authoritative policy threshold or constraint.
    Policy,
    /// Retention, archive, or custodial state.
    Archive,
    /// Authoritative physical effect outcome or receipt.
    Effect,
}

impl WorldFactKind {
    /// All 7 authoritative world fact kinds.
    pub const ALL: [Self; 7] = [
        Self::Device,
        Self::Geometry,
        Self::Calibration,
        Self::Coverage,
        Self::Policy,
        Self::Archive,
        Self::Effect,
    ];

    /// Returns the stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Geometry => "geometry",
            Self::Calibration => "calibration",
            Self::Coverage => "coverage",
            Self::Policy => "policy",
            Self::Archive => "archive",
            Self::Effect => "effect",
        }
    }

    /// Parses from lowercase name.
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "device" => Ok(Self::Device),
            "geometry" => Ok(Self::Geometry),
            "calibration" => Ok(Self::Calibration),
            "coverage" => Ok(Self::Coverage),
            "policy" => Ok(Self::Policy),
            "archive" => Ok(Self::Archive),
            "effect" => Ok(Self::Effect),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl core::fmt::Display for WorldFactKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WorldFactKind {
    type Err = ContractError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}

impl CanonicalEncode for WorldFactKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for WorldFactKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text)
    }
}

/// An authoritative fact observed or established at one anchor (AGT-LAYER-003, INV-063).
///
/// Output: "Device, geometry, calibration, coverage, policy, archive, and effect facts."
/// Prohibition: "Cannot include unqualified cognition as fact."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldFact {
    /// Stable fact identifier (e.g. `fact:device:cam01:calib`).
    pub fact_id: String,
    /// Category of authoritative fact.
    pub kind: WorldFactKind,
    /// Exact authoritative ledger anchor.
    pub anchor: LedgerAnchor,
    /// Human-readable fact statement.
    pub statement: String,
    /// Epistemic provenance: typed origin of this fact.
    pub provenance: ProvenanceClass,
    /// Digest of source evidence, calibration, or receipt witnessing this fact.
    pub evidence_digest: ContentDigest,
    /// Generation identifier for the active registry or schema.
    pub generation: Generation,
}

impl WorldFact {
    /// Creates and validates a new authoritative world fact.
    pub fn new(
        fact_id: impl Into<String>,
        kind: WorldFactKind,
        anchor: LedgerAnchor,
        statement: impl Into<String>,
        provenance: ProvenanceClass,
        evidence_digest: ContentDigest,
        generation: Generation,
    ) -> Result<Self, ContractError> {
        let fact = Self {
            fact_id: fact_id.into(),
            kind,
            anchor,
            statement: statement.into(),
            provenance,
            evidence_digest,
            generation,
        };
        fact.validate()?;
        Ok(fact)
    }

    /// Validates constitutional invariants for this world fact (INV-063).
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id(&self.fact_id)?;
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::DerivedBeliefMissingAnchor);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        if self.evidence_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        // Prohibition: "Cannot include unqualified cognition as fact."
        // Provenance MUST be Observed directly from physical sensors or chronicle evidence.
        // Derived beliefs, predicted cognition, remembered claims, and vendor claims
        // cannot masquerade as authoritative world facts.
        if self.provenance != ProvenanceClass::Observed {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Returns the agent abstraction layer (`AgentAbstractionLayer::WorldFactsAndCoverage`).
    #[must_use]
    pub const fn layer(&self) -> crate::AgentAbstractionLayer {
        crate::AgentAbstractionLayer::WorldFactsAndCoverage
    }

    /// Returns the semantic plane (`Plane::Authority`).
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Authority
    }
}

impl CanonicalEncode for WorldFact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.fact_id);
        self.kind.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        encoder.text(&self.statement);
        self.provenance.encode_canonical(encoder);
        encoder.digest(self.evidence_digest);
        encoder.u64(self.generation.0);
    }
}

impl CanonicalDecode for WorldFact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let fact_id = decoder.text()?.to_owned();
        let kind = WorldFactKind::decode_canonical(decoder)?;
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let statement = decoder.text()?.to_owned();
        let provenance = ProvenanceClass::decode_canonical(decoder)?;
        let evidence_digest = decoder.digest()?;
        let generation = Generation(decoder.u64()?);
        let fact = Self {
            fact_id,
            kind,
            anchor,
            statement,
            provenance,
            evidence_digest,
            generation,
        };
        fact.validate()?;
        Ok(fact)
    }
}

/// Authority-side source providing the authoritative current ledger anchor (INV-063).
///
/// Per AGENTS.md Prime Directive:
/// - Authority, cognition, and effect planes are type-distinct.
/// - Negative reads require a coverage witness verified against the authority plane.
/// - The current anchor must originate from the authority plane rather than an arbitrary caller argument.
pub trait CurrentAnchorSource {
    /// Returns the authoritative current ledger anchor.
    fn current_anchor(&self) -> &LedgerAnchor;
}

/// An explicit authority-plane anchor token proving current ledger state (INV-063).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityAnchor {
    anchor: LedgerAnchor,
}

impl AuthorityAnchor {
    /// Constructs an authoritative anchor token witnessing the given ledger anchor.
    pub fn from_authority(anchor: LedgerAnchor) -> Result<Self, ContractError> {
        if anchor.site_lineage.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self { anchor })
    }

    /// Returns a reference to the underlying ledger anchor.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

impl CurrentAnchorSource for AuthorityAnchor {
    fn current_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

/// Authority context binding an authoritative [`ContractBasis`] and current anchor (INV-063).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityContext<'a> {
    /// Active contract basis from the authority plane.
    pub contract_basis: &'a ContractBasis,
    /// Authoritative current anchor.
    pub anchor: LedgerAnchor,
}

impl<'a> AuthorityContext<'a> {
    /// Creates a new authority context.
    pub fn new(
        contract_basis: &'a ContractBasis,
        anchor: LedgerAnchor,
    ) -> Result<Self, ContractError> {
        if anchor.site_lineage.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            contract_basis,
            anchor,
        })
    }

    /// Returns a reference to the contract basis.
    #[must_use]
    pub const fn contract_basis(&self) -> &ContractBasis {
        self.contract_basis
    }

    /// Returns a reference to the anchor.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

impl<'a> CurrentAnchorSource for AuthorityContext<'a> {
    fn current_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

impl CurrentAnchorSource for (&ContractBasis, &LedgerAnchor) {
    fn current_anchor(&self) -> &LedgerAnchor {
        self.1
    }
}

/// A query or assertion claiming the absence of an event, intrusion, or entity (INV-063).
///
/// Per AGENTS.md Prime Directive:
/// "Negative reads require CoverageWitness; semantic plans require read/write witnesses."
/// "Treating a missing detection during a coverage gap as evidence of absence is prohibited."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeReadClaim {
    /// Stable query or claim identifier.
    pub claim_id: String,
    /// Predicate whose absence is claimed (e.g. `no_unauthorized_intrusion`).
    pub query_predicate: String,
    /// Anchor against which the query is evaluated.
    pub anchor: LedgerAnchor,
    /// Target domain set requiring complete certified coverage.
    pub target_domain: BTreeSet<String>,
    /// Target generation of the active policy or capture system.
    pub target_generation: u64,
    /// Coverage witness provided to prove absence.
    pub coverage_witness: Option<CoverageWitness>,
}

/// Certified outcome of an evaluated negative read query (INV-063).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeReadOutcome {
    /// Stable claim identifier.
    claim_id: String,
    /// Certified negative predicate.
    query_predicate: String,
    /// Authoritative anchor.
    anchor: LedgerAnchor,
    /// Certified domain set.
    certified_domain: BTreeSet<String>,
    /// Pinned witness digest proving absence.
    witness_digest: ContentDigest,
    /// Generation at which coverage was certified.
    generation: u64,
}

impl NegativeReadOutcome {
    /// Constructs a validated negative read outcome directly bound to a certified coverage witness.
    pub fn from_witness<A: CurrentAnchorSource>(
        claim_id: impl Into<String>,
        query_predicate: impl Into<String>,
        anchor: LedgerAnchor,
        certified_domain: BTreeSet<String>,
        witness: &CoverageWitness,
        authority: &A,
        claim_generation: u64,
    ) -> Result<Self, ContractError> {
        let claim_id = claim_id.into();
        let query_predicate = query_predicate.into();
        validate_id(&claim_id)?;
        if query_predicate.is_empty() || query_predicate.len() > 128 {
            return Err(ContractError::InvalidIdentifier);
        }
        if certified_domain.is_empty() || anchor.site_lineage.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        for item in &certified_domain {
            if item.is_empty() || item.len() > 128 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        let current_anchor = authority.current_anchor();
        if current_anchor.site_lineage.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if claim_generation == 0 || witness.authorized_generation != claim_generation {
            return Err(ContractError::GenerationConflict);
        }

        // Witness must certify absence (RM9)
        witness.require_certified_absence()?;

        // 1. Witness anchor must match claim anchor (RM7)
        if witness.anchor != anchor {
            return Err(ContractError::StaleAnchor);
        }

        // 2. Site lineage must match current anchor (RM3)
        if witness.anchor.site_lineage != current_anchor.site_lineage {
            return Err(ContractError::StaleAnchor);
        }

        // 3. Strictly older commit sequence/epoch is stale (RM4)
        if (witness.anchor.ledger_epoch, witness.anchor.commit_sequence)
            < (current_anchor.ledger_epoch, current_anchor.commit_sequence)
        {
            return Err(ContractError::StaleAnchor);
        }

        // 4. Divergent state root / epochs at current sequence, or future anchor (RM8)
        if witness.anchor.state_root != current_anchor.state_root
            || witness.anchor.policy_epoch != current_anchor.policy_epoch
            || witness.anchor.adapter_registry_epoch != current_anchor.adapter_registry_epoch
            || witness.anchor.schema_epoch != current_anchor.schema_epoch
            || witness.anchor.privacy_epoch != current_anchor.privacy_epoch
            || (witness.anchor.ledger_epoch, witness.anchor.commit_sequence)
                > (current_anchor.ledger_epoch, current_anchor.commit_sequence)
        {
            return Err(ContractError::StaleAnchor);
        }

        if witness.negative_predicate != query_predicate {
            return Err(ContractError::CoverageUncertified);
        }
        if !certified_domain.is_subset(&witness.observed_domain) {
            return Err(ContractError::CoverageUncertified);
        }

        let outcome = Self {
            claim_id,
            query_predicate,
            anchor,
            certified_domain,
            witness_digest: witness.witness_digest(),
            generation: claim_generation,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Decodes a negative read outcome from canonical bytes, re-verifying it against
    /// an authoritative coverage witness and authority anchor source (INV-063).
    pub fn decode_verified<A: CurrentAnchorSource>(
        decoder: &mut CanonicalDecoder<'_>,
        witness: &CoverageWitness,
        authority: &A,
    ) -> Result<Self, ContractError> {
        let claim_id = decoder.text()?.to_owned();
        let query_predicate = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let count = decoder.u64()? as usize;
        let mut certified_domain = BTreeSet::new();
        for _ in 0..count {
            let item = decoder.text()?.to_owned();
            if item.is_empty() {
                return Err(ContractError::InvalidIdentifier);
            }
            if certified_domain
                .last()
                .is_some_and(|prev: &String| prev >= &item)
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            certified_domain.insert(item);
        }
        let witness_digest = decoder.digest()?;
        let generation = decoder.u64()?;

        if witness_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        if witness.witness_digest() != witness_digest {
            return Err(ContractError::CoverageUncertified);
        }

        Self::from_witness(
            claim_id,
            query_predicate,
            anchor,
            certified_domain,
            witness,
            authority,
            generation,
        )
    }

    /// Returns the stable claim identifier.
    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    /// Returns the certified negative query predicate.
    #[must_use]
    pub fn query_predicate(&self) -> &str {
        &self.query_predicate
    }

    /// Returns the authoritative anchor at which absence was certified.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Returns the set of domains certified free of the predicate.
    #[must_use]
    pub const fn certified_domain(&self) -> &BTreeSet<String> {
        &self.certified_domain
    }

    /// Returns the pinned digest of the coverage witness proving absence.
    #[must_use]
    pub const fn witness_digest(&self) -> ContentDigest {
        self.witness_digest
    }

    /// Returns the generation at which coverage was certified.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Validates all constitutional invariants on the outcome.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id(&self.claim_id)?;
        if self.query_predicate.is_empty()
            || self.query_predicate.len() > 128
            || self.certified_domain.is_empty()
            || self.anchor.site_lineage.is_empty()
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for item in &self.certified_domain {
            if item.is_empty() || item.len() > 128 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        if self.generation == 0 {
            return Err(ContractError::GenerationConflict);
        }
        if self.witness_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        Ok(())
    }
}

impl CanonicalEncode for NegativeReadOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.claim_id);
        encoder.text(&self.query_predicate);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.certified_domain.len() as u64);
        for item in &self.certified_domain {
            encoder.text(item);
        }
        encoder.digest(self.witness_digest);
        encoder.u64(self.generation);
    }
}

/// Evaluates a negative read claim against its coverage witness and authority anchor source (INV-063).
///
/// Reuses [`CoverageWitness::require_certified_absence`] from `evidence.rs:575`.
/// Fails closed if the witness cannot certify absence, if the anchor does not match,
/// if the witness is stale relative to the authority anchor source (KSTATE-005),
/// or if the target generation or domain bounds mismatch.
pub fn evaluate_negative_read<A: CurrentAnchorSource>(
    claim: &NegativeReadClaim,
    authority: &A,
) -> Result<NegativeReadOutcome, ContractError> {
    validate_id(&claim.claim_id)?;
    if claim.query_predicate.is_empty() || claim.query_predicate.len() > 128 {
        return Err(ContractError::InvalidIdentifier);
    }
    let current_anchor = authority.current_anchor();
    if current_anchor.site_lineage.is_empty() {
        return Err(ContractError::InvalidIdentifier);
    }
    let witness = claim
        .coverage_witness
        .as_ref()
        .ok_or(ContractError::CoverageUncertified)?;

    // REUSE evidence.rs:575 require_certified_absence instead of duplicating it
    witness.require_certified_absence()?;

    // 1. Witness anchor must match claim anchor (RM7)
    if witness.anchor != claim.anchor {
        return Err(ContractError::StaleAnchor);
    }

    // 2. Site lineage must match current anchor (RM3)
    if witness.anchor.site_lineage != current_anchor.site_lineage {
        return Err(ContractError::StaleAnchor);
    }

    // 3. Strictly older commit sequence/epoch is stale (RM4)
    if (witness.anchor.ledger_epoch, witness.anchor.commit_sequence)
        < (current_anchor.ledger_epoch, current_anchor.commit_sequence)
    {
        return Err(ContractError::StaleAnchor);
    }

    // 4. Divergent state root / epochs at current sequence, or future anchor (RM8)
    if witness.anchor.state_root != current_anchor.state_root
        || witness.anchor.policy_epoch != current_anchor.policy_epoch
        || witness.anchor.adapter_registry_epoch != current_anchor.adapter_registry_epoch
        || witness.anchor.schema_epoch != current_anchor.schema_epoch
        || witness.anchor.privacy_epoch != current_anchor.privacy_epoch
        || (witness.anchor.ledger_epoch, witness.anchor.commit_sequence)
            > (current_anchor.ledger_epoch, current_anchor.commit_sequence)
    {
        return Err(ContractError::StaleAnchor);
    }

    if claim.target_generation == 0 || witness.authorized_generation != claim.target_generation {
        return Err(ContractError::GenerationConflict);
    }

    if claim.target_domain.is_empty() || !claim.target_domain.is_subset(&witness.observed_domain) {
        return Err(ContractError::CoverageUncertified);
    }

    if witness.negative_predicate != claim.query_predicate {
        return Err(ContractError::CoverageUncertified);
    }

    NegativeReadOutcome::from_witness(
        claim.claim_id.clone(),
        claim.query_predicate.clone(),
        claim.anchor.clone(),
        claim.target_domain.clone(),
        witness,
        authority,
        claim.target_generation,
    )
}
