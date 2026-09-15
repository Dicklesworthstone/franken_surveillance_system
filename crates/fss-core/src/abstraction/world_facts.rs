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
            return Err(ContractError::InvalidIdentifier);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        if self.evidence_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        // Prohibition: "Cannot include unqualified cognition as fact."
        // Typed provenance check: model predictions (Predicted) and advisory operational memory (Remembered)
        // are cognition outputs and CANNOT be presented as authoritative facts.
        match self.provenance {
            ProvenanceClass::Predicted | ProvenanceClass::Remembered => {
                return Err(ContractError::EvidenceRequired);
            }
            ProvenanceClass::Observed
            | ProvenanceClass::Derived
            | ProvenanceClass::OperatorAsserted
            | ProvenanceClass::VendorClaimed
            | ProvenanceClass::Policy => {}
        }
        // Textual prohibition check against statement text claiming unqualified cognition
        let lower = self.statement.to_lowercase();
        if lower.contains("unqualified cognition")
            || lower.contains("speculative")
            || lower.contains("unverified hypothesis")
        {
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

mod sealed {
    pub trait Sealed {}
}

/// Authority-side source providing the authoritative current ledger anchor (INV-063).
///
/// Per AGENTS.md Prime Directive:
/// - Authority, cognition, and effect planes are type-distinct.
/// - Negative reads require a coverage witness verified against the authority plane.
/// - The current anchor must originate from the authority plane rather than an arbitrary caller argument.
///
/// This trait is sealed and cannot be implemented outside `fss-core`.
///
/// # Compile-fail probe N2b: external callers cannot implement sealed `CurrentAnchorSource`
/// ```compile_fail,E0277
/// use fss_core::abstraction::CurrentAnchorSource;
/// use fss_core::LedgerAnchor;
///
/// struct Liar {
///     anchor: LedgerAnchor,
/// }
///
/// impl CurrentAnchorSource for Liar {
///     fn current_anchor(&self) -> &LedgerAnchor {
///         &self.anchor
///     }
/// }
/// ```
///
/// # Compile-fail probe N2c: `(&ContractBasis, &LedgerAnchor)` does not implement `CurrentAnchorSource`
/// ```compile_fail,E0277
/// use fss_core::abstraction::CurrentAnchorSource;
/// use fss_core::contract_basis::reference_contract_basis;
/// use fss_core::LedgerAnchor;
///
/// let basis = reference_contract_basis();
/// let anchor = LedgerAnchor::genesis("site:main");
/// let tuple_source = (&basis, &anchor);
/// fn require_source<A: CurrentAnchorSource>(_: &A) {}
/// require_source(&tuple_source);
/// ```
pub trait CurrentAnchorSource: sealed::Sealed {
    /// Returns the authoritative current ledger anchor.
    fn current_anchor(&self) -> &LedgerAnchor;
}

/// An authoritative ledger handle proving that the ledger state originates from an
/// opened durable authority handle rather than an arbitrary in-memory construction (INV-063).
///
/// Borrows from the underlying opened ledger handle for lifetime `'a` with no `Clone`
/// and no owned escape, ensuring at compile time that the handle cannot be held across
/// subsequent ledger mutations.
///
/// # Threat Model
/// This is type-level discipline against *accidental or stale* authority. Code in the same process
/// that can write the deployment can always forge durable state, so the goal is that no public API
/// turns a rewound or in-memory ledger into world-fact authority by mistake.
///
/// # Compile-fail probe N2f-a: `ReferenceLedger::new` is not authoritative (fss-sz0cc)
/// ```compile_fail,E0308
/// use fss_core::abstraction::AuthorityAnchor;
/// use fss_core::ReferenceLedger;
///
/// let fresh = ReferenceLedger::new("site:us-east:primary");
/// let _ = AuthorityAnchor::from_committed_head(&fresh);
/// ```
///
/// # Compile-fail probe N2f-b: `ReferenceLedger::replay` prefix is not authoritative (fss-sz0cc)
/// ```compile_fail,E0308
/// use fss_core::abstraction::AuthorityAnchor;
/// use fss_core::ReferenceLedger;
///
/// let Ok(rewound) = ReferenceLedger::replay("site:us-east:primary", vec![]) else { return; };
/// let _ = AuthorityAnchor::from_committed_head(&rewound);
/// ```
///
/// # Compile-fail probe N2f-c: caller cannot construct `AuthoritativeLedger` from authority without durable handle
/// ```compile_fail,E0624
/// use fss_core::abstraction::AuthoritativeLedger;
/// use fss_core::LedgerAnchor;
///
/// let anchor = LedgerAnchor::genesis("site:us-east:primary");
/// let _ = AuthoritativeLedger::from_authority(anchor);
/// ```
///
/// # Compile-fail probe N2f-d: caller cannot construct `AuthoritativeLedger` via struct literal
/// ```compile_fail,E0451
/// use fss_core::abstraction::AuthoritativeLedger;
/// use fss_core::LedgerAnchor;
///
/// let anchor = LedgerAnchor::genesis("site:us-east:primary");
/// let _ = AuthoritativeLedger { anchor, _marker: std::marker::PhantomData };
/// ```
///
/// # Compile-fail probe M1: `AuthoritativeLedger::for_test` is not callable outside `fss-core` (fss-sz0cc)
/// The in-memory test helper exists only under `#[cfg(test)]` inside `fss-core`, so an external
/// caller cannot turn a fresh `ReferenceLedger` into authority through it.
/// ```compile_fail,E0599
/// use fss_core::abstraction::AuthoritativeLedger;
/// use fss_core::ReferenceLedger;
///
/// let fresh = ReferenceLedger::new("site:us-east:primary");
/// let _ = AuthoritativeLedger::for_test(&fresh);
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AuthoritativeLedger<'a> {
    anchor: LedgerAnchor,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> AuthoritativeLedger<'a> {
    /// Returns the authoritative current anchor.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Constructs an authoritative ledger handle witnessing the committed head.
    ///
    /// Restricted to `pub(crate)` so external callers cannot forge authority.
    pub(crate) fn from_authority(anchor: LedgerAnchor) -> Result<Self, ContractError> {
        if anchor.site_lineage.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            anchor,
            _marker: std::marker::PhantomData,
        })
    }

    /// Internal bridge for `fss-ledger`'s `DurableReferenceLedger`.
    ///
    /// Only `fss-ledger`'s `DurableReferenceLedger::authoritative_ledger()` may call this function;
    /// it borrows the underlying opened durable ledger handle and on-disk head for lifetime `'a`;
    /// and calling it from anywhere else is a bug.
    ///
    /// # Threat Model and Residual Limits
    /// This is type-level discipline against *accidental or stale* authority within the same process.
    /// Because `fss-core` (L1) cannot depend on `fss-ledger` (L2), Rust's visibility system cannot
    /// restrict this constructor exclusively to `fss-ledger` at compile time. The static repository
    /// guard test scans every `*.rs` file under `crates/*/{src,tests,examples,benches}` (fss-core
    /// included) and allows this constructor name only in its definition file
    /// `crates/fss-core/src/abstraction/world_facts.rs` and in its sole caller
    /// `crates/fss-ledger/src/durable.rs`.
    #[doc(hidden)]
    pub fn __durable_ledger_only_from_committed_anchor(
        anchor: LedgerAnchor,
    ) -> Result<Self, ContractError> {
        Self::from_authority(anchor)
    }

    /// Test helper for constructing an authoritative handle from an in-memory ledger in tests.
    ///
    /// Restricted to `pub(crate)` and `#[cfg(test)]` so external crates cannot use it
    /// to forge authority. The external-caller `compile_fail,E0599` probe lives on the
    /// [`AuthoritativeLedger`] type docs (probe M1), because rustdoc does not collect doctests
    /// from `#[cfg(test)]` items.
    #[cfg(test)]
    pub(crate) fn for_test(ledger: &'a crate::ReferenceLedger) -> Result<Self, ContractError> {
        Self::from_authority(ledger.current().anchor.clone())
    }
}

impl sealed::Sealed for AuthoritativeLedger<'_> {}

impl CurrentAnchorSource for AuthoritativeLedger<'_> {
    fn current_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

/// An explicit authority-plane anchor token proving current ledger state (INV-063).
///
/// Cannot be constructed from an arbitrary or bare [`LedgerAnchor`], nor from a [`LedgerSnapshot`]
/// through the public API. Must be witnessed directly from the authoritative committed ledger head
/// via [`AuthoritativeLedger`].
///
/// # Threat Model
/// This is type-level discipline against *accidental or stale* authority. Code in the same process
/// that can write the deployment can always forge durable state, so the goal is that no public API
/// turns a rewound or in-memory ledger into world-fact authority by mistake.
///
/// # Compile-fail probe N2: caller cannot construct from a bare anchor via private `from_authority`
/// ```compile_fail,E0624
/// use fss_core::abstraction::AuthorityAnchor;
/// use fss_core::LedgerAnchor;
///
/// let anchor = LedgerAnchor::genesis("site:main");
/// let _ = AuthorityAnchor::from_authority(anchor);
/// ```
///
/// # Compile-fail: caller cannot construct from a `LedgerSnapshot`
/// ```compile_fail,E0308
/// use std::collections::BTreeMap;
/// use fss_core::abstraction::AuthorityAnchor;
/// use fss_core::{LedgerAnchor, LedgerSnapshot};
///
/// let snap = LedgerSnapshot {
///     anchor: LedgerAnchor::genesis("site:main"),
///     objects: BTreeMap::new(),
/// };
/// let _ = AuthorityAnchor::from_committed_head(&snap);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityAnchor {
    anchor: LedgerAnchor,
}

impl AuthorityAnchor {
    /// Constructs an authoritative anchor token witnessing the current committed ledger head.
    ///
    /// Requires an [`AuthoritativeLedger`] handle obtained from an opened durable ledger
    /// rather than an arbitrary in-memory ledger.
    pub fn from_committed_head(ledger: &AuthoritativeLedger<'_>) -> Result<Self, ContractError> {
        Self::from_authority(ledger.anchor().clone())
    }

    /// Constructs an authoritative anchor token witnessing the given ledger anchor.
    ///
    /// Restricted to `pub(crate)` so external callers cannot forge arbitrary anchors.
    pub(crate) fn from_authority(anchor: LedgerAnchor) -> Result<Self, ContractError> {
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

impl sealed::Sealed for AuthorityAnchor {}

impl CurrentAnchorSource for AuthorityAnchor {
    fn current_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

/// Authority context binding an authoritative [`ContractBasis`] and current anchor (INV-063).
///
/// Fields are private and cannot be constructed via struct literal:
/// ```compile_fail,E0451
/// use fss_core::abstraction::AuthorityContext;
/// use fss_core::contract_basis::reference_contract_basis;
/// use fss_core::LedgerAnchor;
///
/// let basis = reference_contract_basis();
/// let anchor = LedgerAnchor::genesis("site:main");
/// let _ = AuthorityContext {
///     contract_basis: &basis,
///     anchor,
/// };
/// ```
///
/// # Compile-fail: caller cannot construct from a `LedgerSnapshot`
/// ```compile_fail,E0308
/// use std::collections::BTreeMap;
/// use fss_core::abstraction::AuthorityContext;
/// use fss_core::contract_basis::reference_contract_basis;
/// use fss_core::{LedgerAnchor, LedgerSnapshot};
///
/// let basis = reference_contract_basis();
/// let snap = LedgerSnapshot {
///     anchor: LedgerAnchor::genesis("site:main"),
///     objects: BTreeMap::new(),
/// };
/// let _ = AuthorityContext::from_committed_head(&basis, &snap);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityContext<'a> {
    /// Active contract basis from the authority plane.
    contract_basis: &'a ContractBasis,
    /// Authoritative current anchor.
    anchor: LedgerAnchor,
}

impl<'a> AuthorityContext<'a> {
    /// Creates a new authority context binding a contract basis and authoritative anchor.
    pub fn new(contract_basis: &'a ContractBasis, authority: &AuthorityAnchor) -> Self {
        Self {
            contract_basis,
            anchor: authority.anchor().clone(),
        }
    }

    /// Creates a new authority context binding a contract basis and current committed ledger head.
    ///
    /// # Threat Model
    /// This is type-level discipline against *accidental or stale* authority. Code in the same process
    /// that can write the deployment can always forge durable state, so the goal is that no public API
    /// turns a rewound or in-memory ledger into world-fact authority by mistake.
    ///
    /// # Compile-fail probe N2f-e: `AuthorityContext::from_committed_head` refuses `ReferenceLedger` (fss-sz0cc)
    /// ```compile_fail,E0308
    /// use fss_core::abstraction::AuthorityContext;
    /// use fss_core::contract_basis::reference_contract_basis;
    /// use fss_core::ReferenceLedger;
    ///
    /// let basis = reference_contract_basis();
    /// let fresh = ReferenceLedger::new("site:us-east:primary");
    /// let _ = AuthorityContext::from_committed_head(&basis, &fresh);
    /// ```
    pub fn from_committed_head(
        contract_basis: &'a ContractBasis,
        ledger: &AuthoritativeLedger<'_>,
    ) -> Result<Self, ContractError> {
        let authority = AuthorityAnchor::from_committed_head(ledger)?;
        Ok(Self::new(contract_basis, &authority))
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

impl sealed::Sealed for AuthorityContext<'_> {}

impl<'a> CurrentAnchorSource for AuthorityContext<'a> {
    fn current_anchor(&self) -> &LedgerAnchor {
        &self.anchor
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

        decoder.ensure_finished()?;

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
/// Fails closed if the witness cannot certify absence, if the anchor does not match,
/// if the witness is stale relative to the authority anchor source (KSTATE-005),
/// or if the target generation or domain bounds mismatch.
///
/// Delegates directly to [`NegativeReadOutcome::from_witness`] to ensure unified validation
/// order and avoid duplicated check logic.
pub fn evaluate_negative_read<A: CurrentAnchorSource>(
    claim: &NegativeReadClaim,
    authority: &A,
) -> Result<NegativeReadOutcome, ContractError> {
    let witness = claim
        .coverage_witness
        .as_ref()
        .ok_or(ContractError::CoverageUncertified)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::error::Error;

    use crate::contract_basis::reference_contract_basis;
    use crate::{
        BatchId, CanonicalDecoder, CanonicalEncoder, CaptureInterval, Completeness, ContentDigest,
        ContractError, CoverageContinuity, CoverageStopReason, CoverageWitness, DigestAlgorithm,
        EvidenceDelta, LedgerAnchor, ObjectId, Plane, ReferenceLedger, TimestampNs,
    };

    fn sample_anchor() -> LedgerAnchor {
        LedgerAnchor::genesis("site:us-east:primary")
    }

    fn sample_ledger() -> ReferenceLedger {
        ReferenceLedger::new("site:us-east:primary")
    }

    fn sample_authority(ledger: &ReferenceLedger) -> Result<AuthorityAnchor, ContractError> {
        let auth_ledger = AuthoritativeLedger::for_test(ledger)?;
        AuthorityAnchor::from_committed_head(&auth_ledger)
    }

    fn make_test_delta(
        id: &str,
        object: &str,
        prior: Option<u64>,
        generation: u64,
    ) -> Result<EvidenceDelta, ContractError> {
        Ok(EvidenceDelta {
            delta_id: id.to_owned(),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(object)?,
            prior_generation: prior,
            new_generation: generation,
            validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(id.as_bytes()),
            witness_digest: None,
            operation_id: None,
        })
    }

    fn advance_ledger(
        ledger: &mut ReferenceLedger,
        batch_id: &str,
        delta_id: &str,
        object_id: &str,
    ) -> Result<(), ContractError> {
        let parsed_object_id = ObjectId::parse(object_id)?;
        let (prior, next_gen) = match ledger.current().objects.get(&parsed_object_id) {
            Some(current) => (Some(current.generation), current.generation + 1),
            None => (None, 1),
        };
        let batch = ledger.prepare_batch(
            BatchId::parse(batch_id)?,
            vec![make_test_delta(delta_id, object_id, prior, next_gen)?],
            [],
        )?;
        ledger.append(batch)?;
        Ok(())
    }

    fn advance_ledger_empty(
        ledger: &mut ReferenceLedger,
        batch_id: &str,
    ) -> Result<(), ContractError> {
        let batch = ledger.prepare_batch(BatchId::parse(batch_id)?, vec![], [])?;
        ledger.append(batch)?;
        Ok(())
    }

    fn sample_witness(predicate: &str, authorized: &[&str], observed: &[&str]) -> CoverageWitness {
        let mut auth_set = BTreeSet::new();
        for a in authorized {
            auth_set.insert((*a).to_string());
        }
        let mut obs_set = BTreeSet::new();
        for o in observed {
            obs_set.insert((*o).to_string());
        }
        CoverageWitness {
            anchor: sample_anchor(),
            authorized_domain: auth_set,
            observed_domain: obs_set,
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Continuous,
            completeness: Completeness::Complete,
            negative_predicate: predicate.to_string(),
            stop_reason: CoverageStopReason::Complete,
            authorized_generation: 1,
            observed_generation: 1,
        }
    }

    #[test]
    fn test_negative_read_claim_requires_coverage_witness() -> Result<(), Box<dyn Error>> {
        let ledger = sample_ledger();
        let anchor = ledger.current().anchor.clone();
        let authority = sample_authority(&ledger)?;
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());

        // Claim WITHOUT CoverageWitness must fail closed (AGENTS.md prime directive)
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:001".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain,
            target_generation: 1,
            coverage_witness: None,
        };

        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for uncertified coverage".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        Ok(())
    }

    #[test]
    fn test_planted_negative_uncertified_coverage_witness_fails() -> Result<(), Box<dyn Error>> {
        let ledger = sample_ledger();
        let anchor = ledger.current().anchor.clone();
        let authority = sample_authority(&ledger)?;
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());

        // 1. Coverage gap (continuity == Gapped)
        let mut witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        witness.continuity = CoverageContinuity::Gapped;
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:gap".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for gapped coverage".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 2. Incomplete coverage (completeness == Partial)
        let mut witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        witness.completeness = Completeness::Partial;
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:partial".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for partial coverage".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 3. Stop reason not complete
        let mut witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        witness.stop_reason = CoverageStopReason::BudgetExhausted;
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:budget".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for budget exhausted stop reason".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 4. Non-empty excluded domain
        let mut witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        witness
            .excluded_domain
            .insert("zone:north_gate".to_string());
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:excluded".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for non-empty excluded domain".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 5. Target domain not covered by observed domain
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:south_perimeter"],
            &["zone:south_perimeter"],
        );
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:domain_mismatch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for domain mismatch".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 6. Predicate mismatch
        let witness = sample_witness(
            "no_fire_detected",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:pred_mismatch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for predicate mismatch".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 7. Generation mismatch
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:gen_mismatch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 2, // Witness has gen 1
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for generation mismatch".into());
        };
        assert_eq!(err, ContractError::GenerationConflict);

        // 8. (Check 1, RM7) Witness anchor mismatch from claim anchor:
        // Witness is at authority anchor, but claim has different anchor.
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut different_claim_anchor = anchor.clone();
        different_claim_anchor.commit_sequence += 1;
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:witness_claim_anchor_mismatch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: different_claim_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for witness != claim anchor (RM7)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 9. (Check 2, RM3) Site lineage mismatch:
        // Witness and claim match each other, but have different site lineage from authority.
        let mut other_site_anchor = anchor.clone();
        other_site_anchor.site_lineage = "site:other_lineage".to_string();
        let mut other_witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        other_witness.anchor = other_site_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:site_lineage_mismatch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: other_site_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(other_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for site lineage mismatch (RM3)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 10. (Check 3, RM4) Strictly older commit sequence/epoch (stale anchor):
        // Witness and claim match, same lineage, but sequence is older than authority anchor.
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut advanced_ledger = sample_ledger();
        advance_ledger_empty(&mut advanced_ledger, "batch:rm4_adv")?;
        assert_eq!(
            advanced_ledger.current().anchor.state_root,
            anchor.state_root
        );
        assert_eq!(
            advanced_ledger.current().anchor.commit_sequence,
            anchor.commit_sequence + 1
        );
        let newer_authority = sample_authority(&advanced_ledger)?;
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:stale_sequence".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &newer_authority) else {
            return Err("expected error for strictly older sequence (RM4)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 11. (Check 4, RM8) Divergent state root at same sequence:
        // Witness and claim match, same lineage and sequence, but different state root from authority.
        let mut ledger_a = sample_ledger();
        advance_ledger(&mut ledger_a, "batch:rm8_a", "delta:rm8_a", "object:rm8_a")?;
        let mut ledger_b = sample_ledger();
        advance_ledger(&mut ledger_b, "batch:rm8_b", "delta:rm8_b", "object:rm8_b")?;
        let anchor_a = ledger_a.current().anchor.clone();
        let forked_authority = sample_authority(&ledger_b)?;
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut witness_a = witness.clone();
        witness_a.anchor = anchor_a.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:divergent_state_root".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor_a,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness_a),
        };
        let Err(err) = evaluate_negative_read(&claim, &forked_authority) else {
            return Err("expected error for divergent state root (RM8)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 12. (Check 4, RM8f) Future witness anchor (ledger_epoch ahead of current)
        let mut future_epoch_anchor = anchor.clone();
        future_epoch_anchor.ledger_epoch += 1;
        let mut future_witness = witness.clone();
        future_witness.anchor = future_epoch_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:future_ledger_epoch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: future_epoch_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(future_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for future ledger epoch (RM8f)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 13. (Check 4, RM8f) Future witness anchor (commit_sequence ahead of current)
        let mut future_seq_anchor = anchor.clone();
        future_seq_anchor.commit_sequence += 1;
        let mut future_witness = witness.clone();
        future_witness.anchor = future_seq_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:future_commit_sequence".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: future_seq_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(future_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for future commit sequence (RM8f)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 14. (Check 4, RM8p) Divergent policy_epoch from authority
        let mut divergent_policy_anchor = anchor.clone();
        divergent_policy_anchor.policy_epoch += 1;
        let mut divergent_policy_witness = witness.clone();
        divergent_policy_witness.anchor = divergent_policy_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:divergent_policy_epoch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: divergent_policy_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(divergent_policy_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for divergent policy epoch (RM8p)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 15. (Check 4, RM8) Divergent privacy_epoch from authority
        let mut divergent_privacy_anchor = anchor.clone();
        divergent_privacy_anchor.privacy_epoch += 1;
        let mut divergent_privacy_witness = witness.clone();
        divergent_privacy_witness.anchor = divergent_privacy_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:divergent_privacy_epoch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: divergent_privacy_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(divergent_privacy_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for divergent privacy epoch (RM8)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 16. (Check 4, RM8) Divergent schema_epoch from authority
        let mut divergent_schema_anchor = anchor.clone();
        divergent_schema_anchor.schema_epoch += 1;
        let mut divergent_schema_witness = witness.clone();
        divergent_schema_witness.anchor = divergent_schema_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:divergent_schema_epoch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: divergent_schema_anchor,
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(divergent_schema_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for divergent schema epoch (RM8)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        // 17. (Check 4, RM8) Divergent adapter_registry_epoch from authority
        let mut divergent_adapter_anchor = anchor.clone();
        divergent_adapter_anchor.adapter_registry_epoch += 1;
        let mut divergent_adapter_witness = witness;
        divergent_adapter_witness.anchor = divergent_adapter_anchor.clone();
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:divergent_adapter_epoch".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: divergent_adapter_anchor,
            target_domain,
            target_generation: 1,
            coverage_witness: Some(divergent_adapter_witness),
        };
        let Err(err) = evaluate_negative_read(&claim, &authority) else {
            return Err("expected error for divergent adapter registry epoch (RM8)".into());
        };
        assert_eq!(err, ContractError::StaleAnchor);

        Ok(())
    }

    #[test]
    fn test_negative_read_outcome_from_witness_direct_contracts() -> Result<(), Box<dyn Error>> {
        let ledger = sample_ledger();
        let anchor = ledger.current().anchor.clone();
        let authority = sample_authority(&ledger)?;
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());

        // 1. Direct construction succeeds with valid parameters (generation taken from claim)
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let outcome = NegativeReadOutcome::from_witness(
            "neg_claim:direct_ok",
            "no_unauthorized_intrusion",
            anchor.clone(),
            target_domain.clone(),
            &witness,
            &authority,
            1,
        )?;
        assert_eq!(outcome.claim_id(), "neg_claim:direct_ok");
        assert_eq!(outcome.query_predicate(), "no_unauthorized_intrusion");
        assert_eq!(outcome.anchor(), &anchor);
        assert_eq!(outcome.certified_domain(), &target_domain);
        assert_eq!(outcome.witness_digest(), witness.witness_digest());
        assert_eq!(outcome.generation(), 1);

        // 2. RM9 killer: Dropping require_certified_absence in from_witness must fail
        let mut uncertified_witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        uncertified_witness.stop_reason = CoverageStopReason::BudgetExhausted;
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm9_direct",
            "no_unauthorized_intrusion",
            anchor.clone(),
            target_domain.clone(),
            &uncertified_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::CoverageUncertified)));

        // 3. RM7 killer: Dropping witness.anchor != anchor in from_witness must fail
        let mut different_anchor = anchor.clone();
        different_anchor.commit_sequence += 1;
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm7_direct",
            "no_unauthorized_intrusion",
            different_anchor,
            target_domain.clone(),
            &witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 4. RM3 in from_witness: site lineage mismatch
        let other_site_ledger = ReferenceLedger::new("site:other");
        let other_site_authority = sample_authority(&other_site_ledger)?;
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm3_direct",
            "no_unauthorized_intrusion",
            anchor.clone(),
            target_domain.clone(),
            &witness,
            &other_site_authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 5. RM4 in from_witness: strictly older sequence
        let mut newer_ledger = sample_ledger();
        advance_ledger_empty(&mut newer_ledger, "batch:rm4_dir")?;
        assert_eq!(newer_ledger.current().anchor.state_root, anchor.state_root);
        assert_eq!(
            newer_ledger.current().anchor.commit_sequence,
            anchor.commit_sequence + 1
        );
        let newer_authority = sample_authority(&newer_ledger)?;
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm4_direct",
            "no_unauthorized_intrusion",
            anchor.clone(),
            target_domain.clone(),
            &witness,
            &newer_authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6. RM8 in from_witness: divergent state root at same sequence
        let mut ledger_a = sample_ledger();
        advance_ledger(
            &mut ledger_a,
            "batch:rm8_da",
            "delta:rm8_da",
            "object:rm8_da",
        )?;
        let mut ledger_b = sample_ledger();
        advance_ledger(
            &mut ledger_b,
            "batch:rm8_db",
            "delta:rm8_db",
            "object:rm8_db",
        )?;
        let anchor_a = ledger_a.current().anchor.clone();
        let mut witness_a = witness.clone();
        witness_a.anchor = anchor_a.clone();
        let forked_authority = sample_authority(&ledger_b)?;
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8_direct",
            "no_unauthorized_intrusion",
            anchor_a,
            target_domain.clone(),
            &witness_a,
            &forked_authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6b. RM8f in from_witness: future witness anchor (ledger_epoch ahead of current)
        let mut future_epoch_anchor = anchor.clone();
        future_epoch_anchor.ledger_epoch += 1;
        let mut future_witness = witness.clone();
        future_witness.anchor = future_epoch_anchor.clone();
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8f_future_epoch",
            "no_unauthorized_intrusion",
            future_epoch_anchor,
            target_domain.clone(),
            &future_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6c. RM8f in from_witness: future witness anchor (commit_sequence ahead of current)
        let mut future_seq_anchor = anchor.clone();
        future_seq_anchor.commit_sequence += 1;
        let mut future_witness = witness.clone();
        future_witness.anchor = future_seq_anchor.clone();
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8f_future_seq",
            "no_unauthorized_intrusion",
            future_seq_anchor,
            target_domain.clone(),
            &future_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6d. RM8p in from_witness: divergent policy_epoch from authority
        let mut divergent_policy_anchor = anchor.clone();
        divergent_policy_anchor.policy_epoch += 1;
        let mut divergent_policy_witness = witness.clone();
        divergent_policy_witness.anchor = divergent_policy_anchor.clone();
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8p_policy_epoch",
            "no_unauthorized_intrusion",
            divergent_policy_anchor,
            target_domain.clone(),
            &divergent_policy_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6e. RM8 in from_witness: divergent privacy_epoch from authority
        let mut divergent_privacy_anchor = anchor.clone();
        divergent_privacy_anchor.privacy_epoch += 1;
        let mut divergent_privacy_witness = witness.clone();
        divergent_privacy_witness.anchor = divergent_privacy_anchor.clone();
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8_privacy_epoch",
            "no_unauthorized_intrusion",
            divergent_privacy_anchor,
            target_domain.clone(),
            &divergent_privacy_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6f. RM8 in from_witness: divergent schema_epoch from authority
        let mut divergent_schema_anchor = anchor.clone();
        divergent_schema_anchor.schema_epoch += 1;
        let mut divergent_schema_witness = witness.clone();
        divergent_schema_witness.anchor = divergent_schema_anchor.clone();
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8_schema_epoch",
            "no_unauthorized_intrusion",
            divergent_schema_anchor,
            target_domain.clone(),
            &divergent_schema_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 6g. RM8 in from_witness: divergent adapter_registry_epoch from authority
        let mut divergent_adapter_anchor = anchor.clone();
        divergent_adapter_anchor.adapter_registry_epoch += 1;
        let mut divergent_adapter_witness = witness.clone();
        divergent_adapter_witness.anchor = divergent_adapter_anchor.clone();
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:rm8_adapter_epoch",
            "no_unauthorized_intrusion",
            divergent_adapter_anchor,
            target_domain.clone(),
            &divergent_adapter_witness,
            &authority,
            1,
        );
        assert!(matches!(res, Err(ContractError::StaleAnchor)));

        // 7. Generation mismatch or zero generation fails closed (N6)
        let res = NegativeReadOutcome::from_witness(
            "neg_claim:gen_zero",
            "no_unauthorized_intrusion",
            anchor.clone(),
            target_domain.clone(),
            &witness,
            &authority,
            0,
        );
        assert!(matches!(res, Err(ContractError::GenerationConflict)));

        let res = NegativeReadOutcome::from_witness(
            "neg_claim:gen_mismatch",
            "no_unauthorized_intrusion",
            anchor,
            target_domain,
            &witness,
            &authority,
            99,
        );
        assert!(matches!(res, Err(ContractError::GenerationConflict)));

        Ok(())
    }

    #[test]
    fn test_authority_context_as_current_anchor_source() -> Result<(), Box<dyn Error>> {
        let ledger = sample_ledger();
        let anchor = ledger.current().anchor.clone();
        let basis = reference_contract_basis();
        let auth_ledger = AuthoritativeLedger::for_test(&ledger)?;
        let authority = AuthorityAnchor::from_committed_head(&auth_ledger)?;

        // 1. AuthorityContext constructed from AuthorityAnchor implements CurrentAnchorSource
        let auth_ctx = AuthorityContext::new(&basis, &authority);
        assert_eq!(auth_ctx.current_anchor(), &anchor);
        assert_eq!(auth_ctx.contract_basis(), &basis);

        // 2. AuthorityContext constructed from committed head implements CurrentAnchorSource
        let auth_ctx_head = AuthorityContext::from_committed_head(&basis, &auth_ledger)?;
        assert_eq!(auth_ctx_head.current_anchor(), &anchor);
        assert_eq!(auth_ctx_head.contract_basis(), &basis);

        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:auth_ctx_ok".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness.clone()),
        };

        let outcome = evaluate_negative_read(&claim, &auth_ctx)?;
        assert_eq!(outcome.claim_id(), "neg_claim:auth_ctx_ok");

        let outcome_head = evaluate_negative_read(&claim, &auth_ctx_head)?;
        assert_eq!(outcome_head.claim_id(), "neg_claim:auth_ctx_ok");

        Ok(())
    }

    #[test]
    fn test_negative_read_claim_with_certified_absence_succeeds() -> Result<(), Box<dyn Error>> {
        let ledger = sample_ledger();
        let anchor = ledger.current().anchor.clone();
        let authority = sample_authority(&ledger)?;
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());
        target_domain.insert("zone:east_perimeter".to_string());

        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter", "zone:east_perimeter"],
            &["zone:north_perimeter", "zone:east_perimeter"],
        );

        let claim = NegativeReadClaim {
            claim_id: "neg_claim:certified_ok".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness.clone()),
        };

        let outcome = evaluate_negative_read(&claim, &authority)?;
        assert_eq!(outcome.claim_id(), "neg_claim:certified_ok");
        assert_eq!(outcome.query_predicate(), "no_unauthorized_intrusion");
        assert_eq!(outcome.anchor(), &anchor);
        assert_eq!(outcome.certified_domain(), &target_domain);
        assert_eq!(outcome.witness_digest(), witness.witness_digest());
        assert_eq!(outcome.generation(), 1);

        // Direct construction via NegativeReadOutcome::from_witness
        let direct = NegativeReadOutcome::from_witness(
            "neg_claim:direct_ok",
            "no_unauthorized_intrusion",
            anchor.clone(),
            target_domain.clone(),
            &witness,
            &authority,
            1,
        )?;
        assert_eq!(direct.claim_id(), "neg_claim:direct_ok");
        assert_eq!(direct.query_predicate(), "no_unauthorized_intrusion");
        assert_eq!(direct.anchor(), &anchor);
        assert_eq!(direct.certified_domain(), &target_domain);
        assert_eq!(direct.witness_digest(), witness.witness_digest());
        assert_eq!(direct.generation(), 1);

        // Canonical roundtrip with verified decode
        let mut encoder = CanonicalEncoder::new();
        outcome.encode_canonical(&mut encoder);
        let encoded = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&encoded);
        let decoded = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)?;
        assert_eq!(decoded, outcome);

        Ok(())
    }

    #[test]
    fn test_negative_read_outcome_decode_invariants() -> Result<(), Box<dyn Error>> {
        let ledger = sample_ledger();
        let anchor = ledger.current().anchor.clone();
        let authority = sample_authority(&ledger)?;
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:a", "zone:b"],
            &["zone:a", "zone:b"],
        );
        let witness_digest = witness.witness_digest();

        // 1. Non-canonical ordering (duplicate or unsorted items in certified_domain)
        let mut encoder = CanonicalEncoder::new();
        encoder.text("neg_claim:001");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(2); // 2 items
        encoder.text("zone:b");
        encoder.text("zone:a"); // unsorted!
        encoder.digest(witness_digest);
        encoder.u64(1);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for non-canonical ordering".into());
        };
        assert_eq!(err, ContractError::NonCanonicalOrdering);

        // 2. Duplicate items in certified_domain
        let mut encoder = CanonicalEncoder::new();
        encoder.text("neg_claim:001");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(2);
        encoder.text("zone:a");
        encoder.text("zone:a"); // duplicate!
        encoder.digest(witness_digest);
        encoder.u64(1);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for duplicate domain items".into());
        };
        assert_eq!(err, ContractError::NonCanonicalOrdering);

        // 3. Zero generation rejected
        let mut encoder = CanonicalEncoder::new();
        encoder.text("neg_claim:001");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(1);
        encoder.text("zone:a");
        encoder.digest(witness_digest);
        encoder.u64(0); // zero generation!
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for zero generation".into());
        };
        assert_eq!(err, ContractError::GenerationConflict);

        // 4. Zero witness digest rejected
        let mut encoder = CanonicalEncoder::new();
        encoder.text("neg_claim:001");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(1);
        encoder.text("zone:a");
        encoder.digest(ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32])); // zero digest!
        encoder.u64(1);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for zero witness digest".into());
        };
        assert_eq!(err, ContractError::InvalidDigest);

        // 5. Empty claim_id rejected
        let mut encoder = CanonicalEncoder::new();
        encoder.text(""); // empty claim_id
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(1);
        encoder.text("zone:a");
        encoder.digest(witness_digest);
        encoder.u64(1);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for empty claim_id".into());
        };
        assert_eq!(err, ContractError::InvalidIdentifier);

        // 6. Malformed claim_id (spaces) rejected by validate_id
        let mut encoder = CanonicalEncoder::new();
        encoder.text("claim with spaces");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(1);
        encoder.text("zone:a");
        encoder.digest(witness_digest);
        encoder.u64(1);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for malformed claim_id".into());
        };
        assert_eq!(err, ContractError::InvalidIdentifier);

        // 7. Witness digest mismatch rejected
        let other_witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:other"],
            &["zone:other"],
        );
        let mut encoder = CanonicalEncoder::new();
        encoder.text("neg_claim:001");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(1);
        encoder.text("zone:a");
        encoder.digest(other_witness.witness_digest()); // mismatched digest!
        encoder.u64(1);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for mismatched witness digest".into());
        };
        assert_eq!(err, ContractError::CoverageUncertified);

        // 8. Trailing unconsumed bytes rejected by ensure_finished()
        let mut encoder = CanonicalEncoder::new();
        encoder.text("neg_claim:001");
        encoder.text("no_unauthorized_intrusion");
        anchor.encode_canonical(&mut encoder);
        encoder.u64(1);
        encoder.text("zone:a");
        encoder.digest(witness_digest);
        encoder.u64(1);
        encoder.u8(0xFF); // trailing byte!
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)
        else {
            return Err("expected error for trailing bytes in decode_verified".into());
        };
        assert_eq!(err, ContractError::NonCanonicalOrdering);

        Ok(())
    }

    #[test]
    fn test_older_snapshot_at_head_refused_as_stale_anchor() -> Result<(), Box<dyn Error>> {
        let mut ledger = sample_ledger();
        let old_snapshot = ledger.current().clone();
        let old_anchor = old_snapshot.anchor.clone();
        advance_ledger(
            &mut ledger,
            "batch:snap_advance",
            "delta:snap_advance",
            "object:snap_advance",
        )?;

        // An older snapshot retrieved via snapshot_at(0)
        let snapshot_0 = ledger.snapshot_at(0).ok_or("snapshot 0 missing")?;
        assert_eq!(snapshot_0.anchor, old_anchor);

        // Real committed authority from ledger head (now at commit_sequence 1)
        let auth_ledger = AuthoritativeLedger::for_test(&ledger)?;
        let authority = AuthorityAnchor::from_committed_head(&auth_ledger)?;
        assert_eq!(authority.anchor().commit_sequence, 1);

        // Claim and witness at older snapshot anchor (commit_sequence 0)
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:old_snapshot".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: old_anchor,
            target_domain,
            target_generation: 1,
            coverage_witness: Some(witness),
        };

        // Evaluating the older snapshot claim against head authority MUST be refused as StaleAnchor
        let res = evaluate_negative_read(&claim, &authority);
        assert_eq!(res.err(), Some(ContractError::StaleAnchor));

        Ok(())
    }

    #[test]
    fn test_probe_n2d_refuses_stale_witness_and_requires_ledger_authority()
    -> Result<(), Box<dyn Error>> {
        let mut ledger = sample_ledger();
        let old_anchor = ledger.current().anchor.clone();

        // The real ledger head is 5 commits past the stale witness.
        for i in 1..=5 {
            advance_ledger(
                &mut ledger,
                &format!("batch:probe_n2d:{i}"),
                &format!("delta:probe_n2d:{i}"),
                &format!("object:probe_n2d:{i}"),
            )?;
        }

        let auth_ledger = AuthoritativeLedger::for_test(&ledger)?;
        let honest = AuthorityAnchor::from_committed_head(&auth_ledger)?;
        assert_eq!(honest.anchor().commit_sequence, 5);

        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:probe_n2d".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: old_anchor,
            target_domain,
            target_generation: 1,
            coverage_witness: Some(witness),
        };

        let res = evaluate_negative_read(&claim, &honest);
        assert_eq!(res.err(), Some(ContractError::StaleAnchor));

        Ok(())
    }

    #[test]
    fn test_probe_n2e_context_from_committed_head_refuses_stale_and_mismatched_claims()
    -> Result<(), Box<dyn Error>> {
        let basis = reference_contract_basis();
        let mut ledger = sample_ledger();
        let old_anchor = ledger.current().anchor.clone();

        advance_ledger(
            &mut ledger,
            "batch:probe_n2e",
            "delta:probe_n2e",
            "object:probe_n2e",
        )?;

        let auth_ledger = AuthoritativeLedger::for_test(&ledger)?;
        let ctx = AuthorityContext::from_committed_head(&basis, &auth_ledger)?;
        assert_eq!(ctx.current_anchor().commit_sequence, 1);

        // 1. Stale claim at sequence 0 against context at sequence 1
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());
        let stale_claim = NegativeReadClaim {
            claim_id: "neg_claim:probe_n2e_stale".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: old_anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness.clone()),
        };
        let res = evaluate_negative_read(&stale_claim, &ctx);
        assert_eq!(res.err(), Some(ContractError::StaleAnchor));

        // 2. Mismatched lineage claim against context
        let mut forged_anchor = old_anchor;
        forged_anchor.site_lineage = "site:arbitrary".to_string();
        let mut forged_witness = witness;
        forged_witness.anchor = forged_anchor.clone();
        let mismatched_claim = NegativeReadClaim {
            claim_id: "neg_claim:probe_n2e_lineage".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: forged_anchor,
            target_domain,
            target_generation: 1,
            coverage_witness: Some(forged_witness),
        };
        let res = evaluate_negative_read(&mismatched_claim, &ctx);
        assert_eq!(res.err(), Some(ContractError::StaleAnchor));

        Ok(())
    }

    #[test]
    fn test_empty_batch_stale_anchor_kills_mutant_mc() -> Result<(), Box<dyn Error>> {
        let mut ledger = sample_ledger();
        let old_anchor = ledger.current().anchor.clone();

        // Empty batch advances sequence without changing state_root.
        advance_ledger_empty(&mut ledger, "batch:empty_mc")?;
        let head = ledger.current().anchor.clone();
        assert_eq!(head.commit_sequence, old_anchor.commit_sequence + 1);
        assert_eq!(head.state_root, old_anchor.state_root);

        let authority = sample_authority(&ledger)?;
        let witness = sample_witness(
            "no_unauthorized_intrusion",
            &["zone:north_perimeter"],
            &["zone:north_perimeter"],
        );
        let mut target_domain = BTreeSet::new();
        target_domain.insert("zone:north_perimeter".to_string());

        // 1. evaluate_negative_read MUST fail with StaleAnchor specifically due to RM4 (<)
        let claim = NegativeReadClaim {
            claim_id: "neg_claim:empty_mc".to_string(),
            query_predicate: "no_unauthorized_intrusion".to_string(),
            anchor: old_anchor.clone(),
            target_domain: target_domain.clone(),
            target_generation: 1,
            coverage_witness: Some(witness.clone()),
        };
        let res = evaluate_negative_read(&claim, &authority);
        assert_eq!(res.err(), Some(ContractError::StaleAnchor));

        // 2. from_witness MUST fail with StaleAnchor specifically due to RM4 (<)
        let res_witness = NegativeReadOutcome::from_witness(
            "neg_claim:empty_mc_direct",
            "no_unauthorized_intrusion",
            old_anchor,
            target_domain,
            &witness,
            &authority,
            1,
        );
        assert_eq!(res_witness.err(), Some(ContractError::StaleAnchor));

        Ok(())
    }
}
