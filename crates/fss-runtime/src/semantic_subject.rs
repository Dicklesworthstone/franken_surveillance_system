#![forbid(unsafe_code)]
//! Typed semantic subject fabric with separate packet, authority, and reasoning
//! service classes (`DOC-050`, bead `fss-x4a.5.50`, import `IMP-AS-SUBJECT-001`,
//! admission gate `INT-AS-001`).
//!
//! FSS is a semantic subject fabric, not a tangle of undifferentiated channels
//! or ad hoc internal RPC. Every internal message names a registered versioned
//! subject schema and a declared service class while preserving strict separation
//! between three type-distinct planes:
//!
//! * [`FabricPlane::Packet`] — immutable object/handle packets, provenance, and
//!   budgets (`EphemeralLatest`, `OrderedTelemetry`, `VerifiedObjectGraph`).
//!   Never carries or mints effect authority (`grants_effect_authority == false`).
//!   ATP moves immutable verified object graphs with root-last exposure only
//!   (`INV-046`, `INV-047`, `INV-066`).
//! * [`FabricPlane::Authority`] — explicit [`AuthorityCx`], [`RegionTree`],
//!   capability grants, [`LeaseRegistry`] fence verification, idempotency,
//!   durable obligations, and cutover (`DurableAtLeastOnce`,
//!   `ObligatedExactlyEffectOnce`). Authority is never inferred from routing.
//! * [`FabricPlane::Reasoning`] — derived cognition anchored to an immutable
//!   evidence root and generation (`DurableAtLeastOnce`). Results remain
//!   strictly derived (`is_authoritative_truth == false`,
//!   `grants_effect_authority == false`).
//!
//! ## Architectural guarantees
//! * **Zero global locks or mutable singletons:** every registry, compiled route
//!   table, fabric instance, and lab harness is explicitly owned by its caller.
//! * **Bounded queues and explicit backpressure:** every service class has an
//!   explicit hard queue capacity; drops/supersedes/gaps/sheds emit typed
//!   receipts rather than silent loss.
//! * **Packet-plane isolation:** packet batching/coalescing/reordering can never
//!   reorder, coalesce away, or starve authority-plane messages, freshness
//!   anchors, coverage transitions, or terminal obligation transitions.
//! * **Versioned subject schemas with tombstones:** stable subject schema IDs
//!   are never renumbered; superseded versions remain tombstoned and fail closed
//!   with explicit migration guidance.
//! * **Region ownership and cancellation (`request -> drain -> finalize`):**
//!   draining refuses new non-terminal work, emits a [`DrainProgressCertificate`]
//!   proving monotonic progress (`INT-AS-001` gate #3), and refuses closure if
//!   any queued item or region obligation remains non-terminal.
//! * **Deterministic lab scheduling:** [`LabFabricHarness`] executes identical
//!   workloads under virtual time and seeded interleavings, proving byte-exact
//!   replay determinism and authority-result invariance across packet-plane
//!   schedules (`INT-AS-001` gates #1 and #8).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use fss_core::effect::Obligation;
use fss_core::{
    BudgetDimension, BudgetVector, CanonicalEncoder, ContentDigest, IdempotencyKey, ObligationId,
    OperationId, QuiescenceProof, RegionId, RegionTree, ResourcePressure, RuntimeGrant,
    TimestampNs,
};

use crate::authority::{AuthorityCx, AuthorityError};
use crate::grant::{GrantError, GrantSet};
use crate::lease::{LeaseError, LeaseRegistry};
use crate::obligation::{LeakedObligation, ObligationTerminal, new_obligation};

// Internal hash-domain tags (non-`fss.*.v1` internal computation tags).
const ROUTE_TABLE_DIGEST_TAG: &str = "fss-internal-semantic-subject-route-table-v1";
const DISPATCH_RECEIPT_TAG: &str = "fss-internal-semantic-subject-dispatch-receipt-v1";
const DRAIN_PROGRESS_TAG: &str = "fss-internal-semantic-subject-drain-progress-v1";
const QUIESCENCE_RECEIPT_TAG: &str = "fss-internal-semantic-subject-quiescence-receipt-v1";
const LAB_TRANSCRIPT_TAG: &str = "fss-internal-semantic-subject-lab-transcript-v1";

/// Hard upper bound on any single service-class queue depth.
pub const MAX_SERVICE_QUEUE_DEPTH: usize = 4096;
/// Hard upper bound on segments in a subject name or schema pattern.
pub const MAX_SUBJECT_SEGMENTS: usize = 16;
/// Hard upper bound on total byte length of a subject name.
pub const MAX_SUBJECT_BYTES: usize = 256;
/// Hard upper bound on object digests carried by a single packet envelope.
pub const MAX_PACKET_OBJECT_DIGESTS: usize = 128;
/// Hard upper bound on chunk digests carried by a single ATP object-graph manifest.
pub const MAX_ATP_MANIFEST_CHUNKS: usize = 256;
/// Hard upper bound on retained idempotency records per fabric instance.
pub const MAX_RETAINED_IDEMPOTENCY: usize = 4096;
/// Hard upper bound on retained ordered-telemetry source watermarks.
pub const MAX_TRACKED_TELEMETRY_SOURCES: usize = 1024;
/// Hard upper bound on registered subject schemas.
pub const MAX_REGISTERED_SUBJECT_SCHEMAS: usize = 512;

// ---------------------------------------------------------------------------
// Planes, Service Classes, Families, and Privacy/Locality/Profile Types
// ---------------------------------------------------------------------------

/// The three type-distinct internal planes of the semantic subject fabric.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FabricPlane {
    /// Immutable object/handle transport, provenance, and budgets. Never carries effect authority.
    Packet,
    /// Explicit `AuthorityCx`, capability checks, leases, fencing, durability, and obligations.
    Authority,
    /// Derived cognition (graph, model, agent, decision cards). Never authoritative truth or effect authority.
    Reasoning,
}

impl FabricPlane {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Packet => "packet",
            Self::Authority => "authority",
            Self::Reasoning => "reasoning",
        }
    }

    /// Whether this plane may ever host effect-authority operations.
    #[must_use]
    pub const fn may_carry_authority(self) -> bool {
        matches!(self, Self::Authority)
    }
}

impl fmt::Display for FabricPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The five declared internal service classes (`FRANKENSTACK_DEEP_DIVE.md §2.8`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceClass {
    /// Bounded loss permitted; newest value per subject key supersedes older queued entries.
    EphemeralLatest,
    /// Per-source monotone sequence ordering with explicit gap receipts on missing/reordered packets.
    OrderedTelemetry,
    /// Acknowledged durable consumer with bounded retry and explicit idempotent handler key.
    DurableAtLeastOnce,
    /// Effect identity + explicit `AuthorityCx` + lease fence + obligation + reconciliation.
    ObligatedExactlyEffectOnce,
    /// ATP verified immutable object-graph movement with root-last exposure (`grants_effect_authority == false`).
    VerifiedObjectGraph,
}

impl ServiceClass {
    /// Stable canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EphemeralLatest => "EphemeralLatest",
            Self::OrderedTelemetry => "OrderedTelemetry",
            Self::DurableAtLeastOnce => "DurableAtLeastOnce",
            Self::ObligatedExactlyEffectOnce => "ObligatedExactlyEffectOnce",
            Self::VerifiedObjectGraph => "VerifiedObjectGraph",
        }
    }

    /// Returns whether `self` is structurally legal on `plane`.
    #[must_use]
    pub const fn is_compatible_with(self, plane: FabricPlane) -> bool {
        matches!(
            (self, plane),
            (
                Self::EphemeralLatest | Self::OrderedTelemetry | Self::VerifiedObjectGraph,
                FabricPlane::Packet
            ) | (
                Self::DurableAtLeastOnce,
                FabricPlane::Authority | FabricPlane::Reasoning
            ) | (Self::ObligatedExactlyEffectOnce, FabricPlane::Authority)
        )
    }

    /// Whether packet-plane batching/reordering is permitted for this service class.
    #[must_use]
    pub const fn allows_packet_batching(self) -> bool {
        matches!(self, Self::EphemeralLatest | Self::VerifiedObjectGraph)
    }

    /// Whether this service class may be shed under `Constrained`/`Critical` resource pressure.
    #[must_use]
    pub const fn sheddable_under_pressure(self) -> bool {
        matches!(self, Self::EphemeralLatest)
    }
}

impl fmt::Display for ServiceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical internal subject families (`DOC-050`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SubjectFamily {
    /// Evidence deltas, sensor packets, and sensor health telemetry (`SUBJ-001`).
    EvidenceDelta,
    /// Source custody, archive manifests, and root-last publication state (`SUBJ-002`).
    CustodyPublication,
    /// Graph projections, model inference, and calibration work (`SUBJ-003`).
    GraphModel,
    /// Agent cognition, event revisions, and decision cards (`SUBJ-004`).
    AgentCognition,
    /// Plans, effects, adapter requests, and durable obligations (`SUBJ-005`).
    PlanEffectObligation,
    /// Proof bundles and qualification receipts (`SUBJ-006`).
    Proof,
}

impl SubjectFamily {
    /// Stable family prefix ID (never renumbered).
    #[must_use]
    pub const fn family_id(self) -> &'static str {
        match self {
            Self::EvidenceDelta => "SUBJ-001",
            Self::CustodyPublication => "SUBJ-002",
            Self::GraphModel => "SUBJ-003",
            Self::AgentCognition => "SUBJ-004",
            Self::PlanEffectObligation => "SUBJ-005",
            Self::Proof => "SUBJ-006",
        }
    }

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceDelta => "evidence_delta",
            Self::CustodyPublication => "custody_publication",
            Self::GraphModel => "graph_model",
            Self::AgentCognition => "agent_cognition",
            Self::PlanEffectObligation => "plan_effect_obligation",
            Self::Proof => "proof",
        }
    }
}

/// Explicit privacy classification zone enforced during route compilation (`INT-AS-001` gate #6).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PrivacyZone {
    /// Public / non-sensitive system telemetry and schema metadata.
    Metadata,
    /// Owner exterior sensor domain.
    ExteriorProperty,
    /// Owner interior private property domain.
    InteriorPrivate,
    /// Restricted secret / vault / protected-media custody domain.
    RestrictedCustody,
}

impl PrivacyZone {
    /// Stable string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::ExteriorProperty => "exterior_property",
            Self::InteriorPrivate => "interior_private",
            Self::RestrictedCustody => "restricted_custody",
        }
    }
}

/// Data locality hop target for route compilation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataLocality {
    /// Same OS process / local Asupersync region tree.
    LocalProcess,
    /// Same edge capture node.
    EdgeNode,
    /// Site-local hub node.
    SiteHub,
    /// Remote archive / replication boundary (ATP immutable graphs ONLY).
    ArchiveRegion,
}

impl DataLocality {
    /// Stable string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalProcess => "local_process",
            Self::EdgeNode => "edge_node",
            Self::SiteHub => "site_hub",
            Self::ArchiveRegion => "archive_region",
        }
    }
}

/// Deployment profile controlling default priorities, batching caps, and locality clamps.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeploymentProfile {
    /// Resource-constrained edge camera host.
    EdgeMinimal,
    /// Single-host owner residential deployment.
    HomeSingleHost,
    /// Multi-site hub with local archive node.
    MultiSiteHub,
    /// Deterministic virtual-time laboratory profile (`INT-AS-001`).
    LabDeterministic,
}

impl DeploymentProfile {
    /// Stable string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeMinimal => "edge_minimal",
            Self::HomeSingleHost => "home_single_host",
            Self::MultiSiteHub => "multi_site_hub",
            Self::LabDeterministic => "lab_deterministic",
        }
    }

    /// Maximum packet-plane batch size permitted under this profile.
    #[must_use]
    pub const fn max_packet_batch(self) -> usize {
        match self {
            Self::EdgeMinimal => 4,
            Self::HomeSingleHost => 16,
            Self::MultiSiteHub => 32,
            Self::LabDeterministic => 8,
        }
    }
}

// ---------------------------------------------------------------------------
// Typed Subject Addresses, Schema Registry, and Tombstones
// ---------------------------------------------------------------------------

/// A validated dot-separated typed semantic subject name (e.g.
/// `fss.site.home.sensor.cam1.packet.v2`).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubjectName {
    raw: String,
    segments: Vec<String>,
}

impl SubjectName {
    /// Parses and validates a semantic subject name.
    pub fn parse(raw: impl Into<String>) -> Result<Self, SubjectError> {
        let raw = raw.into();
        if raw.is_empty() || raw.len() > MAX_SUBJECT_BYTES {
            return Err(SubjectError::InvalidSubjectName {
                subject: raw,
                reason: "length violates 1..=256 bytes",
            });
        }
        let parts: Vec<String> = raw.split('.').map(str::to_owned).collect();
        if parts.len() < 3 || parts.len() > MAX_SUBJECT_SEGMENTS {
            return Err(SubjectError::InvalidSubjectName {
                subject: raw,
                reason: "segment count violates 3..=16",
            });
        }
        if parts[0] != "fss" {
            return Err(SubjectError::InvalidSubjectName {
                subject: raw,
                reason: "subject must begin with canonical `fss.` namespace",
            });
        }
        for seg in &parts {
            if seg.is_empty()
                || seg.len() > 64
                || !seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
            {
                return Err(SubjectError::InvalidSubjectName {
                    subject: raw,
                    reason: "segment contains empty, oversized, wildcard, or non-ASCII token",
                });
            }
        }
        Ok(Self {
            raw,
            segments: parts,
        })
    }

    /// Returns the full canonical subject string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns individual dot-separated segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

impl fmt::Display for SubjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// One segment in a registered subject schema pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectPatternSegment {
    /// Exact literal segment (e.g. `"fss"`, `"site"`, `"packet"`).
    Literal(String),
    /// Named single-segment parameter capture (e.g. `"site"`, `"sensor"`, `"generation"`).
    Param(String),
}

/// Lifecycle state of a registered subject schema version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectSchemaStatus {
    /// Active and eligible for route compilation and publication.
    Active,
    /// Permanently tombstoned (never renumbered or removed); fails closed on use.
    Tombstoned {
        /// Replacement active version number within the same schema family.
        superseded_by_version: u32,
        /// Non-secret human/machine migration reason.
        reason: String,
    },
}

/// One registered versioned subject schema entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectSchema {
    /// Stable schema identifier (e.g. `"SUBJ-001.sensor.packet.v2"`). Never renumbered.
    pub schema_id: String,
    /// Canonical subject family.
    pub family: SubjectFamily,
    /// Monotone schema version (`>= 1`).
    pub version: u32,
    /// Exact dot-separated pattern segments.
    pub pattern: Vec<SubjectPatternSegment>,
    /// Semantic plane owning this subject.
    pub plane: FabricPlane,
    /// Declared service class (must be compatible with `plane`).
    pub service_class: ServiceClass,
    /// Minimum registered capability grant required to publish/route this subject.
    pub required_grant: RuntimeGrant,
    /// Privacy classification zone of messages on this subject.
    pub privacy_zone: PrivacyZone,
    /// Whether this subject requires an active [`LeaseRegistry`] fence token.
    pub requires_lease_fence: bool,
    /// Whether messages on this subject represent coverage or terminal transitions
    /// (protected from shedding and packet-plane coalescing).
    pub terminal_or_coverage_critical: bool,
    /// Whether cross-host/archive ATP locality is permitted for this subject.
    pub allows_archive_locality: bool,
    /// Active or permanently tombstoned status.
    pub status: SubjectSchemaStatus,
}

impl SubjectSchema {
    /// Validates internal invariants of this schema registration.
    pub fn validate(&self) -> Result<(), SubjectError> {
        if self.schema_id.is_empty()
            || self.schema_id.len() > 128
            || !self
                .schema_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(SubjectError::InvalidSchema {
                schema_id: self.schema_id.clone(),
                reason: "invalid schema_id token",
            });
        }
        if self.version == 0 {
            return Err(SubjectError::InvalidSchema {
                schema_id: self.schema_id.clone(),
                reason: "schema version must be >= 1",
            });
        }
        if self.pattern.len() < 3 || self.pattern.len() > MAX_SUBJECT_SEGMENTS {
            return Err(SubjectError::InvalidSchema {
                schema_id: self.schema_id.clone(),
                reason: "pattern segment count violates 3..=16",
            });
        }
        if self.pattern.first() != Some(&SubjectPatternSegment::Literal("fss".to_owned())) {
            return Err(SubjectError::InvalidSchema {
                schema_id: self.schema_id.clone(),
                reason: "pattern must start with literal `fss`",
            });
        }
        if !self.service_class.is_compatible_with(self.plane) {
            return Err(SubjectError::PlaneServiceClassMismatch {
                plane: self.plane,
                service_class: self.service_class,
            });
        }
        if self.service_class == ServiceClass::ObligatedExactlyEffectOnce
            && !self.requires_lease_fence
        {
            return Err(SubjectError::InvalidSchema {
                schema_id: self.schema_id.clone(),
                reason: "ObligatedExactlyEffectOnce schemas must require a lease fence",
            });
        }
        if self.allows_archive_locality && self.service_class != ServiceClass::VerifiedObjectGraph {
            return Err(SubjectError::InvalidSchema {
                schema_id: self.schema_id.clone(),
                reason: "only ATP VerifiedObjectGraph subjects may target ArchiveRegion locality",
            });
        }
        Ok(())
    }

    /// Matches a concrete [`SubjectName`] against this pattern, extracting named parameters.
    #[must_use]
    pub fn match_subject(&self, subject: &SubjectName) -> Option<BTreeMap<String, String>> {
        if subject.segments.len() != self.pattern.len() {
            return None;
        }
        let mut params = BTreeMap::new();
        for (pat, seg) in self.pattern.iter().zip(subject.segments.iter()) {
            match pat {
                SubjectPatternSegment::Literal(lit) => {
                    if lit != seg {
                        return None;
                    }
                }
                SubjectPatternSegment::Param(name) => {
                    params.insert(name.clone(), seg.clone());
                }
            }
        }
        Some(params)
    }

    /// Parses a dotted template string such as `fss.site.<site>.sensor.<sensor>.health`.
    pub fn parse_pattern(template: &str) -> Result<Vec<SubjectPatternSegment>, SubjectError> {
        let mut segs = Vec::new();
        for raw in template.split('.') {
            if raw.is_empty() {
                return Err(SubjectError::InvalidSchema {
                    schema_id: template.to_owned(),
                    reason: "empty segment in pattern template",
                });
            }
            if let Some(inner) = raw.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
                if inner.is_empty()
                    || !inner
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                {
                    return Err(SubjectError::InvalidSchema {
                        schema_id: template.to_owned(),
                        reason: "invalid parameter name in pattern template",
                    });
                }
                segs.push(SubjectPatternSegment::Param(inner.to_owned()));
            } else {
                if !raw
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
                {
                    return Err(SubjectError::InvalidSchema {
                        schema_id: template.to_owned(),
                        reason: "invalid literal token in pattern template",
                    });
                }
                segs.push(SubjectPatternSegment::Literal(raw.to_owned()));
            }
        }
        Ok(segs)
    }
}

/// Resolution result for one concrete subject address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSubject {
    /// Matched schema entry.
    pub schema: SubjectSchema,
    /// Captured named template parameters (e.g. `site`, `sensor`, `generation`).
    pub params: BTreeMap<String, String>,
}

/// Explicitly owned registry of versioned semantic subject schemas with tombstone history.
/// Never stored in a global singleton; callers construct and pass it explicitly.
#[derive(Clone, Debug, Default)]
pub struct SubjectSchemaRegistry {
    schemas: BTreeMap<String, SubjectSchema>,
}

impl SubjectSchemaRegistry {
    /// Creates an empty subject schema registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schemas: BTreeMap::new(),
        }
    }

    /// Registers a new subject schema, refusing duplicates or invalid plane/class pairs.
    pub fn register(&mut self, schema: SubjectSchema) -> Result<(), SubjectError> {
        schema.validate()?;
        if self.schemas.len() >= MAX_REGISTERED_SUBJECT_SCHEMAS {
            return Err(SubjectError::RegistryCapacityExceeded);
        }
        if self.schemas.contains_key(&schema.schema_id) {
            return Err(SubjectError::DuplicateSchemaId {
                schema_id: schema.schema_id,
            });
        }
        self.schemas.insert(schema.schema_id.clone(), schema);
        Ok(())
    }

    /// Permanently tombstones an existing schema version while preserving its ID in history.
    pub fn tombstone_version(
        &mut self,
        schema_id: &str,
        superseded_by_version: u32,
        reason: impl Into<String>,
    ) -> Result<(), SubjectError> {
        let entry =
            self.schemas
                .get_mut(schema_id)
                .ok_or_else(|| SubjectError::UnknownSchemaId {
                    schema_id: schema_id.to_owned(),
                })?;
        if superseded_by_version <= entry.version {
            return Err(SubjectError::InvalidSchema {
                schema_id: schema_id.to_owned(),
                reason: "superseded_by_version must be strictly greater than tombstoned version",
            });
        }
        entry.status = SubjectSchemaStatus::Tombstoned {
            superseded_by_version,
            reason: reason.into(),
        };
        Ok(())
    }

    /// Resolves a concrete [`SubjectName`] against registered schemas.
    /// Fails closed if unregistered, ambiguous, or tombstoned!
    pub fn resolve(&self, subject: &SubjectName) -> Result<ResolvedSubject, SubjectError> {
        let mut matched: Option<(&SubjectSchema, BTreeMap<String, String>)> = None;
        for schema in self.schemas.values() {
            if let Some(params) = schema.match_subject(subject) {
                if let Some((prev, _)) = matched {
                    return Err(SubjectError::AmbiguousSubjectMatch {
                        subject: subject.as_str().to_owned(),
                        first_schema: prev.schema_id.clone(),
                        second_schema: schema.schema_id.clone(),
                    });
                }
                matched = Some((schema, params));
            }
        }
        let Some((schema, params)) = matched else {
            return Err(SubjectError::UnregisteredSubject {
                subject: subject.as_str().to_owned(),
            });
        };
        if let SubjectSchemaStatus::Tombstoned {
            superseded_by_version,
            ref reason,
        } = schema.status
        {
            return Err(SubjectError::SubjectTombstoned {
                schema_id: schema.schema_id.clone(),
                version: schema.version,
                superseded_by_version,
                reason: reason.clone(),
            });
        }
        Ok(ResolvedSubject {
            schema: schema.clone(),
            params,
        })
    }

    /// Returns all registered schemas (active and tombstoned) in canonical sorted ID order.
    pub fn schemas(&self) -> impl Iterator<Item = &SubjectSchema> {
        self.schemas.values()
    }

    /// Looks up a schema by its stable ID (including tombstoned historical versions).
    #[must_use]
    pub fn get(&self, schema_id: &str) -> Option<&SubjectSchema> {
        self.schemas.get(schema_id)
    }

    /// Builds the canonical FSS reference subject registry covering all 6 families
    /// (`SUBJ-001`..`SUBJ-006`), all 3 planes (`Packet`, `Authority`, `Reasoning`),
    /// all 5 declared service classes, and a tombstoned legacy v1 schema proving
    /// non-renumbering tombstone retention.
    pub fn reference_fss_v1() -> Result<Self, SubjectError> {
        let mut reg = Self::new();
        #[allow(clippy::type_complexity)]
        let defs: &[(
            &str,
            SubjectFamily,
            u32,
            &str,
            FabricPlane,
            ServiceClass,
            RuntimeGrant,
            PrivacyZone,
            bool,
            bool,
            bool,
        )] = &[
            // SUBJ-001: Evidence deltas, sensor packets, thumbnails, and ordered health telemetry
            (
                "SUBJ-001.sensor.packet.v1",
                SubjectFamily::EvidenceDelta,
                1,
                "fss.site.<site>.sensor.<sensor>.packet_v1.<generation>",
                FabricPlane::Packet,
                ServiceClass::OrderedTelemetry,
                RuntimeGrant::ObserveStatus,
                PrivacyZone::ExteriorProperty,
                false,
                false,
                false,
            ),
            (
                "SUBJ-001.sensor.packet.v2",
                SubjectFamily::EvidenceDelta,
                2,
                "fss.site.<site>.sensor.<sensor>.packet.<generation>",
                FabricPlane::Packet,
                ServiceClass::OrderedTelemetry,
                RuntimeGrant::ObserveStatus,
                PrivacyZone::ExteriorProperty,
                false,
                true,
                false,
            ),
            (
                "SUBJ-001.sensor.thumbnail.v1",
                SubjectFamily::EvidenceDelta,
                1,
                "fss.site.<site>.sensor.<sensor>.thumbnail.<generation>",
                FabricPlane::Packet,
                ServiceClass::EphemeralLatest,
                RuntimeGrant::ObserveStatus,
                PrivacyZone::ExteriorProperty,
                false,
                false,
                false,
            ),
            (
                "SUBJ-001.sensor.health.v1",
                SubjectFamily::EvidenceDelta,
                1,
                "fss.site.<site>.sensor.<sensor>.health",
                FabricPlane::Packet,
                ServiceClass::OrderedTelemetry,
                RuntimeGrant::ObserveStatus,
                PrivacyZone::Metadata,
                false,
                true,
                false,
            ),
            (
                "SUBJ-001.evidence.delta.v1",
                SubjectFamily::EvidenceDelta,
                1,
                "fss.site.<site>.evidence.delta.<generation>",
                FabricPlane::Authority,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::LedgerAppend,
                PrivacyZone::ExteriorProperty,
                false,
                true,
                false,
            ),
            // SUBJ-002: Custody & root-last publication + ATP immutable object graphs
            (
                "SUBJ-002.archive.graph.v1",
                SubjectFamily::CustodyPublication,
                1,
                "fss.site.<site>.archive.<root>.graph",
                FabricPlane::Packet,
                ServiceClass::VerifiedObjectGraph,
                RuntimeGrant::ObjectStage,
                PrivacyZone::RestrictedCustody,
                false,
                false,
                true,
            ),
            (
                "SUBJ-002.archive.state.v1",
                SubjectFamily::CustodyPublication,
                1,
                "fss.site.<site>.archive.<root>.state",
                FabricPlane::Authority,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::ObjectPublish,
                PrivacyZone::RestrictedCustody,
                false,
                true,
                false,
            ),
            // SUBJ-003: Graph, model inference, and calibration derived reasoning
            (
                "SUBJ-003.graph.delta.v1",
                SubjectFamily::GraphModel,
                1,
                "fss.site.<site>.graph.<projection>.delta",
                FabricPlane::Reasoning,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::AgentQuery,
                PrivacyZone::Metadata,
                false,
                false,
                false,
            ),
            (
                "SUBJ-003.model.infer.v1",
                SubjectFamily::GraphModel,
                1,
                "fss.site.<site>.model.<generation>.infer",
                FabricPlane::Reasoning,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::ModelInfer,
                PrivacyZone::ExteriorProperty,
                false,
                false,
                false,
            ),
            (
                "SUBJ-003.calibration.state.v1",
                SubjectFamily::GraphModel,
                1,
                "fss.site.<site>.calibration.<generation>.state",
                FabricPlane::Reasoning,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::Calibrate,
                PrivacyZone::ExteriorProperty,
                false,
                false,
                false,
            ),
            // SUBJ-004: Agent cognition, event revisions, and decision cards
            (
                "SUBJ-004.event.revision.v1",
                SubjectFamily::AgentCognition,
                1,
                "fss.site.<site>.event.<event>.revision",
                FabricPlane::Reasoning,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::ObserveEvent,
                PrivacyZone::ExteriorProperty,
                false,
                false,
                false,
            ),
            (
                "SUBJ-004.evidence.decision.v1",
                SubjectFamily::AgentCognition,
                1,
                "fss.evidence.decision.<decision>",
                FabricPlane::Reasoning,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::AgentExplain,
                PrivacyZone::Metadata,
                false,
                false,
                false,
            ),
            // SUBJ-005: Plans, effects, adapter requests, and durable obligations (Authority plane ONLY)
            (
                "SUBJ-005.incident.obligation.v1",
                SubjectFamily::PlanEffectObligation,
                1,
                "fss.site.<site>.incident.<incident>.obligation",
                FabricPlane::Authority,
                ServiceClass::ObligatedExactlyEffectOnce,
                RuntimeGrant::AlertCommit,
                PrivacyZone::ExteriorProperty,
                true,
                true,
                false,
            ),
            (
                "SUBJ-005.control.effect.prepare.v1",
                SubjectFamily::PlanEffectObligation,
                1,
                "fss.control.effect.<effect_kind>.prepare",
                FabricPlane::Authority,
                ServiceClass::ObligatedExactlyEffectOnce,
                RuntimeGrant::AgentPlanPrepare,
                PrivacyZone::Metadata,
                true,
                true,
                false,
            ),
            (
                "SUBJ-005.control.adapter.request.v1",
                SubjectFamily::PlanEffectObligation,
                1,
                "fss.control.adapter.<adapter>.request",
                FabricPlane::Authority,
                ServiceClass::ObligatedExactlyEffectOnce,
                RuntimeGrant::AdapterNet,
                PrivacyZone::InteriorPrivate,
                true,
                true,
                false,
            ),
            // SUBJ-006: Proof bundles and qualification receipts
            (
                "SUBJ-006.proof.publish.v1",
                SubjectFamily::Proof,
                1,
                "fss.site.<site>.proof.<bundle>.publish",
                FabricPlane::Authority,
                ServiceClass::DurableAtLeastOnce,
                RuntimeGrant::ObjectPublish,
                PrivacyZone::Metadata,
                false,
                true,
                false,
            ),
        ];

        for &(
            schema_id,
            family,
            version,
            template,
            plane,
            service_class,
            required_grant,
            privacy_zone,
            requires_lease_fence,
            terminal_or_coverage_critical,
            allows_archive_locality,
        ) in defs
        {
            reg.register(SubjectSchema {
                schema_id: schema_id.to_owned(),
                family,
                version,
                pattern: SubjectSchema::parse_pattern(template)?,
                plane,
                service_class,
                required_grant,
                privacy_zone,
                requires_lease_fence,
                terminal_or_coverage_critical,
                allows_archive_locality,
                status: SubjectSchemaStatus::Active,
            })?;
        }
        // Permanently tombstone `SUBJ-001.sensor.packet.v1` -> superseded by `v2`.
        reg.tombstone_version(
            "SUBJ-001.sensor.packet.v1",
            2,
            "Superseded by SUBJ-001.sensor.packet.v2 with mandatory coverage-critical continuity",
        )?;
        Ok(reg)
    }
}

// ---------------------------------------------------------------------------
// Route Compiler: Capability, Privacy, Locality, Pressure, and Profile
// ---------------------------------------------------------------------------

/// Input coordinates used by [`RouteCompiler::compile`] to synthesize a deterministic
/// routing table. Routing NEVER confers or widens authority.
#[derive(Clone, Debug)]
pub struct RouteContext {
    /// Explicit caller/subscriber capability grants.
    pub grants: GrantSet,
    /// Authorized site identifiers (`<site>` parameter scope). Empty denies all site-scoped subjects.
    pub allowed_sites: BTreeSet<String>,
    /// Optional explicit sensor allowlist (`<sensor>` parameter scope). `None` permits all sensors inside allowed sites.
    pub allowed_sensors: Option<BTreeSet<String>>,
    /// Authorized privacy classification zones (fail-closed outside this set).
    pub allowed_privacy_zones: BTreeSet<PrivacyZone>,
    /// Target data locality of the route consumer/hop.
    pub target_locality: DataLocality,
    /// Observed current resource pressure (`Nominal`, `Elevated`, `Constrained`, `Critical`).
    pub pressure: ResourcePressure,
    /// Deployment profile constraining batching and priorities.
    pub profile: DeploymentProfile,
}

/// Compiled routing verdict for one registered subject schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDisposition {
    /// Subject is eligible for admission (runtime still re-verifies `AuthorityCx` / grants / fences).
    Admitted {
        /// Effective deterministic scheduler priority (higher runs first within fairness window).
        effective_priority: u8,
        /// Whether packet-plane batching/coalescing is permitted on this route.
        batching_allowed: bool,
        /// Maximum batch size (`1` for all non-batchable and Authority/Reasoning subjects).
        max_batch_size: usize,
        /// Effective data locality hop.
        locality: DataLocality,
    },
    /// Denied due to missing capability, forbidden privacy zone, tombstoned schema, or illegal locality.
    Denied {
        /// Stable machine-readable denial code.
        code: &'static str,
        /// Non-secret explanation.
        reason: String,
    },
    /// Explicitly shed due to elevated/constrained/critical resource pressure (only `EphemeralLatest`).
    PressureShed {
        /// Observed resource pressure causing shed.
        pressure: ResourcePressure,
        /// Non-secret explanation.
        reason: String,
    },
}

/// One compiled route entry in a [`CompiledRouteTable`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRoute {
    /// Registered stable schema ID.
    pub schema_id: String,
    /// Owning plane.
    pub plane: FabricPlane,
    /// Declared service class.
    pub service_class: ServiceClass,
    /// Required capability (still re-checked via explicit `AuthorityCx` at publish/dispatch!).
    pub required_grant: RuntimeGrant,
    /// Privacy zone.
    pub privacy_zone: PrivacyZone,
    /// Compiled disposition.
    pub disposition: RouteDisposition,
}

/// Cryptographic receipt summarizing a deterministic route compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCompilationReceipt {
    /// Canonical SHA-256 digest over all compiled routes and context coordinates.
    pub route_table_digest: ContentDigest,
    /// Deployment profile used during compilation.
    pub profile: DeploymentProfile,
    /// Resource pressure used during compilation.
    pub pressure: ResourcePressure,
    /// Locality target used during compilation.
    pub target_locality: DataLocality,
    /// Count of admitted, denied, and pressure-shed schemas.
    pub admitted_count: usize,
    /// Count of denied schemas.
    pub denied_count: usize,
    /// Count of pressure-shed schemas.
    pub shed_count: usize,
    /// Structural invariant: routing compilation NEVER grants effect authority.
    pub grants_effect_authority: bool,
}

/// Deterministic compiled routing table binding capability, privacy, locality, pressure,
/// and profile to every registered schema.
#[derive(Clone, Debug)]
pub struct CompiledRouteTable {
    routes: BTreeMap<String, CompiledRoute>,
    allowed_sites: BTreeSet<String>,
    allowed_sensors: Option<BTreeSet<String>>,
    allowed_privacy_zones: BTreeSet<PrivacyZone>,
    pressure: ResourcePressure,
    profile: DeploymentProfile,
    target_locality: DataLocality,
    receipt: RouteCompilationReceipt,
}

impl CompiledRouteTable {
    /// Returns the compilation receipt (`grants_effect_authority == false` always).
    #[must_use]
    pub fn receipt(&self) -> &RouteCompilationReceipt {
        &self.receipt
    }

    /// Returns the compiled route for `schema_id`, if present.
    #[must_use]
    pub fn route_for(&self, schema_id: &str) -> Option<&CompiledRoute> {
        self.routes.get(schema_id)
    }

    /// Returns all compiled routes in canonical sorted schema ID order.
    pub fn routes(&self) -> impl Iterator<Item = &CompiledRoute> {
        self.routes.values()
    }

    /// Checks whether a concrete resolved subject may be routed under this compiled table,
    /// verifying site scope, sensor scope, privacy zone, locality, and pressure.
    /// Does NOT replace explicit `AuthorityCx` verification on the Authority plane!
    pub fn check_subject(
        &self,
        resolved: &ResolvedSubject,
    ) -> Result<&CompiledRoute, SubjectError> {
        let route = self.routes.get(&resolved.schema.schema_id).ok_or_else(|| {
            SubjectError::UnregisteredSubject {
                subject: resolved.schema.schema_id.clone(),
            }
        })?;
        match &route.disposition {
            RouteDisposition::Admitted { .. } => {}
            RouteDisposition::Denied { code, reason } => {
                return Err(SubjectError::RouteDenied {
                    schema_id: resolved.schema.schema_id.clone(),
                    code,
                    reason: reason.clone(),
                });
            }
            RouteDisposition::PressureShed { pressure, reason } => {
                return Err(SubjectError::PressureShed {
                    schema_id: resolved.schema.schema_id.clone(),
                    pressure: *pressure,
                    reason: reason.clone(),
                });
            }
        }
        // Scope checks (`INT-AS-001` gate #6: cannot cross unauthorized site/device/privacy scope).
        if !self
            .allowed_privacy_zones
            .contains(&resolved.schema.privacy_zone)
        {
            return Err(SubjectError::PrivacyScopeViolation {
                schema_id: resolved.schema.schema_id.clone(),
                zone: resolved.schema.privacy_zone,
            });
        }
        if let Some(site) = resolved.params.get("site")
            && !self.allowed_sites.contains(site)
        {
            return Err(SubjectError::SiteScopeViolation {
                schema_id: resolved.schema.schema_id.clone(),
                site: site.clone(),
            });
        }
        if let Some(sensor) = resolved.params.get("sensor")
            && let Some(ref allowed) = self.allowed_sensors
            && !allowed.contains(sensor)
        {
            return Err(SubjectError::SensorScopeViolation {
                schema_id: resolved.schema.schema_id.clone(),
                sensor: sensor.clone(),
            });
        }
        Ok(route)
    }

    /// Returns the pressure level compiled into this table.
    #[must_use]
    pub const fn pressure(&self) -> ResourcePressure {
        self.pressure
    }

    /// Returns the deployment profile compiled into this table.
    #[must_use]
    pub const fn profile(&self) -> DeploymentProfile {
        self.profile
    }

    /// Returns the target locality compiled into this table.
    #[must_use]
    pub const fn target_locality(&self) -> DataLocality {
        self.target_locality
    }
}

/// Deterministic compiler from `(SubjectSchemaRegistry, RouteContext)` to [`CompiledRouteTable`].
pub struct RouteCompiler;

impl RouteCompiler {
    /// Compiles a deterministic routing table across all registered schemas.
    #[must_use]
    pub fn compile(registry: &SubjectSchemaRegistry, ctx: &RouteContext) -> CompiledRouteTable {
        let mut routes = BTreeMap::new();
        let mut admitted_count = 0_usize;
        let mut denied_count = 0_usize;
        let mut shed_count = 0_usize;

        for schema in registry.schemas() {
            let disposition = match &schema.status {
                SubjectSchemaStatus::Tombstoned {
                    superseded_by_version,
                    reason,
                } => {
                    denied_count += 1;
                    RouteDisposition::Denied {
                        code: "SUBJECT-TOMBSTONED",
                        reason: format!(
                            "version {} tombstoned (superseded by v{}): {}",
                            schema.version, superseded_by_version, reason
                        ),
                    }
                }
                SubjectSchemaStatus::Active => {
                    if !ctx.grants.has(schema.required_grant) {
                        denied_count += 1;
                        RouteDisposition::Denied {
                            code: "MISSING-CAPABILITY",
                            reason: format!(
                                "caller lacks required capability {}",
                                schema.required_grant.as_str()
                            ),
                        }
                    } else if !ctx.allowed_privacy_zones.contains(&schema.privacy_zone) {
                        denied_count += 1;
                        RouteDisposition::Denied {
                            code: "PRIVACY-ZONE-DENIED",
                            reason: format!(
                                "privacy zone `{}` outside authorized scope",
                                schema.privacy_zone.as_str()
                            ),
                        }
                    } else if ctx.target_locality == DataLocality::ArchiveRegion
                        && !schema.allows_archive_locality
                    {
                        denied_count += 1;
                        RouteDisposition::Denied {
                            code: "ARCHIVE-LOCALITY-FORBIDDEN",
                            reason: "only ATP VerifiedObjectGraph subjects may cross ArchiveRegion boundary"
                                .to_owned(),
                        }
                    } else if matches!(
                        ctx.pressure,
                        ResourcePressure::Constrained | ResourcePressure::Critical
                    ) && schema.service_class.sheddable_under_pressure()
                        && !schema.terminal_or_coverage_critical
                    {
                        shed_count += 1;
                        RouteDisposition::PressureShed {
                            pressure: ctx.pressure,
                            reason: format!(
                                "shed non-critical {} subject under {} resource pressure",
                                schema.service_class.as_str(),
                                ctx.pressure.as_str()
                            ),
                        }
                    } else if ctx.pressure == ResourcePressure::Critical
                        && schema.plane == FabricPlane::Reasoning
                        && !schema.terminal_or_coverage_critical
                    {
                        shed_count += 1;
                        RouteDisposition::PressureShed {
                            pressure: ctx.pressure,
                            reason: "shed non-critical derived reasoning under critical pressure to protect authority terminalization"
                                .to_owned(),
                        }
                    } else {
                        admitted_count += 1;
                        let effective_priority = compute_route_priority(schema, ctx.profile);
                        let batching_allowed = schema.plane == FabricPlane::Packet
                            && schema.service_class.allows_packet_batching()
                            && !schema.terminal_or_coverage_critical;
                        let max_batch_size = if batching_allowed {
                            ctx.profile.max_packet_batch()
                        } else {
                            1
                        };
                        RouteDisposition::Admitted {
                            effective_priority,
                            batching_allowed,
                            max_batch_size,
                            locality: ctx.target_locality,
                        }
                    }
                }
            };

            routes.insert(
                schema.schema_id.clone(),
                CompiledRoute {
                    schema_id: schema.schema_id.clone(),
                    plane: schema.plane,
                    service_class: schema.service_class,
                    required_grant: schema.required_grant,
                    privacy_zone: schema.privacy_zone,
                    disposition,
                },
            );
        }

        let mut enc = CanonicalEncoder::new();
        enc.text(ROUTE_TABLE_DIGEST_TAG);
        enc.text(ctx.profile.as_str());
        enc.text(ctx.pressure.as_str());
        enc.text(ctx.target_locality.as_str());
        enc.u64(ctx.allowed_sites.len() as u64);
        for s in &ctx.allowed_sites {
            enc.text(s);
        }
        enc.u64(ctx.allowed_privacy_zones.len() as u64);
        for z in &ctx.allowed_privacy_zones {
            enc.text(z.as_str());
        }
        enc.u64(routes.len() as u64);
        for route in routes.values() {
            enc.text(&route.schema_id);
            enc.text(route.plane.as_str());
            enc.text(route.service_class.as_str());
            enc.text(route.required_grant.as_str());
            enc.text(route.privacy_zone.as_str());
            match &route.disposition {
                RouteDisposition::Admitted {
                    effective_priority,
                    batching_allowed,
                    max_batch_size,
                    locality,
                } => {
                    enc.u8(1);
                    enc.u8(*effective_priority);
                    enc.bool(*batching_allowed);
                    enc.u64(*max_batch_size as u64);
                    enc.text(locality.as_str());
                }
                RouteDisposition::Denied { code, .. } => {
                    enc.u8(2);
                    enc.text(code);
                }
                RouteDisposition::PressureShed { pressure, .. } => {
                    enc.u8(3);
                    enc.text(pressure.as_str());
                }
            }
        }
        enc.bool(false); // grants_effect_authority is ALWAYS false
        let route_table_digest = ContentDigest::sha256(&enc.finish());

        CompiledRouteTable {
            routes,
            allowed_sites: ctx.allowed_sites.clone(),
            allowed_sensors: ctx.allowed_sensors.clone(),
            allowed_privacy_zones: ctx.allowed_privacy_zones.clone(),
            pressure: ctx.pressure,
            profile: ctx.profile,
            target_locality: ctx.target_locality,
            receipt: RouteCompilationReceipt {
                route_table_digest,
                profile: ctx.profile,
                pressure: ctx.pressure,
                target_locality: ctx.target_locality,
                admitted_count,
                denied_count,
                shed_count,
                grants_effect_authority: false,
            },
        }
    }
}

const fn compute_route_priority(schema: &SubjectSchema, _profile: DeploymentProfile) -> u8 {
    match (schema.plane, schema.terminal_or_coverage_critical) {
        (FabricPlane::Authority, true) => 240,
        (FabricPlane::Authority, false) => 200,
        (FabricPlane::Packet, true) => 160,
        (FabricPlane::Reasoning, true) => 140,
        (FabricPlane::Reasoning, false) => 100,
        (FabricPlane::Packet, false) => match schema.service_class {
            ServiceClass::OrderedTelemetry => 90,
            ServiceClass::VerifiedObjectGraph => 70,
            ServiceClass::EphemeralLatest => 40,
            _ => 60,
        },
    }
}

// ---------------------------------------------------------------------------
// Type-Distinct Envelopes (Packet, Reasoning, Authority, ATP Object Graph)
// ---------------------------------------------------------------------------

/// Immutable ATP object-graph payload carried ONLY on `ServiceClass::VerifiedObjectGraph`
/// (`INV-046`, `INV-047`, `INV-066`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtpObjectGraphManifest {
    /// Immutable manifest digest.
    pub manifest_digest: ContentDigest,
    /// Root object digest exposed only after child closure and post-repair verification.
    pub root_digest: ContentDigest,
    /// Ordered immutable chunk digests composing this object graph.
    pub chunk_digests: Vec<ContentDigest>,
    /// Number of RaptorQ / parity repair symbols bundled with the transfer.
    pub repair_symbol_count: u32,
    /// Whether child closure and post-repair canonical digest checks succeeded.
    pub post_repair_verified: bool,
    /// Whether root-last exposure invariant is enabled (must be `true`).
    pub root_last_exposure: bool,
    /// Structural invariant: ATP NEVER carries mutation/effect authority.
    grants_effect_authority: bool,
}

impl AtpObjectGraphManifest {
    /// Constructs a validated ATP object-graph manifest (`grants_effect_authority == false`).
    pub fn new(
        manifest_digest: ContentDigest,
        root_digest: ContentDigest,
        chunk_digests: Vec<ContentDigest>,
        repair_symbol_count: u32,
        post_repair_verified: bool,
        root_last_exposure: bool,
    ) -> Result<Self, SubjectError> {
        if chunk_digests.is_empty() || chunk_digests.len() > MAX_ATP_MANIFEST_CHUNKS {
            return Err(SubjectError::InvalidAtpManifest {
                reason: "chunk_digests count violates 1..=256",
            });
        }
        if !root_last_exposure {
            return Err(SubjectError::InvalidAtpManifest {
                reason: "ATP requires root_last_exposure == true (INV-046)",
            });
        }
        if !post_repair_verified {
            return Err(SubjectError::InvalidAtpManifest {
                reason: "ATP root cannot publish before post-repair digest verification (INV-046)",
            });
        }
        Ok(Self {
            manifest_digest,
            root_digest,
            chunk_digests,
            repair_symbol_count,
            post_repair_verified,
            root_last_exposure,
            grants_effect_authority: false,
        })
    }

    /// Always `false` (`INV-047`, `INV-066`).
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        self.grants_effect_authority
    }
}

/// Immutable Packet-plane message carrying content digests/handles, provenance, and budget.
/// Structurally incapable of carrying or granting effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct PacketSubmission {
    /// Target semantic subject (must resolve to `FabricPlane::Packet`).
    pub subject: SubjectName,
    /// Stable source stream identity (used for `OrderedTelemetry` sequencing and `EphemeralLatest` keying).
    pub source_key: String,
    /// Per-source monotone sequence number (required for `OrderedTelemetry`, advisory otherwise).
    pub sequence: u64,
    /// Immutable content-addressed object/handle digests carried by this packet.
    pub object_digests: Vec<ContentDigest>,
    /// Explicit provenance classification label (e.g. `"source:sensor-capture"`).
    pub provenance: String,
    /// Declared budget cost for moving this packet.
    pub budget: BudgetVector,
    /// Caller-observed creation timestamp.
    pub created_at: TimestampNs,
    /// Optional absolute expiry deadline in caller time domain.
    pub deadline: Option<TimestampNs>,
    /// Required for `ServiceClass::VerifiedObjectGraph`; forbidden for other packet classes.
    pub atp_manifest: Option<AtpObjectGraphManifest>,
}

/// Derived Reasoning-plane submission anchored to an immutable evidence root and generation.
/// Structurally incapable of mutating authoritative state or carrying effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct ReasoningSubmission {
    /// Target semantic subject (must resolve to `FabricPlane::Reasoning`).
    pub subject: SubjectName,
    /// Idempotent delivery key for `DurableAtLeastOnce` consumers.
    pub delivery_key: String,
    /// Pinned canonical `EvidenceAnchor` state root (never mutable "latest").
    pub evidence_anchor_root: ContentDigest,
    /// Immutable model/graph/calibration generation identifier.
    pub generation_id: String,
    /// Content digest of the derived cognition payload.
    pub payload_digest: ContentDigest,
    /// Declared budget cost for this derived work item.
    pub budget: BudgetVector,
    /// Caller-observed creation timestamp.
    pub created_at: TimestampNs,
    /// Optional absolute deadline in caller time domain.
    pub deadline: Option<TimestampNs>,
}

/// Explicit Authority-plane submission. Must ALWAYS be paired with a live `&mut AuthorityCx`,
/// `&mut RegionTree`, and `&LeaseRegistry` at admission — authority is never inferred from routing!
#[derive(Clone, Debug, PartialEq)]
pub struct AuthoritySubmission {
    /// Target semantic subject (must resolve to `FabricPlane::Authority`).
    pub subject: SubjectName,
    /// Operation identity bound to the region obligation.
    pub operation_id: OperationId,
    /// Stable idempotency key preventing duplicate effect admission.
    pub idempotency_key: IdempotencyKey,
    /// Leased resource identity (checked against [`LeaseRegistry`] when schema requires a fence).
    pub resource: String,
    /// Monotone lease fence token (checked via [`LeaseRegistry::check_fence`]).
    pub fence: u64,
    /// Terminal predicate recorded on the region obligation.
    pub terminal_predicate: String,
    /// Content digest of the authoritative command/publication payload.
    pub payload_digest: ContentDigest,
    /// Declared budget cost debited atomically from `AuthorityCx::budget_mut`.
    pub budget: BudgetVector,
    /// Caller-observed submission timestamp.
    pub created_at: TimestampNs,
    /// Optional absolute deadline in caller time domain.
    pub deadline: Option<TimestampNs>,
}

// ---------------------------------------------------------------------------
// Receipts, Certificates, and Queued Items
// ---------------------------------------------------------------------------

/// Receipt emitted whenever an `EphemeralLatest` message supersedes an older queued entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersedeReceipt {
    /// Subject key whose queued entry was replaced.
    pub subject: String,
    /// Source key.
    pub source_key: String,
    /// Replaced message sequence.
    pub superseded_seq: u64,
    /// New dominant message sequence.
    pub replacement_seq: u64,
}

/// Explicit gap/reordering receipt emitted by `OrderedTelemetry` (never silent packet drop).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryGapReceipt {
    /// Subject address.
    pub subject: String,
    /// Source stream key.
    pub source_key: String,
    /// Expected next monotone sequence.
    pub expected_seq: u64,
    /// Observed sequence number.
    pub observed_seq: u64,
    /// Whether `observed_seq < expected_seq` (out-of-order/duplicate) vs `> expected_seq` (gap).
    pub out_of_order: bool,
}

/// Publication admission outcome returned by fabric submission methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    /// Monotone fabric-assigned envelope sequence number.
    pub fabric_seq: u64,
    /// Resolved schema ID.
    pub schema_id: String,
    /// Owning plane.
    pub plane: FabricPlane,
    /// Declared service class.
    pub service_class: ServiceClass,
    /// Associated canonical obligation ID (present for Authority plane `ObligatedExactlyEffectOnce`).
    pub obligation_id: Option<ObligationId>,
    /// Whether an existing idempotent Authority submission was deduplicated (no duplicate enqueue).
    pub deduplicated: bool,
    /// Present when `EphemeralLatest` replaced an older queued item.
    pub superseded: Option<SupersedeReceipt>,
    /// Present when `OrderedTelemetry` detected a sequence gap or out-of-order packet.
    pub telemetry_gap: Option<TelemetryGapReceipt>,
    /// Whether this receipt grants effect execution authority (ALWAYS `false` on `Packet` and `Reasoning`).
    pub grants_effect_authority: bool,
    /// Canonical receipt digest.
    pub receipt_digest: ContentDigest,
}

/// One dequeued envelope delivered to its owning plane consumer.
#[derive(Clone, Debug, PartialEq)]
pub enum DispatchedMessage {
    /// Immutable packet-plane item (`grants_effect_authority == false`).
    Packet {
        /// Monotone fabric admission sequence.
        fabric_seq: u64,
        /// Resolved schema ID.
        schema_id: String,
        /// Service class (`EphemeralLatest`, `OrderedTelemetry`, or `VerifiedObjectGraph`).
        service_class: ServiceClass,
        /// Original packet submission.
        submission: PacketSubmission,
        /// Always `false`.
        grants_effect_authority: bool,
    },
    /// Derived reasoning-plane item (`is_authoritative_truth == false`, `grants_effect_authority == false`).
    Reasoning {
        /// Monotone fabric admission sequence.
        fabric_seq: u64,
        /// Resolved schema ID.
        schema_id: String,
        /// Delivery attempt counter (`1..=max_retries`).
        attempt: u32,
        /// Original reasoning submission.
        submission: ReasoningSubmission,
        /// Always `false`.
        is_authoritative_truth: bool,
        /// Always `false`.
        grants_effect_authority: bool,
    },
    /// Explicit authority-plane item bound to its region, capability check, lease fence, and obligation.
    Authority {
        /// Monotone fabric admission sequence.
        fabric_seq: u64,
        /// Authority-plane strict FIFO ordinal (never reordered by packet-plane batching!).
        authority_order_seq: u64,
        /// Resolved schema ID.
        schema_id: String,
        /// Service class (`DurableAtLeastOnce` or `ObligatedExactlyEffectOnce`).
        service_class: ServiceClass,
        /// Delivery attempt counter.
        attempt: u32,
        /// Registered obligation ID (always `Some` for `ObligatedExactlyEffectOnce`).
        obligation_id: Option<ObligationId>,
        /// Owning region ID verified at admission.
        region_id: RegionId,
        /// Original authority submission.
        submission: AuthoritySubmission,
    },
}

impl DispatchedMessage {
    /// Returns the owning plane of this dispatched message.
    #[must_use]
    pub const fn plane(&self) -> FabricPlane {
        match self {
            Self::Packet { .. } => FabricPlane::Packet,
            Self::Reasoning { .. } => FabricPlane::Reasoning,
            Self::Authority { .. } => FabricPlane::Authority,
        }
    }

    /// Returns the monotone fabric admission sequence.
    #[must_use]
    pub const fn fabric_seq(&self) -> u64 {
        match self {
            Self::Packet { fabric_seq, .. }
            | Self::Reasoning { fabric_seq, .. }
            | Self::Authority { fabric_seq, .. } => *fabric_seq,
        }
    }
}

/// Receipt proving a packet-plane batch did not disturb authority/freshness/terminal ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketBatchReceipt {
    /// Number of packet messages batched.
    pub packet_count: usize,
    /// Service class of the batch (`EphemeralLatest` or `VerifiedObjectGraph`).
    pub service_class: ServiceClass,
    /// Authority-plane high-water mark before and after batch drain (unchanged!).
    pub authority_order_high_water: u64,
    /// Structural invariant: packet batching NEVER carries or alters effect authority.
    pub grants_effect_authority: bool,
}

/// Durable delivery acknowledgement state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableAckOutcome {
    /// Message acknowledged and retired from in-flight durable tracking.
    Acknowledged,
    /// Message nacked and requeued for bounded redelivery.
    Redelivered {
        /// Next attempt number.
        next_attempt: u32,
    },
    /// Retry budget exhausted; retired as explicit dead-letter record (never silently dropped).
    DeadLettered {
        /// Total attempts executed.
        attempts: u32,
    },
}

/// Receipt emitted when an item expires before dispatch (`now >= deadline`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadlineExpiredReceipt {
    /// Fabric sequence of the expired item.
    pub fabric_seq: u64,
    /// Schema ID.
    pub schema_id: String,
    /// Plane.
    pub plane: FabricPlane,
    /// Deadline instant.
    pub deadline: TimestampNs,
    /// Evaluation time when expiry was observed.
    pub observed_at: TimestampNs,
}

/// Monotonic drain progress certificate (`INT-AS-001` gate #3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainProgressCertificate {
    /// Total queued + in-flight durable items before this drain step.
    pub remaining_before: usize,
    /// Total queued + in-flight durable items after this drain step.
    pub remaining_after: usize,
    /// Count of items drained or expired in this step.
    pub drained_this_step: usize,
    /// Count of items expired due to deadline during this step.
    pub expired_this_step: usize,
    /// Caller timestamp of this drain step.
    pub observed_at: TimestampNs,
    /// Canonical certificate digest.
    pub certificate_digest: ContentDigest,
}

/// Finalization receipt proving zero queued work, zero in-flight durable deliveries,
/// zero leaked region obligations, and canonical subtree [`QuiescenceProof`].
/// Registered in `architecture/semantic_plane_registry.json` (`plane: "authority"`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FabricQuiescenceReceipt {
    /// Region owning this fabric.
    pub region_id: RegionId,
    /// Canonical region-tree quiescence proof.
    pub quiescence_proof: QuiescenceProof,
    /// Total messages admitted over the fabric's lifetime across all three planes.
    pub total_admitted: u64,
    /// Total authority-plane messages dispatched in strict order.
    pub total_authority_dispatched: u64,
    /// Total packet-plane messages dispatched.
    pub total_packet_dispatched: u64,
    /// Total reasoning-plane messages dispatched.
    pub total_reasoning_dispatched: u64,
    /// Total expired items explicitly accounted for.
    pub total_expired: u64,
    /// Total telemetry gaps explicitly recorded.
    pub total_telemetry_gaps: u64,
    /// Remaining queued items (guaranteed `0`).
    pub remaining_queued: usize,
    /// Remaining unacknowledged in-flight durable deliveries (guaranteed `0`).
    pub remaining_in_flight: usize,
    /// Canonical receipt digest.
    pub receipt_digest: ContentDigest,
}

// ---------------------------------------------------------------------------
// Queue Bounds, Fairness Weights, and Errors
// ---------------------------------------------------------------------------

/// Hard per-service-class queue bounds preventing unbounded memory growth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueBounds {
    /// Max queued `EphemeralLatest` packets (per-key supersede applies before backpressure).
    pub ephemeral_latest: usize,
    /// Max queued `OrderedTelemetry` packets.
    pub ordered_telemetry: usize,
    /// Max queued `VerifiedObjectGraph` ATP manifests.
    pub verified_object_graph: usize,
    /// Max queued `Reasoning` `DurableAtLeastOnce` messages.
    pub reasoning_durable: usize,
    /// Max queued `Authority` `DurableAtLeastOnce` messages.
    pub authority_durable: usize,
    /// Max queued `Authority` `ObligatedExactlyEffectOnce` messages.
    pub authority_obligated: usize,
    /// Maximum bounded delivery attempts for `DurableAtLeastOnce` messages (`>= 1`).
    pub max_durable_attempts: u32,
}

impl Default for QueueBounds {
    fn default() -> Self {
        Self {
            ephemeral_latest: 64,
            ordered_telemetry: 256,
            verified_object_graph: 64,
            reasoning_durable: 128,
            authority_durable: 256,
            authority_obligated: 256,
            max_durable_attempts: 3,
        }
    }
}

impl QueueBounds {
    /// Validates every bound is within `1..=MAX_SERVICE_QUEUE_DEPTH`.
    pub fn validate(&self) -> Result<(), SubjectError> {
        for (name, cap) in [
            ("ephemeral_latest", self.ephemeral_latest),
            ("ordered_telemetry", self.ordered_telemetry),
            ("verified_object_graph", self.verified_object_graph),
            ("reasoning_durable", self.reasoning_durable),
            ("authority_durable", self.authority_durable),
            ("authority_obligated", self.authority_obligated),
        ] {
            if cap == 0 || cap > MAX_SERVICE_QUEUE_DEPTH {
                return Err(SubjectError::InvalidQueueBounds {
                    queue: name,
                    capacity: cap,
                });
            }
        }
        if self.max_durable_attempts == 0 || self.max_durable_attempts > 16 {
            return Err(SubjectError::InvalidQueueBounds {
                queue: "max_durable_attempts",
                capacity: self.max_durable_attempts as usize,
            });
        }
        Ok(())
    }
}

/// Deterministic weighted fairness credits preventing plane starvation while guaranteeing
/// Authority priority over high-volume Packet bursts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FairnessWeights {
    /// Authority-plane quanta per scheduling epoch.
    pub authority_weight: u32,
    /// Reasoning-plane quanta per scheduling epoch.
    pub reasoning_weight: u32,
    /// Packet-plane quanta per scheduling epoch.
    pub packet_weight: u32,
}

impl Default for FairnessWeights {
    fn default() -> Self {
        Self {
            authority_weight: 4,
            reasoning_weight: 2,
            packet_weight: 1,
        }
    }
}

impl FairnessWeights {
    /// Validates strict positivity and Authority dominance (`authority >= reasoning >= packet >= 1`).
    pub fn validate(&self) -> Result<(), SubjectError> {
        if self.packet_weight == 0
            || self.reasoning_weight < self.packet_weight
            || self.authority_weight < self.reasoning_weight
        {
            return Err(SubjectError::InvalidFairnessWeights);
        }
        Ok(())
    }
}

/// Typed fail-closed errors across the semantic subject fabric.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectError {
    /// Subject string failed syntax or namespace validation.
    InvalidSubjectName {
        /// Offending subject string.
        subject: String,
        /// Validation failure reason.
        reason: &'static str,
    },
    /// Schema definition violated structural invariants.
    InvalidSchema {
        /// Schema identifier.
        schema_id: String,
        /// Validation failure reason.
        reason: &'static str,
    },
    /// Service class is illegal on the declared semantic plane.
    PlaneServiceClassMismatch {
        /// Declared plane.
        plane: FabricPlane,
        /// Declared service class.
        service_class: ServiceClass,
    },
    /// Attempted to register an already existing schema ID.
    DuplicateSchemaId {
        /// Duplicate ID.
        schema_id: String,
    },
    /// Unknown schema ID referenced.
    UnknownSchemaId {
        /// Missing ID.
        schema_id: String,
    },
    /// Registry reached hard schema capacity.
    RegistryCapacityExceeded,
    /// Subject did not match any registered schema.
    UnregisteredSubject {
        /// Concrete subject string.
        subject: String,
    },
    /// Subject matched two registered patterns ambiguously.
    AmbiguousSubjectMatch {
        /// Concrete subject string.
        subject: String,
        /// First schema ID.
        first_schema: String,
        /// Second schema ID.
        second_schema: String,
    },
    /// Subject resolved to a permanently tombstoned schema version.
    SubjectTombstoned {
        /// Tombstoned schema ID.
        schema_id: String,
        /// Tombstoned version.
        version: u32,
        /// Active replacement version.
        superseded_by_version: u32,
        /// Migration note.
        reason: String,
    },
    /// Caller attempted to submit through the wrong plane API (e.g. Authority subject via Packet API).
    WrongPlaneBoundary {
        /// Schema's owning plane.
        expected: FabricPlane,
        /// Attempted boundary plane.
        attempted: FabricPlane,
    },
    /// Compiled route denied admission.
    RouteDenied {
        /// Schema ID.
        schema_id: String,
        /// Stable denial code.
        code: &'static str,
        /// Non-secret reason.
        reason: String,
    },
    /// Subject explicitly shed under resource pressure.
    PressureShed {
        /// Schema ID.
        schema_id: String,
        /// Observed pressure.
        pressure: ResourcePressure,
        /// Non-secret reason.
        reason: String,
    },
    /// Subject crossed an unauthorized privacy zone.
    PrivacyScopeViolation {
        /// Schema ID.
        schema_id: String,
        /// Disallowed zone.
        zone: PrivacyZone,
    },
    /// Subject crossed an unauthorized site scope.
    SiteScopeViolation {
        /// Schema ID.
        schema_id: String,
        /// Disallowed site.
        site: String,
    },
    /// Subject crossed an unauthorized sensor scope.
    SensorScopeViolation {
        /// Schema ID.
        schema_id: String,
        /// Disallowed sensor.
        sensor: String,
    },
    /// Invalid ATP object-graph manifest or attempt to transport non-ATP payload on VerifiedObjectGraph.
    InvalidAtpManifest {
        /// Violation detail.
        reason: &'static str,
    },
    /// Packet payload violated hard bounds or missing provenance.
    InvalidPacketPayload {
        /// Violation detail.
        reason: &'static str,
    },
    /// Reasoning payload lacked pinned generation or valid delivery key.
    InvalidReasoningPayload {
        /// Violation detail.
        reason: &'static str,
    },
    /// Explicit `AuthorityCx` capability or region check failed.
    AuthorityDenied {
        /// Non-secret detail.
        detail: String,
    },
    /// Explicit lease fence check failed (`LeaseRegistry::check_fence`).
    LeaseFenceDenied {
        /// Lease failure reason.
        error: LeaseError,
    },
    /// Target service-class queue reached its hard capacity (explicit backpressure).
    BackpressureQueueFull {
        /// Service class whose queue is full.
        service_class: ServiceClass,
        /// Queue capacity.
        capacity: usize,
    },
    /// Submission deadline was already expired at admission.
    AlreadyExpired {
        /// Deadline instant.
        deadline: TimestampNs,
        /// Admission instant.
        now: TimestampNs,
    },
    /// Fabric is draining or closed and refuses new admissions.
    FabricNotAccepting {
        /// Current lifecycle phase.
        phase: &'static str,
    },
    /// Queue bounds configuration invalid.
    InvalidQueueBounds {
        /// Offending queue parameter name.
        queue: &'static str,
        /// Invalid value.
        capacity: usize,
    },
    /// Fairness weights invalid.
    InvalidFairnessWeights,
    /// Unknown in-flight durable fabric sequence for ack/nack.
    UnknownInFlightDelivery {
        /// Requested sequence.
        fabric_seq: u64,
    },
    /// Finalization refused because work or obligations remain non-terminal.
    NotQuiescent {
        /// Remaining queued items.
        remaining_queued: usize,
        /// Remaining in-flight durable deliveries.
        remaining_in_flight: usize,
        /// Leaked pending region obligations.
        leaked_obligations: Vec<LeakedObligation>,
    },
    /// Idempotency table capacity reached.
    IdempotencyCapacityExceeded,
    /// Tracked telemetry source table capacity reached.
    TelemetrySourceCapacityExceeded,
    /// Idempotency key was reused with a different payload digest or subject!
    IdempotencyConflict {
        /// Conflicting idempotency key.
        key: String,
    },
}

impl fmt::Display for SubjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSubjectName { subject, reason } => {
                write!(f, "invalid subject name `{subject}`: {reason}")
            }
            Self::InvalidSchema { schema_id, reason } => {
                write!(f, "invalid subject schema `{schema_id}`: {reason}")
            }
            Self::PlaneServiceClassMismatch {
                plane,
                service_class,
            } => write!(
                f,
                "service class {service_class} is illegal on plane {plane}"
            ),
            Self::DuplicateSchemaId { schema_id } => {
                write!(f, "duplicate subject schema id `{schema_id}`")
            }
            Self::UnknownSchemaId { schema_id } => {
                write!(f, "unknown subject schema id `{schema_id}`")
            }
            Self::RegistryCapacityExceeded => {
                f.write_str("subject schema registry capacity exceeded")
            }
            Self::UnregisteredSubject { subject } => {
                write!(f, "unregistered semantic subject `{subject}`")
            }
            Self::AmbiguousSubjectMatch {
                subject,
                first_schema,
                second_schema,
            } => write!(
                f,
                "ambiguous subject `{subject}` matched `{first_schema}` and `{second_schema}`"
            ),
            Self::SubjectTombstoned {
                schema_id,
                version,
                superseded_by_version,
                reason,
            } => write!(
                f,
                "subject schema `{schema_id}` v{version} is tombstoned (use v{superseded_by_version}): {reason}"
            ),
            Self::WrongPlaneBoundary {
                expected,
                attempted,
            } => write!(
                f,
                "plane boundary violation: subject belongs to {expected}, attempted {attempted}"
            ),
            Self::RouteDenied {
                schema_id,
                code,
                reason,
            } => write!(f, "route denied for `{schema_id}` ({code}): {reason}"),
            Self::PressureShed {
                schema_id,
                pressure,
                reason,
            } => write!(
                f,
                "subject `{schema_id}` shed under {} pressure: {reason}",
                pressure.as_str()
            ),
            Self::PrivacyScopeViolation { schema_id, zone } => write!(
                f,
                "subject `{schema_id}` crosses unauthorized privacy zone `{}`",
                zone.as_str()
            ),
            Self::SiteScopeViolation { schema_id, site } => {
                write!(
                    f,
                    "subject `{schema_id}` crosses unauthorized site `{site}`"
                )
            }
            Self::SensorScopeViolation { schema_id, sensor } => write!(
                f,
                "subject `{schema_id}` crosses unauthorized sensor `{sensor}`"
            ),
            Self::InvalidAtpManifest { reason } => write!(f, "invalid ATP manifest: {reason}"),
            Self::InvalidPacketPayload { reason } => write!(f, "invalid packet payload: {reason}"),
            Self::InvalidReasoningPayload { reason } => {
                write!(f, "invalid reasoning payload: {reason}")
            }
            Self::AuthorityDenied { detail } => write!(f, "authority denied: {detail}"),
            Self::LeaseFenceDenied { error } => write!(f, "lease fence denied: {error}"),
            Self::BackpressureQueueFull {
                service_class,
                capacity,
            } => write!(
                f,
                "backpressure refusal: {service_class} queue reached capacity {capacity}"
            ),
            Self::AlreadyExpired { deadline, now } => write!(
                f,
                "submission deadline {} already expired at {}",
                deadline.0, now.0
            ),
            Self::FabricNotAccepting { phase } => {
                write!(
                    f,
                    "semantic subject fabric is `{phase}` and refuses new work"
                )
            }
            Self::InvalidQueueBounds { queue, capacity } => {
                write!(f, "invalid queue bound `{queue}`={capacity}")
            }
            Self::InvalidFairnessWeights => f.write_str("invalid fairness weights"),
            Self::UnknownInFlightDelivery { fabric_seq } => {
                write!(f, "unknown in-flight durable delivery seq {fabric_seq}")
            }
            Self::NotQuiescent {
                remaining_queued,
                remaining_in_flight,
                leaked_obligations,
            } => write!(
                f,
                "fabric not quiescent: queued={remaining_queued}, in_flight={remaining_in_flight}, leaked_obligations={}",
                leaked_obligations.len()
            ),
            Self::IdempotencyCapacityExceeded => {
                f.write_str("retained authority idempotency capacity exceeded")
            }
            Self::TelemetrySourceCapacityExceeded => {
                f.write_str("tracked telemetry source capacity exceeded")
            }
            Self::IdempotencyConflict { key } => {
                write!(
                    f,
                    "idempotency key `{key}` reused with mismatched payload or subject"
                )
            }
        }
    }
}

impl std::error::Error for SubjectError {}

impl From<AuthorityError> for SubjectError {
    fn from(err: AuthorityError) -> Self {
        Self::AuthorityDenied {
            detail: err.to_string(),
        }
    }
}

impl From<GrantError> for SubjectError {
    fn from(err: GrantError) -> Self {
        Self::AuthorityDenied {
            detail: err.to_string(),
        }
    }
}

impl From<LeaseError> for SubjectError {
    fn from(error: LeaseError) -> Self {
        Self::LeaseFenceDenied { error }
    }
}

// ---------------------------------------------------------------------------
// SemanticSubjectFabric (Explicitly Owned, Zero Global Locks/Singletons)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FabricPhase {
    Running,
    Draining,
    Closed,
}

impl FabricPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug)]
struct QueuedPacket {
    fabric_seq: u64,
    schema_id: String,
    service_class: ServiceClass,
    submission: PacketSubmission,
}

#[derive(Clone, Debug)]
struct QueuedReasoning {
    fabric_seq: u64,
    schema_id: String,
    attempt: u32,
    submission: ReasoningSubmission,
}

#[derive(Clone, Debug)]
struct QueuedAuthority {
    fabric_seq: u64,
    authority_order_seq: u64,
    schema_id: String,
    service_class: ServiceClass,
    attempt: u32,
    obligation_id: Option<ObligationId>,
    region_id: RegionId,
    submission: AuthoritySubmission,
}

#[derive(Clone, Debug)]
enum InFlightDurable {
    Reasoning(QueuedReasoning),
    Authority(QueuedAuthority),
}

#[derive(Clone, Debug)]
struct IdempotencyRecord {
    subject: String,
    payload_digest: ContentDigest,
    receipt: PublishReceipt,
}

/// Explicitly owned semantic subject fabric with separate bounded queues per service class,
/// strict plane boundaries, weighted fairness scheduling, lease/obligation integration, and
/// deterministic `request -> drain -> finalize` quiescence proofs.
#[derive(Debug)]
pub struct SemanticSubjectFabric {
    registry: SubjectSchemaRegistry,
    routes: CompiledRouteTable,
    bounds: QueueBounds,
    fairness: FairnessWeights,
    region_id: RegionId,
    phase: FabricPhase,
    next_fabric_seq: u64,
    next_authority_order_seq: u64,
    authority_order_high_water: u64,

    // Separate bounded queues per service class (NEVER one undifferentiated bus!).
    q_ephemeral: VecDeque<QueuedPacket>,
    q_telemetry: VecDeque<QueuedPacket>,
    q_object_graph: VecDeque<QueuedPacket>,
    q_reasoning: VecDeque<QueuedReasoning>,
    q_authority_durable: VecDeque<QueuedAuthority>,
    q_authority_obligated: VecDeque<QueuedAuthority>,

    // Per-source monotone sequence tracking for `OrderedTelemetry`.
    telemetry_watermarks: BTreeMap<(String, String), u64>,
    // In-flight acknowledged durable deliveries (`DurableAtLeastOnce` & `ObligatedExactlyEffectOnce`).
    in_flight: BTreeMap<u64, InFlightDurable>,
    // Retained authority idempotency records.
    idempotency: BTreeMap<String, IdempotencyRecord>,

    // Weighted deficit counters for starvation-free deterministic scheduling.
    credit_authority: u32,
    credit_reasoning: u32,
    credit_packet: u32,

    // Deterministic telemetry counters & explicit audit receipts.
    total_admitted: u64,
    total_authority_dispatched: u64,
    total_packet_dispatched: u64,
    total_reasoning_dispatched: u64,
    total_expired: u64,
    total_telemetry_gaps: u64,
    expired_log: Vec<DeadlineExpiredReceipt>,
    dead_letters: Vec<u64>,
}

impl SemanticSubjectFabric {
    /// Opens a new explicitly owned semantic subject fabric bound to `authority`'s region.
    pub fn open(
        authority: &AuthorityCx,
        tree: &RegionTree,
        registry: SubjectSchemaRegistry,
        routes: CompiledRouteTable,
        bounds: QueueBounds,
        fairness: FairnessWeights,
    ) -> Result<Self, SubjectError> {
        authority.require_bound(tree)?;
        if authority.is_cancel_requested(tree)? {
            return Err(SubjectError::FabricNotAccepting {
                phase: "cancelled_before_open",
            });
        }
        bounds.validate()?;
        fairness.validate()?;
        Ok(Self {
            registry,
            routes,
            bounds,
            fairness,
            region_id: authority.region().clone(),
            phase: FabricPhase::Running,
            next_fabric_seq: 1,
            next_authority_order_seq: 1,
            authority_order_high_water: 0,
            q_ephemeral: VecDeque::new(),
            q_telemetry: VecDeque::new(),
            q_object_graph: VecDeque::new(),
            q_reasoning: VecDeque::new(),
            q_authority_durable: VecDeque::new(),
            q_authority_obligated: VecDeque::new(),
            telemetry_watermarks: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            credit_authority: fairness.authority_weight,
            credit_reasoning: fairness.reasoning_weight,
            credit_packet: fairness.packet_weight,
            total_admitted: 0,
            total_authority_dispatched: 0,
            total_packet_dispatched: 0,
            total_reasoning_dispatched: 0,
            total_expired: 0,
            total_telemetry_gaps: 0,
            expired_log: Vec::new(),
            dead_letters: Vec::new(),
        })
    }

    /// Replaces the compiled route table atomically (e.g. after pressure or profile change).
    pub fn update_routes(&mut self, routes: CompiledRouteTable) {
        self.routes = routes;
    }

    /// Returns the active compiled route table.
    #[must_use]
    pub fn routes(&self) -> &CompiledRouteTable {
        &self.routes
    }

    /// Returns total queued messages across all service classes.
    #[must_use]
    pub fn total_queued(&self) -> usize {
        self.q_ephemeral.len()
            + self.q_telemetry.len()
            + self.q_object_graph.len()
            + self.q_reasoning.len()
            + self.q_authority_durable.len()
            + self.q_authority_obligated.len()
    }

    /// Returns count of unacknowledged in-flight durable deliveries.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Returns explicit deadline-expiry receipts recorded so far.
    #[must_use]
    pub fn expired_receipts(&self) -> &[DeadlineExpiredReceipt] {
        &self.expired_log
    }

    /// Returns fabric sequence numbers retired to dead-letter after exhausting retries.
    #[must_use]
    pub fn dead_letters(&self) -> &[u64] {
        &self.dead_letters
    }

    /// Returns the strict monotone high-water mark of dispatched Authority-plane items.
    #[must_use]
    pub const fn authority_order_high_water(&self) -> u64 {
        self.authority_order_high_water
    }

    /// Admits an immutable Packet-plane message (`EphemeralLatest`, `OrderedTelemetry`,
    /// or `VerifiedObjectGraph`). Structurally incapable of minting effect authority.
    pub fn publish_packet(
        &mut self,
        submission: PacketSubmission,
        now: TimestampNs,
    ) -> Result<PublishReceipt, SubjectError> {
        self.ensure_running()?;
        if let Some(dl) = submission.deadline
            && now.0 >= dl.0
        {
            return Err(SubjectError::AlreadyExpired { deadline: dl, now });
        }
        if submission.source_key.is_empty() || submission.source_key.len() > 128 {
            return Err(SubjectError::InvalidPacketPayload {
                reason: "source_key violates 1..=128 bytes",
            });
        }
        if submission.provenance.is_empty() || submission.provenance.len() > 128 {
            return Err(SubjectError::InvalidPacketPayload {
                reason: "provenance tag violates 1..=128 bytes",
            });
        }
        if submission.object_digests.is_empty()
            || submission.object_digests.len() > MAX_PACKET_OBJECT_DIGESTS
        {
            return Err(SubjectError::InvalidPacketPayload {
                reason: "object_digests count violates 1..=128",
            });
        }

        let resolved = self.registry.resolve(&submission.subject)?;
        if resolved.schema.plane != FabricPlane::Packet {
            return Err(SubjectError::WrongPlaneBoundary {
                expected: resolved.schema.plane,
                attempted: FabricPlane::Packet,
            });
        }
        let _route = self.routes.check_subject(&resolved)?;

        match resolved.schema.service_class {
            ServiceClass::VerifiedObjectGraph => {
                let Some(ref manifest) = submission.atp_manifest else {
                    return Err(SubjectError::InvalidAtpManifest {
                        reason: "VerifiedObjectGraph requires an AtpObjectGraphManifest",
                    });
                };
                if manifest.grants_effect_authority() {
                    return Err(SubjectError::InvalidAtpManifest {
                        reason: "ATP manifest cannot carry effect authority (INV-047)",
                    });
                }
            }
            ServiceClass::EphemeralLatest | ServiceClass::OrderedTelemetry => {
                if submission.atp_manifest.is_some() {
                    return Err(SubjectError::InvalidAtpManifest {
                        reason: "ATP manifest is only permitted on VerifiedObjectGraph subjects",
                    });
                }
            }
            other => {
                return Err(SubjectError::PlaneServiceClassMismatch {
                    plane: FabricPlane::Packet,
                    service_class: other,
                });
            }
        }

        let mut superseded = None;
        let mut telemetry_gap = None;
        let fabric_seq = self.next_fabric_seq;

        match resolved.schema.service_class {
            ServiceClass::EphemeralLatest => {
                // Coalesce/supersede older queued entry for the same `(subject, source_key)`!
                if let Some(pos) = self.q_ephemeral.iter().position(|item| {
                    item.submission.subject == submission.subject
                        && item.submission.source_key == submission.source_key
                }) {
                    if let Some(old) = self.q_ephemeral.remove(pos) {
                        superseded = Some(SupersedeReceipt {
                            subject: submission.subject.as_str().to_owned(),
                            source_key: submission.source_key.clone(),
                            superseded_seq: old.submission.sequence,
                            replacement_seq: submission.sequence,
                        });
                    }
                } else if self.q_ephemeral.len() >= self.bounds.ephemeral_latest {
                    return Err(SubjectError::BackpressureQueueFull {
                        service_class: ServiceClass::EphemeralLatest,
                        capacity: self.bounds.ephemeral_latest,
                    });
                }
                self.q_ephemeral.push_back(QueuedPacket {
                    fabric_seq,
                    schema_id: resolved.schema.schema_id.clone(),
                    service_class: ServiceClass::EphemeralLatest,
                    submission,
                });
            }
            ServiceClass::OrderedTelemetry => {
                if self.q_telemetry.len() >= self.bounds.ordered_telemetry {
                    return Err(SubjectError::BackpressureQueueFull {
                        service_class: ServiceClass::OrderedTelemetry,
                        capacity: self.bounds.ordered_telemetry,
                    });
                }
                let key = (
                    submission.subject.as_str().to_owned(),
                    submission.source_key.clone(),
                );
                if let Some(&last_seq) = self.telemetry_watermarks.get(&key) {
                    let expected = last_seq.saturating_add(1);
                    if submission.sequence != expected {
                        self.total_telemetry_gaps = self.total_telemetry_gaps.saturating_add(1);
                        telemetry_gap = Some(TelemetryGapReceipt {
                            subject: submission.subject.as_str().to_owned(),
                            source_key: submission.source_key.clone(),
                            expected_seq: expected,
                            observed_seq: submission.sequence,
                            out_of_order: submission.sequence < expected,
                        });
                    }
                    if submission.sequence > last_seq {
                        self.telemetry_watermarks.insert(key, submission.sequence);
                    }
                } else {
                    if self.telemetry_watermarks.len() >= MAX_TRACKED_TELEMETRY_SOURCES {
                        return Err(SubjectError::TelemetrySourceCapacityExceeded);
                    }
                    self.telemetry_watermarks.insert(key, submission.sequence);
                }
                self.q_telemetry.push_back(QueuedPacket {
                    fabric_seq,
                    schema_id: resolved.schema.schema_id.clone(),
                    service_class: ServiceClass::OrderedTelemetry,
                    submission,
                });
            }
            ServiceClass::VerifiedObjectGraph => {
                if self.q_object_graph.len() >= self.bounds.verified_object_graph {
                    return Err(SubjectError::BackpressureQueueFull {
                        service_class: ServiceClass::VerifiedObjectGraph,
                        capacity: self.bounds.verified_object_graph,
                    });
                }
                self.q_object_graph.push_back(QueuedPacket {
                    fabric_seq,
                    schema_id: resolved.schema.schema_id.clone(),
                    service_class: ServiceClass::VerifiedObjectGraph,
                    submission,
                });
            }
            other => {
                return Err(SubjectError::PlaneServiceClassMismatch {
                    plane: FabricPlane::Packet,
                    service_class: other,
                });
            }
        }

        self.next_fabric_seq = self.next_fabric_seq.saturating_add(1);
        self.total_admitted = self.total_admitted.saturating_add(1);
        let receipt_digest = compute_publish_receipt_digest(
            fabric_seq,
            &resolved.schema.schema_id,
            FabricPlane::Packet,
            resolved.schema.service_class,
            None,
            false,
            false,
        );
        Ok(PublishReceipt {
            fabric_seq,
            schema_id: resolved.schema.schema_id,
            plane: FabricPlane::Packet,
            service_class: resolved.schema.service_class,
            obligation_id: None,
            deduplicated: false,
            superseded,
            telemetry_gap,
            grants_effect_authority: false,
            receipt_digest,
        })
    }

    /// Admits a derived Reasoning-plane message (`DurableAtLeastOnce`).
    /// Structurally derived only (`grants_effect_authority == false`, pinned anchor & generation).
    pub fn publish_reasoning(
        &mut self,
        submission: ReasoningSubmission,
        now: TimestampNs,
    ) -> Result<PublishReceipt, SubjectError> {
        self.ensure_running()?;
        if let Some(dl) = submission.deadline
            && now.0 >= dl.0
        {
            return Err(SubjectError::AlreadyExpired { deadline: dl, now });
        }
        if submission.delivery_key.is_empty() || submission.delivery_key.len() > 128 {
            return Err(SubjectError::InvalidReasoningPayload {
                reason: "delivery_key violates 1..=128 bytes",
            });
        }
        if submission.generation_id.is_empty()
            || submission.generation_id.len() > 128
            || submission.generation_id.eq_ignore_ascii_case("latest")
            || submission.generation_id.eq_ignore_ascii_case("head")
        {
            return Err(SubjectError::InvalidReasoningPayload {
                reason: "generation_id must be a pinned immutable generation (not mutable alias)",
            });
        }

        let resolved = self.registry.resolve(&submission.subject)?;
        if resolved.schema.plane != FabricPlane::Reasoning {
            return Err(SubjectError::WrongPlaneBoundary {
                expected: resolved.schema.plane,
                attempted: FabricPlane::Reasoning,
            });
        }
        let _route = self.routes.check_subject(&resolved)?;

        if self.q_reasoning.len() >= self.bounds.reasoning_durable {
            return Err(SubjectError::BackpressureQueueFull {
                service_class: ServiceClass::DurableAtLeastOnce,
                capacity: self.bounds.reasoning_durable,
            });
        }

        let fabric_seq = self.next_fabric_seq;
        self.q_reasoning.push_back(QueuedReasoning {
            fabric_seq,
            schema_id: resolved.schema.schema_id.clone(),
            attempt: 1,
            submission,
        });
        self.next_fabric_seq = self.next_fabric_seq.saturating_add(1);
        self.total_admitted = self.total_admitted.saturating_add(1);
        let receipt_digest = compute_publish_receipt_digest(
            fabric_seq,
            &resolved.schema.schema_id,
            FabricPlane::Reasoning,
            resolved.schema.service_class,
            None,
            false,
            false,
        );
        Ok(PublishReceipt {
            fabric_seq,
            schema_id: resolved.schema.schema_id,
            plane: FabricPlane::Reasoning,
            service_class: resolved.schema.service_class,
            obligation_id: None,
            deduplicated: false,
            superseded: None,
            telemetry_gap: None,
            grants_effect_authority: false,
            receipt_digest,
        })
    }

    /// Admits an explicit Authority-plane message (`DurableAtLeastOnce` or
    /// `ObligatedExactlyEffectOnce`).
    ///
    /// Authority is NEVER inferred from routing: every submission independently verifies:
    /// 1. `authority` belongs to this fabric's bound region and is active (not cancelled/draining).
    /// 2. `authority.require_grant_for(schema.required_grant, &submission.resource)`.
    /// 3. Active unexpired lease fence via `leases.check_fence(&submission.resource, submission.fence, now)`
    ///    whenever `schema.requires_lease_fence` is true.
    /// 4. Idempotency deduplication (returning the original receipt on exact replay, refusing
    ///    conflicts on mismatched payload/subject).
    /// 5. Atomic budget debit through `authority.budget_mut(tree)`.
    /// 6. Canonical [`Obligation`] registration on `RegionTree` for `ObligatedExactlyEffectOnce`.
    pub fn publish_authority(
        &mut self,
        authority: &mut AuthorityCx,
        tree: &mut RegionTree,
        leases: &mut LeaseRegistry,
        submission: AuthoritySubmission,
        now: TimestampNs,
    ) -> Result<PublishReceipt, SubjectError> {
        self.ensure_running()?;
        authority.require_bound(tree)?;
        if *authority.region() != self.region_id {
            return Err(SubjectError::AuthorityDenied {
                detail: format!(
                    "authority region `{}` != fabric region `{}`",
                    authority.region().as_str(),
                    self.region_id.as_str()
                ),
            });
        }
        if authority.is_cancel_requested(tree)? {
            return Err(SubjectError::FabricNotAccepting {
                phase: "authority_cancelled",
            });
        }
        if let Some(dl) = submission.deadline
            && now.0 >= dl.0
        {
            return Err(SubjectError::AlreadyExpired { deadline: dl, now });
        }

        let resolved = self.registry.resolve(&submission.subject)?;
        if resolved.schema.plane != FabricPlane::Authority {
            return Err(SubjectError::WrongPlaneBoundary {
                expected: resolved.schema.plane,
                attempted: FabricPlane::Authority,
            });
        }
        let _route = self.routes.check_subject(&resolved)?;

        // Explicit runtime capability check (NEVER inferred from route table!).
        authority.require_grant_for(resolved.schema.required_grant, &submission.resource)?;

        // Explicit lease fence check for fenced/effect-once schemas.
        if resolved.schema.requires_lease_fence {
            leases.check_fence(&submission.resource, submission.fence, now)?;
        }

        // Idempotency deduplication & conflict detection BEFORE debiting budget or enqueuing.
        let idem_key = submission.idempotency_key.as_str().to_owned();
        if let Some(existing) = self.idempotency.get(&idem_key) {
            if existing.subject != submission.subject.as_str()
                || existing.payload_digest != submission.payload_digest
            {
                return Err(SubjectError::IdempotencyConflict { key: idem_key });
            }
            let mut dup = existing.receipt.clone();
            dup.deduplicated = true;
            return Ok(dup);
        }
        if self.idempotency.len() >= MAX_RETAINED_IDEMPOTENCY {
            return Err(SubjectError::IdempotencyCapacityExceeded);
        }

        // Check queue capacity BEFORE mutating authority budget or registering obligations!
        let (is_obligated, cap) = match resolved.schema.service_class {
            ServiceClass::ObligatedExactlyEffectOnce => (true, self.bounds.authority_obligated),
            ServiceClass::DurableAtLeastOnce => (false, self.bounds.authority_durable),
            other => {
                return Err(SubjectError::PlaneServiceClassMismatch {
                    plane: FabricPlane::Authority,
                    service_class: other,
                });
            }
        };
        let cur_len = if is_obligated {
            self.q_authority_obligated.len()
        } else {
            self.q_authority_durable.len()
        };
        if cur_len >= cap {
            return Err(SubjectError::BackpressureQueueFull {
                service_class: resolved.schema.service_class,
                capacity: cap,
            });
        }

        // Debit declared numeric budget atomically via AuthorityCx!
        debit_budget_vector(authority, tree, &submission.budget)?;

        let fabric_seq = self.next_fabric_seq;
        let authority_order_seq = self.next_authority_order_seq;

        // Register durable region obligation for `ObligatedExactlyEffectOnce`!
        let obligation_id = if is_obligated {
            let ob_id_str = format!(
                "obligation:subj:{}:{fabric_seq}",
                resolved.schema.family.family_id().to_ascii_lowercase()
            );
            let ob: Obligation = new_obligation(
                ob_id_str,
                submission.operation_id.clone(),
                submission.terminal_predicate.clone(),
            )
            .map_err(|e| SubjectError::AuthorityDenied {
                detail: e.to_string(),
            })?;
            let id = ob.obligation_id.clone();
            authority.register_obligation(tree, ob)?;
            Some(id)
        } else {
            None
        };

        let queued = QueuedAuthority {
            fabric_seq,
            authority_order_seq,
            schema_id: resolved.schema.schema_id.clone(),
            service_class: resolved.schema.service_class,
            attempt: 1,
            obligation_id: obligation_id.clone(),
            region_id: authority.region().clone(),
            submission: submission.clone(),
        };
        if is_obligated {
            self.q_authority_obligated.push_back(queued);
        } else {
            self.q_authority_durable.push_back(queued);
        }

        self.next_fabric_seq = self.next_fabric_seq.saturating_add(1);
        self.next_authority_order_seq = self.next_authority_order_seq.saturating_add(1);
        self.total_admitted = self.total_admitted.saturating_add(1);

        let receipt_digest = compute_publish_receipt_digest(
            fabric_seq,
            &resolved.schema.schema_id,
            FabricPlane::Authority,
            resolved.schema.service_class,
            obligation_id.as_ref(),
            false,
            false,
        );
        let receipt = PublishReceipt {
            fabric_seq,
            schema_id: resolved.schema.schema_id,
            plane: FabricPlane::Authority,
            service_class: resolved.schema.service_class,
            obligation_id,
            deduplicated: false,
            superseded: None,
            telemetry_gap: None,
            grants_effect_authority: false,
            receipt_digest,
        };
        self.idempotency.insert(
            idem_key,
            IdempotencyRecord {
                subject: submission.subject.as_str().to_owned(),
                payload_digest: submission.payload_digest,
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    /// Dequeues the next message under deterministic priority + starvation-free weighted fairness
    /// at caller-supplied time `now`, expiring any deadline-exceeded items with explicit receipts.
    ///
    /// Authority-plane messages are ALWAYS dispatched in strict monotone `authority_order_seq`
    /// order and prioritized ahead of Packet floods while preserving bounded Reasoning/Packet
    /// progress under Nominal/Elevated pressure.
    pub fn dequeue_next(&mut self, now: TimestampNs) -> Option<DispatchedMessage> {
        self.expire_stale_heads(now);
        if self.total_queued() == 0 {
            return None;
        }

        // Under Critical pressure, Authority strictly preempts Reasoning and Packet queues!
        if self.routes.pressure() == ResourcePressure::Critical
            && let Some(msg) = self.pop_next_authority()
        {
            return Some(msg);
        }

        // Weighted deficit fairness cycle: Authority -> Reasoning -> Packet.
        // Refill all credits whenever no queued plane has remaining credit.
        for _ in 0..2 {
            if self.has_authority_queued() && self.credit_authority > 0 {
                self.credit_authority -= 1;
                if let Some(msg) = self.pop_next_authority() {
                    return Some(msg);
                }
            }
            if !self.q_reasoning.is_empty() && self.credit_reasoning > 0 {
                self.credit_reasoning -= 1;
                if let Some(msg) = self.pop_next_reasoning() {
                    return Some(msg);
                }
            }
            if self.has_packet_queued() && self.credit_packet > 0 {
                self.credit_packet -= 1;
                if let Some(msg) = self.pop_next_packet() {
                    return Some(msg);
                }
            }
            // Refill weights for next deterministic fairness epoch.
            self.credit_authority = self.fairness.authority_weight;
            self.credit_reasoning = self.fairness.reasoning_weight;
            self.credit_packet = self.fairness.packet_weight;
        }
        None
    }

    /// Drains a bounded batch of Packet-plane messages (`EphemeralLatest` or `VerifiedObjectGraph`)
    /// up to `max_batch`, proving via [`PacketBatchReceipt`] that Authority-plane ordering is
    /// completely untouched.
    pub fn drain_packet_batch(
        &mut self,
        service_class: ServiceClass,
        max_batch: usize,
        now: TimestampNs,
    ) -> Result<(Vec<DispatchedMessage>, PacketBatchReceipt), SubjectError> {
        if !service_class.allows_packet_batching() {
            return Err(SubjectError::PlaneServiceClassMismatch {
                plane: FabricPlane::Packet,
                service_class,
            });
        }
        self.expire_stale_heads(now);
        let limit = max_batch.min(self.routes.profile().max_packet_batch());
        let queue = match service_class {
            ServiceClass::EphemeralLatest => &mut self.q_ephemeral,
            ServiceClass::VerifiedObjectGraph => &mut self.q_object_graph,
            _ => unreachable!(),
        };
        let mut batch = Vec::with_capacity(limit.min(queue.len()));
        while batch.len() < limit {
            let Some(item) = queue.pop_front() else {
                break;
            };
            self.total_packet_dispatched = self.total_packet_dispatched.saturating_add(1);
            batch.push(DispatchedMessage::Packet {
                fabric_seq: item.fabric_seq,
                schema_id: item.schema_id,
                service_class: item.service_class,
                submission: item.submission,
                grants_effect_authority: false,
            });
        }
        let receipt = PacketBatchReceipt {
            packet_count: batch.len(),
            service_class,
            authority_order_high_water: self.authority_order_high_water,
            grants_effect_authority: false,
        };
        Ok((batch, receipt))
    }

    /// Acknowledges an in-flight durable delivery (`Reasoning` or `Authority`).
    /// For `ObligatedExactlyEffectOnce`, the caller must ALSO settle the region obligation
    /// via [`Self::settle_authority_obligation`].
    pub fn ack_durable(&mut self, fabric_seq: u64) -> Result<DurableAckOutcome, SubjectError> {
        if self.in_flight.remove(&fabric_seq).is_none() {
            return Err(SubjectError::UnknownInFlightDelivery { fabric_seq });
        }
        Ok(DurableAckOutcome::Acknowledged)
    }

    /// Nacks an in-flight durable delivery, either re-enqueuing up to `max_durable_attempts`
    /// or explicitly dead-lettering when retries are exhausted (never silently dropped).
    pub fn nack_durable(&mut self, fabric_seq: u64) -> Result<DurableAckOutcome, SubjectError> {
        let Some(entry) = self.in_flight.remove(&fabric_seq) else {
            return Err(SubjectError::UnknownInFlightDelivery { fabric_seq });
        };
        let max_attempts = self.bounds.max_durable_attempts;
        match entry {
            InFlightDurable::Reasoning(mut item) => {
                if item.attempt >= max_attempts {
                    self.dead_letters.push(fabric_seq);
                    Ok(DurableAckOutcome::DeadLettered {
                        attempts: item.attempt,
                    })
                } else {
                    item.attempt += 1;
                    let next = item.attempt;
                    self.q_reasoning.push_back(item);
                    Ok(DurableAckOutcome::Redelivered { next_attempt: next })
                }
            }
            InFlightDurable::Authority(mut item) => {
                if item.attempt >= max_attempts {
                    self.dead_letters.push(fabric_seq);
                    Ok(DurableAckOutcome::DeadLettered {
                        attempts: item.attempt,
                    })
                } else {
                    item.attempt += 1;
                    let next = item.attempt;
                    // Re-insert at the front of the Authority queue to preserve strict ordering!
                    if item.service_class == ServiceClass::ObligatedExactlyEffectOnce {
                        self.q_authority_obligated.push_front(item);
                    } else {
                        self.q_authority_durable.push_front(item);
                    }
                    Ok(DurableAckOutcome::Redelivered { next_attempt: next })
                }
            }
        }
    }

    /// Resolves a canonical region obligation created by `ObligatedExactlyEffectOnce`
    /// through the owning [`AuthorityCx`] and [`RegionTree`].
    /// `ObligationTerminal::Indeterminate` requires a non-empty `reconciliation_note`.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_authority_obligation(
        &mut self,
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        fabric_seq: u64,
        obligation_id: &ObligationId,
        terminal: ObligationTerminal,
        proof_digest: Option<ContentDigest>,
        reconciliation_note: Option<&str>,
    ) -> Result<(), SubjectError> {
        authority.resolve_obligation(
            tree,
            obligation_id,
            terminal,
            proof_digest,
            reconciliation_note,
        )?;
        // Also retire from in_flight if still tracked.
        self.in_flight.remove(&fabric_seq);
        Ok(())
    }

    /// Requests cooperative cancellation and transitions the fabric into `Draining`
    /// (`request -> drain -> finalize`). Refuses all subsequent new admissions.
    pub fn request_drain(
        &mut self,
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<(), SubjectError> {
        authority.require_bound(tree)?;
        if self.phase == FabricPhase::Closed {
            return Err(SubjectError::FabricNotAccepting { phase: "closed" });
        }
        if !authority.is_cancel_requested(tree)? {
            authority.request_cancellation(tree, now)?;
        }
        authority.begin_drain(tree, now)?;
        self.phase = FabricPhase::Draining;
        Ok(())
    }

    /// Executes one bounded cooperative drain step, draining up to `max_items` queued messages
    /// and emitting a [`DrainProgressCertificate`] proving monotonic work reduction
    /// (`INT-AS-001` gate #3).
    pub fn step_drain(
        &mut self,
        max_items: usize,
        now: TimestampNs,
    ) -> Result<(Vec<DispatchedMessage>, DrainProgressCertificate), SubjectError> {
        if self.phase != FabricPhase::Draining {
            return Err(SubjectError::FabricNotAccepting {
                phase: self.phase.as_str(),
            });
        }
        let remaining_before = self.total_queued() + self.in_flight.len();
        let expired_before = self.total_expired;
        let mut drained = Vec::new();
        for _ in 0..max_items {
            let Some(msg) = self.dequeue_next(now) else {
                break;
            };
            drained.push(msg);
        }
        let drained_this_step = drained.len();
        let expired_this_step = (self.total_expired - expired_before) as usize;
        let remaining_after = self.total_queued() + self.in_flight.len();

        let mut enc = CanonicalEncoder::new();
        enc.text(DRAIN_PROGRESS_TAG);
        enc.u64(remaining_before as u64);
        enc.u64(remaining_after as u64);
        enc.u64(drained_this_step as u64);
        enc.u64(expired_this_step as u64);
        enc.i128(now.0);
        let certificate_digest = ContentDigest::sha256(&enc.finish());

        Ok((
            drained,
            DrainProgressCertificate {
                remaining_before,
                remaining_after,
                drained_this_step,
                expired_this_step,
                observed_at: now,
                certificate_digest,
            },
        ))
    }

    /// Finalizes the fabric and owning region, refusing closure if ANY queued item,
    /// unacknowledged in-flight durable delivery, or leaked pending region obligation remains!
    pub fn finalize(
        mut self,
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<FabricQuiescenceReceipt, SubjectError> {
        authority.require_bound(tree)?;
        let leaked = authority.leaked_obligations(tree)?;
        let rem_q = self.total_queued();
        let rem_if = self.in_flight.len();
        if rem_q != 0 || rem_if != 0 || !leaked.is_empty() {
            return Err(SubjectError::NotQuiescent {
                remaining_queued: rem_q,
                remaining_in_flight: rem_if,
                leaked_obligations: leaked,
            });
        }
        let quiescence_proof = authority.finalize(tree, now)?;
        self.phase = FabricPhase::Closed;

        let mut enc = CanonicalEncoder::new();
        enc.text(QUIESCENCE_RECEIPT_TAG);
        enc.text(self.region_id.as_str());
        enc.digest(quiescence_proof.proof_digest);
        enc.u64(self.total_admitted);
        enc.u64(self.total_authority_dispatched);
        enc.u64(self.total_packet_dispatched);
        enc.u64(self.total_reasoning_dispatched);
        enc.u64(self.total_expired);
        enc.u64(self.total_telemetry_gaps);
        let receipt_digest = ContentDigest::sha256(&enc.finish());

        Ok(FabricQuiescenceReceipt {
            region_id: self.region_id,
            quiescence_proof,
            total_admitted: self.total_admitted,
            total_authority_dispatched: self.total_authority_dispatched,
            total_packet_dispatched: self.total_packet_dispatched,
            total_reasoning_dispatched: self.total_reasoning_dispatched,
            total_expired: self.total_expired,
            total_telemetry_gaps: self.total_telemetry_gaps,
            remaining_queued: 0,
            remaining_in_flight: 0,
            receipt_digest,
        })
    }

    fn ensure_running(&self) -> Result<(), SubjectError> {
        if self.phase != FabricPhase::Running {
            return Err(SubjectError::FabricNotAccepting {
                phase: self.phase.as_str(),
            });
        }
        Ok(())
    }

    fn has_authority_queued(&self) -> bool {
        !self.q_authority_obligated.is_empty() || !self.q_authority_durable.is_empty()
    }

    fn has_packet_queued(&self) -> bool {
        !self.q_telemetry.is_empty()
            || !self.q_object_graph.is_empty()
            || !self.q_ephemeral.is_empty()
    }

    fn expire_stale_heads(&mut self, now: TimestampNs) {
        let mut drain_expired_packet = |q: &mut VecDeque<QueuedPacket>| {
            let mut kept = VecDeque::with_capacity(q.len());
            while let Some(item) = q.pop_front() {
                if let Some(dl) = item.submission.deadline
                    && now.0 >= dl.0
                {
                    self.total_expired = self.total_expired.saturating_add(1);
                    self.expired_log.push(DeadlineExpiredReceipt {
                        fabric_seq: item.fabric_seq,
                        schema_id: item.schema_id,
                        plane: FabricPlane::Packet,
                        deadline: dl,
                        observed_at: now,
                    });
                } else {
                    kept.push_back(item);
                }
            }
            *q = kept;
        };
        drain_expired_packet(&mut self.q_ephemeral);
        drain_expired_packet(&mut self.q_telemetry);
        drain_expired_packet(&mut self.q_object_graph);

        let mut kept_r = VecDeque::with_capacity(self.q_reasoning.len());
        while let Some(item) = self.q_reasoning.pop_front() {
            if let Some(dl) = item.submission.deadline
                && now.0 >= dl.0
            {
                self.total_expired = self.total_expired.saturating_add(1);
                self.expired_log.push(DeadlineExpiredReceipt {
                    fabric_seq: item.fabric_seq,
                    schema_id: item.schema_id,
                    plane: FabricPlane::Reasoning,
                    deadline: dl,
                    observed_at: now,
                });
            } else {
                kept_r.push_back(item);
            }
        }
        self.q_reasoning = kept_r;

        // NOTE: Authority items with active deadlines expire ONLY if not yet dispatched;
        // their obligations remain explicitly visible in RegionTree until resolved/reconciled!
        let mut drain_expired_auth = |q: &mut VecDeque<QueuedAuthority>| {
            let mut kept = VecDeque::with_capacity(q.len());
            while let Some(item) = q.pop_front() {
                if let Some(dl) = item.submission.deadline
                    && now.0 >= dl.0
                {
                    self.total_expired = self.total_expired.saturating_add(1);
                    self.expired_log.push(DeadlineExpiredReceipt {
                        fabric_seq: item.fabric_seq,
                        schema_id: item.schema_id,
                        plane: FabricPlane::Authority,
                        deadline: dl,
                        observed_at: now,
                    });
                } else {
                    kept.push_back(item);
                }
            }
            *q = kept;
        };
        drain_expired_auth(&mut self.q_authority_obligated);
        drain_expired_auth(&mut self.q_authority_durable);
    }

    fn pop_next_authority(&mut self) -> Option<DispatchedMessage> {
        // Strict monotone `authority_order_seq` ordering across both Authority queues!
        let pick_obligated = match (
            self.q_authority_obligated.front(),
            self.q_authority_durable.front(),
        ) {
            (Some(a), Some(b)) => a.authority_order_seq <= b.authority_order_seq,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };
        let item = if pick_obligated {
            self.q_authority_obligated.pop_front()?
        } else {
            self.q_authority_durable.pop_front()?
        };
        if item.authority_order_seq > self.authority_order_high_water {
            self.authority_order_high_water = item.authority_order_seq;
        }
        self.total_authority_dispatched = self.total_authority_dispatched.saturating_add(1);
        let seq = item.fabric_seq;
        let msg = DispatchedMessage::Authority {
            fabric_seq: item.fabric_seq,
            authority_order_seq: item.authority_order_seq,
            schema_id: item.schema_id.clone(),
            service_class: item.service_class,
            attempt: item.attempt,
            obligation_id: item.obligation_id.clone(),
            region_id: item.region_id.clone(),
            submission: item.submission.clone(),
        };
        self.in_flight.insert(seq, InFlightDurable::Authority(item));
        Some(msg)
    }

    fn pop_next_reasoning(&mut self) -> Option<DispatchedMessage> {
        let item = self.q_reasoning.pop_front()?;
        self.total_reasoning_dispatched = self.total_reasoning_dispatched.saturating_add(1);
        let seq = item.fabric_seq;
        let msg = DispatchedMessage::Reasoning {
            fabric_seq: item.fabric_seq,
            schema_id: item.schema_id.clone(),
            attempt: item.attempt,
            submission: item.submission.clone(),
            is_authoritative_truth: false,
            grants_effect_authority: false,
        };
        self.in_flight.insert(seq, InFlightDurable::Reasoning(item));
        Some(msg)
    }

    fn pop_next_packet(&mut self) -> Option<DispatchedMessage> {
        // Priority inside Packet plane: OrderedTelemetry > VerifiedObjectGraph > EphemeralLatest.
        let item = self
            .q_telemetry
            .pop_front()
            .or_else(|| self.q_object_graph.pop_front())
            .or_else(|| self.q_ephemeral.pop_front())?;
        self.total_packet_dispatched = self.total_packet_dispatched.saturating_add(1);
        Some(DispatchedMessage::Packet {
            fabric_seq: item.fabric_seq,
            schema_id: item.schema_id,
            service_class: item.service_class,
            submission: item.submission,
            grants_effect_authority: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Deterministic Lab Scheduler (`INT-AS-001` Gates #1 & #8)
// ---------------------------------------------------------------------------

/// One deterministic event emitted by [`LabFabricHarness`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabTranscriptEntry {
    /// Virtual step index.
    pub step: u64,
    /// Virtual clock instant.
    pub virtual_now: TimestampNs,
    /// Dispatched plane.
    pub plane: FabricPlane,
    /// Schema ID.
    pub schema_id: String,
    /// Monotone fabric admission sequence.
    pub fabric_seq: u64,
    /// Authority-plane strict ordinal (`Some` only for Authority plane).
    pub authority_order_seq: Option<u64>,
}

/// Canonical deterministic lab execution transcript proving replay identity and
/// Authority-plane invariance across packet-plane interleavings (`INT-AS-001`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabFabricTranscript {
    /// Deterministic seed used to drive interleaving.
    pub seed: u64,
    /// Ordered trace entries.
    pub entries: Vec<LabTranscriptEntry>,
    /// Extracted Authority-plane ordered sequence of `(schema_id, authority_order_seq, payload_digest)`.
    pub authority_commit_sequence: Vec<(String, u64, ContentDigest)>,
    /// Canonical SHA-256 digest of the full transcript.
    pub transcript_digest: ContentDigest,
    /// Canonical SHA-256 digest of ONLY the Authority-plane commit sequence
    /// (invariant across packet-plane batching/reordering schedules!).
    pub authority_outcome_digest: ContentDigest,
}

/// Deterministic virtual-clock laboratory scheduler for [`SemanticSubjectFabric`].
/// Uses a pure splitmix64/xorshift64* PRNG with zero ambient RNG or clocks.
pub struct LabFabricHarness {
    seed: u64,
    rng_state: u64,
    virtual_now: TimestampNs,
    step_ns: i128,
}

impl LabFabricHarness {
    /// Constructs a deterministic lab harness starting at `start_time` with `seed`.
    #[must_use]
    pub const fn new(seed: u64, start_time: TimestampNs, step_ns: i128) -> Self {
        let init = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self {
            seed,
            rng_state: init,
            virtual_now: start_time,
            step_ns: if step_ns > 0 { step_ns } else { 1_000_000 },
        }
    }

    /// Returns current virtual time.
    #[must_use]
    pub const fn now(&self) -> TimestampNs {
        self.virtual_now
    }

    /// Advances virtual time monotonically by `delta_ns`.
    pub fn advance(&mut self, delta_ns: i128) {
        if delta_ns > 0 {
            self.virtual_now = TimestampNs(self.virtual_now.0.saturating_add(delta_ns));
        }
    }

    /// Deterministic xorshift64* draw (zero ambient entropy).
    fn next_u64(&mut self) -> u64 {
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Drains all queued items from `fabric` under deterministic seeded interleaving of
    /// packet-plane batching vs normal weighted-fairness dequeue, acknowledging all durable
    /// deliveries and verifying Authority-plane obligations to terminal `Completed`.
    pub fn run_to_empty(
        &mut self,
        fabric: &mut SemanticSubjectFabric,
        authority: &AuthorityCx,
        tree: &mut RegionTree,
    ) -> Result<LabFabricTranscript, SubjectError> {
        let mut entries = Vec::new();
        let mut authority_commit_sequence = Vec::new();
        let mut step = 0_u64;

        while fabric.total_queued() > 0 {
            step = step.saturating_add(1);
            self.advance(self.step_ns);
            let now = self.virtual_now;

            // Deterministically interleave bounded packet-plane batching (`EphemeralLatest` /
            // `VerifiedObjectGraph`) with normal weighted-fairness dequeue.
            // Crucially: Authority-plane messages ALWAYS preserve strict `authority_order_seq`!
            let draw = self.next_u64() % 5;
            if draw == 0 {
                let (batch, _batch_rcpt) =
                    fabric.drain_packet_batch(ServiceClass::EphemeralLatest, 4, now)?;
                if !batch.is_empty() {
                    for msg in batch {
                        record_entry(&mut entries, &mut authority_commit_sequence, step, now, msg);
                    }
                    continue;
                }
            } else if draw == 1 {
                let (batch, _batch_rcpt) =
                    fabric.drain_packet_batch(ServiceClass::VerifiedObjectGraph, 4, now)?;
                if !batch.is_empty() {
                    for msg in batch {
                        record_entry(&mut entries, &mut authority_commit_sequence, step, now, msg);
                    }
                    continue;
                }
            }

            let Some(msg) = fabric.dequeue_next(now) else {
                break;
            };
            match &msg {
                DispatchedMessage::Reasoning { fabric_seq, .. } => {
                    fabric.ack_durable(*fabric_seq)?;
                }
                DispatchedMessage::Authority {
                    fabric_seq,
                    obligation_id,
                    submission,
                    ..
                } => {
                    if let Some(ob_id) = obligation_id {
                        fabric.settle_authority_obligation(
                            authority,
                            tree,
                            *fabric_seq,
                            ob_id,
                            ObligationTerminal::Completed,
                            Some(submission.payload_digest),
                            None,
                        )?;
                    } else {
                        fabric.ack_durable(*fabric_seq)?;
                    }
                }
                DispatchedMessage::Packet { .. } => {}
            }
            record_entry(&mut entries, &mut authority_commit_sequence, step, now, msg);
        }

        let mut full_enc = CanonicalEncoder::new();
        full_enc.text(LAB_TRANSCRIPT_TAG);
        full_enc.u64(self.seed);
        full_enc.u64(entries.len() as u64);
        for e in &entries {
            full_enc.u64(e.step);
            full_enc.i128(e.virtual_now.0);
            full_enc.text(e.plane.as_str());
            full_enc.text(&e.schema_id);
            full_enc.u64(e.fabric_seq);
            match e.authority_order_seq {
                Some(seq) => {
                    full_enc.bool(true);
                    full_enc.u64(seq);
                }
                None => full_enc.bool(false),
            }
        }
        let transcript_digest = ContentDigest::sha256(&full_enc.finish());

        let mut auth_enc = CanonicalEncoder::new();
        auth_enc.text(LAB_TRANSCRIPT_TAG);
        auth_enc.text("authority_only");
        auth_enc.u64(authority_commit_sequence.len() as u64);
        for (schema_id, order_seq, digest) in &authority_commit_sequence {
            auth_enc.text(schema_id);
            auth_enc.u64(*order_seq);
            auth_enc.digest(*digest);
        }
        let authority_outcome_digest = ContentDigest::sha256(&auth_enc.finish());

        Ok(LabFabricTranscript {
            seed: self.seed,
            entries,
            authority_commit_sequence,
            transcript_digest,
            authority_outcome_digest,
        })
    }
}

fn record_entry(
    entries: &mut Vec<LabTranscriptEntry>,
    authority_commits: &mut Vec<(String, u64, ContentDigest)>,
    step: u64,
    virtual_now: TimestampNs,
    msg: DispatchedMessage,
) {
    match msg {
        DispatchedMessage::Packet {
            fabric_seq,
            schema_id,
            ..
        } => {
            entries.push(LabTranscriptEntry {
                step,
                virtual_now,
                plane: FabricPlane::Packet,
                schema_id,
                fabric_seq,
                authority_order_seq: None,
            });
        }
        DispatchedMessage::Reasoning {
            fabric_seq,
            schema_id,
            ..
        } => {
            entries.push(LabTranscriptEntry {
                step,
                virtual_now,
                plane: FabricPlane::Reasoning,
                schema_id,
                fabric_seq,
                authority_order_seq: None,
            });
        }
        DispatchedMessage::Authority {
            fabric_seq,
            authority_order_seq,
            schema_id,
            submission,
            ..
        } => {
            authority_commits.push((
                schema_id.clone(),
                authority_order_seq,
                submission.payload_digest,
            ));
            entries.push(LabTranscriptEntry {
                step,
                virtual_now,
                plane: FabricPlane::Authority,
                schema_id,
                fabric_seq,
                authority_order_seq: Some(authority_order_seq),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

fn debit_budget_vector(
    authority: &mut AuthorityCx,
    tree: &RegionTree,
    cost: &BudgetVector,
) -> Result<(), SubjectError> {
    let mut spender = authority.budget_mut(tree)?;
    for (dim, qty) in [
        (BudgetDimension::LatencyMs, cost.latency_ms),
        (BudgetDimension::Tokens, cost.tokens),
        (BudgetDimension::Bytes, cost.bytes),
        (BudgetDimension::ModelCalls, u64::from(cost.model_calls)),
        (BudgetDimension::CpuMillis, cost.cpu_millis),
        (BudgetDimension::AcceleratorMillis, cost.accelerator_millis),
        (BudgetDimension::EnergyMillijoules, cost.energy_millijoules),
        (BudgetDimension::NetworkBytes, cost.network_bytes),
        (BudgetDimension::StorageOperations, cost.storage_operations),
    ] {
        if qty > 0 {
            spender
                .spend(dim, qty)
                .map_err(|e| SubjectError::AuthorityDenied {
                    detail: e.to_string(),
                })?;
        }
    }
    Ok(())
}

fn compute_publish_receipt_digest(
    fabric_seq: u64,
    schema_id: &str,
    plane: FabricPlane,
    service_class: ServiceClass,
    obligation_id: Option<&ObligationId>,
    deduplicated: bool,
    grants_effect_authority: bool,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(DISPATCH_RECEIPT_TAG);
    enc.u64(fabric_seq);
    enc.text(schema_id);
    enc.text(plane.as_str());
    enc.text(service_class.as_str());
    match obligation_id {
        Some(id) => {
            enc.bool(true);
            enc.text(id.as_str());
        }
        None => enc.bool(false),
    }
    enc.bool(deduplicated);
    enc.bool(grants_effect_authority);
    ContentDigest::sha256(&enc.finish())
}

// ---------------------------------------------------------------------------
// Deterministic Unit Verification Suite
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{RegionKind, RootAuthoritySpec};
    use std::error::Error;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn test_root_authority(
        caps: Vec<&str>,
    ) -> TestResult<(AuthorityCx, RegionTree, LeaseRegistry)> {
        let budget = BudgetVector::builder()
            .bytes(1024 * 1024)
            .cpu_millis(10_000)
            .storage_operations(10_000)
            .network_bytes(1024 * 1024)
            .build()?;
        let spec = RootAuthoritySpec {
            trace_id: "trace:doc050-unit".to_owned(),
            operation_id: OperationId::parse("op:doc050:root")?,
            principal: "principal:doc050-owner".to_owned(),
            capabilities: caps.into_iter().map(str::to_owned).collect(),
            deadline: None,
            priority: 10,
            budgets: budget,
            privacy_scope: "private:property".to_owned(),
            retention_scope: "retention:standard".to_owned(),
            anchor_universe: ContentDigest::sha256(b"site:home"),
            generation: 1,
        };
        let (cx, tree) = AuthorityCx::root(
            spec,
            RegionId::new("region:doc050:proc")?,
            RegionKind::Process,
            budget,
            TimestampNs(1_000),
        )?;
        Ok((cx, tree, LeaseRegistry::new()))
    }

    fn all_caps() -> Vec<&'static str> {
        vec![
            RuntimeGrant::ObserveStatus.as_str(),
            RuntimeGrant::ObserveEvent.as_str(),
            RuntimeGrant::LedgerAppend.as_str(),
            RuntimeGrant::ObjectStage.as_str(),
            RuntimeGrant::ObjectPublish.as_str(),
            RuntimeGrant::AgentQuery.as_str(),
            RuntimeGrant::ModelInfer.as_str(),
            RuntimeGrant::Calibrate.as_str(),
            RuntimeGrant::AgentExplain.as_str(),
            RuntimeGrant::AlertCommit.as_str(),
            RuntimeGrant::AgentPlanPrepare.as_str(),
            RuntimeGrant::AdapterNet.as_str(),
        ]
    }

    fn full_route_ctx(grants: &GrantSet, pressure: ResourcePressure) -> RouteContext {
        RouteContext {
            grants: grants.clone(),
            allowed_sites: BTreeSet::from(["home".to_owned()]),
            allowed_sensors: Some(BTreeSet::from(["cam1".to_owned(), "cam2".to_owned()])),
            allowed_privacy_zones: BTreeSet::from([
                PrivacyZone::Metadata,
                PrivacyZone::ExteriorProperty,
                PrivacyZone::InteriorPrivate,
                PrivacyZone::RestrictedCustody,
            ]),
            target_locality: DataLocality::SiteHub,
            pressure,
            profile: DeploymentProfile::HomeSingleHost,
        }
    }

    #[test]
    fn registry_tombstones_plane_compatibility_and_scope_isolation_fail_closed() -> TestResult {
        let reg = SubjectSchemaRegistry::reference_fss_v1()?;

        // 1. Tombstoned v1 packet schema stays preserved in history and fails closed with v2 hint!
        let old_subj = SubjectName::parse("fss.site.home.sensor.cam1.packet_v1.g1")?;
        let err = reg.resolve(&old_subj).expect_err("v1 must be tombstoned");
        assert!(matches!(
            err,
            SubjectError::SubjectTombstoned {
                version: 1,
                superseded_by_version: 2,
                ..
            }
        ));

        // 2. Plane/service-class mismatch is rejected at registration!
        let mut custom = SubjectSchemaRegistry::new();
        let bad = SubjectSchema {
            schema_id: "SUBJ-BAD-001".to_owned(),
            family: SubjectFamily::EvidenceDelta,
            version: 1,
            pattern: SubjectSchema::parse_pattern("fss.site.<site>.bad.v1")?,
            plane: FabricPlane::Packet,
            service_class: ServiceClass::ObligatedExactlyEffectOnce,
            required_grant: RuntimeGrant::AlertCommit,
            privacy_zone: PrivacyZone::Metadata,
            requires_lease_fence: true,
            terminal_or_coverage_critical: true,
            allows_archive_locality: false,
            status: SubjectSchemaStatus::Active,
        };
        assert!(matches!(
            custom.register(bad),
            Err(SubjectError::PlaneServiceClassMismatch {
                plane: FabricPlane::Packet,
                service_class: ServiceClass::ObligatedExactlyEffectOnce,
            })
        ));

        // 3. Route compiler enforces site, sensor, privacy zone, and archive-locality clamps!
        let (cx, _tree, _leases) = test_root_authority(all_caps())?;
        let mut ctx = full_route_ctx(cx.grants(), ResourcePressure::Nominal);
        ctx.allowed_privacy_zones
            .remove(&PrivacyZone::InteriorPrivate);
        ctx.target_locality = DataLocality::ArchiveRegion;
        let compiled = RouteCompiler::compile(&reg, &ctx);
        assert!(!compiled.receipt().grants_effect_authority);

        // ATP VerifiedObjectGraph IS admitted on ArchiveRegion; Authority alert IS DENIED!
        let atp_route = compiled
            .route_for("SUBJ-002.archive.graph.v1")
            .ok_or("missing atp route")?;
        assert!(matches!(
            atp_route.disposition,
            RouteDisposition::Admitted { .. }
        ));
        let alert_route = compiled
            .route_for("SUBJ-005.incident.obligation.v1")
            .ok_or("missing alert route")?;
        assert!(matches!(
            alert_route.disposition,
            RouteDisposition::Denied {
                code: "ARCHIVE-LOCALITY-FORBIDDEN",
                ..
            }
        ));

        // Cross-site and cross-sensor access fail closed (`INT-AS-001` gate #6)!
        let normal = RouteCompiler::compile(
            &reg,
            &full_route_ctx(cx.grants(), ResourcePressure::Nominal),
        );
        let bad_site = reg.resolve(&SubjectName::parse("fss.site.neighbor.sensor.cam1.health")?)?;
        assert!(matches!(
            normal.check_subject(&bad_site),
            Err(SubjectError::SiteScopeViolation { .. })
        ));
        let bad_sensor = reg.resolve(&SubjectName::parse("fss.site.home.sensor.cam99.health")?)?;
        assert!(matches!(
            normal.check_subject(&bad_sensor),
            Err(SubjectError::SensorScopeViolation { .. })
        ));
        Ok(())
    }

    #[test]
    fn five_service_classes_pressure_shed_backpressure_gaps_fencing_and_quiescence() -> TestResult {
        let (mut cx, mut tree, mut leases) = test_root_authority(all_caps())?;
        let reg = SubjectSchemaRegistry::reference_fss_v1()?;
        let routes = RouteCompiler::compile(
            &reg,
            &full_route_ctx(cx.grants(), ResourcePressure::Nominal),
        );
        let mut fabric = SemanticSubjectFabric::open(
            &cx,
            &tree,
            reg.clone(),
            routes,
            QueueBounds {
                ephemeral_latest: 2,
                ordered_telemetry: 4,
                verified_object_graph: 2,
                reasoning_durable: 4,
                authority_durable: 4,
                authority_obligated: 4,
                max_durable_attempts: 2,
            },
            FairnessWeights::default(),
        )?;

        // 1. EphemeralLatest supersedes older queued thumbnail for same key with explicit receipt!
        let thumb_subj = SubjectName::parse("fss.site.home.sensor.cam1.thumbnail.g1")?;
        let r1 = fabric.publish_packet(
            PacketSubmission {
                subject: thumb_subj.clone(),
                source_key: "cam1:thumb".to_owned(),
                sequence: 1,
                object_digests: vec![ContentDigest::sha256(b"thumb-1")],
                provenance: "source:sensor-thumb".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_000),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(2_000),
        )?;
        assert!(r1.superseded.is_none());
        let r2 = fabric.publish_packet(
            PacketSubmission {
                subject: thumb_subj,
                source_key: "cam1:thumb".to_owned(),
                sequence: 2,
                object_digests: vec![ContentDigest::sha256(b"thumb-2")],
                provenance: "source:sensor-thumb".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_100),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(2_100),
        )?;
        assert_eq!(
            r2.superseded,
            Some(SupersedeReceipt {
                subject: "fss.site.home.sensor.cam1.thumbnail.g1".to_owned(),
                source_key: "cam1:thumb".to_owned(),
                superseded_seq: 1,
                replacement_seq: 2,
            })
        );

        // 2. OrderedTelemetry emits explicit GapReceipt on missing sequence (1 -> 3)!
        let health_subj = SubjectName::parse("fss.site.home.sensor.cam1.health")?;
        let g1 = fabric.publish_packet(
            PacketSubmission {
                subject: health_subj.clone(),
                source_key: "cam1:health".to_owned(),
                sequence: 1,
                object_digests: vec![ContentDigest::sha256(b"h1")],
                provenance: "source:sensor-health".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_200),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(2_200),
        )?;
        assert!(g1.telemetry_gap.is_none());
        let g2 = fabric.publish_packet(
            PacketSubmission {
                subject: health_subj,
                source_key: "cam1:health".to_owned(),
                sequence: 3,
                object_digests: vec![ContentDigest::sha256(b"h3")],
                provenance: "source:sensor-health".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_300),
                deadline: None,
                atp_manifest: None,
            },
            TimestampNs(2_300),
        )?;
        assert_eq!(
            g2.telemetry_gap,
            Some(TelemetryGapReceipt {
                subject: "fss.site.home.sensor.cam1.health".to_owned(),
                source_key: "cam1:health".to_owned(),
                expected_seq: 2,
                observed_seq: 3,
                out_of_order: false,
            })
        );

        // 3. VerifiedObjectGraph (ATP) requires verified root-last manifest and NEVER grants authority!
        let atp_subj = SubjectName::parse("fss.site.home.archive.root1.graph")?;
        let bad_atp = AtpObjectGraphManifest::new(
            ContentDigest::sha256(b"m1"),
            ContentDigest::sha256(b"r1"),
            vec![ContentDigest::sha256(b"c1")],
            4,
            false,
            true,
        );
        assert!(matches!(
            bad_atp,
            Err(SubjectError::InvalidAtpManifest { .. })
        ));
        let good_atp = AtpObjectGraphManifest::new(
            ContentDigest::sha256(b"m1"),
            ContentDigest::sha256(b"r1"),
            vec![ContentDigest::sha256(b"c1"), ContentDigest::sha256(b"c2")],
            4,
            true,
            true,
        )?;
        assert!(!good_atp.grants_effect_authority());
        let atp_rcpt = fabric.publish_packet(
            PacketSubmission {
                subject: atp_subj,
                source_key: "archive:node1".to_owned(),
                sequence: 1,
                object_digests: vec![ContentDigest::sha256(b"r1")],
                provenance: "custody:atp-manifest".to_owned(),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_400),
                deadline: None,
                atp_manifest: Some(good_atp),
            },
            TimestampNs(2_400),
        )?;
        assert!(!atp_rcpt.grants_effect_authority);

        // 4. Reasoning plane rejects mutable `"latest"` generation and stays derived only!
        let reason_subj = SubjectName::parse("fss.site.home.model.gen1.infer")?;
        let bad_reason = fabric.publish_reasoning(
            ReasoningSubmission {
                subject: reason_subj.clone(),
                delivery_key: "del:r0".to_owned(),
                evidence_anchor_root: ContentDigest::sha256(b"anchor-1"),
                generation_id: "latest".to_owned(),
                payload_digest: ContentDigest::sha256(b"infer-0"),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_500),
                deadline: None,
            },
            TimestampNs(2_500),
        );
        assert!(matches!(
            bad_reason,
            Err(SubjectError::InvalidReasoningPayload { .. })
        ));
        let r_rcpt = fabric.publish_reasoning(
            ReasoningSubmission {
                subject: reason_subj,
                delivery_key: "del:r1".to_owned(),
                evidence_anchor_root: ContentDigest::sha256(b"anchor-1"),
                generation_id: "model-gen:detector-v1".to_owned(),
                payload_digest: ContentDigest::sha256(b"infer-1"),
                budget: BudgetVector::ZERO,
                created_at: TimestampNs(2_500),
                deadline: None,
            },
            TimestampNs(2_500),
        )?;
        assert!(!r_rcpt.grants_effect_authority);

        // 5. Authority ObligatedExactlyEffectOnce requires valid lease fence + deduplicates exact replay!
        let lease = leases.acquire(
            "alert-channel:primary",
            cx.region().as_str(),
            Some(10_000),
            TimestampNs(2_000),
        )?;
        let auth_subj = SubjectName::parse("fss.site.home.incident.inc1.obligation")?;
        let auth_sub = AuthoritySubmission {
            subject: auth_subj.clone(),
            operation_id: OperationId::parse("op:alert:inc1")?,
            idempotency_key: IdempotencyKey::parse("idem:inc1:alert1")?,
            resource: "alert-channel:primary".to_owned(),
            fence: lease.fence,
            terminal_predicate: "alert webhook verified or reconciled".to_owned(),
            payload_digest: ContentDigest::sha256(b"alert-payload-1"),
            budget: BudgetVector::builder().bytes(256).build()?,
            created_at: TimestampNs(2_600),
            deadline: None,
        };
        // Stale/wrong fence fails closed!
        let mut stale_sub = auth_sub.clone();
        stale_sub.fence = lease.fence + 99;
        assert!(matches!(
            fabric.publish_authority(
                &mut cx,
                &mut tree,
                &mut leases,
                stale_sub,
                TimestampNs(2_600)
            ),
            Err(SubjectError::LeaseFenceDenied { .. })
        ));
        // Valid fence succeeds, registers obligation, and duplicate idempotency key deduplicates!
        let a1 = fabric.publish_authority(
            &mut cx,
            &mut tree,
            &mut leases,
            auth_sub.clone(),
            TimestampNs(2_600),
        )?;
        let ob_id = a1.obligation_id.clone().ok_or("expected obligation id")?;
        assert!(!a1.deduplicated);
        let a1_dup = fabric.publish_authority(
            &mut cx,
            &mut tree,
            &mut leases,
            auth_sub,
            TimestampNs(2_650),
        )?;
        assert!(a1_dup.deduplicated);
        assert_eq!(a1_dup.fabric_seq, a1.fabric_seq);

        // 6. Cooperative cancellation request -> drain -> progress certificate -> finalize quiescence!
        fabric.request_drain(&cx, &mut tree, TimestampNs(3_000))?;
        // New admission is refused during drain!
        assert!(matches!(
            fabric.publish_packet(
                PacketSubmission {
                    subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
                    source_key: "cam1:health".to_owned(),
                    sequence: 4,
                    object_digests: vec![ContentDigest::sha256(b"h4")],
                    provenance: "source:sensor-health".to_owned(),
                    budget: BudgetVector::ZERO,
                    created_at: TimestampNs(3_050),
                    deadline: None,
                    atp_manifest: None,
                },
                TimestampNs(3_050),
            ),
            Err(SubjectError::FabricNotAccepting { phase: "draining" })
        ));

        let (drained, cert) = fabric.step_drain(32, TimestampNs(3_100))?;
        assert!(cert.remaining_after < cert.remaining_before);
        for msg in drained {
            match msg {
                DispatchedMessage::Reasoning { fabric_seq, .. } => {
                    fabric.ack_durable(fabric_seq)?;
                }
                DispatchedMessage::Authority {
                    fabric_seq,
                    obligation_id,
                    submission,
                    ..
                } => {
                    if let Some(id) = obligation_id {
                        fabric.settle_authority_obligation(
                            &cx,
                            &mut tree,
                            fabric_seq,
                            &id,
                            ObligationTerminal::Completed,
                            Some(submission.payload_digest),
                            None,
                        )?;
                    }
                }
                DispatchedMessage::Packet { .. } => {}
            }
        }
        assert!(!ob_id.as_str().is_empty());
        let quiescence = fabric.finalize(&cx, &mut tree, TimestampNs(3_200))?;
        assert_eq!(quiescence.remaining_queued, 0);
        assert_eq!(quiescence.remaining_in_flight, 0);
        assert_eq!(quiescence.total_telemetry_gaps, 1);
        Ok(())
    }

    #[test]
    fn lab_schedule_determinism_and_authority_invariance_across_packet_schedules() -> TestResult {
        let run_seed = |seed: u64| -> TestResult<LabFabricTranscript> {
            let (mut cx, mut tree, mut leases) = test_root_authority(all_caps())?;
            let reg = SubjectSchemaRegistry::reference_fss_v1()?;
            let routes = RouteCompiler::compile(
                &reg,
                &full_route_ctx(cx.grants(), ResourcePressure::Nominal),
            );
            let mut fabric = SemanticSubjectFabric::open(
                &cx,
                &tree,
                reg,
                routes,
                QueueBounds::default(),
                FairnessWeights::default(),
            )?;
            let lease = leases.acquire(
                "alert-channel:primary",
                cx.region().as_str(),
                Some(100_000),
                TimestampNs(1_000),
            )?;
            // Enqueue mixed packet burst + reasoning + 3 ordered authority items.
            for idx in 1..=6_u64 {
                fabric.publish_packet(
                    PacketSubmission {
                        subject: SubjectName::parse("fss.site.home.sensor.cam1.health")?,
                        source_key: "cam1:health".to_owned(),
                        sequence: idx,
                        object_digests: vec![ContentDigest::sha256(
                            format!("pkt-{idx}").as_bytes(),
                        )],
                        provenance: "source:sensor-health".to_owned(),
                        budget: BudgetVector::ZERO,
                        created_at: TimestampNs(1_000 + i128::from(idx)),
                        deadline: None,
                        atp_manifest: None,
                    },
                    TimestampNs(1_000 + i128::from(idx)),
                )?;
            }
            for idx in 1..=3_u64 {
                fabric.publish_authority(
                    &mut cx,
                    &mut tree,
                    &mut leases,
                    AuthoritySubmission {
                        subject: SubjectName::parse(format!(
                            "fss.site.home.incident.inc{idx}.obligation"
                        ))?,
                        operation_id: OperationId::parse(format!("op:inc:{idx}"))?,
                        idempotency_key: IdempotencyKey::parse(format!("idem:inc:{idx}"))?,
                        resource: "alert-channel:primary".to_owned(),
                        fence: lease.fence,
                        terminal_predicate: "authority obligation settled".to_owned(),
                        payload_digest: ContentDigest::sha256(format!("auth-{idx}").as_bytes()),
                        budget: BudgetVector::builder().bytes(64).build()?,
                        created_at: TimestampNs(2_000 + i128::from(idx)),
                        deadline: None,
                    },
                    TimestampNs(2_000 + i128::from(idx)),
                )?;
            }
            let mut lab = LabFabricHarness::new(seed, TimestampNs(3_000), 100);
            let transcript = lab.run_to_empty(&mut fabric, &cx, &mut tree)?;
            fabric.request_drain(&cx, &mut tree, lab.now())?;
            let _ = fabric.finalize(&cx, &mut tree, TimestampNs(lab.now().0 + 100))?;
            Ok(transcript)
        };

        let t_a1 = run_seed(42)?;
        let t_a2 = run_seed(42)?;
        let t_b = run_seed(999_999)?;

        // Same seed -> byte-identical full transcript!
        assert_eq!(t_a1, t_a2);
        // Different packet-interleaving seed -> IDENTICAL Authority-plane commit order & digest!
        assert_eq!(
            t_a1.authority_commit_sequence,
            t_b.authority_commit_sequence
        );
        assert_eq!(t_a1.authority_outcome_digest, t_b.authority_outcome_digest);
        Ok(())
    }
}
