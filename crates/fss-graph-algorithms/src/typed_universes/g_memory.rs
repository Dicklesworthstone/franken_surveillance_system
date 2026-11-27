#![forbid(unsafe_code)]
//! Operational memory graph `G_memory` (`PROJ-MEMORY-001`, `fss-x4a.23.69.10`).
//!
//! Represents evidence-linked lessons, benign routines, failure modes, anti-patterns, operator
//! feedback, runbooks, and counterexamples. Typed edges are strictly `supported-by`,
//! `contradicted-by`, `applies-to`, `supersedes`, `harmed`, `helped`, and `revived-by`.
//!
//! Core guarantees:
//! - Memory is advisory retrieval/attention ONLY: it NEVER mutates authority, policy, identity,
//!   or current canonical evidence (`mutates_authority_or_truth == false`);
//! - Memories cannot be promoted to active guidance without backing evidence roots AND a
//!   validation path digest;
//! - Negative lessons and counterexamples (e.g., `"usually a raccoon"` countered by a real
//!   intrusion) ALWAYS remain retrievable alongside routines;
//! - Superseded, firmware-drifted, or privacy-TTL-expired memories remain auditable/quarantined
//!   and NEVER masquerade as current truth, and cross-property leakage is refused fail-closed!

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

/// Registered digest domain for `G_memory` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-MEMORY-001`).
pub const G_MEMORY_DIGEST_DOMAIN: &str = "fss.graph.g_memory_projection.v1";
/// Wire magic for durable `G_memory` fixtures (`FSSGME01`).
pub const G_MEMORY_WIRE_MAGIC: [u8; 8] = *b"FSSGME01";
/// Registered algorithm ID emitted in `G_memory` witnesses.
pub const G_MEMORY_ALGORITHM_ID: &str = "ALG-PROJ-MEMORY-001";
/// Implementation generation recorded in `G_memory` witnesses.
pub const G_MEMORY_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-memory-001:g-memory-oracle:v2";
/// Policy identity recorded in `G_memory` witnesses.
pub const G_MEMORY_POLICY_ID: &str =
    "graph-policy:g-memory:advisory-only:counterexample-preserving:v2";

/// Closed taxonomy of operational memory node kinds in `G_memory`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MemoryNodeKind {
    /// Evidence-linked operational lesson.
    EvidenceLinkedLesson = 1,
    /// Observed benign household/wildlife routine (e.g., `"usually a raccoon"`).
    BenignRoutine = 2,
    /// Known sensor/model/firmware failure mode.
    FailureMode = 3,
    /// Recorded harmful anti-pattern that must stay retrievable.
    AntiPattern = 4,
    /// Human operator feedback note.
    OperatorFeedback = 5,
    /// Diagnostic or response runbook.
    Runbook = 6,
    /// Explicit counterexample falsifying overbroad routines!
    Counterexample = 7,
}

impl MemoryNodeKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::EvidenceLinkedLesson),
            2 => Ok(Self::BenignRoutine),
            3 => Ok(Self::FailureMode),
            4 => Ok(Self::AntiPattern),
            5 => Ok(Self::OperatorFeedback),
            6 => Ok(Self::Runbook),
            7 => Ok(Self::Counterexample),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown MemoryNodeKind tag {other}"
            ))),
        }
    }
}

/// Exact 7 typed directed edges in `G_memory`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MemoryEdgeKind {
    /// Memory supported by evidence/lesson.
    SupportedBy = 1,
    /// Memory contradicted by counterexample or opposing feedback.
    ContradictedBy = 2,
    /// Applicability link to a zone/device/context scope.
    AppliesTo = 3,
    /// Newer memory supersedes older memory without erasing history.
    Supersedes = 4,
    /// Memory harmed prior outcome (negative lesson!).
    Harmed = 5,
    /// Memory helped prior outcome.
    Helped = 6,
    /// Memory revived after regime/firmware change.
    RevivedBy = 7,
}

impl MemoryEdgeKind {
    /// Stable canonical relation spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SupportedBy => "supported-by",
            Self::ContradictedBy => "contradicted-by",
            Self::AppliesTo => "applies-to",
            Self::Supersedes => "supersedes",
            Self::Harmed => "harmed",
            Self::Helped => "helped",
            Self::RevivedBy => "revived-by",
        }
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::SupportedBy),
            2 => Ok(Self::ContradictedBy),
            3 => Ok(Self::AppliesTo),
            4 => Ok(Self::Supersedes),
            5 => Ok(Self::Harmed),
            6 => Ok(Self::Helped),
            7 => Ok(Self::RevivedBy),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown MemoryEdgeKind tag {other}"
            ))),
        }
    }
}

/// Promotion status of one operational memory record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MemoryPromotionState {
    /// Draft/unpromoted proposal (lacks full validation path; cannot drive active advice).
    CandidateUnpromoted = 1,
    /// Promoted with verified evidence roots AND validation path digest.
    PromotedAdvisory = 2,
    /// Negative lesson / counterexample permanently retained for safety recall.
    RetainedNegativeLesson = 3,
}

impl MemoryPromotionState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::CandidateUnpromoted),
            2 => Ok(Self::PromotedAdvisory),
            3 => Ok(Self::RetainedNegativeLesson),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown MemoryPromotionState tag {other}"
            ))),
        }
    }
}

/// One typed operational memory node in `G_memory`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryNodeSpec {
    /// Stable unique memory ID.
    pub memory_id: String,
    /// Typed memory kind.
    pub kind: MemoryNodeKind,
    /// Property/site boundary preventing cross-property leakage!
    pub property_id: String,
    /// Applicability scope tags (e.g. `zone:driveway`, `camera:front`, `probe:ir-check`).
    pub scope_tags: BTreeSet<String>,
    /// Recency timestamp (ns).
    pub recorded_at_ns: TimestampNs,
    /// Privacy TTL hard expiration timestamp (ns).
    pub privacy_ttl_until_ns: TimestampNs,
    /// Advisory confidence in basis points (`0..=10_000`).
    pub confidence_bps: u16,
    /// Pinned firmware/model generation under which this lesson was validated (`>= 1`).
    pub validated_firmware_gen: Generation,
    /// Backing canonical evidence root digests (mandatory for promotion!).
    pub evidence_roots: Vec<ContentDigest>,
    /// Validation path digest (mandatory for `PromotedAdvisory`!).
    pub validation_path_digest: Option<ContentDigest>,
    /// Promotion posture.
    pub promotion_state: MemoryPromotionState,
    /// Optional advisory probe hint influenced by this memory.
    pub suggested_probe_id: Option<String>,
    /// MUST be `false`: memory NEVER mutates authority, policy, identity, or current evidence!
    pub mutates_authority_or_truth: bool,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl MemoryNodeSpec {
    /// Validates promotion rules, privacy TTL ordering, and non-authority invariant fail-closed!
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.memory_id, "memory_id")?;
        validate_clean_label(&self.property_id, "property_id")?;
        for tag in &self.scope_tags {
            validate_clean_label(tag, "scope_tag")?;
        }
        if let Some(ref probe) = self.suggested_probe_id {
            validate_clean_label(probe, "suggested_probe_id")?;
        }
        if self.mutates_authority_or_truth {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "memory '{}' cannot mutate authority, policy, identity, or canonical evidence",
                self.memory_id
            )));
        }
        if self.confidence_bps > 10_000
            || self.validated_firmware_gen.0 == 0
            || self.privacy_ttl_until_ns.0 < self.recorded_at_ns.0
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "invalid memory bounds on '{}'",
                self.memory_id
            )));
        }
        // Promotion gate: `PromotedAdvisory` REQUIRES >= 1 evidence root AND validation_path_digest!
        if self.promotion_state == MemoryPromotionState::PromotedAdvisory
            && (self.evidence_roots.is_empty() || self.validation_path_digest.is_none())
        {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "memory '{}' cannot be promoted without backing evidence_roots and validation_path_digest",
                self.memory_id
            )));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this memory node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_MEMORY_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.memory_id);
        enc.u8(self.kind as u8);
        enc.text(&self.property_id);
        enc.u64(self.scope_tags.len() as u64);
        for t in &self.scope_tags {
            enc.text(t);
        }
        enc.i128(self.recorded_at_ns.0);
        enc.i128(self.privacy_ttl_until_ns.0);
        enc.u32(u32::from(self.confidence_bps));
        enc.u64(self.validated_firmware_gen.0);
        enc.u64(self.evidence_roots.len() as u64);
        for d in &self.evidence_roots {
            enc.digest(*d);
        }
        match self.validation_path_digest {
            Some(d) => {
                enc.u8(1);
                enc.digest(d);
            }
            None => enc.u8(0),
        }
        enc.u8(self.promotion_state as u8);
        match &self.suggested_probe_id {
            Some(p) => {
                enc.u8(1);
                enc.text(p);
            }
            None => enc.u8(0),
        }
        enc.u8(u8::from(self.mutates_authority_or_truth));
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let memory_id = dec.text().map_err(map_err)?.to_owned();
        let kind = MemoryNodeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let property_id = dec.text().map_err(map_err)?.to_owned();
        let s_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("scope_tags overflow".to_owned()))?;
        if s_len > 64 || s_len.saturating_mul(5) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "scope_tags exceed wire bounds".to_owned(),
            ));
        }
        let mut scope_tags = BTreeSet::new();
        for _ in 0..s_len {
            scope_tags.insert(dec.text().map_err(map_err)?.to_owned());
        }
        let recorded_at_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let privacy_ttl_until_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let confidence_bps = u16::try_from(dec.u32().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("confidence overflow".to_owned()))?;
        let validated_firmware_gen = Generation(dec.u64().map_err(map_err)?);
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("evidence_roots overflow".to_owned()))?;
        if e_len > 64 || e_len.saturating_mul(32) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "evidence_roots exceed wire bounds".to_owned(),
            ));
        }
        let mut evidence_roots = Vec::with_capacity(e_len);
        for _ in 0..e_len {
            evidence_roots.push(dec.digest().map_err(map_err)?);
        }
        let validation_path_digest = match dec.u8().map_err(map_err)? {
            0 => None,
            1 => Some(dec.digest().map_err(map_err)?),
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid validation_path_digest flag".to_owned(),
                ));
            }
        };
        let promotion_state = MemoryPromotionState::from_tag(dec.u8().map_err(map_err)?)?;
        let suggested_probe_id = match dec.u8().map_err(map_err)? {
            0 => None,
            1 => Some(dec.text().map_err(map_err)?.to_owned()),
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid suggested_probe_id flag".to_owned(),
                ));
            }
        };
        let mutates_authority_or_truth = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid mutates_authority_or_truth bool".to_owned(),
                ));
            }
        };
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
        let node = Self {
            memory_id,
            kind,
            property_id,
            scope_tags,
            recorded_at_ns,
            privacy_ttl_until_ns,
            confidence_bps,
            validated_firmware_gen,
            evidence_roots,
            validation_path_digest,
            promotion_state,
            suggested_probe_id,
            mutates_authority_or_truth,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// One typed directed memory relation edge in `G_memory`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemoryEdgeSpec {
    /// Source memory ID.
    pub source_id: String,
    /// Target memory ID.
    pub target_id: String,
    /// Typed memory relation.
    pub kind: MemoryEdgeKind,
}

impl MemoryEdgeSpec {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = MemoryEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        Ok(Self {
            source_id,
            target_id,
            kind,
        })
    }
}

/// Incremental ordered delta applied to `G_memory`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryDelta {
    /// Upsert a memory node.
    UpsertNode(Box<MemoryNodeSpec>),
    /// Add a typed memory relation edge.
    AddEdge(MemoryEdgeSpec),
    /// Remove a typed memory relation edge.
    RemoveEdge(MemoryEdgeSpec),
}

/// Advisory memory retrieval bundle preserving counterexamples, conflicts, and anchor separation.
#[derive(Clone, Debug, PartialEq)]
pub struct AdvisoryMemoryRetrieval {
    /// Queried property isolation boundary.
    pub property_id: String,
    /// Active promoted advisory memories matching scope, privacy TTL, and firmware generation.
    pub active_advisory_ids: Vec<String>,
    /// Always-retained negative lessons, anti-patterns, and counterexamples (`ContradictedBy`/`Harmed`)!
    pub counterexample_and_negative_ids: Vec<String>,
    /// Superseded memories preserved visibly but barred from acting as current truth!
    pub superseded_ids: Vec<String>,
    /// Memories flagged stale due to firmware drift (`validated_firmware_gen != current_firmware_gen`).
    pub firmware_drifted_ids: Vec<String>,
    /// Memories suppressed because privacy TTL expired (`now_ns > privacy_ttl_until_ns`).
    pub privacy_ttl_expired_count: u64,
    /// Conflicting operator feedback pairs detected.
    pub conflicting_feedback_pairs: Vec<(String, String)>,
    /// Advisory probe recommendations derived from retrieved memories (never alters canonical truth!).
    pub suggested_probe_ids: Vec<String>,
    /// Always `true`: current event truth remains pinned to canonical ledger anchor!
    pub current_event_truth_remains_anchor_pinned: bool,
    /// Always `false`: memory retrieval NEVER grants effect or policy-mutation authority!
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Operational Memory Graph (`G_memory`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalMemoryGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, MemoryNodeSpec>,
    visible_edges: BTreeSet<MemoryEdgeSpec>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl OperationalMemoryGraph {
    /// Builds `G_memory`, enforcing cross-property isolation on edges and promotion gates on nodes.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<MemoryNodeSpec>,
        edges: Vec<MemoryEdgeSpec>,
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
        if nodes.len() > MAX_UNIVERSE_ITEMS || edges.len() > MAX_UNIVERSE_ITEMS * 4 {
            return Err(TypedUniverseError::InvalidInput(
                "G_memory size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, MemoryNodeSpec> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.memory_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate G_memory memory_id '{}'",
                    node.memory_id
                )));
            }
            raw_nodes.insert(node.memory_id.clone(), node);
        }

        let mut raw_edges: BTreeSet<MemoryEdgeSpec> = BTreeSet::new();
        for edge in edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            let (Some(src), Some(dst)) = (
                raw_nodes.get(&edge.source_id),
                raw_nodes.get(&edge.target_id),
            ) else {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown G_memory edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            };
            // Prevent cross-property memory leakage!
            if src.property_id != dst.property_id {
                return Err(TypedUniverseError::AuthorityViolation(format!(
                    "cross-property memory edge forbidden: '{}' ({}) -> '{}' ({})",
                    src.memory_id, src.property_id, dst.memory_id, dst.property_id
                )));
            }
            raw_edges.insert(edge);
        }

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_nodes
            .values()
            .map(|n| ProjectionNodeSpec {
                node_id: n.memory_id.clone(),
                plane: n.plane,
                payload_digest: n.node_digest(),
            })
            .collect();
        let proj_edges: Vec<ProjectionEdgeSpec> = raw_edges
            .iter()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: e.kind.as_str().to_owned(),
                weight: u64::from(e.kind as u8),
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GMemory,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, MemoryNodeSpec> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<MemoryEdgeSpec> = raw_edges
            .into_iter()
            .filter(|e| {
                visible_nodes.contains_key(&e.source_id) && visible_nodes.contains_key(&e.target_id)
            })
            .collect();

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_nodes,
            &visible_edges,
        );
        Ok(Self {
            projection_id,
            policy_generation,
            projection,
            visible_nodes,
            visible_edges,
            tombstoned_fields: Vec::new(),
            universe_digest,
        })
    }

    /// Incrementally applies ordered `MemoryDelta` updates with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[MemoryDelta],
        requested_absence: AbsenceBoundary,
        is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if expected_policy_generation != self.policy_generation {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "policy generation mismatch".to_owned(),
            ));
        }
        if new_anchor.site_lineage != self.projection.anchor().site_lineage
            || new_anchor.commit_sequence < self.projection.anchor().commit_sequence
        {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "delta anchor must remain on same site_lineage with monotonic sequence".to_owned(),
            ));
        }
        let mut nodes = self.visible_nodes.clone();
        let mut edges = self.visible_edges.clone();
        for delta in deltas {
            match delta {
                MemoryDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.memory_id.clone(), (**n).clone());
                }
                MemoryDelta::AddEdge(e) => {
                    edges.insert(e.clone());
                }
                MemoryDelta::RemoveEdge(e) => {
                    edges.remove(e);
                }
            }
        }
        Self::build(
            self.projection_id.clone(),
            self.policy_generation,
            new_anchor,
            new_history_root,
            authority,
            nodes.into_values().collect(),
            edges.into_iter().collect(),
            requested_absence,
            is_cancelled,
        )
    }

    /// Underlying capability-filtered `ImmutableGraphProjection`.
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical digest of this `G_memory` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Advisory memory NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Retrieves property-isolated advisory memory context for `(property_id, scope_tag)` at
    /// `now_ns` and `current_firmware_gen`, keeping negative lessons/counterexamples retrievable,
    /// isolating superseded/firmware-drifted/TTL-expired memories, and suggesting probes without
    /// altering anchor-pinned canonical truth!
    pub fn retrieve_advisory_context(
        &self,
        property_id: &str,
        scope_tag: &str,
        now_ns: TimestampNs,
        current_firmware_gen: Generation,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<AdvisoryMemoryRetrieval, TypedUniverseError> {
        validate_clean_label(property_id, "property_id")?;
        validate_clean_label(scope_tag, "scope_tag")?;
        let mut budget = OpBudget::new(max_operations)?;

        let mut superseded_set: BTreeSet<&str> = BTreeSet::new();
        let mut harmed_or_contradicted: BTreeSet<&str> = BTreeSet::new();
        let mut conflicting_feedback_pairs: Vec<(String, String)> = Vec::new();
        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            let (Some(src), Some(dst)) = (
                self.visible_nodes.get(&edge.source_id),
                self.visible_nodes.get(&edge.target_id),
            ) else {
                continue;
            };
            if src.property_id != property_id || dst.property_id != property_id {
                continue;
            }
            match edge.kind {
                MemoryEdgeKind::Supersedes => {
                    superseded_set.insert(edge.target_id.as_str());
                }
                MemoryEdgeKind::ContradictedBy => {
                    harmed_or_contradicted.insert(edge.target_id.as_str());
                    if src.kind == MemoryNodeKind::OperatorFeedback
                        && dst.kind == MemoryNodeKind::OperatorFeedback
                    {
                        conflicting_feedback_pairs
                            .push((src.memory_id.clone(), dst.memory_id.clone()));
                    }
                }
                MemoryEdgeKind::Harmed => {
                    harmed_or_contradicted.insert(edge.source_id.as_str());
                }
                _ => {}
            }
        }
        conflicting_feedback_pairs.sort();

        let mut active_advisory_ids = Vec::new();
        let mut counterexample_and_negative_ids = Vec::new();
        let mut superseded_ids = Vec::new();
        let mut firmware_drifted_ids = Vec::new();
        let mut suggested_probes: BTreeSet<String> = BTreeSet::new();
        let mut privacy_ttl_expired_count = 0_u64;

        for node in self.visible_nodes.values() {
            budget.charge(1, &mut is_cancelled)?;
            // Strict property boundary: NEVER leak memories from another property!
            if node.property_id != property_id || !node.scope_tags.contains(scope_tag) {
                continue;
            }
            // Enforce privacy TTL!
            if now_ns.0 > node.privacy_ttl_until_ns.0 {
                privacy_ttl_expired_count = privacy_ttl_expired_count.saturating_add(1);
                continue;
            }
            if superseded_set.contains(node.memory_id.as_str()) {
                superseded_ids.push(node.memory_id.clone());
                continue;
            }
            // Negative lessons, anti-patterns, and counterexamples ALWAYS stay retrievable!
            let is_negative_or_counter = matches!(
                node.kind,
                MemoryNodeKind::Counterexample
                    | MemoryNodeKind::AntiPattern
                    | MemoryNodeKind::FailureMode
            ) || node.promotion_state
                == MemoryPromotionState::RetainedNegativeLesson
                || harmed_or_contradicted.contains(node.memory_id.as_str());
            if is_negative_or_counter {
                counterexample_and_negative_ids.push(node.memory_id.clone());
                if let Some(ref probe) = node.suggested_probe_id {
                    suggested_probes.insert(probe.clone());
                }
            }
            if node.validated_firmware_gen != current_firmware_gen {
                firmware_drifted_ids.push(node.memory_id.clone());
                continue;
            }
            if node.promotion_state == MemoryPromotionState::PromotedAdvisory
                && !is_negative_or_counter
            {
                active_advisory_ids.push(node.memory_id.clone());
                if let Some(ref probe) = node.suggested_probe_id {
                    suggested_probes.insert(probe.clone());
                }
            }
        }

        let suggested_probe_ids: Vec<String> = suggested_probes.into_iter().collect();
        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(property_id);
        path_enc.text(scope_tag);
        for id in &active_advisory_ids {
            path_enc.text(id);
        }
        for id in &counterexample_and_negative_ids {
            path_enc.text(id);
        }
        let decision_path_digest = hash_domain_tag(G_MEMORY_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(privacy_ttl_expired_count);
        let output_digest = hash_domain_tag(G_MEMORY_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_MEMORY_ALGORITHM_ID,
            G_MEMORY_IMPLEMENTATION_ID,
            GraphUniverse::GMemory,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_MEMORY_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(AdvisoryMemoryRetrieval {
            property_id: property_id.to_owned(),
            active_advisory_ids,
            counterexample_and_negative_ids,
            superseded_ids,
            firmware_drifted_ids,
            privacy_ttl_expired_count,
            conflicting_feedback_pairs,
            suggested_probe_ids,
            current_event_truth_remains_anchor_pinned: true,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_memory` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_auto_activate` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_auto_activate: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_auto_activate)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_auto_activate: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        let proj_bytes = self.projection.to_canonical_bytes()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(&self.projection_id);
        enc.u64(self.policy_generation.0);
        enc.bytes(&proj_bytes);
        enc.u64(self.visible_nodes.len() as u64);
        for node in self.visible_nodes.values() {
            node.encode_body(&mut enc);
        }
        enc.u64(self.visible_edges.len() as u64);
        for edge in &self.visible_edges {
            edge.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u8(u8::from(legacy_auto_activate));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(
            G_MEMORY_WIRE_MAGIC,
            version,
            G_MEMORY_DIGEST_DOMAIN,
            &payload,
        )
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_memory` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_MEMORY_WIRE_MAGIC, G_MEMORY_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GMemory {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_memory".to_owned(),
            ));
        }
        let n_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("node count overflow".to_owned()))?;
        if n_len > MAX_UNIVERSE_ITEMS || n_len.saturating_mul(32) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "node count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_nodes = BTreeMap::new();
        for _ in 0..n_len {
            let node = MemoryNodeSpec::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.memory_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_memory memory_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.memory_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_memory node missing from embedded projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_memory node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.memory_id.clone(), node);
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(9) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeSet::new();
        for _ in 0..e_len {
            let edge = MemoryEdgeSpec::decode_body(&mut dec)?;
            let (Some(src), Some(dst)) = (
                visible_nodes.get(&edge.source_id),
                visible_nodes.get(&edge.target_id),
            ) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_memory edge references unknown node".to_owned(),
                ));
            };
            if src.property_id != dst.property_id {
                return Err(TypedUniverseError::AuthorityViolation(
                    "wire cross-property memory edge forbidden".to_owned(),
                ));
            }
            visible_edges.insert(edge);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec!["v1.legacy_auto_activate:tombstoned_advisory_only_memory".to_owned()],
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
            &visible_nodes,
            &visible_edges,
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
                visible_nodes,
                visible_edges,
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
        visible_nodes: &BTreeMap<String, MemoryNodeSpec>,
        visible_edges: &BTreeSet<MemoryEdgeSpec>,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(projection_id);
        enc.u64(policy_generation.0);
        enc.digest(projection.generation().projection_digest);
        enc.u64(visible_nodes.len() as u64);
        for node in visible_nodes.values() {
            enc.digest(node.node_digest());
        }
        enc.u64(visible_edges.len() as u64);
        for edge in visible_edges {
            edge.encode_body(&mut enc);
        }
        hash_domain_tag(G_MEMORY_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
