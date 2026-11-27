#![forbid(unsafe_code)]
//! Trust and authority graph `G_auth` (`PROJ-AUTH-001`, `fss-x4a.23.69.9`).
//!
//! Represents principals, capabilities, scoped resources, adapters, model executors, effects,
//! policies, plus non-authorizing artifacts (`WorkClaim`, `AtpDelivery`, `Recommendation`,
//! `CognitionArtifact`). Typed edges are strictly `may-read`, `may-derive`, `may-prepare`,
//! `may-commit`, `delegated-from`, `narrowed-by`, and `expires-at`.
//!
//! Enforces:
//! - Monotone narrowing across every delegation chain (refusing privilege escalation & cycles);
//! - Type-distinct authority verbs (`MayRead`/`MayDerive`/`MayPrepare`/`MayCommit`);
//! - Non-implication: work claims, ATP delivery, recommendations, and cognition NEVER imply `MayCommit`;
//! - Cross-property isolation (`property_id`) and mid-query revocation/expiry invalidation;
//! - Capability-partitioned cache keys (`cache_partition_key`);
//! - Capability noninterference: queries filter BEFORE counting, degree, or path expansion so
//!   unauthorized principals cannot infer hidden neighbors, counts, or degrees.

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

/// Registered digest domain for `G_auth` projections and witnesses (`SCHEMA-DOMAIN-GRAPH-G-AUTH-001`).
pub const G_AUTH_DIGEST_DOMAIN: &str = "fss.graph.g_auth_projection.v1";
/// Wire magic for durable `G_auth` fixtures (`FSSGAU01`).
pub const G_AUTH_WIRE_MAGIC: [u8; 8] = *b"FSSGAU01";
/// Registered algorithm ID emitted in `G_auth` witnesses.
pub const G_AUTH_ALGORITHM_ID: &str = "ALG-PROJ-AUTH-001";
/// Implementation generation recorded in `G_auth` witnesses.
pub const G_AUTH_IMPLEMENTATION_ID: &str = "fss-graph-algorithms:proj-auth-001:g-auth-oracle:v2";
/// Policy identity recorded in `G_auth` witnesses.
pub const G_AUTH_POLICY_ID: &str =
    "graph-policy:g-auth:monotone-narrowing:capability-noninterference:v2";

/// Closed taxonomy of node kinds in `G_auth`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthNodeKind {
    /// Human owner, service, or autonomous agent principal.
    Principal = 1,
    /// Explicit capability grant token.
    Capability = 2,
    /// Scoped physical or logical resource (`camera`, `zone`, `ledger`, `archive`).
    ScopedResource = 3,
    /// Device or protocol adapter.
    Adapter = 4,
    /// Bounded pure-Rust model executor.
    ModelExecutor = 5,
    /// External or mutating effect target.
    Effect = 6,
    /// Narrowing/privacy/retention policy node.
    Policy = 7,
    /// Coordination work claim (NEVER implies commit authority!).
    WorkClaim = 8,
    /// Immutable ATP object transfer (NEVER implies commit authority!).
    AtpDelivery = 9,
    /// Derived affordance recommendation (NEVER implies commit authority!).
    Recommendation = 10,
    /// Derived cognition artifact (NEVER implies commit authority!).
    CognitionArtifact = 11,
}

impl AuthNodeKind {
    /// True iff this node kind is strictly non-authorizing for `MayCommit`.
    #[must_use]
    pub const fn is_non_committing_artifact(self) -> bool {
        matches!(
            self,
            Self::WorkClaim | Self::AtpDelivery | Self::Recommendation | Self::CognitionArtifact
        )
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Principal),
            2 => Ok(Self::Capability),
            3 => Ok(Self::ScopedResource),
            4 => Ok(Self::Adapter),
            5 => Ok(Self::ModelExecutor),
            6 => Ok(Self::Effect),
            7 => Ok(Self::Policy),
            8 => Ok(Self::WorkClaim),
            9 => Ok(Self::AtpDelivery),
            10 => Ok(Self::Recommendation),
            11 => Ok(Self::CognitionArtifact),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown AuthNodeKind tag {other}"
            ))),
        }
    }
}

/// Exact 7 typed authority edges in `G_auth` (read/derive/prepare/commit strictly distinct!).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthEdgeKind {
    /// Read-only access to scoped resource.
    MayRead = 1,
    /// Derived cognition/model computation right (never grants commit).
    MayDerive = 2,
    /// Intent preparation right (never grants commit).
    MayPrepare = 3,
    /// Explicit effect commit authority (highest privilege; strictly distinct!).
    MayCommit = 4,
    /// Child capability/principal delegated from parent (must be monotone narrowing!).
    DelegatedFrom = 5,
    /// Capability narrowed by policy constraint.
    NarrowedBy = 6,
    /// Explicit expiry binding edge.
    ExpiresAt = 7,
}

impl AuthEdgeKind {
    /// Stable canonical relation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MayRead => "may-read",
            Self::MayDerive => "may-derive",
            Self::MayPrepare => "may-prepare",
            Self::MayCommit => "may-commit",
            Self::DelegatedFrom => "delegated-from",
            Self::NarrowedBy => "narrowed-by",
            Self::ExpiresAt => "expires-at",
        }
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::MayRead),
            2 => Ok(Self::MayDerive),
            3 => Ok(Self::MayPrepare),
            4 => Ok(Self::MayCommit),
            5 => Ok(Self::DelegatedFrom),
            6 => Ok(Self::NarrowedBy),
            7 => Ok(Self::ExpiresAt),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown AuthEdgeKind tag {other}"
            ))),
        }
    }
}

/// One typed entity in `G_auth` bound to an explicit `property_id`, scope tags, and expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthNodeSpec {
    /// Stable unique node identifier.
    pub node_id: String,
    /// Typed authority node kind.
    pub kind: AuthNodeKind,
    /// Property/site isolation boundary (prevents cross-property identity leakage).
    pub property_id: String,
    /// Explicit narrowed capability/resource scope tags.
    pub scope_tags: BTreeSet<String>,
    /// Hard expiration timestamp (inclusive).
    pub expires_at_ns: TimestampNs,
    /// True when revoked (invalidates all derived views & cache partitions immediately!).
    pub revoked: bool,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl AuthNodeSpec {
    /// Validates node labels fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        validate_clean_label(&self.property_id, "property_id")?;
        for tag in &self.scope_tags {
            validate_clean_label(tag, "scope_tag")?;
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this authority node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_AUTH_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.u8(self.kind as u8);
        enc.text(&self.property_id);
        enc.u64(self.scope_tags.len() as u64);
        for tag in &self.scope_tags {
            enc.text(tag);
        }
        enc.i128(self.expires_at_ns.0);
        enc.u8(u8::from(self.revoked));
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let kind = AuthNodeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let property_id = dec.text().map_err(map_err)?.to_owned();
        let s_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("scope_tags overflow".to_owned()))?;
        if s_len > 64 || s_len.saturating_mul(5) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "scope_tags count out of bounds".to_owned(),
            ));
        }
        let mut scope_tags = BTreeSet::new();
        for _ in 0..s_len {
            scope_tags.insert(dec.text().map_err(map_err)?.to_owned());
        }
        let expires_at_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let revoked = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid revoked bool".to_owned(),
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
        let spec = Self {
            node_id,
            kind,
            property_id,
            scope_tags,
            expires_at_ns,
            revoked,
            plane,
        };
        spec.validate()?;
        Ok(spec)
    }
}

/// One typed directed authority edge in `G_auth`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthEdgeSpec {
    /// Source entity ID.
    pub source_id: String,
    /// Target entity ID.
    pub target_id: String,
    /// Typed authority verb/relation.
    pub kind: AuthEdgeKind,
    /// Hard edge expiration timestamp.
    pub expires_at_ns: TimestampNs,
    /// True when this edge has been revoked.
    pub revoked: bool,
}

impl AuthEdgeSpec {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
        enc.i128(self.expires_at_ns.0);
        enc.u8(u8::from(self.revoked));
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = AuthEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let expires_at_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let revoked = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid revoked bool".to_owned(),
                ));
            }
        };
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        Ok(Self {
            source_id,
            target_id,
            kind,
            expires_at_ns,
            revoked,
        })
    }
}

/// Incremental ordered delta applied to `G_auth`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthDelta {
    /// Upsert an authority node (e.g., to revoke or narrow scope).
    UpsertNode(AuthNodeSpec),
    /// Remove a node and its incident edges.
    RemoveNode(String),
    /// Add a typed authority edge.
    AddEdge(AuthEdgeSpec),
    /// Remove a typed authority edge.
    RemoveEdge(AuthEdgeSpec),
}

/// Capability-projected principal query answer proving noninterference (zero hidden leakage!).
#[derive(Clone, Debug, PartialEq)]
pub struct PrincipalAuthorityView {
    /// Queried principal identifier.
    pub principal_id: String,
    /// Property boundary isolated for this principal.
    pub property_id: String,
    /// Exact capability/privacy-partitioned cache key (`SHA-256`).
    pub cache_partition_key: ContentDigest,
    /// Resources readable (`MayRead`) strictly within active, unrevoked, same-property scope.
    pub readable_resources: BTreeSet<String>,
    /// Resources derivable (`MayDerive`).
    pub derivable_resources: BTreeSet<String>,
    /// Effects preparable (`MayPrepare`).
    pub preparable_effects: BTreeSet<String>,
    /// Effects committable (`MayCommit`) — NEVER populated by work claims, ATP, or cognition!
    pub committable_effects: BTreeSet<String>,
    /// Authorized visible degree count (strictly over authorized targets — zero hidden-neighbor leak!).
    pub visible_degree: u64,
    /// Always `false`: inspecting `G_auth` never executes or authorizes an effect.
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Trust & Authority Graph (`G_auth`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, AuthNodeSpec>,
    visible_edges: BTreeSet<AuthEdgeSpec>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl AuthorityGraph {
    /// Builds `G_auth` while enforcing monotone delegation narrowing, delegation acyclicity,
    /// cross-property isolation, and strict prohibition on `WorkClaim`/`AtpDelivery`/
    /// `Recommendation`/`CognitionArtifact` granting `MayCommit`.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<AuthNodeSpec>,
        edges: Vec<AuthEdgeSpec>,
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
                "G_auth size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, AuthNodeSpec> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate auth node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes.insert(node.node_id.clone(), node);
        }

        let mut raw_edges: BTreeSet<AuthEdgeSpec> = BTreeSet::new();
        let mut delegation_parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            let Some(src) = raw_nodes.get(&edge.source_id) else {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown auth source_id '{}'",
                    edge.source_id
                )));
            };
            let Some(dst) = raw_nodes.get(&edge.target_id) else {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown auth target_id '{}'",
                    edge.target_id
                )));
            };
            // Cross-property isolation: no authority edge may cross distinct property_ids!
            if src.property_id != dst.property_id {
                return Err(TypedUniverseError::AuthorityViolation(format!(
                    "cross-property authority edge forbidden: '{}' ({}) -> '{}' ({})",
                    src.node_id, src.property_id, dst.node_id, dst.property_id
                )));
            }
            // Work claims, ATP deliveries, recommendations, and cognition NEVER grant MayCommit!
            if edge.kind == AuthEdgeKind::MayCommit && src.kind.is_non_committing_artifact() {
                return Err(TypedUniverseError::AuthorityViolation(format!(
                    "non-committing artifact '{}' cannot carry may-commit authority",
                    src.node_id
                )));
            }
            // Monotone narrowing: child delegated from parent MUST have subset scopes & <= expiry!
            if edge.kind == AuthEdgeKind::DelegatedFrom {
                if !src.scope_tags.is_subset(&dst.scope_tags) {
                    return Err(TypedUniverseError::AuthorityViolation(format!(
                        "delegation escalation: child '{}' scope exceeds parent '{}'",
                        src.node_id, dst.node_id
                    )));
                }
                if src.expires_at_ns.0 > dst.expires_at_ns.0 {
                    return Err(TypedUniverseError::AuthorityViolation(format!(
                        "delegation expiry escalation: child '{}' outlives parent '{}'",
                        src.node_id, dst.node_id
                    )));
                }
                delegation_parents
                    .entry(src.node_id.as_str())
                    .or_default()
                    .push(dst.node_id.as_str());
            }
            raw_edges.insert(edge.clone());
        }

        // Reject any delegation cycle fail-closed!
        detect_delegation_cycles(&raw_nodes, &delegation_parents)?;

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_nodes
            .values()
            .map(|n| ProjectionNodeSpec {
                node_id: n.node_id.clone(),
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
            GraphUniverse::GAuth,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, AuthNodeSpec> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<AuthEdgeSpec> = raw_edges
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

    /// Incrementally applies ordered authority deltas (e.g., revoking a principal/capability)
    /// while guaranteeing exact parity with full rebuild.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[AuthDelta],
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
                "delta anchor must stay on same site_lineage with monotonic sequence".to_owned(),
            ));
        }
        let mut nodes = self.visible_nodes.clone();
        let mut edges = self.visible_edges.clone();
        for delta in deltas {
            match delta {
                AuthDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.node_id.clone(), n.clone());
                }
                AuthDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|e| e.source_id != *id && e.target_id != *id);
                }
                AuthDelta::AddEdge(e) => {
                    edges.insert(e.clone());
                }
                AuthDelta::RemoveEdge(e) => {
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

    /// Canonical digest of this `G_auth` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Tombstoned legacy fields recorded during any `v1 -> v2` migration.
    #[must_use]
    pub fn tombstoned_fields(&self) -> &[String] {
        &self.tombstoned_fields
    }

    /// Inspecting `G_auth` NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Computes a noninterfering authority view and cache partition key for `principal_id` at
    /// `now_ns`, strictly enforcing expiry, mid-query revocation (`is_revoked_now`), monotone
    /// scope narrowing, and zero hidden-neighbor / hidden-degree leakage!
    pub fn query_principal_view(
        &self,
        principal_id: &str,
        now_ns: TimestampNs,
        max_operations: u64,
        mut is_revoked_now: impl FnMut() -> bool,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<PrincipalAuthorityView, TypedUniverseError> {
        validate_clean_label(principal_id, "principal_id")?;
        let mut budget = OpBudget::new(max_operations)?;
        if is_revoked_now() {
            return Err(TypedUniverseError::AuthorityViolation(
                "mid-query revocation observed before authority resolution".to_owned(),
            ));
        }
        let Some(principal) = self.visible_nodes.get(principal_id) else {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "principal '{principal_id}' not present in authorized projection"
            )));
        };
        if principal.kind != AuthNodeKind::Principal {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "node '{principal_id}' is not a Principal"
            )));
        }
        if principal.revoked || now_ns.0 > principal.expires_at_ns.0 {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "principal '{principal_id}' is revoked or expired"
            )));
        }

        // Walk principal and its delegation ancestor chain ONLY via `DelegatedFrom` / `NarrowedBy`
        // edges so unrelated principals' edges NEVER perturb budget counters (true noninterference!).
        // Any revoked or expired narrowing policy fails closed rather than silently widening scope.
        let mut effective_scopes = principal.scope_tags.clone();
        let mut cur_ancestors = vec![principal_id];
        let mut visited_anc = BTreeSet::new();
        while let Some(node_id) = cur_ancestors.pop() {
            if !visited_anc.insert(node_id) {
                continue;
            }
            for edge in self.visible_edges.iter().filter(|e| e.source_id == node_id) {
                if !matches!(
                    edge.kind,
                    AuthEdgeKind::NarrowedBy | AuthEdgeKind::DelegatedFrom
                ) {
                    continue;
                }
                budget.charge(1, &mut is_cancelled)?;
                if is_revoked_now() {
                    return Err(TypedUniverseError::AuthorityViolation(
                        "mid-query revocation observed during narrowing/delegation resolution"
                            .to_owned(),
                    ));
                }
                if edge.kind == AuthEdgeKind::NarrowedBy {
                    if edge.revoked || now_ns.0 > edge.expires_at_ns.0 {
                        return Err(TypedUniverseError::AuthorityViolation(
                            "narrowing policy edge revoked or expired; fail closed".to_owned(),
                        ));
                    }
                    let Some(policy) = self.visible_nodes.get(&edge.target_id) else {
                        return Err(TypedUniverseError::AuthorityViolation(
                            "narrowing policy node absent; fail closed".to_owned(),
                        ));
                    };
                    if policy.revoked || now_ns.0 > policy.expires_at_ns.0 {
                        return Err(TypedUniverseError::AuthorityViolation(format!(
                            "narrowing policy '{}' revoked or expired; fail closed",
                            policy.node_id
                        )));
                    }
                    effective_scopes = effective_scopes
                        .intersection(&policy.scope_tags)
                        .cloned()
                        .collect();
                } else if edge.kind == AuthEdgeKind::DelegatedFrom {
                    if edge.revoked || now_ns.0 > edge.expires_at_ns.0 {
                        return Err(TypedUniverseError::AuthorityViolation(
                            "delegation chain edge revoked or expired".to_owned(),
                        ));
                    }
                    let Some(parent) = self.visible_nodes.get(&edge.target_id) else {
                        return Err(TypedUniverseError::AuthorityViolation(
                            "delegation ancestor absent; fail closed".to_owned(),
                        ));
                    };
                    if parent.revoked || now_ns.0 > parent.expires_at_ns.0 {
                        return Err(TypedUniverseError::AuthorityViolation(format!(
                            "delegation ancestor '{}' revoked or expired",
                            parent.node_id
                        )));
                    }
                    effective_scopes = effective_scopes
                        .intersection(&parent.scope_tags)
                        .cloned()
                        .collect();
                    cur_ancestors.push(parent.node_id.as_str());
                }
            }
        }

        // Resolve strictly authorized edges originating from `principal_id` ONLY (filtering BEFORE
        // counting/degree and charging budget strictly on `principal_id`'s own incident edges!).
        let mut readable_resources = BTreeSet::new();
        let mut derivable_resources = BTreeSet::new();
        let mut preparable_effects = BTreeSet::new();
        let mut committable_effects = BTreeSet::new();
        let mut visible_targets = BTreeSet::new();

        for edge in self
            .visible_edges
            .iter()
            .filter(|e| e.source_id == principal_id)
        {
            budget.charge(1, &mut is_cancelled)?;
            if is_revoked_now() {
                return Err(TypedUniverseError::AuthorityViolation(
                    "mid-query revocation observed during capability expansion".to_owned(),
                ));
            }
            if edge.revoked || now_ns.0 > edge.expires_at_ns.0 {
                continue;
            }
            let Some(target) = self.visible_nodes.get(&edge.target_id) else {
                continue;
            };
            if target.revoked
                || now_ns.0 > target.expires_at_ns.0
                || target.property_id != principal.property_id
            {
                continue;
            }
            // Confused-deputy guard: target's required scope tags must be permitted by principal's
            // narrowed effective_scopes!
            if !target.scope_tags.is_subset(&effective_scopes) {
                continue;
            }
            match edge.kind {
                AuthEdgeKind::MayRead => {
                    readable_resources.insert(target.node_id.clone());
                    visible_targets.insert(target.node_id.clone());
                }
                AuthEdgeKind::MayDerive => {
                    derivable_resources.insert(target.node_id.clone());
                    visible_targets.insert(target.node_id.clone());
                }
                AuthEdgeKind::MayPrepare => {
                    preparable_effects.insert(target.node_id.clone());
                    visible_targets.insert(target.node_id.clone());
                }
                AuthEdgeKind::MayCommit => {
                    if target.kind == AuthNodeKind::Effect {
                        committable_effects.insert(target.node_id.clone());
                        visible_targets.insert(target.node_id.clone());
                    }
                }
                AuthEdgeKind::DelegatedFrom
                | AuthEdgeKind::NarrowedBy
                | AuthEdgeKind::ExpiresAt => {}
            }
        }

        // Cache partition key binds principal, property, effective narrowed scopes,
        // authority_generation, privacy_epoch, and authorized verb sets!
        let mut ck = CanonicalEncoder::new();
        ck.text(principal_id);
        ck.text(&principal.property_id);
        ck.u64(self.projection.generation().authority_generation);
        ck.u64(self.projection.generation().privacy_epoch);
        ck.u64(effective_scopes.len() as u64);
        for s in &effective_scopes {
            ck.text(s);
        }
        for set in [
            &readable_resources,
            &derivable_resources,
            &preparable_effects,
            &committable_effects,
        ] {
            ck.u64(set.len() as u64);
            for item in set {
                ck.text(item);
            }
        }
        let cache_partition_key = hash_domain_tag(G_AUTH_DIGEST_DOMAIN, 2, &ck.finish());
        let visible_degree = visible_targets.len() as u64;

        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(cache_partition_key);
        out_enc.u64(visible_degree);
        let output_digest = hash_domain_tag(G_AUTH_DIGEST_DOMAIN, 3, &out_enc.finish());
        let decision_path_digest =
            hash_domain_tag(G_AUTH_DIGEST_DOMAIN, 4, &cache_partition_key.bytes());

        // IMPORTANT NONINTERFERENCE DETAIL: the witness node_count / edge_count exposed for a
        // principal query reflect ONLY the principal's authorized view, never global hidden counts!
        let witness = build_universe_witness(
            G_AUTH_ALGORITHM_ID,
            G_AUTH_IMPLEMENTATION_ID,
            GraphUniverse::GAuth,
            &self.projection_id,
            self.projection.anchor(),
            1_usize.saturating_add(visible_targets.len()),
            visible_targets.len(),
            cache_partition_key,
            G_AUTH_POLICY_ID,
            budget.used(),
            ((visible_targets.len() + 2) * 128) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(PrincipalAuthorityView {
            principal_id: principal_id.to_owned(),
            property_id: principal.property_id.clone(),
            cache_partition_key,
            readable_resources,
            derivable_resources,
            preparable_effects,
            committable_effects,
            visible_degree,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_auth` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_implicit_commit` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_implicit_commit: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_implicit_commit)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_implicit_commit: bool,
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
            enc.u8(u8::from(legacy_implicit_commit));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(G_AUTH_WIRE_MAGIC, version, G_AUTH_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_auth` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_AUTH_WIRE_MAGIC, G_AUTH_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GAuth {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_auth".to_owned(),
            ));
        }
        let n_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("node count overflow".to_owned()))?;
        if n_len > MAX_UNIVERSE_ITEMS || n_len.saturating_mul(20) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "node count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_nodes = BTreeMap::new();
        for _ in 0..n_len {
            let node = AuthNodeSpec::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate auth node_id in wire fixture".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire auth node missing from embedded G_auth projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire auth node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.node_id.clone(), node);
        }
        if visible_nodes.len() != projection.node_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_auth node count disagrees with embedded projection".to_owned(),
            ));
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(20) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeSet::new();
        let mut decoded_edges = Vec::with_capacity(e_len);
        for _ in 0..e_len {
            let edge = AuthEdgeSpec::decode_body(&mut dec)?;
            let Some(src) = visible_nodes.get(&edge.source_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire auth edge source missing".to_owned(),
                ));
            };
            let Some(dst) = visible_nodes.get(&edge.target_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire auth edge target missing".to_owned(),
                ));
            };
            if src.property_id != dst.property_id {
                return Err(TypedUniverseError::AuthorityViolation(
                    "wire cross-property auth edge forbidden".to_owned(),
                ));
            }
            if edge.kind == AuthEdgeKind::MayCommit && src.kind.is_non_committing_artifact() {
                return Err(TypedUniverseError::AuthorityViolation(
                    "wire non-committing artifact cannot carry may-commit".to_owned(),
                ));
            }
            if edge.kind == AuthEdgeKind::DelegatedFrom
                && (!src.scope_tags.is_subset(&dst.scope_tags)
                    || src.expires_at_ns.0 > dst.expires_at_ns.0)
            {
                return Err(TypedUniverseError::AuthorityViolation(
                    "wire delegation violates monotone narrowing".to_owned(),
                ));
            }
            decoded_edges.push(edge.clone());
            if !visible_edges.insert(edge) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate wire G_auth edge".to_owned(),
                ));
            }
        }
        if visible_edges.len() != projection.edge_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_auth edge count disagrees with embedded projection".to_owned(),
            ));
        }
        let mut wire_del_parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &decoded_edges {
            if edge.kind == AuthEdgeKind::DelegatedFrom {
                wire_del_parents
                    .entry(edge.source_id.as_str())
                    .or_default()
                    .push(edge.target_id.as_str());
            }
        }
        detect_delegation_cycles(&visible_nodes, &wire_del_parents)?;
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_implicit_commit:tombstoned_explicit_may_commit_required".to_owned(),
                ],
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
        visible_nodes: &BTreeMap<String, AuthNodeSpec>,
        visible_edges: &BTreeSet<AuthEdgeSpec>,
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
        hash_domain_tag(G_AUTH_DIGEST_DOMAIN, 0, &enc.finish())
    }
}

fn detect_delegation_cycles(
    raw_nodes: &BTreeMap<String, AuthNodeSpec>,
    parents: &BTreeMap<&str, Vec<&str>>,
) -> Result<(), TypedUniverseError> {
    // 0 = unvisited, 1 = visiting, 2 = visited
    let mut color: BTreeMap<&str, u8> = raw_nodes.keys().map(|k| (k.as_str(), 0_u8)).collect();
    for start in raw_nodes.keys() {
        if color.get(start.as_str()).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(start.as_str(), 0)];
        color.insert(start.as_str(), 1);
        while let Some((u, idx)) = stack.pop() {
            let nbrs = parents.get(u).map_or(&[][..], Vec::as_slice);
            if idx < nbrs.len() {
                let v = nbrs[idx];
                stack.push((u, idx + 1));
                match color.get(v).copied().unwrap_or(0) {
                    1 => {
                        return Err(TypedUniverseError::AuthorityViolation(format!(
                            "delegation cycle detected involving '{u}' -> '{v}'"
                        )));
                    }
                    0 => {
                        color.insert(v, 1);
                        stack.push((v, 0));
                    }
                    _ => {}
                }
            } else {
                color.insert(u, 2);
            }
        }
    }
    Ok(())
}
