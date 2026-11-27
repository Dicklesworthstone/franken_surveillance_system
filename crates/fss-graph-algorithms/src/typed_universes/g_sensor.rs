#![forbid(unsafe_code)]
//! Sensor dependency and shared-failure graph `G_sensor` (`PROJ-SENSOR-001`, `fss-x4a.23.69.3`).
//!
//! Represents sensors, access points, switches, power circuits, edge hosts, clock sources, model
//! executors, archive paths, and alert providers. Typed directed edges are strictly `depends-on`,
//! `shares-failure-domain`, `synchronizes-with`, `transfers-through`, `powered-by`,
//! `corroborates`, and `can-fallback-to` — each binding provenance, generation, validity, and
//! domain category (`Clock`, `Network`, `Model`, `Training`, `Vendor`, `Power`, `Host`).
//!
//! Exposes hidden common causes (never calling co-resident components independent!), computes
//! valid infrastructure cuts and degraded modes with fallback invalidation when fallbacks share a
//! failed upstream domain, and enforces capability-projected degree/count noninterference.

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

/// Registered digest domain for `G_sensor` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-SENSOR-001`).
pub const G_SENSOR_DIGEST_DOMAIN: &str = "fss.graph.g_sensor_projection.v1";
/// Wire magic for durable `G_sensor` fixtures (`FSSGSN01`).
pub const G_SENSOR_WIRE_MAGIC: [u8; 8] = *b"FSSGSN01";
/// Registered algorithm ID emitted in `G_sensor` witnesses.
pub const G_SENSOR_ALGORITHM_ID: &str = "ALG-PROJ-SENSOR-001";
/// Implementation generation recorded in `G_sensor` witnesses.
pub const G_SENSOR_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-sensor-001:g-sensor-oracle:v2";
/// Policy identity recorded in `G_sensor` witnesses.
pub const G_SENSOR_POLICY_ID: &str =
    "graph-policy:g-sensor:directed-common-cause:no-false-independence:v2";

/// Closed taxonomy of infrastructure/sensor nodes in `G_sensor`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SensorInfraKind {
    /// Physical camera or environmental sensor.
    Sensor = 1,
    /// Wireless access point.
    AccessPoint = 2,
    /// PoE/Ethernet network switch.
    Switch = 3,
    /// Electrical power circuit or UPS bus.
    PowerCircuit = 4,
    /// Local edge compute host.
    EdgeHost = 5,
    /// NTP/PTP/GPS clock source.
    ClockSource = 6,
    /// Bounded model inference executor.
    ModelExecutor = 7,
    /// Remote or local archive path.
    ArchivePath = 8,
    /// External alert notification provider.
    AlertProvider = 9,
}

impl SensorInfraKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Sensor),
            2 => Ok(Self::AccessPoint),
            3 => Ok(Self::Switch),
            4 => Ok(Self::PowerCircuit),
            5 => Ok(Self::EdgeHost),
            6 => Ok(Self::ClockSource),
            7 => Ok(Self::ModelExecutor),
            8 => Ok(Self::ArchivePath),
            9 => Ok(Self::AlertProvider),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown SensorInfraKind tag {other}"
            ))),
        }
    }
}

/// Exact 7 typed directed edges in `G_sensor`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SensorDepEdgeKind {
    /// Hard operational dependency (`a` fails if `b` fails).
    DependsOn = 1,
    /// Explicit shared failure domain link.
    SharesFailureDomain = 2,
    /// Clock synchronization dependency.
    SynchronizesWith = 3,
    /// Data/network transfer path.
    TransfersThrough = 4,
    /// Power supply dependency.
    PoweredBy = 5,
    /// Candidate corroboration pair (checked for hidden shared domains!).
    Corroborates = 6,
    /// Declared failover / fallback target (invalidated if fallback shares failed upstream!).
    CanFallbackTo = 7,
}

impl SensorDepEdgeKind {
    /// Stable canonical relation spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DependsOn => "depends-on",
            Self::SharesFailureDomain => "shares-failure-domain",
            Self::SynchronizesWith => "synchronizes-with",
            Self::TransfersThrough => "transfers-through",
            Self::PoweredBy => "powered-by",
            Self::Corroborates => "corroborates",
            Self::CanFallbackTo => "can-fallback-to",
        }
    }

    /// True iff failure of target directly impacts source.
    #[must_use]
    pub const fn propagates_upstream_failure(self) -> bool {
        matches!(
            self,
            Self::DependsOn
                | Self::SharesFailureDomain
                | Self::SynchronizesWith
                | Self::TransfersThrough
                | Self::PoweredBy
        )
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::DependsOn),
            2 => Ok(Self::SharesFailureDomain),
            3 => Ok(Self::SynchronizesWith),
            4 => Ok(Self::TransfersThrough),
            5 => Ok(Self::PoweredBy),
            6 => Ok(Self::Corroborates),
            7 => Ok(Self::CanFallbackTo),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown SensorDepEdgeKind tag {other}"
            ))),
        }
    }
}

/// Shared-failure domain category exposed by corroboration queries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FailureDomainCategory {
    /// Shared clock source / drift domain.
    Clock = 1,
    /// Shared switch / AP / VLAN network domain.
    Network = 2,
    /// Shared model weights or executor generation.
    Model = 3,
    /// Shared model training corpus / calibration bias.
    Training = 4,
    /// Shared vendor firmware/cloud/silicon lineage.
    Vendor = 5,
    /// Shared power circuit / UPS / PoE injector.
    Power = 6,
    /// Shared edge host OS/CPU/storage.
    Host = 7,
}

impl FailureDomainCategory {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Clock),
            2 => Ok(Self::Network),
            3 => Ok(Self::Model),
            4 => Ok(Self::Training),
            5 => Ok(Self::Vendor),
            6 => Ok(Self::Power),
            7 => Ok(Self::Host),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown FailureDomainCategory tag {other}"
            ))),
        }
    }
}

/// One typed component node in `G_sensor`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorInfraNode {
    /// Stable unique node ID.
    pub node_id: String,
    /// Infrastructure kind.
    pub kind: SensorInfraKind,
    /// Vendor/model/firmware generation pinning this node (`>= 1`).
    pub component_generation: Generation,
    /// Telemetry freshness expiration timestamp.
    pub telemetry_valid_until_ns: TimestampNs,
    /// Intrinsic shared domain tags (e.g., `vendor:acme`, `training:coco-v1`, `model:yolox-3`).
    pub intrinsic_domains: BTreeSet<(FailureDomainCategory, String)>,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl SensorInfraNode {
    /// Validates node labels and generation fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        if self.component_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(format!(
                "zero component_generation on '{}'",
                self.node_id
            )));
        }
        for (_, dom) in &self.intrinsic_domains {
            validate_clean_label(dom, "intrinsic_domain")?;
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this infrastructure node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_SENSOR_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.u8(self.kind as u8);
        enc.u64(self.component_generation.0);
        enc.i128(self.telemetry_valid_until_ns.0);
        enc.u64(self.intrinsic_domains.len() as u64);
        for (cat, name) in &self.intrinsic_domains {
            enc.u8(*cat as u8);
            enc.text(name);
        }
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let kind = SensorInfraKind::from_tag(dec.u8().map_err(map_err)?)?;
        let component_generation = Generation(dec.u64().map_err(map_err)?);
        let telemetry_valid_until_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let d_len = usize::try_from(dec.u64().map_err(map_err)?).map_err(|_| {
            TypedUniverseError::MalformedWire("intrinsic_domains overflow".to_owned())
        })?;
        if d_len > 64 || d_len.saturating_mul(6) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "intrinsic_domains exceeds wire bounds".to_owned(),
            ));
        }
        let mut intrinsic_domains = BTreeSet::new();
        for _ in 0..d_len {
            let cat = FailureDomainCategory::from_tag(dec.u8().map_err(map_err)?)?;
            let name = dec.text().map_err(map_err)?.to_owned();
            intrinsic_domains.insert((cat, name));
        }
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
            node_id,
            kind,
            component_generation,
            telemetry_valid_until_ns,
            intrinsic_domains,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// One typed directed dependency/failure edge in `G_sensor`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SensorDepEdge {
    /// Source node ID.
    pub source_id: String,
    /// Target node ID.
    pub target_id: String,
    /// Typed dependency relation.
    pub kind: SensorDepEdgeKind,
    /// Failure-domain category attached to this dependency.
    pub category: FailureDomainCategory,
    /// Provenance label (`owner_declared`, `observed_lldp`, `calibration_manifest`).
    pub provenance: String,
    /// Pinned declaration generation (`>= 1`).
    pub generation: Generation,
    /// Validity window end timestamp.
    pub valid_until_ns: TimestampNs,
}

impl SensorDepEdge {
    /// Validates edge fields fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.source_id, "source_id")?;
        validate_clean_label(&self.target_id, "target_id")?;
        validate_clean_label(&self.provenance, "provenance")?;
        if self.generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(
                "zero edge generation".to_owned(),
            ));
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
        enc.u8(self.category as u8);
        enc.text(&self.provenance);
        enc.u64(self.generation.0);
        enc.i128(self.valid_until_ns.0);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = SensorDepEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let category = FailureDomainCategory::from_tag(dec.u8().map_err(map_err)?)?;
        let provenance = dec.text().map_err(map_err)?.to_owned();
        let generation = Generation(dec.u64().map_err(map_err)?);
        let valid_until_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let edge = Self {
            source_id,
            target_id,
            kind,
            category,
            provenance,
            generation,
            valid_until_ns,
        };
        edge.validate()?;
        Ok(edge)
    }
}

/// Incremental ordered delta applied to `G_sensor`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensorDelta {
    /// Upsert an infrastructure node.
    UpsertNode(SensorInfraNode),
    /// Remove a node and incident edges.
    RemoveNode(String),
    /// Add a dependency edge.
    AddEdge(SensorDepEdge),
    /// Remove a dependency edge.
    RemoveEdge(SensorDepEdge),
}

/// Certified failure-cut and corroboration independence analysis over `G_sensor`.
#[derive(Clone, Debug, PartialEq)]
pub struct SensorFailureAssessment {
    /// Simulated failed infrastructure component ID.
    pub failed_component_id: String,
    /// Sensors directly or transitively lost by this cut (sorted).
    pub lost_sensors: Vec<String>,
    /// Declared fallbacks invalidated because the fallback ALSO depends on the failed cut!
    pub invalidated_fallbacks: Vec<(String, String)>,
    /// Surviving valid fallbacks that remain independent of the failed cut.
    pub valid_fallbacks: Vec<(String, String)>,
    /// Shared common-cause domains found across active `Corroborates` pairs (never overstates independence!).
    pub shared_corroboration_domains:
        BTreeMap<(String, String), Vec<(FailureDomainCategory, String)>>,
    /// Nodes/edges with stale telemetry at `now_ns`.
    pub stale_telemetry_ids: Vec<String>,
    /// Degraded-mode posture label (`nominal`, `degraded_partial_cut`, `degraded_fallback_invalidated`, `uncertified_stale_or_redacted`).
    pub degraded_mode: String,
    /// Always `false`: disjoint declared domains never certify physical independence!
    pub certifies_physical_independence: bool,
    /// Always `false`: derived failure analysis never grants effect authority!
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Sensor Dependency & Shared-Failure Graph (`G_sensor`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorDependencyGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, SensorInfraNode>,
    visible_edges: BTreeSet<SensorDepEdge>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl SensorDependencyGraph {
    /// Builds `G_sensor` with capability/privacy projection applied BEFORE dependency expansion.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<SensorInfraNode>,
        edges: Vec<SensorDepEdge>,
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
                "G_sensor size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, SensorInfraNode> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate sensor infra node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes.insert(node.node_id.clone(), node);
        }

        let mut raw_edges: BTreeSet<SensorDepEdge> = BTreeSet::new();
        for edge in edges {
            edge.validate()?;
            if !raw_nodes.contains_key(&edge.source_id) || !raw_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown G_sensor edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            }
            raw_edges.insert(edge);
        }

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
                relation: format!("{}:{}", e.kind.as_str(), e.category as u8),
                weight: e.generation.0,
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GSensor,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, SensorInfraNode> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<SensorDepEdge> = raw_edges
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

    /// Incrementally applies ordered `SensorDelta` updates with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[SensorDelta],
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
                SensorDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.node_id.clone(), n.clone());
                }
                SensorDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|e| e.source_id != *id && e.target_id != *id);
                }
                SensorDelta::AddEdge(e) => {
                    e.validate()?;
                    edges.insert(e.clone());
                }
                SensorDelta::RemoveEdge(e) => {
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

    /// Canonical digest of this `G_sensor` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Capability-projected visible out-degree of `node_id` (leaks zero redacted neighbors!).
    #[must_use]
    pub fn visible_out_degree(&self, node_id: &str) -> usize {
        if !self.visible_nodes.contains_key(node_id) {
            return 0;
        }
        self.visible_edges
            .iter()
            .filter(|e| e.source_id == node_id)
            .count()
    }

    /// Derived sensor dependency graph NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Evaluates upstream failure blast radius for `failed_component_id`, fallback invalidation,
    /// stale telemetry, and transitive shared common-cause domains across corroboration pairs!
    pub fn assess_component_failure(
        &self,
        failed_component_id: &str,
        now_ns: TimestampNs,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<SensorFailureAssessment, TypedUniverseError> {
        validate_clean_label(failed_component_id, "failed_component_id")?;
        let mut budget = OpBudget::new(max_operations)?;

        let mut stale_ids = BTreeSet::new();
        for node in self.visible_nodes.values() {
            budget.charge(1, &mut is_cancelled)?;
            if now_ns.0 > node.telemetry_valid_until_ns.0 {
                stale_ids.insert(node.node_id.clone());
            }
        }

        // Compute transitive upstream dependency closure for every visible node:
        // `upstream[u]` contains `(category, target_id)` for every upstream node `target_id`
        // reachable via failure-propagating edges (`DependsOn`, `PoweredBy`, `TransfersThrough`,
        // `SynchronizesWith`, `SharesFailureDomain`) plus `u`'s own intrinsic domains!
        let mut forward_deps: BTreeMap<&str, Vec<(&str, FailureDomainCategory)>> = BTreeMap::new();
        let mut corroboration_pairs: BTreeSet<(String, String)> = BTreeSet::new();
        let mut fallbacks: Vec<(&str, &str)> = Vec::new();
        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            if now_ns.0 > edge.valid_until_ns.0 {
                stale_ids.insert(format!("{}->{}", edge.source_id, edge.target_id));
            }
            if edge.kind.propagates_upstream_failure() {
                forward_deps
                    .entry(edge.source_id.as_str())
                    .or_default()
                    .push((edge.target_id.as_str(), edge.category));
            } else if edge.kind == SensorDepEdgeKind::Corroborates {
                let pair = if edge.source_id <= edge.target_id {
                    (edge.source_id.clone(), edge.target_id.clone())
                } else {
                    (edge.target_id.clone(), edge.source_id.clone())
                };
                corroboration_pairs.insert(pair);
            } else if edge.kind == SensorDepEdgeKind::CanFallbackTo {
                fallbacks.push((edge.source_id.as_str(), edge.target_id.as_str()));
            }
        }

        let mut closure: BTreeMap<&str, BTreeSet<(FailureDomainCategory, String)>> =
            BTreeMap::new();
        for (nid, node) in &self.visible_nodes {
            let mut domains = node.intrinsic_domains.clone();
            let mut visited = BTreeSet::new();
            let mut stack = vec![nid.as_str()];
            visited.insert(nid.as_str());
            while let Some(u) = stack.pop() {
                budget.charge(1, &mut is_cancelled)?;
                if let Some(deps) = forward_deps.get(u) {
                    for &(target, cat) in deps {
                        domains.insert((cat, target.to_owned()));
                        if visited.insert(target) {
                            if let Some(t_node) = self.visible_nodes.get(target) {
                                domains.extend(t_node.intrinsic_domains.iter().cloned());
                            }
                            stack.push(target);
                        }
                    }
                }
            }
            closure.insert(nid.as_str(), domains);
        }

        // Any node whose upstream closure includes `failed_component_id` (or IS `failed_component_id`) fails!
        let mut failed_set: BTreeSet<&str> = BTreeSet::new();
        if self.visible_nodes.contains_key(failed_component_id) {
            failed_set.insert(failed_component_id);
        }
        for (nid, doms) in &closure {
            if doms.iter().any(|(_, target)| target == failed_component_id) {
                failed_set.insert(*nid);
            }
        }

        let mut lost_sensors: Vec<String> = self
            .visible_nodes
            .values()
            .filter(|n| {
                n.kind == SensorInfraKind::Sensor && failed_set.contains(n.node_id.as_str())
            })
            .map(|n| n.node_id.clone())
            .collect();
        lost_sensors.sort();

        let mut invalidated_fallbacks = Vec::new();
        let mut valid_fallbacks = Vec::new();
        for (src, fb) in fallbacks {
            if failed_set.contains(src) {
                if failed_set.contains(fb) {
                    invalidated_fallbacks.push((src.to_owned(), fb.to_owned()));
                } else {
                    valid_fallbacks.push((src.to_owned(), fb.to_owned()));
                }
            }
        }
        invalidated_fallbacks.sort();
        valid_fallbacks.sort();

        // Expose ALL shared domains across every Corroborates pair (hidden common causes!).
        let mut shared_corroboration_domains = BTreeMap::new();
        for (a, b) in corroboration_pairs {
            budget.charge(1, &mut is_cancelled)?;
            if let (Some(da), Some(db)) = (closure.get(a.as_str()), closure.get(b.as_str())) {
                let shared: Vec<(FailureDomainCategory, String)> =
                    da.intersection(db).cloned().collect();
                shared_corroboration_domains.insert((a, b), shared);
            }
        }

        let degraded_mode =
            if !self.projection.absence_boundary().certifies_absence() || !stale_ids.is_empty() {
                "uncertified_stale_or_redacted"
            } else if !invalidated_fallbacks.is_empty() {
                "degraded_fallback_invalidated"
            } else if !lost_sensors.is_empty() {
                "degraded_partial_cut"
            } else {
                "nominal"
            }
            .to_owned();

        let stale_telemetry_ids: Vec<String> = stale_ids.into_iter().collect();
        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(failed_component_id);
        path_enc.text(&degraded_mode);
        path_enc.u64(lost_sensors.len() as u64);
        for s in &lost_sensors {
            path_enc.text(s);
        }
        let decision_path_digest = hash_domain_tag(G_SENSOR_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(invalidated_fallbacks.len() as u64);
        let output_digest = hash_domain_tag(G_SENSOR_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_SENSOR_ALGORITHM_ID,
            G_SENSOR_IMPLEMENTATION_ID,
            GraphUniverse::GSensor,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_SENSOR_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(SensorFailureAssessment {
            failed_component_id: failed_component_id.to_owned(),
            lost_sensors,
            invalidated_fallbacks,
            valid_fallbacks,
            shared_corroboration_domains,
            stale_telemetry_ids,
            degraded_mode,
            certifies_physical_independence: false,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_sensor` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_assume_independent` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_assume_independent: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_assume_independent)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_assume_independent: bool,
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
            enc.u8(u8::from(legacy_assume_independent));
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
            G_SENSOR_WIRE_MAGIC,
            version,
            G_SENSOR_DIGEST_DOMAIN,
            &payload,
        )
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_sensor` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_SENSOR_WIRE_MAGIC, G_SENSOR_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GSensor {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_sensor".to_owned(),
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
            let node = SensorInfraNode::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_sensor node_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_sensor node missing from embedded projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_sensor node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.node_id.clone(), node);
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(24) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeSet::new();
        for _ in 0..e_len {
            let edge = SensorDepEdge::decode_body(&mut dec)?;
            if !visible_nodes.contains_key(&edge.source_id)
                || !visible_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_sensor edge references unknown node".to_owned(),
                ));
            }
            visible_edges.insert(edge);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_assume_independent:tombstoned_explicit_domain_intersection_required"
                        .to_owned(),
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
        visible_nodes: &BTreeMap<String, SensorInfraNode>,
        visible_edges: &BTreeSet<SensorDepEdge>,
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
        hash_domain_tag(G_SENSOR_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
