#![forbid(unsafe_code)]
//! Physical topology graph `G_phys` (`PROJ-PHYSICAL-001`, `fss-x4a.23.69.1`).
//!
//! Represents doors, windows, gates, walkways, rooms, yards, roof zones, fences, stairs,
//! driveways, likely entry surfaces, shelters, choke points, and surveyed landmarks.
//!
//! Traversal edges carry direction, width, slope, visibility, access state, expected transit-time
//! interval `[min_transit_ms, max_transit_ms]`, uncertainty, and behavioral mode (`OrdinaryWalk`,
//! `CrawlUnderObstacle`, `Climb`, `DoorOpen`, `DoorClosed`, `Evacuation`). Parallel behavioral
//! transitions between the same pair of physical nodes are preserved explicitly so stealth routes
//! (crawl/climb) are NEVER erased by pairwise edge collapse.
//!
//! Derived cognition only: route results preserve time intervals and uncertainty, never infer
//! metric calibration from topology alone, and never grant effect authority.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

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

/// Registered digest domain for `G_phys` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-PHYS-001`).
pub const G_PHYS_DIGEST_DOMAIN: &str = "fss.graph.g_phys_projection.v1";
/// Wire magic for durable `G_phys` fixtures (`FSSGPH01`).
pub const G_PHYS_WIRE_MAGIC: [u8; 8] = *b"FSSGPH01";
/// Registered algorithm ID emitted in `G_phys` witnesses.
pub const G_PHYS_ALGORITHM_ID: &str = "ALG-PROJ-PHYSICAL-001";
/// Implementation generation recorded in `G_phys` witnesses.
pub const G_PHYS_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-physical-001:g-phys-oracle:v2";
/// Policy identity recorded in `G_phys` witnesses.
pub const G_PHYS_POLICY_ID: &str =
    "graph-policy:g-phys:directed-multiedge-behavioral:no-metric-inference:v2";

/// Closed taxonomy of physical site topology nodes in `G_phys`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PhysicalNodeKind {
    /// Entry or interior door.
    Door = 1,
    /// Exterior or ground-level window.
    Window = 2,
    /// Perimeter gate.
    Gate = 3,
    /// Pedestrian walkway.
    Walkway = 4,
    /// Interior room.
    Room = 5,
    /// Exterior yard or lawn.
    Yard = 6,
    /// Elevated roof zone.
    RoofZone = 7,
    /// Perimeter fence line.
    Fence = 8,
    /// Stairwell or exterior steps.
    Stairs = 9,
    /// Vehicle driveway.
    Driveway = 10,
    /// Likely adversarial entry surface.
    EntrySurface = 11,
    /// Visual cover or shelter spot.
    Shelter = 12,
    /// High-value topological choke point.
    ChokePoint = 13,
    /// Surveyed physical landmark (explicitly distinct from inferred metric calibration).
    SurveyedLandmark = 14,
}

impl PhysicalNodeKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Door),
            2 => Ok(Self::Window),
            3 => Ok(Self::Gate),
            4 => Ok(Self::Walkway),
            5 => Ok(Self::Room),
            6 => Ok(Self::Yard),
            7 => Ok(Self::RoofZone),
            8 => Ok(Self::Fence),
            9 => Ok(Self::Stairs),
            10 => Ok(Self::Driveway),
            11 => Ok(Self::EntrySurface),
            12 => Ok(Self::Shelter),
            13 => Ok(Self::ChokePoint),
            14 => Ok(Self::SurveyedLandmark),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown PhysicalNodeKind tag {other}"
            ))),
        }
    }
}

/// Behavioral traversal mode preserved across parallel `G_phys` edges.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TraversalBehaviorMode {
    /// Standard upright walking traversal.
    OrdinaryWalk = 1,
    /// Stealth crawling under an obstacle/fence/camera line of sight.
    CrawlUnderObstacle = 2,
    /// Climbing over a fence, ledge, or roof transition.
    Climb = 3,
    /// Transition through an open door or gate.
    DoorOpen = 4,
    /// Transition requiring breaching/forcing a closed door or gate.
    DoorClosed = 5,
    /// Rapid emergency evacuation transition.
    Evacuation = 6,
}

impl TraversalBehaviorMode {
    /// Stable canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrdinaryWalk => "ordinary-walk",
            Self::CrawlUnderObstacle => "crawl-under-obstacle",
            Self::Climb => "climb",
            Self::DoorOpen => "door-open",
            Self::DoorClosed => "door-closed",
            Self::Evacuation => "evacuation",
        }
    }

    /// True iff this behavioral mode represents a non-nominal/stealth traversal.
    #[must_use]
    pub const fn is_stealth_or_adversarial(self) -> bool {
        matches!(self, Self::CrawlUnderObstacle | Self::Climb)
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::OrdinaryWalk),
            2 => Ok(Self::CrawlUnderObstacle),
            3 => Ok(Self::Climb),
            4 => Ok(Self::DoorOpen),
            5 => Ok(Self::DoorClosed),
            6 => Ok(Self::Evacuation),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown TraversalBehaviorMode tag {other}"
            ))),
        }
    }
}

/// Physical access posture of one traversal edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PhysicalAccessState {
    /// Unobstructed / unlocked traversal.
    Open = 1,
    /// Locked / closed barrier.
    LockedOrClosed = 2,
    /// Temporarily obstructed (parked vehicle, debris).
    Obstructed = 3,
    /// Access state unobserved/unknown.
    Unknown = 4,
}

impl PhysicalAccessState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Open),
            2 => Ok(Self::LockedOrClosed),
            3 => Ok(Self::Obstructed),
            4 => Ok(Self::Unknown),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown PhysicalAccessState tag {other}"
            ))),
        }
    }
}

/// One typed physical topology node in `G_phys`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalNodeSpec {
    /// Stable unique node identifier.
    pub node_id: String,
    /// Physical feature kind.
    pub kind: PhysicalNodeKind,
    /// Survey generation pinning this topological declaration (`>= 1`).
    pub survey_generation: Generation,
    /// Validity expiration timestamp for this survey datum.
    pub survey_valid_until_ns: TimestampNs,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl PhysicalNodeSpec {
    /// Validates node invariants fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        if self.survey_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(format!(
                "zero survey_generation on '{}'",
                self.node_id
            )));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this physical node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_PHYS_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.u8(self.kind as u8);
        enc.u64(self.survey_generation.0);
        enc.i128(self.survey_valid_until_ns.0);
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let kind = PhysicalNodeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let survey_generation = Generation(dec.u64().map_err(map_err)?);
        let survey_valid_until_ns = TimestampNs(dec.i128().map_err(map_err)?);
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
            survey_generation,
            survey_valid_until_ns,
            plane,
        };
        spec.validate()?;
        Ok(spec)
    }
}

/// One directed behavioral traversal edge in `G_phys` (parallel edges preserved!).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhysicalEdgeSpec {
    /// Stable unique edge identifier preserving parallel edges between the same endpoints.
    pub edge_id: String,
    /// Source physical node ID.
    pub source_id: String,
    /// Target physical node ID.
    pub target_id: String,
    /// Behavioral transition mode (walk, crawl, climb, door-open, door-closed, evacuation).
    pub mode: TraversalBehaviorMode,
    /// Clear passage width in centimeters (`>= 1`).
    pub width_cm: u16,
    /// Signed slope in permille (`-1000..=1000`).
    pub slope_permille: i16,
    /// Ambient visibility exposure along this transition in basis points (`0..=10_000`).
    pub visibility_bps: u16,
    /// Current physical access state.
    pub access_state: PhysicalAccessState,
    /// Minimum expected transit time in ms.
    pub min_transit_ms: u64,
    /// Maximum expected transit time in ms (`>= min_transit_ms`).
    pub max_transit_ms: u64,
    /// Explicit transit-time uncertainty bound in ms.
    pub uncertainty_ms: u64,
    /// Survey generation pinning this edge's geometry/access observation.
    pub survey_generation: Generation,
    /// Validity expiration timestamp for this survey edge.
    pub valid_until_ns: TimestampNs,
}

impl PhysicalEdgeSpec {
    /// Validates edge bounds fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.edge_id, "edge_id")?;
        validate_clean_label(&self.source_id, "source_id")?;
        validate_clean_label(&self.target_id, "target_id")?;
        if self.width_cm == 0
            || !(-1_000..=1_000).contains(&self.slope_permille)
            || self.visibility_bps > 10_000
            || self.max_transit_ms < self.min_transit_ms
            || self.survey_generation.0 == 0
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "invalid physical edge bounds on '{}'",
                self.edge_id
            )));
        }
        Ok(())
    }

    fn projection_relation(&self) -> String {
        format!("{}:{}", self.mode.as_str(), self.edge_id)
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.edge_id);
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.mode as u8);
        enc.u32(u32::from(self.width_cm));
        enc.i128(i128::from(self.slope_permille));
        enc.u32(u32::from(self.visibility_bps));
        enc.u8(self.access_state as u8);
        enc.u64(self.min_transit_ms);
        enc.u64(self.max_transit_ms);
        enc.u64(self.uncertainty_ms);
        enc.u64(self.survey_generation.0);
        enc.i128(self.valid_until_ns.0);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let edge_id = dec.text().map_err(map_err)?.to_owned();
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let mode = TraversalBehaviorMode::from_tag(dec.u8().map_err(map_err)?)?;
        let width_cm = u16::try_from(dec.u32().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("width_cm overflow".to_owned()))?;
        let slope_permille = i16::try_from(dec.i128().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("slope_permille overflow".to_owned()))?;
        let visibility_bps = u16::try_from(dec.u32().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("visibility_bps overflow".to_owned()))?;
        let access_state = PhysicalAccessState::from_tag(dec.u8().map_err(map_err)?)?;
        let min_transit_ms = dec.u64().map_err(map_err)?;
        let max_transit_ms = dec.u64().map_err(map_err)?;
        let uncertainty_ms = dec.u64().map_err(map_err)?;
        let survey_generation = Generation(dec.u64().map_err(map_err)?);
        let valid_until_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let edge = Self {
            edge_id,
            source_id,
            target_id,
            mode,
            width_cm,
            slope_permille,
            visibility_bps,
            access_state,
            min_transit_ms,
            max_transit_ms,
            uncertainty_ms,
            survey_generation,
            valid_until_ns,
        };
        edge.validate()?;
        Ok(edge)
    }
}

/// Incremental ordered delta applied to `G_phys`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhysicalDelta {
    /// Upsert a physical node.
    UpsertNode(PhysicalNodeSpec),
    /// Remove a physical node and incident edges.
    RemoveNode(String),
    /// Upsert a parallel traversal edge by `edge_id`.
    UpsertEdge(Box<PhysicalEdgeSpec>),
    /// Remove a traversal edge by `edge_id`.
    RemoveEdge(String),
}

/// One resolved route in `G_phys` preserving exact behavioral edges, transit interval, and uncertainty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalRoute {
    /// Ordered physical node IDs along the route.
    pub node_path: Vec<String>,
    /// Ordered edge IDs (identifying exact parallel behavioral transitions).
    pub edge_ids: Vec<String>,
    /// Behavioral modes used along the route.
    pub modes: Vec<TraversalBehaviorMode>,
    /// Conservative minimum transit time across the route (ms).
    pub min_transit_ms: u64,
    /// Conservative maximum transit time across the route (ms).
    pub max_transit_ms: u64,
    /// Accumulated transit uncertainty across the route (ms).
    pub total_uncertainty_ms: u64,
    /// Peak ambient visibility exposure along the route (bps).
    pub max_visibility_bps: u16,
}

/// Certified comparison of nominal vs stealth routes proving parallel behavioral edge preservation.
#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalRouteComparison {
    /// Fastest open nominal route (`OrdinaryWalk` / `DoorOpen` / `Evacuation`), if any exists.
    pub nominal_route: Option<PhysicalRoute>,
    /// Lowest-exposure / stealth-capable route allowing `CrawlUnderObstacle` and `Climb`, if any exists.
    pub stealth_route: Option<PhysicalRoute>,
    /// True iff collapsing parallel edges down to nominal-only would erase the stealth route!
    pub stealth_route_lost_under_pairwise_collapse: bool,
    /// Stale survey node or edge IDs excluded at `now_ns` / `expected_survey_generation`.
    pub stale_survey_ids: Vec<String>,
    /// Always `false`: topology routes NEVER infer metric camera calibration!
    pub infers_metric_calibration: bool,
    /// Always `false`: derived topology queries NEVER grant effect authority!
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Explicit lossless semantic crosswalk mapping `G_phys` to `DigitalTwinGraph`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigitalTwinCrosswalk {
    /// Source typed universe (`G_phys`).
    pub source_universe: GraphUniverse,
    /// Machine registry projection name (`DigitalTwinGraph`).
    pub registry_projection_name: &'static str,
    /// Count of physical nodes mapped 1-to-1.
    pub mapped_nodes: usize,
    /// Count of parallel behavioral edges preserved without pairwise collapse.
    pub preserved_parallel_edges: usize,
    /// Always `true`: guarantees zero attribute, direction, or multiedge loss.
    pub lossless_verified: bool,
}

/// Anchor-pinned, capability-filtered Physical Topology Graph (`G_phys`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalTopologyGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, PhysicalNodeSpec>,
    visible_edges: BTreeMap<String, PhysicalEdgeSpec>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl PhysicalTopologyGraph {
    /// Builds `G_phys` preserving all parallel behavioral edges through `ImmutableGraphProjection`.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<PhysicalNodeSpec>,
        edges: Vec<PhysicalEdgeSpec>,
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
                "G_phys size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, PhysicalNodeSpec> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate physical node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes.insert(node.node_id.clone(), node);
        }

        let mut raw_edges: BTreeMap<String, PhysicalEdgeSpec> = BTreeMap::new();
        for edge in edges {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            edge.validate()?;
            if !raw_nodes.contains_key(&edge.source_id) || !raw_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown physical edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            }
            if raw_edges.contains_key(&edge.edge_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate physical edge_id '{}'",
                    edge.edge_id
                )));
            }
            raw_edges.insert(edge.edge_id.clone(), edge);
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
            .values()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: e.projection_relation(),
                weight: e.min_transit_ms,
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GPhys,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, PhysicalNodeSpec> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeMap<String, PhysicalEdgeSpec> = raw_edges
            .into_iter()
            .filter(|(_, e)| {
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

    /// Incrementally applies ordered `PhysicalDelta` updates with exact full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[PhysicalDelta],
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
                PhysicalDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.node_id.clone(), n.clone());
                }
                PhysicalDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|_, e| e.source_id != *id && e.target_id != *id);
                }
                PhysicalDelta::UpsertEdge(e) => {
                    e.validate()?;
                    edges.insert(e.edge_id.clone(), (**e).clone());
                }
                PhysicalDelta::RemoveEdge(eid) => {
                    edges.remove(eid);
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
            edges.into_values().collect(),
            requested_absence,
            is_cancelled,
        )
    }

    /// Underlying capability-filtered `ImmutableGraphProjection`.
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical digest of this `G_phys` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Returns the explicit lossless crosswalk to `DigitalTwinGraph`.
    #[must_use]
    pub fn digital_twin_crosswalk(&self) -> DigitalTwinCrosswalk {
        DigitalTwinCrosswalk {
            source_universe: GraphUniverse::GPhys,
            registry_projection_name: "DigitalTwinGraph",
            mapped_nodes: self.visible_nodes.len(),
            preserved_parallel_edges: self.visible_edges.len(),
            lossless_verified: true,
        }
    }

    /// Derived physical topology NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Compares nominal open routes against stealth-capable routes (`CrawlUnderObstacle`/`Climb`),
    /// excluding stale survey data at `now_ns` / `expected_survey_generation` and proving when
    /// pairwise edge collapse would lose a stealth approach path.
    #[allow(clippy::too_many_arguments)]
    pub fn compare_nominal_and_stealth_routes(
        &self,
        start_id: &str,
        goal_id: &str,
        now_ns: TimestampNs,
        expected_survey_generation: Option<Generation>,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<PhysicalRouteComparison, TypedUniverseError> {
        validate_clean_label(start_id, "start_id")?;
        validate_clean_label(goal_id, "goal_id")?;
        let mut budget = OpBudget::new(max_operations)?;

        let mut stale_survey_ids = BTreeSet::new();
        let mut fresh_nodes = BTreeSet::new();
        for node in self.visible_nodes.values() {
            budget.charge(1, &mut is_cancelled)?;
            let stale = now_ns.0 > node.survey_valid_until_ns.0
                || expected_survey_generation.is_some_and(|g| node.survey_generation != g);
            if stale {
                stale_survey_ids.insert(node.node_id.clone());
            } else {
                fresh_nodes.insert(node.node_id.as_str());
            }
        }

        let mut fresh_edges: Vec<&PhysicalEdgeSpec> = Vec::new();
        for edge in self.visible_edges.values() {
            budget.charge(1, &mut is_cancelled)?;
            let stale = now_ns.0 > edge.valid_until_ns.0
                || expected_survey_generation.is_some_and(|g| edge.survey_generation != g);
            if stale {
                stale_survey_ids.insert(edge.edge_id.clone());
            } else if fresh_nodes.contains(edge.source_id.as_str())
                && fresh_nodes.contains(edge.target_id.as_str())
            {
                fresh_edges.push(edge);
            }
        }

        let nominal_route = shortest_physical_route(
            start_id,
            goal_id,
            &fresh_nodes,
            &fresh_edges,
            false,
            &mut budget,
            &mut is_cancelled,
        )?;
        let stealth_route = shortest_physical_route(
            start_id,
            goal_id,
            &fresh_nodes,
            &fresh_edges,
            true,
            &mut budget,
            &mut is_cancelled,
        )?;

        // Pairwise collapse keeps only the fastest nominal edge per (src, dst) pair:
        // if stealth_route exists AND uses a stealth mode (or nominal_route is None / higher exposure),
        // pairwise nominal collapse would lose that stealth route!
        let stealth_route_lost_under_pairwise_collapse = match (&nominal_route, &stealth_route) {
            (None, Some(_)) => true,
            (Some(nom), Some(stl)) => {
                stl.modes.iter().any(|m| m.is_stealth_or_adversarial())
                    && (stl.max_visibility_bps < nom.max_visibility_bps
                        || stl.min_transit_ms < nom.min_transit_ms)
            }
            _ => false,
        };

        let stale_vec: Vec<String> = stale_survey_ids.into_iter().collect();
        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(start_id);
        path_enc.text(goal_id);
        path_enc.u8(u8::from(stealth_route_lost_under_pairwise_collapse));
        if let Some(ref r) = stealth_route {
            for eid in &r.edge_ids {
                path_enc.text(eid);
            }
        }
        let decision_path_digest = hash_domain_tag(G_PHYS_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(stale_vec.len() as u64);
        let output_digest = hash_domain_tag(G_PHYS_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_PHYS_ALGORITHM_ID,
            G_PHYS_IMPLEMENTATION_ID,
            GraphUniverse::GPhys,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_PHYS_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(PhysicalRouteComparison {
            nominal_route,
            stealth_route,
            stealth_route_lost_under_pairwise_collapse,
            stale_survey_ids: stale_vec,
            infers_metric_calibration: false,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_phys` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_collapsed_edges` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_collapsed_edges: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_collapsed_edges)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_collapsed_edges: bool,
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
        for edge in self.visible_edges.values() {
            edge.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u8(u8::from(legacy_collapsed_edges));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(G_PHYS_WIRE_MAGIC, version, G_PHYS_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_phys` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_PHYS_WIRE_MAGIC, G_PHYS_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GPhys {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_phys".to_owned(),
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
            let node = PhysicalNodeSpec::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate physical node_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire physical node missing from embedded G_phys projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire physical node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.node_id.clone(), node);
        }
        if visible_nodes.len() != projection.node_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_phys node count disagrees with embedded projection".to_owned(),
            ));
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(32) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeMap::new();
        for _ in 0..e_len {
            let edge = PhysicalEdgeSpec::decode_body(&mut dec)?;
            if visible_edges.contains_key(&edge.edge_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate physical edge_id".to_owned(),
                ));
            }
            if !visible_nodes.contains_key(&edge.source_id)
                || !visible_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire physical edge references unknown node".to_owned(),
                ));
            }
            visible_edges.insert(edge.edge_id.clone(), edge);
        }
        if visible_edges.len() != projection.edge_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_phys edge count disagrees with embedded projection".to_owned(),
            ));
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_collapsed_edges:tombstoned_parallel_behavioral_edges_preserved"
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
        visible_nodes: &BTreeMap<String, PhysicalNodeSpec>,
        visible_edges: &BTreeMap<String, PhysicalEdgeSpec>,
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
        for edge in visible_edges.values() {
            edge.encode_body(&mut enc);
        }
        hash_domain_tag(G_PHYS_DIGEST_DOMAIN, 0, &enc.finish())
    }
}

fn shortest_physical_route(
    start_id: &str,
    goal_id: &str,
    fresh_nodes: &BTreeSet<&str>,
    fresh_edges: &[&PhysicalEdgeSpec],
    allow_stealth: bool,
    budget: &mut OpBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<PhysicalRoute>, TypedUniverseError> {
    if !fresh_nodes.contains(start_id) || !fresh_nodes.contains(goal_id) {
        return Ok(None);
    }
    let mut adj: BTreeMap<&str, Vec<&PhysicalEdgeSpec>> = BTreeMap::new();
    for &edge in fresh_edges {
        if edge.access_state != PhysicalAccessState::Open {
            continue;
        }
        if !allow_stealth && edge.mode.is_stealth_or_adversarial() {
            continue;
        }
        if edge.mode == TraversalBehaviorMode::DoorClosed {
            continue;
        }
        adj.entry(edge.source_id.as_str()).or_default().push(edge);
    }

    // Cost key: for stealth mode minimize (max_visibility_bps, min_transit_ms, edge_id);
    // for nominal mode minimize (min_transit_ms, max_visibility_bps, edge_id).
    type CostKey = (u64, u64, String);
    let mut best: BTreeMap<&str, (CostKey, u64, u64, u64, u16)> = BTreeMap::new();
    let mut prev: BTreeMap<&str, (&str, &PhysicalEdgeSpec)> = BTreeMap::new();
    let mut heap: BinaryHeap<std::cmp::Reverse<(CostKey, &str)>> = BinaryHeap::new();

    let init_key = (0_u64, 0_u64, String::new());
    best.insert(start_id, (init_key.clone(), 0, 0, 0, 0));
    heap.push(std::cmp::Reverse((init_key, start_id)));

    while let Some(std::cmp::Reverse((cur_key, u))) = heap.pop() {
        budget.charge(1, is_cancelled)?;
        let Some((best_key, cur_min, cur_max, cur_unc, cur_vis)) = best.get(u).cloned() else {
            continue;
        };
        if cur_key > best_key {
            continue;
        }
        if u == goal_id {
            break;
        }
        let Some(edges) = adj.get(u) else {
            continue;
        };
        for &edge in edges {
            budget.charge(1, is_cancelled)?;
            let next_min = cur_min.saturating_add(edge.min_transit_ms);
            let next_max = cur_max.saturating_add(edge.max_transit_ms);
            let next_unc = cur_unc.saturating_add(edge.uncertainty_ms);
            let next_vis = cur_vis.max(edge.visibility_bps);
            let next_key = if allow_stealth {
                (u64::from(next_vis), next_min, edge.edge_id.clone())
            } else {
                (next_min, u64::from(next_vis), edge.edge_id.clone())
            };
            let v = edge.target_id.as_str();
            if best.get(v).is_none_or(|(k, ..)| next_key < *k) {
                best.insert(
                    v,
                    (next_key.clone(), next_min, next_max, next_unc, next_vis),
                );
                prev.insert(v, (u, edge));
                heap.push(std::cmp::Reverse((next_key, v)));
            }
        }
    }

    let Some((_, min_transit_ms, max_transit_ms, total_uncertainty_ms, max_visibility_bps)) =
        best.get(goal_id)
    else {
        return Ok(None);
    };
    let (min_transit_ms, max_transit_ms, total_uncertainty_ms, max_visibility_bps) = (
        *min_transit_ms,
        *max_transit_ms,
        *total_uncertainty_ms,
        *max_visibility_bps,
    );
    let mut node_path = vec![goal_id.to_owned()];
    let mut edge_ids = Vec::new();
    let mut modes = Vec::new();
    let mut cur = goal_id;
    while cur != start_id {
        let Some(&(p, edge)) = prev.get(cur) else {
            return Ok(None);
        };
        edge_ids.push(edge.edge_id.clone());
        modes.push(edge.mode);
        node_path.push(p.to_owned());
        cur = p;
    }
    node_path.reverse();
    edge_ids.reverse();
    modes.reverse();
    Ok(Some(PhysicalRoute {
        node_path,
        edge_ids,
        modes,
        min_transit_ms,
        max_transit_ms,
        total_uncertainty_ms,
        max_visibility_bps,
    }))
}
