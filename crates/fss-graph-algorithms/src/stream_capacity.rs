#![forbid(unsafe_code)]
//! Complete stream-demand routing over an explicitly declared infrastructure topology.
//!
//! This is aggregate, integer, splittable routing in one rate unit, not a claim that a camera
//! transport supports multipath, that link rates were measured, or that a route is authorized.
//! The objective is maximum total delivery, then minimum total link cost. In a shortage the
//! canonical allocation is not a fairness or camera-priority policy. Every original demand
//! remains present, including a camera whose attachment node has explicitly failed.
//!
//! Named link vertices preserve parallel physical links in the strict simple-graph solvers.
//! Failed links and links incident to failed nodes have zero effective capacity; declared
//! capacities remain positive and retained. Recorder limits and camera injection limits are
//! explicit reduction arcs. Thus a fully served query's minimum cut can be its demand arcs;
//! it does not measure spare network capacity.
//!
//! Both existing certified algorithms complete under one operation/output allowance. The final
//! minimum-cost flow must saturate the maximum-flow cut. All inputs, result rows, failures and
//! both complete solver proofs are bound into the composition. No partial optimum is returned.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::GraphError;
use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul,
};
use crate::flow::{self, CutMode, FlowOutput};
use crate::min_cost_flow::{self, MinCostFlowOutput};
use crate::weighted::{WeightedGraph, WeightedGraphBuilder};

/// Maximum declared infrastructure nodes, including isolated or failed nodes.
pub const MAX_NODES: usize = 256;
/// Maximum individually identified physical links; parallel endpoints are permitted.
pub const MAX_LINKS: usize = 1024;
/// Maximum distinct camera sensor demands.
pub const MAX_CAMERAS: usize = 128;
/// Maximum independently capacity-limited recorder endpoints.
pub const MAX_RECORDERS: usize = 32;
/// Maximum ASCII identity bytes, before the internal typed prefix is added.
pub const MAX_ID_BYTES: usize = 256;
/// Maximum ASCII unit bytes.
pub const MAX_UNIT_BYTES: usize = 64;
/// Shared hard operation ceiling across preparation, both solvers and final verification.
pub const MAX_WORK_UNITS: u64 = 50_000_000;
/// Shared logical-output ceiling, including both complete solver proofs.
pub const MAX_OUTPUT_ENTRIES: u64 = 32_768;
/// Canonical complete declaration, including inactive links and explicit failures.
pub const INPUT_DOMAIN: &str = "fss.graph.stream_capacity_input.v1";
/// Complete source-accounted routing answer and both certified solver runs.
pub const OUTPUT_DOMAIN: &str = "fss.graph.stream_capacity_output.v1";
/// Composition decisions, binding the exact decisions of both existing algorithms.
pub const DECISION_DOMAIN: &str = "fss.graph.stream_capacity_decision_path.v1";

/// Additive operational composition of the registered minimum-cost-flow family.
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MCF-001",
    algorithm_name: "min_cost_flow",
    tie_break_rule: "maximum total delivery then minimum total cost; existing canonical residual and heap order over typed stable endpoint identities",
    complexity_witness: "input bytes, preparation steps, both certified solver operation totals and final certificate checks",
    output_size_witness: "all camera/link/recorder rows, failed identities, typed cut/partition and both complete certified flow outputs",
    exactness: "bounded_exact",
    implementation_id: "fss-graph-algorithms:alg-mcf-001:stream-capacity-composition:v1",
    tie_break_policy_id: "tie:typed-source-node-link-camera-recorder-sink:stable-id:existing-flow-and-mcf-order:v1",
    policy_id: "capacity-policy:declared-directed-links:integer-splittable-routing:maximum-delivery-then-minimum-cost:all-demands-retained:explicit-node-link-failures:no-fairness-or-priority:v1",
    complexity_bound_id: "bound:alg-mcf-001:typed-capacity-reduction-plus-certified-maxflow-and-mincost-plus-linear-certificate:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_DOMAIN,
};

/// A directed physical link. Cost is per routed rate unit in the declared cost unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    /// Unique link identity; distinct links can have identical endpoints.
    pub id: String,
    /// Existing infrastructure tail node.
    pub from: String,
    /// Existing infrastructure head node, different from `from`.
    pub to: String,
    /// Positive declared capacity.
    pub capacity: u64,
    /// Nonnegative cost for each routed rate unit on this link.
    pub unit_cost: u64,
}

/// One camera's complete requested rate, never silently removed by a failure declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraDemand {
    /// Distinct sensor identity; no physical person or track identity is involved.
    pub sensor: String,
    /// Existing infrastructure attachment node.
    pub node: String,
    /// Positive complete demand in `CapacityQuery::rate_unit`.
    pub requested: u64,
}

/// One recorder endpoint with an explicit aggregate acceptance limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recorder {
    /// Unique endpoint identity, separate from the node/camera/link namespaces.
    pub id: String,
    /// Existing infrastructure attachment node.
    pub node: String,
    /// Positive acceptance capacity in the declared rate unit.
    pub capacity: u64,
}

/// Complete owner-declared routing problem; ordering has no semantic effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityQuery {
    /// One explicit rate unit shared by demands and all capacities.
    pub rate_unit: String,
    /// Cost unit per routed rate unit; zero-cost links remain valid.
    pub cost_unit: String,
    /// All infrastructure nodes, including isolated and failed nodes.
    pub nodes: Vec<String>,
    /// Directed named links. Endpoint duplicates are allowed, link-ID duplicates are not.
    pub links: Vec<Link>,
    /// One positive demand for each distinct camera sensor.
    pub cameras: Vec<CameraDemand>,
    /// One positive acceptance limit per distinct recorder ID.
    pub recorders: Vec<Recorder>,
    /// Explicitly failed known infrastructure nodes; every incident link is disabled.
    pub failed_nodes: BTreeSet<String>,
    /// Explicitly failed known link IDs; their declared capacities are still retained.
    pub failed_links: BTreeSet<String>,
}

/// Type-preserving vertex in the two certified reduction graphs.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Endpoint {
    /// Synthetic source of the complete camera demands.
    Source,
    /// Declared infrastructure node.
    Node(String),
    /// Named physical link, split to preserve parallel links.
    Link(String),
    /// One camera's private injection/attachment vertex.
    Camera(String),
    /// One recorder's private acceptance vertex.
    Recorder(String),
    /// Synthetic destination collecting recorder deliveries.
    Sink,
}

impl Endpoint {
    /// Exact unambiguous identity used by both inner solver proofs.
    #[must_use]
    pub fn projection_id(&self) -> String {
        match self {
            Self::Source => "0/source".to_owned(),
            Self::Node(id) => format!("1/node/{id}"),
            Self::Link(id) => format!("2/link/{id}"),
            Self::Camera(id) => format!("3/camera/{id}"),
            Self::Recorder(id) => format!("4/recorder/{id}"),
            Self::Sink => "5/sink".to_owned(),
        }
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        match self {
            Self::Source => e.tag(0),
            Self::Node(id) => {
                e.tag(1);
                e.text(id);
            }
            Self::Link(id) => {
                e.tag(2);
                e.text(id);
            }
            Self::Camera(id) => {
                e.tag(3);
                e.text(id);
            }
            Self::Recorder(id) => {
                e.tag(4);
                e.text(id);
            }
            Self::Sink => e.tag(5),
        }
    }
}

/// Complete conditional demand outcome, not a measured network state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityStatus {
    /// Every camera demand is carried in full by the same feasible routing.
    FullyRouted,
    /// This exact maximum flow cannot carry the complete requested sum.
    CapacityShortfall,
}

impl CapacityStatus {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullyRouted => "fully_routed",
            Self::CapacityShortfall => "capacity_shortfall",
        }
    }
}

/// Complete demand accounting for one camera under the chosen minimum-cost maximum flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraDelivery {
    /// Original sensor identity.
    pub sensor: String,
    /// Declared attachment node.
    pub node: String,
    /// Complete original positive demand.
    pub requested: u64,
    /// Actually routed amount, including zero.
    pub delivered: u64,
    /// Exact `requested - delivered`.
    pub shortfall: u64,
    /// Whether the attachment node was explicitly declared failed.
    pub attachment_failed: bool,
}

/// A complete physical-link row, including unused and failed links.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkFlow {
    /// Original link identity.
    pub id: String,
    /// Original tail node.
    pub from: String,
    /// Original head node.
    pub to: String,
    /// Positive declared capacity, unchanged by failure declarations.
    pub capacity: u64,
    /// Original nonnegative unit cost.
    pub unit_cost: u64,
    /// Routed amount, zero for an unavailable link.
    pub flow: u64,
    /// The link itself is explicitly failed.
    pub failed: bool,
    /// Its tail infrastructure node is explicitly failed.
    pub from_failed: bool,
    /// Its head infrastructure node is explicitly failed.
    pub to_failed: bool,
}

impl LinkFlow {
    /// Capacity remaining after the exact declared link and endpoint failures.
    #[must_use]
    pub const fn effective_capacity(&self) -> u64 {
        if self.failed || self.from_failed || self.to_failed {
            0
        } else {
            self.capacity
        }
    }
}

/// Complete recorder acceptance accounting, including an unavailable recorder attachment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecorderDelivery {
    /// Original endpoint identity.
    pub id: String,
    /// Original attachment node.
    pub node: String,
    /// Positive declared acceptance capacity.
    pub capacity: u64,
    /// Total rate accepted at this endpoint.
    pub received: u64,
    /// Whether its attachment node was explicitly failed.
    pub attachment_failed: bool,
}

/// One forward arc of the certified minimum cut, expressed in typed endpoint identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutArc {
    /// Source-side endpoint.
    pub from: Endpoint,
    /// Endpoint outside the source side.
    pub to: Endpoint,
    /// Effective arc capacity; explicit failures can produce zero-capacity cut arcs.
    pub capacity: u64,
    /// Flow in the final minimum-cost answer; verified to equal this cut capacity.
    pub flow: u64,
}

/// Complete conditional routing result, including both original certified solver outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityOutput {
    /// Whether every original camera demand is fully served.
    pub status: CapacityStatus,
    /// Declared shared rate unit.
    pub rate_unit: String,
    /// Declared cost per rate unit.
    pub cost_unit: String,
    /// All infrastructure identities, including isolated and failed nodes, in stable order.
    pub nodes: Vec<String>,
    /// Checked sum of every original camera demand.
    pub requested: u64,
    /// Maximum achievable aggregate delivery under the declared capacities/failures.
    pub delivered: u64,
    /// Exact `requested - delivered`.
    pub shortfall: u64,
    /// Minimum total cost among flows delivering `delivered` units.
    pub total_cost: u64,
    /// Every camera, in sensor order; no fairness/priority inference follows from shortage rows.
    pub cameras: Vec<CameraDelivery>,
    /// Every physical link in link-ID order, including unused or unavailable links.
    pub links: Vec<LinkFlow>,
    /// Every recorder in endpoint-ID order.
    pub recorders: Vec<RecorderDelivery>,
    /// Complete known failed-node set, in stable order.
    pub failed_nodes: Vec<String>,
    /// Complete known failed-link set, in stable order.
    pub failed_links: Vec<String>,
    /// Inclusion-minimal source side of the maximum-flow minimum cut.
    pub source_side: Vec<Endpoint>,
    /// Complete forward cut, saturated by the final minimum-cost maximum flow.
    pub cut: Vec<CutArc>,
    /// Existing `ALG-FLOW-001` proof over the exact capacity reduction.
    pub maximum_flow: CertifiedRun<FlowOutput>,
    /// Existing `ALG-MCF-001` proof over the exact paired cost/capacity reductions.
    pub minimum_cost: CertifiedRun<MinCostFlowOutput>,
}

fn encode_proof<O: CertifiedOutput>(e: &mut CanonicalEncoder, run: &CertifiedRun<O>) {
    e.text(run.identity.algorithm_id);
    e.text(run.identity.implementation_id);
    e.text(run.identity.policy_id);
    e.u64(run.node_count);
    e.u64(run.edge_count);
    e.digest(run.input_digest);
    e.digest(run.output_digest);
    e.digest(run.decision_path_digest);
    e.u64(run.operations);
    e.u64(run.output_entries);
    e.u64(run.peak_working_bytes);
    e.u64(run.counters.len() as u64);
    for (name, value) in &run.counters {
        e.text(name);
        e.u64(*value);
    }
    run.output.encode(e);
}

impl CertifiedOutput for CapacityOutput {
    fn entries(&self) -> u64 {
        // 64 includes totals, units, status and the scalar/counter metadata of both proofs.
        64 + (self.nodes.len()
            + self.cameras.len()
            + self.links.len()
            + self.recorders.len()
            + self.failed_nodes.len()
            + self.failed_links.len()
            + self.source_side.len()
            + self.cut.len()) as u64
            + self.maximum_flow.output_entries
            + self.minimum_cost.output_entries
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(self.status.as_str());
        e.text(&self.rate_unit);
        e.text(&self.cost_unit);
        encode_ids(e, &self.nodes);
        for value in [
            self.requested,
            self.delivered,
            self.shortfall,
            self.total_cost,
        ] {
            e.u64(value);
        }
        e.u64(self.cameras.len() as u64);
        for camera in &self.cameras {
            e.text(&camera.sensor);
            e.text(&camera.node);
            e.u64(camera.requested);
            e.u64(camera.delivered);
            e.u64(camera.shortfall);
            e.bool(camera.attachment_failed);
        }
        e.u64(self.links.len() as u64);
        for link in &self.links {
            e.text(&link.id);
            e.text(&link.from);
            e.text(&link.to);
            e.u64(link.capacity);
            e.u64(link.unit_cost);
            e.u64(link.flow);
            e.bool(link.failed);
            e.bool(link.from_failed);
            e.bool(link.to_failed);
        }
        e.u64(self.recorders.len() as u64);
        for recorder in &self.recorders {
            e.text(&recorder.id);
            e.text(&recorder.node);
            e.u64(recorder.capacity);
            e.u64(recorder.received);
            e.bool(recorder.attachment_failed);
        }
        encode_ids(e, &self.failed_nodes);
        encode_ids(e, &self.failed_links);
        e.u64(self.source_side.len() as u64);
        for endpoint in &self.source_side {
            endpoint.encode(e);
        }
        e.u64(self.cut.len() as u64);
        for arc in &self.cut {
            arc.from.encode(e);
            arc.to.encode(e);
            e.u64(arc.capacity);
            e.u64(arc.flow);
        }
        encode_proof(e, &self.maximum_flow);
        encode_proof(e, &self.minimum_cost);
    }
}

/// Conservative composition bounds in terms of the reduced node/arc counts and total demand.
/// Both inner run bounds remain separately available and are enforced by their existing owners.
#[must_use]
pub fn bound(nodes: u64, arcs: u64, demand: u64) -> Vec<BoundRow> {
    let size = add(add(nodes, arcs), 1);
    vec![
        ("input_bytes", mul(4096, size)),
        ("preparation_steps", mul(128, size)),
        (
            "max_flow_operations",
            Budget::registered(&flow::bound(nodes, arcs)).max_operations,
        ),
        (
            "min_cost_flow_operations",
            Budget::registered(&min_cost_flow::bound(nodes, arcs, demand)).max_operations,
        ),
        ("certificate_checks", mul(64, size)),
        (OUTPUT_ENTRIES, add(64, mul(8, size))),
    ]
}

fn invalid(reason: &'static str) -> GraphError {
    GraphError::PreconditionFailed(reason.to_owned())
}
fn inconsistent(reason: &'static str) -> GraphError {
    GraphError::Inconsistent(reason.to_owned())
}

fn valid_text(value: &str, maximum: usize, meter: &mut Meter<'_>) -> Result<(), GraphError> {
    meter.tick_n("input_bytes", value.len().min(maximum + 1) as u64)?;
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
    {
        return Err(invalid(
            "capacity identities and units require bounded ASCII alphanumeric/:_.- text",
        ));
    }
    Ok(())
}

fn canonical(
    query: &CapacityQuery,
    meter: &mut Meter<'_>,
) -> Result<(CapacityQuery, u64, ContentDigest), GraphError> {
    meter.checkpoint()?;
    if query.nodes.is_empty()
        || query.nodes.len() > MAX_NODES
        || query.links.len() > MAX_LINKS
        || query.cameras.is_empty()
        || query.cameras.len() > MAX_CAMERAS
        || query.recorders.is_empty()
        || query.recorders.len() > MAX_RECORDERS
        || query.failed_nodes.len() > MAX_NODES
        || query.failed_links.len() > MAX_LINKS
    {
        return Err(GraphError::TooLarge);
    }
    let count = (query.nodes.len()
        + query.links.len()
        + query.cameras.len()
        + query.recorders.len()
        + query.failed_nodes.len()
        + query.failed_links.len()) as u64;
    meter.tick_n("preparation_steps", count * (u64::from(count.ilog2()) + 4))?;
    valid_text(&query.rate_unit, MAX_UNIT_BYTES, meter)?;
    valid_text(&query.cost_unit, MAX_UNIT_BYTES, meter)?;
    for node in query
        .nodes
        .iter()
        .chain(&query.failed_nodes)
        .chain(&query.failed_links)
    {
        valid_text(node, MAX_ID_BYTES, meter)?;
    }
    for link in &query.links {
        for value in [&link.id, &link.from, &link.to] {
            valid_text(value, MAX_ID_BYTES, meter)?;
        }
        if link.capacity == 0 {
            return Err(invalid("declared link capacities must be positive"));
        }
        if link.from == link.to {
            return Err(GraphError::SelfLoop(link.from.clone()));
        }
    }
    let mut requested = 0;
    for camera in &query.cameras {
        valid_text(&camera.sensor, MAX_ID_BYTES, meter)?;
        valid_text(&camera.node, MAX_ID_BYTES, meter)?;
        if camera.requested == 0 {
            return Err(invalid("camera demands must be positive"));
        }
        requested = checked_add(requested, camera.requested, "total camera demand")?;
    }
    for recorder in &query.recorders {
        valid_text(&recorder.id, MAX_ID_BYTES, meter)?;
        valid_text(&recorder.node, MAX_ID_BYTES, meter)?;
        if recorder.capacity == 0 {
            return Err(invalid("recorder capacities must be positive"));
        }
    }
    let mut query = query.clone();
    query.nodes.sort_unstable();
    query.links.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    query
        .cameras
        .sort_unstable_by(|a, b| a.sensor.cmp(&b.sensor));
    query.recorders.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    if query.nodes.windows(2).any(|w| w[0] == w[1])
        || query.links.windows(2).any(|w| w[0].id == w[1].id)
        || query.cameras.windows(2).any(|w| w[0].sensor == w[1].sensor)
        || query.recorders.windows(2).any(|w| w[0].id == w[1].id)
    {
        return Err(invalid(
            "duplicate node, link, camera sensor or recorder identity",
        ));
    }
    let known_node = |id: &str| {
        query
            .nodes
            .binary_search_by(|value| value.as_str().cmp(id))
            .is_ok()
    };
    for id in query
        .links
        .iter()
        .flat_map(|l| [&l.from, &l.to])
        .chain(query.cameras.iter().map(|c| &c.node))
        .chain(query.recorders.iter().map(|r| &r.node))
        .chain(&query.failed_nodes)
    {
        meter.tick_n("preparation_steps", 1)?;
        if !known_node(id) {
            return Err(GraphError::UnknownNode(id.clone()));
        }
    }
    for id in &query.failed_links {
        meter.tick_n("preparation_steps", 1)?;
        if query
            .links
            .binary_search_by(|link| link.id.cmp(id))
            .is_err()
        {
            return Err(invalid(
                "failed link identity is not in the declared topology",
            ));
        }
    }
    let mut e = CanonicalEncoder::new();
    e.text(INPUT_DOMAIN);
    e.text(IDENTITY.implementation_id);
    e.text(IDENTITY.policy_id);
    e.text(&query.rate_unit);
    e.text(&query.cost_unit);
    encode_ids(&mut e, &query.nodes);
    e.u64(query.links.len() as u64);
    for link in &query.links {
        meter.checkpoint()?;
        e.text(&link.id);
        e.text(&link.from);
        e.text(&link.to);
        e.u64(link.capacity);
        e.u64(link.unit_cost);
    }
    e.u64(query.cameras.len() as u64);
    for camera in &query.cameras {
        meter.checkpoint()?;
        e.text(&camera.sensor);
        e.text(&camera.node);
        e.u64(camera.requested);
    }
    e.u64(query.recorders.len() as u64);
    for recorder in &query.recorders {
        meter.checkpoint()?;
        e.text(&recorder.id);
        e.text(&recorder.node);
        e.u64(recorder.capacity);
    }
    for failures in [&query.failed_nodes, &query.failed_links] {
        e.u64(failures.len() as u64);
        for id in failures {
            e.text(id);
        }
    }
    let bytes = e
        .finish_checked()
        .map_err(|_| invalid("capacity input exceeds canonical encoding bounds"))?;
    meter.tick_n("input_bytes", bytes.len() as u64)?;
    Ok((query, requested, ContentDigest::sha256(&bytes)))
}

struct Projection {
    capacities: WeightedGraph,
    costs: WeightedGraph,
    endpoints: BTreeMap<String, Endpoint>,
}

fn project(query: &CapacityQuery, meter: &mut Meter<'_>) -> Result<Projection, GraphError> {
    let n = query.nodes.len() + query.links.len() + query.cameras.len() + query.recorders.len() + 2;
    let m = 2 * (query.links.len() + query.cameras.len() + query.recorders.len());
    // Both strict builders canonicalize; pay a conservative comparison allowance up front.
    meter.tick_n(
        "preparation_steps",
        4 * (n + m) as u64 * (u64::from((n + m).ilog2()) + 2),
    )?;
    let mut capacities = WeightedGraphBuilder::directed(&query.rate_unit);
    let mut costs = WeightedGraphBuilder::directed(&query.cost_unit);
    let mut endpoints = BTreeMap::new();
    for endpoint in [Endpoint::Source, Endpoint::Sink]
        .into_iter()
        .chain(query.nodes.iter().cloned().map(Endpoint::Node))
        .chain(query.links.iter().map(|l| Endpoint::Link(l.id.clone())))
        .chain(
            query
                .cameras
                .iter()
                .map(|c| Endpoint::Camera(c.sensor.clone())),
        )
        .chain(
            query
                .recorders
                .iter()
                .map(|r| Endpoint::Recorder(r.id.clone())),
        )
    {
        meter.checkpoint()?;
        let id = endpoint.projection_id();
        capacities.add_node(&id);
        costs.add_node(&id);
        if endpoints.insert(id, endpoint).is_some() {
            return Err(inconsistent("typed endpoint collision"));
        }
    }
    let mut arc = |from: Endpoint, to: Endpoint, capacity: u64, cost: u64| {
        let (from, to) = (from.projection_id(), to.projection_id());
        capacities.add_arc(&from, &to, capacity);
        costs.add_arc(from, to, cost);
    };
    for camera in &query.cameras {
        meter.checkpoint()?;
        let endpoint = Endpoint::Camera(camera.sensor.clone());
        arc(Endpoint::Source, endpoint.clone(), camera.requested, 0);
        let capacity = if query.failed_nodes.contains(&camera.node) {
            0
        } else {
            camera.requested
        };
        arc(endpoint, Endpoint::Node(camera.node.clone()), capacity, 0);
    }
    for link in &query.links {
        meter.checkpoint()?;
        let failed = query.failed_links.contains(&link.id)
            || query.failed_nodes.contains(&link.from)
            || query.failed_nodes.contains(&link.to);
        let capacity = if failed { 0 } else { link.capacity };
        let endpoint = Endpoint::Link(link.id.clone());
        arc(
            Endpoint::Node(link.from.clone()),
            endpoint.clone(),
            capacity,
            link.unit_cost,
        );
        arc(endpoint, Endpoint::Node(link.to.clone()), capacity, 0);
    }
    for recorder in &query.recorders {
        meter.checkpoint()?;
        let endpoint = Endpoint::Recorder(recorder.id.clone());
        let capacity = if query.failed_nodes.contains(&recorder.node) {
            0
        } else {
            recorder.capacity
        };
        arc(
            Endpoint::Node(recorder.node.clone()),
            endpoint.clone(),
            capacity,
            0,
        );
        arc(endpoint, Endpoint::Sink, recorder.capacity, 0);
    }
    let capacities = capacities.build()?;
    meter.checkpoint()?;
    let costs = costs.build()?;
    meter.checkpoint()?;
    Ok(Projection {
        capacities,
        costs,
        endpoints,
    })
}

fn base_entries(query: &CapacityQuery) -> u64 {
    64 + (query.nodes.len()
        + query.links.len()
        + query.cameras.len()
        + query.recorders.len()
        + query.failed_nodes.len()
        + query.failed_links.len()) as u64
}

fn remaining_output(budget: Budget, used: u64) -> Result<u64, GraphError> {
    budget
        .max_output_entries
        .checked_sub(used)
        .ok_or(GraphError::BudgetExhausted {
            dimension: OUTPUT_ENTRIES,
            limit: budget.max_output_entries,
        })
}

/// Compute a complete conditional routing/cut answer, with no I/O or effects.
pub fn analyze(
    query: &CapacityQuery,
    budget: Budget,
) -> Result<CertifiedRun<CapacityOutput>, GraphError> {
    analyze_with_cancel(query, budget, &|| false)
}

/// Compute the same exact answer with one borrowed cancellation probe across every stage.
/// Any cancellation, numeric overflow or budget failure returns no answer or partial proof.
pub fn analyze_with_cancel(
    query: &CapacityQuery,
    budget: Budget,
    cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<CapacityOutput>, GraphError> {
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, cancelled);
    meter.checkpoint()?;
    if budget.max_operations > MAX_WORK_UNITS || budget.max_output_entries > MAX_OUTPUT_ENTRIES {
        return Err(invalid(
            "capacity allowance exceeds its hard work/output ceiling",
        ));
    }
    let (query, requested, input_digest) = canonical(query, &mut meter)?;
    let base = base_entries(&query);
    remaining_output(budget, base)?;
    let projection = project(&query, &mut meter)?;
    let source = Endpoint::Source.projection_id();
    let sink = Endpoint::Sink.projection_id();
    let maximum_flow = flow::max_flow_min_cut_with_cancel(
        &projection.capacities,
        &source,
        &sink,
        CutMode::Arcs,
        Budget::new(
            budget.max_operations - meter.operations(),
            remaining_output(budget, base)?,
        ),
        cancelled,
    )?;
    meter.tick_n("max_flow_operations", maximum_flow.operations)?;
    let minimum_cost = min_cost_flow::min_cost_flow_with_cancel(
        &projection.costs,
        &projection.capacities,
        &source,
        &sink,
        requested,
        Budget::new(
            budget.max_operations - meter.operations(),
            remaining_output(budget, base + maximum_flow.output_entries)?,
        ),
        cancelled,
    )?;
    meter.tick_n("min_cost_flow_operations", minimum_cost.operations)?;
    let output = assemble(
        query,
        requested,
        &projection,
        maximum_flow,
        minimum_cost,
        budget,
        &mut meter,
    )?;
    let (n, m) = (
        projection.capacities.node_count() as u64,
        projection.capacities.arc_count() as u64,
    );
    meter.path().digest(input_digest);
    meter
        .path()
        .digest(output.maximum_flow.decision_path_digest);
    meter
        .path()
        .digest(output.minimum_cost.decision_path_digest);
    meter.path().u64(output.delivered);
    meter.path().u64(output.total_cost);
    let peak = mul(4096, add(n, m)).saturating_add(
        output
            .maximum_flow
            .peak_working_bytes
            .max(output.minimum_cost.peak_working_bytes),
    );
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n,
            edge_count: m,
            input_digest,
        },
        output,
        &bound(n, m, requested),
        peak,
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    query: CapacityQuery,
    requested: u64,
    projection: &Projection,
    maximum_flow: CertifiedRun<FlowOutput>,
    minimum_cost: CertifiedRun<MinCostFlowOutput>,
    budget: Budget,
    meter: &mut Meter<'_>,
) -> Result<CapacityOutput, GraphError> {
    let FlowOutput::Arcs(maximum) = &maximum_flow.output else {
        return Err(inconsistent("capacity composition requires an arc cut"));
    };
    let minimum = &minimum_cost.output;
    if minimum.requested != requested
        || minimum.delivered != maximum.value
        || minimum.delivered > requested
        || minimum.shortfall != requested - minimum.delivered
    {
        return Err(inconsistent(
            "maximum flow and minimum-cost delivery disagree",
        ));
    }
    let entries = base_entries(&query)
        + maximum_flow.output_entries
        + minimum_cost.output_entries
        + maximum.source_side.len() as u64
        + maximum.cut.len() as u64;
    remaining_output(budget, entries)?;
    let mut flows = BTreeMap::new();
    for (from, to, amount, _) in &minimum.flows {
        meter.tick_n("certificate_checks", 1)?;
        if flows
            .insert((from.as_str(), to.as_str()), *amount)
            .is_some()
        {
            return Err(inconsistent("duplicate certified flow arc"));
        }
    }
    let amount = |from: &Endpoint, to: &Endpoint| {
        flows
            .get(&(from.projection_id().as_str(), to.projection_id().as_str()))
            .copied()
            .unwrap_or(0)
    };
    let mut cameras = Vec::with_capacity(query.cameras.len());
    let mut camera_total = 0;
    for camera in &query.cameras {
        meter.tick_n("certificate_checks", 4)?;
        let port = Endpoint::Camera(camera.sensor.clone());
        let delivered = amount(&Endpoint::Source, &port);
        let attached = amount(&port, &Endpoint::Node(camera.node.clone()));
        let attachment_failed = query.failed_nodes.contains(&camera.node);
        if delivered != attached
            || delivered > camera.requested
            || attachment_failed && delivered != 0
        {
            return Err(inconsistent(
                "camera demand accounting differs from certified flow",
            ));
        }
        camera_total = checked_add(camera_total, delivered, "camera delivery")?;
        cameras.push(CameraDelivery {
            sensor: camera.sensor.clone(),
            node: camera.node.clone(),
            requested: camera.requested,
            delivered,
            shortfall: camera.requested - delivered,
            attachment_failed,
        });
    }
    let mut links = Vec::with_capacity(query.links.len());
    let mut total_cost = 0;
    for link in &query.links {
        meter.tick_n("certificate_checks", 4)?;
        let port = Endpoint::Link(link.id.clone());
        let flow = amount(&Endpoint::Node(link.from.clone()), &port);
        let outgoing = amount(&port, &Endpoint::Node(link.to.clone()));
        let row = LinkFlow {
            id: link.id.clone(),
            from: link.from.clone(),
            to: link.to.clone(),
            capacity: link.capacity,
            unit_cost: link.unit_cost,
            flow,
            failed: query.failed_links.contains(&link.id),
            from_failed: query.failed_nodes.contains(&link.from),
            to_failed: query.failed_nodes.contains(&link.to),
        };
        if flow != outgoing || flow > row.effective_capacity() {
            return Err(inconsistent(
                "physical link accounting differs from certified flow",
            ));
        }
        let cost = flow
            .checked_mul(link.unit_cost)
            .ok_or(GraphError::ArithmeticOverflow("link flow cost"))?;
        total_cost = checked_add(total_cost, cost, "total routed link cost")?;
        links.push(row);
    }
    let mut recorders = Vec::with_capacity(query.recorders.len());
    let mut recorder_total = 0;
    for recorder in &query.recorders {
        meter.tick_n("certificate_checks", 4)?;
        let port = Endpoint::Recorder(recorder.id.clone());
        let received = amount(&port, &Endpoint::Sink);
        let attached = amount(&Endpoint::Node(recorder.node.clone()), &port);
        let attachment_failed = query.failed_nodes.contains(&recorder.node);
        if received != attached
            || received > recorder.capacity
            || attachment_failed && received != 0
        {
            return Err(inconsistent(
                "recorder acceptance differs from certified flow",
            ));
        }
        recorder_total = checked_add(recorder_total, received, "recorder delivery")?;
        recorders.push(RecorderDelivery {
            id: recorder.id.clone(),
            node: recorder.node.clone(),
            capacity: recorder.capacity,
            received,
            attachment_failed,
        });
    }
    if camera_total != minimum.delivered
        || recorder_total != minimum.delivered
        || total_cost != minimum.total_cost
    {
        return Err(inconsistent(
            "camera, recorder and cost totals differ from certified flow",
        ));
    }
    let side: BTreeSet<&str> = maximum.source_side.iter().map(String::as_str).collect();
    let lookup = |id: &str| {
        projection
            .endpoints
            .get(id)
            .cloned()
            .ok_or_else(|| inconsistent("unknown certified endpoint"))
    };
    let mut source_side = Vec::with_capacity(side.len());
    for id in &maximum.source_side {
        meter.tick_n("certificate_checks", 1)?;
        source_side.push(lookup(id)?);
    }
    let mut cut = Vec::with_capacity(maximum.cut.len());
    let mut cut_capacity = 0;
    for (from, to, capacity) in &maximum.cut {
        meter.tick_n("certificate_checks", 2)?;
        let flow = flows
            .get(&(from.as_str(), to.as_str()))
            .copied()
            .unwrap_or(0);
        if !side.contains(from.as_str()) || side.contains(to.as_str()) || flow != *capacity {
            return Err(inconsistent(
                "minimum-cost flow does not saturate the maximum-flow cut",
            ));
        }
        cut_capacity = checked_add(cut_capacity, *capacity, "composed cut capacity")?;
        cut.push(CutArc {
            from: lookup(from)?,
            to: lookup(to)?,
            capacity: *capacity,
            flow,
        });
    }
    for arc in projection.capacities.arcs() {
        meter.tick_n("certificate_checks", 1)?;
        let from = projection.capacities.id(arc.tail);
        let to = projection.capacities.id(arc.head);
        if !side.contains(from)
            && side.contains(to)
            && flows.get(&(from, to)).is_some_and(|value| *value != 0)
        {
            return Err(inconsistent(
                "minimum-cost flow crosses the minimum cut backwards",
            ));
        }
    }
    if cut_capacity != minimum.delivered {
        return Err(inconsistent("cut capacity differs from final delivery"));
    }
    Ok(CapacityOutput {
        status: if minimum.shortfall == 0 {
            CapacityStatus::FullyRouted
        } else {
            CapacityStatus::CapacityShortfall
        },
        rate_unit: query.rate_unit,
        cost_unit: query.cost_unit,
        nodes: query.nodes,
        requested,
        delivered: minimum.delivered,
        shortfall: minimum.shortfall,
        total_cost,
        cameras,
        links,
        recorders,
        failed_nodes: query.failed_nodes.into_iter().collect(),
        failed_links: query.failed_links.into_iter().collect(),
        source_side,
        cut,
        maximum_flow,
        minimum_cost,
    })
}
