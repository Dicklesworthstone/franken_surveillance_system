#![forbid(unsafe_code)]
//! `AOP-005 query --target graph` — executes registered Certified Graph Atlas projections
//! (`SensorCoverageGraph`, `EvidenceClaimGraph`, `DeviceFailureGraph`, `PlanObligationGraph`)
//! via `fss-graph-algorithms` and returns a verified [`fss_core::GraphAlgorithmWitness`].
//!
//! Semantic plane: `"cognition"` (pure derived graph analysis; grants no effect authority).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_core::{
    AgentView, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest, ExecutionBoundary,
    GraphAlgorithmWitness, KnowledgeState, PrincipalId, ResponseSafeRetry, SessionId,
};
use fss_graph_algorithms::bridges::{GraphBudget, analyse_bridges};
use fss_graph_algorithms::certified::{Budget, CertifiedRun};
use fss_graph_algorithms::community::{self, CommunityOutput};
use fss_graph_algorithms::evidence;
use fss_graph_algorithms::graph::{GraphBuilder, GraphError, UndirectedGraph};
use fss_graph_algorithms::scc::{self, SccOutput};
use fss_graph_algorithms::weighted::{WeightedGraph, WeightedGraphBuilder};
use fss_reference::agent_orient::{DeploymentSnapshot, OrientLimits, read_deployment_cancellable};
use fss_reference::coverage_graph::{coverage_single_points, weighted_historical_coverage};
use fss_reference::evidence_claim_graph::retained_evidence_projection;

use super::{
    CAP_AGENT_QUERY, OpsEnvelopeParams, OpsError, ensure_deployment_root, render_ok_envelope,
    render_refusal_envelope, require_capabilities, resolve_effective_capabilities,
};
use crate::agent_json::evidence_anchor;
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string, strings};

/// Registered payload schema for `query --target graph`.
pub const GRAPH_PAYLOAD_SCHEMA: &str = "fss.agent_ops_graph.v1";
/// Canonical digest domain for `query --target graph`.
pub const GRAPH_DIGEST_DOMAIN: &str = "fss.ops_targets.graph.v1";

/// Registered Certified Graph Atlas projection families exposed over `query --target graph`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphProjectionKind {
    /// Retained sensor-to-zone coverage witness topology.
    SensorCoverageGraph,
    /// Retained event-revision evidence support/contradiction graph.
    EvidenceClaimGraph,
    /// Shared failure-domain coupling across sensors, zones, and events.
    DeviceFailureGraph,
    /// Active effect operations and durable obligation dependencies.
    PlanObligationGraph,
}

impl GraphProjectionKind {
    /// Parses a canonical projection kind string.
    pub fn parse(raw: &str) -> Result<Self, OpsError> {
        match raw {
            "SensorCoverageGraph" => Ok(Self::SensorCoverageGraph),
            "EvidenceClaimGraph" => Ok(Self::EvidenceClaimGraph),
            "DeviceFailureGraph" => Ok(Self::DeviceFailureGraph),
            "PlanObligationGraph" => Ok(Self::PlanObligationGraph),
            other => Err(OpsError::InvalidRequest(format!(
                "unsupported graph projection `{other}`; expected SensorCoverageGraph, EvidenceClaimGraph, DeviceFailureGraph, or PlanObligationGraph"
            ))),
        }
    }

    /// Stable canonical projection name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SensorCoverageGraph => "SensorCoverageGraph",
            Self::EvidenceClaimGraph => "EvidenceClaimGraph",
            Self::DeviceFailureGraph => "DeviceFailureGraph",
            Self::PlanObligationGraph => "PlanObligationGraph",
        }
    }
}

/// Registered Certified Graph Atlas algorithms exposed over `query --target graph`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphAlgorithmKind {
    /// `ALG-BRIDGE-001` — articulation points, bridges, and single-point separation analysis.
    Bridges,
    /// `ALG-SCC-001` — Tarjan strongly connected components and condensation DAG.
    Scc,
    /// `ALG-COMM-001` — deterministic modularity community / failure-domain clustering.
    Community,
}

impl GraphAlgorithmKind {
    /// Parses a registered algorithm identity string.
    pub fn parse(raw: &str) -> Result<Self, OpsError> {
        match raw {
            "ALG-BRIDGE-001" => Ok(Self::Bridges),
            "ALG-SCC-001" => Ok(Self::Scc),
            "ALG-COMM-001" => Ok(Self::Community),
            other => Err(OpsError::InvalidRequest(format!(
                "unsupported graph algorithm `{other}`; expected ALG-BRIDGE-001, ALG-SCC-001, or ALG-COMM-001"
            ))),
        }
    }

    /// Stable registered algorithm identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bridges => "ALG-BRIDGE-001",
            Self::Scc => "ALG-SCC-001",
            Self::Community => "ALG-COMM-001",
        }
    }
}

/// Request parameters for certified graph analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphQueryRequest {
    /// Existing deployment root directory.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Optional owning session identity for capability resolution.
    pub session_id: Option<SessionId>,
    /// Selected registered graph projection.
    pub projection: GraphProjectionKind,
    /// Selected registered Certified Graph Atlas algorithm.
    pub algorithm: GraphAlgorithmKind,
    /// Optional root node identity for `ALG-BRIDGE-001` separation analysis.
    pub root_node: Option<String>,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Executes `query --target graph` and renders a registered `AgentResponseEnvelope`.
pub(crate) fn execute(
    req: &GraphQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "query",
            &req.principal,
            req.session_id.as_ref(),
            GRAPH_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

fn run<'a>(
    req: &'a GraphQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<OpsEnvelopeParams<'a>, OpsError> {
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let effective = resolve_effective_capabilities(
        &req.root,
        &req.principal,
        req.session_id.as_ref(),
        &req.granted_capabilities,
    )?;
    require_capabilities(&effective, &[CAP_AGENT_QUERY], "query --target graph")?;
    ensure_deployment_root(&req.root)?;
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;
    if cancelled() {
        return Err(OpsError::Cancelled);
    }

    let (projection_id, witness, analysis_json) = match (req.projection, req.algorithm) {
        (GraphProjectionKind::SensorCoverageGraph, GraphAlgorithmKind::Bridges)
            if req.root_node.is_none() =>
        {
            let report = coverage_single_points(&snapshot).map_err(|err| {
                OpsError::OperationFailed(format!("coverage graph failed: {err}"))
            })?;
            let analysis = render_coverage_single_points(&report);
            (report.projection_id, report.witness, analysis)
        }
        (proj, GraphAlgorithmKind::Bridges) => {
            let (proj_id, weighted) = compile_weighted_projection(&snapshot, proj)?;
            let undirected = to_undirected(&weighted).map_err(|err| {
                OpsError::OperationFailed(format!("undirected projection failed: {err}"))
            })?;
            let root = req.root_node.as_deref().or_else(|| {
                if undirected.index_of("plane:site").is_some() {
                    Some("plane:site")
                } else if undirected.index_of("root:control").is_some() {
                    Some("root:control")
                } else {
                    (0..undirected.node_count() as u32)
                        .next()
                        .map(|i| undirected.id(i))
                }
            });
            let budget = GraphBudget::registered(&undirected);
            let analysis = analyse_bridges(&undirected, root, budget).map_err(|err| {
                OpsError::OperationFailed(format!("ALG-BRIDGE-001 failed: {err}"))
            })?;
            let witness = analysis
                .witness(&proj_id, snapshot.anchor.clone())
                .map_err(|err| OpsError::OperationFailed(format!("witness failed: {err}")))?;
            let body = render_bridge_output(&analysis.output);
            (proj_id, witness, body)
        }
        (proj, GraphAlgorithmKind::Scc) => {
            let (proj_id, weighted) = compile_weighted_projection(&snapshot, proj)?;
            let bound = scc::bound(weighted.node_count() as u64, weighted.arc_count() as u64);
            let run = scc::strongly_connected_components(&weighted, Budget::registered(&bound))
                .map_err(|err| OpsError::OperationFailed(format!("ALG-SCC-001 failed: {err}")))?;
            let witness = build_certified_witness(&proj_id, &snapshot, &run)?;
            let body = render_scc_output(&run.output);
            (proj_id, witness, body)
        }
        (proj, GraphAlgorithmKind::Community) => {
            let (proj_id, weighted) = compile_weighted_projection(&snapshot, proj)?;
            let max_passes = 8_u32;
            let bound = community::bound(
                weighted.node_count() as u64,
                weighted.arc_count() as u64,
                max_passes,
            );
            let run = community::community_detection(
                &weighted,
                max_passes,
                Budget::registered(&bound),
            )
            .map_err(|err| OpsError::OperationFailed(format!("ALG-COMM-001 failed: {err}")))?;
            let witness = build_certified_witness(&proj_id, &snapshot, &run)?;
            let body = render_community_output(&run.output);
            (proj_id, witness, body)
        }
    };

    let witness_digest = witness.digest();
    let mut fp_enc = CanonicalEncoder::new();
    fp_enc.text(GRAPH_DIGEST_DOMAIN);
    snapshot.anchor.encode_canonical(&mut fp_enc);
    fp_enc.text(req.projection.as_str());
    fp_enc.text(req.algorithm.as_str());
    fp_enc.digest(witness_digest);
    let fingerprint = ContentDigest::sha256(&fp_enc.finish());

    let payload_json = object(&[
        ("schema", string(GRAPH_PAYLOAD_SCHEMA)),
        ("projectionKind", string(req.projection.as_str())),
        ("projectionId", string(&projection_id)),
        ("algorithmId", string(req.algorithm.as_str())),
        ("witnessDigest", string(&witness_digest.to_text())),
        ("witness", render_witness_json(&witness)),
        ("analysis", analysis_json),
        ("effectsAuthorized", "false".to_owned()),
    ]);

    Ok(OpsEnvelopeParams {
        operation: "query",
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: snapshot.anchor.clone(),
        view: AgentView::Case,
        capabilities: vec![CAP_AGENT_QUERY.to_owned()],
        privacy_purpose: "read-only Certified Graph Atlas structural analysis with witness",
        allowed_domains: &["certified-graph-projections", "graph-algorithm-witnesses"],
        redacted_domains: &["media-payloads", "raw-credentials"],
        payload_schema: GRAPH_PAYLOAD_SCHEMA,
        payload_json,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Bounded,
        warnings: vec![
            "Graph analysis is derived cognition over committed history; structural resilience does not prove live sensor health or physical absence.".to_owned(),
        ],
        proof_pointers: vec![
            snapshot.anchor.state_root.to_text(),
            witness.input_digest().to_text(),
            witness.output_digest().to_text(),
            witness_digest.to_text(),
        ],
        decision_fingerprint: fingerprint,
        idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest,
        recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![format!(
                "Compiled {} at commit {} and executed {} with verified GraphAlgorithmWitness.",
                req.projection.as_str(),
                snapshot.anchor.commit_sequence,
                req.algorithm.as_str(),
            )],
            not_started: vec![
                "No deployment state was mutated and no effect authority was granted.".to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Every complexity bound and CGSE tie-break policy was verified before emitting output."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn compile_weighted_projection(
    snapshot: &DeploymentSnapshot,
    kind: GraphProjectionKind,
) -> Result<(String, WeightedGraph), OpsError> {
    let base_id = format!(
        "{}@commit:{}",
        kind.as_str(),
        snapshot.anchor.commit_sequence
    );
    match kind {
        GraphProjectionKind::SensorCoverageGraph => {
            let graph =
                weighted_historical_coverage(snapshot, Default::default()).map_err(|err| {
                    OpsError::OperationFailed(format!("coverage projection failed: {err}"))
                })?;
            Ok((format!("{base_id}:retained-witnesses:v1"), graph))
        }
        GraphProjectionKind::EvidenceClaimGraph => {
            let proj = retained_evidence_projection(snapshot.events.iter(), Default::default())
                .map_err(|err| {
                    OpsError::OperationFailed(format!("evidence projection failed: {err}"))
                })?;
            Ok((evidence::PROJECTION_ID.to_owned(), proj.into_graph()))
        }
        GraphProjectionKind::DeviceFailureGraph => {
            let mut nodes = BTreeSet::new();
            let mut edges: BTreeMap<(String, String), u64> = BTreeMap::new();
            nodes.insert("plane:site".to_owned());
            for cov in &snapshot.coverage {
                let sensor = cov.record.sensor_id.as_str().to_owned();
                nodes.insert(sensor.clone());
                *edges
                    .entry(("plane:site".to_owned(), sensor.clone()))
                    .or_default() += 1;
                for zone in &cov.record.zones {
                    let z = zone.scope.as_str().to_owned();
                    nodes.insert(z.clone());
                    if cov.calibration_invalidation.is_none() && !zone.witnesses.is_empty() {
                        *edges.entry((sensor.clone(), z)).or_default() +=
                            zone.witnesses.len() as u64;
                    }
                }
            }
            for event in &snapshot.events {
                let ev_node = event.event.event_id.as_str().to_owned();
                for domain in event.failure_domains() {
                    let dom = format!("domain:{domain}");
                    nodes.insert(dom.clone());
                    nodes.insert(ev_node.clone());
                    *edges
                        .entry(("plane:site".to_owned(), dom.clone()))
                        .or_default() += 1;
                    *edges.entry((dom, ev_node.clone())).or_default() += 1;
                }
            }
            let graph = build_directed_weighted("failure-coupling:v1", nodes, edges)
                .map_err(|err| OpsError::OperationFailed(format!("failure graph failed: {err}")))?;
            Ok((format!("{base_id}:retained-witnesses:v1"), graph))
        }
        GraphProjectionKind::PlanObligationGraph => {
            let mut nodes = BTreeSet::new();
            let mut edges: BTreeMap<(String, String), u64> = BTreeMap::new();
            nodes.insert("root:control".to_owned());
            for op in &snapshot.operations {
                let op_node = format!("op:{}", op.intent.operation_id);
                nodes.insert(op_node.clone());
                *edges
                    .entry(("root:control".to_owned(), op_node))
                    .or_default() += 1;
            }
            for ob in &snapshot.obligations {
                let ob_node = ob.obligation_id.as_str().to_owned();
                nodes.insert(ob_node.clone());
                let parent = format!("op:{}", ob.operation_id);
                if nodes.contains(&parent) {
                    *edges.entry((parent, ob_node)).or_default() += 1;
                } else {
                    *edges
                        .entry(("root:control".to_owned(), ob_node))
                        .or_default() += 1;
                }
            }
            let graph = build_directed_weighted("steps", nodes, edges).map_err(|err| {
                OpsError::OperationFailed(format!("obligation graph failed: {err}"))
            })?;
            Ok((base_id, graph))
        }
    }
}

fn build_directed_weighted(
    unit: &str,
    nodes: BTreeSet<String>,
    edges: BTreeMap<(String, String), u64>,
) -> Result<WeightedGraph, GraphError> {
    let mut builder = WeightedGraphBuilder::directed(unit);
    for node in nodes {
        builder.add_weighted_node(node, 1);
    }
    for ((from, to), weight) in edges {
        if from != to {
            builder.add_arc(from, to, weight.max(1));
        }
    }
    builder.build()
}

fn to_undirected(weighted: &WeightedGraph) -> Result<UndirectedGraph, GraphError> {
    let mut builder = GraphBuilder::new();
    for idx in 0..weighted.node_count() as u32 {
        builder.add_node(weighted.id(idx).to_owned());
    }
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for arc in weighted.arcs() {
        let u = weighted.id(arc.tail).to_owned();
        let v = weighted.id(arc.head).to_owned();
        if u == v {
            continue;
        }
        let pair = if u < v { (u, v) } else { (v, u) };
        if seen.insert(pair.clone()) {
            builder.add_edge(pair.0, pair.1);
        }
    }
    builder.build()
}

fn build_certified_witness<T>(
    projection_id: &str,
    snapshot: &DeploymentSnapshot,
    run: &CertifiedRun<T>,
) -> Result<GraphAlgorithmWitness, OpsError> {
    run.witness(projection_id, snapshot.anchor.clone())
        .map_err(|err| OpsError::OperationFailed(format!("witness validation failed: {err:?}")))
}

fn render_witness_json(witness: &GraphAlgorithmWitness) -> String {
    let map_json = |entries: &BTreeMap<String, u64>| -> String {
        let fields: Vec<(&str, String)> = entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_string()))
            .collect();
        object(&fields)
    };
    object(&[
        ("schema", string(GraphAlgorithmWitness::SCHEMA)),
        ("algorithmId", string(witness.algorithm_id())),
        ("implementationId", string(witness.implementation_id())),
        ("projectionId", string(witness.projection_id())),
        ("anchor", evidence_anchor(witness.anchor())),
        ("nodeCount", witness.node_count().to_string()),
        ("edgeCount", witness.edge_count().to_string()),
        ("inputDigest", string(&witness.input_digest().to_text())),
        ("policyId", string(witness.policy_id())),
        (
            "dominantOperationCounts",
            map_json(witness.dominant_operation_counts()),
        ),
        ("peakWorkingBytes", witness.peak_working_bytes().to_string()),
        ("budgetConsumed", map_json(witness.budget_consumed())),
        ("exactness", string(witness.exactness())),
        ("stopReason", string(witness.stop_reason())),
        (
            "decisionPathDigest",
            string(&witness.decision_path_digest().to_text()),
        ),
        ("outputDigest", string(&witness.output_digest().to_text())),
    ])
}

fn render_coverage_single_points(
    report: &fss_reference::coverage_graph::CoverageGraphReport,
) -> String {
    let single_points: Vec<String> = report
        .answer
        .sensors
        .iter()
        .filter(|s| !s.sole_observer_of.is_empty())
        .map(|sp| {
            object(&[
                ("sensorId", string(&sp.sensor_id)),
                ("zonesLost", strings(&sp.sole_observer_of)),
                ("uplinkIsBridge", sp.uplink_is_bridge.to_string()),
            ])
        })
        .collect();
    let zones: Vec<String> = report
        .answer
        .zones
        .iter()
        .map(|z| {
            object(&[
                ("zoneScope", string(&z.scope)),
                ("state", string(z.state.as_str())),
                ("coveringSensors", strings(&z.observers)),
                (
                    "singlePointsOfFailure",
                    strings(&z.single_points_of_failure),
                ),
                ("witnessCount", z.witnesses.to_string()),
            ])
        })
        .collect();
    object(&[
        ("kind", string("coverage_single_points")),
        ("recordsRead", report.records.to_string()),
        ("singlePointSensors", array(&single_points)),
        ("zones", array(&zones)),
        (
            "bridgeOutput",
            render_bridge_output(&report.answer.analysis.output),
        ),
    ])
}

fn render_bridge_output(output: &fss_graph_algorithms::bridges::BridgeOutput) -> String {
    let bridges: Vec<String> = output
        .bridges
        .iter()
        .map(|(a, b)| array(&[string(a), string(b)]))
        .collect();
    let vertex_seps: Vec<String> = output
        .vertex_separations
        .iter()
        .map(|s| {
            object(&[
                ("node", string(&s.node)),
                ("separated", strings(&s.separated)),
            ])
        })
        .collect();
    let bridge_seps: Vec<String> = output
        .bridge_separations
        .iter()
        .map(|s| {
            object(&[
                ("edge", array(&[string(&s.edge.0), string(&s.edge.1)])),
                ("separated", strings(&s.separated)),
            ])
        })
        .collect();
    object(&[
        (
            "root",
            output
                .root
                .as_deref()
                .map_or_else(|| "null".to_owned(), string),
        ),
        ("articulationPoints", strings(&output.articulation_points)),
        ("bridges", array(&bridges)),
        (
            "unreachableFromRoot",
            strings(&output.unreachable_from_root),
        ),
        ("vertexSeparations", array(&vertex_seps)),
        ("bridgeSeparations", array(&bridge_seps)),
    ])
}

fn render_scc_output(output: &SccOutput) -> String {
    let comps: Vec<String> = output
        .components
        .iter()
        .map(|c| {
            object(&[
                ("label", c.label.to_string()),
                ("cyclic", c.cyclic.to_string()),
                ("members", strings(&c.members)),
            ])
        })
        .collect();
    let arcs: Vec<String> = output
        .condensation_arcs
        .iter()
        .map(|(from, to)| array(&[from.to_string(), to.to_string()]))
        .collect();
    object(&[
        ("kind", string("strongly_connected_components")),
        ("componentCount", output.components.len().to_string()),
        ("components", array(&comps)),
        ("condensationArcs", array(&arcs)),
    ])
}

fn render_community_output(output: &CommunityOutput) -> String {
    let comms: Vec<String> = output
        .communities
        .iter()
        .map(|c| {
            object(&[
                ("communityId", c.community_id.to_string()),
                ("members", strings(&c.members)),
            ])
        })
        .collect();
    object(&[
        ("kind", string("community_clusters")),
        ("communityCount", output.communities.len().to_string()),
        ("modularityPpb", output.modularity_ppb.to_string()),
        ("passes", output.passes.to_string()),
        ("communities", array(&comms)),
    ])
}
