#![forbid(unsafe_code)]
//! `fss-event graph analyze` — certified graph-atlas analysis over retained `--root` deployments.
//!
//! Compiles canonical, anchor-pinned projections (`SensorCoverageGraph`, `EvidenceClaimGraph`,
//! `DeviceFailureGraph`, `ArchiveObjectGraph`, `PlanObligationGraph`) from a committed
//! `ReferenceDeployment` (`read_deployment`), executes a registered algorithm from the 27/27
//! Certified Graph Atlas (`ALG-CENTRAL-001`, `ALG-COMM-001`, `ALG-SPECTRAL-001`, `ALG-SCC-001`,
//! `ALG-TOPO-001`, `ALG-PPR-001`, `ALG-HITS-001`, `ALG-MST-001`, `ALG-STEINER-001`,
//! `ALG-ZSET-001`), checks the complexity and output witness against the registered bound, and
//! emits a canonical `fss.deployment_graph_analysis.v1` JSON document.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::json_input::{Value, parse};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::GraphAlgorithmWitness;
use fss_graph_algorithms::centrality::{self, CentralityOutput};
use fss_graph_algorithms::certified::{
    self, AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun,
};
use fss_graph_algorithms::community::{self, CommunityOutput};
use fss_graph_algorithms::evidence::{self, EvidenceProjectionError};
use fss_graph_algorithms::graph::GraphError;
use fss_graph_algorithms::hits::{self, HitsConfig, HitsOutput};
use fss_graph_algorithms::ppr::{self, PprConfig, PprOutput};
use fss_graph_algorithms::scc::{self, SccOutput};
use fss_graph_algorithms::spanning::{self, SpanningForestOutput};
use fss_graph_algorithms::spectral::{self, SpectralConfig, SpectralOutput};
use fss_graph_algorithms::steiner::{self, SteinerTreeOutput};
use fss_graph_algorithms::topo::{self, TopoOutput};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};
use fss_graph_algorithms::zset::{
    self, ZSet, ZSetDeltaBatch, ZSetGraphState, ZSetMaintenanceOutput,
};
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::agent_orient::{DeploymentSnapshot, OrientLimits, read_deployment};
use fss_reference::coverage_graph::weighted_historical_coverage;
use fss_reference::evidence_claim_graph::retained_evidence_projection;

/// Digest domain for `fss-event graph analyze` (`SCHEMA-DOMAIN-DEPLOYMENT-GRAPH-ANALYSIS-001`).
const FORMAT_DOMAIN: &str = "fss.deployment_graph_analysis.v1";

const HELP: &str = "fss-event graph analyze --root DIR --site SITE\n\
  --projection <SensorCoverageGraph|EvidenceClaimGraph|DeviceFailureGraph|ArchiveObjectGraph|PlanObligationGraph>\n\
  --algorithm <ALG-CENTRAL-001|ALG-SPECTRAL-001|ALG-SCC-001|ALG-TOPO-001|ALG-PPR-001|ALG-HITS-001|ALG-MST-001|ALG-STEINER-001|ALG-ZSET-001>\n\
  [--seed NODE[:WEIGHT]]... (PPR) [--terminal NODE]... (Steiner)\n\
  Only registry-listed algorithm/projection pairs with the required orientation can run.\n\
  Coverage nodes use plane/<site>, sensor/<sensor>, and zone/<scope>.\n\
  Compiles the requested projection at the deployment's committed authority anchor,\n\
  executes the registered Certified Graph Atlas algorithm under its registered complexity bound,\n\
  verifies the GraphAlgorithmWitness, and outputs a canonical JSON report.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionKind {
    SensorCoverageGraph,
    EvidenceClaimGraph,
    DeviceFailureGraph,
    ArchiveObjectGraph,
    PlanObligationGraph,
}

impl ProjectionKind {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "SensorCoverageGraph" => Ok(Self::SensorCoverageGraph),
            "EvidenceClaimGraph" => Ok(Self::EvidenceClaimGraph),
            "DeviceFailureGraph" => Ok(Self::DeviceFailureGraph),
            "ArchiveObjectGraph" => Ok(Self::ArchiveObjectGraph),
            "PlanObligationGraph" => Ok(Self::PlanObligationGraph),
            other => Err(format!(
                "unsupported `--projection` `{other}`; expected one of `SensorCoverageGraph`, `EvidenceClaimGraph`, `DeviceFailureGraph`, `ArchiveObjectGraph`, or `PlanObligationGraph`"
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::SensorCoverageGraph => "SensorCoverageGraph",
            Self::EvidenceClaimGraph => "EvidenceClaimGraph",
            Self::DeviceFailureGraph => "DeviceFailureGraph",
            Self::ArchiveObjectGraph => "ArchiveObjectGraph",
            Self::PlanObligationGraph => "PlanObligationGraph",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AlgorithmKind {
    Centrality,
    Community,
    Spectral,
    Scc,
    Topo,
    Ppr,
    Hits,
    Mst,
    Steiner,
    ZSet,
}

impl AlgorithmKind {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "ALG-CENTRAL-001" => Ok(Self::Centrality),
            "ALG-COMM-001" => Ok(Self::Community),
            "ALG-SPECTRAL-001" => Ok(Self::Spectral),
            "ALG-SCC-001" => Ok(Self::Scc),
            "ALG-TOPO-001" => Ok(Self::Topo),
            "ALG-PPR-001" => Ok(Self::Ppr),
            "ALG-HITS-001" => Ok(Self::Hits),
            "ALG-MST-001" => Ok(Self::Mst),
            "ALG-STEINER-001" => Ok(Self::Steiner),
            "ALG-ZSET-001" => Ok(Self::ZSet),
            other => Err(format!(
                "unsupported `--algorithm` `{other}`; expected one of `ALG-CENTRAL-001`, `ALG-COMM-001`, `ALG-SPECTRAL-001`, `ALG-SCC-001`, `ALG-TOPO-001`, `ALG-PPR-001`, `ALG-HITS-001`, `ALG-MST-001`, `ALG-STEINER-001`, or `ALG-ZSET-001`"
            )),
        }
    }
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [command, flag] if command.to_str() == Some("analyze") && matches!(flag.to_str(), Some("--help" | "-h")))
    {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }

    let mut str_args = Vec::with_capacity(args.len());
    for arg in args {
        let Some(text) = arg.to_str() else {
            return usage_error("non-UTF-8 CLI argument");
        };
        str_args.push(text);
    }

    let mut root: Option<PathBuf> = None;
    let mut site: Option<String> = None;
    let mut projection: Option<ProjectionKind> = None;
    let mut algorithm = None;
    let mut seeds = Vec::new();
    let mut terminals: Vec<String> = Vec::new();
    let mut idx = 1;
    while idx < str_args.len() {
        let flag = str_args[idx];
        match flag {
            "--root" => {
                if root.is_some() {
                    return usage_error("duplicate option `--root`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--root`");
                };
                if val.is_empty() {
                    return usage_error("empty value for `--root`");
                }
                root = Some(PathBuf::from(val));
                idx += 2;
            }
            "--site" => {
                if site.is_some() {
                    return usage_error("duplicate option `--site`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--site`");
                };
                if val.trim().is_empty() {
                    return usage_error("empty value for `--site`");
                }
                site = Some(val.to_owned());
                idx += 2;
            }
            "--projection" => {
                if projection.is_some() {
                    return usage_error("duplicate option `--projection`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--projection`");
                };
                match ProjectionKind::parse(val) {
                    Ok(parsed) => projection = Some(parsed),
                    Err(msg) => return usage_error(&msg),
                }
                idx += 2;
            }
            "--algorithm" => {
                if algorithm.is_some() {
                    return usage_error("duplicate option `--algorithm`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--algorithm`");
                };
                match AlgorithmKind::parse(val) {
                    Ok(parsed) => algorithm = Some((val, parsed)),
                    Err(msg) => return usage_error(&msg),
                }
                idx += 2;
            }
            "--seed" => {
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--seed`");
                };
                seeds.push(val);
                idx += 2;
            }
            "--terminal" => {
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--terminal`");
                };
                if val.trim().is_empty() {
                    return usage_error("empty value for `--terminal`");
                }
                terminals.push(val.to_owned());
                idx += 2;
            }
            other => {
                return usage_error(&format!(
                    "unknown `fss-event graph analyze` argument `{other}`"
                ));
            }
        }
    }

    let Some(root) = root else {
        return usage_error("missing required `--root <DIR>`");
    };
    let Some(site) = site else {
        return usage_error("missing required `--site <SITE>`");
    };
    let Some(projection_kind) = projection else {
        return usage_error("missing required `--projection <PROJECTION>`");
    };
    let Some((algorithm_id, algorithm_kind)) = algorithm else {
        return usage_error("missing required `--algorithm <ALG-...>`");
    };

    if let Err(error) = admit_projection(algorithm_id, projection_kind) {
        return fail_graph(&error);
    }
    if !seeds.is_empty() && algorithm_kind != AlgorithmKind::Ppr {
        return usage_error("--seed applies only to ALG-PPR-001");
    }
    if !terminals.is_empty() && algorithm_kind != AlgorithmKind::Steiner {
        return usage_error("--terminal applies only to ALG-STEINER-001");
    }
    let snapshot = match read_deployment(&root, &OrientLimits::default()) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return fail_message(
                ERR_CLI_RUNTIME_FAILURE,
                &format!("deployment load failed: {error}"),
            );
        }
    };
    if snapshot.site_lineage != site {
        return fail_message(
            "ERR-GRAPH-PRECONDITION-001",
            &format!(
                "deployment site lineage `{}` does not match requested `--site {site}`",
                snapshot.site_lineage
            ),
        );
    }

    let (projection_id, graph) = match compile_projection(projection_kind, &snapshot) {
        Ok(compiled) => compiled,
        Err(error) => return fail_message(error.stable_id(), &error.to_string()),
    };

    let mut resolved_seeds = Vec::with_capacity(seeds.len());
    for raw in seeds {
        // A canonical support-incidence node itself ends in a numeric edge index.
        if graph.index_of(raw).is_some() {
            resolved_seeds.push((raw.to_owned(), ppr::SCALE_PPB));
        } else {
            match parse_seed(raw) {
                Ok(seed) => resolved_seeds.push(seed),
                Err(message) => return usage_error(&message),
            }
        }
    }

    match execute_and_render(
        &site,
        projection_kind,
        &projection_id,
        &snapshot,
        &graph,
        algorithm_kind,
        &resolved_seeds,
        &terminals,
    ) {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => fail_graph(&error),
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("{ERR_CLI_MALFORMED_VALUE}: {message}; use fss-event graph analyze --help");
    ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
}

fn fail_message(error_id: &str, message: &str) -> ExitCode {
    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error_id}: {message}");
    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
}

fn fail_graph(error: &GraphError) -> ExitCode {
    fail_message(error.stable_id(), &error.to_string())
}

fn parse_seed(raw: &str) -> Result<(String, u64), String> {
    if let Some((node, weight_raw)) = raw.rsplit_once(':')
        && !weight_raw.is_empty()
        && weight_raw.bytes().all(|b| b.is_ascii_digit())
        && !node.trim().is_empty()
    {
        let weight: u64 = weight_raw
            .parse()
            .map_err(|_| format!("invalid `--seed` weight `{weight_raw}`"))?;
        if weight == 0 {
            return Err("`--seed` weight must be > 0".to_owned());
        }
        return Ok((node.to_owned(), weight));
    }
    if raw.trim().is_empty() {
        return Err("empty `--seed`".to_owned());
    }
    Ok((raw.to_owned(), ppr::SCALE_PPB))
}

fn admit_projection(algorithm: &str, kind: ProjectionKind) -> Result<(), GraphError> {
    let registry = parse(include_str!(
        "../../../../../architecture/graph_algorithms.json"
    ))
    .map_err(|error| GraphError::Inconsistent(error.to_string()))?;
    let allowed = registry
        .object()
        .and_then(|root| root.get("algorithms"))
        .and_then(Value::array)
        .and_then(|rows| {
            rows.iter()
                .filter_map(Value::object)
                .find(|row| row.get("id").and_then(Value::text) == Some(algorithm))
        })
        .and_then(|row| row.get("projection"))
        .and_then(Value::array)
        .ok_or_else(|| {
            GraphError::Inconsistent(format!("missing projection registry row for {algorithm}"))
        })?;
    if allowed
        .iter()
        .any(|entry| entry.text() == Some(kind.as_str()))
    {
        Ok(())
    } else {
        let registered: Vec<_> = allowed.iter().filter_map(Value::text).collect();
        Err(GraphError::PreconditionFailed(format!(
            "{algorithm} is not registered for {}. Registered projections: {}",
            kind.as_str(), registered.join(", ")
        )))
    }
}

fn compile_projection(
    kind: ProjectionKind,
    snapshot: &DeploymentSnapshot,
) -> Result<(String, WeightedGraph), EvidenceProjectionError> {
    let projection_id = format!(
        "projection:{}:{}:{}",
        kind.as_str(),
        snapshot.site_lineage,
        snapshot.anchor.commit_sequence
    );

    let mut nodes = BTreeSet::new();
    let mut edge_weights: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut add_arc = |from: &str, to: &str, weight: u64| -> Result<(), GraphError> {
        if from != to {
            let entry = edge_weights
                .entry((from.to_owned(), to.to_owned()))
                .or_default();
            *entry = entry
                .checked_add(weight)
                .ok_or(GraphError::ArithmeticOverflow("edge weight"))?;
        }
        Ok(())
    };

    let unit = match kind {
        ProjectionKind::SensorCoverageGraph => {
            let graph = weighted_historical_coverage(snapshot, Default::default())?;
            return Ok((format!("{projection_id}:retained-witnesses:v1"), graph));
        }
        ProjectionKind::EvidenceClaimGraph => {
            let projection =
                retained_evidence_projection(snapshot.events.iter(), Default::default())?;
            return Ok((evidence::PROJECTION_ID.to_owned(), projection.into_graph()));
        }
        ProjectionKind::DeviceFailureGraph => {
            nodes.insert("plane:site".to_owned());
            for cov in &snapshot.coverage {
                let sensor = cov.record.sensor_id.as_str();
                nodes.insert(sensor.to_owned());
                add_arc("plane:site", sensor, 1)?;
                for zone in &cov.record.zones {
                    let zone_id = zone.scope.as_str();
                    nodes.insert(zone_id.to_owned());
                    if cov.calibration_invalidation.is_none() && !zone.witnesses.is_empty() {
                        add_arc(sensor, zone_id, zone.witnesses.len() as u64)?;
                    }
                }
            }
            for event in &snapshot.events {
                let domains = event.failure_domains();
                for domain in &domains {
                    let dom_node = format!("domain:{domain}");
                    nodes.insert(dom_node.to_owned());
                    add_arc("plane:site", &dom_node, 1)?;
                    let event_node = event.event.event_id.as_str();
                    nodes.insert(event_node.to_owned());
                    add_arc(&dom_node, event_node, 1)?;
                }
            }
            "failure-coupling:retained-witnesses:v1"
        }
        ProjectionKind::ArchiveObjectGraph => {
            nodes.insert("root:deployment".to_owned());
            for import in &snapshot.completed_imports {
                let imp_node = format!("import:{import}");
                nodes.insert(imp_node.to_owned());
                add_arc("root:deployment", &imp_node, 1)?;
            }
            for cov in &snapshot.coverage {
                let cov_node = format!("coverage:{}", cov.record.sensor_id);
                nodes.insert(cov_node.to_owned());
                add_arc("root:deployment", &cov_node, 1)?;
            }
            for event in &snapshot.events {
                let ev_node = format!("event_root:{}", event.event_root);
                let rev_node = format!("revision_obj:{}", event.revision_digest);
                nodes.insert(ev_node.to_owned());
                nodes.insert(rev_node.to_owned());
                add_arc("root:deployment", &ev_node, 1)?;
                add_arc(&ev_node, &rev_node, 1)?;
            }
            "objects"
        }
        ProjectionKind::PlanObligationGraph => {
            nodes.insert("root:control".to_owned());
            for op in &snapshot.operations {
                let op_node = format!("op:{}", op.intent.operation_id);
                nodes.insert(op_node.to_owned());
                add_arc("root:control", &op_node, 1)?;
            }
            for ob in &snapshot.obligations {
                let ob_node = ob.obligation_id.as_str();
                nodes.insert(ob_node.to_owned());
                let parent = format!("op:{}", ob.operation_id);
                if nodes.contains(&parent) {
                    add_arc(&parent, ob_node, 1)?;
                } else {
                    add_arc("root:control", ob_node, 1)?;
                }
            }
            "steps"
        }
    };

    let mut builder = WeightedGraphBuilder::directed(unit);
    for id in nodes {
        builder.add_weighted_node(id, 1);
    }
    for ((from, to), weight) in edge_weights {
        builder.add_arc(from, to, weight);
    }
    let graph = builder.build()?;
    let projection_id = if kind == ProjectionKind::DeviceFailureGraph {
        format!("{projection_id}:retained-witnesses:v1")
    } else {
        projection_id
    };
    Ok((projection_id, graph))
}

#[allow(clippy::too_many_arguments)]
fn execute_and_render(
    site: &str,
    projection_kind: ProjectionKind,
    projection_id: &str,
    snapshot: &DeploymentSnapshot,
    graph: &WeightedGraph,
    algorithm_kind: AlgorithmKind,
    seeds: &[(String, u64)],
    terminals: &[String],
) -> Result<String, GraphError> {
    let (n, m) = (graph.node_count() as u64, graph.arc_count() as u64);
    match algorithm_kind {
        AlgorithmKind::Centrality => {
            let bound = centrality::bound(n, m);
            let run = centrality::centrality_family(graph, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_centrality(&run.output),
            )
        }
        AlgorithmKind::Community => {
            let max_passes = 8_u32;
            let bound = community::bound(n, m, max_passes);
            let run =
                community::community_detection(graph, max_passes, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_community(&run.output),
            )
        }
        AlgorithmKind::Spectral => {
            let config = SpectralConfig::default();
            let bound = spectral::bound(n, m, config.max_iterations);
            let run =
                spectral::spectral_change_detection(graph, &config, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_spectral(&run.output),
            )
        }
        AlgorithmKind::Scc => {
            let bound = scc::bound(n, m);
            let run = scc::strongly_connected_components(graph, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_scc(&run.output),
            )
        }
        AlgorithmKind::Topo => {
            let bound = topo::bound(n, m);
            let run = topo::topological_schedule(graph, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_topo(&run.output),
            )
        }
        AlgorithmKind::Ppr => {
            let resolved_seeds: Vec<(String, u64)> = if seeds.is_empty() {
                let first = (0..graph.node_count() as u32)
                    .next()
                    .map(|idx| graph.id(idx).to_owned())
                    .unwrap_or_default();
                vec![(first, ppr::SCALE_PPB)]
            } else {
                seeds.to_vec()
            };
            let seed_refs: Vec<(&str, u64)> = resolved_seeds
                .iter()
                .map(|(s, w)| (s.as_str(), *w))
                .collect();
            let config = PprConfig::default();
            let bound = ppr::bound(n, m, config.max_iterations);
            let run =
                ppr::personalized_pagerank(graph, &seed_refs, &config, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_ppr(&run.output),
            )
        }
        AlgorithmKind::Hits => {
            let config = HitsConfig::default();
            let bound = hits::bound(n, m, config.max_iterations);
            let run = hits::hits(graph, &config, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_hits(&run.output),
            )
        }
        AlgorithmKind::Mst => {
            let bound = spanning::bound(n, m);
            let run = spanning::minimum_spanning_forest(graph, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_mst(&run.output),
            )
        }
        AlgorithmKind::Steiner => {
            let resolved_terminals: Vec<String> = if terminals.is_empty() {
                (0..graph.node_count() as u32)
                    .take(3)
                    .map(|idx| graph.id(idx).to_owned())
                    .collect()
            } else {
                terminals.to_vec()
            };
            let terminal_refs: Vec<&str> = resolved_terminals.iter().map(String::as_str).collect();
            let t = terminal_refs.len() as u64;
            let bound = steiner::bound(n, m, t);
            let run = steiner::steiner_tree_approximation(
                graph,
                &terminal_refs,
                Budget::registered(&bound),
            )?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_steiner(&run.output),
            )
        }
        AlgorithmKind::ZSet => {
            let base = ZSetGraphState {
                nodes: ZSet::new(),
                arcs: ZSet::new(),
            };
            let mut node_deltas = Vec::with_capacity(graph.node_count());
            for node_idx in 0..graph.node_count() as u32 {
                node_deltas.push((graph.id(node_idx).to_owned(), 1_i64));
            }
            let mut arc_deltas = Vec::with_capacity(graph.arc_count());
            for arc in graph.arcs() {
                let tail = graph.id(arc.tail).to_owned();
                let head = graph.id(arc.head).to_owned();
                let w = i64::try_from(arc.weight).map_err(|_| GraphError::ArithmeticOverflow("Z-set multiplicity"))?;
                arc_deltas.push(((tail, head), w));
            }
            let batch = ZSetDeltaBatch {
                commit_sequence: snapshot.anchor.commit_sequence,
                node_deltas,
                arc_deltas,
            };
            let delta_count = (batch.node_deltas.len() + batch.arc_deltas.len()).max(1) as u64;
            let bound = zset::bound(n.max(1), m.max(1), delta_count);
            let run =
                zset::zset_incremental_maintenance(&base, &batch, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_zset(&run.output),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_certified<T>(
    site: &str,
    projection_kind: ProjectionKind,
    projection_id: &str,
    snapshot: &DeploymentSnapshot,
    graph: &WeightedGraph,
    run: &CertifiedRun<T>,
    bound: &[BoundRow],
    rendered_result: String,
) -> Result<String, GraphError>
where
    T: CertifiedOutput,
{
    let witness = run
        .witness(projection_id, snapshot.anchor.clone())
        .map_err(|err| GraphError::PreconditionFailed(format!("{err:?}")))?;
    certified::check_witness(&witness, run.identity, bound)?;

    Ok(object(&[
        ("format", string(FORMAT_DOMAIN)),
        ("site_id", string(site)),
        ("authority_anchor", evidence_anchor(&snapshot.anchor)),
        (
            "authority_anchor_token",
            string(&snapshot_anchor_token(snapshot)),
        ),
        ("projection_kind", string(projection_kind.as_str())),
        ("projection_id", string(projection_id)),
        ("projection_digest", string(&graph.digest().to_text())),
        (
            "orientation",
            string(match graph.orientation() {
                Orientation::Undirected => "undirected",
                Orientation::Directed => "directed",
            }),
        ),
        ("node_count", graph.node_count().to_string()),
        ("edge_count", graph.arc_count().to_string()),
        ("algorithm_id", string(run.identity.algorithm_id)),
        ("algorithm_name", string(run.identity.algorithm_name)),
        ("exactness", string(run.identity.exactness)),
        ("result", rendered_result),
        ("witness", render_witness(&witness, run.identity)),
    ]))
}

fn counts(values: &BTreeMap<String, u64>) -> String {
    let fields: Vec<String> = values
        .iter()
        .map(|(name, value)| format!("{}:{value}", string(name)))
        .collect();
    format!("{{{}}}", fields.join(","))
}

fn render_witness(witness: &GraphAlgorithmWitness, id: &AlgorithmIdentity) -> String {
    object(&[
        ("schema", string(GraphAlgorithmWitness::SCHEMA)),
        ("algorithm_id", string(witness.algorithm_id())),
        ("implementation_id", string(witness.implementation_id())),
        ("projection_id", string(witness.projection_id())),
        ("authority_anchor", evidence_anchor(witness.anchor())),
        ("input_digest", string(&witness.input_digest().to_text())),
        ("node_count", witness.node_count().to_string()),
        ("edge_count", witness.edge_count().to_string()),
        ("policy_id", string(witness.policy_id())),
        ("tie_break_policy_id", string(id.tie_break_policy_id)),
        ("tie_break_rule", string(id.tie_break_rule)),
        ("complexity_bound_id", string(id.complexity_bound_id)),
        (
            "dominant_operation_counts",
            counts(witness.dominant_operation_counts()),
        ),
        (
            "peak_working_bytes",
            witness.peak_working_bytes().to_string(),
        ),
        ("budget_consumed", counts(witness.budget_consumed())),
        ("exactness", string(witness.exactness())),
        ("stop_reason", string(witness.stop_reason())),
        (
            "decision_path_digest",
            string(&witness.decision_path_digest().to_text()),
        ),
        ("output_digest", string(&witness.output_digest().to_text())),
    ])
}

fn render_centrality(result: &CentralityOutput) -> String {
    let vertices: Vec<String> = result
        .vertices
        .iter()
        .map(|row| {
            object(&[
                ("node", string(&row.node_id)),
                ("betweenness_ppb", row.betweenness_ppb.to_string()),
                ("closeness_ppb", row.closeness_ppb.to_string()),
            ])
        })
        .collect();
    let edges: Vec<String> = result
        .edges
        .iter()
        .map(|row| {
            object(&[
                ("tail", string(&row.tail_id)),
                ("head", string(&row.head_id)),
                ("betweenness_ppb", row.betweenness_ppb.to_string()),
            ])
        })
        .collect();
    object(&[
        ("vertices", array(&vertices)),
        ("edges", array(&edges)),
    ])
}

fn render_community(result: &CommunityOutput) -> String {
    let communities: Vec<String> = result
        .communities
        .iter()
        .map(|comm| {
            object(&[
                ("community_id", comm.community_id.to_string()),
                ("members", strings(&comm.members)),
            ])
        })
        .collect();
    object(&[
        ("passes", result.passes.to_string()),
        ("modularity_ppb", result.modularity_ppb.to_string()),
        ("communities", array(&communities)),
    ])
}

fn render_spectral(result: &SpectralOutput) -> String {
    let eigenvector: Vec<String> = result
        .eigenvector
        .iter()
        .map(|entry| {
            object(&[
                ("node", string(&entry.node_id)),
                ("value_ppb", entry.value_ppb.to_string()),
            ])
        })
        .collect();
    object(&[
        ("iterations", result.iterations.to_string()),
        (
            "algebraic_connectivity_ppb",
            result.algebraic_connectivity_ppb.to_string(),
        ),
        ("anomaly_score_ppb", result.anomaly_score_ppb.to_string()),
        ("eigenvector", array(&eigenvector)),
    ])
}

fn render_scc(result: &SccOutput) -> String {
    let components: Vec<String> = result
        .components
        .iter()
        .map(|comp| {
            object(&[
                ("label", comp.label.to_string()),
                ("cyclic", comp.cyclic.to_string()),
                ("members", strings(&comp.members)),
            ])
        })
        .collect();
    object(&[
        ("component_count", result.components.len().to_string()),
        ("components", array(&components)),
    ])
}

fn render_topo(result: &TopoOutput) -> String {
    object(&[
        ("makespan", result.makespan.to_string()),
        ("order", strings(&result.order)),
        ("critical_path", strings(&result.critical_path)),
    ])
}

fn render_ppr(result: &PprOutput) -> String {
    let scores: Vec<String> = result
        .scores
        .iter()
        .map(|row| {
            object(&[
                ("node", string(&row.node_id)),
                ("score_ppb", row.score_ppb.to_string()),
            ])
        })
        .collect();
    object(&[
        ("iterations", result.iterations.to_string()),
        ("converged", result.converged.to_string()),
        ("residual_ppb", result.residual_ppb.to_string()),
        ("scores", array(&scores)),
    ])
}

fn render_hits(result: &HitsOutput) -> String {
    let hubs: Vec<String> = result
        .hubs
        .iter()
        .map(|row| {
            object(&[
                ("node", string(&row.node_id)),
                ("score_ppb", row.score_ppb.to_string()),
            ])
        })
        .collect();
    let authorities: Vec<String> = result
        .authorities
        .iter()
        .map(|row| {
            object(&[
                ("node", string(&row.node_id)),
                ("score_ppb", row.score_ppb.to_string()),
            ])
        })
        .collect();
    object(&[
        ("iterations", result.iterations.to_string()),
        ("converged", result.converged.to_string()),
        ("residual_ppb", result.residual_ppb.to_string()),
        ("hubs", array(&hubs)),
        ("authorities", array(&authorities)),
    ])
}

fn render_mst(result: &SpanningForestOutput) -> String {
    let edges: Vec<String> = result
        .edges
        .iter()
        .map(|(u, v, w)| {
            object(&[
                ("u", string(u)),
                ("v", string(v)),
                ("weight", w.to_string()),
            ])
        })
        .collect();
    object(&[
        ("total_weight", result.total_weight.to_string()),
        ("components", result.components.to_string()),
        ("edges", array(&edges)),
    ])
}

fn render_steiner(result: &SteinerTreeOutput) -> String {
    let edges: Vec<String> = result
        .tree_edges
        .iter()
        .map(|edge| {
            object(&[
                ("u", string(&edge.u)),
                ("v", string(&edge.v)),
                ("weight", edge.weight.to_string()),
            ])
        })
        .collect();
    object(&[
        ("total_weight", result.total_weight.to_string()),
        ("nodes", strings(&result.tree_nodes)),
        ("edges", array(&edges)),
    ])
}

fn render_zset(result: &ZSetMaintenanceOutput) -> String {
    let deltas: Vec<String> = result
        .delta_records
        .iter()
        .map(|row| {
            object(&[
                ("commit_sequence", row.commit_sequence.to_string()),
                ("tuple_key", string(&row.tuple_key)),
                ("delta_weight", row.delta_weight.to_string()),
            ])
        })
        .collect();
    object(&[
        (
            "two_hop_delta_count",
            result.two_hop_delta_count.to_string(),
        ),
        ("delta_records", array(&deltas)),
    ])
}
