#![forbid(unsafe_code)]
//! `fss-event graph analyze` — certified graph-atlas analysis over retained `--root` deployments.
//!
//! Compiles canonical, anchor-pinned projections (`SensorCoverageGraph`, `EvidenceClaimGraph`,
//! `DeviceFailureGraph`, `ArchiveObjectGraph`, `PlanObligationGraph`) from a committed
//! `ReferenceDeployment` (`DeploymentHistory::read`), executes a registered algorithm from the
//! 27/27 Certified Graph Atlas (`ALG-CENTRAL-001`, `ALG-COMM-001`, `ALG-DYNCONN-001`,
//! `ALG-FACTOR-001`, `ALG-GH-001`, `ALG-HITS-001`, `ALG-KSP-001`, `ALG-MSD-001`, `ALG-MST-001`,
//! `ALG-PPR-001`, `ALG-SCC-001`, `ALG-SP-001`, `ALG-SPECTRAL-001`, `ALG-STEINER-001`,
//! `ALG-SUBMOD-001`, `ALG-TOPO-001`, `ALG-ZSET-001`), checks the complexity and output witness
//! against the registered bound, and emits a canonical `fss.deployment_graph_analysis.v1` JSON
//! document.

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
use fss_graph_algorithms::dynconn::{self, DynamicConnectivityOutput, EdgeUpdate};
use fss_graph_algorithms::evidence::{self, EvidenceProjectionError};
use fss_graph_algorithms::factorized_join::{self, FactorJoinOutput, FactorJoinProblem};
use fss_graph_algorithms::gomory_hu::{self, GomoryHuOutput};
use fss_graph_algorithms::graph::GraphError;
use fss_graph_algorithms::hits::{self, HitsConfig, HitsOutput};
use fss_graph_algorithms::ksp::{self, KspOutput};
use fss_graph_algorithms::paths::{self, MultiSourceOutput, ShortestPathOutput};
use fss_graph_algorithms::ppr::{self, PprConfig, PprOutput};
use fss_graph_algorithms::scc::{self, SccOutput};
use fss_graph_algorithms::set_cover::{CoverBudget, CoverSet, SetCoverProblem};
use fss_graph_algorithms::spanning::{self, SpanningForestOutput};
use fss_graph_algorithms::spectral::{self, SpectralConfig, SpectralOutput};
use fss_graph_algorithms::steiner::{self, SteinerTreeOutput};
use fss_graph_algorithms::submodular::{self, SubmodularAnalysis, SubmodularProblem};
use fss_graph_algorithms::topo::{self, TopoOutput};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};
use fss_graph_algorithms::zset::{
    self, ZSet, ZSetDeltaBatch, ZSetGraphState, ZSetMaintenanceOutput,
};
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::agent_orient::{
    DeploymentHistory, DeploymentSnapshot, HistoryPosition, OrientLimits,
};
use fss_reference::coverage_graph::weighted_historical_coverage;
use fss_reference::evidence_claim_graph::retained_evidence_projection;

/// Digest domain for `fss-event graph analyze` (`SCHEMA-DOMAIN-DEPLOYMENT-GRAPH-ANALYSIS-001`).
const FORMAT_DOMAIN: &str = "fss.deployment_graph_analysis.v1";

const HELP: &str = "fss-event graph analyze --root DIR --site SITE\n\
  --projection <SensorCoverageGraph|EvidenceClaimGraph|DeviceFailureGraph|ArchiveObjectGraph|PlanObligationGraph>\n\
  --algorithm <ALG-CENTRAL-001|ALG-COMM-001|ALG-DYNCONN-001|ALG-FACTOR-001|ALG-GH-001|ALG-HITS-001|ALG-KSP-001|ALG-MSD-001|ALG-MST-001|ALG-PPR-001|ALG-SCC-001|ALG-SP-001|ALG-SPECTRAL-001|ALG-STEINER-001|ALG-SUBMOD-001|ALG-TOPO-001|ALG-ZSET-001>\n\
  [--seed NODE[:WEIGHT]]... (PPR) [--terminal NODE]... (Steiner)\n\
  [--source NODE]... (SP/MSD/KSP) [--target NODE] (SP/KSP) [--k N] [--min-distinct-arcs N] (KSP)\n\
  [--update <+u,v|-u,v>]... [--query <state,u,v>]... (DYNCONN)\n\
  [--budget N] (SUBMOD) [--from-commit SEQ] (ZSET incremental baseline)\n\
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
    DynConn,
    FactorizedJoin,
    GomoryHu,
    Spectral,
    Scc,
    ShortestPath,
    MultiSourceDistance,
    KShortestPaths,
    Topo,
    Ppr,
    Hits,
    Mst,
    Steiner,
    Submodular,
    ZSet,
}

impl AlgorithmKind {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "ALG-CENTRAL-001" => Ok(Self::Centrality),
            "ALG-COMM-001" => Ok(Self::Community),
            "ALG-DYNCONN-001" => Ok(Self::DynConn),
            "ALG-FACTOR-001" => Ok(Self::FactorizedJoin),
            "ALG-GH-001" => Ok(Self::GomoryHu),
            "ALG-SPECTRAL-001" => Ok(Self::Spectral),
            "ALG-SCC-001" => Ok(Self::Scc),
            "ALG-SP-001" => Ok(Self::ShortestPath),
            "ALG-MSD-001" => Ok(Self::MultiSourceDistance),
            "ALG-KSP-001" => Ok(Self::KShortestPaths),
            "ALG-TOPO-001" => Ok(Self::Topo),
            "ALG-PPR-001" => Ok(Self::Ppr),
            "ALG-HITS-001" => Ok(Self::Hits),
            "ALG-MST-001" => Ok(Self::Mst),
            "ALG-STEINER-001" => Ok(Self::Steiner),
            "ALG-SUBMOD-001" => Ok(Self::Submodular),
            "ALG-ZSET-001" => Ok(Self::ZSet),
            other => Err(format!(
                "unsupported `--algorithm` `{other}`; expected one of `ALG-CENTRAL-001`, `ALG-COMM-001`, `ALG-DYNCONN-001`, `ALG-FACTOR-001`, `ALG-GH-001`, `ALG-HITS-001`, `ALG-KSP-001`, `ALG-MSD-001`, `ALG-MST-001`, `ALG-PPR-001`, `ALG-SCC-001`, `ALG-SP-001`, `ALG-SPECTRAL-001`, `ALG-STEINER-001`, `ALG-SUBMOD-001`, `ALG-TOPO-001`, or `ALG-ZSET-001`"
            )),
        }
    }
}

struct ExtraArgs {
    seeds: Vec<(String, u64)>,
    terminals: Vec<String>,
    sources: Vec<String>,
    target: Option<String>,
    k: Option<u32>,
    min_distinct_arcs: Option<u32>,
    budget: Option<u64>,
    from_commit: Option<u64>,
    updates: Vec<EdgeUpdate>,
    queries: Vec<(u32, String, String)>,
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
    let mut sources: Vec<String> = Vec::new();
    let mut target: Option<String> = None;
    let mut k: Option<u32> = None;
    let mut min_distinct_arcs: Option<u32> = None;
    let mut budget: Option<u64> = None;
    let mut from_commit: Option<u64> = None;
    let mut updates: Vec<EdgeUpdate> = Vec::new();
    let mut queries: Vec<(u32, String, String)> = Vec::new();
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
            "--source" => {
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--source`");
                };
                if val.trim().is_empty() {
                    return usage_error("empty value for `--source`");
                }
                sources.push(val.to_owned());
                idx += 2;
            }
            "--target" => {
                if target.is_some() {
                    return usage_error("duplicate option `--target`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--target`");
                };
                if val.trim().is_empty() {
                    return usage_error("empty value for `--target`");
                }
                target = Some(val.to_owned());
                idx += 2;
            }
            "--k" => {
                if k.is_some() {
                    return usage_error("duplicate option `--k`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--k`");
                };
                let Ok(parsed) = val.parse::<u32>() else {
                    return usage_error(&format!("invalid `--k` `{val}`"));
                };
                if parsed == 0 || parsed > ksp::MAX_PATHS {
                    return usage_error("`--k` must be in 1..=1024");
                }
                k = Some(parsed);
                idx += 2;
            }
            "--min-distinct-arcs" => {
                if min_distinct_arcs.is_some() {
                    return usage_error("duplicate option `--min-distinct-arcs`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--min-distinct-arcs`");
                };
                let Ok(parsed) = val.parse::<u32>() else {
                    return usage_error(&format!("invalid `--min-distinct-arcs` `{val}`"));
                };
                min_distinct_arcs = Some(parsed);
                idx += 2;
            }
            "--budget" => {
                if budget.is_some() {
                    return usage_error("duplicate option `--budget`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--budget`");
                };
                let Ok(parsed) = val.parse::<u64>() else {
                    return usage_error(&format!("invalid `--budget` `{val}`"));
                };
                if parsed == 0 {
                    return usage_error("`--budget` must be >= 1");
                }
                budget = Some(parsed);
                idx += 2;
            }
            "--from-commit" => {
                if from_commit.is_some() {
                    return usage_error("duplicate option `--from-commit`");
                }
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--from-commit`");
                };
                let Ok(parsed) = val.parse::<u64>() else {
                    return usage_error(&format!("invalid `--from-commit` `{val}`"));
                };
                from_commit = Some(parsed);
                idx += 2;
            }
            "--update" => {
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--update`");
                };
                match parse_edge_update(val) {
                    Ok(parsed) => updates.push(parsed),
                    Err(msg) => return usage_error(&msg),
                }
                idx += 2;
            }
            "--query" => {
                let Some(&val) = str_args.get(idx + 1) else {
                    return usage_error("missing value for `--query`");
                };
                match parse_dynconn_query(val) {
                    Ok(parsed) => queries.push(parsed),
                    Err(msg) => return usage_error(&msg),
                }
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
    if !sources.is_empty()
        && !matches!(
            algorithm_kind,
            AlgorithmKind::ShortestPath
                | AlgorithmKind::MultiSourceDistance
                | AlgorithmKind::KShortestPaths
        )
    {
        return usage_error("--source applies only to ALG-SP-001, ALG-MSD-001, or ALG-KSP-001");
    }
    if sources.len() > 1
        && matches!(
            algorithm_kind,
            AlgorithmKind::ShortestPath | AlgorithmKind::KShortestPaths
        )
    {
        return usage_error("at most one --source is allowed for ALG-SP-001 or ALG-KSP-001");
    }
    if target.is_some()
        && !matches!(
            algorithm_kind,
            AlgorithmKind::ShortestPath | AlgorithmKind::KShortestPaths
        )
    {
        return usage_error("--target applies only to ALG-SP-001 or ALG-KSP-001");
    }
    if (k.is_some() || min_distinct_arcs.is_some())
        && algorithm_kind != AlgorithmKind::KShortestPaths
    {
        return usage_error("--k and --min-distinct-arcs apply only to ALG-KSP-001");
    }
    if budget.is_some() && algorithm_kind != AlgorithmKind::Submodular {
        return usage_error("--budget applies only to ALG-SUBMOD-001");
    }
    if from_commit.is_some() && algorithm_kind != AlgorithmKind::ZSet {
        return usage_error("--from-commit applies only to ALG-ZSET-001");
    }
    if (!updates.is_empty() || !queries.is_empty()) && algorithm_kind != AlgorithmKind::DynConn {
        return usage_error("--update and --query apply only to ALG-DYNCONN-001");
    }

    let history = match DeploymentHistory::read(&root, &OrientLimits::default()) {
        Ok(history) => history,
        Err(error) => {
            return fail_message(
                ERR_CLI_RUNTIME_FAILURE,
                &format!("deployment load failed: {error}"),
            );
        }
    };
    let head_pos = history.head();
    let snapshot = match history.snapshot_at(head_pos) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return fail_message(
                ERR_CLI_RUNTIME_FAILURE,
                &format!("deployment head snapshot failed: {error}"),
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

    let extra = ExtraArgs {
        seeds: resolved_seeds,
        terminals,
        sources,
        target,
        k,
        min_distinct_arcs,
        budget,
        from_commit,
        updates,
        queries,
    };

    match execute_and_render(
        &site,
        projection_kind,
        &projection_id,
        &history,
        head_pos,
        &snapshot,
        &graph,
        algorithm_kind,
        &extra,
    ) {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => fail_graph(&error),
    }
}

fn parse_edge_update(raw: &str) -> Result<EdgeUpdate, String> {
    let (insert, rest) = if let Some(rest) = raw.strip_prefix('+') {
        (true, rest)
    } else if let Some(rest) = raw.strip_prefix('-') {
        (false, rest)
    } else {
        return Err(format!(
            "invalid `--update` `{raw}`; expected `+u,v` or `-u,v`"
        ));
    };
    let Some((a, b)) = rest.split_once(',') else {
        return Err(format!(
            "invalid `--update` `{raw}`; expected `+u,v` or `-u,v`"
        ));
    };
    if a.trim().is_empty() || b.trim().is_empty() {
        return Err(format!("empty endpoint in `--update` `{raw}`"));
    }
    Ok(if insert {
        EdgeUpdate::Insert(a.to_owned(), b.to_owned())
    } else {
        EdgeUpdate::Delete(a.to_owned(), b.to_owned())
    })
}

fn parse_dynconn_query(raw: &str) -> Result<(u32, String, String), String> {
    let mut parts = raw.splitn(3, ',');
    let (Some(state_raw), Some(a), Some(b)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("invalid `--query` `{raw}`; expected `state,u,v`"));
    };
    let state = state_raw
        .parse::<u32>()
        .map_err(|_| format!("invalid state `{state_raw}` in `--query` `{raw}`"))?;
    if a.trim().is_empty() || b.trim().is_empty() {
        return Err(format!("empty endpoint in `--query` `{raw}`"));
    }
    Ok((state, a.to_owned(), b.to_owned()))
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
            kind.as_str(),
            registered.join(", ")
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
    history: &DeploymentHistory,
    head_pos: HistoryPosition,
    snapshot: &DeploymentSnapshot,
    graph: &WeightedGraph,
    algorithm_kind: AlgorithmKind,
    extra: &ExtraArgs,
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
        AlgorithmKind::DynConn => {
            graph.require_orientation(Orientation::Undirected)?;
            let batches: Vec<Vec<EdgeUpdate>> = extra
                .updates
                .iter()
                .map(|update| vec![update.clone()])
                .collect();
            let final_state = u32::try_from(batches.len()).map_err(|_| GraphError::TooLarge)?;
            let owned_queries: Vec<(u32, String, String)> = if !extra.queries.is_empty() {
                extra.queries.clone()
            } else if graph.node_count() >= 2 {
                let root = graph.id(0).to_owned();
                let mut qs = Vec::new();
                for idx in 1..graph.node_count() as u32 {
                    let node = graph.id(idx).to_owned();
                    qs.push((0_u32, root.clone(), node.clone()));
                    if final_state > 0 {
                        qs.push((final_state, root.clone(), node));
                    }
                }
                qs
            } else {
                Vec::new()
            };
            let query_refs: Vec<(u32, &str, &str)> = owned_queries
                .iter()
                .map(|(s, a, b)| (*s, a.as_str(), b.as_str()))
                .collect();
            let lifetimes = m.saturating_add(extra.updates.len() as u64);
            let states = (batches.len() + 1) as u64;
            let bound = dynconn::bound(n, lifetimes, states, query_refs.len() as u64);
            let run = dynconn::dynamic_connectivity(
                graph,
                &batches,
                &query_refs,
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
                render_dynconn(&run.output),
            )
        }
        AlgorithmKind::FactorizedJoin => {
            let problem = FactorJoinProblem::from_graph_pattern(
                graph,
                vec!["x".to_owned(), "y".to_owned(), "z".to_owned()],
                &[("hop_1", 0, 1), ("hop_2", 1, 2)],
            )?;
            let v = problem.domain.len() as u64;
            let m_rel: u64 = problem.relations.iter().map(|r| r.pairs.len() as u64).sum();
            let r = problem.relations.len() as u64;
            let bound = factorized_join::bound(v, m_rel, r);
            let run = factorized_join::factorized_free_join(&problem, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_factorized(&problem.variables, &run.output),
            )
        }
        AlgorithmKind::GomoryHu => {
            let bound = gomory_hu::bound(n, m);
            let run = gomory_hu::gomory_hu_tree(graph, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_gomory_hu(&run.output),
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
        AlgorithmKind::ShortestPath => {
            if graph.node_count() == 0 {
                return Err(GraphError::PreconditionFailed(
                    "ALG-SP-001 requires at least one node in the projection".to_owned(),
                ));
            }
            let source = extra
                .sources
                .first()
                .map_or_else(|| graph.id(0), String::as_str);
            let bound = paths::sp_bound(graph.orientation(), n, m);
            let run = paths::shortest_paths(
                graph,
                source,
                extra.target.as_deref(),
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
                render_shortest_path(&run.output),
            )
        }
        AlgorithmKind::MultiSourceDistance => {
            if graph.node_count() == 0 {
                return Err(GraphError::PreconditionFailed(
                    "ALG-MSD-001 requires at least one node in the projection".to_owned(),
                ));
            }
            let resolved_sources: Vec<String> = if extra.sources.is_empty() {
                vec![graph.id(0).to_owned()]
            } else {
                extra.sources.clone()
            };
            let source_refs: Vec<&str> = resolved_sources.iter().map(String::as_str).collect();
            let bound = paths::msd_bound(graph.orientation(), n, m);
            let run =
                paths::multi_source_distances(graph, &source_refs, Budget::registered(&bound))?;
            render_certified(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &run,
                &bound,
                render_multi_source(&run.output),
            )
        }
        AlgorithmKind::KShortestPaths => {
            if graph.node_count() < 2 {
                return Err(GraphError::PreconditionFailed(
                    "ALG-KSP-001 requires at least two distinct nodes in the projection".to_owned(),
                ));
            }
            let source = extra
                .sources
                .first()
                .map_or_else(|| graph.id(0), String::as_str);
            let target = extra.target.as_deref().unwrap_or_else(|| {
                let last = graph.id((graph.node_count() - 1) as u32);
                if last == source { graph.id(0) } else { last }
            });
            let k = extra.k.unwrap_or(3);
            let min_distinct_arcs = extra.min_distinct_arcs.unwrap_or(1);
            let max_enumerated = k.saturating_mul(4).min(ksp::MAX_PATHS);
            let bound = ksp::bound(
                graph.orientation(),
                n,
                m,
                u64::from(k),
                u64::from(max_enumerated),
            );
            let run = ksp::k_shortest_paths(
                graph,
                source,
                target,
                k,
                min_distinct_arcs,
                max_enumerated,
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
                render_ksp(&run.output),
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
            let resolved_seeds: Vec<(String, u64)> = if extra.seeds.is_empty() {
                let first = (0..graph.node_count() as u32)
                    .next()
                    .map(|idx| graph.id(idx).to_owned())
                    .unwrap_or_default();
                vec![(first, ppr::SCALE_PPB)]
            } else {
                extra.seeds.clone()
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
            let resolved_terminals: Vec<String> = if extra.terminals.is_empty() {
                (0..graph.node_count() as u32)
                    .take(3)
                    .map(|idx| graph.id(idx).to_owned())
                    .collect()
            } else {
                extra.terminals.clone()
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
        AlgorithmKind::Submodular => {
            let analysis = run_submodular_projection(projection_kind, graph, extra.budget)?;
            let witness = analysis
                .witness(projection_id, snapshot.anchor.clone())
                .map_err(|err| GraphError::PreconditionFailed(format!("{err:?}")))?;
            render_submodular_report(
                site,
                projection_kind,
                projection_id,
                snapshot,
                graph,
                &analysis,
                &witness,
            )
        }
        AlgorithmKind::ZSet => {
            let (base_commit, prior_graph) =
                resolve_zset_baseline(history, head_pos, projection_kind, extra.from_commit)?;
            let incremental = prior_graph.is_some();
            let base = match &prior_graph {
                Some(prior) => graph_to_zset_state(prior)?,
                None => ZSetGraphState {
                    nodes: ZSet::new(),
                    arcs: ZSet::new(),
                },
            };
            let head_state = graph_to_zset_state(graph)?;
            let mut node_deltas = Vec::new();
            let mut all_nodes = BTreeSet::new();
            for (k, _) in base.nodes.iter() {
                all_nodes.insert(k.clone());
            }
            for (k, _) in head_state.nodes.iter() {
                all_nodes.insert(k.clone());
            }
            for node in all_nodes {
                let delta = head_state
                    .nodes
                    .weight(&node)
                    .checked_sub(base.nodes.weight(&node))
                    .ok_or(GraphError::ArithmeticOverflow("Z-set node delta"))?;
                if delta != 0 {
                    node_deltas.push((node, delta));
                }
            }
            let mut arc_deltas = Vec::new();
            let mut all_arcs = BTreeSet::new();
            for (k, _) in base.arcs.iter() {
                all_arcs.insert(k.clone());
            }
            for (k, _) in head_state.arcs.iter() {
                all_arcs.insert(k.clone());
            }
            for arc_key in all_arcs {
                let delta = head_state
                    .arcs
                    .weight(&arc_key)
                    .checked_sub(base.arcs.weight(&arc_key))
                    .ok_or(GraphError::ArithmeticOverflow("Z-set arc delta"))?;
                if delta != 0 {
                    arc_deltas.push((arc_key, delta));
                }
            }
            let node_delta_count = node_deltas.len();
            let arc_delta_count = arc_deltas.len();
            let batch = ZSetDeltaBatch {
                commit_sequence: snapshot.anchor.commit_sequence,
                node_deltas,
                arc_deltas,
            };
            let n_bound = (base.nodes.len() + graph.node_count()).max(1) as u64;
            let m_bound = (base.arcs.len() + graph.arc_count()).max(1) as u64;
            let delta_count = (batch.node_deltas.len() + batch.arc_deltas.len()).max(1) as u64;
            let bound = zset::bound(n_bound, m_bound, delta_count);
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
                render_zset(
                    &run.output,
                    base_commit,
                    snapshot.anchor.commit_sequence,
                    incremental,
                    node_delta_count,
                    arc_delta_count,
                ),
            )
        }
    }
}

fn resolve_zset_baseline(
    history: &DeploymentHistory,
    head_pos: HistoryPosition,
    projection_kind: ProjectionKind,
    requested_from_commit: Option<u64>,
) -> Result<(u64, Option<WeightedGraph>), GraphError> {
    if let Some(seq) = requested_from_commit {
        if seq > head_pos.commit_sequence {
            return Err(GraphError::PreconditionFailed(format!(
                "--from-commit {seq} exceeds deployment head commit {}",
                head_pos.commit_sequence
            )));
        }
        if seq == 0 {
            return Ok((0, None));
        }
        let pos = HistoryPosition {
            commit_sequence: seq,
            effect_records: head_pos.effect_records,
        };
        let prior_snapshot = history.snapshot_at(pos).map_err(|err| {
            GraphError::PreconditionFailed(format!("cannot load baseline commit {seq}: {err}"))
        })?;
        let (_, prior_graph) = compile_projection(projection_kind, &prior_snapshot)
            .map_err(|err| GraphError::PreconditionFailed(err.to_string()))?;
        return Ok((seq, Some(prior_graph)));
    }
    if head_pos.commit_sequence > 1 {
        let prev = head_pos.commit_sequence - 1;
        let pos = HistoryPosition {
            commit_sequence: prev,
            effect_records: head_pos.effect_records,
        };
        if history.contains(pos)
            && let Ok(prior_snapshot) = history.snapshot_at(pos)
            && let Ok((_, prior_graph)) = compile_projection(projection_kind, &prior_snapshot)
        {
            return Ok((prev, Some(prior_graph)));
        }
    }
    Ok((0, None))
}

fn graph_to_zset_state(graph: &WeightedGraph) -> Result<ZSetGraphState, GraphError> {
    let mut nodes = ZSet::new();
    for node_idx in 0..graph.node_count() as u32 {
        nodes.add_weight(graph.id(node_idx).to_owned(), 1_i64)?;
    }
    let mut arcs = ZSet::new();
    for arc in graph.arcs() {
        let tail = graph.id(arc.tail).to_owned();
        let head = graph.id(arc.head).to_owned();
        let w = i64::try_from(arc.weight)
            .map_err(|_| GraphError::ArithmeticOverflow("Z-set multiplicity"))?;
        arcs.add_weight((tail, head), w)?;
    }
    Ok(ZSetGraphState { nodes, arcs })
}

fn run_submodular_projection(
    projection_kind: ProjectionKind,
    graph: &WeightedGraph,
    budget_override: Option<u64>,
) -> Result<SubmodularAnalysis, GraphError> {
    let mut provider_targets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut target_utilities: BTreeMap<String, u64> = BTreeMap::new();

    match projection_kind {
        ProjectionKind::SensorCoverageGraph => {
            for idx in 0..graph.node_count() as u32 {
                let id = graph.id(idx);
                if id.starts_with("zone/") {
                    target_utilities.entry(id.to_owned()).or_insert(1);
                } else if id.starts_with("sensor/") {
                    provider_targets.entry(id.to_owned()).or_default();
                }
            }
            for arc in graph.arcs() {
                let a = graph.id(arc.tail);
                let b = graph.id(arc.head);
                let (sensor, zone) = if a.starts_with("sensor/") && b.starts_with("zone/") {
                    (a, b)
                } else if b.starts_with("sensor/") && a.starts_with("zone/") {
                    (b, a)
                } else {
                    continue;
                };
                provider_targets
                    .entry(sensor.to_owned())
                    .or_default()
                    .insert(zone.to_owned());
                let util = target_utilities.entry(zone.to_owned()).or_insert(0);
                *util = util.saturating_add(arc.weight.max(1));
            }
        }
        ProjectionKind::EvidenceClaimGraph => {
            for idx in 0..graph.node_count() as u32 {
                let id = graph.id(idx);
                if id.starts_with("event:") {
                    target_utilities.entry(id.to_owned()).or_insert(1);
                }
            }
            for arc in graph.arcs() {
                let tail = graph.id(arc.tail);
                let head = graph.id(arc.head);
                if head.starts_with("event:") && !tail.starts_with("event:") {
                    provider_targets
                        .entry(tail.to_owned())
                        .or_default()
                        .insert(head.to_owned());
                    let util = target_utilities.entry(head.to_owned()).or_insert(0);
                    *util = util.saturating_add(arc.weight.max(1));
                } else if tail.starts_with("event:") && !head.starts_with("event:") {
                    provider_targets
                        .entry(head.to_owned())
                        .or_default()
                        .insert(tail.to_owned());
                    let util = target_utilities.entry(tail.to_owned()).or_insert(0);
                    *util = util.saturating_add(arc.weight.max(1));
                }
            }
        }
        _ => {
            return Err(GraphError::PreconditionFailed(format!(
                "ALG-SUBMOD-001 is not registered for {}",
                projection_kind.as_str()
            )));
        }
    }

    if target_utilities.is_empty() || provider_targets.is_empty() {
        return Err(GraphError::PreconditionFailed(format!(
            "projection {} has no provider/target coverage pairs for ALG-SUBMOD-001",
            projection_kind.as_str()
        )));
    }
    for util in target_utilities.values_mut() {
        if *util == 0 {
            *util = 1;
        }
    }
    let elements: Vec<String> = target_utilities.keys().cloned().collect();
    let mut sets = Vec::with_capacity(provider_targets.len());
    let mut costs = BTreeMap::new();
    for (provider, targets) in &provider_targets {
        let covered: Vec<String> = targets.iter().cloned().collect();
        let cover_set = CoverSet::new(provider, &covered)
            .map_err(|err| GraphError::PreconditionFailed(err.to_string()))?;
        sets.push(cover_set);
        costs.insert(provider.clone(), 1_u64);
    }
    let cost_budget = budget_override.unwrap_or(sets.len() as u64);
    let max_sets = usize::try_from(cost_budget)
        .unwrap_or(sets.len())
        .min(sets.len());
    let support = SetCoverProblem::new(&elements, &sets, &[], &[], max_sets)
        .map_err(|err| GraphError::PreconditionFailed(err.to_string()))?;
    let problem = SubmodularProblem::new(support, &target_utilities, &costs, cost_budget)
        .map_err(|err| GraphError::PreconditionFailed(err.to_string()))?;
    problem
        .solve(CoverBudget::default())
        .map_err(|err| GraphError::PreconditionFailed(err.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn render_submodular_report(
    site: &str,
    projection_kind: ProjectionKind,
    projection_id: &str,
    snapshot: &DeploymentSnapshot,
    graph: &WeightedGraph,
    analysis: &SubmodularAnalysis,
    witness: &GraphAlgorithmWitness,
) -> Result<String, GraphError> {
    let steps: Vec<String> = analysis
        .steps()
        .iter()
        .map(|step| {
            object(&[
                ("action_id", string(&step.action_id)),
                ("marginal_utility", step.marginal_utility.to_string()),
                ("cost_units", step.cost_units.to_string()),
                (
                    "cumulative_cost_units",
                    step.cumulative_cost_units.to_string(),
                ),
                ("cumulative_utility", step.cumulative_utility.to_string()),
            ])
        })
        .collect();
    let rendered_result = object(&[
        ("stop", string(analysis.stop().as_str())),
        ("selected", strings(analysis.selected())),
        ("uncovered", strings(analysis.uncovered())),
        ("uncoverable", strings(analysis.uncoverable())),
        ("cost_units", analysis.cost_units().to_string()),
        ("utility", analysis.utility().to_string()),
        ("total_utility", analysis.total_utility().to_string()),
        ("steps", array(&steps)),
    ]);
    let rendered_witness = object(&[
        ("schema", string(GraphAlgorithmWitness::SCHEMA)),
        ("algorithm_id", string(witness.algorithm_id())),
        ("implementation_id", string(witness.implementation_id())),
        ("projection_id", string(witness.projection_id())),
        ("authority_anchor", evidence_anchor(witness.anchor())),
        ("input_digest", string(&witness.input_digest().to_text())),
        ("node_count", witness.node_count().to_string()),
        ("edge_count", witness.edge_count().to_string()),
        ("policy_id", string(witness.policy_id())),
        (
            "tie_break_policy_id",
            string("tie:ratio-then-stable-action-identity:v1"),
        ),
        (
            "tie_break_rule",
            string("marginal gain per unit cost then stable action identity"),
        ),
        (
            "complexity_bound_id",
            string("bound:alg-submod-001:eager-weighted-coverage:v1"),
        ),
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
    ]);
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
        ("algorithm_id", string(submodular::ALGORITHM_ID)),
        ("algorithm_name", string("submodular_selection")),
        ("exactness", string("approximate")),
        ("result", rendered_result),
        ("witness", rendered_witness),
    ]))
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
    object(&[("vertices", array(&vertices)), ("edges", array(&edges))])
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

fn render_dynconn(result: &DynamicConnectivityOutput) -> String {
    let counts_json: Vec<String> = result
        .component_counts
        .iter()
        .map(ToString::to_string)
        .collect();
    let answers: Vec<String> = result
        .answers
        .iter()
        .map(|(state, a, b, connected)| {
            object(&[
                ("state", state.to_string()),
                ("u", string(a)),
                ("v", string(b)),
                ("connected", connected.to_string()),
            ])
        })
        .collect();
    object(&[
        ("component_counts", array(&counts_json)),
        ("answers", array(&answers)),
    ])
}

fn render_factorized(variables: &[String], result: &FactorJoinOutput) -> String {
    let tuples: Vec<String> = result
        .materialize_tuples(variables.len())
        .into_iter()
        .take(64)
        .map(|tuple| strings(&tuple))
        .collect();
    object(&[
        ("variables", strings(variables)),
        ("factor_count", result.factors.len().to_string()),
        ("complete_bindings", result.complete_bindings.to_string()),
        ("capped", result.capped.to_string()),
        ("tuples", array(&tuples)),
    ])
}

fn render_gomory_hu(result: &GomoryHuOutput) -> String {
    let tree: Vec<String> = result
        .tree
        .iter()
        .map(|(node, parent, min_cut)| {
            object(&[
                ("node", string(node)),
                ("parent", string(parent)),
                ("min_cut", min_cut.to_string()),
            ])
        })
        .collect();
    object(&[
        (
            "root",
            match &result.root {
                Some(r) => string(r),
                None => "null".to_owned(),
            },
        ),
        ("tree", array(&tree)),
    ])
}

fn render_shortest_path(result: &ShortestPathOutput) -> String {
    let reachable: Vec<String> = result
        .reachable
        .iter()
        .map(|row| {
            object(&[
                ("node", string(&row.node)),
                ("distance", row.distance.to_string()),
                ("hops", row.hops.to_string()),
                (
                    "parent",
                    match &row.parent {
                        Some(p) => string(p),
                        None => "null".to_owned(),
                    },
                ),
            ])
        })
        .collect();
    let target_json = match &result.target {
        None => "null".to_owned(),
        Some((goal, path)) => object(&[
            ("node", string(goal)),
            (
                "path",
                match path {
                    Some(p) => strings(p),
                    None => "null".to_owned(),
                },
            ),
        ]),
    };
    object(&[
        ("source", string(&result.source)),
        ("reachable", array(&reachable)),
        ("unreachable", strings(&result.unreachable)),
        ("target", target_json),
    ])
}

fn render_multi_source(result: &MultiSourceOutput) -> String {
    let reachable: Vec<String> = result
        .reachable
        .iter()
        .map(|row| {
            object(&[
                ("node", string(&row.node)),
                ("nearest_source", string(&row.source)),
                ("distance", row.distance.to_string()),
                ("hops", row.hops.to_string()),
            ])
        })
        .collect();
    object(&[
        ("sources", strings(&result.sources)),
        ("reachable", array(&reachable)),
        ("unreachable", strings(&result.unreachable)),
    ])
}

fn render_ksp(result: &KspOutput) -> String {
    let paths: Vec<String> = result
        .paths
        .iter()
        .map(|path| {
            object(&[
                ("cost", path.cost.to_string()),
                ("hops", path.hops.to_string()),
                ("nodes", strings(&path.nodes)),
            ])
        })
        .collect();
    object(&[
        ("source", string(&result.source)),
        ("target", string(&result.target)),
        ("requested", result.requested.to_string()),
        ("min_distinct_arcs", result.min_distinct_arcs.to_string()),
        ("enumerated", result.enumerated.to_string()),
        (
            "rejected_for_diversity",
            result.rejected_for_diversity.to_string(),
        ),
        ("stop", string(result.stop.as_str())),
        ("paths", array(&paths)),
    ])
}

fn render_zset(
    result: &ZSetMaintenanceOutput,
    base_commit: u64,
    head_commit: u64,
    incremental: bool,
    node_delta_count: usize,
    arc_delta_count: usize,
) -> String {
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
        ("base_commit_sequence", base_commit.to_string()),
        ("head_commit_sequence", head_commit.to_string()),
        ("incremental", incremental.to_string()),
        ("node_delta_count", node_delta_count.to_string()),
        ("arc_delta_count", arc_delta_count.to_string()),
        (
            "two_hop_delta_count",
            result.two_hop_delta_count.to_string(),
        ),
        ("delta_records", array(&deltas)),
    ])
}
