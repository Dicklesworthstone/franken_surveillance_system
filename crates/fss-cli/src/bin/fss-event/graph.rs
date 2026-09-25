#![forbid(unsafe_code)]
//! `fss-event graph single-points`: read-only, certified single points of failure of a
//! deployment's retained coverage (`ALG-BRIDGE-001` over the `SensorCoverageGraph` projection).
//!
//! The deployment is read at its committed head through the same read-only snapshot as `fss
//! orient` (nothing is written, locked, or repaired). The report names the projection, every
//! zone's observers and single points of failure, every sensor whose loss leaves some zone without
//! a retained witness, the raw cut vertices and bridges, the registered complexity bound, and the
//! `fss.graph_algorithm_witness.v1` witness of the run. It is derived cognition and grants no
//! authority.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::GraphAlgorithmWitness;
use fss_graph_algorithms::coverage::PROJECTION_KIND;
use fss_graph_algorithms::registry;
use fss_reference::coverage_graph::{CoverageGraphReport, read_coverage_single_points};

/// Report format tag (`SCHEMA-DOMAIN-COVERAGE-SINGLE-POINTS-001`).
const FORMAT: &str = "fss.coverage_single_points.v1";

#[derive(Debug)]
struct Request {
    root: PathBuf,
    site: String,
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("single-points") => {}
        Some(other) => {
            return Err(format!(
                "unknown graph command {other:?}; expected single-points"
            ));
        }
        None => return Err("graph requires a command: single-points".into()),
    }
    let mut root = None;
    let mut site = None;
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("required value for {key}"))?;
        match key {
            "--root" if root.is_none() => root = Some(PathBuf::from(value)),
            "--site" if site.is_none() => {
                site = Some(value.to_str().ok_or("--site requires UTF-8")?.to_owned());
            }
            "--root" | "--site" => return Err(format!("duplicate option {key}")),
            _ => return Err(format!("unknown option {key} for graph single-points")),
        }
        index += 2;
    }
    Ok(Request {
        root: root.ok_or("required option --root")?,
        site: site.ok_or("required option --site")?,
    })
}

fn counts(values: &BTreeMap<String, u64>) -> String {
    let fields: Vec<String> = values
        .iter()
        .map(|(name, value)| format!("{}:{value}", string(name)))
        .collect();
    format!("{{{}}}", fields.join(","))
}

/// `GraphAlgorithmWitness` as `fss.graph_algorithm_witness.v1`, in schema field order.
fn witness(value: &GraphAlgorithmWitness) -> String {
    object(&[
        ("schema", string(GraphAlgorithmWitness::SCHEMA)),
        ("algorithmId", string(value.algorithm_id())),
        ("implementationId", string(value.implementation_id())),
        ("projectionId", string(value.projection_id())),
        ("anchor", evidence_anchor(value.anchor())),
        ("nodeCount", value.node_count().to_string()),
        ("edgeCount", value.edge_count().to_string()),
        ("inputDigest", string(&value.input_digest().to_text())),
        ("policyId", string(value.policy_id())),
        (
            "dominantOperationCounts",
            counts(value.dominant_operation_counts()),
        ),
        ("peakWorkingBytes", value.peak_working_bytes().to_string()),
        ("budgetConsumed", counts(value.budget_consumed())),
        ("exactness", string(value.exactness())),
        (
            "errorBound",
            value
                .error_bound()
                .filter(|bound| bound.is_finite())
                .map_or_else(|| "null".to_owned(), |bound| format!("{bound}")),
        ),
        ("stopReason", string(value.stop_reason())),
        (
            "decisionPathDigest",
            string(&value.decision_path_digest().to_text()),
        ),
        ("outputDigest", string(&value.output_digest().to_text())),
    ])
}

fn report(value: &CoverageGraphReport) -> String {
    let analysis = &value.answer.analysis;
    let zones: Vec<String> = value
        .answer
        .zones
        .iter()
        .map(|zone| {
            object(&[
                ("scope", string(&zone.scope)),
                ("state", string(zone.state.as_str())),
                ("observers", strings(&zone.observers)),
                (
                    "single_points_of_failure",
                    strings(&zone.single_points_of_failure),
                ),
                ("retained_witnesses", zone.witnesses.to_string()),
            ])
        })
        .collect();
    let sensors: Vec<String> = value
        .answer
        .sensors
        .iter()
        .map(|sensor| {
            object(&[
                ("sensor_id", string(&sensor.sensor_id)),
                ("sole_observer_of", strings(&sensor.sole_observer_of)),
                ("uplink_is_bridge", sensor.uplink_is_bridge.to_string()),
            ])
        })
        .collect();
    let bridges: Vec<String> = analysis
        .output
        .bridges
        .iter()
        .map(|(a, b)| strings([a, b]))
        .collect();
    let bound = &analysis.bound;
    object(&[
        ("format", string(FORMAT)),
        ("site", string(&value.site)),
        ("anchor", evidence_anchor(&value.anchor)),
        (
            "projection",
            object(&[
                ("kind", string(PROJECTION_KIND)),
                ("projection_id", string(&value.projection_id)),
                ("input_digest", string(&analysis.input_digest.to_text())),
                ("node_count", analysis.node_count.to_string()),
                ("edge_count", analysis.edge_count.to_string()),
                ("retained_coverage_records", value.records.to_string()),
                ("root", string(&value.projection.plane)),
                (
                    "edge_predicate",
                    string(
                        "plane--sensor for every sensor with retained coverage; sensor--zone iff the \
                         sensor holds at least one retained coverage witness for the zone scope",
                    ),
                ),
                ("witness_intervals_intersected", "false".to_owned()),
                ("failure_domains_modelled", strings(["sensor"])),
                (
                    "failure_domains_not_modelled",
                    strings(["network", "power", "clock", "host"]),
                ),
            ]),
        ),
        ("zones", array(&zones)),
        ("sensors", array(&sensors)),
        (
            "algorithm",
            object(&[
                ("id", string(registry::ALGORITHM_ID)),
                ("name", string(registry::ALGORITHM_NAME)),
                ("tie_break_policy_id", string(registry::TIE_BREAK_POLICY_ID)),
                ("complexity_bound_id", string(registry::COMPLEXITY_BOUND_ID)),
                (
                    "articulation_points",
                    strings(&analysis.output.articulation_points),
                ),
                ("bridges", array(&bridges)),
                (
                    "unreachable_from_root",
                    strings(&analysis.output.unreachable_from_root),
                ),
                (
                    "complexity_bound",
                    object(&[
                        ("dfs_node_visits", bound.dfs_node_visits.to_string()),
                        ("adjacency_scans", bound.adjacency_scans.to_string()),
                        ("low_link_updates", bound.low_link_updates.to_string()),
                        ("tree_edges", bound.tree_edges.to_string()),
                    ]),
                ),
                ("within_bound", "true".to_owned()),
            ]),
        ),
        ("witness", witness(&value.witness)),
        ("witness_digest", string(&value.witness.digest().to_text())),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "claim",
            string(
                "structural single points over retained coverage witnesses at the anchor; not \
                 current observability, not absence, not a resilience certificate",
            ),
        ),
        ("qualification", string("implemented_not_qualified")),
    ])
}

/// Runs `fss-event graph ...` with the arguments after `graph`.
pub(super) fn main(args: &[OsString]) -> ExitCode {
    let request = match parse(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match read_coverage_single_points(&request.root, &request.site) {
        Ok(value) => {
            let mut out = io::stdout().lock();
            match writeln!(out, "{}", report(&value)) {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
            }
        }
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            if let Some(id) = error.stable_id() {
                eprintln!("refusal_id={id}");
            }
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
