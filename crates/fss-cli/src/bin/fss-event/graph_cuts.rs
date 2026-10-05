#![forbid(unsafe_code)]
//! Operator-facing bounded joint-dependency loss, using the existing registered solver.
//! Owner assertions are not measured topology; no result grants effect or absence authority.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{CaptureInterval, GraphAlgorithmWitness, TimestampNs};
use fss_graph_algorithms::GraphBudget;
use fss_graph_algorithms::failure_domains::combinations::{
    MAX_FAILURE_COMBINATIONS, ZoneFailureMinimum, analyse_failure_combinations,
};
use fss_graph_algorithms::failure_domains::{
    FailureDomain, FailureDomainKind, MAX_DOMAIN_MEMBERS, MAX_FAILURE_DOMAINS,
    MAX_FAILURE_OPERATIONS, MAX_FAILURE_OUTPUT_ENTRIES,
};
use fss_reference::coverage_graph::{CoverageGraphReport, read_coverage_single_points_during};

#[path = "graph_cuts_timeline.rs"]
mod timeline;

const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const HELP: &str = "fss-event graph failure-cuts --root DIR --site SITE --during START_NS:END_NS\n\
  [--timeline] --max-failed-domains K --failure-domain KIND:ID=SENSOR[,SENSOR...] (repeatable)\n\
  Enumerates EVERY nonempty combination of up to K declared dependencies. A sensor\n\
  shared by several failed dependencies is removed once, not treated as an alternate route.\n\
  KIND: network, power, clock, or host. Use exact sensor IDs from retained coverage.\n\
  Reports the minimum declared-domain cut per zone, its failed sensors and checked\n\
  ALG-BRIDGE-001 witness. Zones without qualifying witnesses remain explicitly unknown.\n\
  --during uses inclusive signed 128-bit capture nanoseconds, including point windows.\n\
  Each qualifying witness must cover the whole window; capture hints are NOT calibrated\n\
  clock alignment. A no-cut-within-bound result is NOT an independence certificate.\n\
  --timeline instead splits at every certain witness boundary and evaluates the full\n\
  failure family in EACH segment, including unwitnessed intervals and camera handovers.\n\
  One pinned snapshot and one aggregate budget cover ALL segments (at most 256).\n\
  Reads one committed snapshot. No mutation, repair, persisted declaration or effect.\n\
  Limits: 16 declarations, 1024 members each, 256 combinations, 1000000 aggregate\n\
  graph/enumeration operations, 100000 output entries, 8 MiB. No partial report.\n";

#[derive(Debug)]
struct Request {
    root: PathBuf,
    site: String,
    window: CaptureInterval,
    maximum: usize,
    domains: Vec<FailureDomain>,
    timeline: bool,
}

fn domain(value: &str) -> Result<FailureDomain, String> {
    if value.len() > 80 + MAX_DOMAIN_MEMBERS * 513 {
        return Err("failure declaration exceeds its byte limit".into());
    }
    let (label, members) = value
        .split_once('=')
        .ok_or("--failure-domain requires KIND:ID=SENSOR[,SENSOR...]")?;
    let (kind, id) = label.split_once(':').ok_or("failure domain requires KIND:ID")?;
    let kind = match kind {
        "network" => FailureDomainKind::Network,
        "power" => FailureDomainKind::Power,
        "clock" => FailureDomainKind::Clock,
        "host" => FailureDomainKind::Host,
        _ => return Err("failure kind must be network, power, clock, or host".into()),
    };
    let members: Vec<String> = members
        .split(',')
        .take(MAX_DOMAIN_MEMBERS + 1)
        .map(str::to_owned)
        .collect();
    FailureDomain::new(kind, id, &members).map_err(|error| error.to_string())
}

// Validate the complete family before opening the deployment. The solver repeats admission;
// this check never substitutes for its own validation or silently reduces the requested K.
fn admitted_count(domains: usize, maximum: usize) -> Result<usize, String> {
    if domains > MAX_FAILURE_DOMAINS || maximum == 0 || maximum > domains {
        return Err("--max-failed-domains must be in 1..=number of declared domains".into());
    }
    let mut choose = 1;
    let mut total = 0;
    for size in 1..=maximum {
        choose = choose * (domains + 1 - size) / size;
        total += choose;
        if total > MAX_FAILURE_COMBINATIONS {
            return Err("complete requested family exceeds 256 combinations; reduce K explicitly".into());
        }
    }
    Ok(total)
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    if args.first().and_then(|arg| arg.to_str()) != Some("failure-cuts") {
        return Err("expected graph failure-cuts".into());
    }
    let mut root = None;
    let mut site = None;
    let mut window = None;
    let mut maximum = None;
    let mut domains: Vec<FailureDomain> = Vec::new();
    let mut timeline = false;
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if key == "--timeline" {
            if timeline {
                return Err("duplicate option --timeline".into());
            }
            timeline = true;
            index += 1;
            continue;
        }
        let value = args.get(index + 1).ok_or_else(|| format!("required value for {key}"))?;
        if key == "--root" && root.is_none() {
            root = Some(PathBuf::from(value));
            index += 2;
            continue;
        }
        let value = value.to_str().ok_or_else(|| format!("{key} requires UTF-8"))?;
        match key {
            "--site" if site.is_none() => {
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                    return Err("invalid site lineage".into());
                }
                site = Some(value.to_owned());
            }
            "--during" if window.is_none() => {
                let (first, last) = value.split_once(':').ok_or("--during requires START_NS:END_NS")?;
                let first = first.parse::<i128>().map_err(|_| "invalid capture start")?;
                let last = last.parse::<i128>().map_err(|_| "invalid capture end")?;
                window = Some(CaptureInterval::new(TimestampNs(first), TimestampNs(last))
                    .map_err(|_| "capture start must not exceed end")?);
            }
            "--max-failed-domains" if maximum.is_none() => {
                maximum = Some(value.parse::<usize>().map_err(|_| "invalid maximum failed domains")?);
            }
            "--failure-domain" => {
                if domains.len() == MAX_FAILURE_DOMAINS {
                    return Err("at most 16 failure domains are allowed".into());
                }
                let next = domain(value)?;
                if domains.iter().any(|prior| prior.kind() == next.kind() && prior.id() == next.id()) {
                    return Err("duplicate failure domain".into());
                }
                domains.push(next);
            }
            "--root" | "--site" | "--during" | "--max-failed-domains" => {
                return Err(format!("duplicate option {key}"));
            }
            _ => return Err(format!("unknown option {key}")),
        }
        index += 2;
    }
    let maximum = maximum.ok_or("required option --max-failed-domains")?;
    admitted_count(domains.len(), maximum)?;
    Ok(Request {
        root: root.ok_or("required option --root")?,
        site: site.ok_or("required option --site")?,
        window: window.ok_or("required option --during")?,
        maximum,
        domains,
        timeline,
    })
}

fn budget() -> GraphBudget {
    GraphBudget {
        max_operations: MAX_FAILURE_OPERATIONS,
        max_output_entries: MAX_FAILURE_OUTPUT_ENTRIES,
    }
}

fn counts(values: &BTreeMap<String, u64>) -> String {
    let fields: Vec<String> = values.iter().map(|(name, value)| format!("{}:{value}", string(name))).collect();
    format!("{{{}}}", fields.join(","))
}

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
        ("dominantOperationCounts", counts(value.dominant_operation_counts())),
        ("peakWorkingBytes", value.peak_working_bytes().to_string()),
        ("budgetConsumed", counts(value.budget_consumed())),
        ("exactness", string(value.exactness())),
        ("errorBound", value.error_bound().filter(|v| v.is_finite()).map_or_else(|| "null".into(), |v| v.to_string())),
        ("stopReason", string(value.stop_reason())),
        ("decisionPathDigest", string(&value.decision_path_digest().to_text())),
        ("outputDigest", string(&value.output_digest().to_text())),
    ])
}

fn capture_window(window: CaptureInterval) -> String {
    object(&[
        ("start_ns", string(&window.earliest.0.to_string())),
        ("end_ns", string(&window.latest.0.to_string())),
        ("endpoints", string("inclusive")),
    ])
}

struct Rendered {
    json: String,
    operations: u64,
    output_entries: u64,
}

fn combinations(
    value: &CoverageGraphReport,
    domains: &[FailureDomain],
    maximum: usize,
    limit: GraphBudget,
    max_bytes: usize,
) -> Result<Rendered, String> {
    let max_bytes = max_bytes.min(MAX_REPORT_BYTES);
    // The algorithm requires the parent WITNESS, not just a graph digest. Verify the binding
    // before deriving child witnesses so public report fields cannot substitute a different input.
    if value.witness.anchor() != &value.anchor
        || value.witness.projection_id() != value.projection_id.as_str()
        || value.witness.input_digest().to_text() != value.projection.graph.digest().to_text()
    {
        return Err("ERR-GRAPH-INPUT-INVALID-001: parent witness does not bind this coverage projection".into());
    }
    fss_graph_algorithms::bridges::check_witness_bound(&value.witness)
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let result = analyse_failure_combinations(&value.projection, domains, maximum, limit)
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let parent = value.witness.digest();
    let declarations: Vec<String> = result.domains.iter().map(|domain| object(&[
        ("kind", string(domain.kind().as_str())),
        ("id", string(domain.id())),
        ("members", strings(domain.members())),
    ])).collect();
    let mut rows = Vec::with_capacity(result.scenarios.len());
    let mut bytes = 0_usize;
    for (index, scenario) in result.scenarios.iter().enumerate() {
        let projection_id = result.projection_id(index, parent).map_err(|error| error.to_string())?;
        let bound = scenario.analysis.witness(&projection_id, value.anchor.clone())
            .map_err(|error| format!("combination witness rejected: {error:?}"))?;
        fss_graph_algorithms::bridges::check_witness_bound(&bound)
            .map_err(|error| format!("{}: {error}", error.stable_id()))?;
        let indices: Vec<String> = scenario.domain_indices.iter().map(usize::to_string).collect();
        let row = object(&[
            ("index", index.to_string()),
            ("domain_indices", array(&indices)),
            ("domain_mask", string(&format!("{:04x}", scenario.domain_mask))),
            ("failed_sensors", strings(&scenario.failed_sensors)),
            ("lost_zones", strings(&scenario.lost_zones)),
            ("witness", witness(&bound)),
            ("witness_digest", string(&bound.digest().to_text())),
        ]);
        bytes = bytes.checked_add(row.len() + 1).ok_or("report size overflow")?;
        if bytes > max_bytes {
            return Err("ERR-GRAPH-BUDGET-EXHAUSTED-001: failure-cut report exceeds byte limit".into());
        }
        rows.push(row);
    }
    let zones: Vec<String> = result.zones.iter().map(|(scope, minimum)| {
        let (state, count, index) = match minimum {
            ZoneFailureMinimum::InitiallyUnwitnessed => ("initially_unwitnessed", "null".into(), "null".into()),
            ZoneFailureMinimum::NoCutWithinBound => ("no_cut_within_bound", "null".into(), "null".into()),
            ZoneFailureMinimum::Cut { failed_domains, scenario_index } => ("cut", failed_domains.to_string(), scenario_index.to_string()),
        };
        object(&[
            ("scope", string(scope)),
            ("state", string(state)),
            ("minimum_failed_domains", count),
            ("scenario_index", index),
        ])
    }).collect();
    let json = object(&[
        ("parent_witness", witness(&value.witness)),
        ("parent_witness_digest", string(&parent.to_text())),
        ("coverage_digest", string(&result.coverage_digest.to_text())),
        ("declarations_digest", string(&result.declarations_digest.to_text())),
        ("max_failed_domains", maximum.to_string()),
        ("declarations", array(&declarations)),
        ("scenario_count", rows.len().to_string()),
        ("scenarios", array(&rows)),
        ("zones", array(&zones)),
        ("operations", result.operations.to_string()),
        ("output_entries", result.output_entries.to_string()),
        ("completion", string("complete_within_declared_bound")),
        ("declaration_basis", string("owner_assertion_not_verified_topology")),
        ("independence", string("unknown")),
        ("undeclared_dependencies", string("unknown_not_absent")),
        ("authority", string("derived_cognition_no_effect_authority")),
    ]);
    if json.len() > max_bytes {
        return Err("ERR-GRAPH-BUDGET-EXHAUSTED-001: failure-cut report exceeds byte limit".into());
    }
    Ok(Rendered { json, operations: result.operations, output_entries: result.output_entries })
}

fn render_single(value: &CoverageGraphReport, request: &Request, limit: GraphBudget, max_bytes: usize) -> Result<String, String> {
    let limit = GraphBudget {
        max_operations: limit.max_operations.min(budget().max_operations),
        max_output_entries: limit.max_output_entries.min(budget().max_output_entries),
    };
    let operations = value.answer.analysis.operations;
    let output_entries = value.answer.analysis.output_entries;
    if operations > limit.max_operations || output_entries > limit.max_output_entries {
        return Err("ERR-GRAPH-BUDGET-EXHAUSTED-001: parent exceeds request budget".into());
    }
    let result = combinations(value, &request.domains, request.maximum, GraphBudget {
        max_operations: limit.max_operations - operations,
        max_output_entries: limit.max_output_entries - output_entries,
    }, max_bytes)?;
    let json = object(&[
        ("format", string("fss.coverage_failure_cuts.v1")),
        ("site", string(&value.site)),
        ("anchor", evidence_anchor(&value.anchor)),
        ("capture_window", capture_window(request.window)),
        ("selection", string("whole-witness-v1")),
        ("clock_alignment", string("operator_hints_not_calibration")),
        ("result", result.json),
        ("operations", (operations + result.operations).to_string()),
        ("output_entries", (output_entries + result.output_entries).to_string()),
        ("qualification", string("implemented_not_qualified")),
        ("claim", string("conditional loss of retained qualifying witnesses; not current availability, calibrated clock alignment, independence, sensor failure or evidence of absence")),
    ]);
    if json.len() > max_bytes.min(MAX_REPORT_BYTES) {
        return Err("ERR-GRAPH-BUDGET-EXHAUSTED-001: complete report exceeds byte limit".into());
    }
    Ok(json)
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [command, flag] if command.to_str() == Some("failure-cuts") && matches!(flag.to_str(), Some("--help" | "-h"))) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let request = match parse(args) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event graph failure-cuts --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let rendered = if request.timeline {
        timeline::run(&request)
    } else {
        read_coverage_single_points_during(&request.root, &request.site, request.window)
            .map_err(|error| format!("{}: {error}", error.stable_id().unwrap_or(ERR_CLI_RUNTIME_FAILURE)))
            .and_then(|value| render_single(&value, &request, budget(), MAX_REPORT_BYTES))
    };
    match rendered {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::LedgerAnchor;
    use fss_graph_algorithms::{CoverageObservation, SensorCoverageProjection};

    fn sample(context: &str) -> Result<CoverageGraphReport, Box<dyn std::error::Error>> {
        let projection = SensorCoverageProjection::build("site:test", &[
            CoverageObservation { sensor_id: "a".into(), zone_scope: "door".into(), witnesses: 1 },
            CoverageObservation { sensor_id: "b".into(), zone_scope: "door".into(), witnesses: 1 },
            CoverageObservation { sensor_id: "c".into(), zone_scope: "blind".into(), witnesses: 0 },
        ])?;
        let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
        let anchor = LedgerAnchor::genesis("site:test");
        let witness = answer.analysis.witness(context, anchor.clone())?;
        Ok(CoverageGraphReport { site: "site:test".into(), anchor, projection_id: context.into(), records: 3, projection, answer, witness })
    }

    fn args() -> Vec<OsString> {
        ["failure-cuts", "--root", "not-opened", "--site", "site:test", "--during", "-10:10", "--max-failed-domains", "2", "--failure-domain", "power:left=a", "--failure-domain", "network:right=b"].into_iter().map(Into::into).collect()
    }

    #[test]
    fn joint_cut_is_reachable_and_unknown_zones_are_not_new_losses() -> Result<(), Box<dyn std::error::Error>> {
        let value = sample("test-parent")?;
        let request = parse(&args())?;
        let joint = combinations(&value, &request.domains, 2, budget(), MAX_REPORT_BYTES)?;
        assert!(joint.json.contains("\"scenario_count\":3"));
        assert!(joint.json.contains("\"minimum_failed_domains\":2"));
        assert!(joint.json.contains("\"failed_sensors\":[\"a\",\"b\"]"));
        assert!(joint.json.contains("\"state\":\"initially_unwitnessed\""));
        assert!(!joint.json.contains("\"lost_zones\":[\"blind\""));
        let singles = combinations(&value, &request.domains, 1, budget(), MAX_REPORT_BYTES)?;
        assert!(singles.json.contains("\"state\":\"no_cut_within_bound\""));
        assert!(singles.json.contains("\"independence\":\"unknown\""));
        Ok(())
    }

    #[test]
    fn canonical_declarations_and_parent_binding_survive_rendering() -> Result<(), Box<dyn std::error::Error>> {
        let first = sample("capture:-10:10")?;
        let second = sample("capture:-20:20")?;
        let request = parse(&args())?;
        let a = combinations(&first, &request.domains, 2, budget(), MAX_REPORT_BYTES)?.json;
        let mut reversed = request.domains.clone();
        reversed.reverse();
        assert_eq!(a, combinations(&first, &reversed, 2, budget(), MAX_REPORT_BYTES)?.json);
        assert_ne!(a, combinations(&second, &reversed, 2, budget(), MAX_REPORT_BYTES)?.json);
        let mut substituted = first;
        substituted.anchor.commit_sequence += 1;
        assert!(combinations(&substituted, &reversed, 2, budget(), MAX_REPORT_BYTES).is_err());
        Ok(())
    }

    #[test]
    fn one_budget_covers_all_scenarios_and_the_complete_report() -> Result<(), Box<dyn std::error::Error>> {
        let value = sample("test-parent")?;
        let request = parse(&args())?;
        let result = combinations(&value, &request.domains, 2, budget(), MAX_REPORT_BYTES)?;
        let exact = GraphBudget { max_operations: result.operations, max_output_entries: result.output_entries };
        assert_eq!(result.json, combinations(&value, &request.domains, 2, exact, result.json.len())?.json);
        for limited in [GraphBudget { max_operations: exact.max_operations - 1, ..exact }, GraphBudget { max_output_entries: exact.max_output_entries - 1, ..exact }] {
            assert!(combinations(&value, &request.domains, 2, limited, MAX_REPORT_BYTES).is_err());
        }
        assert!(combinations(&value, &request.domains, 2, budget(), result.json.len() - 1).is_err());
        let full = render_single(&value, &request, budget(), MAX_REPORT_BYTES)?;
        assert!(render_single(&value, &request, budget(), full.len() - 1).is_err());
        assert!(combinations(&value, &[domain("power:x=missing")?], 1, budget(), MAX_REPORT_BYTES).is_err());
        Ok(())
    }

    #[test]
    fn malformed_and_oversized_requests_fail_before_io() -> Result<(), String> {
        assert_eq!(parse(&args())?.maximum, 2);
        assert!(!parse(&args())?.timeline);
        let mut temporal = args();
        temporal.push("--timeline".into());
        assert!(parse(&temporal)?.timeline);
        temporal.push("--timeline".into());
        assert!(parse(&temporal).is_err());
        for extra in [["--during", "0:1"], ["--max-failed-domains", "1"], ["--failure-domain", "power:left=b"], ["--surprise", "x"]] {
            let mut invalid = args();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid).is_err());
        }
        for malformed in ["", "network:x=", "power:x=a,a", "power:x=a,", "wrong:x=a", "power:=a"] {
            assert!(domain(malformed).is_err());
        }
        assert_eq!(admitted_count(16, 2)?, 136);
        assert!(admitted_count(16, 3).is_err());
        assert!(admitted_count(0, 1).is_err());
        assert!(admitted_count(2, 0).is_err());
        assert!(admitted_count(2, 3).is_err());
        Ok(())
    }
}
