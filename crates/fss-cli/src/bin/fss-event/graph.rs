#![forbid(unsafe_code)]
//! Read-only retained coverage single points, with optional owner-declared common failures.
//!
//! One committed snapshot supplies all facts. `--during` selects whole certain witnesses,
//! never uncertainty hulls or unions of partial intervals. Optional shared-failure scenarios
//! use this same projection and bind its complete algorithm witness, including window and
//! anchor. Nothing is written, locked, repaired, or authorized.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{CaptureInterval, GraphAlgorithmWitness, TimestampNs};
use fss_graph_algorithms::coverage::PROJECTION_KIND;
use fss_graph_algorithms::failure_domains::{FailureDomain, MAX_FAILURE_DOMAINS};
use fss_graph_algorithms::registry;
use fss_reference::coverage_graph::{
    CoverageGraphReport, read_coverage_single_points, read_coverage_single_points_during,
};

#[path = "graph_failures.rs"]
mod shared_failures;

/// Report format tag (`SCHEMA-DOMAIN-COVERAGE-SINGLE-POINTS-001`).
const FORMAT: &str = "fss.coverage_single_points.v1";

const HELP: &str = "fss-event graph single-points --root DIR --site SITE [--during START_NS:END_NS]\n\
  Reads one committed snapshot without writing or granting authority.\n\
  Without --during: structural single points over all retained witness history.\n\
  --during: signed integer capture nanoseconds, inclusive, START_NS <= END_NS.\n\
  START_NS == END_NS queries one instant. Each sensor--zone edge requires one witness\n\
  whose certain covered bounds contain the WHOLE window. Uncertainty hulls and unions\n\
  of partial witnesses do not qualify; zones with zero qualifying witnesses remain explicit.\n\
  Endpoints and the selection rule are bound into the projection and algorithm witness.\n\
  Capture clocks are operator hints, not calibrated alignment. Not current observability,\n\
  absence, or a resilience certificate; the base projection models only sensor failures.\n\
  --failure-domain KIND:ID=SENSOR[,SENSOR...] (repeatable, at most 16 domains):\n\
  KIND is network, power, clock, or host. IDs are owner labels (1..64 UTF-8 bytes).\n\
  Each domain has 1..1024 unique sensors present in retained coverage. Unknown sensors,\n\
  duplicate domains/members and empty values are refused. Sensor IDs may contain colons,\n\
  but commas delimit members. All members of ONE domain are removed simultaneously.\n\
  Overlapping domains are tested separately, not as alternative power/network routes.\n\
  Results appear in shared_failure_scenarios with separate ALG-BRIDGE-001 witnesses\n\
  bound to the base witness. Declarations are assertions, not verified topology; omitted\n\
  dependencies and independence remain UNKNOWN. No declaration or effect is persisted.\n\
  Limits: 8192 sensor/zone facts, 1000000 aggregate traversal operations, 100000 emitted\n\
  identities, 8 MiB report with scenarios. Without this option, report bytes are unchanged.\n";

fn help_requested(args: &[OsString]) -> bool {
    match args {
        [flag] => matches!(flag.to_str(), Some("help" | "--help" | "-h")),
        [command, flag] => {
            command.to_str() == Some("single-points")
                && matches!(flag.to_str(), Some("--help" | "-h"))
        }
        _ => false,
    }
}

#[derive(Debug)]
struct Request {
    root: PathBuf,
    site: String,
    window: Option<CaptureInterval>,
    domains: Vec<FailureDomain>,
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
    let mut window = None;
    let mut domains: Vec<FailureDomain> = Vec::new();
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
            "--during" if window.is_none() => {
                window = Some(capture_window(
                    value.to_str().ok_or("--during requires UTF-8")?,
                )?);
            }
            "--failure-domain" => {
                if domains.len() == MAX_FAILURE_DOMAINS {
                    return Err("at most 16 failure domains are allowed".to_owned());
                }
                let domain = shared_failures::parse_domain(
                    value.to_str().ok_or("--failure-domain requires UTF-8")?,
                )?;
                if domains
                    .iter()
                    .any(|prior| prior.kind() == domain.kind() && prior.id() == domain.id())
                {
                    return Err(format!(
                        "duplicate failure domain {}:{}",
                        domain.kind().as_str(),
                        domain.id()
                    ));
                }
                domains.push(domain);
            }
            "--root" | "--site" | "--during" => return Err(format!("duplicate option {key}")),
            _ => return Err(format!("unknown option {key} for graph single-points")),
        }
        index += 2;
    }
    Ok(Request {
        root: root.ok_or("required option --root")?,
        site: site.ok_or("required option --site")?,
        window,
        domains,
    })
}

/// Inclusive signed nanoseconds in the recordings' declared capture-time coordinate system.
fn capture_window(value: &str) -> Result<CaptureInterval, String> {
    let (first, last) = value
        .split_once(':')
        .ok_or("--during requires START_NS:END_NS")?;
    let first = first
        .parse::<i128>()
        .map_err(|_| "--during start must be signed integer nanoseconds")?;
    let last = last
        .parse::<i128>()
        .map_err(|_| "--during end must be signed integer nanoseconds")?;
    CaptureInterval::new(TimestampNs(first), TimestampNs(last))
        .map_err(|_| "--during requires START_NS <= END_NS".to_owned())
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

fn projection(value: &CoverageGraphReport, window: Option<CaptureInterval>) -> String {
    let analysis = &value.answer.analysis;
    let mut fields = vec![
        ("kind", string(PROJECTION_KIND)),
        ("projection_id", string(&value.projection_id)),
        ("input_digest", string(&analysis.input_digest.to_text())),
        ("node_count", analysis.node_count.to_string()),
        ("edge_count", analysis.edge_count.to_string()),
        ("retained_coverage_records", value.records.to_string()),
        ("root", string(&value.projection.plane)),
        (
            "edge_predicate",
            string(match window {
                None => {
                    "plane--sensor for every sensor with retained coverage; sensor--zone iff the \
                     sensor holds at least one retained coverage witness for the zone scope"
                }
                Some(_) => {
                    "plane--sensor for every sensor with retained coverage; sensor--zone iff \
                        at least one witness covers the entire capture window with certain bounds"
                }
            }),
        ),
        (
            "witness_intervals_intersected",
            window.is_some().to_string(),
        ),
        ("failure_domains_modelled", strings(["sensor"])),
        (
            "failure_domains_not_modelled",
            strings(["network", "power", "clock", "host"]),
        ),
    ];
    if let Some(window) = window {
        fields.push((
            "capture_window",
            object(&[
                // Decimal strings preserve all 128 timestamp bits in JavaScript consumers too.
                ("start_ns", string(&window.earliest.0.to_string())),
                ("end_ns", string(&window.latest.0.to_string())),
                ("endpoints", string("inclusive")),
                ("selection", string("whole-witness-v1")),
                ("partial_witness_union", "false".to_owned()),
                ("clock_alignment", string("operator_hints_not_calibration")),
            ]),
        ));
    }
    object(&fields)
}

fn report(value: &CoverageGraphReport, window: Option<CaptureInterval>) -> String {
    report_with_failures(value, window, None)
}

fn report_with_failures(
    value: &CoverageGraphReport,
    window: Option<CaptureInterval>,
    shared: Option<String>,
) -> String {
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
    let mut fields = vec![
        ("format", string(FORMAT)),
        ("site", string(&value.site)),
        ("anchor", evidence_anchor(&value.anchor)),
        ("projection", projection(value, window)),
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
            string(match window {
                None => {
                    "structural single points over retained coverage witnesses at the anchor; not \
                     current observability, not absence, not a resilience certificate"
                }
                Some(_) => {
                    "structural single points over retained witnesses covering the whole capture \
                        window; conditional on operator capture hints, not calibrated clock alignment, \
                        current observability, absence, or a resilience certificate"
                }
            }),
        ),
        ("qualification", string("implemented_not_qualified")),
    ];
    if let Some(shared) = shared {
        fields.push(("shared_failure_scenarios", shared));
    }
    object(&fields)
}

/// Runs `fss-event graph ...` with the arguments after `graph`.
pub(super) fn main(args: &[OsString]) -> ExitCode {
    if help_requested(args) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let request = match parse(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = match request.window {
        None => read_coverage_single_points(&request.root, &request.site),
        Some(window) => read_coverage_single_points_during(&request.root, &request.site, window),
    };
    match result {
        Ok(value) => {
            let rendered = if request.domains.is_empty() {
                report(&value, request.window)
            } else {
                let shared = match shared_failures::render(&value, &request.domains) {
                    Ok(shared) => shared,
                    Err(error) => {
                        eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                        return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
                    }
                };
                let rendered = report_with_failures(&value, request.window, Some(shared));
                if rendered.len() > shared_failures::MAX_REPORT_BYTES {
                    eprintln!(
                        "ERR-GRAPH-BUDGET-EXHAUSTED-001: shared failure report exceeds 8 MiB"
                    );
                    return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
                }
                rendered
            };
            let mut out = io::stdout().lock();
            match writeln!(out, "{rendered}") {
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

#[cfg(test)]
mod window_tests {
    use super::*;

    fn args(window: Option<&str>) -> Vec<OsString> {
        let mut args: Vec<OsString> = [
            "single-points",
            "--root",
            "/tmp/coverage",
            "--site",
            "site:test",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        if let Some(window) = window {
            args.extend(["--during".into(), window.into()]);
        }
        args
    }

    #[test]
    fn help_needs_no_deployment_and_does_not_match_option_values() {
        assert!(help_requested(&["single-points".into(), "--help".into()]));
        assert!(help_requested(&["help".into()]));
        assert!(!help_requested(&args(Some("1:2"))));
        assert!(!help_requested(&[
            "single-points".into(),
            "--root".into(),
            "help".into()
        ]));
    }

    #[test]
    fn historical_requests_still_have_no_window() -> Result<(), String> {
        assert!(parse(&args(None))?.window.is_none());
        assert!(parse(&args(None))?.domains.is_empty());
        Ok(())
    }

    #[test]
    fn parses_inclusive_signed_windows_and_point_queries() -> Result<(), String> {
        for (text, first, last) in [("-20:30", -20, 30), ("7:7", 7, 7), ("0:1", 0, 1)] {
            let request = parse(&args(Some(text)))?;
            let window = request.window.ok_or("missing parsed window")?;
            assert_eq!(window.earliest, TimestampNs(first));
            assert_eq!(window.latest, TimestampNs(last));
        }
        Ok(())
    }

    #[test]
    fn refuses_malformed_inverted_or_out_of_range_windows() {
        for text in [
            "",
            "1",
            ":2",
            "1:",
            "1:2:3",
            "2:1",
            "1.0:2",
            "NaN:2",
            "1:inf",
            "170141183460469231731687303715884105728:170141183460469231731687303715884105728",
        ] {
            assert!(parse(&args(Some(text))).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn accepts_full_timestamp_precision() -> Result<(), String> {
        let text = format!("{}:{}", i128::MIN, i128::MAX);
        let window = capture_window(&text)?;
        assert_eq!(window.earliest.0, i128::MIN);
        assert_eq!(window.latest.0, i128::MAX);
        Ok(())
    }

    #[test]
    fn duplicate_and_missing_windows_are_refused() {
        let mut duplicate = args(Some("1:2"));
        duplicate.extend(["--during".into(), "3:4".into()]);
        assert!(
            matches!(parse(&duplicate), Err(message) if message == "duplicate option --during")
        );
        let mut missing = args(None);
        missing.push("--during".into());
        assert!(parse(&missing).is_err());
        missing.extend(["--site".into(), "site:other".into()]);
        assert!(parse(&missing).is_err());
    }

    #[test]
    fn window_option_can_precede_the_deployment_arguments() -> Result<(), String> {
        let mut reordered: Vec<OsString> = ["single-points", "--during", "10:20"]
            .into_iter()
            .map(Into::into)
            .collect();
        reordered.extend(args(None).into_iter().skip(1));
        let request = parse(&reordered)?;
        assert_eq!(request.window, Some(capture_window("10:20")?));
        assert_eq!(request.root, PathBuf::from("/tmp/coverage"));
        Ok(())
    }

    fn sample() -> Result<CoverageGraphReport, Box<dyn std::error::Error>> {
        use fss_core::LedgerAnchor;
        use fss_graph_algorithms::{CoverageObservation, GraphBudget, SensorCoverageProjection};
        let projection = SensorCoverageProjection::build(
            "site:test",
            &[CoverageObservation {
                sensor_id: "sensor:east".to_owned(),
                zone_scope: "ground-zone:door".to_owned(),
                witnesses: 1,
            }],
        )?;
        let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
        let anchor = LedgerAnchor::genesis("site:test");
        let projection_id = format!("{PROJECTION_KIND}@commit:{}", anchor.commit_sequence);
        let witness = answer.analysis.witness(&projection_id, anchor.clone())?;
        Ok(CoverageGraphReport {
            site: "site:test".to_owned(),
            anchor,
            projection_id,
            records: 1,
            projection,
            answer,
            witness,
        })
    }

    #[test]
    fn historical_json_keeps_its_explicit_unintersected_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = sample()?;
        let json = report(&value, None);
        assert!(!json.contains("capture_window"));
        assert!(json.contains("\"witness_intervals_intersected\":false"));
        assert!(
            json.contains(
                "structural single points over retained coverage witnesses at the anchor"
            )
        );
        assert!(!json.contains("shared_failure_scenarios"));
        Ok(())
    }

    #[test]
    fn window_json_retains_exact_endpoints_and_conservative_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = sample()?;
        let window = capture_window("9007199254740993:9007199254741003")?;
        let json = report(&value, Some(window));
        assert!(json.contains("\"start_ns\":\"9007199254740993\""));
        assert!(json.contains("\"end_ns\":\"9007199254741003\""));
        assert!(json.contains("whole-witness-v1"));
        assert!(json.contains("\"partial_witness_union\":false"));
        assert!(json.contains("operator_hints_not_calibration"));
        assert!(json.contains("\"witness_intervals_intersected\":true"));
        Ok(())
    }

    #[test]
    fn shared_domains_can_overlap_but_duplicates_and_excess_are_refused() -> Result<(), String> {
        let mut input = args(Some("1:2"));
        input.extend([
            "--failure-domain".into(),
            "network:lan=sensor:a,sensor:b".into(),
            "--failure-domain".into(),
            "power:ups=sensor:b,sensor:c".into(),
        ]);
        assert_eq!(parse(&input)?.domains.len(), 2);
        input.extend(["--failure-domain".into(), "network:lan=sensor:a".into()]);
        assert!(matches!(parse(&input), Err(error) if error.contains("duplicate failure domain")));
        let mut input = args(None);
        for i in 0..=MAX_FAILURE_DOMAINS {
            input.extend([
                "--failure-domain".into(),
                format!("host:{i}=sensor:a").into(),
            ]);
        }
        assert!(parse(&input).is_err());
        Ok(())
    }
}
