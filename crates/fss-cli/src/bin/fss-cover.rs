#![forbid(unsafe_code)]
//! Read-only reference sensor/evidence selection over one pinned common capture window.
//! This is an operator query, not the universal fss/1 plan operation or an effect grant.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{
    CaptureInterval, ContentDigest, DigestAlgorithm, GraphAlgorithmWitness, TimestampNs,
};
use fss_graph_algorithms::set_cover::{
    CoverAnalysis, CoverBudget, CoverError, CoverMethod, CoverStatus, MAX_ELEMENTS, MAX_SETS,
    MAX_WORK_UNITS, SetCoverProblem,
};
use fss_reference::coverage_graph::{CoverageGraphReport, read_coverage_single_points_during};

#[path = "fss-cover/resilient.rs"]
mod resilient;

const FORMAT: &str = "fss.coverage_set_selection.v1";
const MAX_ARGS: usize = 513;
const MAX_ARG_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const HELP: &str = "fss-cover select --root DIR --site SITE --during START_NS:END_NS\n\
  --zone SCOPE [--zone SCOPE ...] (1..64 explicit zone:ID or ground-zone:ID scopes)\n\
  [--require-sensor ID ...] [--exclude-sensor ID ...]\n\
  [--method exact-small|greedy] [--max-sensors N] [--expected-coverage sha256:HEX]\n\
  [--work-units N] [--max-report-bytes N] [--timeout-ms N]\n\
\n\
  Read-only retained-evidence selection. No locks, writes, repairs, camera shutdown,\n\
  model invocation, effect preparation or authority grant. A common capture window\n\
  is REQUIRED: inclusive signed 128-bit nanoseconds, START <= END. One whole witness\n\
  must cover it with certain bounds. Partial-witness unions and history from different\n\
  times do not provide coverage. Capture coordinates are operator hints, not calibration.\n\
\n\
  Cost is ONE UNIT PER SELECTED SENSOR, not money, risk, confidence or information value.\n\
  exact-small (default) proves the minimum count with stable sensor-tuple ties; at most\n\
  20 eligible nonmandatory sensors. An oversized or exhausted exact request is refused,\n\
  never silently made greedy. Greedy supports up to 1024 sensors: largest remaining\n\
  zone gain, then stable sensor ID; a failed greedy selection does NOT prove infeasibility.\n\
  Mandatory sensors count against --max-sensors (default 1024, permitted 0..1024).\n\
  Unknown required/excluded sensors, duplicates and contradictory constraints are errors.\n\
  Unknown requested zones stay explicit as uncoverable. Empty selections are not absence.\n\
\n\
  Reports carry source and selection witnesses and exact anchors. --expected-coverage\n\
  optionally pins source_coverage_witness_digest from an earlier report. Uncovered zones\n\
  and heuristic_incomplete/infeasible_within_limit/uncoverable dispositions remain explicit.\n\
  Exit 0 means a complete QUERY report, not necessarily a feasible full cover.\n\
  Independent failures, current sensor health and live detection quality are NOT certified.\n\
\n\
  Bounds: 513 arguments, 4096 bytes each; 2 MiB report (default); 2000000 solver work\n\
  units (default; hard ceiling 50000000); timeout 30000 ms (default; 1..3600000).\n\
  Work units cover selection only, not the separately bounded source snapshot/projection.\n\
  Deadline checks bracket the existing source reader (filesystem reads are not preemptible)\n\
  and occur at every charged selection step. No partial report on an error.\n\
  Shared-failure selection: fss-cover select-resilient --help.\n\
  Reference candidate: Rust tests and production qualification have not been run.\n";

#[derive(Clone, Debug)]
struct Request {
    root: PathBuf,
    site: String,
    window: CaptureInterval,
    zones: Vec<String>,
    mandatory: Vec<String>,
    excluded: Vec<String>,
    maximum: usize,
    method: CoverMethod,
    budget: CoverBudget,
    expected: Option<ContentDigest>,
    report_limit: usize,
    timeout: Duration,
}

#[derive(Debug)]
enum CommandError {
    Usage(&'static str),
    Source,
    StaleSource,
    Selection(CoverError),
    Witness,
    Stopped,
    OutputBound,
}

fn text(value: &OsStr) -> Result<&str, CommandError> {
    value
        .to_str()
        .filter(|v| !v.is_empty())
        .ok_or(CommandError::Usage("value requires nonempty UTF-8"))
}
fn number(value: &OsStr, lower: u64, upper: u64) -> Result<u64, CommandError> {
    let raw = text(value)?;
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CommandError::Usage("expected unsigned decimal integer"));
    }
    let parsed = raw
        .parse::<u64>()
        .map_err(|_| CommandError::Usage("integer overflow"))?;
    if parsed < lower || parsed > upper {
        return Err(CommandError::Usage("numeric option outside its bounds"));
    }
    Ok(parsed)
}
fn identity(value: &OsStr) -> Result<String, CommandError> {
    let value = text(value)?;
    if value.len() > fss_graph_algorithms::graph::MAX_NODE_ID_LEN
        || value.chars().any(char::is_control)
    {
        return Err(CommandError::Usage(
            "identity is oversized or contains controls",
        ));
    }
    Ok(value.to_owned())
}
fn window(value: &OsStr) -> Result<CaptureInterval, CommandError> {
    let (first, last) = text(value)?
        .split_once(':')
        .ok_or(CommandError::Usage("--during requires START_NS:END_NS"))?;
    let first = first
        .parse::<i128>()
        .map_err(|_| CommandError::Usage("invalid signed capture start"))?;
    let last = last
        .parse::<i128>()
        .map_err(|_| CommandError::Usage("invalid signed capture end"))?;
    CaptureInterval::new(TimestampNs(first), TimestampNs(last))
        .map_err(|_| CommandError::Usage("capture start must not exceed end"))
}
fn insert(
    values: &mut BTreeSet<String>,
    value: String,
    maximum: usize,
) -> Result<(), CommandError> {
    if values.len() >= maximum {
        return Err(CommandError::Usage("too many repeated values"));
    }
    if !values.insert(value) {
        return Err(CommandError::Usage("duplicate repeated value"));
    }
    Ok(())
}

// Parse everything before reading any deployment. Paths preserve native OS bytes.
fn parse(args: &[OsString]) -> Result<Option<Request>, CommandError> {
    if args.len() > MAX_ARGS
        || args
            .iter()
            .any(|v| v.as_encoded_bytes().len() > MAX_ARG_BYTES)
    {
        return Err(CommandError::Usage(
            "argument count or length exceeds its bound",
        ));
    }
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return Ok(None);
    }
    if args.len() == 2 && args[0] == "select" && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Ok(None);
    }
    if args.first().and_then(|v| v.to_str()) != Some("select") || args.len() % 2 != 1 {
        return Err(CommandError::Usage(
            "expected select and separate option/value pairs",
        ));
    }
    let mut root = None;
    let mut site = None;
    let mut during = None;
    let mut zones = BTreeSet::new();
    let mut mandatory = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    let mut maximum = MAX_SETS;
    let mut method = CoverMethod::ExactSmall;
    let mut budget = CoverBudget::default();
    let mut expected = None;
    let mut report_limit = MAX_REPORT_BYTES;
    let mut timeout = Duration::from_millis(30_000);
    let mut seen = BTreeSet::new();
    for pair in args[1..].as_chunks::<2>().0 {
        let key = text(&pair[0])?;
        let value = &pair[1];
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(CommandError::Usage("missing option value"));
        }
        if !matches!(key, "--zone" | "--require-sensor" | "--exclude-sensor") && !seen.insert(key) {
            return Err(CommandError::Usage("duplicate singleton option"));
        }
        match key {
            "--root" => root = Some(PathBuf::from(value)),
            "--site" => {
                let value = text(value)?;
                if value.len() > 256
                    || fss_reference::reference_deployment::validate_site_lineage(value).is_err()
                {
                    return Err(CommandError::Usage("invalid bounded site lineage"));
                }
                site = Some(value.to_owned());
            }
            "--during" => during = Some(window(value)?),
            "--zone" => {
                let value = identity(value)?;
                if !value
                    .strip_prefix("zone:")
                    .or_else(|| value.strip_prefix("ground-zone:"))
                    .is_some_and(|suffix| !suffix.is_empty())
                {
                    return Err(CommandError::Usage(
                        "zone requires explicit zone:ID or ground-zone:ID scope",
                    ));
                }
                insert(&mut zones, value, MAX_ELEMENTS)?;
            }
            "--require-sensor" => insert(&mut mandatory, identity(value)?, MAX_SETS)?,
            "--exclude-sensor" => insert(&mut excluded, identity(value)?, MAX_SETS)?,
            "--max-sensors" => maximum = number(value, 0, MAX_SETS as u64)? as usize,
            "--method" => {
                method = match text(value)? {
                    "exact-small" => CoverMethod::ExactSmall,
                    "greedy" => CoverMethod::Greedy,
                    _ => return Err(CommandError::Usage("method must be exact-small or greedy")),
                }
            }
            "--work-units" => budget.max_work_units = number(value, 1, MAX_WORK_UNITS)?,
            "--max-report-bytes" => {
                report_limit = number(value, 1024, MAX_REPORT_BYTES as u64)? as usize
            }
            "--timeout-ms" => timeout = Duration::from_millis(number(value, 1, 3_600_000)?),
            "--expected-coverage" => {
                let digest = ContentDigest::parse(text(value)?)
                    .map_err(|_| CommandError::Usage("invalid coverage digest"))?;
                if digest.algorithm() != DigestAlgorithm::Sha256 {
                    return Err(CommandError::Usage("coverage pin must be SHA-256"));
                }
                expected = Some(digest);
            }
            _ => return Err(CommandError::Usage("unknown or inapplicable option")),
        }
    }
    if zones.is_empty() {
        return Err(CommandError::Usage(
            "at least one explicit target zone is required",
        ));
    }
    if mandatory.len() > maximum || !mandatory.is_disjoint(&excluded) {
        return Err(CommandError::Usage(
            "mandatory/excluded sensors contradict the cardinality constraint",
        ));
    }
    Ok(Some(Request {
        root: root.ok_or(CommandError::Usage("--root is required"))?,
        site: site.ok_or(CommandError::Usage("--site is required"))?,
        window: during.ok_or(CommandError::Usage(
            "--during is required; history is not simultaneous coverage",
        ))?,
        zones: zones.into_iter().collect(),
        mandatory: mandatory.into_iter().collect(),
        excluded: excluded.into_iter().collect(),
        maximum,
        method,
        budget,
        expected,
        report_limit,
        timeout,
    }))
}

fn counts(values: &BTreeMap<String, u64>) -> String {
    let fields: Vec<String> = values
        .iter()
        .map(|(name, n)| format!("{}:{n}", string(name)))
        .collect();
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
                .filter(|n| n.is_finite())
                .map_or_else(|| "null".to_owned(), |n| n.to_string()),
        ),
        ("stopReason", string(value.stop_reason())),
        (
            "decisionPathDigest",
            string(&value.decision_path_digest().to_text()),
        ),
        ("outputDigest", string(&value.output_digest().to_text())),
    ])
}

fn render(
    request: &Request,
    source: &CoverageGraphReport,
    analysis: &CoverAnalysis,
) -> Result<String, CommandError> {
    let parent_digest = source.witness.digest();
    let selection_witness = analysis
        .witness(
            &format!("SensorCoverageGraph:set-cover:parent:{parent_digest}"),
            source.anchor.clone(),
        )
        .map_err(|_| CommandError::Witness)?;
    let certificate: Vec<String> = analysis
        .certificate()
        .iter()
        .map(|row| {
            object(&[
                ("zone_scope", string(&row.element)),
                ("sensor_id", string(&row.set_id)),
            ])
        })
        .collect();
    let result = object(&[
        ("format", string(FORMAT)),
        ("site", string(&source.site)),
        ("anchor", evidence_anchor(&source.anchor)),
        (
            "capture_window",
            object(&[
                ("start_ns", string(&request.window.earliest.0.to_string())),
                ("end_ns", string(&request.window.latest.0.to_string())),
                ("endpoints", string("inclusive")),
                ("selection", string("whole-witness-v1")),
                ("clock_alignment", string("operator_hints_not_calibration")),
            ]),
        ),
        ("source_coverage_witness", witness(&source.witness)),
        (
            "source_coverage_witness_digest",
            string(&parent_digest.to_text()),
        ),
        (
            "objective",
            object(&[
                ("required_zones", strings(&request.zones)),
                ("mandatory_sensors", strings(&request.mandatory)),
                ("excluded_sensors", strings(&request.excluded)),
                ("maximum_sensors", request.maximum.to_string()),
                ("cost_model", string("one_unit_per_selected_sensor")),
            ]),
        ),
        ("method", string(analysis.method().as_str())),
        ("status", string(analysis.status().as_str())),
        (
            "objective_covered",
            (analysis.status() == CoverStatus::Covered).to_string(),
        ),
        ("selected_sensors", strings(analysis.selected())),
        (
            "selection_cost_units",
            analysis.selected().len().to_string(),
        ),
        ("uncovered_zones", strings(analysis.uncovered())),
        ("uncoverable_zones", strings(analysis.uncoverable())),
        ("support_certificate", array(&certificate)),
        ("witness", witness(&selection_witness)),
        (
            "witness_digest",
            string(&selection_witness.digest().to_text()),
        ),
        (
            "work_budget_scope",
            string("set_cover_solver_only; source_reader_and_projection_separately_bounded"),
        ),
        (
            "working_bytes_interpretation",
            string("conservative_charged_workspace_bound_not_measured_allocator_peak"),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "claim",
            string(
                "selection of retained positive witnesses over one common capture window; not live observability, calibrated clocks, absence, sensor independence, or permission to disable sensors",
            ),
        ),
        (
            "qualification",
            string("authored_unvalidated_reference_candidate"),
        ),
    ]);
    if result.len() + 1 > request.report_limit {
        return Err(CommandError::OutputBound);
    }
    Ok(result + "\n")
}

fn read_source(
    request: &Request,
    stopped: &impl Fn() -> bool,
) -> Result<CoverageGraphReport, CommandError> {
    if stopped() {
        return Err(CommandError::Stopped);
    }
    // The existing reader is bounded/read-only, but individual filesystem calls cannot be
    // preempted. This does not pretend a selection-work budget prices the snapshot read.
    let source = read_coverage_single_points_during(&request.root, &request.site, request.window)
        .map_err(|_| CommandError::Source)?;
    if stopped() {
        return Err(CommandError::Stopped);
    }
    if request
        .expected
        .is_some_and(|expected| expected != source.witness.digest())
    {
        return Err(CommandError::StaleSource);
    }
    Ok(source)
}

fn execute(request: &Request, stopped: &impl Fn() -> bool) -> Result<String, CommandError> {
    let source = read_source(request, stopped)?;
    let problem = SetCoverProblem::from_coverage(
        &source.projection,
        &request.zones,
        &request.mandatory,
        &request.excluded,
        request.maximum,
    )
    .map_err(CommandError::Selection)?;
    let analysis = problem
        .solve_cancellable(request.method, request.budget, stopped)
        .map_err(CommandError::Selection)?;
    let result = render(request, &source, &analysis)?;
    if stopped() {
        return Err(CommandError::Stopped);
    }
    Ok(result)
}

// Bounded EINTR handling; output failure is not a complete delivery claim.
fn emit(writer: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interruptions = 0;
    while !bytes.is_empty() {
        let chunk = &bytes[..bytes.len().min(64 * 1024)];
        match writer.write(chunk) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= chunk.len() => {
                bytes = &bytes[n..];
                interruptions = 0;
            }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                interruptions += 1
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).take(MAX_ARGS + 1).collect();
    let result = if args.first().and_then(|value| value.to_str()) == Some("select-resilient") {
        resilient::run(&args)
    } else {
        match parse(&args) {
            Ok(None) => Ok(HELP.to_owned()),
            Ok(Some(request)) => {
                let started = Instant::now();
                execute(&request, &|| started.elapsed() >= request.timeout)
            }
            Err(error) => Err(error),
        }
    };
    match result {
        Ok(report) => match emit(&mut io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let usage = matches!(&error, CommandError::Usage(_));
            let explanation = match &error {
                CommandError::Usage(reason) => *reason,
                CommandError::Source => {
                    "retained coverage unavailable, damaged, outside its bounds, or from another site"
                }
                CommandError::StaleSource => {
                    "source coverage witness differs from --expected-coverage; refresh the read before continuing"
                }
                CommandError::Selection(CoverError::Cancelled) | CommandError::Stopped => {
                    "deadline or cancellation reached; no selection or witness emitted"
                }
                CommandError::Selection(_) => {
                    "selection refused by its input, exact-size, hard-constraint, work or output contract; no heuristic fallback"
                }
                CommandError::Witness => "selection witness validation failed",
                CommandError::OutputBound => {
                    "complete report exceeds output budget; nothing was truncated"
                }
            };
            let code = if usage {
                ERR_CLI_MALFORMED_VALUE
            } else {
                ERR_CLI_RUNTIME_FAILURE
            };
            eprintln!("{code}: {explanation}. No effect was authorized. Use fss-cover --help.");
            ExitCode::from(if usage {
                ExitIdentity::MALFORMED_VALUE.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn args(extra: &[&str]) -> Vec<OsString> {
        [
            "select",
            "--root",
            "/unused/private-root",
            "--site",
            "site:test",
            "--during",
            "10:20",
            "--zone",
            "zone:gate",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(OsString::from)
        .collect()
    }
    fn request(extra: &[&str]) -> Result<Request, String> {
        parse(&args(extra))
            .map_err(|error| format!("{error:?}"))?
            .ok_or_else(|| "valid fixture unexpectedly requested help".to_owned())
    }
    #[test]
    fn parser_requires_explicit_window_and_target_before_any_read() {
        assert!(parse(&args(&[])).is_ok());
        let mut no_window = args(&[]);
        no_window.drain(5..7);
        assert!(parse(&no_window).is_err());
        let mut no_target = args(&[]);
        no_target.truncate(7);
        assert!(parse(&no_target).is_err());
        let mut inverted = args(&[]);
        inverted[6] = "20:10".into();
        assert!(parse(&inverted).is_err());
    }
    #[test]
    fn duplicates_unknown_options_and_contradictory_constraints_are_rejected() {
        for extra in [
            vec!["--zone", "zone:gate"],
            vec!["--method", "greedy", "--method", "exact-small"],
            vec!["--require-sensor", "a", "--exclude-sensor", "a"],
            vec!["--require-sensor", "a", "--max-sensors", "0"],
            vec!["--unknown", "secret"],
            vec!["--work-units", "0"],
            vec!["--timeout-ms", "0"],
            vec!["--zone", "gate"],
            vec!["--max-sensors", "18446744073709551616"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "case {extra:?}");
        }
    }
    #[test]
    fn signed_extremes_and_point_windows_are_preserved() {
        for input in [
            format!("{}:{}", i128::MIN, i128::MAX),
            "-9:-9".into(),
            "0:0".into(),
        ] {
            let mut values = args(&[]);
            values[6] = input.into();
            assert!(parse(&values).is_ok());
        }
    }
    #[test]
    fn repeated_inputs_are_canonical_and_native_paths_are_not_interpreted() -> Result<(), String> {
        let a = request(&[
            "--zone",
            "ground-zone:yard",
            "--require-sensor",
            "z",
            "--require-sensor",
            "a",
        ])?;
        assert_eq!(a.zones, vec!["ground-zone:yard", "zone:gate"]);
        assert_eq!(a.mandatory, vec!["a", "z"]);
        assert_eq!(a.root, PathBuf::from("/unused/private-root"));
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn path_bytes_need_not_be_utf8_but_identities_must_be() {
        use std::os::unix::ffi::OsStringExt;
        let mut values = args(&[]);
        values[2] = OsString::from_vec(b"/unused/\xff".to_vec());
        assert!(parse(&values).is_ok());
        values[8] = OsString::from_vec(b"zone:\xff".to_vec());
        assert!(parse(&values).is_err());
    }
    #[test]
    fn cancellation_before_read_leaves_nonexistent_deployment_unopened() -> Result<(), String> {
        assert!(matches!(
            execute(&request(&[])?, &|| true),
            Err(CommandError::Stopped)
        ));
        Ok(())
    }
    #[test]
    fn help_has_no_trailing_options_and_argument_bounds_are_hard() {
        assert!(matches!(parse(&["--help".into()]), Ok(None)));
        assert!(parse(&["--help".into(), "--root".into(), "/unused".into()]).is_err());
        assert!(parse(&vec!["x".into(); MAX_ARGS + 1]).is_err());
        let mut values = args(&[]);
        values[2] = "x".repeat(MAX_ARG_BYTES + 1).into();
        assert!(parse(&values).is_err());
    }
    struct Interrupted;
    impl Write for Interrupted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::Interrupted.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn output_interruptions_are_bounded_and_success_bytes_are_exact() -> TestResult {
        assert!(emit(&mut Interrupted, b"report").is_err());
        let mut bytes = Vec::new();
        emit(&mut bytes, b"report\n")?;
        assert_eq!(bytes, b"report\n");
        Ok(())
    }
}
