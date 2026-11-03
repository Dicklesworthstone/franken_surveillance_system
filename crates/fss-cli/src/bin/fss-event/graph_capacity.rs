#![forbid(unsafe_code)]
//! Source-bound capacity/failover planning over explicit, directed infrastructure.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{CaptureInterval, ContentDigest, GraphAlgorithmWitness, TimestampNs};
use fss_graph_algorithms::certified::{Budget, CertifiedRun};
use fss_graph_algorithms::stream_capacity::{
    self, CameraDemand, CapacityOutput, CapacityQuery, Link, Recorder,
};
use fss_reference::coverage_graph::{CoverageGraphReport, read_coverage_single_points_during};

const FORMAT: &str = "fss.stream_capacity.v1";
const MAX_ARGS: usize = 8193;
const MAX_ARG_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const HELP: &str = "fss-event graph capacity --root DIR --site SITE --during START_NS:END_NS\n\
  --rate-unit UNIT --cost-unit UNIT --node ID [--node ID ...]\n\
  --camera SENSOR=NODE=DEMAND [--camera ...]\n\
  --recorder ID=NODE=CAPACITY [--recorder ...]\n\
  [--link ID=FROM=TO=CAPACITY=UNIT_COST ...]\n\
  [--failed-node ID ...] [--failed-link ID ...]\n\
  [--expected-coverage sha256:HEX] [--work-units N]\n\
  [--max-report-bytes N] [--timeout-ms N]\n\
\n\
  Compute the maximum aggregate delivered camera rate, then the minimum cost of\n\
  that delivery. Report every camera shortfall, recorder intake, physical link\n\
  flow and limiting cut, with certified max-flow and min-cost-flow witnesses.\n\
  All camera IDs must occur in the retained source projection. Positive coverage\n\
  of the WHOLE requested window is reported separately and does not set demands.\n\
  Topology, camera rates, recorder capacities, failures and costs are declarations.\n\
  A camera attached to a failed node retains its entire requested demand.\n\
\n\
  Links are directed; declare both directions if intended. Named parallel links\n\
  remain separate. Flow may split across paths: this is aggregate capacity, not\n\
  proof that a single transport session can use multiple routes. Partial delivery\n\
  has no camera fairness or priority guarantee. A complete report may be infeasible.\n\
  Rates/capacities are positive integers in --rate-unit; nonnegative unit costs\n\
  use --cost-unit per rate unit. Units and IDs use ASCII letters/digits/: _ - .\n\
\n\
  Limits: 256 nodes, 1024 links, 128 cameras, 32 recorders; 256-byte IDs and 64-byte\n\
  units. Default work is 2000000, maximum 50000000, shared by both certified solvers\n\
  and composition. Exhaustion refuses a partial answer. Source reads have their\n\
  own bounds. Deadline checks bracket nonpreemptible reads and run inside solvers.\n\
  Default timeout is 30000 ms (1..3600000); complete JSON is at most 2 MiB.\n\
  The source pin commits the retained coverage witness; all declarations are also\n\
  bound into the capacity witness. Capture coordinates are retained operator hints.\n\
  This read-only query does not change routes, activate streams or measure throughput.\n";

#[derive(Debug)]
struct Request {
    root: PathBuf,
    site: String,
    window: CaptureInterval,
    expected: Option<ContentDigest>,
    query: CapacityQuery,
    budget: Budget,
    report_bytes: usize,
    timeout: Duration,
}

fn identifier(value: &str, maximum: usize) -> Result<String, String> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
    {
        return Err(format!(
            "identity/unit must contain 1..{maximum} ASCII letters, digits or : _ - ."
        ));
    }
    Ok(value.to_owned())
}

fn integer(value: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a nonnegative decimal integer".into());
    }
    let value = value.parse::<u64>().map_err(|_| "integer exceeds u64")?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("integer must be in {minimum}..={maximum}"));
    }
    Ok(value)
}

fn insert(set: &mut BTreeSet<String>, value: String, maximum: usize) -> Result<(), String> {
    if set.len() >= maximum || !set.insert(value) {
        return Err("duplicate or excessive declaration".into());
    }
    Ok(())
}

fn parts<const N: usize>(value: &str) -> Result<[&str; N], String> {
    let parts: Vec<_> = value.split('=').collect();
    parts
        .try_into()
        .map_err(|_| format!("expected {N} fields separated by '='"))
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    if args.len() > MAX_ARGS
        || args
            .iter()
            .any(|arg| arg.as_encoded_bytes().len() > MAX_ARG_BYTES)
        || args.first().and_then(|v| v.to_str()) != Some("capacity")
        || args.len() % 2 != 1
    {
        return Err("expected capacity followed by bounded separate option/value pairs".into());
    }
    let (mut root, mut site, mut window, mut expected) = (None, None, None, None);
    let (mut rate_unit, mut cost_unit) = (None, None);
    let (mut nodes, mut failed_nodes, mut failed_links) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let (mut cameras, mut links, mut recorders) =
        (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let mut singleton = BTreeSet::new();
    let (mut work, mut report_bytes, mut timeout_ms) = (2_000_000, MAX_REPORT_BYTES, 30_000);
    for pair in args[1..].as_chunks::<2>().0 {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        let value = pair[1].to_str().ok_or("option values require UTF-8")?;
        if value.is_empty() || value.starts_with("--") {
            return Err("missing option value".into());
        }
        match key {
            "--node" => insert(&mut nodes, identifier(value, 256)?, 256)?,
            "--failed-node" => insert(&mut failed_nodes, identifier(value, 256)?, 256)?,
            "--failed-link" => insert(&mut failed_links, identifier(value, 256)?, 1024)?,
            "--camera" => {
                let [sensor, node, requested] = parts(value)?;
                let camera = CameraDemand {
                    sensor: identifier(sensor, 256)?,
                    node: identifier(node, 256)?,
                    requested: integer(requested, 1, u64::MAX)?,
                };
                if cameras.len() >= 128 || cameras.insert(camera.sensor.clone(), camera).is_some() {
                    return Err("duplicate or excessive cameras".into());
                }
            }
            "--link" => {
                let [id, from, to, capacity, unit_cost] = parts(value)?;
                let link = Link {
                    id: identifier(id, 256)?,
                    from: identifier(from, 256)?,
                    to: identifier(to, 256)?,
                    capacity: integer(capacity, 1, u64::MAX)?,
                    unit_cost: integer(unit_cost, 0, u64::MAX)?,
                };
                if links.len() >= 1024 || links.insert(link.id.clone(), link).is_some() {
                    return Err("duplicate or excessive links".into());
                }
            }
            "--recorder" => {
                let [id, node, capacity] = parts(value)?;
                let recorder = Recorder {
                    id: identifier(id, 256)?,
                    node: identifier(node, 256)?,
                    capacity: integer(capacity, 1, u64::MAX)?,
                };
                if recorders.len() >= 32
                    || recorders.insert(recorder.id.clone(), recorder).is_some()
                {
                    return Err("duplicate or excessive recorders".into());
                }
            }
            _ => {
                if !singleton.insert(key) {
                    return Err(format!("duplicate option {key}"));
                }
                match key {
                    "--root" => root = Some(PathBuf::from(value)),
                    "--site" => site = Some(identifier(value, 256)?),
                    "--during" => {
                        let (first, last) = value
                            .split_once(':')
                            .ok_or("--during requires START_NS:END_NS")?;
                        window = Some(
                            CaptureInterval::new(
                                TimestampNs(
                                    first
                                        .parse::<i128>()
                                        .map_err(|_| "invalid start nanoseconds")?,
                                ),
                                TimestampNs(
                                    last.parse::<i128>()
                                        .map_err(|_| "invalid end nanoseconds")?,
                                ),
                            )
                            .map_err(|_| "window start exceeds end")?,
                        );
                    }
                    "--expected-coverage" => {
                        if !value.starts_with("sha256:") {
                            return Err("source pin must be sha256:HEX".into());
                        }
                        expected =
                            Some(ContentDigest::parse(value).map_err(|_| "invalid source digest")?);
                    }
                    "--rate-unit" => rate_unit = Some(identifier(value, 64)?),
                    "--cost-unit" => cost_unit = Some(identifier(value, 64)?),
                    "--work-units" => work = integer(value, 1, 50_000_000)?,
                    "--max-report-bytes" => {
                        report_bytes = integer(value, 1024, MAX_REPORT_BYTES as u64)? as usize
                    }
                    "--timeout-ms" => timeout_ms = integer(value, 1, 3_600_000)?,
                    _ => return Err(format!("unknown capacity option {key}")),
                }
            }
        }
    }
    if nodes.is_empty() || cameras.is_empty() || recorders.is_empty() {
        return Err("at least one node, camera and recorder is required".into());
    }
    if cameras.values().any(|row| !nodes.contains(&row.node))
        || recorders.values().any(|row| !nodes.contains(&row.node))
        || links
            .values()
            .any(|row| row.from == row.to || !nodes.contains(&row.from) || !nodes.contains(&row.to))
        || failed_nodes.iter().any(|id| !nodes.contains(id))
        || failed_links.iter().any(|id| !links.contains_key(id))
    {
        return Err("unknown topology endpoint/failure or self-link".into());
    }
    Ok(Request {
        root: root.ok_or("--root is required")?,
        site: site.ok_or("--site is required")?,
        window: window.ok_or("--during is required")?,
        expected,
        query: CapacityQuery {
            rate_unit: rate_unit.ok_or("--rate-unit is required")?,
            cost_unit: cost_unit.ok_or("--cost-unit is required")?,
            nodes: nodes.into_iter().collect(),
            cameras: cameras.into_values().collect(),
            links: links.into_values().collect(),
            recorders: recorders.into_values().collect(),
            failed_nodes: failed_nodes.into_iter().collect(),
            failed_links: failed_links.into_iter().collect(),
        },
        budget: Budget::new(work, 32_768),
        report_bytes,
        timeout: Duration::from_millis(timeout_ms),
    })
}

fn counts(values: &BTreeMap<String, u64>) -> String {
    let fields: Vec<_> = values
        .iter()
        .map(|(name, value)| format!("{}:{value}", string(name)))
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
                .map_or_else(|| "null".into(), |n| n.to_string()),
        ),
        ("stopReason", string(value.stop_reason())),
        (
            "decisionPathDigest",
            string(&value.decision_path_digest().to_text()),
        ),
        ("outputDigest", string(&value.output_digest().to_text())),
    ])
}

fn endpoint(value: &stream_capacity::Endpoint) -> String {
    use stream_capacity::Endpoint;
    let (kind, id) = match value {
        Endpoint::Source => ("source", None),
        Endpoint::Sink => ("sink", None),
        Endpoint::Node(id) => ("node", Some(id)),
        Endpoint::Link(id) => ("link", Some(id)),
        Endpoint::Camera(id) => ("camera", Some(id)),
        Endpoint::Recorder(id) => ("recorder", Some(id)),
    };
    object(&[
        ("kind", string(kind)),
        ("id", id.map_or_else(|| "null".into(), |id| string(id))),
    ])
}

fn proof<O>(
    run: &CertifiedRun<O>,
    source: &CoverageGraphReport,
    projection: &str,
    output: String,
) -> Result<String, String> {
    let value = run
        .witness(projection, source.anchor.clone())
        .map_err(|error| error.to_string())?;
    Ok(object(&[
        ("witness", witness(&value)),
        ("witness_digest", string(&value.digest().to_text())),
        ("output", output),
    ]))
}

fn maximum_flow_output(output: &fss_graph_algorithms::flow::FlowOutput) -> Result<String, String> {
    let fss_graph_algorithms::flow::FlowOutput::Arcs(output) = output else {
        return Err("unexpected node-cut capacity proof".into());
    };
    let flows: Vec<_> = output
        .flows
        .iter()
        .map(|(from, to, flow)| {
            object(&[
                ("from", string(from)),
                ("to", string(to)),
                ("flow", flow.to_string()),
            ])
        })
        .collect();
    let cut: Vec<_> = output
        .cut
        .iter()
        .map(|(from, to, capacity)| {
            object(&[
                ("from", string(from)),
                ("to", string(to)),
                ("capacity", capacity.to_string()),
            ])
        })
        .collect();
    Ok(object(&[
        ("source", string(&output.source)),
        ("sink", string(&output.sink)),
        ("value", output.value.to_string()),
        ("flows", array(&flows)),
        ("source_side", strings(&output.source_side)),
        ("cut", array(&cut)),
    ]))
}

fn minimum_cost_output(output: &fss_graph_algorithms::min_cost_flow::MinCostFlowOutput) -> String {
    let flows: Vec<_> = output
        .flows
        .iter()
        .map(|(from, to, flow, cost)| {
            object(&[
                ("from", string(from)),
                ("to", string(to)),
                ("flow", flow.to_string()),
                ("unit_cost", cost.to_string()),
            ])
        })
        .collect();
    object(&[
        ("source", string(&output.source)),
        ("sink", string(&output.sink)),
        ("requested", output.requested.to_string()),
        ("delivered", output.delivered.to_string()),
        ("shortfall", output.shortfall.to_string()),
        ("total_cost", output.total_cost.to_string()),
        ("flows", array(&flows)),
    ])
}

fn retained_support(
    request: &Request,
    source: &CoverageGraphReport,
    cancelled: &impl Fn() -> bool,
) -> Result<String, String> {
    if cancelled() {
        return Err("capacity deadline reached before retained-support selection".into());
    }
    source
        .projection
        .validate()
        .map_err(|error| error.to_string())?;
    let mut selected: BTreeMap<&str, (bool, Vec<String>, u64)> = request
        .query
        .cameras
        .iter()
        .map(|camera| (camera.sensor.as_str(), (false, Vec::new(), 0)))
        .collect();
    let mut zone_bytes = 0_usize;
    // One traversal of the bounded source, independent of the camera count.
    // Count encoded zone bytes before retaining them; they are a lower bound on
    // the complete report, so this cannot admit a truncated support prefix.
    for ((sensor, zone), witnesses) in &source.projection.witnesses {
        if cancelled() {
            return Err("capacity deadline reached during retained-support selection".into());
        }
        if let Some((known, zones, count)) = selected.get_mut(sensor.as_str()) {
            *known = true;
            if *witnesses > 0 {
                zone_bytes = zone_bytes
                    .checked_add(string(zone).len())
                    .ok_or("support byte overflow")?;
                if zone_bytes > request.report_bytes {
                    return Err("complete retained support exceeds report bound".into());
                }
                zones.push(zone.clone());
                *count = count
                    .checked_add(*witnesses)
                    .ok_or("retained witness count overflow")?;
            }
        }
    }
    let mut rows = Vec::new();
    for (sensor, (known, zones, count)) in selected {
        if !known {
            return Err(format!(
                "camera {sensor} is not present in the retained source projection"
            ));
        }
        rows.push(object(&[
            ("sensor_id", string(sensor)),
            ("qualifying_zones", strings(&zones)),
            ("qualifying_witness_count", count.to_string()),
        ]));
    }
    Ok(array(&rows))
}

fn render(
    request: &Request,
    source: &CoverageGraphReport,
    support: String,
    analysis: &CertifiedRun<CapacityOutput>,
) -> Result<String, String> {
    let output = &analysis.output;
    let parent = source.witness.digest().to_text();
    let projection = format!("DeviceFailureGraph@coverage:{parent}");
    let certificate = analysis
        .witness(&projection, source.anchor.clone())
        .map_err(|error| error.to_string())?;
    let cameras: Vec<_> = output
        .cameras
        .iter()
        .map(|row| {
            object(&[
                ("sensor_id", string(&row.sensor)),
                ("node", string(&row.node)),
                ("requested", row.requested.to_string()),
                ("delivered", row.delivered.to_string()),
                ("shortfall", row.shortfall.to_string()),
                ("attachment_failed", row.attachment_failed.to_string()),
            ])
        })
        .collect();
    let links: Vec<_> = output
        .links
        .iter()
        .map(|row| {
            object(&[
                ("id", string(&row.id)),
                ("from", string(&row.from)),
                ("to", string(&row.to)),
                ("capacity", row.capacity.to_string()),
                ("unit_cost", row.unit_cost.to_string()),
                ("flow", row.flow.to_string()),
                ("failed", row.failed.to_string()),
                ("from_failed", row.from_failed.to_string()),
                ("to_failed", row.to_failed.to_string()),
            ])
        })
        .collect();
    let recorders: Vec<_> = output
        .recorders
        .iter()
        .map(|row| {
            object(&[
                ("id", string(&row.id)),
                ("node", string(&row.node)),
                ("capacity", row.capacity.to_string()),
                ("received", row.received.to_string()),
                ("attachment_failed", row.attachment_failed.to_string()),
            ])
        })
        .collect();
    let partition: Vec<_> = output.source_side.iter().map(endpoint).collect();
    let cut: Vec<_> = output
        .cut
        .iter()
        .map(|arc| {
            object(&[
                ("from", endpoint(&arc.from)),
                ("to", endpoint(&arc.to)),
                ("capacity", arc.capacity.to_string()),
                ("flow", arc.flow.to_string()),
            ])
        })
        .collect();
    let report = object(&[
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
        ("source_coverage_witness_digest", string(&parent)),
        ("retained_sensor_support", support),
        (
            "declared_problem",
            object(&[
                ("provenance", string("operator_asserted_hypothetical")),
                ("orientation", string("directed")),
                ("rate_unit", string(&request.query.rate_unit)),
                ("cost_unit", string(&request.query.cost_unit)),
                ("cost_basis", string("per_rate_unit")),
                ("nodes", strings(&request.query.nodes)),
                ("failed_nodes", strings(&request.query.failed_nodes)),
                ("failed_links", strings(&request.query.failed_links)),
                (
                    "objective",
                    string("maximum_aggregate_delivery_then_minimum_cost"),
                ),
                ("routing", string("splittable_integral_flow")),
                (
                    "partial_allocation",
                    string("deterministic_without_fairness_or_priority_guarantee"),
                ),
            ]),
        ),
        ("status", string(output.status.as_str())),
        ("requested", output.requested.to_string()),
        ("delivered", output.delivered.to_string()),
        ("shortfall", output.shortfall.to_string()),
        ("total_cost", output.total_cost.to_string()),
        ("cameras", array(&cameras)),
        ("links", array(&links)),
        ("recorders", array(&recorders)),
        ("source_side", array(&partition)),
        ("cut", array(&cut)),
        (
            "maximum_flow_proof",
            proof(
                &output.maximum_flow,
                source,
                &format!("{projection}/maximum-flow"),
                maximum_flow_output(&output.maximum_flow.output)?,
            )?,
        ),
        (
            "minimum_cost_proof",
            proof(
                &output.minimum_cost,
                source,
                &format!("{projection}/minimum-cost"),
                minimum_cost_output(&output.minimum_cost.output),
            )?,
        ),
        ("witness", witness(&certificate)),
        ("witness_digest", string(&certificate.digest().to_text())),
        (
            "work_budget_scope",
            string(
                "reduction_maximum_flow_minimum_cost_and_composition; source_reader_and_projection_separately_bounded",
            ),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "claim",
            string(
                "exact aggregate routing conditional on declared topology, rates, costs and failures; retained camera identity/support is not measured throughput, current health, multipath session support or permission to activate or route streams",
            ),
        ),
        (
            "qualification",
            string("deterministic_reference_not_production_qualified"),
        ),
    ]);
    if report.len() + 1 > request.report_bytes {
        return Err(
            "complete capacity report exceeds output bound; no report was truncated".into(),
        );
    }
    Ok(report + "\n")
}

fn run(request: &Request) -> Result<String, String> {
    let started = Instant::now();
    let cancelled = || started.elapsed() >= request.timeout;
    if cancelled() {
        return Err("capacity deadline reached before source read".into());
    }
    let source = read_coverage_single_points_during(&request.root, &request.site, request.window)
        .map_err(|error| error.to_string())?;
    if cancelled() {
        return Err("capacity deadline reached during source read".into());
    }
    if request
        .expected
        .is_some_and(|pin| pin != source.witness.digest())
    {
        return Err("retained source coverage pin is stale or mismatched".into());
    }
    let support = retained_support(request, &source, &cancelled)?;
    let analysis = stream_capacity::analyze_with_cancel(&request.query, request.budget, &cancelled)
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let report = render(request, &source, support, &analysis)?;
    if cancelled() {
        return Err("capacity deadline reached before complete report publication".into());
    }
    Ok(report)
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [command, flag] if command == "capacity" && matches!(flag.to_str(), Some("--help" | "-h")))
    {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let request = match parse(args) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event graph capacity --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&request) {
        Ok(report) => match io::stdout().lock().write_all(report.as_bytes()) {
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
#[path = "graph_capacity_tests.rs"]
mod tests;
