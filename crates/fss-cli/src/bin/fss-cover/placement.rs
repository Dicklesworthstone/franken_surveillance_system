#![forbid(unsafe_code)]
//! Read-only camera-addition analysis over retained whole-window coverage. Movement,
//! candidate coverage and both cost scales are explicit hypothetical owner declarations.

use super::*;
use fss_graph_algorithms::certified::CertifiedRun;
use fss_graph_algorithms::interdiction::{InterdictionOutcome, InterdictionQuery};
use fss_graph_algorithms::robust_placement::{
    self, MAX_CANDIDATES, PlacementCandidate, PlacementOutput, PlacementQuery,
};
use fss_graph_algorithms::weighted::{WeightedGraph, WeightedGraphBuilder};

#[path = "placement_failures.rs"]
mod shared;

const FORMAT: &str = "fss.coverage_robust_placement.v1";
const MAX_MOVES: usize = 128;
const CLAIM: &str = "exact hypothetical camera-addition optimum for the declared movement graph, candidate coverage and additive sensor-loss costs; baseline support uses retained whole-window witnesses, not current health, calibrated clocks, independent failures, complete physical routes, absence, or authority to install or disable cameras";
const HELP: &str = "fss-cover placement --root DIR --site SITE --during START_NS:END_NS\n\
  --zone SCOPE [--zone SCOPE ...] (all movement nodes; zone:ID or ground-zone:ID)\n\
  --entry SCOPE [--entry SCOPE ...] --target SCOPE [--target SCOPE ...]\n\
  [--move FROM=TO ...] (directed; declare both directions when intended)\n\
  --candidate SENSOR=INSTALL_COST:DISABLE_COST:ZONE[,ZONE...] [--candidate ...]\n\
  --installation-budget N [--max-additions N] [--sensor-disable-cost SENSOR=N ...]\n\
  [--failure-action ID=COST=SENSOR[,SENSOR...] ...]\n\
  --installation-cost-unit UNIT --sensor-loss-cost-unit UNIT\n\
  [--expected-coverage sha256:HEX] [--work-units N] [--max-report-bytes N] [--timeout-ms N]\n\
\n\
  Choose proposed cameras maximizing the minimum additive sensor-loss cost that opens\n\
  an unobserved entry-to-target path. Ties: lower installation cost, fewer additions,\n\
  then canonical sensor IDs. Entry and target zones also require observation.\n\
  Costs are declared integer units, not calibrated probabilities or inferred money.\n\
  Both unit names are required (1..64 ASCII letters/digits or : _ - .).\n\
  Existing relevant sensors default to loss cost 1; overrides must name an existing\n\
  positive observer in this movement graph. Installation and loss units are separate.\n\
  With --failure-action, shared power/network/host losses are considered alongside\n\
  individual sensor losses. COST uses --sensor-loss-cost-unit and is charged once per\n\
  selected action. Overlapping memberships are unioned. Members may name proposed\n\
  candidates or retained sensors; unknown identities refuse. Explicit retained members\n\
  without positive support add NO observer edges and default to loss cost 1 (overridable).\n\
  Only installed members are affected. The report names typed actions, affected sensors\n\
  and paths; these are hypothetical loss assumptions, not measured probabilities.\n\
\n\
  Every baseline edge requires one retained witness covering the WHOLE requested window.\n\
  Proposed coverage, movement and costs are owner assertions, never retained sensor facts.\n\
  An unobserved path means unsupported by this graph; it proves no physical absence.\n\
  Unreachable means only no path in the declared movement graph, not a secure property.\n\
  No camera action, storage mutation, model invocation, effect plan or approval occurs.\n\
\n\
  Limits: 64 zones, 128 directed moves, 16 candidates, 20 total relevant existing and\n\
  candidate sensors. --max-additions defaults to 1 (0..16). Exact search shares one\n\
  cumulative work allowance across all placements and sensor-loss searches: 2000000\n\
  default, hard ceiling 50000000. Exhaustion refuses; no heuristic fallback or partial\n\
  optimum. Source reads have independent bounds. --timeout-ms defaults to 30000;\n\
  checks bracket nonpreemptible source reads and run throughout the exact solver.\n\
  Output is complete fss.coverage_robust_placement.v1 JSON (2 MiB maximum by default).\n\
  Shared actions select fss.coverage_shared_failure_placement.v1 with a distinct witness\n\
  policy. At most 16 shared actions, additional to the same 20-sensor/16-candidate limits.\n\
  --expected-coverage pins the retained source witness, not the hypothetical declarations.\n\
  IDs in declarations must not contain '=' or ','; duplicates and unknown zones refuse.\n\
  This is a deterministic reference analysis, not production qualification.\n";

#[derive(Clone, Debug)]
struct PlacementRequest {
    common: Request,
    movement: WeightedGraph,
    moves: Vec<(String, String)>,
    entries: BTreeSet<String>,
    targets: BTreeSet<String>,
    candidates: Vec<PlacementCandidate>,
    failure_actions: Vec<shared::FailureAction>,
    disable_costs: BTreeMap<String, u64>,
    installation_budget: u64,
    maximum_additions: usize,
    disable_cost_unit: String,
    installation_cost_unit: String,
}

fn declared_id(raw: &str) -> Result<String, CommandError> {
    let id = identity(OsStr::new(raw))?;
    if id.contains(['=', ',']) {
        return Err(CommandError::Usage(
            "declaration identities cannot contain '=' or ','",
        ));
    }
    Ok(id)
}

fn candidate(raw: &OsStr) -> Result<PlacementCandidate, CommandError> {
    let (sensor, values) = text(raw)?.split_once('=').ok_or(CommandError::Usage(
        "candidate requires SENSOR=INSTALL_COST:DISABLE_COST:ZONE[,ZONE...]",
    ))?;
    let mut fields = values.splitn(3, ':');
    let installation_cost = number(
        OsStr::new(
            fields
                .next()
                .ok_or(CommandError::Usage("missing installation cost"))?,
        ),
        0,
        u64::MAX,
    )?;
    let disable_cost = number(
        OsStr::new(
            fields
                .next()
                .ok_or(CommandError::Usage("missing loss cost"))?,
        ),
        0,
        u64::MAX,
    )?;
    let zones = fields
        .next()
        .ok_or(CommandError::Usage("missing candidate zones"))?;
    let mut observes = BTreeSet::new();
    for zone in zones.split(',') {
        insert(&mut observes, declared_id(zone)?, MAX_ELEMENTS)?;
    }
    Ok(PlacementCandidate {
        sensor: declared_id(sensor)?,
        observes,
        disable_cost,
        installation_cost,
    })
}

fn parse(args: &[OsString]) -> Result<Option<PlacementRequest>, CommandError> {
    if args.len() > MAX_ARGS
        || args
            .iter()
            .any(|v| v.as_encoded_bytes().len() > MAX_ARG_BYTES)
    {
        return Err(CommandError::Usage(
            "argument count or length exceeds its bound",
        ));
    }
    if args.len() == 2
        && args[0] == "placement"
        && matches!(args[1].to_str(), Some("--help" | "-h"))
    {
        return Ok(None);
    }
    if args.first().and_then(|v| v.to_str()) != Some("placement") || args.len() % 2 != 1 {
        return Err(CommandError::Usage(
            "expected placement and separate option/value pairs",
        ));
    }
    let mut common = vec![OsString::from("select")];
    let mut moves = BTreeSet::new();
    let mut entries = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    let mut failure_actions = BTreeMap::new();
    let mut disable_costs = BTreeMap::new();
    let mut installation_budget = None;
    let mut maximum_additions = 1;
    let mut disable_cost_unit = None;
    let mut installation_cost_unit = None;
    let mut singleton = BTreeSet::new();
    for pair in args[1..].as_chunks::<2>().0 {
        let key = text(&pair[0])?;
        let value = &pair[1];
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(CommandError::Usage("missing option value"));
        }
        match key {
            "--entry" => insert(&mut entries, declared_id(text(value)?)?, MAX_ELEMENTS)?,
            "--target" => insert(&mut targets, declared_id(text(value)?)?, MAX_ELEMENTS)?,
            "--move" => {
                let (from, to) = text(value)?
                    .split_once('=')
                    .ok_or(CommandError::Usage("move requires FROM=TO"))?;
                if moves.len() >= MAX_MOVES || !moves.insert((declared_id(from)?, declared_id(to)?))
                {
                    return Err(CommandError::Usage("duplicate or excessive movement arcs"));
                }
            }
            "--candidate" => {
                let value = candidate(value)?;
                if candidates.len() >= MAX_CANDIDATES
                    || candidates.insert(value.sensor.clone(), value).is_some()
                {
                    return Err(CommandError::Usage(
                        "duplicate or excessive candidate sensors",
                    ));
                }
            }
            "--failure-action" => {
                let action = shared::parse_action(value)?;
                if failure_actions.len() >= shared::MAX_SHARED_ACTIONS
                    || failure_actions.insert(action.id.clone(), action).is_some()
                {
                    return Err(CommandError::Usage(
                        "duplicate or excessive shared failure actions",
                    ));
                }
            }
            "--sensor-disable-cost" => {
                let (sensor, cost) = text(value)?
                    .split_once('=')
                    .ok_or(CommandError::Usage("sensor loss cost requires SENSOR=N"))?;
                let cost = number(OsStr::new(cost), 0, u64::MAX)?;
                if disable_costs.len() >= robust_placement::MAX_TOTAL_SENSORS
                    || disable_costs.insert(declared_id(sensor)?, cost).is_some()
                {
                    return Err(CommandError::Usage(
                        "duplicate or excessive sensor loss costs",
                    ));
                }
            }
            "--installation-budget" | "--max-additions" => {
                if !singleton.insert(key) {
                    return Err(CommandError::Usage("duplicate singleton option"));
                }
                if key == "--installation-budget" {
                    installation_budget = Some(number(value, 0, u64::MAX)?);
                } else {
                    maximum_additions = number(value, 0, MAX_CANDIDATES as u64)? as usize;
                }
            }
            "--installation-cost-unit" | "--sensor-loss-cost-unit" => {
                if !singleton.insert(key) {
                    return Err(CommandError::Usage("duplicate singleton option"));
                }
                let unit = text(value)?;
                if unit.len() > 64
                    || !unit
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b":_-.".contains(&b))
                {
                    return Err(CommandError::Usage(
                        "invalid cost unit: expected 1..64 ASCII letters/digits or : _ - .",
                    ));
                }
                if key == "--installation-cost-unit" {
                    installation_cost_unit = Some(unit.to_owned());
                } else {
                    disable_cost_unit = Some(unit.to_owned());
                }
            }
            "--method" | "--require-sensor" | "--exclude-sensor" | "--max-sensors" => {
                return Err(CommandError::Usage(
                    "nominal selection constraints do not apply to placement",
                ));
            }
            _ => common.extend_from_slice(pair),
        }
    }
    let common = super::parse(&common)?.ok_or(CommandError::Usage("invalid mixed help request"))?;
    if entries.is_empty() || targets.is_empty() || candidates.is_empty() {
        return Err(CommandError::Usage(
            "placement requires entries, targets and candidates",
        ));
    }
    let nodes: BTreeSet<_> = common.zones.iter().cloned().collect();
    if !entries.is_subset(&nodes)
        || !targets.is_subset(&nodes)
        || candidates.values().any(|v| !v.observes.is_subset(&nodes))
    {
        return Err(CommandError::Usage(
            "entry, target and candidate zones must be explicitly declared with --zone",
        ));
    }
    let mut builder = WeightedGraphBuilder::directed("owner-declared-movement");
    for zone in &nodes {
        declared_id(zone)?;
        builder.add_node(zone);
    }
    for (from, to) in &moves {
        builder.add_arc(from, to, 0);
    }
    let movement = builder
        .build()
        .map_err(|_| CommandError::Usage("movement contains a loop or an undeclared zone"))?;
    Ok(Some(PlacementRequest {
        common,
        movement,
        moves: moves.into_iter().collect(),
        entries,
        targets,
        candidates: candidates.into_values().collect(),
        failure_actions: failure_actions.into_values().collect(),
        disable_costs,
        installation_budget: installation_budget
            .ok_or(CommandError::Usage("--installation-budget is required"))?,
        maximum_additions,
        disable_cost_unit: disable_cost_unit
            .ok_or(CommandError::Usage("--sensor-loss-cost-unit is required"))?,
        installation_cost_unit: installation_cost_unit
            .ok_or(CommandError::Usage("--installation-cost-unit is required"))?,
    }))
}

fn problem(
    request: &PlacementRequest,
    source: &CoverageGraphReport,
) -> Result<PlacementQuery, CommandError> {
    source
        .projection
        .validate()
        .map_err(|_| CommandError::Witness)?;
    let zones: BTreeSet<&str> = request.common.zones.iter().map(String::as_str).collect();
    let mut observers: BTreeMap<String, BTreeSet<String>> = request
        .common
        .zones
        .iter()
        .map(|zone| (zone.clone(), BTreeSet::new()))
        .collect();
    let mut costs = BTreeMap::new();
    let mut known = BTreeSet::new();
    for ((sensor, zone), count) in &source.projection.witnesses {
        known.insert(sensor.as_str());
        if *count > 0 && zones.contains(zone.as_str()) {
            observers
                .entry(zone.clone())
                .or_default()
                .insert(sensor.clone());
            costs.insert(sensor.clone(), 1);
        }
    }
    if request
        .candidates
        .iter()
        .any(|c| known.contains(c.sensor.as_str()))
    {
        return Err(CommandError::Usage(
            "candidate ID already names a retained sensor",
        ));
    }
    let candidates: BTreeSet<&str> = request
        .candidates
        .iter()
        .map(|c| c.sensor.as_str())
        .collect();
    for action in &request.failure_actions {
        for member in &action.members {
            if known.contains(member.as_str()) {
                // Explicitly named retained members remain in the failure catalog, including
                // zero-support sensors. This adds no coverage and preserves the declared union.
                costs.entry(member.clone()).or_insert(1);
            } else if !candidates.contains(member.as_str()) {
                return Err(CommandError::Usage(
                    "failure action names no retained or candidate sensor",
                ));
            }
        }
    }
    for (sensor, cost) in &request.disable_costs {
        let current = costs.get_mut(sensor).ok_or(CommandError::Usage(
            "sensor loss override names no positive observer or declared failure member",
        ))?;
        *current = *cost;
    }
    Ok(PlacementQuery {
        baseline: InterdictionQuery {
            observers,
            costs,
            entries: request.entries.clone(),
            targets: request.targets.clone(),
        },
        candidates: request.candidates.clone(),
        installation_budget: request.installation_budget,
        maximum_additions: request.maximum_additions,
        disable_cost_unit: request.disable_cost_unit.clone(),
        installation_cost_unit: request.installation_cost_unit.clone(),
    })
}

fn outcome(value: &InterdictionOutcome) -> String {
    let (status, sensors, cost, path) = match value {
        InterdictionOutcome::BlindPath { path } => {
            ("blind_path", Vec::new(), "0".to_owned(), path.clone())
        }
        InterdictionOutcome::Interdiction {
            sensors,
            cost,
            path,
            ..
        } => (
            "interdiction",
            sensors.clone(),
            cost.to_string(),
            path.clone(),
        ),
        InterdictionOutcome::Unreachable => (
            "unreachable_in_declared_graph",
            Vec::new(),
            "null".to_owned(),
            Vec::new(),
        ),
    };
    object(&[
        ("status", string(status)),
        ("sensor_loss_cost_units", cost),
        ("disabled_sensors", strings(&sensors)),
        ("path", strings(&path)),
    ])
}

fn render(
    request: &PlacementRequest,
    source: &CoverageGraphReport,
    query: &PlacementQuery,
    analysis: &CertifiedRun<PlacementOutput>,
) -> Result<String, CommandError> {
    let parent = source.witness.digest();
    let certificate = analysis
        .witness(
            &format!("SensorCoverageGraph:robust-placement:parent:{parent}"),
            source.anchor.clone(),
        )
        .map_err(|_| CommandError::Witness)?;
    let declarations: Vec<_> = query
        .candidates
        .iter()
        .map(|c| {
            object(&[
                ("sensor_id", string(&c.sensor)),
                (
                    "observes",
                    strings(&c.observes.iter().cloned().collect::<Vec<_>>()),
                ),
                ("installation_cost_units", c.installation_cost.to_string()),
                ("sensor_loss_cost_units", c.disable_cost.to_string()),
            ])
        })
        .collect();
    let baseline: Vec<_> = query
        .baseline
        .observers
        .iter()
        .map(|(zone, sensors)| {
            object(&[
                ("zone", string(zone)),
                (
                    "sensors",
                    strings(&sensors.iter().cloned().collect::<Vec<_>>()),
                ),
            ])
        })
        .collect();
    let moves: Vec<_> = request
        .moves
        .iter()
        .map(|(from, to)| object(&[("from", string(from)), ("to", string(to))]))
        .collect();
    let unsupported: Vec<_> = query
        .baseline
        .observers
        .iter()
        .filter(|(_, s)| s.is_empty())
        .map(|(z, _)| z.clone())
        .collect();
    let report = object(&[
        ("format", string(FORMAT)),
        ("site", string(&source.site)),
        ("anchor", evidence_anchor(&source.anchor)),
        (
            "capture_window",
            object(&[
                (
                    "start_ns",
                    string(&request.common.window.earliest.0.to_string()),
                ),
                (
                    "end_ns",
                    string(&request.common.window.latest.0.to_string()),
                ),
                ("endpoints", string("inclusive")),
                ("selection", string("whole-witness-v1")),
                ("clock_alignment", string("operator_hints_not_calibration")),
            ]),
        ),
        ("source_coverage_witness", witness(&source.witness)),
        ("source_coverage_witness_digest", string(&parent.to_text())),
        ("baseline_observers", array(&baseline)),
        ("zones_without_retained_support", strings(&unsupported)),
        (
            "declared_problem",
            object(&[
                ("provenance", string("operator_asserted_hypothetical")),
                ("movement_orientation", string("directed")),
                ("zones", strings(&request.common.zones)),
                ("moves", array(&moves)),
                (
                    "entries",
                    strings(&query.baseline.entries.iter().cloned().collect::<Vec<_>>()),
                ),
                (
                    "targets",
                    strings(&query.baseline.targets.iter().cloned().collect::<Vec<_>>()),
                ),
                ("existing_sensor_loss_costs", counts(&query.baseline.costs)),
                ("candidates", array(&declarations)),
                (
                    "installation_budget_units",
                    query.installation_budget.to_string(),
                ),
                (
                    "installation_cost_unit",
                    string(&query.installation_cost_unit),
                ),
                ("sensor_loss_cost_unit", string(&query.disable_cost_unit)),
                ("maximum_additions", query.maximum_additions.to_string()),
                (
                    "objective",
                    string("maximize_minimum_additive_sensor_loss_cost"),
                ),
                (
                    "tie_break",
                    string("lower_installation_cost_then_fewer_additions_then_sensor_ids"),
                ),
            ]),
        ),
        (
            "selected_sensors",
            strings(&analysis.output.selected_sensors),
        ),
        (
            "installation_cost_units",
            analysis.output.installation_cost.to_string(),
        ),
        ("baseline", outcome(&analysis.output.baseline)),
        ("defended", outcome(&analysis.output.defended)),
        (
            "evaluated_placements",
            analysis.output.evaluated_placements.to_string(),
        ),
        ("witness", witness(&certificate)),
        ("witness_digest", string(&certificate.digest().to_text())),
        (
            "work_budget_scope",
            string(
                "all_placement_and_sensor_loss_searches; source_reader_and_projection_separately_bounded",
            ),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("claim", string(CLAIM)),
        (
            "qualification",
            string("deterministic_reference_not_production_qualified"),
        ),
    ]);
    if report.len() + 1 > request.common.report_limit {
        return Err(CommandError::OutputBound);
    }
    Ok(report + "\n")
}

fn select(
    request: &PlacementRequest,
    source: &CoverageGraphReport,
    stopped: &impl Fn() -> bool,
) -> Result<String, CommandError> {
    let query = problem(request, source)?;
    if !request.failure_actions.is_empty() {
        return shared::select(request, source, query, stopped);
    }
    let analysis = robust_placement::select_robust_placement_with_cancel(
        &request.movement,
        &query,
        request.common.budget,
        stopped,
    )
    .map_err(CommandError::Selection)?;
    render(request, source, &query, &analysis)
}

pub(super) fn run(args: &[OsString]) -> Result<String, CommandError> {
    let Some(request) = parse(args)? else {
        return Ok(HELP.to_owned());
    };
    let start = Instant::now();
    let stopped = || start.elapsed() >= request.common.timeout;
    let source = read_source(&request.common, &stopped)?;
    let report = select(&request, &source, &stopped)?;
    if stopped() {
        return Err(CommandError::Stopped);
    }
    Ok(report)
}

#[cfg(test)]
#[path = "placement_tests.rs"]
mod tests;
