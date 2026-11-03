#![forbid(unsafe_code)]
//! Shared-failure placement adapter. Source reads remain owned by the existing coverage command.

use super::*;
use fss_graph_algorithms::robust_placement::shared_failures::{
    self, ActionIdentity, FailureOutcome, SharedFailureQuery, SharedPlacementOutput,
};
pub(super) use fss_graph_algorithms::robust_placement::shared_failures::{
    FailureAction, MAX_SHARED_ACTIONS,
};

const FORMAT: &str = "fss.coverage_shared_failure_placement.v1";
const CLAIM: &str = "exact hypothetical camera-addition optimum for declared movement, candidate coverage, individual sensor losses and shared failure actions; action costs add once and active member sets union; retained whole-window support does not certify current health, calibrated clocks, independent failures, failure probabilities, physical routes, absence or authority to install or disable cameras";

pub(super) fn parse_action(raw: &OsStr) -> Result<FailureAction, CommandError> {
    let (id, values) = text(raw)?.split_once('=').ok_or(CommandError::Usage(
        "shared failure action requires ID=COST=SENSOR[,SENSOR...]",
    ))?;
    let (cost, sensors) = values.split_once('=').ok_or(CommandError::Usage(
        "shared failure action requires ID=COST=SENSOR[,SENSOR...]",
    ))?;
    let cost = number(OsStr::new(cost), 0, u64::MAX)?;
    let mut members = BTreeSet::new();
    for sensor in sensors.split(',') {
        insert(
            &mut members,
            declared_id(sensor)?,
            robust_placement::MAX_TOTAL_SENSORS,
        )?;
    }
    Ok(FailureAction {
        id: declared_id(id)?,
        cost,
        members,
    })
}

fn outcome(value: &FailureOutcome) -> String {
    let (status, actions, sensors, cost, path) = match value {
        FailureOutcome::BlindPath { path } => (
            "blind_path",
            Vec::new(),
            Vec::new(),
            "0".to_owned(),
            path.clone(),
        ),
        FailureOutcome::Interdiction {
            actions,
            sensors,
            cost,
            path,
        } => (
            "interdiction",
            actions.clone(),
            sensors.clone(),
            cost.to_string(),
            path.clone(),
        ),
        FailureOutcome::Unreachable => (
            "unreachable_in_declared_graph",
            Vec::new(),
            Vec::new(),
            "null".to_owned(),
            Vec::new(),
        ),
    };
    let actions: Vec<_> = actions
        .iter()
        .map(|action| {
            let (kind, id) = match action {
                ActionIdentity::Sensor(id) => ("individual_sensor", id),
                ActionIdentity::Shared(id) => ("shared_failure", id),
            };
            object(&[("kind", string(kind)), ("id", string(id))])
        })
        .collect();
    object(&[
        ("status", string(status)),
        ("failure_action_loss_cost_units", cost),
        ("failure_actions", array(&actions)),
        ("disabled_sensors", strings(&sensors)),
        ("path", strings(&path)),
    ])
}

fn render(
    request: &PlacementRequest,
    source: &CoverageGraphReport,
    query: &SharedFailureQuery,
    analysis: &CertifiedRun<SharedPlacementOutput>,
) -> Result<String, CommandError> {
    let parent = source.witness.digest();
    let certificate = analysis
        .witness(
            &format!("SensorCoverageGraph:shared-failure-placement:parent:{parent}"),
            source.anchor.clone(),
        )
        .map_err(|_| CommandError::Witness)?;
    let placement = &query.placement;
    let candidates: Vec<_> = placement
        .candidates
        .iter()
        .map(|candidate| {
            object(&[
                ("sensor_id", string(&candidate.sensor)),
                (
                    "observes",
                    strings(&candidate.observes.iter().cloned().collect::<Vec<_>>()),
                ),
                (
                    "installation_cost_units",
                    candidate.installation_cost.to_string(),
                ),
                (
                    "individual_loss_cost_units",
                    candidate.disable_cost.to_string(),
                ),
            ])
        })
        .collect();
    let actions: Vec<_> = query
        .actions
        .iter()
        .map(|action| {
            object(&[
                ("id", string(&action.id)),
                ("loss_cost_units", action.cost.to_string()),
                (
                    "members",
                    strings(&action.members.iter().cloned().collect::<Vec<_>>()),
                ),
            ])
        })
        .collect();
    let baseline: Vec<_> = placement
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
    let unsupported: Vec<_> = placement
        .baseline
        .observers
        .iter()
        .filter(|(_, sensors)| sensors.is_empty())
        .map(|(zone, _)| zone.clone())
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
                    strings(
                        &placement
                            .baseline
                            .entries
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>(),
                    ),
                ),
                (
                    "targets",
                    strings(
                        &placement
                            .baseline
                            .targets
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>(),
                    ),
                ),
                (
                    "existing_individual_loss_costs",
                    counts(&placement.baseline.costs),
                ),
                ("candidates", array(&candidates)),
                ("shared_failure_actions", array(&actions)),
                (
                    "installation_budget_units",
                    placement.installation_budget.to_string(),
                ),
                (
                    "installation_cost_unit",
                    string(&placement.installation_cost_unit),
                ),
                (
                    "failure_action_loss_cost_unit",
                    string(&placement.disable_cost_unit),
                ),
                ("maximum_additions", placement.maximum_additions.to_string()),
                (
                    "objective",
                    string("maximize_minimum_additive_failure_action_cost"),
                ),
                (
                    "loss_model",
                    string(
                        "individual_sensor_actions_plus_declared_shared_actions;charge_each_action_once;union_active_members",
                    ),
                ),
                (
                    "tie_break",
                    string("lower_installation_cost_then_fewer_additions_then_sensor_ids"),
                ),
                (
                    "loss_tie_break",
                    string(
                        "lower_action_cost_then_fewer_actions_then_typed_ids;individual_before_shared;shortest_canonical_path",
                    ),
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
                "all_placement_and_failure_action_searches;source_reader_and_projection_separately_bounded",
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

pub(super) fn select(
    request: &PlacementRequest,
    source: &CoverageGraphReport,
    placement: PlacementQuery,
    stopped: &impl Fn() -> bool,
) -> Result<String, CommandError> {
    let query = SharedFailureQuery {
        placement,
        actions: request.failure_actions.clone(),
    };
    let analysis = shared_failures::select_robust_placement_with_cancel(
        &request.movement,
        &query,
        request.common.budget,
        stopped,
    )
    .map_err(CommandError::Selection)?;
    render(request, source, &query, &analysis)
}
