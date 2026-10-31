#![forbid(unsafe_code)]
//! Pure, bounded owner-input adapter for anonymous multi-camera handoff hypotheses.
//!
//! The source handles and clock, calibration, model and transit declarations are preserved
//! exactly. Reading this document does not authenticate their underlying evidence. The
//! complete constraint family accompanies the displayed ranked prefix; no path is identity.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::assignment::{Assignment, NonAssignment};
use fss_graph_algorithms::certified::{Budget, CertifiedRun};
use fss_graph_algorithms::continuity::{
    self, ContinuityOutput, ContinuityQuery, PathCover, Scope, Tracklet, TrackletSupport,
    Transition, TransitionDisposition, TransitionEdge,
};

use crate::json_input::{self, Value};
use crate::json_output::{array, object, string, strings};

/// Strict interchange schema of the owner-declared query.
pub const QUERY_SCHEMA: &str = "fss.scene_handoffs_query.v1";
/// Complete report schema. No durable event or authority record is created.
pub const REPORT_SCHEMA: &str = "fss.scene_handoffs.v1";
/// Maximum complete report, including both solver certificates and the implicit family.
pub const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Explicit hard work ceiling of the operator adapter.
pub const MAX_WORK: u64 = 50_000_000;
/// Logical output allowance shared by composition and its assignment solver.
pub const MAX_OUTPUT_ENTRIES: u64 = 32_768;

/// Typed refusal retained through the operator boundary instead of classifying cancellation
/// or exhausted native work as malformed input.
#[derive(Debug)]
pub enum QueryError {
    /// The owner document is malformed or violates the strict input profile.
    Input(String),
    /// A native admission, arithmetic, work, cancellation or consistency refusal.
    Graph(GraphError),
    /// The requested adapter allowance is outside its hard limits.
    Allowance,
    /// The complete answer cannot fit the output allowance.
    ReportLimit,
    /// Cancellation at the adapter's pre/post-computation checkpoint.
    Cancelled,
}

impl QueryError {
    /// Existing registered scene/graph error identity appropriate for this refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input(_) => "ERR-SCENE-FUSION-INPUT-001",
            Self::Graph(error) => error.stable_id(),
            Self::Allowance | Self::ReportLimit => "ERR-SCENE-FUSION-LIMIT-001",
            Self::Cancelled => "ERR-GRAPH-CANCELLED-001",
        }
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(detail) => f.write_str(detail),
            Self::Graph(error) => write!(f, "{}: {error}", error.stable_id()),
            Self::Allowance => f.write_str("query allowance is outside the hard adapter bounds"),
            Self::ReportLimit => f.write_str(
                "complete handoff report exceeds the output bound; no alternative was truncated",
            ),
            Self::Cancelled => f.write_str("ERR-GRAPH-CANCELLED-001: handoff query cancelled"),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Graph(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) fn fields<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<&'a BTreeMap<String, Value>, String> {
    let value = value.object().ok_or("expected a JSON object")?;
    if value.len() != allowed.len() || value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("missing or unknown query field".into());
    }
    Ok(value)
}

pub(crate) fn required<'a>(
    value: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a Value, String> {
    value.get(key).ok_or_else(|| format!("missing field {key}"))
}

pub(crate) fn text(value: &Value) -> Result<&str, String> {
    value.text().ok_or_else(|| "expected a string".into())
}

pub(crate) fn id(value: &Value, maximum: usize) -> Result<String, String> {
    let value = text(value)?;
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
    {
        return Err("identifier or unit exceeds its ASCII grammar or size bound".into());
    }
    Ok(value.to_owned())
}

pub(crate) fn number(value: &Value) -> Result<i128, String> {
    // JSON integers, not strings or exponent/fraction spellings, preserve signed clock ticks.
    if !matches!(value, Value::Number(_)) {
        return Err("expected an exact JSON integer".into());
    }
    value
        .integer()
        .ok_or_else(|| "expected an exact JSON integer".into())
}

pub(crate) fn unsigned(value: &Value) -> Result<u64, String> {
    u64::try_from(number(value)?).map_err(|_| "integer is outside u64".into())
}

pub(crate) fn digest(value: &Value) -> Result<ContentDigest, String> {
    let value = ContentDigest::parse(text(value)?).map_err(|_| "invalid content digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("expected a nonzero sha256 content digest".into());
    }
    Ok(value)
}

pub(crate) fn list(value: &Value, maximum: usize) -> Result<&[Value], String> {
    value
        .array()
        .filter(|items| items.len() <= maximum)
        .ok_or_else(|| "expected an array within its declared bound".into())
}

pub(crate) fn clock_interval(value: &Value) -> Result<[i64; 2], String> {
    let values = list(value, 2)?;
    if values.len() != 2 {
        return Err("clock interval requires two endpoints".into());
    }
    Ok([
        i64::try_from(number(&values[0])?).map_err(|_| "clock tick outside i64")?,
        i64::try_from(number(&values[1])?).map_err(|_| "clock tick outside i64")?,
    ])
}

fn tracklet(value: &Value) -> Result<Tracklet, String> {
    let row = fields(
        value,
        &[
            "id",
            "camera",
            "camera_generation",
            "calibration",
            "model",
            "evidence",
            "start",
            "end",
            "support",
        ],
    )?;
    let support = match text(required(row, "support")?)? {
        "declared" => TrackletSupport::Declared,
        "missing" => TrackletSupport::Missing,
        "invalidated" => TrackletSupport::Invalidated,
        "redacted" => TrackletSupport::Redacted,
        _ => return Err("unknown tracklet support state".into()),
    };
    Ok(Tracklet {
        id: id(required(row, "id")?, 256)?,
        camera: id(required(row, "camera")?, 256)?,
        camera_generation: digest(required(row, "camera_generation")?)?,
        calibration: digest(required(row, "calibration")?)?,
        model: digest(required(row, "model")?)?,
        evidence: list(required(row, "evidence")?, 16)?
            .iter()
            .map(digest)
            .collect::<Result<_, _>>()?,
        start: clock_interval(required(row, "start")?)?,
        end: clock_interval(required(row, "end")?)?,
        support,
    })
}

pub(crate) fn transition(value: &Value) -> Result<Transition, String> {
    let row = fields(value, &["from", "to", "transit", "cost", "basis"])?;
    let times = list(required(row, "transit")?, 2)?;
    if times.len() != 2 {
        return Err("transit interval requires two endpoints".into());
    }
    Ok(Transition {
        from: id(required(row, "from")?, 256)?,
        to: id(required(row, "to")?, 256)?,
        transit: [unsigned(&times[0])?, unsigned(&times[1])?],
        cost: unsigned(required(row, "cost")?)?,
        basis: digest(required(row, "basis")?)?,
    })
}

/// Decode the complete bounded query. The native planner additionally validates cross-row
/// relationships, generation compatibility, duplicate declarations and interval geometry.
pub fn parse_query(bytes: &[u8]) -> Result<ContinuityQuery, String> {
    let document = json_input::parse(std::str::from_utf8(bytes).map_err(|_| "query is not UTF-8")?)
        .map_err(|e| e.to_string())?;
    let top = fields(
        &document,
        &[
            "schema",
            "scope",
            "time_unit",
            "cost_unit",
            "birth_cost",
            "end_cost",
            "k",
            "tracklets",
            "transitions",
        ],
    )?;
    if text(required(top, "schema")?)? != QUERY_SCHEMA {
        return Err("unsupported handoff query schema".into());
    }
    let scope = fields(
        required(top, "scope")?,
        &[
            "property",
            "session",
            "privacy_policy",
            "generation",
            "clock",
        ],
    )?;
    let k = u32::try_from(unsigned(required(top, "k")?)?)
        .map_err(|_| "k is outside its integer range")?;
    if !(1..=32).contains(&k) {
        return Err("k must be in 1..=32".into());
    }
    let tracklets = list(required(top, "tracklets")?, 32)?
        .iter()
        .map(tracklet)
        .collect::<Result<Vec<_>, _>>()?;
    if tracklets.is_empty() {
        return Err("at least one tracklet is required".into());
    }
    Ok(ContinuityQuery {
        scope: Scope {
            property: id(required(scope, "property")?, 256)?,
            session: id(required(scope, "session")?, 256)?,
            privacy_policy: digest(required(scope, "privacy_policy")?)?,
            generation: digest(required(scope, "generation")?)?,
            clock: digest(required(scope, "clock")?)?,
        },
        time_unit: id(required(top, "time_unit")?, 64)?,
        cost_unit: id(required(top, "cost_unit")?, 64)?,
        birth_cost: unsigned(required(top, "birth_cost")?)?,
        end_cost: unsigned(required(top, "end_cost")?)?,
        k,
        tracklets,
        transitions: list(required(top, "transitions")?, 32 * 31)?
            .iter()
            .map(transition)
            .collect::<Result<_, _>>()?,
    })
}

fn digest_text(value: ContentDigest) -> String {
    string(&value.to_text())
}

fn interval<T: std::fmt::Display>(value: &[T; 2]) -> String {
    format!("[{},{}]", value[0], value[1])
}

fn scope(value: &Scope) -> String {
    object(&[
        ("property", string(&value.property)),
        ("session", string(&value.session)),
        ("privacy_policy", digest_text(value.privacy_policy)),
        ("generation", digest_text(value.generation)),
        ("clock", digest_text(value.clock)),
    ])
}

fn tracklet_json(value: &Tracklet) -> String {
    object(&[
        ("id", string(&value.id)),
        ("camera", string(&value.camera)),
        ("camera_generation", digest_text(value.camera_generation)),
        ("calibration", digest_text(value.calibration)),
        ("model", digest_text(value.model)),
        (
            "evidence",
            strings(value.evidence.iter().map(|d| d.to_text())),
        ),
        ("start", interval(&value.start)),
        ("end", interval(&value.end)),
        ("support", string(value.support.as_str())),
    ])
}

fn edge(value: &TransitionEdge) -> String {
    object(&[
        ("from", string(&value.from)),
        ("to", string(&value.to)),
        ("cost", value.cost.to_string()),
    ])
}

fn transition_json(value: &Transition) -> String {
    object(&[
        ("from", string(&value.from)),
        ("to", string(&value.to)),
        ("transit", interval(&value.transit)),
        ("cost", value.cost.to_string()),
        ("basis", digest_text(value.basis)),
    ])
}

fn disposition(value: &TransitionDisposition) -> String {
    object(&[
        ("from", string(&value.from)),
        ("to", string(&value.to)),
        (
            "declared",
            value
                .declared
                .as_ref()
                .map_or_else(|| "null".into(), transition_json),
        ),
        ("gap", interval(&value.gap)),
        ("reasons", strings(value.reasons.iter().map(|r| r.as_str()))),
        ("admitted", value.admitted.to_string()),
    ])
}

fn path_cover(value: &PathCover) -> String {
    object(&[
        (
            "paths",
            array(&value.paths.iter().map(strings).collect::<Vec<_>>()),
        ),
        (
            "links",
            array(&value.links.iter().map(edge).collect::<Vec<_>>()),
        ),
        ("starts", strings(&value.starts)),
        ("ends", strings(&value.ends)),
        ("link_cost", value.link_cost.to_string()),
        ("birth_cost", value.birth_cost.to_string()),
        ("end_cost", value.end_cost.to_string()),
        ("total_cost", value.total_cost.to_string()),
    ])
}

fn counts(value: &BTreeMap<String, u64>) -> String {
    let fields: Vec<_> = value
        .iter()
        .map(|(key, value)| format!("{}:{value}", string(key)))
        .collect();
    format!("{{{}}}", fields.join(","))
}

fn certificate<O>(value: &CertifiedRun<O>) -> String {
    object(&[
        ("algorithm_id", string(value.identity.algorithm_id)),
        ("algorithm_name", string(value.identity.algorithm_name)),
        (
            "implementation_id",
            string(value.identity.implementation_id),
        ),
        ("policy_id", string(value.identity.policy_id)),
        (
            "tie_break_policy_id",
            string(value.identity.tie_break_policy_id),
        ),
        (
            "complexity_bound_id",
            string(value.identity.complexity_bound_id),
        ),
        ("exactness", string(value.identity.exactness)),
        ("tie_break_rule", string(value.identity.tie_break_rule)),
        (
            "complexity_witness",
            string(value.identity.complexity_witness),
        ),
        (
            "output_size_witness",
            string(value.identity.output_size_witness),
        ),
        ("output_domain", string(value.identity.output_domain)),
        (
            "decision_path_domain",
            string(value.identity.decision_path_domain),
        ),
        ("node_count", value.node_count.to_string()),
        ("edge_count", value.edge_count.to_string()),
        ("input_digest", digest_text(value.input_digest)),
        ("output_digest", digest_text(value.output_digest)),
        (
            "decision_path_digest",
            digest_text(value.decision_path_digest),
        ),
        ("operation_counts", counts(&value.counters)),
        ("operations", value.operations.to_string()),
        ("output_entries", value.output_entries.to_string()),
        ("peak_working_bytes", value.peak_working_bytes.to_string()),
        ("stop_reason", string("completed")),
    ])
}

fn assignment(value: &Assignment) -> String {
    let pairs = value
        .pairs
        .iter()
        .map(|(from, to, cost)| {
            object(&[
                ("from", string(from)),
                ("to", string(to)),
                ("cost", cost.to_string()),
            ])
        })
        .collect::<Vec<_>>();
    object(&[
        ("pairs", array(&pairs)),
        ("unassigned_left", strings(&value.unassigned_left)),
        ("unassigned_right", strings(&value.unassigned_right)),
        ("matched_cost", value.matched_cost.to_string()),
        ("non_assignment_cost", value.non_assignment_cost.to_string()),
        ("objective", value.objective.to_string()),
    ])
}

fn render(
    run: &CertifiedRun<ContinuityOutput>,
    input: ContentDigest,
    budget: Budget,
) -> Result<String, String> {
    let output = &run.output;
    let NonAssignment::Priced { left, right } = output.matching.output.policy else {
        return Err("unexpected continuity non-assignment policy".into());
    };
    let matching = &output.matching;
    Ok(object(&[
        ("schema", string(REPORT_SCHEMA)),
        ("outcome", string("completed")),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "source_provenance",
            string("owner_declared_handles_not_authenticated_custody"),
        ),
        (
            "association_semantics",
            string("conditional_anonymous_hypotheses"),
        ),
        ("physical_identity_established", "false".into()),
        (
            "cost_semantics",
            string("declared_integer_costs_not_probabilities"),
        ),
        (
            "temporal_semantics",
            string("strictly_forward_robust_over_all_declared_endpoint_times"),
        ),
        ("input_document_digest", digest_text(input)),
        ("scope", scope(&output.scope)),
        ("time_unit", string(&output.time_unit)),
        ("cost_unit", string(&output.cost_unit)),
        ("birth_cost", output.birth_cost.to_string()),
        ("end_cost", output.end_cost.to_string()),
        (
            "tracklets",
            array(
                &output
                    .tracklets
                    .iter()
                    .map(tracklet_json)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "transitions",
            array(
                &output
                    .transitions
                    .iter()
                    .map(disposition)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "alternative_family",
            object(&[
                (
                    "representation",
                    string(
                        "all_subsets_of_forward_edges_with_at_most_one_predecessor_and_successor_per_member",
                    ),
                ),
                ("complete_for_declared_domain", "true".into()),
                ("members", strings(&output.family.members)),
                (
                    "edges",
                    array(&output.family.edges.iter().map(edge).collect::<Vec<_>>()),
                ),
                ("all_singletons", path_cover(&output.family.all_singletons)),
            ]),
        ),
        (
            "alternatives",
            array(
                &output
                    .alternatives
                    .iter()
                    .map(path_cover)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "requested_alternatives",
            matching.output.requested.to_string(),
        ),
        (
            "displayed_prefix_complete",
            output.displayed_prefix_complete.to_string(),
        ),
        ("continuity_certificate", certificate(run)),
        ("matching_certificate", certificate(matching)),
        (
            "matching_output",
            object(&[
                ("policy", string("priced_non_assignment")),
                ("left_price", left.to_string()),
                ("right_price", right.to_string()),
                ("requested", matching.output.requested.to_string()),
                ("exhausted", matching.output.exhausted.to_string()),
                (
                    "assignments",
                    array(
                        &matching
                            .output
                            .assignments
                            .iter()
                            .map(assignment)
                            .collect::<Vec<_>>(),
                    ),
                ),
            ]),
        ),
        (
            "budget",
            object(&[
                ("max_operations", budget.max_operations.to_string()),
                ("max_output_entries", budget.max_output_entries.to_string()),
            ]),
        ),
    ]))
}

/// Run the exact production planner over a strict query and render its complete report.
/// Cancellation or either allowance refuses the entire answer; no ranked prefix escapes.
/// `max_report_bytes` includes the newline the command writes after the returned document.
pub fn analyze(
    bytes: &[u8],
    budget: Budget,
    max_report_bytes: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, QueryError> {
    if budget.max_operations == 0
        || budget.max_operations > MAX_WORK
        || budget.max_output_entries == 0
        || budget.max_output_entries > MAX_OUTPUT_ENTRIES
        || !(1024..=MAX_REPORT_BYTES).contains(&max_report_bytes)
    {
        return Err(QueryError::Allowance);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    let query = parse_query(bytes).map_err(QueryError::Input)?;
    let run = continuity::plan_with_cancel(&query, budget, cancelled).map_err(QueryError::Graph)?;
    let report = render(&run, ContentDigest::sha256(bytes), budget)
        .map_err(|detail| QueryError::Graph(GraphError::Inconsistent(detail)))?;
    if report.len() + 1 > max_report_bytes {
        return Err(QueryError::ReportLimit);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    Ok(report)
}

/// Analyze a typed query supplied by a source owner, using the same native solver and
/// unchanged conditional report as the owner-document entrypoint. This pure operation
/// does not authenticate the handles: a custody owner must carry its separate projection
/// witness and revalidate it before returning the enclosing report.
pub fn analyze_prepared(
    query: &ContinuityQuery,
    input_document: ContentDigest,
    budget: Budget,
    max_report_bytes: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, QueryError> {
    if budget.max_operations == 0
        || budget.max_operations > MAX_WORK
        || budget.max_output_entries == 0
        || budget.max_output_entries > MAX_OUTPUT_ENTRIES
        || !(1024..=MAX_REPORT_BYTES).contains(&max_report_bytes)
    {
        return Err(QueryError::Allowance);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    let run = continuity::plan_with_cancel(query, budget, cancelled).map_err(QueryError::Graph)?;
    let report = render(&run, input_document, budget)
        .map_err(|detail| QueryError::Graph(GraphError::Inconsistent(detail)))?;
    if report.len() + 1 > max_report_bytes {
        return Err(QueryError::ReportLimit);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    Ok(report)
}
