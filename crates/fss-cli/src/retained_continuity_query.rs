#![forbid(unsafe_code)]
//! Strict selection and complete report for handoffs over retained package observations.
//!
//! Parsing selects existing immutable evidence; it does not authenticate it. The reference
//! package owner must reconstruct and revalidate the sealed projection before this serializer's
//! derived output is returned. Clock alignment, calibration and transition costs remain explicit
//! operator assumptions even when the original source bytes and observations are authenticated.

use fss_core::{CanonicalEncode, ClockBasis, ContentDigest, LedgerAnchor, StreamId};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::continuity::ContinuityQuery;

use crate::continuity_query::{
    self, QueryError, clock_interval, digest, fields, id, list, required, text, transition,
    unsigned,
};
use crate::json_input::{self, Value};
use crate::json_output::{array, object, string, strings};
use crate::retained_handoff_contract::{
    PackageClockAlignment, PackageHandoffBinding, PackageHandoffObservation, PackageHandoffRequest,
    PackageHandoffSelection, PackageHandoffTracking,
};

/// Strict bounded selection of source-authenticated package tracks.
pub const QUERY_SCHEMA: &str = "fss.scene_handoffs_retained_query.v1";
/// Complete custody projection and its conditional anonymous association analysis.
pub const REPORT_SCHEMA: &str = "fss.scene_handoffs_retained.v1";
/// Maximum selection document, before JSON allocation.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum complete report including every selected observation and final newline.
pub const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;

fn u32_value(value: &Value) -> Result<u32, String> {
    u32::try_from(unsigned(value)?).map_err(|_| "integer is outside u32".into())
}

fn tracking(value: &Value) -> Result<PackageHandoffTracking, String> {
    let row = fields(
        value,
        &[
            "confirmation_hits",
            "maximum_missed_frames",
            "minimum_iou_ppm",
        ],
    )?;
    let value = PackageHandoffTracking {
        confirmation_hits: u32_value(required(row, "confirmation_hits")?)?,
        maximum_missed_frames: u32_value(required(row, "maximum_missed_frames")?)?,
        minimum_iou_ppm: u32_value(required(row, "minimum_iou_ppm")?)?,
    };
    value.validate().map_err(|e| e.to_string())?;
    Ok(value)
}

fn alignment(value: &Value) -> Result<PackageClockAlignment, String> {
    let row = fields(
        value,
        &[
            "import_identity",
            "stream_id",
            "clock_basis",
            "offset_ns",
            "basis",
        ],
    )?;
    let stream = text(required(row, "stream_id")?)?;
    if stream.len() > 256 {
        return Err("stream identity exceeds the bounded selection profile".into());
    }
    let stream_id = StreamId::parse(stream).map_err(|_| "invalid stream identity")?;
    let offset_ns = clock_interval(required(row, "offset_ns")?)?;
    if offset_ns[0] > offset_ns[1] {
        return Err("clock offset interval is reversed".into());
    }
    Ok(PackageClockAlignment {
        import_identity: digest(required(row, "import_identity")?)?,
        stream_id: stream_id.as_str().to_owned(),
        clock_basis: ClockBasis::parse(text(required(row, "clock_basis")?)?)
            .map_err(|_| "unknown original clock basis")?,
        offset_ns,
        basis: digest(required(row, "basis")?)?,
    })
}

fn selection(value: &Value) -> Result<PackageHandoffSelection, String> {
    let row = fields(
        value,
        &[
            "id",
            "report_digest",
            "label",
            "tracking",
            "track",
            "calibration",
            "alignment",
        ],
    )?;
    let label = text(required(row, "label")?)?;
    if label.is_empty() || label.len() > 512 {
        return Err("label must contain 1..512 UTF-8 bytes".into());
    }
    Ok(PackageHandoffSelection {
        id: id(required(row, "id")?, 256)?,
        report_digest: digest(required(row, "report_digest")?)?,
        label: label.to_owned(),
        tracking: tracking(required(row, "tracking")?)?,
        track: digest(required(row, "track")?)?,
        calibration: digest(required(row, "calibration")?)?,
        alignment: alignment(required(row, "alignment")?)?,
    })
}

/// Parse a selection without accepting caller-supplied capture endpoints, sensor identities,
/// detector outputs or model comparison keys. Those facts must come from retained custody.
pub fn parse_query(bytes: &[u8]) -> Result<PackageHandoffRequest, String> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("retained handoff selection exceeds 1 MiB".into());
    }
    let value =
        json_input::parse(std::str::from_utf8(bytes).map_err(|_| "selection must be UTF-8")?)
            .map_err(|e| e.to_string())?;
    let top = fields(
        &value,
        &[
            "schema",
            "session",
            "generation",
            "clock",
            "cost_unit",
            "birth_cost",
            "end_cost",
            "k",
            "selections",
            "transitions",
        ],
    )?;
    if text(required(top, "schema")?)? != QUERY_SCHEMA {
        return Err("unsupported retained handoff selection schema".into());
    }
    let k = u32_value(required(top, "k")?)?;
    if !(1..=32).contains(&k) {
        return Err("k must be in 1..=32".into());
    }
    let selections = list(required(top, "selections")?, 32)?
        .iter()
        .map(selection)
        .collect::<Result<Vec<_>, _>>()?;
    if selections.is_empty() {
        return Err("at least one retained track must be selected".into());
    }
    let request = PackageHandoffRequest {
        session: id(required(top, "session")?, 256)?,
        generation: digest(required(top, "generation")?)?,
        clock: digest(required(top, "clock")?)?,
        cost_unit: id(required(top, "cost_unit")?, 64)?,
        birth_cost: unsigned(required(top, "birth_cost")?)?,
        end_cost: unsigned(required(top, "end_cost")?)?,
        k,
        selections,
        transitions: list(required(top, "transitions")?, 32 * 31)?
            .iter()
            .map(transition)
            .collect::<Result<_, _>>()?,
    };
    request.validate().map_err(|e| e.to_string())?;
    Ok(request)
}

fn d(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn numbers<T: std::fmt::Display>(values: &[T]) -> String {
    array(&values.iter().map(ToString::to_string).collect::<Vec<_>>())
}

/// Exact canonical anchor hash accepted by the command's optional expected-anchor pin.
#[must_use]
pub fn anchor_digest(anchor: &LedgerAnchor) -> ContentDigest {
    ContentDigest::sha256(&anchor.canonical_bytes())
}

fn anchor_json(value: &LedgerAnchor) -> String {
    object(&[
        ("site_lineage", string(&value.site_lineage)),
        ("ledger_epoch", value.ledger_epoch.to_string()),
        ("commit_sequence", value.commit_sequence.to_string()),
        (
            "adapter_registry_epoch",
            value.adapter_registry_epoch.to_string(),
        ),
        ("schema_epoch", value.schema_epoch.to_string()),
        ("policy_epoch", value.policy_epoch.to_string()),
        ("privacy_epoch", value.privacy_epoch.to_string()),
        ("state_root", d(value.state_root)),
    ])
}

fn tracking_json(value: &PackageHandoffTracking) -> String {
    object(&[
        ("confirmation_hits", value.confirmation_hits.to_string()),
        (
            "maximum_missed_frames",
            value.maximum_missed_frames.to_string(),
        ),
        ("minimum_iou_ppm", value.minimum_iou_ppm.to_string()),
    ])
}

fn alignment_json(value: &PackageClockAlignment) -> String {
    object(&[
        ("import_identity", d(value.import_identity)),
        ("stream_id", string(&value.stream_id)),
        ("clock_basis", string(value.clock_basis.as_str())),
        ("offset_ns", numbers(&value.offset_ns)),
        ("basis", d(value.basis)),
    ])
}

fn observation(value: &PackageHandoffObservation) -> String {
    object(&[
        ("segment", value.segment.to_string()),
        ("capsule_digest", d(value.capsule_digest)),
        ("source_digest", d(value.source_digest)),
        ("capture", numbers(&value.capture)),
        ("aligned_capture", numbers(&value.aligned_capture)),
        ("detection_row", value.detection_row.to_string()),
        ("class_index", value.class_index.to_string()),
        ("score_bits", value.score_bits.to_string()),
        ("bounds", numbers(&value.bounds)),
        ("confirmed", value.confirmed.to_string()),
        ("inference_identity", d(value.inference_identity)),
        ("output_digest", d(value.output_digest)),
        ("detection_report_digest", d(value.detection_report_digest)),
    ])
}

fn binding(value: &PackageHandoffBinding) -> String {
    object(&[
        ("id", string(&value.id)),
        ("report_digest", d(value.report_digest)),
        ("analysis_digest", d(value.analysis_digest)),
        ("record_digest", d(value.record_digest)),
        ("retained_root", d(value.retained_root)),
        ("import_identity", d(value.import_identity)),
        ("import_root", d(value.import_root)),
        ("retained_anchor", anchor_json(&value.retained_anchor)),
        ("track", d(value.track)),
        ("confirmed", value.confirmed.to_string()),
        ("sensor_id", string(&value.sensor_id)),
        ("stream_id", string(&value.stream_id)),
        ("clock_basis", string(value.clock_basis.as_str())),
        ("capture_time_label", string(&value.capture_time_label)),
        ("dimensions", numbers(&value.dimensions)),
        ("camera_generation", d(value.camera_generation)),
        ("calibration", d(value.calibration)),
        ("model", d(value.model)),
        ("package_digest", d(value.package_digest)),
        ("manifest_digest", d(value.manifest_digest)),
        ("model_digest", d(value.model_digest)),
        ("graph_digest", d(value.graph_digest)),
        ("contract_digest", d(value.contract_digest)),
        ("model_id", string(&value.model_id)),
        ("model_generation", string(&value.model_generation)),
        ("label", string(&value.label)),
        ("class_index", value.class_index.to_string()),
        ("tracking", tracking_json(&value.tracking)),
        ("privacy_binding", d(value.privacy_binding)),
        (
            "privacy_policy",
            value.privacy_policy.map_or_else(|| "null".into(), d),
        ),
        ("alignment", alignment_json(&value.alignment)),
        (
            "observations",
            array(
                &value
                    .observations
                    .iter()
                    .map(observation)
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}

/// Borrowed output of a sealed source-owner projection. Constructing this view grants no
/// authority; the owner must revalidate the original projection before releasing its report.
pub struct RetainedReportInput<'a> {
    /// Exact input selection bytes, independently of canonical projection and solver inputs.
    pub input_document: ContentDigest,
    /// Digest of the full canonical custody projection and declared assumptions.
    pub projection_digest: ContentDigest,
    /// Exact deployment authority observed by the source owner.
    pub anchor: &'a LedgerAnchor,
    /// Every selected native track and every actual assigned observation.
    pub bindings: &'a [PackageHandoffBinding],
    /// Native continuity query derived by the source owner.
    pub query: &'a ContinuityQuery,
}

/// Run the native planner and render the complete retained projection and conditional analysis.
/// The nested v1 analysis preserves its original pure-handle semantics and certificates; the
/// enclosing source-owner witness supplies custody provenance without certifying assumptions.
pub fn analyze(
    input: RetainedReportInput<'_>,
    budget: Budget,
    max_report_bytes: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, QueryError> {
    if !(1024..=MAX_REPORT_BYTES).contains(&max_report_bytes)
        || input.bindings.is_empty()
        || input.bindings.len() > 32
        || input
            .bindings
            .iter()
            .any(|b| b.observations.is_empty() || b.observations.len() > 64)
    {
        return Err(QueryError::Allowance);
    }
    let conditional = continuity_query::analyze_prepared(
        input.query,
        input.input_document,
        budget,
        continuity_query::MAX_REPORT_BYTES,
        cancelled,
    )?;
    let report = object(&[
        ("schema", string(REPORT_SCHEMA)),
        ("outcome", string("completed")),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "source_provenance",
            string("verified_retained_package_observations"),
        ),
        ("source_scope", string("selected_tracks_in_one_deployment")),
        ("physical_identity_established", "false".into()),
        ("input_document_digest", d(input.input_document)),
        ("projection_digest", d(input.projection_digest)),
        ("anchor_digest", d(anchor_digest(input.anchor))),
        ("anchor", anchor_json(input.anchor)),
        (
            "assumptions",
            strings([
                "clock_alignment_and_common_clock_are_operator_declarations",
                "calibration_handles_do_not_certify_geometry",
                "transition_costs_and_transit_bounds_are_operator_declarations",
                "source_custody_does_not_establish_detector_accuracy_or_physical_identity",
                "complete_alternative_family_is_only_for_selected_tracks_and_admitted_robust_edges",
            ]),
        ),
        (
            "bindings",
            array(&input.bindings.iter().map(binding).collect::<Vec<_>>()),
        ),
        ("conditional_analysis", conditional),
    ]);
    if report.len() + 1 > max_report_bytes {
        return Err(QueryError::ReportLimit);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    Ok(report)
}
