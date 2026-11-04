#![forbid(unsafe_code)]
//! Conservative clock replay over authenticated retained package observations.
//!
//! The unchanged source owner authenticates the original local captures. A separate derived
//! query uses every original clock hypothesis, including unsupported hypotheses. Camera/clock
//! associations and the clock query's observation pins remain declarations; this bridge neither
//! authenticates those observations nor activates a physical clock or calibration.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ClockBasis, ContentDigest, SensorId, StreamId};
use fss_geometry::{GeometryError, WorkBudget};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::continuity::{self, ContinuityQuery};
use fss_reference::ingest::package_handoffs::PackageHandoffProjection;

use crate::clock_alignment::{ClockValidationQuery, ClockValidationReplay};
use crate::continuity_query::{
    self, QueryError, digest, fields, id, list, required, text, transition, unsigned,
};
use crate::json_input::{self, Value};
use crate::json_output::{array, object, string, strings};
use crate::retained_continuity_query::{self as retained, RetainedReportInput};
use crate::retained_handoff_contract::{
    self as contract, PackageClockAlignment, PackageHandoffRequest, PackageHandoffSelection,
};

/// Explicit two-stream selection with original native clock-query replay.
pub const QUERY_SCHEMA: &str = "fss.scene_handoffs_retained_query.v2";
/// Complete source projection, separate mapped observations, clock replay and solver proof.
pub const REPORT_SCHEMA: &str = "fss.scene_handoffs_retained.v2";
/// Domain of the derived timing projection; the original source projection stays unchanged.
pub const PROJECTION_DOMAIN: &str = "fss.package_handoff_clock_projection.v1";
/// Complete unique target-capsule inventory, bounded by the existing clock owner.
pub const MAX_PROJECTIONS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamBinding {
    camera: u64,
    clock: u64,
    import: ContentDigest,
    sensor: String,
    stream: String,
    basis: ClockBasis,
    calibration: ContentDigest,
    image_domain: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectionBinding {
    capsule: ContentDigest,
    projection: u64,
}

/// Privately admitted selection. Its source request uses identity mappings solely to preserve
/// the unchanged custody owner's original local captures; those are never the derived times.
#[derive(Clone, Debug)]
pub struct ClockHandoffRequest {
    input_document: ContentDigest,
    input_bytes: usize,
    source: PackageHandoffRequest,
    query_path: String,
    query_digest: ContentDigest,
    world: ContentDigest,
    streams: [StreamBinding; 2],
    projections: Vec<ProjectionBinding>,
}

impl ClockHandoffRequest {
    /// Existing custody-owner request with zero offsets, bound to the original clock query.
    pub fn source_request(&self) -> &PackageHandoffRequest {
        &self.source
    }
    /// Explicit original-query file. The command resolves relative paths beside the selection.
    pub fn clock_query_path(&self) -> &str {
        &self.query_path
    }
    /// Pin checked by native admission before evaluating any original clock observations.
    pub fn clock_query_digest(&self) -> ContentDigest {
        self.query_digest
    }
}

fn positive(value: &Value) -> Result<u64, String> {
    unsigned(value).and_then(|n| {
        if n == 0 {
            Err("expected a nonzero integer".into())
        } else {
            Ok(n)
        }
    })
}

fn stream(value: &Value) -> Result<StreamBinding, String> {
    let row = fields(
        value,
        &[
            "camera",
            "clock_generation",
            "import_identity",
            "sensor_id",
            "stream_id",
            "clock_basis",
            "calibration_digest",
            "image_domain",
        ],
    )?;
    let sensor = id(required(row, "sensor_id")?, 256)?;
    let stream = id(required(row, "stream_id")?, 256)?;
    SensorId::parse(&sensor).map_err(|_| "invalid bound sensor")?;
    StreamId::parse(&stream).map_err(|_| "invalid bound stream")?;
    Ok(StreamBinding {
        camera: positive(required(row, "camera")?)?,
        clock: positive(required(row, "clock_generation")?)?,
        import: digest(required(row, "import_identity")?)?,
        sensor,
        stream,
        basis: ClockBasis::parse(text(required(row, "clock_basis")?)?)
            .map_err(|_| "invalid original clock basis")?,
        calibration: digest(required(row, "calibration_digest")?)?,
        image_domain: digest(required(row, "image_domain")?)?,
    })
}

/// Admit the v2 selection without opening source custody or trusting a serialized success.
/// Both streams and every projection must be selected exactly; extra fields are refused.
pub fn parse_query(bytes: &[u8]) -> Result<ClockHandoffRequest, String> {
    if bytes.is_empty() || bytes.len() > retained::MAX_INPUT_BYTES {
        return Err("clock-backed handoff selection exceeds 1 MiB".into());
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
            "cost_unit",
            "birth_cost",
            "end_cost",
            "k",
            "selections",
            "transitions",
            "clock_validation",
        ],
    )?;
    if text(required(top, "schema")?)? != QUERY_SCHEMA {
        return Err("unsupported clock-backed retained handoff schema".into());
    }
    let clock = fields(
        required(top, "clock_validation")?,
        &[
            "query_path",
            "query_digest",
            "world_basis",
            "reference",
            "target",
            "projections",
        ],
    )?;
    let path = text(required(clock, "query_path")?)?;
    if path.is_empty()
        || path.len() > 4096
        || path.trim() != path
        || path.chars().any(char::is_control)
    {
        return Err("original clock query path is empty, malformed or exceeds 4096 bytes".into());
    }
    let query_digest = digest(required(clock, "query_digest")?)?;
    let streams = [
        stream(required(clock, "reference")?)?,
        stream(required(clock, "target")?)?,
    ];
    if streams[0].camera == streams[1].camera
        || streams[0].clock == streams[1].clock
        || streams[0].sensor == streams[1].sensor
        || streams[0].stream == streams[1].stream
        || streams[0].import == streams[1].import
    {
        return Err(
            "clock replay requires two distinct cameras, clocks, imports, sensors and streams"
                .into(),
        );
    }
    let mut capsules = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut projections = Vec::new();
    for row in list(required(clock, "projections")?, MAX_PROJECTIONS)? {
        let row = fields(row, &["capsule_digest", "projection_id"])?;
        let binding = ProjectionBinding {
            capsule: digest(required(row, "capsule_digest")?)?,
            projection: positive(required(row, "projection_id")?)?,
        };
        if !capsules.insert(binding.capsule) || !ids.insert(binding.projection) {
            return Err("target capsule or projection is repeated".into());
        }
        projections.push(binding);
    }
    if projections.is_empty() {
        return Err("clock replay requires the complete nonempty target-capsule inventory".into());
    }
    projections.sort_unstable_by_key(|p| p.capsule);
    let mut selected_streams = [false; 2];
    let mut selections = Vec::new();
    for value in list(required(top, "selections")?, 32)? {
        let row = fields(
            value,
            &[
                "id",
                "report_digest",
                "label",
                "tracking",
                "track",
                "source",
            ],
        )?;
        let side = match text(required(row, "source")?)? {
            "reference" => 0,
            "target" => 1,
            _ => return Err("selection source must be reference or target".into()),
        };
        selected_streams[side] = true;
        let bound = &streams[side];
        selections.push(PackageHandoffSelection {
            id: id(required(row, "id")?, 256)?,
            report_digest: digest(required(row, "report_digest")?)?,
            label: text(required(row, "label")?)?.to_owned(),
            tracking: retained::tracking(required(row, "tracking")?)?,
            track: digest(required(row, "track")?)?,
            calibration: bound.calibration,
            alignment: PackageClockAlignment {
                import_identity: bound.import,
                stream_id: bound.stream.clone(),
                clock_basis: bound.basis,
                offset_ns: [0, 0],
                basis: query_digest,
            },
        });
    }
    if selected_streams != [true, true] {
        return Err("both declared source streams must have selected native tracks".into());
    }
    let source = PackageHandoffRequest {
        session: id(required(top, "session")?, 256)?,
        generation: digest(required(top, "generation")?)?,
        clock: query_digest,
        cost_unit: id(required(top, "cost_unit")?, 64)?,
        birth_cost: unsigned(required(top, "birth_cost")?)?,
        end_cost: unsigned(required(top, "end_cost")?)?,
        k: u32::try_from(unsigned(required(top, "k")?)?).map_err(|_| "k exceeds u32")?,
        selections,
        transitions: list(required(top, "transitions")?, 32 * 31)?
            .iter()
            .map(transition)
            .collect::<Result<_, _>>()?,
    };
    source.validate().map_err(|e| e.to_string())?;
    Ok(ClockHandoffRequest {
        input_document: ContentDigest::sha256(bytes),
        input_bytes: bytes.len(),
        source,
        query_path: path.to_owned(),
        query_digest,
        world: digest(required(clock, "world_basis")?)?,
        streams,
        projections,
    })
}

fn charge(work: &mut WorkBudget<'_>, units: u64) -> Result<(), QueryError> {
    work.charge(units).map_err(|e| match e {
        GeometryError::Cancelled => QueryError::Cancelled,
        _ => QueryError::Allowance,
    })
}
fn invalid(detail: &'static str) -> QueryError {
    QueryError::Input(detail.into())
}
fn clock_error(error: crate::clock_alignment::Failure) -> QueryError {
    match error.code {
        "ERR-CLOCK-ALIGNMENT-CANCELLED-001" => QueryError::Cancelled,
        "ERR-CLOCK-ALIGNMENT-LIMIT-001" => QueryError::Allowance,
        _ => QueryError::Input(error.to_string()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MappedObservation {
    capsule: ContentDigest,
    original: [i128; 2],
    common: [i64; 2],
    projection: Option<u64>,
    containing_sessions: Vec<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct MappedTrack {
    id: String,
    observations: Vec<MappedObservation>,
}

fn prepare_clock(
    request: &ClockHandoffRequest,
    bytes: &[u8],
    work: &mut WorkBudget<'_>,
) -> Result<ClockValidationReplay, QueryError> {
    charge(work, 4096 + request.input_bytes as u64 * 4)?;
    let query = ClockValidationQuery::parse_pinned(bytes, request.query_digest, work)
        .map_err(clock_error)?;
    let pair = query.pair();
    if query.world_basis() != request.world
        || pair.reference_camera != request.streams[0].camera
        || pair.target_camera != request.streams[1].camera
        || pair.reference_clock != request.streams[0].clock
        || pair.target_clock != request.streams[1].clock
    {
        return Err(invalid(
            "original clock world, camera or clock generation differs from the declared handoff scope",
        ));
    }
    for bound in &request.streams {
        let camera = query
            .cameras()
            .iter()
            .find(|c| c.id == bound.camera)
            .ok_or_else(|| invalid("clock query camera missing"))?;
        if camera.calibration != bound.calibration
            || camera.image_domain != bound.image_domain
            || camera.clock != bound.clock
        {
            return Err(invalid(
                "clock camera calibration, image domain or clock generation differs",
            ));
        }
    }
    let declared: BTreeSet<_> = request.projections.iter().map(|p| p.projection).collect();
    let original: BTreeSet<_> = query.projections().iter().map(|p| p.id).collect();
    if declared != original {
        return Err(invalid(
            "original clock query must contain exactly the selected projection inventory",
        ));
    }
    query.evaluate(work).map_err(clock_error)
}

/// Private derivation seam: public callers must supply the opaque source-owner projection.
fn derive(
    request: &ClockHandoffRequest,
    source: RetainedReportInput<'_>,
    replay: &ClockValidationReplay,
    work: &mut WorkBudget<'_>,
) -> Result<(ContinuityQuery, Vec<MappedTrack>), QueryError> {
    let rebuilt = contract::continuity_query(source.anchor, &request.source, source.bindings)
        .map_err(|e| QueryError::Input(e.to_string()))?;
    if &rebuilt != source.query {
        return Err(invalid(
            "sealed source projection belongs to a different handoff selection",
        ));
    }
    let mut query = rebuilt;
    let mut mapped = Vec::with_capacity(source.bindings.len());
    let mut used_capsules = BTreeSet::new();
    let mut actual_streams = BTreeSet::new();
    let projections: BTreeMap<_, _> = request
        .projections
        .iter()
        .map(|p| (p.capsule, p.projection))
        .collect();
    for binding in source.bindings {
        charge(work, 512 + binding.observations.len() as u64 * 256)?;
        let side = request
            .streams
            .iter()
            .position(|s| s.import == binding.import_identity)
            .ok_or_else(|| invalid("retained source is outside the clock stream inventory"))?;
        let bound = &request.streams[side];
        actual_streams.insert(side);
        let camera = replay
            .query()
            .cameras()
            .iter()
            .find(|c| c.id == bound.camera)
            .ok_or_else(|| invalid("retained source has no original clock camera"))?;
        if binding.sensor_id != bound.sensor
            || binding.stream_id != bound.stream
            || binding.clock_basis != bound.basis
            || binding.calibration != bound.calibration
            || binding.dimensions != camera.intrinsics.dimensions()
            || binding.alignment.offset_ns != [0, 0]
            || binding.alignment.basis != request.query_digest
        {
            return Err(invalid(
                "actual retained import, sensor, stream, clock basis or image mode differs from the clock binding",
            ));
        }
        let mut observations = Vec::with_capacity(binding.observations.len());
        for observation in &binding.observations {
            let (common, projection, containing_sessions) = if side == 0 {
                (observation.capture, None, Vec::new())
            } else {
                let id = *projections
                    .get(&observation.capsule_digest)
                    .ok_or_else(|| {
                        invalid("selected target observation has no frozen clock projection")
                    })?;
                let projected = replay
                    .report()
                    .projections
                    .iter()
                    .find(|p| p.request.id == id)
                    .ok_or_else(|| invalid("native clock replay omitted a selected projection"))?;
                if projected.request.target_interval_ns != observation.capture {
                    return Err(invalid(
                        "clock projection must match the entire actual retained capture interval",
                    ));
                }
                used_capsules.insert(observation.capsule_digest);
                (
                    projected.reference_envelope_ns,
                    Some(id),
                    projected.containing_session_ids.clone(),
                )
            };
            let common = [
                i64::try_from(common[0])
                    .map_err(|_| invalid("clock projection exceeds signed handoff nanoseconds"))?,
                i64::try_from(common[1])
                    .map_err(|_| invalid("clock projection exceeds signed handoff nanoseconds"))?,
            ];
            observations.push(MappedObservation {
                capsule: observation.capsule_digest,
                original: observation.capture,
                common,
                projection,
                containing_sessions,
            });
        }
        // Display-order endpoints are meaningful only when their full intervals remain
        // ordered. An interior capture outside those bounds cannot silently disappear from
        // the solver's transit gate. Refuse discontinuous/reordered original or mapped times.
        if observations.windows(2).any(|pair| {
            pair[0].original[0] > pair[1].original[0]
                || pair[0].original[1] > pair[1].original[1]
                || pair[0].common[0] > pair[1].common[0]
                || pair[0].common[1] > pair[1].common[1]
        }) {
            return Err(invalid(
                "retained or mapped track capture intervals are reordered or discontinuous",
            ));
        }
        let tracklet = query
            .tracklets
            .iter_mut()
            .find(|t| t.id == binding.id)
            .ok_or_else(|| invalid("native handoff query omitted a selected track"))?;
        tracklet.start = observations
            .first()
            .ok_or_else(|| invalid("empty retained track"))?
            .common;
        tracklet.end = observations
            .last()
            .ok_or_else(|| invalid("empty retained track"))?
            .common;
        mapped.push(MappedTrack {
            id: binding.id.clone(),
            observations,
        });
    }
    if actual_streams.len() != 2 || used_capsules.len() != projections.len() {
        return Err(invalid(
            "clock source or target projection inventory is incomplete or contains unused entries",
        ));
    }
    mapped.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    charge(work, 0)?;
    Ok((query, mapped))
}

fn d(digest: ContentDigest) -> String {
    string(&digest.to_text())
}
fn numbers<T: std::fmt::Display>(values: &[T]) -> String {
    array(&values.iter().map(ToString::to_string).collect::<Vec<_>>())
}
fn mapped_json(track: &MappedTrack) -> String {
    object(&[
        ("id", string(&track.id)),
        (
            "observations",
            array(
                &track
                    .observations
                    .iter()
                    .map(|o| {
                        object(&[
                            ("capsule_digest", d(o.capsule)),
                            ("original_capture_ns", numbers(&o.original)),
                            ("common_capture_ns", numbers(&o.common)),
                            (
                                "projection_id",
                                o.projection
                                    .map_or_else(|| "null".into(), |id| id.to_string()),
                            ),
                            ("containing_session_ids", numbers(&o.containing_sessions)),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}
fn stream_json(bound: &StreamBinding) -> String {
    object(&[
        ("camera", bound.camera.to_string()),
        ("clock_generation", bound.clock.to_string()),
        ("import_identity", d(bound.import)),
        ("sensor_id", string(&bound.sensor)),
        ("stream_id", string(&bound.stream)),
        ("clock_basis", string(bound.basis.as_str())),
        ("calibration_digest", d(bound.calibration)),
        ("image_domain", d(bound.image_domain)),
    ])
}

/// Borrowed exact v2 request, its sealed source-owner result and original clock-query bytes.
pub struct ClockReportInput<'a> {
    /// The strict original v2 request; mutable reconstructed public source records are insufficient.
    pub request: &'a ClockHandoffRequest,
    /// Authenticated source projection, revalidated by the caller immediately before release.
    pub projection: &'a PackageHandoffProjection,
    /// Original pinned native validation query, never a serialized success report.
    pub clock_query: &'a [u8],
}

/// Replay, bind every source exposure, solve native handoffs and render the complete report.
/// Clock admission, replay, derivation and the solver consume one nonrefillable work allowance.
/// No source projection is mutated; no result is returned on any incomplete inventory or limit.
pub fn analyze(
    input: ClockReportInput<'_>,
    work: &mut WorkBudget<'_>,
    maximum_report_bytes: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, QueryError> {
    if !(1024..=retained::MAX_REPORT_BYTES).contains(&maximum_report_bytes)
        || work.remaining() > continuity_query::MAX_WORK
    {
        return Err(QueryError::Allowance);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    let request = input.request;
    let source = RetainedReportInput {
        input_document: request.input_document,
        projection_digest: input.projection.digest(),
        anchor: input.projection.anchor(),
        bindings: input.projection.bindings(),
        query: input.projection.query(),
    };
    let replay = prepare_clock(request, input.clock_query, work)?;
    let (query, mapped) = derive(request, source, &replay, work)?;
    let native_clock = replay.render(work).map_err(clock_error)?;
    let original_query_json = string(
        std::str::from_utf8(input.clock_query).map_err(|_| invalid("clock query is not UTF-8"))?,
    );
    let source_bindings: Vec<_> = input
        .projection
        .bindings()
        .iter()
        .map(retained::source_binding_json)
        .collect();
    let mapped_bindings: Vec<_> = mapped.iter().map(mapped_json).collect();
    let bytes_to_render = native_clock.len()
        + input.clock_query.len()
        + original_query_json.len()
        + source_bindings.iter().map(String::len).sum::<usize>()
        + mapped_bindings.iter().map(String::len).sum::<usize>();
    charge(work, 4096 + bytes_to_render as u64 * 2)?;
    let graph_budget = Budget::new(work.remaining(), continuity_query::MAX_OUTPUT_ENTRIES);
    let run =
        continuity::plan_with_cancel(&query, graph_budget, cancelled).map_err(QueryError::Graph)?;
    charge(work, run.operations)?;
    let conditional = continuity_query::render(&run, request.input_document, graph_budget)
        .map_err(QueryError::Input)?;
    let mut e = CanonicalEncoder::new();
    e.text(PROJECTION_DOMAIN);
    e.digest(request.input_document);
    e.digest(input.projection.digest());
    e.digest(request.query_digest);
    e.digest(request.world);
    e.digest(run.input_digest);
    e.u64(mapped.len() as u64);
    for track in &mapped {
        e.text(&track.id);
        e.u64(track.observations.len() as u64);
        for observation in &track.observations {
            e.digest(observation.capsule);
            for n in observation.original {
                e.i128(n);
            }
            for n in observation.common {
                e.i128(i128::from(n));
            }
            e.bool(observation.projection.is_some());
            if let Some(id) = observation.projection {
                e.u64(id);
            }
            e.u64(observation.containing_sessions.len() as u64);
            for id in &observation.containing_sessions {
                e.u64(*id);
            }
        }
    }
    let projection_digest = ContentDigest::sha256(
        &e.finish_checked()
            .map_err(|error| QueryError::Input(error.to_string()))?,
    );
    let report = object(&[
        ("schema", string(REPORT_SCHEMA)),
        ("outcome", string("completed")),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "source_provenance",
            string("verified_retained_package_observations"),
        ),
        ("physical_identity_established", "false".into()),
        ("clock_activated", "false".into()),
        ("clock_observation_custody_verified", "false".into()),
        ("input_document_digest", d(request.input_document)),
        ("projection_digest", d(projection_digest)),
        ("world_basis", d(request.world)),
        (
            "anchor_digest",
            d(retained::anchor_digest(input.projection.anchor())),
        ),
        (
            "anchor",
            retained::authority_anchor_json(input.projection.anchor()),
        ),
        (
            "source_projection",
            object(&[
                ("digest", d(input.projection.digest())),
                (
                    "time_interpretation",
                    string("identity_mapping_preserves_original_local_capture_only"),
                ),
                ("bindings", array(&source_bindings)),
            ]),
        ),
        ("derived_clock_bindings", array(&mapped_bindings)),
        (
            "clock_validation",
            object(&[
                ("query_digest", d(request.query_digest)),
                ("reference", stream_json(&request.streams[0])),
                ("target", stream_json(&request.streams[1])),
                ("original_query_json", original_query_json),
                (
                    "original_query",
                    std::str::from_utf8(input.clock_query)
                        .map_err(|_| invalid("clock query is not UTF-8"))?
                        .to_owned(),
                ),
                ("native_replay", native_clock),
            ]),
        ),
        (
            "assumptions",
            strings([
                "clock_query_observation_pins_and_camera_clock_associations_are_operator_declarations",
                "all_declared_clock_candidates_remain_in_every_target_time_envelope",
                "clock_session_containment_is_not_physical_clock_validity_or_source_coverage",
                "calibration_and_image_domain_pins_bind_declared_scope_without_authenticating_geometry",
                "transition_costs_and_transit_bounds_are_operator_declarations",
                "source_custody_does_not_establish_detector_accuracy_or_physical_identity",
            ]),
        ),
        ("work_used", work.used().to_string()),
        ("work_remaining", work.remaining().to_string()),
        ("conditional_analysis", conditional),
    ]);
    if report.len() + 1 > maximum_report_bytes {
        return Err(QueryError::ReportLimit);
    }
    if cancelled() {
        return Err(QueryError::Cancelled);
    }
    charge(work, 0)?;
    Ok(report)
}

#[cfg(test)]
#[path = "retained_clock_handoffs/tests.rs"]
mod tests;
