#![forbid(unsafe_code)]
//! Retained repeated exposures with explicit fixed-camera and constant-velocity assumptions.
//!
//! Capture intervals, feature pixels, native image identities and privacy masks come only
//! from the sealed owner snapshots. This pure adapter verifies their declared bindings;
//! it neither authenticates custody nor establishes a physical feature correspondence.

use std::collections::{BTreeMap, BTreeSet};

use fss_cli::json_input::{self, Value};
use fss_cli::scene_rig::SceneRig;
use fss_core::ContentDigest;
use fss_twin::feature_association::FeatureView;
use fss_twin::localization::native::ExtractionOptions;
use fss_twin::temporal_feature_association::TemporalAssociationOptions;

use super::super::{Result, input as fusion_input, input_error};
use super::fail;
use super::input::{self as shared, ResolvedFrame, View, ViewBindingPolicy};

pub(super) const SCHEMA: &str = "fss.scene_feature_motion_match_retained_query.v1";
const MAX_EXPOSURES: usize = 16;
const MAX_CAMERAS: usize = 8;
const MAX_TOTAL_FEATURES: usize = 256;
const MAX_CAPTURE_SPAN_NS: u64 = 60_000_000_000;

pub(super) struct Query {
    pub views: Vec<View>,
    pub extraction: ExtractionOptions,
    pub matching: TemporalAssociationOptions,
    pub declarations: String,
}

/// Admit only the explicit motion schema while reusing the complete v2 image/source syntax.
pub(super) fn parse(bytes: &[u8], rig_digest: ContentDigest) -> Result<Query> {
    let document = json_input::parse(
        std::str::from_utf8(bytes)
            .map_err(|_| input_error("retained motion query must be UTF-8"))?,
    )
    .map_err(|_| input_error("malformed retained motion query"))?;
    let top = shared::fields(
        &document,
        &[
            "schema",
            "camera_rig_digest",
            "privacy_domain",
            "clock",
            "clock_evidence",
            "association_basis",
            "reference_time_ns",
            "max_capture_span_ns",
            "max_capture_uncertainty_ns",
            "motion",
            "views",
            "extraction",
            "matching",
            "triangulation",
        ],
    )?;
    if shared::text(shared::get(top, "schema")?)? != SCHEMA
        || shared::digest(shared::get(top, "camera_rig_digest")?)? != rig_digest
    {
        return Err(input_error(
            "retained motion schema or exact rig pin differs",
        ));
    }
    if shared::text(shared::get(top, "motion")?)? != "constant_velocity_during_capture_hull" {
        return Err(input_error(
            "retained motion requires its explicit constant-velocity assumption",
        ));
    }
    let max_capture_span_ns = shared::unsigned(
        shared::get(top, "max_capture_span_ns")?,
        1,
        MAX_CAPTURE_SPAN_NS,
    )?;
    let max_capture_uncertainty_ns = shared::unsigned(
        shared::get(top, "max_capture_uncertainty_ns")?,
        0,
        max_capture_span_ns,
    )?;
    let extraction = shared::fields(
        shared::get(top, "extraction")?,
        &["threshold", "maximum_features", "separation"],
    )?;
    let extraction = ExtractionOptions {
        threshold: shared::unsigned(shared::get(extraction, "threshold")?, 1, 254)? as u8,
        maximum_features: shared::unsigned(shared::get(extraction, "maximum_features")?, 1, 128)?
            as usize,
        separation: shared::unsigned(shared::get(extraction, "separation")?, 1, 128)? as u16,
    };
    let matching = shared::fields(
        shared::get(top, "matching")?,
        &["maximum_hamming_distance", "ratio_percent"],
    )?;
    // Reuse the existing temporal solver parser, with its native numerical bounds
    // checked here before the owner decodes or publishes any source derivative.
    if let Some(value) = top.get("triangulation") {
        let values = shared::fields(
            value,
            &[
                "max_reprojection_pixels",
                "max_distance",
                "max_speed",
                "max_condition_number",
                "max_iterations",
            ],
        )?;
        for (key, minimum, maximum) in [
            ("max_reprojection_pixels", 1e-6, 1e6),
            ("max_distance", 1e-6, 1e12),
            ("max_speed", 1e-9, 1e12),
            ("max_condition_number", 1.0, 1e12),
        ] {
            if let Some(value) = values.get(key) {
                shared::real(value, minimum, maximum)?;
            }
        }
        if let Some(value) = values.get("max_iterations") {
            shared::unsigned(value, 1, 32)?;
        }
    }
    let motion = Value::Object(BTreeMap::from([
        ("kind".into(), Value::Text("infer_linear".into())),
        (
            "max_capture_uncertainty_ns".into(),
            Value::Number(max_capture_uncertainty_ns.to_string()),
        ),
    ]));
    let fusion_input::Motion::InferLinear {
        options: triangulation,
        ..
    } = fusion_input::motion(&motion, top.get("triangulation"))?
    else {
        return Err(input_error("unsupported retained temporal solver policy"));
    };
    let matching = TemporalAssociationOptions {
        association_basis: shared::digest(shared::get(top, "association_basis")?)?.bytes(),
        camera_rig_digest: rig_digest.bytes(),
        clock_evidence: shared::digest(shared::get(top, "clock_evidence")?)?.bytes(),
        privacy_domain: shared::unsigned(shared::get(top, "privacy_domain")?, 1, u64::MAX)?,
        clock: shared::unsigned(shared::get(top, "clock")?, 1, u64::MAX)?,
        reference_time_ns: shared::unsigned(shared::get(top, "reference_time_ns")?, 0, u64::MAX)?,
        max_capture_span_ns,
        max_capture_uncertainty_ns,
        maximum_hamming_distance: shared::unsigned(
            shared::get(matching, "maximum_hamming_distance")?,
            0,
            256,
        )? as u16,
        ratio_percent: shared::unsigned(shared::get(matching, "ratio_percent")?, 1, 99)? as u8,
        triangulation,
    };
    let rows = shared::get(top, "views")?
        .array()
        .filter(|rows| (4..=MAX_EXPOSURES).contains(&rows.len()))
        .ok_or_else(|| input_error("retained motion requires four through sixteen exposures"))?;
    let mut views = Vec::new();
    views.try_reserve_exact(rows.len()).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "temporal selection allocation refused",
        )
    })?;
    for row in rows {
        views.push(shared::parse_view(row, 2)?);
    }
    validate_declarations(&views)?;
    Ok(Query {
        views,
        extraction,
        matching,
        declarations: shared::json(&document),
    })
}

fn validate_declarations(views: &[View]) -> Result<()> {
    let mut cameras = BTreeMap::<u64, &View>::new();
    let mut sensors = BTreeMap::<&str, u64>::new();
    let mut capsules = BTreeSet::new();
    let mut selections = BTreeSet::new();
    for view in views {
        let pins = view.source.pins();
        if !capsules.insert(pins.capsule_digest)
            || !selections.insert((pins.import_identity, pins.segment))
        {
            return Err(input_error(
                "retained motion repeats a capsule or import/segment selection",
            ));
        }
        if sensors
            .insert(&pins.sensor_id, view.camera)
            .is_some_and(|camera| camera != view.camera)
        {
            return Err(input_error(
                "one physical source sensor cannot supply different logical cameras",
            ));
        }
        if let Some(previous) = cameras.get(&view.camera) {
            if previous.source.pins().sensor_id != pins.sensor_id
                || previous.alignment.stream_id != view.alignment.stream_id
                || previous.alignment.clock_basis != view.alignment.clock_basis
                || previous.alignment.offset_ns != view.alignment.offset_ns
                || previous.alignment.basis != view.alignment.basis
                || previous.image != view.image
                || previous.mapping_basis != view.mapping_basis
            {
                return Err(input_error(
                    "repeated camera changes its sensor, stream, clock alignment or image/rig declaration",
                ));
            }
        } else {
            cameras.insert(view.camera, view);
        }
    }
    if !(2..=MAX_CAMERAS).contains(&cameras.len()) {
        return Err(input_error(
            "retained motion requires two through eight fixed logical cameras",
        ));
    }
    Ok(())
}

/// Bind every original exposure and its full aligned interval before descriptor expansion.
/// Repeated encoded bytes are allowed; they are not a second independent sensor claim.
pub(super) fn bind(
    query: &Query,
    resolved: &[ResolvedFrame<'_>],
    rig: &SceneRig,
) -> Result<Vec<FeatureView>> {
    if !(4..=MAX_EXPOSURES).contains(&query.views.len()) || query.views.len() != resolved.len() {
        return Err(input_error(
            "temporal selection and complete owner exposure inventory differ",
        ));
    }
    validate_declarations(&query.views)?;
    let descriptor = resolved[0].frame.descriptor_domain();
    let mut exposures = BTreeSet::new();
    let mut capsules = BTreeSet::new();
    let mut total = 0_usize;
    for source in resolved {
        if !exposures.insert(source.exposure)
            || !capsules.insert(source.capsule.capsule_id.as_str())
            || source.frame.descriptor_domain() != descriptor
        {
            return Err(input_error(
                "temporal owners reuse an exposure/capsule or mix descriptor generations",
            ));
        }
        total = total
            .checked_add(source.frame.features().len())
            .filter(|n| *n <= MAX_TOTAL_FEATURES)
            .ok_or_else(|| {
                fail(
                    "ERR-SCENE-FUSION-LIMIT-001",
                    "complete temporal feature inventory exceeds 256",
                )
            })?;
    }
    let policy = ViewBindingPolicy {
        privacy_domain: query.matching.privacy_domain,
        clock: query.matching.clock,
        clock_evidence: query.matching.clock_evidence,
        maximum_features: query.extraction.maximum_features,
    };
    let mut views = Vec::new();
    views.try_reserve_exact(resolved.len()).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "temporal binding allocation refused",
        )
    })?;
    let mut hull = [u64::MAX, 0];
    for (view, source) in query.views.iter().zip(resolved) {
        let bound = shared::bind_source_view(policy, view, source, rig)?;
        if bound.capture[1] - bound.capture[0] > query.matching.max_capture_uncertainty_ns {
            return Err(input_error(
                "complete aligned capture exceeds the temporal uncertainty allowance",
            ));
        }
        hull[0] = hull[0].min(bound.capture[0]);
        hull[1] = hull[1].max(bound.capture[1]);
        views.push(bound);
    }
    if hull[1] - hull[0] > query.matching.max_capture_span_ns
        || !(hull[0]..=hull[1]).contains(&query.matching.reference_time_ns)
    {
        return Err(input_error(
            "complete temporal capture hull exceeds the requested scene-time policy",
        ));
    }
    Ok(views)
}

#[cfg(test)]
#[path = "temporal_input_tests.rs"]
mod tests;
