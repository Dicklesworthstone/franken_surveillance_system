#![forbid(unsafe_code)]
//! Bounded multi-camera selection using the retained pair command's exact source contracts.
//!
//! Full source capture, dimensions, privacy and decoded features come exclusively
//! from the retained owner. One global static-scene capture hull is admitted here;
//! the native solver separately records each pair/component's subset solve time.

use std::collections::BTreeSet;

use fss_cli::scene_rig::SceneRig;
use fss_core::ContentDigest;
use fss_twin::feature_association::{AssociationOptions, FeatureView};
use fss_twin::localization::native::ExtractionOptions;
use fss_twin::multiview_feature_association::{MAX_MULTIVIEW_CAMERAS, MAX_MULTIVIEW_FEATURES};

use super::super::input as shared;
use super::super::{Result, fail, input_error};

pub(in super::super) const SCHEMA: &str = "fss.scene_feature_multimatch_retained_query.v1";
pub(in super::super) const SCHEMA_V2: &str = "fss.scene_feature_multimatch_retained_query.v2";

pub(in super::super) struct Query {
    pub version: u8,
    pub views: Vec<shared::View>,
    pub extraction: ExtractionOptions,
    pub matching: AssociationOptions,
    pub declarations: String,
}

/// Select three through eight distinct retained source cameras without authenticating custody.
pub(in super::super) fn parse(bytes: &[u8], rig_digest: ContentDigest) -> Result<Query> {
    let header = shared::parse_header(bytes, [SCHEMA, SCHEMA_V2], &["views"], rig_digest)?;
    let top = header
        .document
        .object()
        .ok_or_else(|| input_error("expected a retained multi-view query"))?;
    let rows = shared::get(top, "views")?
        .array()
        .filter(|rows| (3..=MAX_MULTIVIEW_CAMERAS).contains(&rows.len()))
        .ok_or_else(|| {
            input_error("retained multi-view matching requires three through eight views")
        })?;
    let mut views = Vec::new();
    views.try_reserve_exact(rows.len()).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "multi-view selection allocation refused",
        )
    })?;
    for row in rows {
        views.push(shared::parse_view(row, header.version)?);
    }
    shared::validate_distinct_declarations(&views)?;
    Ok(Query {
        version: header.version,
        views,
        extraction: header.extraction,
        matching: header.matching,
        declarations: header.declarations,
    })
}

/// Bind all owner snapshots and the complete global interval before any pair expansion.
/// Requested per-view maxima never authorize dropping actual selected features to fit the total.
pub(in super::super) fn bind(
    query: &Query,
    resolved: &[shared::ResolvedFrame<'_>],
    rig: &SceneRig,
) -> Result<Vec<FeatureView>> {
    if !(3..=MAX_MULTIVIEW_CAMERAS).contains(&query.views.len())
        || query.views.len() != resolved.len()
    {
        return Err(input_error(
            "retained multi-view selection and complete source set differ",
        ));
    }
    let descriptor_domain = resolved
        .first()
        .ok_or_else(|| input_error("retained multi-view source set is empty"))?
        .frame
        .descriptor_domain();
    let mut sensors = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut exposures = BTreeSet::new();
    let mut cameras = BTreeSet::new();
    let mut total_features = 0_usize;
    for (view, source) in query.views.iter().zip(resolved) {
        if !sensors.insert(source.capsule.sensor_id.as_str())
            || !sources.insert(source.capsule.source_digest)
            || !exposures.insert(source.exposure)
            || !cameras.insert(view.camera)
            || source.frame.descriptor_domain() != descriptor_domain
        {
            return Err(input_error(
                "retained multi-view inputs reuse a physical source or mix descriptor spaces",
            ));
        }
        total_features = total_features
            .checked_add(source.frame.features().len())
            .filter(|count| *count <= MAX_MULTIVIEW_FEATURES)
            .ok_or_else(|| {
                fail(
                    "ERR-SCENE-FUSION-LIMIT-001",
                    "complete multi-view feature inventory exceeds 256",
                )
            })?;
    }
    let mut views = Vec::new();
    views.try_reserve_exact(resolved.len()).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "multi-view binding allocation refused",
        )
    })?;
    let mut hull = [u64::MAX, 0];
    for (view, source) in query.views.iter().zip(resolved) {
        let bound = shared::bind_view(
            query.matching,
            query.extraction.maximum_features,
            view,
            source,
            rig,
        )?;
        hull[0] = hull[0].min(bound.capture[0]);
        hull[1] = hull[1].max(bound.capture[1]);
        views.push(bound);
    }
    if hull[1] - hull[0] > query.matching.max_capture_span_ns
        || !(hull[0]..=hull[1]).contains(&query.matching.reference_time_ns)
    {
        return Err(input_error(
            "full multi-view capture hull exceeds the matching interval policy",
        ));
    }
    Ok(views)
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
