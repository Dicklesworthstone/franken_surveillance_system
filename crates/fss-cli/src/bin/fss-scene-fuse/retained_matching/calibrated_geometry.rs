#![forbid(unsafe_code)]
//! Native reconstruction and strict outcome accounting for the adopted-calibration command.
//!
//! These operations consume already bound native feature views, not retained-source authority.
//! The complete associations remain available for the established diagnostic serializers.

use fss_cli::json_output::{array, object, string};
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::PropertyTwin;
use fss_twin::feature_association::{
    AssociationError, AssociationOptions, FeatureAssociation, FeatureHypothesisOutcome,
    FeatureView, associate_features,
};
use fss_twin::multiview_feature_association::{
    ComponentOutcome, MultiFeatureAssociation, associate_multiview_features,
};
use fss_twin::temporal_feature_association::{
    TemporalAssociationError, TemporalAssociationOptions, TemporalComponentOutcome,
    TemporalFeatureAssociation, associate_temporal_features,
};

use crate::{Failure, Result, fail, input_error};

#[derive(Clone, Copy)]
pub(super) enum GeometryPolicy {
    Pair(AssociationOptions),
    Multi(AssociationOptions),
    Temporal(TemporalAssociationOptions),
}

pub(super) enum NativeGeometry {
    Pair(Box<FeatureAssociation>),
    Multi(MultiFeatureAssociation),
    Temporal(TemporalFeatureAssociation),
}

pub(super) struct Analysis {
    pub association: NativeGeometry,
    pub views: Vec<FeatureView>,
    pub reconstructed: bool,
    pub reference_time_ns: u64,
    pub capture_hull: [u64; 2],
    pub solved: usize,
    /// Nontrivial unresolved/refused components, including solved nominal occlusion conflicts.
    pub unresolved: usize,
    pub occlusion_conflicts: usize,
}

pub(super) fn work_failure(error: GeometryError) -> Failure {
    fail(
        if error == GeometryError::Cancelled {
            "ERR-SCENE-FUSION-CANCELLED-001"
        } else {
            "ERR-SCENE-FUSION-LIMIT-001"
        },
        error.to_string(),
    )
}

fn static_failure(error: AssociationError) -> Failure {
    match error {
        AssociationError::Geometry(
            inner @ (GeometryError::Cancelled
            | GeometryError::BudgetExhausted
            | GeometryError::LimitExceeded),
        ) => work_failure(inner),
        AssociationError::Limit => work_failure(GeometryError::LimitExceeded),
        _ => fail("ERR-SCENE-FUSION-POINT-001", error.to_string()),
    }
}

fn temporal_failure(error: TemporalAssociationError) -> Failure {
    match error {
        TemporalAssociationError::Geometry(
            inner @ (GeometryError::Cancelled
            | GeometryError::BudgetExhausted
            | GeometryError::LimitExceeded),
        ) => work_failure(inner),
        TemporalAssociationError::Limit => work_failure(GeometryError::LimitExceeded),
        _ => fail("ERR-SCENE-FUSION-POINT-001", error.to_string()),
    }
}

impl NativeGeometry {
    fn views(&self) -> &[FeatureView] {
        match self {
            Self::Pair(value) => value.views(),
            Self::Multi(value) => value.views(),
            Self::Temporal(value) => value.views(),
        }
    }

    fn counts(&self) -> (usize, usize, usize) {
        let mut solved = 0;
        let mut unresolved = 0;
        let mut occlusion_conflicts = 0;
        match self {
            Self::Pair(value) => {
                for hypothesis in value.hypotheses() {
                    match &hypothesis.outcome {
                        FeatureHypothesisOutcome::Fused(point) => {
                            solved += 1;
                            occlusion_conflicts +=
                                usize::from(point.has_nominal_occlusion_conflict());
                        }
                        FeatureHypothesisOutcome::Refused(_) => unresolved += 1,
                    }
                }
            }
            Self::Multi(value) => {
                for component in value.components() {
                    match component.outcome() {
                        ComponentOutcome::Unmatched => {}
                        ComponentOutcome::Fused(point) => {
                            solved += 1;
                            occlusion_conflicts +=
                                usize::from(point.has_nominal_occlusion_conflict());
                        }
                        _ => unresolved += 1,
                    }
                }
            }
            Self::Temporal(value) => {
                for component in value.components() {
                    match component.outcome() {
                        TemporalComponentOutcome::Unmatched => {}
                        TemporalComponentOutcome::Fused(motion) => {
                            solved += 1;
                            occlusion_conflicts +=
                                usize::from(motion.has_nominal_occlusion_conflict());
                        }
                        _ => unresolved += 1,
                    }
                }
            }
        }
        (
            solved,
            unresolved + occlusion_conflicts,
            occlusion_conflicts,
        )
    }

    fn time(&self) -> (u64, [u64; 2]) {
        match self {
            Self::Pair(value) => (value.options().reference_time_ns, value.capture_hull()),
            Self::Multi(value) => (value.options().reference_time_ns, value.capture_hull()),
            Self::Temporal(value) => (value.options().reference_time_ns, value.capture_hull()),
        }
    }
}

/// Keep native alternatives and source order; strict success also excludes nominal occlusion.
/// No local calibration covariance is converted into a deterministic scene-error bound.
pub(super) fn analyze(
    policy: GeometryPolicy,
    twin: &PropertyTwin,
    views: &[FeatureView],
    work: &mut WorkBudget<'_>,
) -> Result<Analysis> {
    work.charge(0).map_err(work_failure)?;
    let association = match policy {
        GeometryPolicy::Pair(options) => {
            let [left, right] = views else {
                return Err(input_error(
                    "calibrated pair reconstruction requires exactly two views",
                ));
            };
            let pair =
                associate_features(twin, [left, right], options, work).map_err(static_failure)?;
            work.charge(2048).map_err(work_failure)?;
            NativeGeometry::Pair(Box::new(pair))
        }
        GeometryPolicy::Multi(options) => NativeGeometry::Multi(
            associate_multiview_features(twin, views, options, work).map_err(static_failure)?,
        ),
        GeometryPolicy::Temporal(options) => NativeGeometry::Temporal(
            associate_temporal_features(twin, views, options, work).map_err(temporal_failure)?,
        ),
    };
    let (solved, unresolved, occlusion_conflicts) = association.counts();
    let (reference_time_ns, capture_hull) = association.time();
    let canonical_views = association.views();
    let features = canonical_views
        .iter()
        .map(|view| view.frame.features().len())
        .sum::<usize>();
    // Native admission already bounds the full inventory (<=16 views, <=256 features).
    // Charge the retained immutable feature-frame copy before allocating it for the report.
    work.charge(8192 + canonical_views.len() as u64 * 4096 + features as u64 * 512)
        .map_err(work_failure)?;
    let views = canonical_views.to_vec();
    work.charge(0).map_err(work_failure)?;
    Ok(Analysis {
        association,
        views,
        reconstructed: solved > 0 && unresolved == 0,
        reference_time_ns,
        capture_hull,
        solved,
        unresolved,
        occlusion_conflicts,
    })
}

/// Wrap the unchanged complete native serializer in this command's strict outcome policy.
/// The payload is already trusted JSON from a production serializer, never query-authored text.
pub(super) fn envelope(
    kind: &str,
    analysis: &Analysis,
    diagnostics: String,
    maximum_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    // Reserve the complete immutable payload copy, independently of the output allowance.
    work.charge(8192 + diagnostics.len() as u64 * 4)
        .map_err(work_failure)?;
    let outcome = if analysis.solved == 0 {
        "no_reconstruction"
    } else if analysis.reconstructed {
        "reconstructed"
    } else {
        "reconstructed_with_refusals"
    };
    let json = object(&[
        ("kind", string(kind)),
        ("outcome", string(outcome)),
        (
            "reference_time_ns",
            string(&analysis.reference_time_ns.to_string()),
        ),
        (
            "capture_hull_ns",
            array(
                &analysis
                    .capture_hull
                    .map(|value| string(&value.to_string())),
            ),
        ),
        (
            "counts",
            object(&[
                ("solved", analysis.solved.to_string()),
                ("unresolved", analysis.unresolved.to_string()),
                (
                    "nominal_occlusion_conflicts",
                    analysis.occlusion_conflicts.to_string(),
                ),
            ]),
        ),
        ("native_diagnostics", diagnostics),
    ]);
    work.charge(0).map_err(work_failure)?;
    if json
        .len()
        .checked_add(1)
        .is_none_or(|length| length > maximum_bytes)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete calibrated geometry exceeds its output allowance",
        ));
    }
    Ok(json)
}

#[cfg(test)]
#[path = "calibrated_report_tests.rs"]
mod tests;
