#![forbid(unsafe_code)]
//! Complete native multi-camera geometry diagnostics, without source-owner authority claims.

use fss_cli::json_output::{array, object, string};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_twin::multiview_feature_association::{
    ComponentOutcome, FeatureComponent, MultiFeatureAssociation, PairReference,
};

use crate::matching::report::{AssociationRows, association_rows, point};
use crate::{Result, fail};

pub(super) struct GeometryReport {
    pub(super) json: String,
    pub(super) reconstructed: bool,
}

fn digest(value: [u8; 32]) -> String {
    string(&ContentDigest::new(DigestAlgorithm::Sha256, value).to_text())
}
fn time(value: u64) -> String {
    string(&value.to_string())
}
fn interval(value: [u64; 2]) -> String {
    array(&value.map(time))
}
fn reference(value: &PairReference) -> String {
    object(&[
        ("pair", value.pair.to_string()),
        ("decision", value.decision.to_string()),
    ])
}
fn references(values: &[PairReference]) -> String {
    array(&values.iter().map(reference).collect::<Vec<_>>())
}

fn component(index: usize, value: &FeatureComponent) -> String {
    let members = value
        .members()
        .iter()
        .map(|member| {
            object(&[
                ("camera", time(member.camera)),
                ("feature", time(member.feature)),
            ])
        })
        .collect::<Vec<_>>();
    let outcome = match value.outcome() {
        ComponentOutcome::Unmatched => object(&[("state", string("unmatched"))]),
        ComponentOutcome::CameraConflict { cameras } => object(&[
            ("state", string("camera_conflict")),
            (
                "cameras",
                array(&cameras.iter().copied().map(time).collect::<Vec<_>>()),
            ),
        ]),
        ComponentOutcome::IncompleteCycleSupport { pairs } => object(&[
            ("state", string("incomplete_cycle_support")),
            ("missing_pairs", references(pairs)),
        ]),
        ComponentOutcome::Fused(value) => point(value),
        ComponentOutcome::Refused(error) => object(&[
            ("state", string("refused")),
            ("reason", string(&error.to_string())),
        ]),
    };
    object(&[
        ("index", index.to_string()),
        ("members", array(&members)),
        ("links", references(value.links())),
        ("evidence_digest", digest(value.evidence())),
        (
            "requested_scene_time_ns",
            time(value.requested_scene_time_ns()),
        ),
        ("solve_time_ns", time(value.solve_time_ns())),
        ("capture_hull_ns", interval(value.capture_hull())),
        ("outcome", outcome),
    ])
}

/// Serialize every native pair decision and component, including unsuccessful geometry.
///
/// All serialization work is reserved against the complete immutable inventory, independently
/// of the caller's byte limit. Cancellation or a byte-limit failure returns no partial report.
/// Source snapshots, original capsules and source-owner revalidation belong to the enclosing
/// retained command. A successful joint component does not erase its weak two-view refusals.
pub(super) fn compute(
    association: &MultiFeatureAssociation,
    max_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<GeometryReport> {
    let mut pair_rows = 0_usize;
    let mut pair_features = 0_usize;
    let mut pair_hypotheses = 0_usize;
    for pair in association.pairs() {
        pair_rows += pair.report().pairs().len();
        pair_features += pair.report().features().len();
        pair_hypotheses += pair.report().hypotheses().len();
    }
    let mut members = 0_usize;
    let mut links = 0_usize;
    let mut missing_links = 0_usize;
    for value in association.components() {
        members += value.members().len();
        links += value.links().len();
        if let ComponentOutcome::IncompleteCycleSupport { pairs } = value.outcome() {
            missing_links += pairs.len();
        }
    }
    // The native owner bounds cameras <=8, total features <=256, pair rows <=28,672,
    // pair-specific feature outcomes <=1,792, and pair hypotheses/selected links <=896.
    // Feature rows can contain all nearest ties. Point bounds include long finite decimal
    // coordinates/covariances, every residual/visibility record, and JSON construction copies.
    // Component member allowance also covers every joint-view record (at most eight per point).
    let serialization_work = 65_536
        + association.pairs().len() as u64 * 4096
        + pair_rows as u64 * 1024
        + pair_features as u64 * 8192
        + pair_hypotheses as u64 * 65_536
        + association.components().len() as u64 * 4096
        + members as u64 * 16_384
        + (links + missing_links) as u64 * 128;
    work.charge(serialization_work)
        .map_err(|error| fail("ERR-SCENE-FUSION-LIMIT-001", error.to_string()))?;

    let mut pair_solved = 0_usize;
    let mut camera_pairs = Vec::with_capacity(association.pairs().len());
    for (index, pair) in association.pairs().iter().enumerate() {
        work.charge(0)
            .map_err(|error| fail("ERR-SCENE-FUSION-LIMIT-001", error.to_string()))?;
        let AssociationRows {
            hypotheses,
            pairs,
            features,
            solved,
        } = association_rows(pair.report());
        pair_solved += solved;
        camera_pairs.push(object(&[
            ("index", index.to_string()),
            ("cameras", array(&pair.cameras().map(time))),
            (
                "requested_scene_time_ns",
                time(pair.requested_scene_time_ns()),
            ),
            ("solve_time_ns", time(pair.solve_time_ns())),
            ("capture_hull_ns", interval(pair.report().capture_hull())),
            ("evidence_digest", digest(pair.report().evidence())),
            ("pairs", array(&pairs)),
            ("feature_outcomes", array(&features)),
            ("hypotheses", array(&hypotheses)),
            (
                "counts",
                object(&[
                    ("features", features.len().to_string()),
                    ("pairs", pairs.len().to_string()),
                    ("selected", hypotheses.len().to_string()),
                    ("solved", solved.to_string()),
                    ("refused", (hypotheses.len() - solved).to_string()),
                ]),
            ),
        ]));
    }

    let mut solved = 0_usize;
    let mut unmatched = 0_usize;
    let mut camera_conflicts = 0_usize;
    let mut incomplete_cycles = 0_usize;
    let mut refused = 0_usize;
    let mut components = Vec::with_capacity(association.components().len());
    for (index, value) in association.components().iter().enumerate() {
        work.charge(0)
            .map_err(|error| fail("ERR-SCENE-FUSION-LIMIT-001", error.to_string()))?;
        match value.outcome() {
            ComponentOutcome::Unmatched => unmatched += 1,
            ComponentOutcome::CameraConflict { .. } => camera_conflicts += 1,
            ComponentOutcome::IncompleteCycleSupport { .. } => incomplete_cycles += 1,
            ComponentOutcome::Fused(_) => solved += 1,
            ComponentOutcome::Refused(_) => refused += 1,
        }
        components.push(component(index, value));
    }
    let unresolved = camera_conflicts + incomplete_cycles + refused;
    let reconstructed = solved > 0 && unresolved == 0;
    let outcome = if solved == 0 {
        "no_reconstruction"
    } else if reconstructed {
        "reconstructed"
    } else {
        "reconstructed_with_refusals"
    };
    let json = object(&[
        ("outcome", string(outcome)),
        ("scene_evidence", digest(association.evidence())),
        (
            "requested_scene_time_ns",
            time(association.options().reference_time_ns),
        ),
        ("capture_hull_ns", interval(association.capture_hull())),
        (
            "subset_time_policy",
            string(
                "requested_scene_time_clamped_to_subset_full_capture_hull_under_static_assumption",
            ),
        ),
        ("camera_pairs", array(&camera_pairs)),
        ("components", array(&components)),
        (
            "counts",
            object(&[
                ("cameras", association.views().len().to_string()),
                ("camera_pairs", camera_pairs.len().to_string()),
                ("features", members.to_string()),
                ("pair_rows", pair_rows.to_string()),
                ("pair_feature_outcomes", pair_features.to_string()),
                ("pair_hypotheses", pair_hypotheses.to_string()),
                ("pair_solved", pair_solved.to_string()),
                ("pair_refused", (pair_hypotheses - pair_solved).to_string()),
                ("components", components.len().to_string()),
                ("links", links.to_string()),
                ("missing_links", missing_links.to_string()),
                ("solved", solved.to_string()),
                ("unmatched", unmatched.to_string()),
                ("camera_conflicts", camera_conflicts.to_string()),
                ("incomplete_cycles", incomplete_cycles.to_string()),
                ("refused", refused.to_string()),
                ("unresolved", unresolved.to_string()),
            ]),
        ),
    ]);
    work.charge(0)
        .map_err(|error| fail("ERR-SCENE-FUSION-LIMIT-001", error.to_string()))?;
    if json.len().checked_add(1).is_none_or(|n| n > max_bytes) {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete multi-camera geometry report exceeds output allowance",
        ));
    }
    Ok(GeometryReport {
        json,
        reconstructed,
    })
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
