#![forbid(unsafe_code)]
//! Bounded canonical, source-bound candidate receipts. No authority or activation record.

use super::*;
use fss_geometry::PinholeIntrinsics;
use fss_twin::localization::MatchRejection;
use fss_twin::rectification::{LensDistortion, LumaRange};

fn optional_digest(e: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    e.bool(value.is_some());
    if let Some(value) = value { e.digest(value); }
}
fn optional_u64(e: &mut CanonicalEncoder, value: Option<u64>) {
    e.bool(value.is_some());
    if let Some(value) = value { e.u64(value); }
}
fn hash(e: &mut CanonicalEncoder, bytes: [u8; 32]) {
    e.digest(ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes));
}
fn image(e: &mut CanonicalEncoder, identity: ImageIdentity) {
    hash(e, identity.exposure);
    hash(e, identity.pixels);
    hash(e, identity.image_domain);
    for n in identity.dimensions { e.u32(n); }
}
fn number(e: &mut CanonicalEncoder, value: f64) {
    // All model parameters and pose outputs were admitted by their numeric owners.
    // Canonicalize negative zero as those owners do when recording numeric geometry.
    e.u64(if value == 0.0 { 0 } else { value.to_bits() });
}
fn camera(e: &mut CanonicalEncoder, intrinsics: PinholeIntrinsics) {
    for value in intrinsics.dimensions() { e.u32(value); }
    for value in intrinsics.focal_lengths().into_iter().chain(intrinsics.principal_point()) {
        number(e, value);
    }
}
fn mode(e: &mut CanonicalEncoder, mode: RecordedImageMode) {
    match mode {
        RecordedImageMode::Pinhole(c) => {
            e.u8(0);
            camera(e, c.intrinsics);
            hash(e, c.image_domain);
        }
        RecordedImageMode::Raw(s) => {
            e.u8(1);
            camera(e, s.source);
            camera(e, s.target);
            match s.distortion {
                LensDistortion::Pinhole => e.u8(0),
                LensDistortion::BrownConrady { radial, tangential } => {
                    e.u8(1);
                    for n in radial.into_iter().chain(tangential) { number(e, n); }
                }
                LensDistortion::Fisheye { coefficients } => {
                    e.u8(2);
                    for n in coefficients { number(e, n); }
                }
            }
            number(e, s.maximum_radius);
            hash(e, s.source_domain);
            hash(e, s.calibration);
            e.u8(match s.range { LumaRange::Full => 0, LumaRange::Video => 1 });
        }
    }
}
fn options(e: &mut CanonicalEncoder, o: ImageLocalizationOptions) {
    e.u8(o.extraction.threshold);
    e.u64(o.extraction.maximum_features as u64);
    e.u32(u32::from(o.extraction.separation));
    e.u32(u32::from(o.matching.maximum_distance));
    e.u8(o.matching.ratio_percent);
    e.u64(o.solving.ransac_trials as u64);
    e.u64(o.solving.refinement_iterations as u64);
    e.u64(o.solving.seed);
    number(e, o.solving.inlier_threshold_px);
    e.u64(o.solving.minimum_inliers as u64);
    number(e, o.solving.minimum_inlier_fraction);
    number(e, o.solving.minimum_axis_ratio);
    number(e, o.solving.minimum_image_span);
}

/// Stable v1 outcome tokens, independent of human-readable error wording.
pub(super) fn geometry_reason(error: GeometryError) -> &'static str {
    match error {
        GeometryError::NonFinite => "nonfinite",
        GeometryError::OutOfRange => "out_of_range",
        GeometryError::InvalidCamera => "invalid_camera",
        GeometryError::InvalidRotation => "invalid_rotation",
        GeometryError::BehindCamera => "behind_camera",
        GeometryError::OutOfImage => "out_of_image",
        GeometryError::Degenerate => "degenerate",
        GeometryError::EmptyInput => "empty_input",
        GeometryError::LimitExceeded => "limit_exceeded",
        GeometryError::BudgetExhausted => "budget_exhausted",
        GeometryError::Cancelled => "cancelled",
        GeometryError::BasisMismatch => "basis_mismatch",
        GeometryError::InvalidIndex => "invalid_index",
        GeometryError::InvalidSolverOptions => "invalid_solver_options",
        GeometryError::InvalidCorrespondence => "invalid_correspondence",
        GeometryError::InsufficientCorrespondences => "insufficient_correspondences",
        GeometryError::UnsupportedGeometry => "unsupported_geometry",
        GeometryError::SolverDidNotConverge => "solver_did_not_converge",
        GeometryError::NoPoseConsensus => "no_pose_consensus",
        GeometryError::TooManyPoseCandidates => "too_many_pose_candidates",
        GeometryError::HoldoutLeak => "holdout_leak",
    }
}

pub(super) fn encode(
    b: &RecordedLocalizationBinding,
    native_receipt: &[u8],
    plan: RecordedLocalizationPlan<'_>,
    result: &ImageLocalization,
    rectification: Option<&RectificationReceipt>,
    work: u64,
) -> Result<Vec<u8>> {
    if native_receipt.len() > 16 * 1024
        || result.localization.matches.decisions.len() > 512
        || result.localization.matches.correspondences.len() > 512
    { return Err(RecordedLocalizationError::InvalidRequest); }
    let mut e = CanonicalEncoder::new();
    e.text(RECEIPT_DOMAIN);
    e.text("unactivated_camera_pose_candidates");
    e.text(b.codec);
    for value in [b.import_identity, b.import_root, b.manifest, b.capsule, b.encoded_source,
        b.exposure, b.luma, b.decode_receipt, b.mask_binding] { e.digest(value); }
    b.source_anchor.encode_canonical(&mut e);
    optional_digest(&mut e, b.decode_root);
    optional_digest(&mut e, b.mask_policy);
    e.u64(b.segment);
    e.u64(b.range_start);
    e.u64(b.range_count);
    for n in b.dimensions { e.u32(n); }
    e.bytes(native_receipt);
    hash(&mut e, plan.twin.digest());
    hash(&mut e, plan.atlas.digest());
    hash(&mut e, fss_twin::localization::native::descriptor_domain());
    mode(&mut e, plan.image);
    options(&mut e, plan.options);
    e.bool(rectification.is_some());
    if let Some(r) = rectification {
        hash(&mut e, r.source.exposure);
        hash(&mut e, r.source.storage);
        hash(&mut e, r.source.allowed_mask);
        hash(&mut e, r.source.image_domain);
        hash(&mut e, r.source.calibration);
        for n in r.source.dimensions { e.u32(n); }
        e.u32(r.source.row_stride);
        e.u8(match r.source.range { LumaRange::Full => 0, LumaRange::Video => 1 });
        image(&mut e, r.output);
        hash(&mut e, r.map_digest);
        hash(&mut e, r.allowed_mask);
        for n in [r.coverage.mapped, r.coverage.outside_source, r.coverage.outside_lens_domain,
            r.allowed_pixels, r.privacy_rejected] { e.u64(n as u64); }
    }
    let selection = result.selection;
    hash(&mut e, selection.mask_digest);
    e.u8(selection.threshold);
    e.u64(selection.maximum_features as u64);
    e.u32(u32::from(selection.separation));
    for n in [selection.tested_centers, selection.local_maxima, selection.selected,
        selection.omitted, result.localization.matches.correspondences.len()] { e.u64(n as u64); }
    let matches = &result.localization.matches;
    hash(&mut e, matches.atlas);
    image(&mut e, matches.query);
    e.u64(matches.decisions.len() as u64);
    for decision in &matches.decisions {
        e.u64(decision.image_feature);
        optional_u64(&mut e, decision.landmark);
        e.u8(match decision.rejection {
            None => 0, Some(MatchRejection::TooDistant) => 1,
            Some(MatchRejection::Ambiguous) => 2, Some(MatchRejection::NonMutual) => 3,
        });
        e.u32(u32::from(decision.distance));
        optional_u64(&mut e, decision.runner_up_distance.map(u64::from));
    }
    match &result.localization.outcome {
        LocalizationOutcome::InsufficientMatches => e.u8(0),
        LocalizationOutcome::GeometricFailure(error) => {
            e.u8(1);
            e.text(geometry_reason(*error));
        }
        LocalizationOutcome::Candidates(search) => {
            e.u8(2);
            if search.candidates().len() > 16 { return Err(RecordedLocalizationError::InvalidRequest); }
            e.u64(search.candidates().len() as u64);
            for candidate in search.candidates() {
                for n in candidate.pose().center() { number(&mut e, n); }
                for row in candidate.pose().rotation() {
                    for n in row { number(&mut e, n); }
                }
                number(&mut e, candidate.rms_px());
                e.u64(candidate.inlier_landmarks().len() as u64);
                for id in candidate.inlier_landmarks() { e.u64(*id); }
            }
        }
    }
    e.u64(work);
    let bytes = e.finish_checked().map_err(RecordedDecodeError::from)?;
    if bytes.len() > MAX_RECEIPT_BYTES { return Err(RecordedLocalizationError::InvalidRequest); }
    Ok(bytes)
}
