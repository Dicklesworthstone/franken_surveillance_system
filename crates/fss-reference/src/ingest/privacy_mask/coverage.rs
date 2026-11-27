#![forbid(unsafe_code)]
//! Coverage honesty over masked zones: a masked pixel is never absence evidence.
//!
//! The coverage model has no sub-zone domain, so it cannot express "covered over the unmasked
//! part of a zone". A zone with *any* masked pixel is therefore not observable: every witness it
//! would have carried becomes an uncovered interval with reason `privacy_masked`, and every other
//! frame interval is reported `privacy_masked` too (the mask alone already makes the zone
//! unobservable), except zone-entry frames, which remain named observations, and segments that
//! produced no pixels at all: never decoded (`segment_not_decoded`) or refused by a tolerant
//! decode (`decode_refused`, which keeps its registered error id). Owners who want coverage of
//! the visible part of a zone draw that part as its own zone. The full reason precedence is
//! documented in [`crate::ingest::recorded_coverage`].

use std::collections::BTreeSet;

use fss_core::{CaptureInterval, ContractError};

use super::PrivacyMaskPolicy;
use crate::ingest::ground_visibility::{homography_pixel, invert};
use crate::ingest::recorded_coverage::{CoverageRecord, UncoveredInterval, UncoveredReason};

fn hull(a: Option<CaptureInterval>, b: Option<CaptureInterval>) -> Option<CaptureInterval> {
    match (a, b) {
        (Some(a), Some(b)) => {
            CaptureInterval::new(a.earliest.min(b.earliest), a.latest.max(b.latest)).ok()
        }
        _ => None,
    }
}

/// Rewrites the zones of `record` named in `masked`: no witness survives, and every frame
/// interval other than a zone entry, an undecoded segment or a decode refusal is
/// `privacy_masked`. Adjacent
/// masked intervals merge. The record is revalidated.
pub fn mask_coverage_zones(
    record: &mut CoverageRecord,
    masked: &BTreeSet<String>,
) -> Result<(), ContractError> {
    for zone in &mut record.zones {
        if !masked.contains(&zone.zone_id) {
            continue;
        }
        let mut intervals: Vec<UncoveredInterval> = zone
            .witnesses
            .drain(..)
            .map(|witness| UncoveredInterval {
                first_segment: witness.first_segment,
                last_segment: witness.last_segment,
                capture: Some(witness.outer),
                reason: UncoveredReason::PrivacyMasked,
            })
            .collect();
        for mut gap in zone.uncovered.drain(..) {
            if !matches!(
                gap.reason,
                UncoveredReason::ZoneEntry { .. }
                    | UncoveredReason::SegmentNotDecoded
                    | UncoveredReason::DecodeRefused { .. }
            ) {
                gap.reason = UncoveredReason::PrivacyMasked;
            }
            intervals.push(gap);
        }
        intervals.sort_by_key(|gap| (gap.first_segment, gap.last_segment));
        let mut merged: Vec<UncoveredInterval> = Vec::with_capacity(intervals.len());
        for gap in intervals {
            if let Some(previous) = merged.last_mut()
                && previous.reason == UncoveredReason::PrivacyMasked
                && gap.reason == UncoveredReason::PrivacyMasked
                && previous.last_segment + 1 == gap.first_segment
            {
                previous.last_segment = gap.last_segment;
                previous.capture = hull(previous.capture, gap.capture);
                continue;
            }
            merged.push(gap);
        }
        zone.uncovered = merged;
    }
    record.validate()
}

/// Whether any masked pixel may lie inside the image preimage of the ground-plane rectangle
/// `[x, y, width, height]` under the owner homography `matrix` (image pixels -> ground units).
/// Conservative: the preimage's axis-aligned bounding box is tested, and a preimage that cannot
/// be computed counts as masked.
#[must_use]
pub fn ground_zone_masked(policy: &PrivacyMaskPolicy, matrix: [f64; 9], zone: [f64; 4]) -> bool {
    let [x, y, w, h] = zone;
    let (max_x, max_y) = (x + w, y + h);
    if ![x, y, max_x, max_y].iter().all(|v| v.is_finite()) || max_x <= x || max_y <= y {
        return true;
    }
    let Ok(inverse) = invert(&matrix) else {
        return true;
    };
    let corners = [(x, y), (max_x, y), (x, max_y), (max_x, max_y)];
    let mut bounds = [
        f64::INFINITY,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NEG_INFINITY,
    ];
    for (gx, gy) in corners {
        // The inverse denominator is affine over the zone. Only if every corner is on
        // the front side of the horizon are the coordinate extrema at these corners.
        let weight = inverse[6] * gx + inverse[7] * gy + inverse[8];
        if !weight.is_finite() || weight <= 0.0 {
            return true;
        }
        let Some((column, row)) = homography_pixel(&matrix, &inverse, gx, gy) else {
            return true;
        };
        bounds = [
            bounds[0].min(column),
            bounds[1].min(row),
            bounds[2].max(column),
            bounds[3].max(row),
        ];
    }
    let [width, height] = policy.resolution();
    let left = bounds[0].floor().max(0.0);
    let top = bounds[1].floor().max(0.0);
    // GroundZone::contains includes the maximum x and y. An endpoint exactly at
    // integer column k touches pixel k, so its exclusive right edge is k + 1.
    let right = (bounds[2].floor() + 1.0).min(f64::from(width));
    let bottom = (bounds[3].floor() + 1.0).min(f64::from(height));
    if left >= right || top >= bottom {
        return false;
    }
    // Finite, clipped to [0, 4096]: exact in u32.
    let rectangle = [
        left as u32,
        top as u32,
        (right - left) as u32,
        (bottom - top) as u32,
    ];
    policy.zone_masking(rectangle).any()
}
