#![forbid(unsafe_code)]
//! Coverage honesty over masked zones: a masked pixel is never absence evidence.
//!
//! The coverage model has no sub-zone domain, so it cannot express "covered over the unmasked
//! part of a zone". A zone with *any* masked pixel is therefore not observable: every witness it
//! would have carried becomes an uncovered interval with reason `privacy_masked`, and every other
//! frame interval is reported `privacy_masked` too (the mask alone already makes the zone
//! unobservable), except zone-entry frames, which remain named observations, and segments that
//! were never decoded. Owners who want coverage of the visible part of a zone draw that part as
//! its own zone.

use std::collections::BTreeSet;

use fss_core::{CaptureInterval, ContractError};

use super::PrivacyMaskPolicy;
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
/// interval other than a zone entry or an undecoded segment is `privacy_masked`. Adjacent
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
                UncoveredReason::ZoneEntry { .. } | UncoveredReason::SegmentNotDecoded
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
    let [a, b, c, d, e, f, g, h, i] = matrix;
    let det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
    if !det.is_finite() || det == 0.0 {
        return true;
    }
    let inverse = [
        (e * i - f * h) / det,
        (c * h - b * i) / det,
        (b * f - c * e) / det,
        (f * g - d * i) / det,
        (a * i - c * g) / det,
        (c * d - a * f) / det,
        (d * h - e * g) / det,
        (b * g - a * h) / det,
        (a * e - b * d) / det,
    ];
    let [x, y, w, zh] = zone;
    let corners = [(x, y), (x + w, y), (x, y + zh), (x + w, y + zh)];
    let [m11, m12, m13, m21, m22, m23, m31, m32, m33] = inverse;
    let mut bounds = [
        f64::INFINITY,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NEG_INFINITY,
    ];
    for (gx, gy) in corners {
        let weight = m31 * gx + m32 * gy + m33;
        let column = (m11 * gx + m12 * gy + m13) / weight;
        let row = (m21 * gx + m22 * gy + m23) / weight;
        if !weight.is_finite() || weight == 0.0 || !column.is_finite() || !row.is_finite() {
            return true;
        }
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
    let right = bounds[2].ceil().min(f64::from(width));
    let bottom = bounds[3].ceil().min(f64::from(height));
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
