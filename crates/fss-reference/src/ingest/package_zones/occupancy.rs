#![forbid(unsafe_code)]
//! Complete per-frame, per-zone counts of actual class-selected observations.
//!
//! The public read owner accepts only retained zone-report identities. Counts describe
//! confirmed detector assignments, not people, calibrated population bounds, continuous
//! occupancy, queue length or absence. Missing observations remain explicit even when no
//! track was ever created. Historical screening retains the source report's exact policy.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};

use super::{
    MAX_PACKAGE_ZONE_CELLS, MAX_PACKAGE_ZONES, PackageZoneCell, PackageZoneError,
    PackageZoneRelation, Result,
};

mod json;
mod retained;
#[cfg(test)]
mod tests;

/// Canonical projection and JSON schema identity; independent of the source report encoding.
pub const PACKAGE_OCCUPANCY_REPORT_DOMAIN: &str = "fss.package_zone_occupancy.v1";
/// Exact immutable interpretation of the source report's assigned samples and health policy.
pub const PACKAGE_OCCUPANCY_POLICY: &str = "confirmed-actual-inside:source-health-policy:complete-frame-zone-grid:no-absence-no-continuity:v1";
/// Complete output bound, including all positive support and unavailable-sample accounting.
pub const MAX_PACKAGE_OCCUPANCY_JSON_BYTES: usize = 4 * 1024 * 1024;
/// Checkpoint after projection and rendering, before current source/authority revalidation.
pub const STAGE_OCCUPANCY_REVALIDATE: &str = "package_occupancy:revalidate";

/// Historical source-health interpretation, never a current camera-health certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccupancyHealth {
    /// The retained v1 report has no source-health screening policy.
    Unassessed,
    /// Matching complete finite diagnostics contain no findings.
    ScreenedWithoutFindings,
    /// No matching retained diagnostic exists for this source frame and privacy generation.
    NoMatchingDiagnostic,
    /// Matching screening did not complete.
    ScreeningIncomplete,
    /// At least one matching diagnostic contains a finding.
    Findings,
}
impl OccupancyHealth {
    /// Stable machine-readable historical-health state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unassessed => "unassessed",
            Self::ScreenedWithoutFindings => "screened_without_findings",
            Self::NoMatchingDiagnostic => "no_matching_diagnostic",
            Self::ScreeningIncomplete => "screening_incomplete",
            Self::Findings => "findings",
        }
    }
    /// The exact source report's policy allows a positive observation. Unscreened v1 reports
    /// keep their original policy, explicitly labeled unassessed rather than called healthy.
    pub const fn source_policy_allows(self) -> bool {
        matches!(self, Self::Unassessed | Self::ScreenedWithoutFindings)
    }
}

/// Meaning of one sampled count. None of these states is an absence certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccupancyState {
    /// At least one actual confirmed inside assignment supports this source sample.
    ObservedPositive,
    /// No usable positive assignment; zero says nothing about unobserved physical subjects.
    NoPositiveObservation,
    /// Current source privacy masks overlap the zone; a count is unavailable, including
    /// empty track inventories where no masked cells exist to carry this information.
    Masked,
    /// The retained screening policy withholds positive support; a count is unavailable.
    HealthExcluded,
}
impl OccupancyState {
    /// Stable machine-readable count interpretation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedPositive => "observed_positive",
            Self::NoPositiveObservation => "no_positive_observation",
            Self::Masked => "masked",
            Self::HealthExcluded => "health_excluded",
        }
    }
}

/// Complete unavailable-sample accounting. Geometric exclusions are classified after
/// masking/missing assignments and then confirmation, so these categories do not overlap.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OccupancyExclusions {
    /// Actual assignment whose track is not confirmed at this source sample.
    pub tentative: usize,
    /// Confirmed whole box touches or intersects a zone edge or its margin.
    pub boundary: usize,
    /// Confirmed detector silhouette is clipped.
    pub partial: usize,
    /// No actual assignment, including coasting, retirement, and pre-track samples.
    pub unobserved: usize,
    /// Source privacy masks overlap the zone; no classification is disclosed.
    pub masked: usize,
    /// Otherwise eligible confirmed inside assignments withheld by historical screening.
    pub health: usize,
}

/// One row for every source frame and declared zone, including an empty track inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OccupancySample {
    /// Source report frame ordinal, not a guessed wall-clock sampling bin.
    pub frame: usize,
    /// Source report's canonical zone ordinal.
    pub zone: usize,
    /// Explicit positive, missing-positive or unavailable interpretation.
    pub state: OccupancyState,
    /// Actual model observations under the original source policy; null for a masked or
    /// health-excluded row. Zero never means that the physical zone is empty.
    pub observed_count: Option<usize>,
    /// Exact anonymous track identities for the counted assignments, in digest order.
    pub supporting_tracks: Vec<ContentDigest>,
    /// Confirmed actual outside assignments, not a negative observation about the zone.
    pub confirmed_outside: usize,
    /// Every track sample excluded from this row's positive count.
    pub excluded: OccupancyExclusions,
    /// Source report's historical screening state, or explicit unassessed v1 policy.
    pub health: OccupancyHealth,
}

/// A completed source-verified read. Construction is restricted to the retained owner;
/// exported JSON cannot be submitted as evidence or converted into a new approval.
#[derive(Debug)]
pub struct PackageOccupancyReport {
    digest: ContentDigest,
    source_report: ContentDigest,
    samples: Vec<OccupancySample>,
    json: String,
}
impl PackageOccupancyReport {
    /// Identity binding the original complete zone report, provenance root and every row.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact retained zone report that the owner reopened and revalidated.
    pub const fn source_report(&self) -> ContentDigest {
        self.source_report
    }
    /// Complete frame-major, zone-minor projection; no ranked or truncated subset.
    pub fn samples(&self) -> &[OccupancySample] {
        &self.samples
    }
    /// Complete pre-admitted JSON, rendered before final source/authority revalidation.
    pub fn to_json(&self) -> &str {
        &self.json
    }
}

fn project(
    frames: usize,
    zones_masked: &[bool],
    tracks: &[ContentDigest],
    cells: &[PackageZoneCell],
    health: &[OccupancyHealth],
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<Vec<OccupancySample>> {
    if frames == 0
        || frames > 64
        || zones_masked.is_empty()
        || zones_masked.len() > MAX_PACKAGE_ZONES
    {
        return Err(PackageZoneError::Limit);
    }
    let rows = frames
        .checked_mul(zones_masked.len())
        .ok_or(PackageZoneError::Limit)?;
    let expected = tracks
        .len()
        .checked_mul(rows)
        .ok_or(PackageZoneError::Limit)?;
    if expected > MAX_PACKAGE_ZONE_CELLS || cells.len() > MAX_PACKAGE_ZONE_CELLS {
        return Err(PackageZoneError::Limit);
    }
    if cells.len() != expected || health.len() != frames {
        return Err(PackageZoneError::Mismatch);
    }
    let track_index = tracks
        .iter()
        .copied()
        .enumerate()
        .map(|(i, d)| (d, i))
        .collect::<BTreeMap<_, _>>();
    if track_index.len() != tracks.len() {
        return Err(PackageZoneError::Mismatch);
    }
    let mut samples = Vec::with_capacity(rows);
    for (frame, h) in health.iter().copied().enumerate() {
        for (zone, masked) in zones_masked.iter().copied().enumerate() {
            samples.push(OccupancySample {
                frame,
                zone,
                state: if masked {
                    OccupancyState::Masked
                } else if !h.source_policy_allows() {
                    OccupancyState::HealthExcluded
                } else {
                    OccupancyState::NoPositiveObservation
                },
                observed_count: (h.source_policy_allows() && !masked).then_some(0),
                supporting_tracks: Vec::new(),
                confirmed_outside: 0,
                excluded: OccupancyExclusions::default(),
                health: h,
            });
        }
    }
    let mut seen = vec![false; expected];
    let mut assignments = BTreeSet::new();
    for cell in cells {
        checkpoint()?;
        let track = *track_index
            .get(&cell.track)
            .ok_or(PackageZoneError::Mismatch)?;
        if cell.frame >= frames || cell.zone >= zones_masked.len() {
            return Err(PackageZoneError::Mismatch);
        }
        let row_index = cell.frame * zones_masked.len() + cell.zone;
        let index = track * rows + row_index;
        if std::mem::replace(&mut seen[index], true)
            || (cell.relation == PackageZoneRelation::Masked) != zones_masked[cell.zone]
            || cell.detection_row.is_some() != cell.bounds.is_some()
        {
            return Err(PackageZoneError::Mismatch);
        }
        let row = &mut samples[row_index];
        if zones_masked[cell.zone] {
            row.excluded.masked += 1;
            continue;
        }
        if cell.relation == PackageZoneRelation::Unobserved {
            if cell.detection_row.is_some() || cell.sample_confirmed || cell.clipped {
                return Err(PackageZoneError::Mismatch);
            }
            row.excluded.unobserved += 1;
            continue;
        }
        let detection = cell.detection_row.ok_or(PackageZoneError::Mismatch)?;
        if !assignments.insert((row_index, detection))
            || cell.clipped != (cell.relation == PackageZoneRelation::Partial)
        {
            return Err(PackageZoneError::Mismatch);
        }
        if !cell.sample_confirmed {
            row.excluded.tentative += 1;
            continue;
        }
        match cell.relation {
            PackageZoneRelation::Inside if row.health.source_policy_allows() => {
                row.supporting_tracks.push(cell.track);
            }
            PackageZoneRelation::Inside => row.excluded.health += 1,
            PackageZoneRelation::Outside => row.confirmed_outside += 1,
            PackageZoneRelation::Boundary => row.excluded.boundary += 1,
            PackageZoneRelation::Partial => row.excluded.partial += 1,
            PackageZoneRelation::Unobserved | PackageZoneRelation::Masked => {
                return Err(PackageZoneError::Mismatch);
            }
        }
    }
    for row in &mut samples {
        checkpoint()?;
        row.supporting_tracks.sort_unstable();
        if let Some(count) = &mut row.observed_count {
            *count = row.supporting_tracks.len();
            if *count != 0 {
                row.state = OccupancyState::ObservedPositive;
            }
        }
    }
    Ok(samples)
}

fn identity(
    source: ContentDigest,
    root: ContentDigest,
    samples: &[OccupancySample],
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_OCCUPANCY_REPORT_DOMAIN);
    e.text(PACKAGE_OCCUPANCY_POLICY);
    e.digest(source);
    e.digest(root);
    e.u64(samples.len() as u64);
    for row in samples {
        e.u64(row.frame as u64);
        e.u64(row.zone as u64);
        e.text(row.state.as_str());
        e.bool(row.observed_count.is_some());
        if let Some(count) = row.observed_count {
            e.u64(count as u64);
        }
        e.text(row.health.as_str());
        e.u64(row.confirmed_outside as u64);
        for count in [
            row.excluded.tentative,
            row.excluded.boundary,
            row.excluded.partial,
            row.excluded.unobserved,
            row.excluded.masked,
            row.excluded.health,
        ] {
            e.u64(count as u64);
        }
        e.u64(row.supporting_tracks.len() as u64);
        for track in &row.supporting_tracks {
            e.digest(*track);
        }
    }
    let bytes = e
        .finish_checked()
        .map_err(|error| PackageZoneError::Source(Box::new(error)))?;
    Ok(ContentDigest::sha256(&bytes))
}
