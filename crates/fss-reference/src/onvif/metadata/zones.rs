#![forbid(unsafe_code)]
//! Source-verified finite zone observations over retained vendor metadata.
//!
//! Geometry is evaluated inside each complete source-reconstruction pass and debits the
//! same nonrenewing request allowance. An exact raw-coordinate policy remains a caller
//! declaration; custody verification does not make it calibrated geometry or authority.

use std::fmt;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest, Plane, ProvenanceClass};

use super::MetadataError;
use super::tracks::{RetainedTrackError, RetainedTracklets, TrackReadLimits, TrackSourcePin};
use crate::{ReferenceError, ReplayAdmission, ReplayCx};

/// Pure bounded vendor-coordinate observations, without source custody or clock authority.
pub mod contract;
pub use contract::{ZoneError, ZoneLimits, ZonePolicy, ZoneReport, project_zones};

/// Complete retained snapshot domain; distinct from the pure geometry report.
pub const RETAINED_ZONES_SCHEMA: &str = "fss.onvif_retained_vendor_zones.v1";
/// One cumulative source/history/projector allowance across both complete passes.
pub const DEFAULT_ZONE_READ_WORK_UNITS: usize = 32 * 1024 * 1024;

/// Original custody bounds and the independently bounded complete zone projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneReadLimits {
    /// Existing source custody, unchanged tracks-v1 policy and cumulative request allowance.
    pub source: TrackReadLimits,
    /// Full occurrence/frame matrices, transitions, work and canonical output bounds.
    pub projection: ZoneLimits,
}
impl Default for ZoneReadLimits {
    fn default() -> Self {
        Self {
            source: TrackReadLimits {
                max_work_units: DEFAULT_ZONE_READ_WORK_UNITS,
                ..TrackReadLimits::default()
            },
            projection: ZoneLimits::default(),
        }
    }
}
impl ZoneReadLimits {
    /// Reject widened or impossible policies before opening an existing deployment.
    pub fn validate(self) -> Result<(), RetainedZoneError> {
        self.source.validate()?;
        self.projection.validate()?;
        let minimum = self
            .source
            .projection
            .max_work_units
            .checked_add(self.projection.max_work_units)
            .and_then(|value| value.checked_add(512))
            .and_then(|value| value.checked_mul(2))
            .ok_or(RetainedZoneError::Projection(ZoneError::InvalidLimits))?;
        if self.projection.max_work_units <= self.source.projection.max_work_units
            || minimum > self.source.max_work_units as u64
        {
            return Err(RetainedZoneError::Projection(ZoneError::InvalidLimits));
        }
        Ok(())
    }
}

/// Whole-query refusal. No successful partial matrix or detached source owner escapes.
#[derive(Debug)]
pub enum RetainedZoneError {
    /// Exact original custody, deletion checks, request admission or shared work failed.
    Source(Box<RetainedTrackError>),
    /// The complete bounded source-linked geometry projection refused its input or policy.
    Projection(ZoneError),
}
impl RetainedZoneError {
    /// Stable diagnostic with no path, policy label or vendor value.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Source(error) => error.code(),
            Self::Projection(error) => error.code(),
        }
    }
}
impl fmt::Display for RetainedZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for RetainedZoneError {}
impl From<RetainedTrackError> for RetainedZoneError {
    fn from(value: RetainedTrackError) -> Self {
        Self::Source(Box::new(value))
    }
}
impl From<MetadataError> for RetainedZoneError {
    fn from(value: MetadataError) -> Self {
        RetainedTrackError::from(value).into()
    }
}
impl From<ReferenceError> for RetainedZoneError {
    fn from(value: ReferenceError) -> Self {
        RetainedTrackError::from(value).into()
    }
}
impl From<super::tracks::TrackError> for RetainedZoneError {
    fn from(value: super::tracks::TrackError) -> Self {
        RetainedTrackError::from(value).into()
    }
}
impl From<ZoneError> for RetainedZoneError {
    fn from(value: ZoneError) -> Self {
        Self::Projection(value)
    }
}

/// A complete zone result released only after both source passes and final authority checks.
#[derive(Debug)]
pub struct RetainedZones {
    snapshot: RetainedTracklets,
    report: ZoneReport,
    limits: ZoneReadLimits,
    digest: ContentDigest,
}
impl RetainedZones {
    /// Reconstruct all pinned originals twice, compare every derived row, and verify the
    /// final authority/effect-store state under the original request's shared allowance.
    pub fn open(
        root: &Path,
        site_lineage: &str,
        pins: &[TrackSourcePin],
        policy: &ZonePolicy,
        limits: ZoneReadLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, RetainedZoneError> {
        limits.validate()?;
        policy.validate()?;
        let (snapshot, report) = RetainedTracklets::open_projected(
            root,
            site_lineage,
            pins,
            limits.source,
            cx,
            |input, _deployment, work, cx| {
                // Prepay the fixed final envelope encoding/hash inside both admitted passes;
                // no work balance or callback is created after final source authority checks.
                work.reserve(512)?;
                work.reserve(limits.projection.max_work_units as usize)?;
                project_zones(
                    input.frames,
                    input.tracks,
                    policy,
                    limits.projection,
                    || super::checkpoint(cx, "onvif_zones:projection").is_ok(),
                )
                .map_err(RetainedZoneError::from)
            },
        )?;
        // Only fixed-size pure commitment work follows the source owner's final checks.
        let mut encoded = CanonicalEncoder::new();
        encoded.text(RETAINED_ZONES_SCHEMA);
        encoded.digest(snapshot.digest());
        encoded.digest(report.report_digest);
        let digest =
            ContentDigest::sha256(&encoded.finish_checked().map_err(|_| ZoneError::Encoding)?);
        Ok(Self {
            snapshot,
            report,
            limits,
            digest,
        })
    }

    /// Unchanged tracks-v1 grouping, every source receipt, authority and total accounting.
    #[must_use]
    pub fn snapshot(&self) -> &RetainedTracklets {
        &self.snapshot
    }
    /// Complete source-linked vendor-zone cells, frame accounting and observed side changes.
    #[must_use]
    pub fn report(&self) -> &ZoneReport {
        &self.report
    }
    /// Exact caller-declared bounds.
    #[must_use]
    pub const fn limits(&self) -> ZoneReadLimits {
        self.limits
    }
    /// Binds original custody snapshot, policy, complete result and all execution bounds.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Zone interpretation remains cognition.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// Geometry classification is derived, never an authority event.
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::Derived
    }
    /// Source boxes, identifiers and timestamps remain vendor claims.
    #[must_use]
    pub const fn source_provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
}
