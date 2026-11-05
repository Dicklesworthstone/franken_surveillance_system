#![forbid(unsafe_code)]
//! Observed QSR counts, sampled dwell and lane-stage endpoints from retained detector tracks.
//!
//! The sole public constructor cold-reopens the existing screened package-zone owner. This
//! layer neither executes a model nor accepts loose tracks, renews rights, commits events or
//! certifies absence. Every count is a count of actual confirmed model-track observations.

use std::error::Error;
use std::fmt;

use fss_core::ContentDigest;

use super::package_zones::{PackageZoneError, PackageZoneReport};
use crate::{ReferenceDeployment, ReplayCx};

mod derive;
mod types;
mod wire;
pub use types::*;
#[cfg(test)]
mod tests;

/// Byte-free read projection schema; this is not an EventKind or a capability.
pub const QSR_OBSERVATION_SCHEMA: &str = "fss.qsr_observation_report.v1";
/// Immutable reducer policy, bound into every report identity.
pub const QSR_OBSERVATION_POLICY: &str = "fss.qsr_observation_policy.v1:actual-confirmed-boxes;complete-historical-screen;no-absence;sampled-dwell;adjacent-ordered-stage-endpoints";
/// Complete output bound, including every exclusion and supporting track identity.
pub const MAX_QSR_JSON_BYTES: usize = 8 * 1024 * 1024;
/// After complete derivation/rendering, before current source and retained-proof revalidation.
pub const STAGE_QSR_REVALIDATE: &str = "qsr:revalidate";

/// Typed refusals never return an empty-success substitute for missing source custody.
#[derive(Debug)]
pub enum QsrError {
    /// Invalid or unsupported operator annotation.
    Invalid(&'static str),
    /// A complete work or output bound was exceeded.
    Limit,
    /// Source owner returned inconsistent dimensions or indices.
    Mismatch,
    /// Cooperative cancellation before delivery.
    Cancelled,
    /// Existing custody, privacy, historical screening or deletion owner refused.
    Source(PackageZoneError),
}
impl fmt::Display for QsrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "QSR observation invalid: {reason}"),
            Self::Limit => f.write_str("QSR complete work/output bound exceeded"),
            Self::Mismatch => f.write_str("QSR source report mismatch"),
            Self::Cancelled => f.write_str("QSR observation cancelled"),
            Self::Source(error) => write!(f, "QSR source owner refused: {error}"),
        }
    }
}
impl Error for QsrError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            _ => None,
        }
    }
}
/// Complete observation or a typed refusal.
pub type Result<T> = std::result::Result<T, QsrError>;

/// Sealed derived read, built only from currently verified retained source evidence.
#[derive(Debug)]
pub struct QsrObservationReport {
    source: PackageZoneReport,
    config: QsrConfig,
    observations: QsrObservations,
    bytes: Vec<u8>,
    digest: ContentDigest,
    json: String,
}
impl QsrObservationReport {
    /// Reopen one retained v2 screened report through its original custody/privacy/deletion
    /// owner, then project it without inference, source acquisition, retention or authority writes.
    /// Complete canonical and JSON output is admitted before final custody/privacy/deletion,
    /// principal, ledger-head and retained-proof revalidation under the remaining source-health
    /// allowance. A failed final check returns no report, even when derivation has completed.
    pub fn open(
        deployment: &ReferenceDeployment,
        report_digest: ContentDigest,
        config: QsrConfig,
        cx: &ReplayCx,
    ) -> Result<Self> {
        cx.checkpoint("qsr:open").map_err(|_| QsrError::Cancelled)?;
        config.validate_shape()?;
        let source =
            PackageZoneReport::open(deployment, report_digest, cx).map_err(QsrError::Source)?;
        if !source.requires_health_screening() || source.retention_anchor().is_none() {
            return Err(QsrError::Invalid(
                "retained screened package-zone report required",
            ));
        }
        let zones: Vec<_> = source
            .config()
            .zones
            .iter()
            .map(|zone| zone.id.clone())
            .collect();
        let config = config.normalized(&zones)?;
        let health: Vec<_> = (0..source.frames().len())
            .map(|frame| {
                source
                    .health_support_allowed(frame)
                    .ok_or(QsrError::Mismatch)
            })
            .collect::<Result<_>>()?;
        let masked: Vec<_> = (0..zones.len())
            .map(|zone| source.zone_is_masked(zone).ok_or(QsrError::Mismatch))
            .collect::<Result<_>>()?;
        let tracks: Vec<_> = source
            .analysis()
            .tracks()
            .iter()
            .map(|track| track.identity)
            .collect();
        let observations = derive::derive(
            &config,
            source.config().maximum_sample_gap_ns,
            source.frames(),
            source.cells(),
            source.events(),
            &tracks,
            &health,
            &masked,
            || cx.checkpoint("qsr:derive").map_err(|_| QsrError::Cancelled),
        )?;
        let bytes = wire::encode(&source, &config, &observations)?;
        let digest = ContentDigest::sha256(&bytes);
        let mut report = Self {
            source,
            config,
            observations,
            bytes,
            digest,
            json: String::new(),
        };
        let json = wire::json(&report)?;
        cx.checkpoint(STAGE_QSR_REVALIDATE)
            .map_err(|_| QsrError::Cancelled)?;
        report
            .source
            .revalidate_retained_read(deployment, cx)
            .map_err(QsrError::Source)?;
        cx.checkpoint("qsr:complete")
            .map_err(|_| QsrError::Cancelled)?;
        report.json = json;
        Ok(report)
    }
    /// Exact source-verified report and its immutable evidence handles.
    pub fn source(&self) -> &PackageZoneReport {
        &self.source
    }
    /// Complete normalized roles; lane order remains the explicitly requested order.
    pub fn config(&self) -> &QsrConfig {
        &self.config
    }
    /// Every derived sample, dwell span, lane transition and interruption.
    pub fn observations(&self) -> &QsrObservations {
        &self.observations
    }
    /// Complete canonical read-result bytes, not an authority record or retention promise.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 of the complete canonical result, including source and policy bindings.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Complete bounded byte-free JSON, admitted before the final source check in `open`.
    /// This is the immutable snapshot of that completed read; rendering it performs no new
    /// source reads, budget refills or claim of freshness after construction.
    pub fn to_json(&self) -> Result<String> {
        Ok(self.json.clone())
    }
}
