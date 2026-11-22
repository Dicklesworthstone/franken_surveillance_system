#![forbid(unsafe_code)]
//! Complete native ONVIF analysis while a capture owner retains the publisher lock.
//!
//! Verified deployment history brackets the same two complete source/projection passes used
//! by canonical ONVIF queries. No publisher, recovery, writer lock or mutable deployment is
//! constructed. Metadata payload reads and source filesystem calls have separate, explicit,
//! nonrenewing allowances. This is a bounded repeated observation, not an atomic read lease.

use std::path::Path;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, LedgerAnchor};
use fss_object::{HostSpoolIo, SpoolIo};

use super::read_view::{read_analysis_with_admission, validate_pins};
use super::tracks::{TrackReadLimits, TrackSourcePin};
pub use super::read_view::{
    OnvifAnalysis, OnvifAnalysisResult, OnvifReadError, OnvifReadLimits, OnvifReadResult,
};
use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
use crate::{ReplayAdmission, ReplayCx};

/// Separate hard ceiling for all opening/final deployment metadata payload bytes.
pub const MAX_NATIVE_DEPLOYMENT_READ_BYTES: usize = 256 * 1024 * 1024;
/// Separate hard ceiling for all deployment metadata payload-read attempts.
pub const MAX_NATIVE_DEPLOYMENT_READ_ATTEMPTS: usize = 65_536;
/// Commitment domain for the immutable native owner; old mutable-owner snapshots are distinct.
pub const NATIVE_ONVIF_READ_SCHEMA: &str = "fss.onvif_native_immutable_read.v1";

/// Bounds for the complete native read, including both authority observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOnvifReadLimits {
    /// Existing bounded native metadata projection; never the global spool doctor.
    pub snapshot: OrientLimits,
    /// One metadata payload-byte balance shared by opening and final history reconstruction.
    pub max_deployment_read_bytes: usize,
    /// One metadata payload-read-attempt balance; filesystem stat/open calls are not counted.
    pub max_deployment_read_attempts: usize,
    /// One exact source closure and conservative computation balance for both complete passes.
    pub source: OnvifReadLimits,
}

impl Default for NativeOnvifReadLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            max_deployment_read_bytes: 128 * 1024 * 1024,
            max_deployment_read_attempts: 16_384,
            source: OnvifReadLimits::default(),
        }
    }
}

impl NativeOnvifReadLimits {
    /// Carry the native tracklet policy into immutable source accounting. The caller's byte
    /// and attempt ceilings now bound all source closure bytes and filesystem calls; no
    /// indexed-spool accounting is claimed. Deployment metadata has its own explicit balance.
    pub fn from_tracks(limits: TrackReadLimits) -> Result<Self, NativeOnvifReadError> {
        limits
            .validate()
            .map_err(|error| NativeOnvifReadError::Source(error.into()))?;
        let mut result = Self::default();
        result.source.max_sources = limits.max_sources;
        result.source.max_work_units = limits.max_work_units;
        result.source.tracks = limits.projection;
        result.source.custody.max_read_bytes = limits.max_stored_bytes;
        result.source.custody.max_io_calls = limits.max_indexed_reads;
        Ok(result)
    }

    /// Refuse widened or impossible bounds before reading any deployment or source path.
    pub fn validate(&self, analysis: &OnvifAnalysis) -> Result<(), NativeOnvifReadError> {
        let ceiling = OrientLimits::default();
        for (value, maximum) in [
            (self.max_deployment_read_bytes, MAX_NATIVE_DEPLOYMENT_READ_BYTES),
            (
                self.max_deployment_read_attempts,
                MAX_NATIVE_DEPLOYMENT_READ_ATTEMPTS,
            ),
            (self.snapshot.max_layout_bytes, ceiling.max_layout_bytes),
            (self.snapshot.max_journal_bytes, ceiling.max_journal_bytes),
            (self.snapshot.max_object_bytes, ceiling.max_object_bytes),
            (self.snapshot.max_events, ceiling.max_events),
            (
                self.snapshot.max_revisions_per_event,
                ceiling.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(NativeOnvifReadError::InvalidRequest);
            }
        }
        self.source.validate(analysis).map_err(NativeOnvifReadError::Source)
    }
}

/// Complete refusal; an error never returns a partial native report or repairs the deployment.
#[derive(Debug)]
pub enum NativeOnvifReadError {
    /// Invalid root, site, pins or explicit limits.
    InvalidRequest,
    /// Current deployment metadata is absent, unreadable or fails native replay.
    Deployment(DeploymentReadError),
    /// Authority is incomplete: a journal is absent or has an uncommitted tail.
    IncompleteHistory,
    /// The current authority, layout, effect history or deletion restrictions changed.
    Changed,
    /// Source reconstruction, projection or source accounting refused.
    Source(OnvifReadError),
    /// The native owner refused a cooperative authority/cancellation/deadline boundary.
    Cancelled,
    /// The shared deployment metadata allowance was exhausted or poisoned.
    MetadataBudget,
}
impl NativeOnvifReadError {
    /// Stable payload-free diagnostics; paths, vendor values and source bytes remain private.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "onvif.native_read.invalid_request",
            Self::Deployment(_) => "onvif.native_read.deployment",
            Self::IncompleteHistory => "onvif.native_read.incomplete_history",
            Self::Changed => "onvif.native_read.changed",
            Self::Source(error) => error.code(),
            Self::Cancelled => "onvif.native_read.cancelled",
            Self::MetadataBudget => "onvif.native_read.metadata_budget",
        }
    }
}
impl std::fmt::Display for NativeOnvifReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for NativeOnvifReadError {}

/// Full native rows and independently verified custody accounting, without a synopsis limit.
/// Raw vendor values remain in this local typed result; presentation still controls disclosure.
#[derive(Debug)]
pub struct NativeOnvifRead {
    /// All original tracks and the selected complete lifecycle/zone interpretation.
    pub native: OnvifReadResult,
    /// Current authority observed identically before and after source reconstruction.
    pub authority_anchor: LedgerAnchor,
    /// Exact source, metadata and computation ceilings.
    pub limits: NativeOnvifReadLimits,
    /// Metadata payload bytes across opening and final revalidation.
    pub deployment_read_bytes: u64,
    /// Metadata payload-read attempts across opening and final revalidation.
    pub deployment_read_attempts: u64,
    /// Immutable-owner result identity; pure native projection identities remain unchanged.
    pub snapshot_digest: ContentDigest,
}

impl NativeOnvifRead {
    /// Read exact existing sources without taking a publication lock, repairing a journal or
    /// creating a missing store. Native task admission may borrow a non-Sync synchronous scope.
    ///
    /// Opening and source reconstruction cooperate at every bounded payload-read boundary.
    /// The final checkpoint admits one bounded metadata-only finalization under the original
    /// allowance; no caller callback follows it, so a callback cannot mutate already-checked
    /// authority. The caller must gate delivery for cancellation/deadline after finalization.
    pub fn open(
        root: &Path,
        site: &str,
        pins: &[TrackSourcePin],
        analysis: &OnvifAnalysis,
        limits: NativeOnvifReadLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, NativeOnvifReadError> {
        Self::open_with_io(&HostSpoolIo, root, site, pins, analysis, limits, cx)
    }

    /// The same owner with an explicitly supplied source I/O capability for fault qualification.
    /// Deployment metadata still uses the bounded native immutable inspectors.
    #[allow(clippy::too_many_arguments)]
    pub fn open_with_io(
        io: &dyn SpoolIo,
        root: &Path,
        site: &str,
        pins: &[TrackSourcePin],
        analysis: &OnvifAnalysis,
        limits: NativeOnvifReadLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, NativeOnvifReadError> {
        limits.validate(analysis)?;
        validate_pins(pins, limits.source.max_sources)
            .map_err(NativeOnvifReadError::Source)?;
        if root != cx.root_dir()
            || !root.is_absolute()
            || crate::reference_deployment::validate_site_lineage(site).is_err()
        {
            return Err(NativeOnvifReadError::InvalidRequest);
        }
        cx.checkpoint("onvif_tracks:open")
            .map_err(|_| NativeOnvifReadError::Cancelled)?;
        let budget = MetadataReadBudget::new(
            limits.max_deployment_read_bytes,
            limits.max_deployment_read_attempts,
        );
        let refused = || cx.checkpoint("onvif_native_read:read").is_err();
        let history = DeploymentHistory::read_metadata_cancellable(
            root,
            &limits.snapshot,
            &budget,
            &refused,
        )
        .map_err(NativeOnvifReadError::Deployment)?;
        if history.site_lineage() != site {
            return Err(NativeOnvifReadError::InvalidRequest);
        }
        let snapshot = history
            .snapshot_at_cancellable(history.head(), &refused)
            .map_err(NativeOnvifReadError::Deployment)?;
        require_complete(&history, &snapshot)?;
        budget
            .ensure_valid()
            .map_err(|_| NativeOnvifReadError::MetadataBudget)?;
        let native = read_analysis_with_admission(
            io,
            history.replay_objects_root(),
            site,
            history.batches_through_head(),
            &snapshot.deletions,
            pins,
            analysis,
            limits.source,
            &refused,
        )
        .map_err(NativeOnvifReadError::Source)?;
        // One last native owner callback precedes the bounded final authority observation.
        cx.checkpoint("onvif_tracks:complete")
            .map_err(|_| NativeOnvifReadError::Cancelled)?;
        let final_history = DeploymentHistory::read_metadata(root, &limits.snapshot, &budget)
            .map_err(NativeOnvifReadError::Deployment)?;
        let final_snapshot = final_history
            .snapshot_at(final_history.head())
            .map_err(NativeOnvifReadError::Deployment)?;
        require_complete(&final_history, &final_snapshot)?;
        budget
            .ensure_valid()
            .map_err(|_| NativeOnvifReadError::MetadataBudget)?;
        if final_history.site_lineage() != history.site_lineage()
            || final_history.metadata_layout_digest() != history.metadata_layout_digest()
            || final_history.replay_objects_root() != history.replay_objects_root()
            || final_history.head() != history.head()
            || final_history.roots_at(final_history.head()) != history.roots_at(history.head())
            || final_snapshot.deletions != snapshot.deletions
            || native
                .reference_digests
                .iter()
                .any(|digest| final_snapshot.deletions.object(*digest).is_some())
        {
            return Err(NativeOnvifReadError::Changed);
        }
        // Only bounded pure result assembly follows the final authority/deletion comparison.
        let (deployment_read_bytes, deployment_read_attempts) = budget.consumed();
        let mut encoded = CanonicalEncoder::new();
        encoded.text(NATIVE_ONVIF_READ_SCHEMA);
        snapshot.anchor.encode_canonical(&mut encoded);
        encoded.digest(history.metadata_layout_digest());
        encoded.digest(snapshot.ledger_root);
        encoded.digest(snapshot.effect_journal_root);
        encoded.digest(native.decision_digest);
        for value in [
            limits.snapshot.max_layout_bytes,
            limits.snapshot.max_journal_bytes,
            limits.snapshot.max_object_bytes,
            limits.snapshot.max_events,
            limits.snapshot.max_revisions_per_event,
            limits.max_deployment_read_bytes,
            limits.max_deployment_read_attempts,
        ] {
            encoded.u64(value as u64);
        }
        encoded.u64(deployment_read_bytes);
        encoded.u64(deployment_read_attempts);
        let snapshot_digest = ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| NativeOnvifReadError::InvalidRequest)?,
        );
        Ok(Self {
            native,
            authority_anchor: snapshot.anchor,
            limits,
            deployment_read_bytes,
            deployment_read_attempts,
            snapshot_digest,
        })
    }
}

fn require_complete(
    history: &DeploymentHistory,
    snapshot: &DeploymentSnapshot,
) -> Result<(), NativeOnvifReadError> {
    if history.has_uncommitted_tail() || !snapshot.effect_journal_present {
        return Err(NativeOnvifReadError::IncompleteHistory);
    }
    Ok(())
}
