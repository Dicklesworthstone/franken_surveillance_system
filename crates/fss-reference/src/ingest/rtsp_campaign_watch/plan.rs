#![forbid(unsafe_code)]
//! Pure exact-history admission and whole-operation resource reservations.

use std::path::{Component, Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolLimits;
use fss_publication::LocalPublicationLimits;

use super::{POLICY, Result, RtspCampaignWatchError};
use crate::ingest::long_dwell::limits::encode_limits;
use crate::ingest::long_watch::LongWatchLimits;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::rtsp_campaign_sources::{self, SourcePlan};
use crate::ingest::rtsp_selected_watch::{
    MAX_REPORT_BYTES, RtspSelectedWatchLimits, RtspSelectedWatchPlan, RtspSelectedWatchReservation,
    RtspWatchSelection,
};
use crate::rtsp::campaign_history::{
    CampaignHistoryLimits, CampaignPin, MAX_CAMPAIGN_ATTEMPTS, VerifiedCampaignHistory,
};

/// One explicit row for every selected start, including failed and unknown native outcomes.
#[derive(Clone, Debug)]
pub struct RtspCampaignWatchBinding {
    /// One-based native attempt ordinal, in exact selected-history order.
    pub ordinal: u32,
    /// Every saved catalog for this attempt, or `None` precisely when no catalogs were observed.
    /// Windows and partial page inventories cannot stand in for the whole retained catalog list.
    pub selection: Option<RtspWatchSelection>,
}

/// Exact immutable history and independent per-attempt analysis choices. The saved namespace
/// commits each supplied codec, sensor, stream, authority anchor, generation and clock declaration.
#[derive(Clone, Debug)]
pub struct RtspCampaignWatchPlan {
    /// Independently saved approval, frozen-plan, root and record-count coordinates.
    pub history: CampaignPin,
    /// Exact existing metadata owner; no latest-head discovery or directory creation is permitted.
    pub history_root: PathBuf,
    /// Complete selected started-attempt inventory, including non-analyzable rows.
    pub bindings: Vec<RtspCampaignWatchBinding>,
    /// Native AVC/HEVC YCbCr interpretation.
    pub interpretation: ComponentInterpretation,
    /// Image zones independently evaluated in each analyzed attempt.
    pub zones: Vec<WatchZone>,
    /// Shared detector configuration, with fresh background state for every attempt.
    pub detector: WatchDetectorConfig,
    /// Shared thresholds, with independent trackers and local identities at every attempt.
    pub tracker: WatchTrackerConfig,
    /// Strict or explicitly tolerant native decode policy.
    pub options: WatchOptions,
    /// Apply the native conservative health screen after privacy masking.
    pub screened: bool,
}

/// Complete cold-history, per-attempt analysis and final combined-report ceilings.
#[derive(Clone, Copy, Debug)]
pub struct RtspCampaignWatchLimits {
    /// One bounded exact metadata verification; initial and final passes share caller work.
    pub history: CampaignHistoryLimits,
    /// Native read-only publication inspection bounds, never a new storage policy.
    pub history_publication: LocalPublicationLimits,
    /// Fixed native allowance reserved for each analyzed attempt before any mutation.
    pub watch: LongWatchLimits,
    /// Complete output bound; rows and native candidates are never truncated to fit.
    pub maximum_report_bytes: usize,
}
impl Default for RtspCampaignWatchLimits {
    fn default() -> Self {
        Self {
            history: CampaignHistoryLimits::default(),
            history_publication: LocalPublicationLimits::new(
                33,
                4,
                16,
                4096,
                SpoolLimits::new(4096, 32 * 1024 * 1024, 256 * 1024, 4096),
            ),
            watch: LongWatchLimits::default(),
            maximum_report_bytes: MAX_REPORT_BYTES,
        }
    }
}

/// Checked ceilings for the complete selected operation, not observed consumption. Original
/// preflight, import and final revalidation share one work account; no per-attempt refill occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtspCampaignWatchReservation {
    /// Every selected started attempt, including failed/unknown rows with no catalog.
    pub attempts: u32,
    /// Two complete bounded cold-metadata inspections; caller-side admission is additional work.
    pub history_metadata_bytes: u64,
    /// Complete original verification passes: preflight, native import, and final revalidation.
    pub source_verification_passes: u32,
    /// Three times the sum of complete native original-selection ceilings.
    pub original_verification_bytes: u64,
    /// Existing fixed native watch/import reservations for all catalog-bearing attempts.
    pub analysis: RtspSelectedWatchReservation,
}

impl RtspCampaignWatchPlan {
    pub(super) fn selected_plan(&self) -> RtspSelectedWatchPlan {
        RtspSelectedWatchPlan {
            selections: self
                .bindings
                .iter()
                .filter_map(|b| b.selection.clone())
                .collect(),
            interpretation: self.interpretation,
            zones: self.zones.clone(),
            detector: self.detector,
            tracker: self.tracker,
            options: self.options,
            screened: self.screened,
        }
    }

    pub(super) fn watch_plan(&self, import: ContentDigest, frames: usize) -> WatchPlan {
        WatchPlan {
            import_identity: import,
            interpretation: self.interpretation,
            first_segment: 0,
            segment_count: frames,
            zones: self.zones.clone(),
            detector: self.detector,
            tracker: self.tracker,
        }
    }

    /// Validate all native request/configuration fields and checked total reservations before I/O.
    /// Empty analysis still validates the native watch configuration without fabricating a source.
    pub fn reservation(
        &self,
        limits: &RtspCampaignWatchLimits,
    ) -> Result<RtspCampaignWatchReservation> {
        self.history.validate()?;
        limits.history.validate()?;
        limits
            .history_publication
            .validate()
            .map_err(|_| RtspCampaignWatchError::Invalid("history publication limits"))?;
        let path = self
            .history_root
            .to_str()
            .ok_or(RtspCampaignWatchError::Invalid("history path UTF-8"))?;
        if !self.history_root.is_absolute()
            || self.history_root.parent().is_none()
            || path.len() > 2048
            || path.chars().any(char::is_control)
            || !self.history_root.components().all(|part| {
                matches!(
                    part,
                    Component::RootDir | Component::Prefix(_) | Component::Normal(_)
                )
            })
            || !(1..=MAX_CAMPAIGN_ATTEMPTS).contains(&self.bindings.len())
        {
            return Err(RtspCampaignWatchError::Invalid(
                "history path or binding count",
            ));
        }
        for (index, binding) in self.bindings.iter().enumerate() {
            if binding.ordinal != index as u32 + 1
                || matches!(binding.selection, Some(RtspWatchSelection::Window(_)))
            {
                return Err(RtspCampaignWatchError::Invalid(
                    "attempt order or complete catalog selection",
                ));
            }
        }
        let analysis =
            self.selected_plan()
                .reservation_including_empty(&RtspSelectedWatchLimits {
                    watch: limits.watch,
                    maximum_report_bytes: limits.maximum_report_bytes,
                })?;
        Ok(RtspCampaignWatchReservation {
            attempts: self.bindings.len() as u32,
            history_metadata_bytes: limits
                .history
                .maximum_metadata_bytes
                .checked_mul(2)
                .ok_or(RtspCampaignWatchError::Limit)?,
            source_verification_passes: 3,
            original_verification_bytes: analysis
                .original_bytes
                .checked_mul(3)
                .ok_or(RtspCampaignWatchError::Limit)?,
            analysis,
        })
    }

    /// Pure whole-history mapping check, suitable before the CLI opens an archive or destination.
    /// A verified metadata object is not current source custody; execution revalidates both.
    pub fn validate_history(&self, history: &VerifiedCampaignHistory) -> Result<()> {
        rtsp_campaign_sources::validate_history(self.source_plan(), history)
    }

    pub(super) fn source_plan(&self) -> SourcePlan<'_> {
        SourcePlan {
            pin: self.history,
            root: &self.history_root,
            bindings: &self.bindings,
        }
    }

    /// Refuse overlap with every frozen acquisition owner, including pin journals, source bytes,
    /// and planned attempts outside the selected prefix. This check performs no filesystem I/O.
    pub fn validate_destination(
        &self,
        history: &VerifiedCampaignHistory,
        destination: &Path,
    ) -> Result<()> {
        rtsp_campaign_sources::validate_destination(self.source_plan(), history, destination)
    }

    /// Canonical approval identity binds the independent history pin, every native selection,
    /// all capture assumptions, every watch choice and both metadata/analysis resource envelopes.
    pub fn digest(&self, limits: &RtspCampaignWatchLimits) -> Result<ContentDigest> {
        self.reservation(limits)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_campaign_watch_plan.v1");
        e.digest(ContentDigest::sha256(POLICY));
        for digest in [self.history.approval, self.history.plan, self.history.root] {
            e.digest(digest);
        }
        e.u32(self.history.records);
        e.text(
            self.history_root
                .to_str()
                .ok_or(RtspCampaignWatchError::Invalid("history path"))?,
        );
        e.u32(self.bindings.len() as u32);
        for binding in &self.bindings {
            e.u32(binding.ordinal);
            e.bool(binding.selection.is_some());
            if let Some(selection) = &binding.selection {
                e.digest(selection.digest()?);
            }
        }
        e.digest(self.watch_plan(ContentDigest::sha256(POLICY), 1).digest());
        e.bool(self.options.tolerate_decode_refusals);
        e.bool(self.screened);
        e.digest(limits.history.digest()?);
        let local = limits.history_publication;
        for count in [
            local.max_roots,
            local.max_children,
            local.max_tombstones,
            local.max_scan_entries,
            local.spool.max_objects,
            local.spool.max_object_bytes,
            local.spool.max_scan_entries,
        ] {
            e.u64(count as u64);
        }
        e.u64(local.spool.max_total_bytes);
        encode_limits(&mut e, &limits.watch);
        e.u64(limits.maximum_report_bytes as u64);
        let bytes = e
            .finish_checked()
            .map_err(|_| RtspCampaignWatchError::Limit)?;
        Ok(ContentDigest::sha256(&bytes))
    }
}
