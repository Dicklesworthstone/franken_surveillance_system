#![forbid(unsafe_code)]
//! Pure exact-history admission and deterministic campaign-wide whole-burst allocation.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_publication::LocalPublicationLimits;

use super::{POLICY, Result, RtspCampaignSentinelError as Error};
use crate::KernelBackend;
use crate::ingest::long_sentinel::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelReservation,
};
use crate::ingest::long_watch::MAX_LONG_WATCH_FRAMES;
use crate::ingest::package_detect::MAX_PACKAGE_DETECT_FRAMES;
use crate::ingest::package_detect::sentinel::MAX_SENTINEL_BURST_FRAMES;
use crate::ingest::rtsp_campaign_sources::{self, SourcePlan};
use crate::ingest::rtsp_campaign_watch::{RtspCampaignWatchBinding, RtspCampaignWatchLimits};
use crate::ingest::rtsp_selected_watch::{MAX_REPORT_BYTES, RtspWatchSelection};
use crate::rtsp::campaign_history::{
    CampaignHistoryLimits, CampaignPin, MAX_CAMPAIGN_ATTEMPTS, VerifiedCampaignHistory,
};

/// Hard campaign inference ceiling; each native recording still admits at most 64 frames.
pub const MAX_CAMPAIGN_SENTINEL_INFERENCES: usize =
    MAX_CAMPAIGN_ATTEMPTS * MAX_PACKAGE_DETECT_FRAMES;
/// Bound the combined model output retained in memory before optional aggregate publication.
pub const MAX_CAMPAIGN_SENTINEL_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// Sampling depends only on retained source coordinates and a finite whole-campaign allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtspCampaignSentinelConfig {
    /// Distance between complete burst starts in each independent attempt.
    pub every_frames: usize,
    /// Complete contiguous frames in a burst, 1..=8, no greater than the period.
    pub burst_frames: usize,
    /// One maximum for all attempts together; partial leftover allowance admits no burst.
    pub max_inferences: usize,
}
impl Default for RtspCampaignSentinelConfig {
    fn default() -> Self {
        Self {
            every_frames: 16,
            burst_frames: 3,
            max_inferences: 48,
        }
    }
}
impl RtspCampaignSentinelConfig {
    /// Validate without source reads, model loading or destination mutation.
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_LONG_WATCH_FRAMES).contains(&self.every_frames)
            || !(1..=MAX_SENTINEL_BURST_FRAMES).contains(&self.burst_frames)
            || self.burst_frames > self.every_frames
            || self.max_inferences < self.burst_frames
            || self.max_inferences > MAX_CAMPAIGN_SENTINEL_INFERENCES
        {
            return Err(Error::Invalid("campaign sentinel sampling bounds"));
        }
        Ok(())
    }
}

/// Exact campaign prefix, current native model and explicit motion-independent analysis policy.
#[derive(Clone, Debug)]
pub struct RtspCampaignSentinelPlan {
    /// Independently saved complete campaign pin, never a latest-head selection.
    pub history: CampaignPin,
    /// Existing immutable history owner, separate from all source and destination roots.
    pub history_root: PathBuf,
    /// Every selected started attempt and its complete exact ordered catalog inventory.
    pub bindings: Vec<RtspCampaignWatchBinding>,
    /// Native AVC/HEVC YCbCr interpretation.
    pub interpretation: ComponentInterpretation,
    /// Independently expected digest of the complete local native RGB detector package.
    pub package_digest: ContentDigest,
    /// Explicit native kernel backend; its implementation generation is bound into approval.
    pub backend: KernelBackend,
    /// Package threshold unless an explicit inclusive ppm override is supplied.
    pub minimum_score_ppm: Option<u32>,
    /// Round-robin whole-burst admission across every exact catalog-bearing attempt.
    pub sampling: RtspCampaignSentinelConfig,
    /// Explicit permission to retain native per-attempt detector aggregates and exact model bytes.
    pub retain: bool,
}

/// Independent history/import admission and one nonrenewable native inference resource pool.
#[derive(Clone, Copy, Debug)]
pub struct RtspCampaignSentinelLimits {
    /// Bounded exact history inspections; initial and final inspections share caller work.
    pub history: CampaignHistoryLimits,
    /// Existing read-only publication limits for the history owner.
    pub history_publication: LocalPublicationLimits,
    /// Source bytes, video capacity/pixels, JPEG work, head work and native report bytes are
    /// shared by the entire campaign. Read/dimension/model limits remain per native frame.
    pub sentinel: LongSentinelLimits,
    /// Complete combined JSON ceiling; no row or native report is truncated to fit.
    pub maximum_report_bytes: usize,
}
impl Default for RtspCampaignSentinelLimits {
    fn default() -> Self {
        let history = RtspCampaignWatchLimits::default();
        Self {
            history: history.history,
            history_publication: history.history_publication,
            sentinel: LongSentinelLimits::default(),
            maximum_report_bytes: MAX_REPORT_BYTES,
        }
    }
}

/// Conservative checked ceilings before I/O, separate from exact allocation and actual usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtspCampaignSentinelReservation {
    /// All selected starts, including unknown and empty attempts.
    pub attempts: u32,
    /// Exact independently owned catalog-bearing archives.
    pub selected_archives: u32,
    /// Two complete bounded metadata inspections; CLI admission is additional work.
    pub history_metadata_bytes: u64,
    /// Native preflight, import and final verification passes over original custody.
    pub source_verification_passes: u32,
    /// Three times all complete original-selection ceilings.
    pub original_verification_bytes: u64,
    /// Sum of native original-selection import ceilings.
    pub import_original_bytes: u64,
    /// Sum of native reconstructed-media import ceilings.
    pub import_media_bytes: u64,
    /// Sum of exact-selection frame ceilings, before actual source preflight.
    pub maximum_frames: u64,
    /// Single global inference reservation; these values are never renewed per attempt.
    pub inference: LongSentinelReservation,
}

/// Exact allocation from verified catalog frame counts, not the broader native durable count.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RtspCampaignSentinelAllocation {
    /// Verified imported catalog samples; omitted/unavailable native observations stay separate.
    pub catalogued_frames: usize,
    /// All complete scheduled bursts in this retained source range.
    pub eligible_bursts: usize,
    /// Complete bursts granted by the campaign round-robin policy.
    pub admitted_bursts: usize,
    /// Exact granted model calls, always admitted_bursts times the explicit burst size.
    pub admitted_inferences: usize,
    /// Eligible bursts denied by the global allowance or the native per-attempt 64-frame ceiling.
    pub budget_skipped_bursts: usize,
}

impl RtspCampaignSentinelPlan {
    pub(super) fn source_plan(&self) -> SourcePlan<'_> {
        SourcePlan {
            pin: self.history,
            root: &self.history_root,
            bindings: &self.bindings,
        }
    }

    /// Pure exact metadata/selection/namespace check before opening any archive or destination.
    pub fn validate_history(&self, history: &VerifiedCampaignHistory) -> Result<()> {
        Ok(rtsp_campaign_sources::validate_history(
            self.source_plan(),
            history,
        )?)
    }

    /// Pure non-overlap check against every frozen acquisition owner, even beyond this prefix.
    pub fn validate_destination(
        &self,
        history: &VerifiedCampaignHistory,
        destination: &Path,
    ) -> Result<()> {
        Ok(rtsp_campaign_sources::validate_destination(
            self.source_plan(),
            history,
            destination,
        )?)
    }

    /// Admit every configuration and conservative whole-operation resource sum before I/O.
    pub fn reservation(
        &self,
        limits: &RtspCampaignSentinelLimits,
    ) -> Result<RtspCampaignSentinelReservation> {
        self.sampling.validate()?;
        self.history
            .validate()
            .map_err(crate::ingest::rtsp_campaign_watch::RtspCampaignWatchError::from)?;
        limits
            .history
            .validate()
            .map_err(crate::ingest::rtsp_campaign_watch::RtspCampaignWatchError::from)?;
        limits
            .history_publication
            .validate()
            .map_err(|_| Error::Invalid("history publication limits"))?;
        limits.sentinel.validate()?;
        let path = self
            .history_root
            .to_str()
            .ok_or(Error::Invalid("history path UTF-8"))?;
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
            || self.interpretation != ComponentInterpretation::YCbCr
            || self.package_digest.algorithm() != DigestAlgorithm::Sha256
            || self.package_digest.is_laboratory()
            || self.package_digest.bytes() == [0; 32]
            || self
                .minimum_score_ppm
                .is_some_and(|score| score > 1_000_000)
            || !(1..=MAX_REPORT_BYTES).contains(&limits.maximum_report_bytes)
        {
            return Err(Error::Invalid(
                "history path, inventory, package, threshold or report limit",
            ));
        }
        let package = &limits.sentinel.package;
        if package.jpeg_work_units == 0
            || package.detection_work_units == 0
            || package.detection_scratch_bytes == 0
            || package.run.preprocess.max_macs == 0
            || package.run.preprocess.max_bytes == 0
            || package.run.execution.max_macs == 0
            || package.run.execution.max_bytes == 0
            || package.run.maximum_output_bytes == 0
            || !(1..=512 * 1024 * 1024).contains(&package.read.max_source_bytes)
            || !(1..=16 * 1024 * 1024).contains(&package.read.max_chunk_bytes)
            || !(1..=16 * 1024 * 1024).contains(&package.read.max_segment_bytes)
        {
            return Err(Error::Invalid(
                "native read, model or nonrenewable work limits",
            ));
        }
        fss_codec_h264::Decoder::new(package.h264)
            .map_err(|_| Error::Invalid("AVC decoder limits"))?;
        fss_codec_h265::Decoder::new(package.h265)
            .map_err(|_| Error::Invalid("HEVC decoder limits"))?;
        let mut identities = BTreeSet::new();
        let mut selected_archives = 0_u32;
        let mut maximum_frames = 0_u64;
        let mut original_bytes = 0_u64;
        let mut media_bytes = 0_u64;
        for (index, binding) in self.bindings.iter().enumerate() {
            if binding.ordinal != index as u32 + 1
                || matches!(binding.selection, Some(RtspWatchSelection::Window(_)))
            {
                return Err(Error::Invalid(
                    "attempt order or complete catalog selection",
                ));
            }
            if let Some(selection) = &binding.selection {
                if !identities.insert(
                    selection.digest().map_err(
                        crate::ingest::rtsp_campaign_watch::RtspCampaignWatchError::from,
                    )?,
                ) || selection.capture_origin().is_none()
                    || selection.maximum_frames() > MAX_LONG_WATCH_FRAMES
                {
                    return Err(Error::Invalid(
                        "duplicate request, capture assumption or frame ceiling",
                    ));
                }
                selected_archives += 1;
                maximum_frames = maximum_frames
                    .checked_add(selection.maximum_frames() as u64)
                    .ok_or(Error::Limit)?;
                let (original, media) = match selection {
                    RtspWatchSelection::Catalog(r) => (r.max_original_bytes, r.max_media_bytes),
                    RtspWatchSelection::Pages(r) => (r.max_original_bytes, r.max_media_bytes),
                    RtspWatchSelection::Window(_) => {
                        return Err(Error::Invalid("whole catalogs required"));
                    }
                };
                original_bytes = original_bytes.checked_add(original).ok_or(Error::Limit)?;
                media_bytes = media_bytes.checked_add(media).ok_or(Error::Limit)?;
            }
        }
        let count = self.sampling.max_inferences as u64;
        let product = |per_frame: u64| count.checked_mul(per_frame).ok_or(Error::Limit);
        let output_bytes = product(package.run.maximum_output_bytes as u64)?;
        if output_bytes > MAX_CAMPAIGN_SENTINEL_OUTPUT_BYTES {
            return Err(Error::Limit);
        }
        let global = &limits.sentinel;
        Ok(RtspCampaignSentinelReservation {
            attempts: self.bindings.len() as u32,
            selected_archives,
            history_metadata_bytes: limits
                .history
                .maximum_metadata_bytes
                .checked_mul(2)
                .ok_or(Error::Limit)?,
            source_verification_passes: 3,
            original_verification_bytes: original_bytes.checked_mul(3).ok_or(Error::Limit)?,
            import_original_bytes: original_bytes,
            import_media_bytes: media_bytes,
            maximum_frames,
            inference: LongSentinelReservation {
                source_chunk_bytes: global.maximum_source_chunk_bytes,
                pixel_samples: global.maximum_pixel_samples,
                video_encoded_bytes: global.maximum_source_chunk_bytes,
                video_coded_luma_capacity: global.maximum_pixel_samples,
                video_decode_work_units: global
                    .maximum_source_chunk_bytes
                    .checked_add(global.maximum_pixel_samples)
                    .ok_or(Error::Limit)?,
                jpeg_work_units: package.jpeg_work_units,
                detection_work_units: package.detection_work_units,
                inferences: self.sampling.max_inferences,
                preprocess_macs: product(package.run.preprocess.max_macs)?,
                execution_macs: product(package.run.execution.max_macs)?,
                output_bytes,
                report_bytes: global.maximum_report_bytes,
            },
        })
    }

    /// Allocate one complete burst per eligible attempt per round, in immutable ordinal order.
    /// Counts must come from all-source preflight. A short tail and unused partial allowance
    /// remain unsampled; a later attempt never receives an invented new inference budget.
    pub fn allocate(&self, frames: &[usize]) -> Result<Vec<RtspCampaignSentinelAllocation>> {
        self.sampling.validate()?;
        if frames.len() != self.bindings.len() || frames.len() > MAX_CAMPAIGN_ATTEMPTS {
            return Err(Error::Invalid("exact preflight frame inventory"));
        }
        let config = self.sampling;
        let mut rows = Vec::with_capacity(frames.len());
        for (&count, binding) in frames.iter().zip(&self.bindings) {
            if count > MAX_LONG_WATCH_FRAMES
                || binding
                    .selection
                    .as_ref()
                    .is_some_and(|s| count > s.maximum_frames())
                || (binding.selection.is_none() && count != 0)
            {
                return Err(Error::Invalid(
                    "preflight samples differ from selected source bounds",
                ));
            }
            let eligible = if count < config.burst_frames {
                0
            } else {
                1 + (count - config.burst_frames) / config.every_frames
            };
            rows.push(RtspCampaignSentinelAllocation {
                catalogued_frames: count,
                eligible_bursts: eligible,
                budget_skipped_bursts: eligible,
                ..RtspCampaignSentinelAllocation::default()
            });
        }
        admit_round_robin(&mut rows, config);
        Ok(rows)
    }

    pub(super) fn native_config(
        &self,
        allocation: RtspCampaignSentinelAllocation,
    ) -> LongSentinelConfig {
        LongSentinelConfig {
            every_frames: self.sampling.every_frames,
            burst_frames: self.sampling.burst_frames,
            max_inferences: allocation.admitted_inferences,
        }
    }

    /// Canonical approval binds exact history/selections, package, backend generation, whole
    /// resource pool, motion-independent schedule, threshold and separate retention authority.
    pub fn digest(&self, limits: &RtspCampaignSentinelLimits) -> Result<ContentDigest> {
        self.reservation(limits)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_campaign_sentinel_plan.v1");
        e.digest(ContentDigest::sha256(POLICY));
        for digest in [self.history.approval, self.history.plan, self.history.root] {
            e.digest(digest);
        }
        e.u32(self.history.records);
        e.text(
            self.history_root
                .to_str()
                .ok_or(Error::Invalid("history path"))?,
        );
        e.u32(self.bindings.len() as u32);
        for binding in &self.bindings {
            e.u32(binding.ordinal);
            e.bool(binding.selection.is_some());
            if let Some(selection) = &binding.selection {
                e.digest(
                    selection.digest().map_err(
                        crate::ingest::rtsp_campaign_watch::RtspCampaignWatchError::from,
                    )?,
                );
            }
        }
        e.text("ycbcr");
        e.digest(self.package_digest);
        e.text(self.backend.stable_id());
        e.digest(self.backend.generation());
        e.bool(self.minimum_score_ppm.is_some());
        if let Some(score) = self.minimum_score_ppm {
            e.u32(score);
        }
        for n in [
            self.sampling.every_frames,
            self.sampling.burst_frames,
            self.sampling.max_inferences,
        ] {
            e.u64(n as u64);
        }
        e.bool(self.retain);
        e.digest(
            limits
                .history
                .digest()
                .map_err(crate::ingest::rtsp_campaign_watch::RtspCampaignWatchError::from)?,
        );
        let local = limits.history_publication;
        for n in [
            local.max_roots,
            local.max_children,
            local.max_tombstones,
            local.max_scan_entries,
            local.spool.max_objects,
            local.spool.max_object_bytes,
            local.spool.max_scan_entries,
        ] {
            e.u64(n as u64);
        }
        e.u64(local.spool.max_total_bytes);
        e.digest(limits.sentinel.digest());
        e.u64(limits.maximum_report_bytes as u64);
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| Error::Limit)?,
        ))
    }
}

fn admit_round_robin(
    rows: &mut [RtspCampaignSentinelAllocation],
    config: RtspCampaignSentinelConfig,
) {
    let per_attempt = MAX_PACKAGE_DETECT_FRAMES / config.burst_frames;
    let mut remaining = config.max_inferences / config.burst_frames;
    while remaining != 0 {
        let mut progressed = false;
        for row in rows.iter_mut() {
            if remaining != 0 && row.admitted_bursts < row.eligible_bursts.min(per_attempt) {
                row.admitted_bursts += 1;
                row.admitted_inferences += config.burst_frames;
                row.budget_skipped_bursts -= 1;
                remaining -= 1;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(eligible: &[usize]) -> Vec<RtspCampaignSentinelAllocation> {
        eligible
            .iter()
            .map(|&eligible_bursts| RtspCampaignSentinelAllocation {
                eligible_bursts,
                budget_skipped_bursts: eligible_bursts,
                ..RtspCampaignSentinelAllocation::default()
            })
            .collect()
    }

    #[test]
    fn round_robin_uses_catalog_burst_counts_and_leaves_partial_allowance_unused() {
        // Six catalogued pictures (not eight recorded durable) yield one 3-frame burst at
        // cadence five; sixteen catalogued pictures yield three. Neither count implies time coverage.
        let mut rows = rows(&[1, 3, 0, 0]);
        admit_round_robin(
            &mut rows,
            RtspCampaignSentinelConfig {
                every_frames: 5,
                burst_frames: 3,
                max_inferences: 11,
            },
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.admitted_inferences)
                .collect::<Vec<_>>(),
            vec![3, 6, 0, 0]
        );
        assert_eq!(rows[1].budget_skipped_bursts, 1);
    }

    #[test]
    fn a_global_burst_goes_to_one_attempt_without_refilling_others() {
        let mut rows = rows(&[4, 4, 4]);
        admit_round_robin(
            &mut rows,
            RtspCampaignSentinelConfig {
                every_frames: 8,
                burst_frames: 3,
                max_inferences: 5,
            },
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.admitted_inferences)
                .collect::<Vec<_>>(),
            vec![3, 0, 0]
        );
        assert_eq!(rows[1].budget_skipped_bursts, 4);
        assert_eq!(rows[2].budget_skipped_bursts, 4);
    }

    #[test]
    fn native_per_attempt_limit_never_splits_a_burst_or_hides_skipped_work() {
        let mut rows = rows(&[100, 100]);
        admit_round_robin(
            &mut rows,
            RtspCampaignSentinelConfig {
                every_frames: 3,
                burst_frames: 3,
                max_inferences: 1024,
            },
        );
        for row in rows {
            assert_eq!(row.admitted_inferences, 63);
            assert_eq!(row.admitted_bursts, 21);
            assert_eq!(row.budget_skipped_bursts, 79);
        }
    }
}
