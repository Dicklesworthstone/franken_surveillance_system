#![forbid(unsafe_code)]
//! Native JPEG -> independent health -> learned HOG -> tracks -> zone events.
//! Each committed upstream stage stays owned until its consumer completes. A
//! budget refusal resumes only the unfinished stage, never re-ingests an exposure.

use super::{HogZoneError, HogZonePipeline};
use crate::hog::{HogError, HogModel};
use crate::hog_scan::{HogScan, MAX_SCAN_LEVELS, ScanLevel, ScanPolicy, scan_hog};
use crate::image_tracking::ImageTrackingReport;
use crate::image_zones::pipeline::{ImageZonePipeline, ZonePipelineProgress};
use crate::image_zones::{ImageZoneError, ImageZoneReport};
use crate::mjpeg::JpegBackground;
use crate::rectification::RectificationPlan;
use crate::screened_mjpeg::{JpegScreeningError, JpegScreeningQuery, ScreenedJpeg, screen_jpeg};
use crate::screening::{ScreeningError, ScreeningMonitor, ScreeningPolicy, StallObservation};
use fss_codec_mjpeg::DecodeBudget;
use fss_geometry::WorkBudget;

/// Explicit immutable episode settings; model admission and source authority remain external.
#[derive(Clone, Copy)]
pub struct JpegHogConfig<'a> {
    /// Original stream generation shared by health and screened learned tracking.
    pub stream_generation: u64,
    /// Owner-supplied start on the receive clock, not a wall-clock read.
    pub started_at_ns: u64,
    /// Independent source/health/sentinel policy; no model margin can clear it.
    pub screening: ScreeningPolicy,
    /// Complete explicit scale schedule. Copied into this owner, never changed online.
    pub levels: &'a [ScanLevel],
    /// Frozen native scan policy, validated by the scanner before any result.
    pub scan: ScanPolicy,
}
/// The only outer errors: no new source has been accepted by the health monitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegHogError {
    /// A previously accepted image still has unfinished downstream work.
    PendingAnalysis,
    /// No accepted source exists to resume.
    NoObservation,
    /// Invalid or unallocatable bounded scale schedule, or initialization work refused.
    Configuration(HogError),
    /// Independent monitor initialization or watchdog check failed.
    Screening(ScreeningError),
    /// Native decode, rectification or health refused before advancing the source.
    Image(JpegScreeningError),
    /// The supplied trajectory/zone owner was not a valid fresh episode.
    Zones(HogZoneError),
}
impl std::fmt::Display for JpegHogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PendingAnalysis => "resume the accepted JPEG before the next exposure",
            Self::NoObservation => "no JPEG observation is available to resume",
            Self::Configuration(_) => "JPEG learned-analysis configuration refused",
            Self::Screening(_) => "JPEG health monitor refused",
            Self::Image(_) => "JPEG source or health refused before acceptance",
            Self::Zones(_) => "JPEG trajectory/zone episode refused",
        })
    }
}
impl std::error::Error for JpegHogError {}
/// Which computation has not completed for the owned source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegHogStage {
    /// No source has yet passed native decoding and independent screening.
    AwaitingImage,
    /// The actual screened image is owned; learned scanning has not completed.
    Inference,
    /// The complete learned scan is owned; tracking has not consumed it yet.
    Tracking,
    /// Tracking consumed this exposure; only the existing zone stage can resume.
    Zones,
    /// All requested computation completed; no durable publication is implied.
    Complete,
}
/// An accepted image remains available alongside every downstream refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegHogRefusal {
    /// Native model inference did not complete. Its image can be reused exactly.
    Inference(HogError),
    /// Screened tracking refused without consuming the scan.
    Tracking(HogZoneError),
    /// Tracking succeeded but the existing zone monitor did not finish.
    Zones(ImageZoneError),
    /// The existing zone-resume owner refused; the accepted track remains retained.
    Resume(HogZoneError),
}
/// Exact roots of completed COMPUTATIONS; hashes alone are not retained custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegHogCompletion {
    /// Actual native JPEG, rectification, foreground stage and independent health result.
    pub image: [u8; 32],
    /// Complete learned scan including masked, negative and suppressed windows.
    pub scan: [u8; 32],
    /// Exact existing anonymous trajectory update.
    pub tracking: [u8; 32],
    /// Exact existing zone occupancy/transition/sampled-dwell projection.
    pub zones: [u8; 32],
}
/// Both variants mean native decoding/screening already accepted this image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegHogProgress {
    /// Current image and all downstream computations completed.
    Complete(JpegHogCompletion),
    /// Keep this owner and call resume with a new allowance; do not re-ingest.
    Pending {
        /// Exact accepted image still owned by the pipeline.
        image: [u8; 32],
        /// Only this stage and its successors remain to run.
        stage: JpegHogStage,
        /// Typed refusal, distinct from successful empty/negative output.
        error: JpegHogRefusal,
    },
}

/// Exclusive in-process owner of actual image evidence and all unfinished computation.
/// This is not a daemon, a disk checkpoint, sensor authority or an effect coordinator.
pub struct JpegHogPipeline {
    monitor: ScreeningMonitor,
    zones: HogZonePipeline,
    model: HogModel,
    levels: Vec<ScanLevel>,
    policy: ScanPolicy,
    image: Option<ScreenedJpeg>,
    scan: Option<HogScan>,
    stage: JpegHogStage,
    completed: Option<JpegHogCompletion>,
}
impl JpegHogPipeline {
    /// Take a fresh existing zone pipeline and a verified local model. Scale/scanner
    /// semantics remain owned by scan_hog; invalid settings cannot consume tracking.
    pub fn new(
        zones: ImageZonePipeline,
        model: HogModel,
        config: JpegHogConfig<'_>,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, JpegHogError> {
        budget
            .charge(1)
            .map_err(HogError::from)
            .map_err(JpegHogError::Configuration)?;
        if !(1..=MAX_SCAN_LEVELS).contains(&config.levels.len()) {
            return Err(JpegHogError::Configuration(HogError::Limit));
        }
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(config.levels.len())
            .map_err(|_| JpegHogError::Configuration(HogError::Limit))?;
        levels.extend_from_slice(config.levels);
        let monitor = ScreeningMonitor::new(
            config.screening,
            config.stream_generation,
            config.started_at_ns,
        )
        .map_err(JpegHogError::Screening)?;
        let zones = HogZonePipeline::new(zones, config.stream_generation, budget)
            .map_err(JpegHogError::Zones)?;
        Ok(Self {
            monitor,
            zones,
            model,
            levels,
            policy: config.scan,
            image: None,
            scan: None,
            stage: JpegHogStage::AwaitingImage,
            completed: None,
        })
    }
    /// Current exact stage, including an accepted but incomplete source.
    pub fn stage(&self) -> JpegHogStage {
        self.stage
    }
    /// Actual current JPEG/rectification/health evidence, including while inference fails.
    pub fn image(&self) -> Option<&ScreenedJpeg> {
        self.image.as_ref()
    }
    /// Complete scan for the current image only; never the preceding image's result.
    pub fn scan(&self) -> Option<&HogScan> {
        self.scan.as_ref()
    }
    /// Exact immutable model, for checking weight and provenance identities.
    pub fn model(&self) -> &HogModel {
        &self.model
    }
    /// Existing current tracking receipt only after THIS source was consumed.
    pub fn tracking_report(&self) -> Option<&ImageTrackingReport> {
        if matches!(self.stage, JpegHogStage::Zones | JpegHogStage::Complete) {
            self.zones.pipeline().tracking_report()
        } else {
            None
        }
    }
    /// Current complete zone result only; pending work never exposes a stale predecessor.
    pub fn zone_report(&self) -> Option<&ImageZoneReport> {
        if self.stage == JpegHogStage::Complete {
            self.zones.pipeline().zone_report()
        } else {
            None
        }
    }
    /// Read-only history/trajectory owner; its latest track may predate a pending image.
    pub fn zones(&self) -> &HogZonePipeline {
        &self.zones
    }
    /// Health watchdog remains usable during model/zone pressure. This records only
    /// source-input silence on an owner-supplied clock; it invents no image or absence.
    pub fn poll(&mut self, now_ns: u64) -> Result<StallObservation, JpegHogError> {
        self.monitor.poll(now_ns).map_err(JpegHogError::Screening)
    }

    /// Accept one original complete JPEG. Every budget is separate, and should share
    /// the owner's cancellation flag. Native input failure does not replace prior state.
    /// Once screening succeeds, downstream refusal is Pending, never a source-retry error.
    /// The requested learned scan runs even when the foreground comparison finds no change.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        background: Option<&JpegBackground>,
        plan: &RectificationPlan,
        mut query: JpegScreeningQuery<'_>,
        decode: &mut DecodeBudget<'_>,
        rectification: &mut WorkBudget<'_>,
        foreground: &mut WorkBudget<'_>,
        health: &mut WorkBudget<'_>,
        inference: &mut WorkBudget<'_>,
        downstream: &mut WorkBudget<'_>,
    ) -> Result<JpegHogProgress, JpegHogError> {
        if !matches!(
            self.stage,
            JpegHogStage::AwaitingImage | JpegHogStage::Complete
        ) {
            return Err(JpegHogError::PendingAnalysis);
        }
        query.stamp.owner_requests_analysis |= self.zones.requires_analysis();
        let image = screen_jpeg(
            &mut self.monitor,
            background,
            plan,
            query,
            decode,
            rectification,
            foreground,
            health,
        )
        .map_err(JpegHogError::Image)?;
        // Screening owns the first commit. All following errors retain the accepted image.
        self.image = Some(image);
        self.scan = None;
        self.completed = None;
        self.stage = JpegHogStage::Inference;
        self.resume(inference, downstream)
    }
    /// Resume only the unfinished stage. Complete retries return the same roots with
    /// no new work, source consumption, health ACK or trajectory aging.
    pub fn resume(
        &mut self,
        inference: &mut WorkBudget<'_>,
        downstream: &mut WorkBudget<'_>,
    ) -> Result<JpegHogProgress, JpegHogError> {
        if let Some(completed) = self.completed {
            return Ok(JpegHogProgress::Complete(completed));
        }
        let image = self.image.as_ref().ok_or(JpegHogError::NoObservation)?;
        if self.stage == JpegHogStage::Inference {
            let frame = image.image().frame();
            match scan_hog(
                image.screening().source(),
                frame.pixels(),
                frame.allowed(),
                &self.model,
                &self.levels,
                self.policy,
                inference,
            ) {
                Err(error) => {
                    return Ok(JpegHogProgress::Pending {
                        image: image.digest(),
                        stage: self.stage,
                        error: JpegHogRefusal::Inference(error),
                    });
                }
                Ok(scan) => {
                    self.scan = Some(scan);
                    self.stage = JpegHogStage::Tracking;
                }
            }
        }
        let scan = self.scan.as_ref().ok_or(JpegHogError::NoObservation)?;
        let progress = if self.stage == JpegHogStage::Tracking {
            match self.zones.observe(scan, image.screening(), downstream) {
                Ok(progress) => progress,
                Err(error) => {
                    return Ok(JpegHogProgress::Pending {
                        image: image.digest(),
                        stage: self.stage,
                        error: JpegHogRefusal::Tracking(error),
                    });
                }
            }
        } else {
            match self.zones.resume(downstream) {
                Ok(progress) => progress,
                Err(error) => {
                    return Ok(JpegHogProgress::Pending {
                        image: image.digest(),
                        stage: self.stage,
                        error: JpegHogRefusal::Resume(error),
                    });
                }
            }
        };
        match progress {
            ZonePipelineProgress::Pending { error, .. } => {
                self.stage = JpegHogStage::Zones;
                Ok(JpegHogProgress::Pending {
                    image: image.digest(),
                    stage: self.stage,
                    error: JpegHogRefusal::Zones(error),
                })
            }
            ZonePipelineProgress::Complete { tracking, zones } => {
                let completed = JpegHogCompletion {
                    image: image.digest(),
                    scan: scan.digest(),
                    tracking,
                    zones,
                };
                self.stage = JpegHogStage::Complete;
                self.completed = Some(completed);
                Ok(JpegHogProgress::Complete(completed))
            }
        }
    }
}

/// Original MJPEG stream ranges preserved through resumable learned analysis.
pub mod stream;
