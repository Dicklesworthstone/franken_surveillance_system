#![forbid(unsafe_code)]
//! Bounded trained classification after the complete native foreground/tracking walk.
//!
//! Only an entry and its following actual matches are selected. The second colour pass shares
//! the original whole-recording custody and JPEG ceilings; decoder recovery never renews them.

use std::collections::{BTreeMap, BTreeSet};

use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::color::{MAX_RGB_BYTES, RgbDecodeLimits, decode_rgb};
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};

use super::{LongWatchEntry, LongWatchLimits, MAX_LONG_WATCH_CANDIDATES, Result};
use crate::ingest::RetainedFileImport;
use crate::ingest::detector_cascade::{
    CASCADE_FRAME_REFUSED, CascadeConfig, CascadeError, CascadeFrame, CascadeOutcome,
    CascadeSelection, CascadeSource, ClassEvidence, EvidenceOutcome, FrameStatus, SelectionReason,
    cascade_outcome_json,
};
use crate::ingest::detector_cascade_engine::{self as engine, DetectorCascade};
use crate::ingest::long_dwell::reader::ChunkCursor;
use crate::ingest::long_dwell::{ScanData, ScanObservation, ScanObserver};
use crate::ingest::package_detect::{DecodedFrame, FrameRun, PackageDetectLimits};
use crate::ingest::recorded_decode::{RecordedDecodeError, source_capsule};
use crate::ingest::recorded_watch::{WatchError, WatchOptions, WatchPlan};
use crate::ingest::retained::SourceReadBudget;
use crate::ingest::rgb_detections::RgbDetectionBudget;
use crate::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use crate::ingest::tolerant_decode::{TolerantItem, TolerantRequest, TolerantSource};
use crate::ingest::tracker::TrackStatus;
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};

pub mod recipe;
pub use recipe::LongWatchDetectorRecipe;

pub(crate) const OUTCOME_DOMAIN: &str = "fss.long_watch_detector_outcome.v1";
pub(crate) const MAX_OUTCOME_BYTES: usize = 4 * 1024 * 1024;
const MAX_CLASS_BYTES: usize = 16 * 1024;

/// Verified immutable package, its exact portable archive, and explicitly bounded inference policy.
/// Construction opens no source and publishes nothing. The borrowed archive is retained only
/// if an exact candidate is later approved for publication.
///
/// Native custody and colour decode use the `LongWatchLimits::decode` owner supplied to analysis.
/// Package limits supply preprocessing, model execution, output and detection-head budgets;
/// their unused decoder fields remain in the exact retained recipe for caller-policy identity.
pub struct LongWatchDetector<'a> {
    pub(super) package: &'a RgbDetectorPackage,
    pub(super) archive: &'a [u8],
    pub(super) config: CascadeConfig,
    pub(super) limits: PackageDetectLimits,
    pub(super) scalar: &'a ScalarExecCx,
}
impl std::fmt::Debug for LongWatchDetector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LongWatchDetector")
            .field("package", &self.package.archive_digest())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
impl<'a> LongWatchDetector<'a> {
    /// Verify the retained archive binding and admit the existing package/cascade policy.
    pub fn new(
        package: &'a RgbDetectorPackage,
        archive_bytes: &'a [u8],
        config: CascadeConfig,
        limits: PackageDetectLimits,
        scalar: &'a ScalarExecCx,
    ) -> Result<Self> {
        config.validate()?;
        if archive_bytes.len() > MAX_RGB_PACKAGE_BYTES
            || ContentDigest::sha256(archive_bytes) != package.archive_digest()
        {
            return Err(WatchError::InvalidPlan(
                "detector archive differs from verified package",
            ));
        }
        // Reuse the existing threshold, inference, scratch and head-contract admission.
        let _ = DetectorCascade::new(package, config, limits, scalar)?;
        Ok(Self {
            package,
            archive: archive_bytes,
            config,
            limits,
            scalar,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct Selection {
    pub(super) position: usize,
    pub(super) capsule: ContentDigest,
    pub(super) item: CascadeSelection,
}
#[derive(Clone, Debug)]
pub(super) struct SelectedEntry {
    pub(super) entry: LongWatchEntry,
    pub(super) frames: Vec<Selection>,
}

/// Only scalar selection metadata survives a source frame. Candidate and frame counts are hard
/// bounded independently of recording length; no image cache or track history is accumulated.
pub(super) struct Select {
    frames_per_track: usize,
    pub(super) entries: Vec<SelectedEntry>,
    pub(super) decoded: Vec<usize>,
}
impl Select {
    pub(super) fn new(config: CascadeConfig) -> Self {
        Self {
            frames_per_track: config.frames_per_track,
            entries: Vec::new(),
            decoded: Vec::new(),
        }
    }
}
impl ScanObserver for Select {
    fn observe(&mut self, frame: ScanObservation<'_>) -> Result<()> {
        if self.decoded.len() == super::MAX_LONG_WATCH_FRAMES {
            return Err(WatchError::Limit);
        }
        self.decoded.push(frame.segment);
        for entry in frame.zone_entries {
            if self.entries.len() == MAX_LONG_WATCH_CANDIDATES {
                return Err(WatchError::Limit);
            }
            self.entries.push(SelectedEntry {
                entry: entry.clone(),
                frames: vec![Selection {
                    position: frame.position,
                    capsule: frame.capsule_digest,
                    item: CascadeSelection {
                        segment: frame.segment,
                        reason: SelectionReason::ZoneEntry,
                        track_box: entry.filtered_box,
                    },
                }],
            });
        }
        for selected in &mut self.entries {
            if selected.entry.epoch != frame.epoch
                || selected.frames.len() == self.frames_per_track
                || selected
                    .frames
                    .last()
                    .is_some_and(|last| last.position == frame.position)
            {
                continue;
            }
            if let Some(target) = frame.tracks.iter().find(|target| {
                target.id == selected.entry.track
                    && target.status == TrackStatus::Confirmed
                    && target.misses == 0
            }) {
                selected.frames.push(Selection {
                    position: frame.position,
                    capsule: frame.capsule_digest,
                    item: CascadeSelection {
                        segment: frame.segment,
                        reason: SelectionReason::FollowingMatch,
                        track_box: [target.cx, target.cy, target.box_w, target.box_h]
                            .map(|v| v.round() as i64),
                    },
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct Completed {
    pub(super) recipe: LongWatchDetectorRecipe,
    pub(super) archive: Vec<u8>,
    pub(super) outcome: CascadeOutcome,
    pub(super) entries: Vec<SelectedEntry>,
    pub(super) bytes: Vec<u8>,
    pub(super) source_bytes: u64,
    pub(super) jpeg_work: u64,
    pub(super) pixel_samples: u64,
    pub(super) inference_pipeline_attempts: usize,
    pub(super) policy_json: String,
}
impl Completed {
    pub(super) fn children(&self) -> BTreeSet<ContentDigest> {
        let mut children = BTreeSet::from([
            ContentDigest::sha256(&self.archive),
            self.recipe.digest(),
            ContentDigest::sha256(&self.bytes),
        ]);
        children.extend(
            self.outcome
                .evidence
                .iter()
                .flatten()
                .map(|item| item.digest),
        );
        children
    }
    pub(super) fn staged(&self) -> Vec<&[u8]> {
        let mut bytes = vec![self.archive.as_slice(), self.bytes.as_slice()];
        bytes.extend(
            self.outcome
                .evidence
                .iter()
                .flatten()
                .map(|item| item.record.as_slice()),
        );
        bytes
    }
}

pub(super) fn run(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    options: WatchOptions,
    scan: &ScanData,
    limits: &LongWatchLimits,
    detector: &LongWatchDetector<'_>,
    selected: Select,
    cx: &ReplayCx,
) -> Result<Completed> {
    cx.checkpoint("long_watch_detector:admit")
        .map_err(|_| RecordedDecodeError::Cancelled)?;
    detector
        .scalar
        .checkpoint("long_watch_detector:admit")
        .map_err(|_| CascadeError::Cancelled)?;
    let recipe =
        LongWatchDetectorRecipe::new(detector.package, detector.config, detector.limits, limits)?;
    let engine = DetectorCascade::new(
        detector.package,
        detector.config,
        detector.limits,
        detector.scalar,
    )?;
    // Selection order is deterministic: entry order, then each entry's display-order matches.
    let mut order = Vec::new();
    for entry in &selected.entries {
        for selection in &entry.frames {
            if !order.contains(&selection.item.segment) {
                order.push(selection.item.segment);
            }
        }
    }
    let wanted: BTreeSet<usize> = order
        .iter()
        .take(detector.config.max_inferences)
        .copied()
        .collect();
    let remaining_source = limits
        .maximum_source_chunk_bytes
        .checked_sub(scan.source_bytes)
        .ok_or(WatchError::Limit)?;
    let remaining_jpeg = limits
        .decode
        .jpeg_work_units
        .checked_sub(scan.jpeg_work)
        .ok_or(WatchError::Limit)?;
    let remaining_pixels = limits
        .maximum_pixel_samples
        .checked_sub(scan.pixel_samples)
        .ok_or(WatchError::Limit)?;
    let mut run = FrameRun {
        package: detector.package,
        contract: engine.contract(),
        run: detector.limits.run,
        import_root: scan.import_root,
        budget: RgbDetectionBudget::new(
            detector.limits.detection_work_units,
            detector.limits.detection_scratch_bytes,
        ),
        scalar: detector.scalar,
        cx,
    };
    let mut statuses = BTreeMap::new();
    let mut source_bytes = 0;
    let mut pixel_samples = 0;
    let mut inference_pipeline_attempts = 0;
    let mut jpeg = DecodeBudget::new(remaining_jpeg);
    if !wanted.is_empty() {
        if scan.media_format == "mjpeg" {
            let retained = RetainedFileImport::open(
                deployment,
                plan.import_identity,
                limits.decode.read_limits,
                cx,
            )?;
            let mut source = ChunkCursor::new(remaining_source);
            for &segment in &wanted {
                cx.checkpoint("long_watch_detector:frame")
                    .map_err(|_| RecordedDecodeError::Cancelled)?;
                let (capsule, capsule_digest) = source_capsule(deployment, &retained, segment)?;
                if capsule.sensor_id != scan.sensor {
                    return Err(WatchError::Conflict);
                }
                let bytes = source.segment(
                    deployment,
                    &retained,
                    segment,
                    limits.decode.read_limits,
                    cx,
                )?;
                let rgb = decode_rgb(
                    &bytes,
                    capsule.source_digest.bytes(),
                    plan.interpretation,
                    RgbDecodeLimits {
                        frame: limits.decode.jpeg_limits,
                        maximum_output_bytes: MAX_RGB_BYTES,
                    },
                    &mut jpeg,
                );
                let status = match rgb {
                    Ok(rgb) => {
                        charge_pixels(&mut pixel_samples, rgb.dimensions(), remaining_pixels)?;
                        match DecodedFrame::jpeg(
                            segment,
                            capsule,
                            capsule_digest,
                            rgb,
                            scan.privacy.clone(),
                        ) {
                            Ok(frame) => {
                                inference_pipeline_attempts += 1;
                                engine::infer_one(
                                    &mut run,
                                    frame,
                                    &engine.contract().spec().labels,
                                )?
                                .1
                            }
                            Err(_) => FrameStatus::Refused(CASCADE_FRAME_REFUSED),
                        }
                    }
                    // A second decoder cannot turn budget exhaustion into a publishable partial analysis.
                    Err(error)
                        if matches!(
                            error,
                            fss_codec_mjpeg::DecodeError::BudgetExhausted
                                | fss_codec_mjpeg::DecodeError::Cancelled
                        ) =>
                    {
                        return Err(RecordedDecodeError::from(error).into());
                    }
                    Err(_) => FrameStatus::Refused(CASCADE_FRAME_REFUSED),
                };
                statuses.insert(segment, status);
            }
            source_bytes = source.bytes_read();
        } else {
            let budget = SourceReadBudget::new(remaining_source);
            let request = TolerantRequest {
                import_identity: plan.import_identity,
                interpretation: plan.interpretation,
                first_segment: plan.first_segment,
                end: plan.first_segment + plan.segment_count,
                read_limits: limits.decode.read_limits,
                jpeg_limits: limits.decode.jpeg_limits,
                h264_limits: limits.decode.h264_limits,
                h265_limits: limits.decode.h265_limits,
                stream: true,
            };
            let mut source =
                TolerantSource::open_with_source_budget(deployment, request, &budget, cx)?;
            source.select_rgb(&wanted)?;
            while let Some(item) = source.next(deployment, &mut jpeg, cx)? {
                cx.checkpoint("long_watch_detector:video")
                    .map_err(|_| RecordedDecodeError::Cancelled)?;
                match item {
                    TolerantItem::Break(_) if !options.tolerate_decode_refusals => {
                        return Err(WatchError::Conflict);
                    }
                    TolerantItem::Frame(frame) => {
                        charge_pixels(&mut pixel_samples, frame.dimensions, remaining_pixels)?;
                        if let Some(color) = source.take_rgb() {
                            if frame.segment != color.segment
                                || frame.capsule.sensor_id != scan.sensor
                                || statuses.contains_key(&color.segment)
                            {
                                return Err(WatchError::Conflict);
                            }
                            let status = match color.frame {
                                Ok(decoded) => {
                                    inference_pipeline_attempts += 1;
                                    engine::infer_one(
                                        &mut run,
                                        decoded,
                                        &engine.contract().spec().labels,
                                    )?
                                    .1
                                }
                                Err(_) => FrameStatus::Refused(CASCADE_FRAME_REFUSED),
                            };
                            statuses.insert(color.segment, status);
                        }
                    }
                    TolerantItem::Break(_) => {}
                }
                if statuses.len() == wanted.len() {
                    break;
                }
            }
            source_bytes = budget.used();
        }
    }
    if statuses.len() != wanted.len() {
        return Err(WatchError::Conflict);
    }
    detector
        .scalar
        .checkpoint("long_watch_detector:complete")
        .map_err(|_| CascadeError::Cancelled)?;
    let mut frames = Vec::new();
    for segment in order {
        frames.push(CascadeFrame {
            segment,
            status: statuses
                .remove(&segment)
                .unwrap_or(FrameStatus::BudgetExhausted),
        });
    }
    let source = CascadeSource {
        import_identity: plan.import_identity,
        import_root: scan.import_root,
        interpretation: plan.interpretation,
        media_format: &scan.media_format,
        first_segment: plan.first_segment,
        decoded_segments: &selected.decoded,
    };
    let mut evidence = Vec::new();
    for entry in &selected.entries {
        let mut records = Vec::new();
        for selected_frame in &entry.frames {
            let status = &frames
                .iter()
                .find(|frame| frame.segment == selected_frame.item.segment)
                .ok_or(WatchError::Conflict)?
                .status;
            let outcome = match status {
                FrameStatus::Inferred(frame) => engine::associate(
                    frame,
                    &selected_frame.item,
                    detector.config.minimum_association_iou_ppm,
                ),
                FrameStatus::Refused(id) => EvidenceOutcome::Refused(id),
                FrameStatus::BudgetExhausted => EvidenceOutcome::BudgetExhausted,
            };
            let record = engine.record(
                &source,
                entry.entry.track,
                &selected_frame.item,
                status,
                &outcome,
            );
            if record.len() > MAX_CLASS_BYTES {
                return Err(WatchError::Limit);
            }
            records.push(ClassEvidence {
                segment: selected_frame.item.segment,
                reason: selected_frame.item.reason,
                digest: ContentDigest::sha256(&record),
                record,
                outcome,
            });
        }
        evidence.push(records);
    }
    let selected_segments: BTreeSet<_> = frames.iter().map(|frame| frame.segment).collect();
    let outcome = CascadeOutcome {
        import_identity: plan.import_identity,
        frames,
        evidence,
        cascade_skipped: selected
            .decoded
            .into_iter()
            .filter(|segment| !selected_segments.contains(segment))
            .collect(),
    };
    let jpeg_work = remaining_jpeg
        .checked_sub(jpeg.remaining())
        .ok_or(WatchError::Limit)?;
    let mut e = CanonicalEncoder::new();
    e.text(OUTCOME_DOMAIN);
    e.digest(recipe.digest());
    e.digest(plan.import_identity);
    e.digest(outcome.digest(engine.digest()));
    e.u64(source_bytes);
    e.u64(jpeg_work);
    e.u64(pixel_samples);
    e.u64(inference_pipeline_attempts as u64);
    e.u64(outcome.inferred_segments().len() as u64);
    e.bytes(format!("{{{}}}", cascade_outcome_json(&outcome)).as_bytes());
    e.u64(selected.entries.len() as u64);
    for (entry, records) in selected.entries.iter().zip(&outcome.evidence) {
        e.u64(entry.entry.epoch);
        e.u64(entry.entry.track);
        e.u64(entry.entry.zone as u64);
        e.u64(entry.entry.position as u64);
        e.u64(records.len() as u64);
        for (frame, record) in entry.frames.iter().zip(records) {
            e.u64(frame.position as u64);
            e.u64(record.segment as u64);
            e.digest(frame.capsule);
            e.bool(record.supports());
            e.digest(record.digest);
            e.bytes(&record.record);
        }
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_OUTCOME_BYTES {
        return Err(WatchError::Limit);
    }
    let policy_json = engine::cascade_policy_json(&engine)
        .replace(
            "zone_entry_then_confirmation_then_following_matches",
            "whole_recording_entry_then_following_actual_matches",
        )
        .replace("\"cascade_digest\":", "\"association_engine_identity\":")
        .replace(
            "\"policy_digest\":",
            "\"association_engine_policy_digest\":",
        );
    Ok(Completed {
        recipe,
        archive: detector.archive.to_vec(),
        outcome,
        entries: selected.entries,
        bytes,
        source_bytes,
        jpeg_work,
        pixel_samples,
        inference_pipeline_attempts,
        policy_json,
    })
}

fn charge_pixels(total: &mut u64, dimensions: [u32; 2], maximum: u64) -> Result<()> {
    *total = total
        .checked_add(u64::from(dimensions[0]) * u64::from(dimensions[1]))
        .filter(|sum| *sum <= maximum)
        .ok_or(WatchError::Limit)?;
    Ok(())
}

/// One class record and its exact native source/track association, recovered without inference.
#[derive(Clone, Debug)]
pub(crate) struct RetainedClass {
    pub(crate) epoch: u64,
    pub(crate) track: u64,
    pub(crate) zone: usize,
    pub(crate) entry_position: usize,
    pub(crate) position: usize,
    pub(crate) segment: usize,
    pub(crate) capsule: ContentDigest,
    pub(crate) supports: bool,
    pub(crate) digest: ContentDigest,
}
/// Bounded closure metadata. Opaque output tensors and scores are certified only by native replay.
#[derive(Clone, Debug)]
pub(crate) struct RetainedInventory {
    pub(crate) recipe: ContentDigest,
    pub(crate) import_identity: ContentDigest,
    pub(crate) classes: Vec<RetainedClass>,
}
/// Parse only canonical closure identities; this does not claim the retained inference ran.
pub(crate) fn retained_inventory(bytes: &[u8]) -> Result<RetainedInventory> {
    if bytes.len() > MAX_OUTCOME_BYTES {
        return Err(WatchError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != OUTCOME_DOMAIN {
        return Err(WatchError::Conflict);
    }
    let recipe = d.digest()?;
    let import_identity = d.digest()?;
    let _outcome = d.digest()?;
    let _source = d.u64()?;
    let _jpeg = d.u64()?;
    let _pixels = d.u64()?;
    let attempts = d.u64()?;
    let completed = d.u64()?;
    if attempts > 64 || completed > attempts {
        return Err(WatchError::Limit);
    }
    if d.bytes()?.len() > MAX_OUTCOME_BYTES {
        return Err(WatchError::Limit);
    }
    let entries = d.u64()?;
    if entries > MAX_LONG_WATCH_CANDIDATES as u64 {
        return Err(WatchError::Limit);
    }
    let mut classes = Vec::new();
    let position = |n: u64| usize::try_from(n).map_err(|_| WatchError::Limit);
    for _ in 0..entries {
        let epoch = d.u64()?;
        let track = d.u64()?;
        let zone = position(d.u64()?)?;
        let entry_position = position(d.u64()?)?;
        let count = d.u64()?;
        if !(1..=8).contains(&count) || zone >= 16 {
            return Err(WatchError::Limit);
        }
        for _ in 0..count {
            let at = position(d.u64()?)?;
            let segment = position(d.u64()?)?;
            let capsule = d.digest()?;
            let supports = d.bool()?;
            let digest = d.digest()?;
            let record = d.bytes()?;
            if record.len() > MAX_CLASS_BYTES
                || ContentDigest::sha256(record) != digest
                || at < entry_position
            {
                return Err(WatchError::Conflict);
            }
            classes.push(RetainedClass {
                epoch,
                track,
                zone,
                entry_position,
                position: at,
                segment,
                capsule,
                supports,
                digest,
            });
        }
    }
    d.ensure_finished()?;
    Ok(RetainedInventory {
        recipe,
        import_identity,
        classes,
    })
}
