#![forbid(unsafe_code)]
//! Incremental ownership of the existing conservative IDR/IRAP recovery source.

use super::*;
use crate::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;

/// Additional v5 accounting. A discontinuity is an explicit continuation item, never a
/// decoded picture, and every native recovery probe spends the original decode allowance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DwellVideoRecoveryProgress {
    /// Decoded pictures plus admitted discontinuity records. Cold replay reproduces this prefix.
    pub continuation_items_processed: usize,
    /// Admitted resets of health continuity, background, tracking and dwell state.
    pub discontinuities: usize,
    /// Number of source coordinates in the complete, disjoint refusal inventory below.
    pub refused_segments: usize,
    /// Exact coding coordinates and registered causes of missing observations.
    pub decode_refusals: Vec<DecodeRefusal>,
    /// Encoded bytes admitted before native work, including unsuccessful recovery attempts.
    pub decode_encoded_bytes: u64,
    /// Conservative coded-luma capacity admitted before native work, including read-ahead.
    pub decode_coded_luma_capacity: u64,
}

impl DwellVideoRecoveryProgress {
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.u64(self.continuation_items_processed as u64);
        e.u64(self.discontinuities as u64);
        e.u64(self.refused_segments as u64);
        e.u64(self.decode_encoded_bytes);
        e.u64(self.decode_coded_luma_capacity);
        e.u64(self.decode_refusals.len() as u64);
        for run in &self.decode_refusals {
            e.u64(run.first_segment as u64);
            e.u64(run.last_segment as u64);
            e.text(&run.error_id);
        }
    }

    pub(super) fn decode(
        d: &mut CanonicalDecoder<'_>,
        codec: &str,
        plan: &WatchPlan,
        work: DwellWork,
        limits: &LongDwellLimits,
    ) -> Result<Self> {
        let continuation_items_processed = count(d, plan.segment_count * 2)?;
        let discontinuities = count(d, plan.segment_count)?;
        let refused_segments = count(d, plan.segment_count)?;
        let decode_encoded_bytes = d.u64()?;
        let decode_coded_luma_capacity = d.u64()?;
        let runs = count(d, MAX_REFUSAL_RUNS)?;
        let mut decode_refusals: Vec<DecodeRefusal> = Vec::with_capacity(runs);
        let mut refused = 0_usize;
        let consumed_end = plan
            .first_segment
            .checked_add(work.source_positions)
            .ok_or(WatchError::Limit)?;
        for _ in 0..runs {
            let first_segment = usize::try_from(d.u64()?).map_err(|_| WatchError::Limit)?;
            let last_segment = usize::try_from(d.u64()?).map_err(|_| WatchError::Limit)?;
            let error_id = d.text()?;
            let valid_error = matches!(error_id, "ERR-DECODE-001" | "ERR-DECODE-BOUNDS-001")
                || match codec {
                    "h264" => matches!(
                        error_id,
                        "ERR-DECODE-H264-RANGE-NOT-IDR-001"
                            | "ERR-DECODE-H264-RANGE-GAP-001"
                            | "ERR-DECODE-H264-UNSUPPORTED-001"
                    ),
                    "h265" => matches!(
                        error_id,
                        "ERR-DECODE-H265-RANGE-NOT-IRAP-001"
                            | "ERR-DECODE-H265-RANGE-GAP-001"
                            | "ERR-DECODE-H265-UNSUPPORTED-001"
                    ),
                    _ => false,
                };
            if !valid_error
                || first_segment < plan.first_segment
                || last_segment < first_segment
                || last_segment >= consumed_end
                || decode_refusals.last().is_some_and(|last| {
                    last.last_segment >= first_segment
                        || (last.last_segment.checked_add(1) == Some(first_segment)
                            && last.error_id == error_id)
                })
            {
                return Err(WatchError::Conflict);
            }
            refused = refused
                .checked_add(last_segment - first_segment + 1)
                .ok_or(WatchError::Limit)?;
            decode_refusals.push(DecodeRefusal {
                first_segment,
                last_segment,
                error_id: error_id.to_owned(),
            });
        }
        if continuation_items_processed == 0
            || continuation_items_processed
                != work
                    .frames_decoded
                    .checked_add(discontinuities)
                    .ok_or(WatchError::Limit)?
            || refused != refused_segments
            || runs > discontinuities
            || decode_encoded_bytes > limits.maximum_source_chunk_bytes
            || decode_coded_luma_capacity > limits.maximum_pixel_samples
        {
            return Err(WatchError::Conflict);
        }
        Ok(Self {
            continuation_items_processed,
            discontinuities,
            refused_segments,
            decode_refusals,
            decode_encoded_bytes,
            decode_coded_luma_capacity,
        })
    }

    pub(super) fn contains_refusal(&self, segment: usize) -> bool {
        self.decode_refusals
            .iter()
            .any(|run| run.first_segment <= segment && segment <= run.last_segment)
    }

    fn admit(&mut self, item: &TolerantItem, maximum: usize) -> Result<()> {
        self.continuation_items_processed = self
            .continuation_items_processed
            .checked_add(1)
            .ok_or(WatchError::Limit)?;
        if self.continuation_items_processed > maximum * 2 {
            return Err(WatchError::Limit);
        }
        if let TolerantItem::Break(refusal) = item {
            self.discontinuities = self
                .discontinuities
                .checked_add(1)
                .ok_or(WatchError::Limit)?;
            if self.discontinuities > maximum {
                return Err(WatchError::Limit);
            }
            if let Some(run) = refusal {
                self.refused_segments = self
                    .refused_segments
                    .checked_add(run.last_segment - run.first_segment + 1)
                    .ok_or(WatchError::Limit)?;
                if self.refused_segments > maximum {
                    return Err(WatchError::Conflict);
                }
                match self.decode_refusals.last_mut() {
                    Some(last)
                        if last.last_segment.checked_add(1) == Some(run.first_segment)
                            && last.error_id == run.error_id =>
                    {
                        last.last_segment = run.last_segment
                    }
                    _ => {
                        if self.decode_refusals.len() == MAX_REFUSAL_RUNS {
                            return Err(WatchError::Limit);
                        }
                        self.decode_refusals.push(run.clone());
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn to_json(&self) -> String {
        let refusals = self
            .decode_refusals
            .iter()
            .map(|run| {
                format!(
                    "{{\"first_segment\":{},\"last_segment\":{},\"error_id\":\"{}\"}}",
                    run.first_segment, run.last_segment, run.error_id
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"continuation_items_processed\":{},\"discontinuities\":{},",
                "\"refused_segments\":{},\"decode_refusals\":[{}],",
                "\"decode_encoded_bytes\":{},\"decode_coded_luma_capacity\":{}}}"
            ),
            self.continuation_items_processed,
            self.discontinuities,
            self.refused_segments,
            refusals,
            self.decode_encoded_bytes,
            self.decode_coded_luma_capacity
        )
    }
}

pub(super) struct RecoveryVideo {
    source: TolerantSource,
    jpeg_budget: DecodeBudget<'static>,
    codec: &'static str,
    count: usize,
    drained: bool,
    progress: DwellVideoRecoveryProgress,
}

impl RecoveryVideo {
    pub(super) fn open(
        prepared: &PreparedIncrementalDwell,
        deployment: &ReferenceDeployment,
        source_budget: &SourceReadBudget,
        cx: &ReplayCx,
    ) -> Result<Self> {
        let plan = &prepared.plan;
        let limits = &prepared.limits;
        let decode = &limits.decode;
        let budget = RecordedVideoDecodeBudget::with_separate_limits(
            limits.maximum_source_chunk_bytes,
            limits.maximum_pixel_samples,
        )?;
        let mut source = TolerantSource::open_with_budgets(
            deployment,
            TolerantRequest {
                import_identity: plan.import_identity,
                interpretation: plan.interpretation,
                first_segment: plan.first_segment,
                end: plan.first_segment + plan.segment_count,
                read_limits: decode.read_limits,
                jpeg_limits: decode.jpeg_limits,
                h264_limits: decode.h264_limits,
                h265_limits: decode.h265_limits,
                stream: true,
            },
            source_budget,
            budget,
            cx,
        )?;
        source.track_checkpoint_progress();
        Ok(Self {
            source,
            jpeg_budget: DecodeBudget::new(decode.jpeg_work_units),
            codec: codec(&prepared.source.retained.manifest().format)?,
            count: plan.segment_count,
            drained: false,
            progress: DwellVideoRecoveryProgress::default(),
        })
    }

    pub(super) fn drained(&self) -> bool {
        self.drained
    }
    pub(super) fn consumed(&self) -> usize {
        self.source.source_positions()
    }

    pub(super) fn progress(&self) -> DwellVideoProgress {
        let mut recovery = self.progress.clone();
        if let Some(budget) = self.source.video_budget() {
            recovery.decode_encoded_bytes = budget.encoded_bytes();
            recovery.decode_coded_luma_capacity = budget.coded_luma_capacity();
        }
        let skipped = self
            .source
            .skipped_rasl_segments()
            .into_iter()
            .filter(|segment| !recovery.contains_refusal(*segment))
            .collect();
        DwellVideoProgress {
            codec: self.codec,
            source_segments_consumed: self.consumed(),
            display_frames_processed: recovery.continuation_items_processed
                - recovery.discontinuities,
            skipped_rasl_segments: skipped,
            decoder_drained: self.drained,
            recovery: Some(recovery),
        }
    }

    pub(super) fn next(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Option<TolerantItem>> {
        if self.drained {
            return Ok(None);
        }
        let next = self.source.next(deployment, &mut self.jpeg_budget, cx)?;
        if let Some(item) = &next {
            self.progress.admit(item, self.count)?;
        } else {
            let progress = self.progress();
            if progress.display_frames_processed == 0
                || self.consumed() != self.count
                || progress.display_frames_processed
                    + self.progress.refused_segments
                    + progress.skipped_rasl_segments.len()
                    != self.count
            {
                return Err(WatchError::Conflict);
            }
            self.drained = true;
        }
        Ok(next)
    }
}
