#![forbid(unsafe_code)]
//! Owned native inter-coded input. Coding read-ahead is distinct from admitted display work.

use super::*;

/// Exact native stream progress. A consumed access unit need not have yielded its picture yet.
/// Skipped RASL access units are explicit omissions, never fabricated observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwellVideoProgress {
    /// Native codec, selected by the immutable retained source format.
    pub codec: &'static str,
    /// Coding access units already consumed, including native read-ahead and skipped RASL.
    pub source_segments_consumed: usize,
    /// Display-order pictures actually admitted to the temporal/health owners.
    pub display_frames_processed: usize,
    /// Original coding coordinates of leading RASL inputs skipped by the HEVC owner.
    pub skipped_rasl_segments: Vec<usize>,
    /// Native EOF, delayed output and complete access-unit accounting have all been checked.
    pub decoder_drained: bool,
}

impl DwellVideoProgress {
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.bool(self.decoder_drained);
        e.u64(self.skipped_rasl_segments.len() as u64);
        for segment in &self.skipped_rasl_segments {
            e.u64(*segment as u64);
        }
    }

    pub(super) fn decode(
        d: &mut CanonicalDecoder<'_>,
        format: &str,
        plan: &WatchPlan,
        work: DwellWork,
    ) -> Result<Self> {
        let decoder_drained = d.bool()?;
        let count = count(d, plan.segment_count)?;
        let mut skipped_rasl_segments = Vec::new();
        skipped_rasl_segments
            .try_reserve_exact(count)
            .map_err(|_| WatchError::Limit)?;
        let consumed_end = plan
            .first_segment
            .checked_add(work.source_positions)
            .ok_or(WatchError::Limit)?;
        for _ in 0..count {
            let segment = usize::try_from(d.u64()?).map_err(|_| WatchError::Limit)?;
            if segment < plan.first_segment
                || segment >= consumed_end
                || skipped_rasl_segments
                    .last()
                    .is_some_and(|last| *last >= segment)
            {
                return Err(WatchError::Conflict);
            }
            skipped_rasl_segments.push(segment);
        }
        let codec = codec(format)?;
        let accounted = work
            .frames_decoded
            .checked_add(count)
            .ok_or(WatchError::Limit)?;
        if work.frames_decoded == 0
            || accounted > work.source_positions
            || (codec == "h264" && count != 0)
            || (decoder_drained
                && (work.source_positions != plan.segment_count || accounted != plan.segment_count))
            || (!decoder_drained && accounted == plan.segment_count)
        {
            return Err(WatchError::Conflict);
        }
        Ok(Self {
            codec,
            source_segments_consumed: work.source_positions,
            display_frames_processed: work.frames_decoded,
            skipped_rasl_segments,
            decoder_drained,
        })
    }

    /// Complete bounded accounting, without claiming that consumed inputs were all observed.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"codec\":\"{}\",\"source_segments_consumed\":{},\"display_frames_processed\":{},\"skipped_rasl_segments\":[{}],\"decoder_drained\":{},\"step_unit\":\"display_frames\",\"coding_read_ahead_is_observation\":false}}",
            self.codec,
            self.source_segments_consumed,
            self.display_frames_processed,
            self.skipped_rasl_segments
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.decoder_drained,
        )
    }
}

pub(super) fn codec(format: &str) -> Result<&'static str> {
    match format {
        "annexb" | "mp4avc" | "mkvavc" => Ok("h264"),
        "hevc" | "mp4hevc" | "mkvhevc" => Ok("h265"),
        _ => Err(WatchError::InvalidPlan(
            "unsupported incremental video format",
        )),
    }
}

pub(super) fn identity(format: &str) -> Result<ContentDigest> {
    match codec(format)? {
        "h264" => Ok(super::super::super::recorded_decode::h264::h264_decoder_identity()),
        "h265" => Ok(super::super::super::recorded_decode::h265::h265_decoder_identity()),
        _ => Err(WatchError::Conflict),
    }
}

enum Decoder {
    Avc(Box<RecordedH264Range>),
    Hevc(Box<RecordedH265Range>),
}

pub(super) struct NativeVideo {
    decoder: Decoder,
    source_budget: SourceReadBudget,
    first: usize,
    count: usize,
    drained: bool,
}

impl NativeVideo {
    pub(super) fn open(
        prepared: &PreparedIncrementalDwell,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        let plan = &prepared.plan;
        let limits = prepared.limits.decode;
        let source_budget = SourceReadBudget::new(prepared.limits.maximum_source_chunk_bytes);
        let decoder = match codec(&prepared.source.retained.manifest().format)? {
            "h264" => Decoder::Avc(Box::new(RecordedH264Range::open_stream_with_source_budget(
                deployment,
                RecordedH264Request {
                    import_identity: plan.import_identity,
                    first_segment: plan.first_segment,
                    segment_count: plan.segment_count,
                    interpretation: plan.interpretation,
                    read_limits: limits.read_limits,
                    decoder_limits: limits.h264_limits,
                },
                &source_budget,
                cx,
            )?)),
            "h265" => Decoder::Hevc(Box::new(RecordedH265Range::open_stream_with_source_budget(
                deployment,
                RecordedH265Request {
                    import_identity: plan.import_identity,
                    first_segment: plan.first_segment,
                    segment_count: plan.segment_count,
                    interpretation: plan.interpretation,
                    read_limits: limits.read_limits,
                    decoder_limits: limits.h265_limits,
                },
                &source_budget,
                cx,
            )?)),
            _ => return Err(WatchError::Conflict),
        };
        Ok(Self {
            decoder,
            source_budget,
            first: plan.first_segment,
            count: plan.segment_count,
            drained: false,
        })
    }

    pub(super) fn bytes_read(&self) -> u64 {
        self.source_budget.used()
    }
    pub(super) fn drained(&self) -> bool {
        self.drained
    }
    pub(super) fn consumed(&self) -> usize {
        (match &self.decoder {
            Decoder::Avc(range) => range.next_source_segment(),
            Decoder::Hevc(range) => range.next_source_segment(),
        }) - self.first
    }
    fn accounted(&self) -> usize {
        match &self.decoder {
            Decoder::Avc(range) => range.decoded() as usize,
            Decoder::Hevc(range) => range.decoded() as usize + range.skipped_rasl_segments().len(),
        }
    }

    pub(super) fn progress(&self) -> DwellVideoProgress {
        let (codec, next, decoded, skipped) = match &self.decoder {
            Decoder::Avc(range) => (
                "h264",
                range.next_source_segment(),
                range.decoded(),
                Vec::new(),
            ),
            Decoder::Hevc(range) => (
                "h265",
                range.next_source_segment(),
                range.decoded(),
                range.skipped_rasl_segments().to_vec(),
            ),
        };
        DwellVideoProgress {
            codec,
            source_segments_consumed: next - self.first,
            display_frames_processed: decoded as usize,
            skipped_rasl_segments: skipped,
            decoder_drained: self.drained,
        }
    }

    pub(super) fn next(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Option<TolerantFrame>> {
        let frame = match &mut self.decoder {
            Decoder::Avc(range) => range.next_frame(deployment, cx)?.map(|f| TolerantFrame {
                segment: f.segment_index() as usize,
                capsule: f.capsule().clone(),
                capsule_digest: f.capsule_digest(),
                dimensions: f.dimensions(),
                pixels: f.pixels().to_vec(),
            }),
            Decoder::Hevc(range) => range.next_frame(deployment, cx)?.map(|f| TolerantFrame {
                segment: f.segment_index() as usize,
                capsule: f.capsule().clone(),
                capsule_digest: f.capsule_digest(),
                dimensions: f.dimensions(),
                pixels: f.pixels().to_vec(),
            }),
        };
        if frame.is_none() {
            if self.consumed() != self.count || self.accounted() != self.count {
                return Err(WatchError::Conflict);
            }
            self.drained = true;
        }
        Ok(frame)
    }

    /// When every source unit already has an observed output or explicit skip, demand native
    /// EOF now. Never consume another hidden observation merely to guess whether a step ended.
    pub(super) fn finish_if_accounted(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<()> {
        if !self.drained && self.consumed() == self.count && self.accounted() == self.count {
            self.require_drain(deployment, cx)?;
        }
        Ok(())
    }

    /// Reproduce a saved terminal drain, including any final explicit skips. A surprise
    /// output refuses reconstruction; it is never silently admitted as another observation.
    pub(super) fn require_drain(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<()> {
        if !self.drained && self.next(deployment, cx)?.is_some() {
            return Err(WatchError::Conflict);
        }
        Ok(())
    }
}
