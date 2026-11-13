#![forbid(unsafe_code)]
//! Whole observed lane sequences, without changing the original QSR report codec or policy.

use fss_core::ContentDigest;

use super::{QsrError, QsrLaneInterruptionReason, Result};
use crate::ingest::package_zones::PackageZoneFrame;

mod wire;

/// Independently identified companion to the unchanged sampled-observation report.
pub const QSR_LANE_TRAVERSAL_SCHEMA: &str = "fss.qsr_lane_traversal_report.v1";
/// At most one nonempty sequence per track/frame under the 8192-cell, two-stage source bound.
pub const MAX_QSR_LANE_TRAVERSALS: usize = 4096;
/// Exact finite reducer policy; completion concerns sampled stage order, never a physical trip.
pub const QSR_LANE_TRAVERSAL_POLICY: &str = "fss.qsr_lane_traversal_policy.v1:shared-admitted-lane-samples;first-through-last-adjacent-stages;direct-endpoint-intervals;partial-suffixes;report-end-censoring;no-physical-trip-or-wait-claim";

/// Whether all declared stages were observed within this one uninterrupted sampled sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsrLaneTraversalStatus {
    /// Every stage, from index zero through the last, was observed in adjacent order.
    Completed,
    /// The finite sample ended, or the last stage was reached without observing initial stages.
    Incomplete,
    /// A source, observability or ordering barrier stopped this sequence.
    Interrupted,
}
impl QsrLaneTraversalStatus {
    /// Stable machine spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Incomplete => "incomplete",
            Self::Interrupted => "interrupted",
        }
    }
}

/// The finite observation that closed a sequence; this does not assert a physical exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsrLaneTraversalTermination {
    /// First admitted sample inside the last declared stage.
    LastStageObserved,
    /// The exact retained source sample ended while a sequence was still open.
    SourceSampleEnded,
    /// Existing lane-owner interruption, with its original typed uncertainty reason.
    Interrupted(QsrLaneInterruptionReason),
}
impl QsrLaneTraversalTermination {
    /// Stable machine spelling; interruption reasons retain their original vocabulary.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LastStageObserved => "last_stage_observed",
            Self::SourceSampleEnded => "source_sample_ended",
            Self::Interrupted(reason) => reason.as_str(),
        }
    }
}

/// First admitted inside observation of one stage in a sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrLaneStageObservation {
    /// Index in the exact explicitly ordered lane-stage configuration.
    pub stage: usize,
    /// Frame index in the unchanged source QSR report.
    pub frame: usize,
}

/// Complete record of one finite observed sequence, including interrupted and censored runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrLaneTraversal {
    /// Anonymous analysis-local track; never a cross-report physical identity.
    pub track: ContentDigest,
    /// Sampled stage-order completion, incompleteness or interruption.
    pub status: QsrLaneTraversalStatus,
    /// Every observed stage's first inside frame, in adjacent declared order.
    pub stages: Vec<QsrLaneStageObservation>,
    /// First admitted stage sample of this sequence.
    pub from_frame: usize,
    /// Last admitted actual assignment before termination; includes observed corridor samples.
    pub last_observed_frame: usize,
    /// Frame that completed, interrupted or censored the sequence.
    pub at_frame: usize,
    /// Why this bounded sequence ended.
    pub termination: QsrLaneTraversalTermination,
    /// Number of initial declared stages not observed in this sequence.
    pub missing_initial_stages: usize,
    /// Number of trailing declared stages not observed in this sequence.
    pub remaining_stages: usize,
    /// Lower separation of the exact first/last observed capture endpoints, in nanoseconds.
    pub minimum_elapsed_ns: u128,
    /// Upper separation of those endpoints; not the sum of adjacent uncertainty intervals.
    pub maximum_elapsed_ns: u128,
}

/// Sealed read companion. Its independent identity binds every row and the original QSR digest.
#[derive(Debug)]
pub struct QsrLaneTraversalReport {
    traversals: Vec<QsrLaneTraversal>,
    bytes: Vec<u8>,
    digest: ContentDigest,
    json: String,
}
impl QsrLaneTraversalReport {
    pub(super) fn build(
        source_qsr: ContentDigest,
        source_zone: ContentDigest,
        provenance_root: ContentDigest,
        sampled_frames: usize,
        maximum_sample_gap_ns: u64,
        lane_stages: &[String],
        traversals: Vec<QsrLaneTraversal>,
    ) -> Result<Self> {
        let bytes = wire::encode(source_qsr, lane_stages, &traversals)?;
        let digest = ContentDigest::sha256(&bytes);
        let json = wire::json(
            digest,
            source_qsr,
            source_zone,
            provenance_root,
            sampled_frames,
            maximum_sample_gap_ns,
            lane_stages,
            &traversals,
        )?;
        Ok(Self {
            traversals,
            bytes,
            digest,
            json,
        })
    }

    /// Every completed, interrupted and incomplete sequence, in track then source-frame order.
    pub fn traversals(&self) -> &[QsrLaneTraversal] {
        &self.traversals
    }
    /// Independent canonical read-result bytes; original QSR v1 bytes remain unchanged.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 of the complete canonical companion, including original QSR identity.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Complete admitted JSON snapshot. This performs no I/O or claim of renewed freshness.
    pub fn to_json(&self) -> &str {
        &self.json
    }
}

struct Active {
    stages: Vec<QsrLaneStageObservation>,
    last_observed_frame: usize,
}

/// Receives exactly the existing reducer's admitted samples and interruption barriers.
pub(super) struct Reducer<'a> {
    track: ContentDigest,
    stage_count: usize,
    frames: &'a [PackageZoneFrame],
    output: &'a mut Vec<QsrLaneTraversal>,
    active: Option<Active>,
    closed_stage: Option<usize>,
}
impl<'a> Reducer<'a> {
    pub(super) fn new(
        track: ContentDigest,
        stage_count: usize,
        frames: &'a [PackageZoneFrame],
        output: &'a mut Vec<QsrLaneTraversal>,
    ) -> Self {
        Self {
            track,
            stage_count,
            frames,
            output,
            active: None,
            closed_stage: None,
        }
    }

    pub(super) fn interrupt(
        &mut self,
        at_frame: usize,
        reason: QsrLaneInterruptionReason,
    ) -> Result<()> {
        self.close(at_frame, QsrLaneTraversalTermination::Interrupted(reason))?;
        self.closed_stage = None;
        Ok(())
    }

    pub(super) fn observe(&mut self, frame: usize, stage: Option<usize>) -> Result<()> {
        if let Some(stage) = stage {
            // Remaining inside the last stage does not create repeated suffix records.
            if self.closed_stage == Some(stage) {
                return Ok(());
            }
            if self.closed_stage.is_some() {
                return Err(QsrError::Mismatch);
            }
            if let Some(active) = &mut self.active {
                let previous = active.stages.last().ok_or(QsrError::Mismatch)?.stage;
                if stage != previous {
                    if stage != previous + 1 {
                        return Err(QsrError::Mismatch);
                    }
                    active.stages.push(QsrLaneStageObservation { stage, frame });
                }
                active.last_observed_frame = frame;
            } else {
                self.active = Some(Active {
                    stages: vec![QsrLaneStageObservation { stage, frame }],
                    last_observed_frame: frame,
                });
            }
            if stage + 1 == self.stage_count {
                self.close(frame, QsrLaneTraversalTermination::LastStageObserved)?;
                self.closed_stage = Some(stage);
            }
        } else if let Some(active) = &mut self.active {
            active.last_observed_frame = frame;
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<()> {
        let end = self.frames.len().checked_sub(1).ok_or(QsrError::Mismatch)?;
        self.close(end, QsrLaneTraversalTermination::SourceSampleEnded)
    }

    fn close(&mut self, at_frame: usize, termination: QsrLaneTraversalTermination) -> Result<()> {
        let Some(active) = self.active.take() else {
            return Ok(());
        };
        let first = active.stages.first().ok_or(QsrError::Mismatch)?;
        let last = active.stages.last().ok_or(QsrError::Mismatch)?;
        let remaining_stages = self
            .stage_count
            .checked_sub(last.stage + 1)
            .ok_or(QsrError::Mismatch)?;
        let earlier = self
            .frames
            .get(first.frame)
            .ok_or(QsrError::Mismatch)?
            .capture;
        let later = self
            .frames
            .get(active.last_observed_frame)
            .ok_or(QsrError::Mismatch)?
            .capture;
        if active.last_observed_frame < first.frame || at_frame < active.last_observed_frame {
            return Err(QsrError::Mismatch);
        }
        let (minimum_elapsed_ns, maximum_elapsed_ns) = if first.frame == active.last_observed_frame
        {
            (0, 0)
        } else {
            if later.earliest < earlier.earliest || later.latest < earlier.latest {
                return Err(QsrError::Mismatch);
            }
            (
                if later.earliest > earlier.latest {
                    later.earliest.0.abs_diff(earlier.latest.0)
                } else {
                    0
                },
                later.latest.0.abs_diff(earlier.earliest.0),
            )
        };
        let status = match termination {
            QsrLaneTraversalTermination::LastStageObserved if first.stage == 0 => {
                QsrLaneTraversalStatus::Completed
            }
            QsrLaneTraversalTermination::Interrupted(_) => QsrLaneTraversalStatus::Interrupted,
            _ => QsrLaneTraversalStatus::Incomplete,
        };
        if self.output.len() >= MAX_QSR_LANE_TRAVERSALS {
            return Err(QsrError::Limit);
        }
        self.output.push(QsrLaneTraversal {
            track: self.track,
            status,
            from_frame: first.frame,
            last_observed_frame: active.last_observed_frame,
            at_frame,
            termination,
            missing_initial_stages: first.stage,
            remaining_stages,
            minimum_elapsed_ns,
            maximum_elapsed_ns,
            stages: active.stages,
        });
        Ok(())
    }
}
