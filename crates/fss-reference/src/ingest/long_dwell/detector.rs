#![forbid(unsafe_code)]
//! Trained classification of actual observations belonging to completed sampled-dwell episodes.
//!
//! Temporal eligibility comes exclusively from the native dwell owner. We select from its bounded
//! scalar trace after the complete scan, so a nonqualifying visit spends no model allowance and a
//! later visit by the same tracker ID cannot lend evidence to an earlier episode.

use fss_core::{CanonicalDecoder, CaptureInterval, TimestampNs};

use super::{FRAME_DOMAIN, Result, ScanData, WatchError};
use crate::ReplayCx;
use crate::ingest::detector_cascade::{CascadeConfig, CascadeSelection, SelectionReason};
use crate::ingest::long_watch::LongWatchEntry;
use crate::ingest::long_watch::detector::{Select, SelectedEntry, Selection};

pub(in crate::ingest) const SELECTION_POLICY: &[u8] =
    b"whole-recording-sampled-dwell-detector-v1:qualifying-episodes-only:\
first-actual-matched-samples-within-episode:epoch-track-zone-bound:\
one-inference-allowance:uncalibrated-class-annotations:no-temporal-or-authority-upgrade";

fn index(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| WatchError::Limit)
}

/// Read only the trace emitted by this invocation's native scanner. No caller-authored trace is
/// accepted here. Native replay reruns the scanner before this selection is made again.
pub(super) fn select(scan: &ScanData, config: CascadeConfig, cx: &ReplayCx) -> Result<Select> {
    let mut selected = Select::new(config);
    let mut episodes: Vec<Option<SelectedEntry>> = vec![None; scan.episodes.len()];
    let mut trace = CanonicalDecoder::new(&scan.trace);
    while trace.remaining() != 0 {
        cx.checkpoint("long_dwell_detector:select")
            .map_err(|_| crate::ingest::recorded_decode::RecordedDecodeError::Cancelled)?;
        let bytes = trace.bytes()?;
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != FRAME_DOMAIN {
            return Err(WatchError::Conflict);
        }
        let inter_coded = scan.media_format != "mjpeg";
        if inter_coded && d.clone().text().ok() == Some("break") {
            continue;
        }
        let position = index(d.u64()?)?;
        let segment = if inter_coded {
            index(d.u64()?)?
        } else {
            position
        };
        let capsule_digest = d.digest()?;
        let capture = CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?;
        let reliable = d.bool()?;
        let _gap = d.bool()?;
        if !d.bool()? {
            continue;
        }
        selected.decoded.push(segment);
        if selected.decoded.len() > super::MAX_LONG_DWELL_FRAMES {
            return Err(WatchError::Limit);
        }
        let epoch = d.u64()?;
        let _dimensions = [d.u32()?, d.u32()?];
        let _luma = d.digest()?;
        let _baseline = d.bool()?;
        let detections = index(d.u64()?)?;
        if detections > super::MAX_TRACKS {
            return Err(WatchError::Limit);
        }
        for _ in 0..detections {
            for _ in 0..4 {
                let _coordinate = d.u64()?;
            }
        }
        let tracks = index(d.u64()?)?;
        if tracks > super::MAX_TRACKS {
            return Err(WatchError::Limit);
        }
        for _ in 0..tracks {
            let track = d.u64()?;
            let status = d.u8()?;
            let _hits = d.u32()?;
            let misses = d.u32()?;
            let mut geometry = [0_f64; 6];
            for coordinate in &mut geometry {
                *coordinate = f64::from_bits(d.u64()?);
            }
            if !reliable || status != 1 || misses != 0 {
                continue;
            }
            for (episode, choice) in scan.episodes.iter().zip(&mut episodes) {
                if episode.epoch != epoch
                    || episode.track != track
                    || position < episode.span.first.position
                    || position > episode.span.last.position
                    || choice
                        .as_ref()
                        .is_some_and(|value| value.frames.len() == config.frames_per_track)
                {
                    continue;
                }
                let first = position == episode.span.first.position;
                let filtered_box = [geometry[0], geometry[1], geometry[4], geometry[5]]
                    .map(|value| value.round() as i64);
                if choice.is_none() {
                    if !first || episode.span.first.capture != Some(capture) {
                        return Err(WatchError::Conflict);
                    }
                    *choice = Some(SelectedEntry {
                        entry: LongWatchEntry {
                            epoch,
                            track,
                            zone: episode.zone,
                            position,
                            segment,
                            capsule_digest,
                            capture,
                            filtered_box,
                        },
                        frames: Vec::new(),
                    });
                }
                choice
                    .as_mut()
                    .ok_or(WatchError::Conflict)?
                    .frames
                    .push(Selection {
                        position,
                        capsule: capsule_digest,
                        item: CascadeSelection {
                            segment,
                            reason: if first {
                                SelectionReason::DwellStart
                            } else {
                                SelectionReason::FollowingMatch
                            },
                            track_box: filtered_box,
                        },
                    });
            }
        }
    }
    selected.entries = episodes
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(WatchError::Conflict)?;
    Ok(selected)
}
