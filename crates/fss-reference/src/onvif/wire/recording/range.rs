#![forbid(unsafe_code)]
//! Pure comparisons of advertised extrema, never recording coverage or clock calibration.

use std::fmt;
use super::{RecordingInformation, RecordingStatus, RecordingTrackInformation, RecordingTrackType};

pub(super) const MAX_RECORDING_UTC_NS: i128 = 253_402_300_799_999_999_999;

/// Independently optional oldest/newest UTC assertions. Equal bounds are a valid single
/// coordinate observation; the wider recording history is not constrained to seven days.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdvertisedRecordingRange {
    /// Oldest device-advertised coordinate, in Unix nanoseconds, if supplied.
    pub earliest_ns: Option<i128>,
    /// Newest device-advertised coordinate, in Unix nanoseconds, if supplied.
    pub latest_ns: Option<i128>,
}

/// Range comparison is weaker than proof that any requested sample is retained or delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingRangeAssessment {
    /// Both recording and selected-video extrema contain the exact request; holes remain unknown.
    WithinAdvertisedBounds,
    /// At least one extremum was absent; every supplied bound still contained the request.
    Unknown,
}
impl RecordingRangeAssessment {
    /// Payload-free stable status for operator output and protected handoffs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WithinAdvertisedBounds => "within_advertised_bounds",
            Self::Unknown => "unknown",
        }
    }
}

/// Bounded, payload-free reasons that an exact recorder replay selection cannot proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingCheckError {
    /// The response described another recording token.
    TokenMismatch,
    /// No advertised video track can be selected.
    NoVideoTrack,
    /// More than one video track prevents an unambiguous replay handoff.
    AmbiguousVideoTracks,
    /// At least one exact request edge exceeds a supplied extremum; never silently clip it.
    OutsideAdvertisedBounds,
    /// Device extrema are reversed or a track contradicts the recording-wide extrema.
    ContradictoryAdvertisedBounds,
    /// Device explicitly reports removal, without converting that claim into local deletion.
    RecordingUnavailable,
    /// Invalid caller coordinates; a native ReplayWindow already prevents this condition.
    InvalidRequestedBounds,
}
impl RecordingCheckError {
    /// Stable identity without recording tokens, descriptions, URIs or remote error prose.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TokenMismatch => "ERR-ONVIF-RECORDING-TOKEN-001",
            Self::NoVideoTrack | Self::AmbiguousVideoTracks => "ERR-ONVIF-RECORDING-VIDEO-001",
            Self::OutsideAdvertisedBounds => "ERR-ONVIF-RECORDING-RANGE-001",
            Self::ContradictoryAdvertisedBounds => "ERR-ONVIF-RECORDING-BOUNDS-001",
            Self::RecordingUnavailable => "ERR-ONVIF-RECORDING-STATE-001",
            Self::InvalidRequestedBounds => "ERR-ONVIF-RECORDING-REQUEST-001",
        }
    }
}
impl fmt::Display for RecordingCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.code()) }
}
impl std::error::Error for RecordingCheckError {}

impl AdvertisedRecordingRange {
    fn consistent(self) -> Result<(), RecordingCheckError> {
        if self.earliest_ns.into_iter().chain(self.latest_ns)
            .any(|n| !(0..=MAX_RECORDING_UTC_NS).contains(&n))
            || matches!((self.earliest_ns, self.latest_ns), (Some(first), Some(last)) if first > last)
        {
            return Err(RecordingCheckError::ContradictoryAdvertisedBounds);
        }
        Ok(())
    }

    fn contains(self, start: i128, end: i128) -> Result<bool, RecordingCheckError> {
        self.consistent()?;
        if self.earliest_ns.is_some_and(|first| start < first)
            || self.latest_ns.is_some_and(|last| end > last)
        {
            return Err(RecordingCheckError::OutsideAdvertisedBounds);
        }
        Ok(self.earliest_ns.is_some() && self.latest_ns.is_some())
    }
}

impl RecordingInformation {
    /// Select only an unambiguous advertised video track. A track token never supplies a codec
    /// or an SDP control mapping, and a descriptive name never chooses between several tracks.
    pub fn video_track(&self) -> Result<&RecordingTrackInformation, RecordingCheckError> {
        let mut video = self.tracks.iter().filter(|track| track.kind == RecordingTrackType::Video);
        let first = video.next().ok_or(RecordingCheckError::NoVideoTrack)?;
        if video.next().is_some() { return Err(RecordingCheckError::AmbiguousVideoTracks); }
        Ok(first)
    }

    /// Compare exact caller UTC coordinates with supplied recording/video bounds.
    /// Missing bounds remain explicit, and in-range extrema never establish continuous data.
    /// The native client additionally requires the independently bounded ReplayWindow type.
    pub fn validate_requested_bounds(&self, start_ns: i128, end_ns: i128) -> Result<RecordingRangeAssessment, RecordingCheckError> {
        if start_ns < 0 || start_ns >= end_ns || end_ns > MAX_RECORDING_UTC_NS {
            return Err(RecordingCheckError::InvalidRequestedBounds);
        }
        if matches!(self.status, RecordingStatus::Removing | RecordingStatus::Removed) {
            return Err(RecordingCheckError::RecordingUnavailable);
        }
        let selected = self.video_track()?;
        self.range.consistent()?;
        // Inspect every advertised track's consistency; do not select a convenient subset
        // of a contradictory device observation.
        for track in &self.tracks {
            track.range.consistent()?;
            if matches!((self.range.earliest_ns, track.range.earliest_ns), (Some(recording), Some(track)) if track < recording)
                || matches!((self.range.latest_ns, track.range.latest_ns), (Some(recording), Some(track)) if track > recording)
            {
                return Err(RecordingCheckError::ContradictoryAdvertisedBounds);
            }
        }
        let recording_known = self.range.contains(start_ns, end_ns)?;
        let video_known = selected.range.contains(start_ns, end_ns)?;
        Ok(if recording_known && video_known {
            RecordingRangeAssessment::WithinAdvertisedBounds
        } else {
            RecordingRangeAssessment::Unknown
        })
    }
}
