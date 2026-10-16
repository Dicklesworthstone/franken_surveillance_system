#![forbid(unsafe_code)]
//! Explicit offline preparation of already-collected original footage.
//!
//! No I/O, camera connection, credential access or retry-policy change occurs.
//! The native recording verifier must replay every selected original datagram.
//! Original timing and the original reason for stopping remain separate from custody.

use super::{CollectionStop, CollectorError, PreparedRecording, RecordingScope, UnsealedRecording};
use crate::rtsp::recording::{
    MAX_RECORDING_BYTES, MAX_RECORDING_MAPPINGS, MAX_RECORDING_PACKETS, MAX_RECORDING_SAMPLES,
    prepare_recording,
};
use fss_container::TimedAvcPicture;

/// A source-verified prepared prefix and its exact, still-unarchived remainder.
///
/// Preparation is not publication. The recording must still cross the existing
/// publication and independent pin barriers under separately supplied authority.
#[must_use]
#[derive(Debug)]
pub struct RecoveredRecordingPrefix {
    /// Immutable native recording with original RTP bytes and explicit media timing.
    pub recording: PreparedRecording,
    /// All whole source packets after the selected prefix, with the original reason.
    /// These packets are NOT evidence of complete pictures or durable source custody.
    pub remainder: UnsealedRecording,
    /// Original stop reason. Recovery does not replace it with EndOfInput.
    pub original_stop: CollectionStop,
    /// Exact count of whole original packets included in the prepared recording.
    pub selected_packets: usize,
}

/// Failed preparation returns every caller-owned input unchanged.
#[must_use]
#[derive(Debug)]
pub struct PrefixRecoveryRefusal {
    /// Native configuration, bound, source, timeline or verification failure.
    pub reason: CollectorError,
    /// Every original packet and picture, without a partial split or dropped tail.
    pub original: UnsealedRecording,
}
impl std::fmt::Display for PrefixRecoveryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "offline recording prefix refused: {}", self.reason)
    }
}
impl std::error::Error for PrefixRecoveryRefusal {}

impl UnsealedRecording {
    /// Prepare all completed, explicitly timed pictures in a retired collector.
    ///
    /// Supply the ORIGINAL recording scope and time scale retained by the owner;
    /// this container retains the receiver key, not an independent sensor/clock grant.
    /// Only whole datagrams through the last completed picture may be selected.
    /// Source replay rejects shared-packet suffixes, missing packets, changed source,
    /// invalid timing and unverified boundaries instead of truncating bytes to fit.
    ///
    /// Success transfers the selected source into an immutable recording and returns
    /// all later packets with their original bytes, receive times, key and stop reason.
    /// Refusal returns the ENTIRE input unchanged. No live capture is resumed, no
    /// source EOF is asserted, and no new recording epoch or authority is inferred.
    /// A containing retirement's ready window, untimed picture and protocol state
    /// remain separate obligations; this operation consumes only its unsealed collection.
    pub fn prepare_verified_prefix(
        mut self,
        original_scope: RecordingScope,
        original_time_scale: u32,
        max_window_bytes: usize,
    ) -> Result<RecoveredRecordingPrefix, PrefixRecoveryRefusal> {
        let prepared = prepare_prefix(&self, original_scope, original_time_scale, max_window_bytes);
        match prepared {
            Ok((recording, selected_packets)) => {
                let original_stop = self.reason;
                drop(self.sources.drain(..selected_packets));
                self.pictures.clear();
                Ok(RecoveredRecordingPrefix {
                    recording,
                    remainder: self,
                    original_stop,
                    selected_packets,
                })
            }
            Err(reason) => Err(PrefixRecoveryRefusal {
                reason,
                original: self,
            }),
        }
    }
}

pub(crate) fn prepare_prefix(
    original: &UnsealedRecording,
    scope: RecordingScope,
    time_scale: u32,
    max_window_bytes: usize,
) -> Result<(PreparedRecording, usize), CollectorError> {
    if !(1..=MAX_RECORDING_BYTES).contains(&max_window_bytes) || time_scale == 0 {
        return Err(CollectorError::Configuration);
    }
    // Public retirement vectors may have changed since capture. Bound their lengths
    // BEFORE iterating either vector or allocating a proof.
    if original.sources.len() > MAX_RECORDING_PACKETS
        || original.pictures.len() > MAX_RECORDING_SAMPLES
    {
        return Err(CollectorError::Capacity);
    }
    if original.key.ingress == 0
        || original.key.generation == 0
        || original.key.generation != scope.generation
        || original
            .pictures
            .iter()
            .any(|p| p.picture.key() != original.key)
    {
        return Err(CollectorError::StreamMismatch);
    }
    if original.pictures.is_empty() {
        return Err(CollectorError::UnverifiedPicture);
    }
    let mut source_bytes = 0_usize;
    for source in &original.sources {
        source_bytes = source_bytes
            .checked_add(source.bytes().len())
            .ok_or(CollectorError::Capacity)?;
        if source_bytes > 16 * 1024 * 1024 {
            return Err(CollectorError::Capacity);
        }
    }
    // Include the remainder in this check: partition_point must never operate on
    // a reordered public vector, even if its apparent selected prefix looks valid.
    if original
        .sources
        .windows(2)
        .any(|s| s[0].sequence() >= s[1].sequence())
    {
        return Err(CollectorError::SourceOrder);
    }
    let mut picture_bytes = 0_usize;
    let mut nals = 0_usize;
    let mut spans = 0_usize;
    for picture in &original.pictures {
        picture_bytes = picture_bytes
            .checked_add(picture.picture.byte_len())
            .ok_or(CollectorError::Capacity)?;
        nals = nals
            .checked_add(picture.picture.nals().len())
            .ok_or(CollectorError::Capacity)?;
        if picture_bytes > 16 * 1024 * 1024 || nals > MAX_RECORDING_MAPPINGS {
            return Err(CollectorError::Capacity);
        }
        for nal in picture.picture.nals() {
            spans = spans
                .checked_add(nal.sources().len())
                .ok_or(CollectorError::Capacity)?;
            if spans > MAX_RECORDING_MAPPINGS {
                return Err(CollectorError::Capacity);
            }
        }
    }
    let last_sequence = original
        .pictures
        .last()
        .and_then(|p| p.picture.nals().last())
        .and_then(|n| n.sources().last())
        .ok_or(CollectorError::Source)?
        .sequence;
    let selected_packets = original
        .sources
        .partition_point(|source| source.sequence() <= last_sequence);
    let mut packets = Vec::new();
    packets
        .try_reserve_exact(selected_packets)
        .map_err(|_| CollectorError::Allocation)?;
    packets.extend(
        original.sources[..selected_packets]
            .iter()
            .map(|s| s.as_packet()),
    );
    let mut pictures = Vec::new();
    pictures
        .try_reserve_exact(original.pictures.len())
        .map_err(|_| CollectorError::Allocation)?;
    pictures.extend(original.pictures.iter().map(|p| TimedAvcPicture {
        picture: &p.picture,
        decode_time: p.timing.decode_time,
        duration: p.timing.duration,
        composition_offset: p.timing.composition_offset,
    }));
    // Reuse the native proof owner rather than trusting cached picture metadata.
    let recording = prepare_recording(scope, time_scale, &pictures, &packets)
        .map_err(CollectorError::Recording)?;
    if recording.byte_len() > max_window_bytes {
        return Err(CollectorError::Capacity);
    }
    Ok((recording, selected_packets))
}
