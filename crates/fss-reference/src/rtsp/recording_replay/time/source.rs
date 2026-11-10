#![forbid(unsafe_code)]
//! Native source projections only. No timestamp is invented from sample position.

use super::super::{ReplayReceiptError, Result, storage};
use crate::rtsp::recording::hevc::{MAX_HEVC_LOOKAHEAD_NALS, PreparedHevcRecording};
use crate::rtsp::recording::{
    MAX_RECORDING_MAPPINGS, PreparedRecording, RecordingError, RecordingPacket,
};
use fss_packet::{H265Depacketizer, H265Limits, PacketLimits, RtpPacket, StreamKey};
use fss_publication::PublishCancellation;

pub(super) struct SampleSource {
    pub sample: usize,
    pub decode_time: u64,
    pub presentation_time: u64,
    pub duration: u32,
    pub rtp_timestamp: u32,
    pub sequences: Vec<u64>,
}

pub(super) struct SourceOnly {
    pub rtp_timestamp: u32,
    pub sequences: Vec<u64>,
}

pub(super) struct Projection {
    pub samples: Vec<SampleSource>,
    pub source_only: Vec<SourceOnly>,
}

pub(super) fn avc(
    recording: &PreparedRecording,
    cancel: &dyn PublishCancellation,
) -> Result<Projection> {
    let source_map = recording.avc_source_map()?;
    let mut samples = super::super::bounded_vec(source_map.samples().len())?;
    for (ordinal, sample) in source_map.samples().iter().enumerate() {
        storage::cancelled(cancel)?;
        let mappings = source_map
            .mappings()
            .get(sample.mappings.clone())
            .ok_or(RecordingError::Source)?;
        let sequences = ordered_sequences(
            mappings
                .iter()
                .flat_map(|mapping| mapping.sources.iter().map(|span| span.sequence)),
            cancel,
        )?;
        samples.push(SampleSource {
            sample: ordinal,
            decode_time: sample.decode_time,
            presentation_time: sample.presentation_time,
            duration: sample.duration,
            rtp_timestamp: sample.rtp_timestamp,
            sequences,
        });
    }
    Ok(Projection {
        samples,
        source_only: Vec::new(),
    })
}

pub(super) fn hevc(
    recording: &PreparedHevcRecording,
    packets: &[RecordingPacket<'_>],
    cancel: &dyn PublishCancellation,
) -> Result<Projection> {
    let mut samples = super::super::bounded_vec(recording.samples().len())?;
    for (ordinal, sample) in recording.samples().iter().enumerate() {
        storage::cancelled(cancel)?;
        let mappings = recording
            .mappings()
            .get(sample.mappings.clone())
            .ok_or(RecordingError::Source)?;
        let sequences = ordered_sequences(
            mappings
                .iter()
                .flat_map(|mapping| mapping.sources.iter().map(|span| span.sequence)),
            cancel,
        )?;
        samples.push(SampleSource {
            sample: ordinal,
            decode_time: sample.decode_time,
            presentation_time: sample.presentation_time,
            duration: sample.duration,
            rtp_timestamp: sample.rtp_timestamp,
            sequences,
        });
    }
    // The native verifier already proved that all media NALs form an exact prefix
    // of this depacketizer's output, followed only by bounded source-only NALs.
    // Repeating only packet reconstruction obtains those trailing source spans.
    // A packet shared with media remains present here; unused-packet subtraction
    // would silently lose that evidence.
    let first = packets.first().ok_or(RecordingError::Source)?;
    let first = RtpPacket::parse(first.bytes, PacketLimits::default())
        .map_err(|_| RecordingError::Source)?;
    let key = StreamKey {
        ingress: 1,
        generation: recording.summary().scope.generation,
        ssrc: first.ssrc(),
    };
    let mut dep = H265Depacketizer::new(
        key,
        first.payload_type(),
        0,
        H265Limits {
            max_nal_bytes: 16 * 1024 * 1024,
            max_packet_nals: 256,
            ..H265Limits::default()
        },
    )
    .map_err(|_| RecordingError::Source)?;
    let mut source_only: Vec<SourceOnly> = super::super::bounded_vec(recording.source_only_nals())?;
    let mut ordinal = 0_usize;
    let mut trailing_spans = 0_usize;
    for original in packets {
        storage::cancelled(cancel)?;
        let packet = RtpPacket::parse(original.bytes, PacketLimits::default())
            .map_err(|_| RecordingError::Source)?;
        let output = dep
            .push(key, original.sequence, packet, 0)
            .map_err(|_| RecordingError::Source)?;
        if output.discarded.is_some() || output.gap_before {
            return Err(RecordingError::Source.into());
        }
        for nal in output.nals {
            storage::cancelled(cancel)?;
            if let Some(mapping) = recording.mappings().get(ordinal) {
                if mapping.sources != nal.sources() {
                    return Err(RecordingError::Source.into());
                }
            } else {
                if ordinal - recording.mappings().len() >= MAX_HEVC_LOOKAHEAD_NALS {
                    return Err(ReplayReceiptError::Limit);
                }
                if source_only
                    .last()
                    .is_none_or(|group| group.rtp_timestamp != nal.timestamp())
                {
                    source_only.push(SourceOnly {
                        rtp_timestamp: nal.timestamp(),
                        sequences: Vec::new(),
                    });
                }
                let group = source_only.last_mut().ok_or(RecordingError::Source)?;
                trailing_spans = trailing_spans
                    .checked_add(nal.sources().len())
                    .ok_or(ReplayReceiptError::Limit)?;
                if trailing_spans > MAX_RECORDING_MAPPINGS {
                    return Err(ReplayReceiptError::Limit);
                }
                group
                    .sequences
                    .try_reserve_exact(nal.sources().len())
                    .map_err(|_| ReplayReceiptError::Limit)?;
                group
                    .sequences
                    .extend(nal.sources().iter().map(|span| span.sequence));
            }
            ordinal = ordinal.checked_add(1).ok_or(ReplayReceiptError::Limit)?;
        }
    }
    if dep.finish().is_some()
        || ordinal != recording.mappings().len() + recording.source_only_nals()
    {
        return Err(RecordingError::Source.into());
    }
    for group in &mut source_only {
        storage::cancelled(cancel)?;
        group.sequences.sort_unstable();
        group.sequences.dedup();
        if group.sequences.is_empty() {
            return Err(RecordingError::Source.into());
        }
    }
    Ok(Projection {
        samples,
        source_only,
    })
}

fn ordered_sequences(
    values: impl Iterator<Item = u64>,
    cancel: &dyn PublishCancellation,
) -> Result<Vec<u64>> {
    let mut sequences = Vec::new();
    for value in values {
        storage::cancelled(cancel)?;
        if sequences.len() >= MAX_RECORDING_MAPPINGS {
            return Err(ReplayReceiptError::Limit);
        }
        sequences
            .try_reserve(1)
            .map_err(|_| ReplayReceiptError::Limit)?;
        sequences.push(value);
    }
    sequences.sort_unstable();
    sequences.dedup();
    if sequences.is_empty() {
        return Err(RecordingError::Source.into());
    }
    Ok(sequences)
}
