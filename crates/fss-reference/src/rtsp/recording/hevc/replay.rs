#![forbid(unsafe_code)]

use super::*;
use fss_container::{HevcFragment, HevcMuxer, Mp4Error, Mp4Limits, TimedHevcPicture};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcConfigurationLimits,
};
use fss_packet::{H265Depacketizer, H265Limits, StreamKey};

pub(super) struct Replayed {
    pub initialization: Vec<u8>,
    pub parameters: [Range<usize>; 3],
    pub fragment: HevcFragment,
    pub source_only_nals: usize,
}

pub(super) fn validate_timings(timings: &[HevcRecordingTiming], scale: u32) -> Result<()> {
    if timings.is_empty() || timings.len() > MAX_RECORDING_SAMPLES {
        return Err(RecordingError::Limit);
    }
    if scale == 0 {
        return Err(RecordingError::Media(Mp4Error::Configuration));
    }
    let mut end = timings[0].decode_time;
    for t in timings {
        if t.duration == 0 || t.decode_time != end {
            return Err(RecordingError::Media(Mp4Error::Timeline));
        }
        end = t
            .decode_time
            .checked_add(u64::from(t.duration))
            .ok_or(RecordingError::Media(Mp4Error::Timeline))?;
        t.decode_time
            .checked_add_signed(i64::from(t.composition_offset))
            .ok_or(RecordingError::Media(Mp4Error::Timeline))?;
    }
    Ok(())
}

pub(super) fn configuration(init: &[u8], ranges: &[Range<usize>; 3]) -> Result<HevcConfiguration> {
    if init.len() > Mp4Limits::default().max_initialization_bytes {
        return Err(RecordingError::Limit);
    }
    let vps = init
        .get(ranges[0].clone())
        .ok_or(RecordingError::Malformed)?;
    let sps = init
        .get(ranges[1].clone())
        .ok_or(RecordingError::Malformed)?;
    let pps = init
        .get(ranges[2].clone())
        .ok_or(RecordingError::Malformed)?;
    HevcConfiguration::parse(vps, sps, pps, HevcConfigurationLimits::default())
        .map_err(|_| RecordingError::Media(Mp4Error::ParameterSet))
}

pub(super) fn run(
    generation: u64,
    ssrc: u32,
    payload_type: u8,
    config: &HevcConfiguration,
    scale: u32,
    timings: &[HevcRecordingTiming],
    packets: &[RecordingPacket<'_>],
) -> Result<Replayed> {
    validate_timings(timings, scale)?;
    if generation == 0 || payload_type > 127 {
        return Err(RecordingError::Scope);
    }
    if packets.is_empty() || packets.len() > MAX_RECORDING_PACKETS {
        return Err(RecordingError::Limit);
    }
    // A fresh local alias is NOT a recovered durable ingress identifier.
    let key = StreamKey {
        ingress: 1,
        generation,
        ssrc,
    };
    let config = HevcConfiguration::parse(
        config.vps(),
        config.sps(),
        config.pps(),
        HevcConfigurationLimits::default(),
    )
    .map_err(|_| RecordingError::Media(Mp4Error::ParameterSet))?;
    let mut mux =
        HevcMuxer::new(key, config, scale, Mp4Limits::default()).map_err(RecordingError::Media)?;
    let mut dep = H265Depacketizer::new(
        key,
        payload_type,
        0,
        H265Limits {
            max_nal_bytes: 16 * 1024 * 1024,
            max_packet_nals: 256,
            ..H265Limits::default()
        },
    )
    .map_err(|_| RecordingError::Source)?;
    let mut assembler = HevcAssembler::new(
        key,
        HevcAssemblyLimits {
            max_nals: 4096,
            max_source_spans: MAX_RECORDING_MAPPINGS,
            ..HevcAssemblyLimits::default()
        },
    )
    .map_err(|_| RecordingError::Source)?;
    let mut pictures = bounded_vec(timings.len(), MAX_RECORDING_SAMPLES)?;
    let (mut total_nals, mut total_spans, mut total_bytes) = (0_usize, 0_usize, 0_usize);
    let mut media_nals = 0_usize;
    let mut previous: Option<u64> = None;
    for original in packets {
        if previous.is_some_and(|seq| seq.checked_add(1) != Some(original.sequence)) {
            return Err(RecordingError::Source);
        }
        previous = Some(original.sequence);
        let packet = RtpPacket::parse(original.bytes, PacketLimits::default())
            .map_err(|_| RecordingError::Source)?;
        let output = dep
            .push(key, original.sequence, packet, 0)
            .map_err(|_| RecordingError::Source)?;
        if output.discarded.is_some() || output.gap_before {
            return Err(RecordingError::Source);
        }
        for nal in output.nals {
            total_nals = total_nals.checked_add(1).ok_or(RecordingError::Limit)?;
            total_spans = total_spans
                .checked_add(nal.sources().len())
                .ok_or(RecordingError::Limit)?;
            total_bytes = total_bytes
                .checked_add(nal.bytes().len())
                .ok_or(RecordingError::Limit)?;
            if total_nals > MAX_RECORDING_MAPPINGS
                || total_spans > MAX_RECORDING_MAPPINGS
                || total_bytes > MAX_RECORDING_BYTES
                || pictures.len() == timings.len()
                    && total_nals - media_nals > MAX_HEVC_LOOKAHEAD_NALS
            {
                return Err(RecordingError::Limit);
            }
            match assembler.push(nal, 0) {
                HevcAssemblyStep::Refused(_) => return Err(RecordingError::Source),
                HevcAssemblyStep::Accepted(output) => {
                    // No malformed/retired/standalone prefix may disappear between samples.
                    if output.retired.is_some() || output.standalone.is_some() {
                        return Err(RecordingError::Source);
                    }
                    if let Some(picture) = output.picture {
                        if pictures.len() == timings.len() {
                            return Err(RecordingError::Source);
                        }
                        media_nals = media_nals
                            .checked_add(picture.nals().len())
                            .ok_or(RecordingError::Limit)?;
                        pictures.push(picture);
                    }
                }
            }
        }
    }
    if dep.finish().is_some() || pictures.len() != timings.len() {
        return Err(RecordingError::Source);
    }
    // Never flush EOF to manufacture the final media boundary. The remaining
    // assembler state is exclusively trailing source-only lookahead and is not
    // output as a verified picture or used to configure any media in this root.
    let source_only_nals = total_nals
        .checked_sub(media_nals)
        .ok_or(RecordingError::Source)?;
    if source_only_nals > MAX_HEVC_LOOKAHEAD_NALS {
        return Err(RecordingError::Limit);
    }
    let _ = assembler.cancel();
    let mut timed = bounded_vec(pictures.len(), MAX_RECORDING_SAMPLES)?;
    for (picture, t) in pictures.iter().zip(timings) {
        timed.push(TimedHevcPicture {
            picture,
            decode_time: t.decode_time,
            duration: t.duration,
            composition_offset: t.composition_offset,
        });
    }
    let fragment = mux.fragment(&timed).map_err(RecordingError::Media)?;
    let initialization = copy(mux.initialization().bytes())?;
    Ok(Replayed {
        initialization,
        parameters: mux.initialization().parameter_ranges().clone(),
        fragment,
        source_only_nals,
    })
}
