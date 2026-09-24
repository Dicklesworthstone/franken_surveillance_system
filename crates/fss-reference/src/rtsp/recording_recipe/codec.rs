#![forbid(unsafe_code)]
//! Complete explicit encoding, with exhaustive limit destructuring to expose future field drift.
use super::*;
use crate::rtsp::recording::RecordingScope;
use fss_core::{CanonicalDecoder, CanonicalEncoder, SensorId, StreamId};
use fss_packet::avc::{AvcAssemblyLimits, AvcSyntaxLimits};
use fss_packet::{H264Limits, PacketLimits, ReorderLimits, StreamKey};

type Result<T> = std::result::Result<T, RecordingRecipeError>;

fn avc_values(limits: AvcReceiveLimits) -> [u64; 20] {
    let AvcReceiveLimits {
        reorder,
        reconstruction,
        syntax,
        assembly,
    } = limits;
    let ReorderLimits {
        packet,
        max_packets,
        max_bytes,
        max_delay_ns,
    } = reorder;
    let PacketLimits {
        max_packet_bytes,
        max_extension_bytes,
        max_rtcp_packets,
    } = packet;
    let H264Limits {
        max_nal_bytes: nal,
        max_packet_nals,
        max_fragment_packets,
        max_pending_age_ns,
    } = reconstruction;
    let AvcSyntaxLimits {
        max_nal_bytes,
        max_parameter_set_bytes,
        max_width,
        max_height,
        max_luma_samples,
        max_reference_frames,
        max_slice_identity_bits,
    } = syntax;
    let AvcAssemblyLimits {
        max_nals: group_nals,
        max_bytes: group_bytes,
        max_age_ns,
    } = assembly;
    [
        max_packet_bytes as u64,
        max_extension_bytes as u64,
        max_rtcp_packets as u64,
        max_packets as u64,
        max_bytes as u64,
        max_delay_ns,
        nal as u64,
        max_packet_nals as u64,
        max_fragment_packets as u64,
        max_pending_age_ns,
        max_nal_bytes as u64,
        max_parameter_set_bytes as u64,
        max_slice_identity_bits as u64,
        u64::from(max_width),
        u64::from(max_height),
        max_luma_samples,
        u64::from(max_reference_frames),
        group_nals as u64,
        group_bytes as u64,
        max_age_ns,
    ]
}
fn collector_values(limits: CollectorLimits) -> [u64; 7] {
    let CollectorLimits {
        max_packets,
        max_source_bytes,
        max_samples,
        max_picture_bytes,
        max_nals,
        max_source_spans,
        max_age_ns,
    } = limits;
    [
        max_packets as u64,
        max_source_bytes as u64,
        max_samples as u64,
        max_picture_bytes as u64,
        max_nals as u64,
        max_source_spans as u64,
        max_age_ns,
    ]
}
pub(super) fn check_limits(
    avc: AvcReceiveLimits,
    collector: CollectorLimits,
    limits: RecordingRecipeLimits,
) -> Result<()> {
    if avc_values(avc)
        .iter()
        .zip(avc_values(limits.receiver))
        .any(|(n, ceiling)| *n > ceiling)
        || collector_values(collector)
            .iter()
            .zip(collector_values(limits.collector))
            .any(|(n, ceiling)| *n > ceiling)
    {
        return Err(RecordingRecipeError::Limit);
    }
    Ok(())
}
fn pin(e: &mut CanonicalEncoder, p: DatagramPin) {
    e.digest(p.scope);
    e.digest(p.head);
    e.u64(p.datagrams);
    e.u64(p.payload_bytes);
}
fn key(e: &mut CanonicalEncoder, k: StreamKey) {
    e.u64((k.ingress >> 64) as u64);
    e.u64(k.ingress as u64);
    e.u64(k.generation);
    e.u32(k.ssrc);
}
fn boundary(value: AvcBoundary) -> u8 {
    match value {
        AvcBoundary::NextPrimaryPicture => 0,
        AvcBoundary::NextAccessUnitPrefix => 1,
        AvcBoundary::RtpMarker => 2,
        AvcBoundary::EndOfSequence => 3,
        AvcBoundary::EndOfStream => 4,
        AvcBoundary::EndOfInputUnverified => 5,
    }
}
pub(super) fn encode(
    source: DatagramPin,
    avc: AvcReplaySpec<'_>,
    recording: &RecordingReplaySpec,
    timings: &[RecordingTimingDecision],
    interpretation: ContentDigest,
) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text(DOMAIN);
    e.text(POLICY);
    pin(&mut e, source);
    e.digest(interpretation);
    e.tag(avc.payload_type);
    e.tag(match avc.mode {
        H264Mode::SingleNal => 0,
        H264Mode::NonInterleaved => 1,
    });
    e.bool(avc.reduced_rtcp);
    e.digest(avc.configuration_evidence);
    for value in avc_values(avc.limits) {
        e.u64(value);
    }
    e.bytes(avc.sps);
    e.bytes(avc.pps);
    e.text(recording.scope.sensor.as_str());
    e.text(recording.scope.stream.as_str());
    e.u64(recording.scope.generation);
    e.digest(recording.scope.anchor);
    e.digest(recording.scope.receive_clock);
    e.u32(recording.time_scale);
    e.digest(recording.timing_evidence);
    for value in collector_values(recording.limits) {
        e.u64(value);
    }
    e.u64(timings.len() as u64);
    for decision in timings {
        e.u64(decision.observations_read);
        key(&mut e, decision.picture.key);
        e.u32(decision.picture.rtp_timestamp);
        e.u32(u32::from(decision.picture.frame_num));
        e.bool(decision.picture.idr);
        e.tag(boundary(decision.picture.boundary));
        e.u64(decision.picture.bytes as u64);
        e.u64(decision.timing.decode_time);
        e.u32(decision.timing.duration);
        e.i128(i128::from(decision.timing.composition_offset));
    }
    Ok(e.finish_checked()?)
}
fn usize_value(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| RecordingRecipeError::Limit)
}
fn u32_value(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| RecordingRecipeError::Limit)
}
fn read_avc(d: &mut CanonicalDecoder<'_>, ceiling: AvcReceiveLimits) -> Result<AvcReceiveLimits> {
    let mut v = [0_u64; 20];
    for (value, maximum) in v.iter_mut().zip(avc_values(ceiling)) {
        *value = d.u64()?;
        if *value > maximum {
            return Err(RecordingRecipeError::Limit);
        }
    }
    Ok(AvcReceiveLimits {
        reorder: ReorderLimits {
            packet: PacketLimits {
                max_packet_bytes: usize_value(v[0])?,
                max_extension_bytes: usize_value(v[1])?,
                max_rtcp_packets: usize_value(v[2])?,
            },
            max_packets: usize_value(v[3])?,
            max_bytes: usize_value(v[4])?,
            max_delay_ns: v[5],
        },
        reconstruction: H264Limits {
            max_nal_bytes: usize_value(v[6])?,
            max_packet_nals: usize_value(v[7])?,
            max_fragment_packets: usize_value(v[8])?,
            max_pending_age_ns: v[9],
        },
        syntax: AvcSyntaxLimits {
            max_nal_bytes: usize_value(v[10])?,
            max_parameter_set_bytes: usize_value(v[11])?,
            max_slice_identity_bits: usize_value(v[12])?,
            max_width: u32_value(v[13])?,
            max_height: u32_value(v[14])?,
            max_luma_samples: v[15],
            max_reference_frames: u32_value(v[16])?,
        },
        assembly: AvcAssemblyLimits {
            max_nals: usize_value(v[17])?,
            max_bytes: usize_value(v[18])?,
            max_age_ns: v[19],
        },
    })
}
fn read_collector(
    d: &mut CanonicalDecoder<'_>,
    ceiling: CollectorLimits,
) -> Result<CollectorLimits> {
    let mut v = [0_u64; 7];
    for (value, maximum) in v.iter_mut().zip(collector_values(ceiling)) {
        *value = d.u64()?;
        if *value > maximum {
            return Err(RecordingRecipeError::Limit);
        }
    }
    Ok(CollectorLimits {
        max_packets: usize_value(v[0])?,
        max_source_bytes: usize_value(v[1])?,
        max_samples: usize_value(v[2])?,
        max_picture_bytes: usize_value(v[3])?,
        max_nals: usize_value(v[4])?,
        max_source_spans: usize_value(v[5])?,
        max_age_ns: v[6],
    })
}
fn read_boundary(d: &mut CanonicalDecoder<'_>) -> Result<AvcBoundary> {
    Ok(match d.tag()? {
        0 => AvcBoundary::NextPrimaryPicture,
        1 => AvcBoundary::NextAccessUnitPrefix,
        2 => AvcBoundary::RtpMarker,
        3 => AvcBoundary::EndOfSequence,
        4 => AvcBoundary::EndOfStream,
        5 => AvcBoundary::EndOfInputUnverified,
        _ => return Err(RecordingRecipeError::Mismatch),
    })
}
pub(super) fn decode(
    bytes: &[u8],
    archive: &DatagramArchive,
    limits: RecordingRecipeLimits,
) -> Result<RecordingRecipe> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != DOMAIN || d.text()? != POLICY {
        return Err(RecordingRecipeError::Mismatch);
    }
    let source = DatagramPin {
        scope: d.digest()?,
        head: d.digest()?,
        datagrams: d.u64()?,
        payload_bytes: d.u64()?,
    };
    if source != archive.pin() {
        return Err(RecordingRecipeError::Mismatch);
    }
    let interpretation = d.digest()?;
    let payload_type = d.tag()?;
    let mode = match d.tag()? {
        0 => H264Mode::SingleNal,
        1 => H264Mode::NonInterleaved,
        _ => return Err(RecordingRecipeError::Mismatch),
    };
    let reduced_rtcp = d.bool()?;
    let configuration_evidence = d.digest()?;
    let receiver = read_avc(&mut d, limits.receiver)?;
    let sps = d.bytes()?;
    let pps = d.bytes()?;
    if sps.len() > receiver.syntax.max_parameter_set_bytes
        || pps.len() > receiver.syntax.max_parameter_set_bytes
    {
        return Err(RecordingRecipeError::Limit);
    }
    let avc = AvcReplaySpec {
        payload_type,
        mode,
        sps,
        pps,
        limits: receiver,
        reduced_rtcp,
        configuration_evidence,
    };
    let scope = RecordingScope {
        sensor: SensorId::parse(d.text()?)?,
        stream: StreamId::parse(d.text()?)?,
        generation: d.u64()?,
        anchor: d.digest()?,
        receive_clock: d.digest()?,
    };
    let time_scale = d.u32()?;
    let timing_evidence = d.digest()?;
    let collector = read_collector(&mut d, limits.collector)?;
    let recording = RecordingReplaySpec {
        scope,
        time_scale,
        limits: collector,
        timing_evidence,
    };
    let count = usize_value(d.u64()?)?;
    if count > limits.max_timings {
        return Err(RecordingRecipeError::Limit);
    }
    let mut timings = Vec::new();
    timings
        .try_reserve_exact(count)
        .map_err(|_| RecordingRecipeError::Limit)?;
    for _ in 0..count {
        let observations_read = d.u64()?;
        let ingress = (u128::from(d.u64()?) << 64) | u128::from(d.u64()?);
        let key = StreamKey {
            ingress,
            generation: d.u64()?,
            ssrc: d.u32()?,
        };
        let rtp_timestamp = d.u32()?;
        let frame_num = u16::try_from(d.u32()?).map_err(|_| RecordingRecipeError::Timing)?;
        let idr = d.bool()?;
        let boundary = read_boundary(&mut d)?;
        let picture_bytes = usize_value(d.u64()?)?;
        let timing = RecordingTiming {
            decode_time: d.u64()?,
            duration: d.u32()?,
            composition_offset: i32::try_from(d.i128()?)
                .map_err(|_| RecordingRecipeError::Timing)?,
        };
        timings.push(RecordingTimingDecision {
            observations_read,
            picture: PictureTimingRequest {
                key,
                rtp_timestamp,
                frame_num,
                idr,
                boundary,
                bytes: picture_bytes,
            },
            timing,
        });
    }
    d.ensure_finished()?;
    let recipe = RecordingRecipe::new(archive, avc, recording, timings, limits)?;
    if recipe.interpretation != interpretation || recipe.canonical_bytes() != bytes {
        return Err(RecordingRecipeError::Mismatch);
    }
    Ok(recipe)
}
