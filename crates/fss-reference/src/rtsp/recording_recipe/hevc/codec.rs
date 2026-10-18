#![forbid(unsafe_code)]
//! Hand-written HEVC recipe v1 encoding; exhaustive field destructuring exposes policy drift.
use super::*;
use crate::rtsp::recording::RecordingScope;
use fss_core::{CanonicalDecoder, CanonicalEncoder, SensorId, StreamId};
use fss_packet::{PacketLimits, StreamKey};
type Result<T> = std::result::Result<T, RecordingRecipeError>;

fn transport_values(reorder: ReorderLimits, reconstruction: H265Limits) -> [u64; 10] {
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
    let H265Limits {
        max_nal_bytes,
        max_packet_nals,
        max_fragment_packets,
        max_pending_age_ns,
    } = reconstruction;
    [
        max_packet_bytes as u64,
        max_extension_bytes as u64,
        max_rtcp_packets as u64,
        max_packets as u64,
        max_bytes as u64,
        max_delay_ns,
        max_nal_bytes as u64,
        max_packet_nals as u64,
        max_fragment_packets as u64,
        max_pending_age_ns,
    ]
}
fn assembly_values(limits: HevcAssemblyLimits) -> [u64; 4] {
    let HevcAssemblyLimits {
        max_nals,
        max_bytes,
        max_source_spans,
        max_age_ns,
    } = limits;
    [
        max_nals as u64,
        max_bytes as u64,
        max_source_spans as u64,
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
    hevc: HevcReplaySpec,
    recording: &HevcRecordingReplaySpec,
    limits: RecordingRecipeLimits,
) -> Result<()> {
    if transport_values(hevc.reorder, hevc.reconstruction)
        .iter()
        .zip(transport_values(limits.reorder, limits.reconstruction))
        .any(|(n, max)| *n > max)
        || assembly_values(recording.assembly)
            .iter()
            .zip(assembly_values(limits.assembly))
            .any(|(n, max)| *n > max)
        || collector_values(recording.limits)
            .iter()
            .zip(collector_values(limits.collector))
            .any(|(n, max)| *n > max)
    {
        return Err(RecordingRecipeError::Limit);
    }
    // Native construction reparses the original tuple with these current ceilings.
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
fn boundary(value: HevcBoundary) -> u8 {
    match value {
        HevcBoundary::NextFirstSlice => 0,
        HevcBoundary::NextAccessUnitPrefix => 1,
        HevcBoundary::AccessUnitDelimiter => 2,
        HevcBoundary::EndOfSequence => 3,
        HevcBoundary::EndOfBitstream => 4,
        HevcBoundary::EndOfInputUnverified => 5,
    }
}
pub(super) fn encode(
    source: DatagramPin,
    hevc: HevcReplaySpec,
    recording: &HevcRecordingReplaySpec,
    timings: &[RecordingTimingDecision],
    interpretation: ContentDigest,
) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text(DOMAIN);
    e.text(POLICY);
    pin(&mut e, source);
    e.digest(interpretation);
    e.tag(hevc.payload_type);
    e.u32(u32::from(hevc.sprop_max_don_diff));
    e.bool(hevc.reduced_rtcp);
    e.digest(hevc.configuration_evidence);
    for v in transport_values(hevc.reorder, hevc.reconstruction) {
        e.u64(v);
    }
    for v in assembly_values(recording.assembly) {
        e.u64(v);
    }
    e.bytes(recording.configuration.vps());
    e.bytes(recording.configuration.sps());
    e.bytes(recording.configuration.pps());
    e.text(recording.scope.sensor.as_str());
    e.text(recording.scope.stream.as_str());
    e.u64(recording.scope.generation);
    e.digest(recording.scope.anchor);
    e.digest(recording.scope.receive_clock);
    e.u32(recording.time_scale);
    e.digest(recording.timing_evidence);
    for v in collector_values(recording.limits) {
        e.u64(v);
    }
    e.u64(timings.len() as u64);
    for d in timings {
        e.u64(d.observations_read);
        key(&mut e, d.picture.key);
        e.u32(d.picture.rtp_timestamp);
        e.bool(d.picture.idr);
        e.tag(boundary(d.picture.boundary));
        e.u64(d.picture.bytes as u64);
        e.u64(d.timing.decode_time);
        e.u32(d.timing.duration);
        e.i128(i128::from(d.timing.composition_offset));
    }
    Ok(e.finish_checked()?)
}
fn usize_value(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| RecordingRecipeError::Limit)
}
fn read_transport(
    d: &mut CanonicalDecoder<'_>,
    limits: RecordingRecipeLimits,
) -> Result<(ReorderLimits, H265Limits)> {
    let mut v = [0; 10];
    for (n, max) in v
        .iter_mut()
        .zip(transport_values(limits.reorder, limits.reconstruction))
    {
        *n = d.u64()?;
        if *n > max {
            return Err(RecordingRecipeError::Limit);
        }
    }
    Ok((
        ReorderLimits {
            packet: PacketLimits {
                max_packet_bytes: usize_value(v[0])?,
                max_extension_bytes: usize_value(v[1])?,
                max_rtcp_packets: usize_value(v[2])?,
            },
            max_packets: usize_value(v[3])?,
            max_bytes: usize_value(v[4])?,
            max_delay_ns: v[5],
        },
        H265Limits {
            max_nal_bytes: usize_value(v[6])?,
            max_packet_nals: usize_value(v[7])?,
            max_fragment_packets: usize_value(v[8])?,
            max_pending_age_ns: v[9],
        },
    ))
}
fn read_assembly(
    d: &mut CanonicalDecoder<'_>,
    limit: HevcAssemblyLimits,
) -> Result<HevcAssemblyLimits> {
    let mut v = [0; 4];
    for (n, max) in v.iter_mut().zip(assembly_values(limit)) {
        *n = d.u64()?;
        if *n > max {
            return Err(RecordingRecipeError::Limit);
        }
    }
    Ok(HevcAssemblyLimits {
        max_nals: usize_value(v[0])?,
        max_bytes: usize_value(v[1])?,
        max_source_spans: usize_value(v[2])?,
        max_age_ns: v[3],
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
fn read_boundary(d: &mut CanonicalDecoder<'_>) -> Result<HevcBoundary> {
    Ok(match d.tag()? {
        0 => HevcBoundary::NextFirstSlice,
        1 => HevcBoundary::NextAccessUnitPrefix,
        2 => HevcBoundary::AccessUnitDelimiter,
        3 => HevcBoundary::EndOfSequence,
        4 => HevcBoundary::EndOfBitstream,
        5 => HevcBoundary::EndOfInputUnverified,
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
    let sprop_max_don_diff = u16::try_from(d.u32()?).map_err(|_| RecordingRecipeError::Limit)?;
    let reduced_rtcp = d.bool()?;
    let configuration_evidence = d.digest()?;
    let (reorder, reconstruction) = read_transport(&mut d, limits)?;
    let assembly = read_assembly(&mut d, limits.assembly)?;
    let configuration =
        HevcConfiguration::parse(d.bytes()?, d.bytes()?, d.bytes()?, limits.configuration)
            .map_err(RecordingRecipeError::Configuration)?;
    let hevc = HevcReplaySpec {
        payload_type,
        sprop_max_don_diff,
        reorder,
        reconstruction,
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
    let recording = HevcRecordingReplaySpec {
        scope,
        configuration,
        time_scale,
        timing_evidence,
        limits: collector,
        assembly,
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
        let picture = HevcPictureTimingRequest {
            key,
            rtp_timestamp: d.u32()?,
            idr: d.bool()?,
            boundary: read_boundary(&mut d)?,
            bytes: usize_value(d.u64()?)?,
        };
        let timing = HevcRecordingTiming {
            decode_time: d.u64()?,
            duration: d.u32()?,
            composition_offset: i32::try_from(d.i128()?)
                .map_err(|_| RecordingRecipeError::Timing)?,
        };
        timings.push(RecordingTimingDecision {
            observations_read,
            picture,
            timing,
        });
    }
    d.ensure_finished()?;
    let recipe = RecordingRecipe::new(archive, hevc, recording, timings, limits)?;
    if recipe.interpretation() != interpretation || recipe.canonical_bytes() != bytes {
        return Err(RecordingRecipeError::Mismatch);
    }
    Ok(recipe)
}
