#![forbid(unsafe_code)]

use super::*;
use fss_container::NalTarget;
use fss_packet::{H264Depacketizer, H264Limits, H264Mode, PacketLimits, RtpPacket};
use fss_packet::avc::{AvcBoundary, AvcSliceIdentity, AvcSyntaxLimits, parse_pps, parse_slice_identity, parse_sps};

pub(super) fn content(index: &Index, objects: RecordingObjects<'_>, packets: &[RecordingPacket<'_>]) -> Result<()> {
    let syntax = AvcSyntaxLimits::default();
    let sps_bytes = objects.initialization.get(index.sps.clone()).ok_or(RecordingError::Malformed)?;
    let pps_bytes = objects.initialization.get(index.pps.clone()).ok_or(RecordingError::Malformed)?;
    let sps = parse_sps(sps_bytes, syntax).map_err(|_| RecordingError::Malformed)?;
    let pps = parse_pps(pps_bytes, &sps, syntax).map_err(|_| RecordingError::Malformed)?;
    let mux = AvcMuxer::new(key(index), sps.clone(), pps.clone(), index.time_scale, Mp4Limits::default())
        .map_err(RecordingError::Media)?;
    if mux.initialization().bytes() != objects.initialization
        || mux.initialization().sps_range() != index.sps || mux.initialization().pps_range() != index.pps {
        return Err(RecordingError::Malformed);
    }
    check_layout(index, objects)?;
    // Re-run the real packet depacketizer, not a hand-written approximation of FU
    // header synthesis. Synthetic replay time zero only disables age accounting;
    // original receive timestamps remain unchanged in the source object.
    let mut depacketizer = H264Depacketizer::new(key(index), index.payload_type, H264Mode::NonInterleaved,
        H264Limits { max_nal_bytes: 16 * 1024 * 1024, max_packet_nals: 256, ..H264Limits::default() })
        .map_err(|_| RecordingError::Source)?;
    let mut ordinal = 0;
    let mut sample_identity: Option<AvcSliceIdentity> = None;
    let mut saw_first = false;
    let mut active_sample = 0;
    for p in packets {
        let packet = RtpPacket::parse(p.bytes, PacketLimits::default()).map_err(|_| RecordingError::Source)?;
        let output = depacketizer.push(key(index), p.sequence, packet, 0).map_err(|_| RecordingError::Source)?;
        if output.discarded.is_some() { return Err(RecordingError::Source); }
        for nal in output.nals {
            let mapping = index.mappings.get(ordinal).ok_or(RecordingError::Source)?;
            let bytes = target(mapping, objects)?;
            if mapping.sources != nal.sources() || bytes != nal.bytes() { return Err(RecordingError::Source); }
            if mapping.sample != active_sample {
                if sample_identity.is_none() || !saw_first || mapping.sample != active_sample + 1 {
                    return Err(RecordingError::Source);
                }
                sample_identity = None; saw_first = false; active_sample = mapping.sample;
            }
            if matches!(nal.nal_type(), 1 | 5) {
                let id = parse_slice_identity(bytes, &sps, &pps, syntax).map_err(|_| RecordingError::Source)?;
                let sample = &index.samples[mapping.sample]; // check_layout proved the index.
                if id.redundant_pic_cnt() != 0 || id.field_pic()
                    || id.idr_pic_id().is_some() != sample.idr || nal.timestamp() != sample.rtp_timestamp
                    || sample_identity.is_some_and(|previous| id.starts_new_picture(previous)) {
                    return Err(RecordingError::Source);
                }
                sample_identity = Some(id); saw_first |= id.first_mb_in_slice() == 0;
            } else if matches!(nal.nal_type(), 2..=4 | 13..=23) {
                return Err(RecordingError::Source);
            }
            ordinal += 1;
        }
    }
    if depacketizer.finish().is_some() || ordinal != index.mappings.len()
        || sample_identity.is_none() || !saw_first || active_sample + 1 != index.samples.len() {
        return Err(RecordingError::Source);
    }
    Ok(())
}

fn target<'a>(mapping: &NalMapping, objects: RecordingObjects<'a>) -> Result<&'a [u8]> {
    let bytes = match &mapping.target {
        NalTarget::Media(r) => objects.media.get(r.clone()),
        NalTarget::Initialization(r) => objects.initialization.get(r.clone()),
    }.ok_or(RecordingError::Malformed)?;
    if bytes.is_empty() { return Err(RecordingError::Malformed); }
    Ok(bytes)
}

fn check_layout(index: &Index, objects: RecordingObjects<'_>) -> Result<()> {
    let count = index.samples.len();
    if count == 0 || !index.samples[0].idr { return Err(RecordingError::Malformed); }
    let offset = 96 + 16 * count;
    if objects.media.len() < offset { return Err(RecordingError::Malformed); }
    let mut header = bounded_vec(offset, 96 + 16 * MAX_RECORDING_SAMPLES)?;
    // Match this reference writer's complete supported box grammar, including
    // 64-bit tfdt, signed trun offsets, sample flags and the whole mdat length.
    box_header(&mut header, 88 + 16 * count, b"moof");
    box_header(&mut header, 16, b"mfhd"); u32be(&mut header, 0); u32be(&mut header, 1);
    box_header(&mut header, 64 + 16 * count, b"traf");
    box_header(&mut header, 16, b"tfhd"); u32be(&mut header, 0x0002_0000); u32be(&mut header, 1);
    box_header(&mut header, 20, b"tfdt"); u32be(&mut header, 0x0100_0000);
    header.extend_from_slice(&index.samples[0].decode_time.to_be_bytes());
    box_header(&mut header, 20 + 16 * count, b"trun"); u32be(&mut header, 0x0100_0f01);
    u32be(&mut header, count as u32); u32be(&mut header, offset as u32);
    let mut end = index.samples[0].decode_time;
    let mut cursor = offset;
    let mut map_cursor = 0;
    for (sample_index, s) in index.samples.iter().enumerate() {
        if s.duration == 0 || s.decode_time != end || s.range.start != cursor || s.range.end <= cursor
            || s.range.end > objects.media.len() || s.mappings.start != map_cursor
            || s.mappings.end <= map_cursor || s.mappings.end > index.mappings.len()
            || s.boundary == AvcBoundary::EndOfInputUnverified { return Err(RecordingError::Malformed); }
        end = end.checked_add(u64::from(s.duration)).ok_or(RecordingError::Malformed)?;
        let composition = i128::from(s.presentation_time) - i128::from(s.decode_time);
        let composition = i32::try_from(composition).map_err(|_| RecordingError::Malformed)?;
        u32be(&mut header, s.duration); u32be(&mut header, s.range.len() as u32);
        u32be(&mut header, if s.idr { 0x0200_0000 } else { 0x0101_0000 });
        header.extend_from_slice(&composition.to_be_bytes());
        for (nal_index, m) in index.mappings[s.mappings.clone()].iter().enumerate() {
            if m.sample != sample_index || m.nal != nal_index { return Err(RecordingError::Malformed); }
            let bytes = target(m, objects)?;
            match &m.target {
                NalTarget::Initialization(r) => {
                    if !((bytes[0] & 31 == 7 && r == &index.sps) || (bytes[0] & 31 == 8 && r == &index.pps)) {
                        return Err(RecordingError::Malformed);
                    }
                }
                NalTarget::Media(r) => {
                    if matches!(bytes[0] & 31, 7 | 8) || r.start != cursor + 4 || r.end > s.range.end {
                        return Err(RecordingError::Malformed);
                    }
                    let prefix = objects.media.get(cursor..r.start).ok_or(RecordingError::Malformed)?;
                    if prefix != (bytes.len() as u32).to_be_bytes() { return Err(RecordingError::Malformed); }
                    cursor = r.end;
                }
            }
        }
        if cursor != s.range.end { return Err(RecordingError::Malformed); }
        map_cursor = s.mappings.end;
    }
    if cursor != objects.media.len() || map_cursor != index.mappings.len() { return Err(RecordingError::Malformed); }
    box_header(&mut header, objects.media.len() - offset + 8, b"mdat");
    if header != objects.media[..offset] { return Err(RecordingError::Malformed); }
    Ok(())
}
fn u32be(out: &mut Vec<u8>, n: u32) { out.extend_from_slice(&n.to_be_bytes()); }
fn box_header(out: &mut Vec<u8>, n: usize, kind: &[u8; 4]) {
    u32be(out, n as u32); out.extend_from_slice(kind);
}
