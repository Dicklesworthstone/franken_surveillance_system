#![forbid(unsafe_code)]

use std::ops::Range;

use super::*;
use crate::site::parse_manifest;

const MANIFEST: &[u8] = include_bytes!("../../../../fixtures/site_probe/manifest.v1.json");
const AVC_DESCRIPTION: &[u8] = include_bytes!("../../../../fixtures/site_probe/avc.describe.rtsp");
const AVC_RTP: &[u8] = include_bytes!("../../../../fixtures/site_probe/avc.rtpdump");
const HEVC_DESCRIPTION: &[u8] =
    include_bytes!("../../../../fixtures/site_probe/hevc.describe.rtsp");
const HEVC_RTP: &[u8] = include_bytes!("../../../../fixtures/site_probe/hevc.rtpdump");
const JPEG_DESCRIPTION: &[u8] =
    include_bytes!("../../../../fixtures/site_probe/jpeg.describe.rtsp");
const JPEG_RTP: &[u8] = include_bytes!("../../../../fixtures/site_probe/jpeg.rtpdump");
const SOURCE: &str = "source:front";
const FIRST: u32 = 0xffff_f000;
const TICKS: u32 = 3600;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn selection(codec: ProbeCodec) -> ProbeSelection {
    ProbeSelection {
        codec,
        media_index: 0,
        rtp_channel: 0,
    }
}

fn measured(codec: ProbeCodec, description: &[u8], rtp: &[u8]) -> Test<MeasuredProbe> {
    Ok(measure_probe(
        &parse_manifest(MANIFEST)?,
        SOURCE,
        &selection(codec),
        description,
        rtp,
    )?)
}

fn packet_spans(bytes: &[u8]) -> Test<Vec<Range<usize>>> {
    let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())?;
    let mut spans = Vec::new();
    while let Some(record) = reader.next_record()? {
        if record.kind() == RtpDumpKind::Rtp {
            spans.push(record.packet_span());
        }
    }
    Ok(spans)
}

fn record_spans(bytes: &[u8]) -> Test<Vec<Range<usize>>> {
    let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())?;
    let mut spans = Vec::new();
    while let Some(record) = reader.next_record()? {
        spans.push(record.span());
    }
    Ok(spans)
}

fn replace_timestamp(bytes: &mut [u8], from: u32, to: u32) -> Test {
    for span in packet_spans(bytes)? {
        let packet = RtpPacket::parse(&bytes[span.clone()], PacketLimits::default())?;
        if packet.timestamp() == from {
            bytes[span.start + 4..span.start + 8].copy_from_slice(&to.to_be_bytes());
        }
    }
    Ok(())
}

fn sdp_changed(response: &[u8], edit: impl FnOnce(&str) -> String) -> Test<Vec<u8>> {
    let text = std::str::from_utf8(response)?;
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .ok_or("fixture header boundary")?;
    let body = edit(body);
    let mut output = String::new();
    for header in headers.split("\r\n") {
        if header.starts_with("Content-Length:") {
            output.push_str(&format!("Content-Length: {}\r\n", body.len()));
        } else {
            output.push_str(header);
            output.push_str("\r\n");
        }
    }
    output.push_str("\r\n");
    output.push_str(&body);
    Ok(output.into_bytes())
}

#[test]
fn native_avc_hevc_and_jpeg_measure_exact_wrapping_cadence() -> Test {
    for (codec, response, dump, frames, packets, payload_type, ssrc, sets) in [
        (
            ProbeCodec::Avc,
            AVC_DESCRIPTION,
            AVC_RTP,
            4,
            23,
            96,
            0x1122_3344,
            2,
        ),
        (
            ProbeCodec::Hevc,
            HEVC_DESCRIPTION,
            HEVC_RTP,
            3,
            14,
            98,
            0x5566_7788,
            3,
        ),
        (
            ProbeCodec::Jpeg,
            JPEG_DESCRIPTION,
            JPEG_RTP,
            3,
            6,
            26,
            0x99aa_bbcc,
            0,
        ),
    ] {
        let result = measured(codec, response, dump)?;
        let receipt = result.receipt();
        receipt.validate_for(&parse_manifest(MANIFEST)?)?;
        assert_eq!(receipt.codec, codec);
        assert_eq!(receipt.payload_type, payload_type);
        assert_eq!(receipt.ssrc, ssrc);
        assert_eq!(receipt.frame_duration_ticks, TICKS);
        assert_eq!(receipt.clock_rate_hz, 90_000);
        assert_eq!(receipt.observed_frames, frames);
        assert_eq!(receipt.first_rtp_timestamp, FIRST);
        assert_eq!(
            receipt.last_rtp_timestamp,
            FIRST.wrapping_add(TICKS * (frames - 1))
        );
        assert!(receipt.last_rtp_timestamp < receipt.first_rtp_timestamp);
        assert_eq!(receipt.parameter_set_digests.len(), sets);
        assert_eq!(result.rtp_packets(), packets);
        assert_eq!(result.rtcp_packets(), 0);
        assert_eq!(result.describe_digest(), ContentDigest::sha256(response));
        assert_eq!(result.rtp_dump_digest(), ContentDigest::sha256(dump));
        assert_eq!(result, measured(codec, response, dump)?);
    }
    Ok(())
}

#[test]
fn full_response_and_dump_metadata_are_bound_without_becoming_measured_facts() -> Test {
    let baseline = measured(ProbeCodec::Avc, AVC_DESCRIPTION, AVC_RTP)?;
    let mut changed_dump = AVC_RTP.to_vec();
    let preamble = changed_dump
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("header")?
        + 1;
    changed_dump[preamble] ^= 0x80;
    let changed = measured(ProbeCodec::Avc, AVC_DESCRIPTION, &changed_dump)?;
    assert_eq!(baseline.receipt(), changed.receipt());
    assert_ne!(baseline.evidence_digest(), changed.evidence_digest());
    let response = std::str::from_utf8(AVC_DESCRIPTION)?.replace("CSeq: 2", "CSeq: 79");
    let changed = measured(ProbeCodec::Avc, response.as_bytes(), AVC_RTP)?;
    assert_eq!(baseline.receipt(), changed.receipt());
    assert_ne!(baseline.evidence_digest(), changed.evidence_digest());
    // Supplied recording offsets are opaque metadata, not trusted timing evidence.
    for record in record_spans(&changed_dump)? {
        changed_dump[record.start + 4..record.start + 8].copy_from_slice(&u32::MAX.to_be_bytes());
    }
    let changed = measured(ProbeCodec::Avc, AVC_DESCRIPTION, &changed_dump)?;
    assert_eq!(baseline.receipt(), changed.receipt());
    assert_ne!(baseline.evidence_digest(), changed.evidence_digest());
    Ok(())
}

#[test]
fn manifest_and_operator_channel_selection_rebind_the_evidence() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let baseline = measure_probe(
        &manifest,
        SOURCE,
        &selection(ProbeCodec::Avc),
        AVC_DESCRIPTION,
        AVC_RTP,
    )?;
    let mut chosen = selection(ProbeCodec::Avc);
    chosen.rtp_channel = 6;
    let changed = measure_probe(&manifest, SOURCE, &chosen, AVC_DESCRIPTION, AVC_RTP)?;
    assert_eq!(changed.receipt().rtp_channel, 6);
    assert_eq!(changed.receipt().rtcp_channel, 7);
    assert_eq!(changed.receipt().ssrc, baseline.receipt().ssrc);
    assert_ne!(changed.evidence_digest(), baseline.evidence_digest());
    let mut renamed = manifest;
    renamed.generation += 1;
    let changed = measure_probe(
        &renamed,
        SOURCE,
        &selection(ProbeCodec::Avc),
        AVC_DESCRIPTION,
        AVC_RTP,
    )?;
    assert_ne!(changed.evidence_digest(), baseline.evidence_digest());
    assert_eq!(changed.receipt().manifest_digest, renamed.digest()?);
    Ok(())
}

#[test]
fn server_header_is_digest_only_or_explicitly_unknown() -> Test {
    let result = measured(ProbeCodec::Avc, AVC_DESCRIPTION, AVC_RTP)?;
    let digest = ContentDigest::sha256(b"fixture-private-server-canary");
    assert_eq!(result.server_header_digest(), Some(digest));
    assert_eq!(
        result.receipt().server_identity,
        format!("server-header:{digest}")
    );
    assert!(!format!("{result:?}").contains("fixture-private-server-canary"));
    assert!(!format!("{result:?}").contains("camera-10.example"));
    let response = std::str::from_utf8(AVC_DESCRIPTION)?
        .replace("Server: fixture-private-server-canary\r\n", "");
    let unknown = measured(ProbeCodec::Avc, response.as_bytes(), AVC_RTP)?;
    assert_eq!(unknown.server_header_digest(), None);
    assert_eq!(
        unknown.receipt().server_identity,
        "unknown:server-not-reported"
    );
    assert_ne!(unknown.evidence_digest(), result.evidence_digest());
    for extra in [
        "Server: another-private-value\r\n",
        "sErVeR: another-private-value\r\n",
    ] {
        let response = std::str::from_utf8(AVC_DESCRIPTION)?
            .replace("CSeq: 2\r\n", &format!("CSeq: 2\r\n{extra}"));
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                response.as_bytes(),
                AVC_RTP
            ),
            Err(SiteProbeError::ServerHeader)
        );
    }
    Ok(())
}

#[test]
fn loss_duplicate_reorder_and_sender_or_payload_changes_refuse_the_whole_trace() -> Test {
    let spans = packet_spans(AVC_RTP)?;
    let span = spans.get(8).ok_or("packet")?;
    for (offset, replacement, expected) in [
        (2, vec![0, 99], SiteProbeError::Sequence),
        (2, vec![0, 5], SiteProbeError::Sequence),
        (8, vec![0, 0, 0, 0], SiteProbeError::StreamChanged),
        (1, vec![127], SiteProbeError::StreamChanged),
    ] {
        let mut changed = AVC_RTP.to_vec();
        changed[span.start + offset..span.start + offset + replacement.len()]
            .copy_from_slice(&replacement);
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                AVC_DESCRIPTION,
                &changed
            ),
            Err(expected)
        );
    }
    let records = record_spans(AVC_RTP)?;
    let removed = records.get(8).ok_or("record")?;
    let mut changed = AVC_RTP.to_vec();
    changed.drain(removed.clone());
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &changed
        ),
        Err(SiteProbeError::Sequence)
    );
    let mut changed = AVC_RTP.to_vec();
    changed.splice(
        removed.start..removed.start,
        AVC_RTP[removed.clone()].iter().copied(),
    );
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &changed
        ),
        Err(SiteProbeError::Sequence)
    );
    Ok(())
}

#[test]
fn zero_ssrc_is_an_exact_observation_not_an_automatic_selection_sentinel() -> Test {
    let mut changed = AVC_RTP.to_vec();
    for span in packet_spans(AVC_RTP)? {
        changed[span.start + 8..span.start + 12].fill(0);
    }
    let result = measured(ProbeCodec::Avc, AVC_DESCRIPTION, &changed)?;
    assert_eq!(result.receipt().ssrc, 0);
    Ok(())
}

#[test]
fn variable_zero_reverse_and_over_bound_cadence_are_refused() -> Test {
    for timestamp in [
        FIRST.wrapping_add(TICKS + 1),
        FIRST,
        FIRST.wrapping_sub(1),
        FIRST.wrapping_add(90_001),
    ] {
        let mut changed = AVC_RTP.to_vec();
        replace_timestamp(&mut changed, FIRST.wrapping_add(TICKS), timestamp)?;
        assert!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                AVC_DESCRIPTION,
                &changed
            )
            .is_err()
        );
    }
    let mut changed = AVC_RTP.to_vec();
    replace_timestamp(
        &mut changed,
        FIRST.wrapping_add(TICKS * 3),
        FIRST.wrapping_add(TICKS * 3 + 1),
    )?;
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &changed
        ),
        Err(SiteProbeError::Cadence)
    );
    Ok(())
}

#[test]
fn exact_framing_and_capture_prefixes_cannot_be_repaired() -> Test {
    for tail in [&AVC_RTP[..AVC_RTP.len() - 1], b"#!rtpplay1.0 0.0.0.0/0\n"] {
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                AVC_DESCRIPTION,
                tail
            ),
            Err(SiteProbeError::RtpDump)
        );
    }
    let first = record_spans(AVC_RTP)?.first().cloned().ok_or("record")?;
    let mut changed = AVC_RTP.to_vec();
    let claimed = u16::from_be_bytes([changed[first.start + 2], changed[first.start + 3]]) + 1;
    changed[first.start + 2..first.start + 4].copy_from_slice(&claimed.to_be_bytes());
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &changed
        ),
        Err(SiteProbeError::RtpDump)
    );
    let mut changed = AVC_RTP.to_vec();
    changed.extend_from_slice(&[0]);
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &changed
        ),
        Err(SiteProbeError::RtpDump)
    );
    Ok(())
}

#[test]
fn a_picture_or_fragment_without_an_observed_boundary_never_becomes_a_receipt() -> Test {
    let mut changed = AVC_RTP.to_vec();
    let last = packet_spans(&changed)?
        .last()
        .cloned()
        .ok_or("last packet")?;
    changed[last.start + 1] &= 0x7f;
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &changed
        ),
        Err(SiteProbeError::IncompletePicture)
    );
    let last = record_spans(AVC_RTP)?
        .last()
        .cloned()
        .ok_or("last record")?;
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &AVC_RTP[..last.start]
        ),
        Err(SiteProbeError::IncompletePicture)
    );
    // The HEVC stream still carries RTP markers when its syntax EOS is removed.
    let eos = record_spans(HEVC_RTP)?
        .last()
        .cloned()
        .ok_or("EOS record")?;
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Hevc),
            HEVC_DESCRIPTION,
            &HEVC_RTP[..eos.start]
        ),
        Err(SiteProbeError::IncompletePicture)
    );
    Ok(())
}

#[test]
fn too_short_samples_and_marker_only_payloads_do_not_create_picture_facts() -> Test {
    let mut reader = RtpDumpReader::new(AVC_RTP, RtpDumpLimits::default())?;
    let mut boundary = None;
    while let Some(record) = reader.next_record()? {
        let packet = RtpPacket::parse(record.packet(), PacketLimits::default())?;
        if packet.timestamp() == FIRST.wrapping_add(TICKS * 2) {
            boundary = Some(record.span().start);
            break;
        }
    }
    let short = &AVC_RTP[..boundary.ok_or("third picture")?];
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            short
        ),
        Err(SiteProbeError::InsufficientPictures)
    );
    let header = RtpDumpReader::new(AVC_RTP, RtpDumpLimits::default())?.header_span();
    let mut dump = AVC_RTP[header].to_vec();
    for index in 0u16..4 {
        let mut packet = vec![0x80, 0x80 | 96];
        packet.extend_from_slice(&index.to_be_bytes());
        packet.extend_from_slice(&(u32::from(index) * TICKS).to_be_bytes());
        packet.extend_from_slice(&17u32.to_be_bytes());
        packet.extend_from_slice(&[9, 0xf0]); // A marked AUD is not a primary picture.
        dump.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
        dump.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        dump.extend_from_slice(&0u32.to_be_bytes());
        dump.extend_from_slice(&packet);
    }
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &dump
        ),
        Err(SiteProbeError::InsufficientPictures)
    );
    Ok(())
}

#[test]
fn configuration_drift_is_not_silently_adopted() -> Test {
    for (codec, response, dump, parameter_kind) in [
        (ProbeCodec::Avc, AVC_DESCRIPTION, AVC_RTP, 7),
        (ProbeCodec::Hevc, HEVC_DESCRIPTION, HEVC_RTP, 32),
    ] {
        let mut changed = dump.to_vec();
        let mut found = false;
        for span in packet_spans(dump)? {
            let packet = RtpPacket::parse(&dump[span.clone()], PacketLimits::default())?;
            let payload = packet.payload();
            let kind = if codec == ProbeCodec::Avc {
                payload[0] & 31
            } else {
                (payload[0] >> 1) & 63
            };
            if kind == parameter_kind {
                changed[span.end - 1] ^= 1;
                found = true;
                break;
            }
        }
        assert!(found);
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(codec),
                response,
                &changed
            ),
            Err(SiteProbeError::ParameterChange)
        );
    }
    Ok(())
}

#[test]
fn native_description_scope_codec_and_ambiguity_rules_remain_in_force() -> Test {
    for response in [
        sdp_changed(AVC_DESCRIPTION, |body| {
            body.replace("trackID=0", "rtsp://evil.example/live/track")
        })?,
        sdp_changed(AVC_DESCRIPTION, |body| {
            body.replace("H264/90000", "H264/48000")
        })?,
        sdp_changed(AVC_DESCRIPTION, |body| {
            body.replace("packetization-mode=1", "packetization-mode=2")
        })?,
        sdp_changed(AVC_DESCRIPTION, |body| {
            body.replace(
                "m=video 0 RTP/AVP 96\r\n",
                "m=video 0 RTP/AVP 96 97\r\na=rtpmap:97 H264/90000\r\n",
            )
        })?,
    ] {
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                &response,
                AVC_RTP
            ),
            Err(SiteProbeError::Description)
        );
    }
    let don = sdp_changed(HEVC_DESCRIPTION, |body| {
        body.replace("sprop-vps=", "sprop-max-don-diff=1;sprop-vps=")
    })?;
    assert_eq!(
        measure_probe(
            &parse_manifest(MANIFEST)?,
            SOURCE,
            &selection(ProbeCodec::Hevc),
            &don,
            HEVC_RTP
        ),
        Err(SiteProbeError::Description)
    );
    Ok(())
}

#[test]
fn complete_response_is_exactly_one_successful_strict_message() -> Test {
    let mut doubled = AVC_DESCRIPTION.to_vec();
    doubled.extend_from_slice(AVC_DESCRIPTION);
    let mut suffix = AVC_DESCRIPTION.to_vec();
    suffix.extend_from_slice(b"X");
    for response in [
        doubled,
        suffix,
        AVC_DESCRIPTION[..AVC_DESCRIPTION.len() - 1].to_vec(),
        std::str::from_utf8(AVC_DESCRIPTION)?
            .replace("\r\n", "\n")
            .into_bytes(),
        std::str::from_utf8(AVC_DESCRIPTION)?
            .replace("200 OK", "401 Unauthorized")
            .into_bytes(),
        std::str::from_utf8(AVC_DESCRIPTION)?
            .replace("CSeq: 2", "CSeq: -1")
            .into_bytes(),
        std::str::from_utf8(AVC_DESCRIPTION)?
            .replace("CSeq: 2", "CSeq: 4294967296")
            .into_bytes(),
    ] {
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                &response,
                AVC_RTP
            ),
            Err(SiteProbeError::Description)
        );
    }
    Ok(())
}

#[test]
fn public_values_and_resource_bounds_are_checked_before_receipt_production() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    assert_eq!(
        measure_probe(
            &manifest,
            "unknown",
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            AVC_RTP
        ),
        Err(SiteProbeError::Source)
    );
    for bad in [
        ProbeSelection {
            codec: ProbeCodec::Jpeg,
            media_index: 64,
            rtp_channel: 0,
        },
        ProbeSelection {
            codec: ProbeCodec::Avc,
            media_index: 64,
            rtp_channel: 0,
        },
        ProbeSelection {
            codec: ProbeCodec::Avc,
            media_index: 0,
            rtp_channel: 1,
        },
        ProbeSelection {
            codec: ProbeCodec::Avc,
            media_index: 0,
            rtp_channel: 255,
        },
    ] {
        assert_eq!(
            measure_probe(&manifest, SOURCE, &bad, AVC_DESCRIPTION, AVC_RTP),
            Err(SiteProbeError::Selection)
        );
    }
    let mut invalid = manifest.clone();
    invalid.generation = 0;
    assert_eq!(
        measure_probe(
            &invalid,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            AVC_RTP
        ),
        Err(SiteProbeError::Manifest)
    );
    let oversized = vec![0; MAX_DESCRIBE_RESPONSE_BYTES + 1];
    assert_eq!(
        measure_probe(
            &manifest,
            SOURCE,
            &selection(ProbeCodec::Avc),
            &oversized,
            AVC_RTP
        ),
        Err(SiteProbeError::Limit)
    );
    let oversized = vec![0; MAX_PROBE_RTPDUMP_BYTES + 1];
    assert_eq!(
        measure_probe(
            &manifest,
            SOURCE,
            &selection(ProbeCodec::Avc),
            AVC_DESCRIPTION,
            &oversized
        ),
        Err(SiteProbeError::Limit)
    );
    let mut cadence = Cadence::default();
    for index in 0..MAX_MEASURED_PROBE_FRAMES {
        cadence.observe(index)?;
    }
    assert_eq!(
        cadence.observe(MAX_MEASURED_PROBE_FRAMES),
        Err(SiteProbeError::Limit)
    );
    Ok(())
}

#[test]
fn field_and_mbaff_syntax_cannot_mint_frame_cadence() -> Test {
    use fss_packet::avc::{AvcSyntaxLimits, parse_pps, parse_slice_identity, parse_sps};

    // Exact syntax-only counterexamples from the field-picture construction in
    // fss-packet/tests/avc_syntax_contract.rs. These are deliberately NOT decoded
    // pictures: they prove why the packet syntax owner's broader field support
    // must not become an admitted footage configuration.
    let pps_bytes = [0x68, 0xce, 0x38, 0x80];
    let slices = [[0x41, 0xe1, 0x04], [0x41, 0xe1, 0x8c], [0x41, 0xe3, 0x14]];
    for (sps_bytes, encoded) in [
        (
            [0x67, 0x42, 0x00, 0x1f, 0xf4, 0x14, 0x20, 0x90],
            "Z0IAH/QUIJA=",
        ),
        (
            [0x67, 0x42, 0x00, 0x1f, 0xf4, 0x14, 0x21, 0x90],
            "Z0IAH/QUIZA=",
        ),
    ] {
        let syntax = AvcSyntaxLimits::default();
        let sps = parse_sps(&sps_bytes, syntax)?;
        assert!(!sps.frame_mbs_only());
        let pps = parse_pps(&pps_bytes, &sps, syntax)?;
        let mut previous = None;
        for slice in &slices {
            let identity = parse_slice_identity(slice, &sps, &pps, syntax)?;
            assert!(identity.field_pic());
            assert_eq!(identity.first_mb_in_slice(), 0);
            if let Some(previous) = previous {
                assert!(identity.starts_new_picture(previous));
            }
            previous = Some(identity);
        }
        let body = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=field syntax counterexample\r\n\
             t=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
             a=fmtp:96 packetization-mode=1;sprop-parameter-sets={encoded},aM44gA==\r\n\
             a=control:trackID=0\r\n"
        );
        let response = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let header = RtpDumpReader::new(AVC_RTP, RtpDumpLimits::default())?.header_span();
        let mut dump = AVC_RTP[header].to_vec();
        for (index, slice) in slices.iter().enumerate() {
            let mut packet = vec![0x80, 0x80 | 96];
            packet.extend_from_slice(&(index as u16).to_be_bytes());
            packet.extend_from_slice(&(index as u32 * 1800).to_be_bytes());
            packet.extend_from_slice(&17u32.to_be_bytes());
            packet.extend_from_slice(slice);
            dump.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
            dump.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            dump.extend_from_slice(&0u32.to_be_bytes());
            dump.extend_from_slice(&packet);
        }
        assert_eq!(
            measure_probe(
                &parse_manifest(MANIFEST)?,
                SOURCE,
                &selection(ProbeCodec::Avc),
                response.as_bytes(),
                &dump,
            ),
            Err(SiteProbeError::Codec)
        );
    }
    Ok(())
}

#[test]
fn hevc_vui_field_sequence_cannot_mint_frame_cadence() -> Test {
    use crate::rtsp::client::observed::ObservedVideoDescription;
    use fss_codec_h265::nal::{NalHeader, rbsp_from_ebsp};
    use fss_codec_h265::{DecodeError, UnsupportedFeature};
    use fss_packet::hevc::{HevcConfiguration, HevcConfigurationLimits};

    const ORIGINAL_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaAgAAADACAAAAMBQQ==";
    const FIELD_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaEgAAADACAAAAMBQQ==";
    let manifest = parse_manifest(MANIFEST)?;
    let source = manifest.sources.first().ok_or("fixture source")?;
    let observed = description::inspect(source, &selection(ProbeCodec::Hevc), HEVC_DESCRIPTION)?;
    let ObservedVideoDescription::Hevc(media) = observed.media else {
        return Err("fixture must select HEVC".into());
    };
    let original = media.sps().first().ok_or("fixture SPS")?;
    let mut changed_sps = original.clone();
    // A native-parser-confirmed single-bit mutation of the real codec fixture:
    // VUI field_seq_flag is beyond the packet owner's configuration prefix.
    *changed_sps.get_mut(28).ok_or("fixture field flag")? ^= 0x01;
    assert_eq!(changed_sps, crate::rtsp::decode_base64(FIELD_SPS)?);
    assert_eq!(*original, crate::rtsp::decode_base64(ORIGINAL_SPS)?);
    let prefix = HevcConfiguration::parse(
        media.vps().first().ok_or("fixture VPS")?,
        &changed_sps,
        media.pps().first().ok_or("fixture PPS")?,
        HevcConfigurationLimits::default(),
    )?;
    assert_eq!(prefix.bit_depth(), 8);
    let (_, original_escaped) = NalHeader::split(original)?;
    fss_codec_h265::params::parse_sps(&rbsp_from_ebsp(original_escaped, 16_384)?)?;
    let (_, changed_escaped) = NalHeader::split(&changed_sps)?;
    assert!(matches!(
        fss_codec_h265::params::parse_sps(&rbsp_from_ebsp(changed_escaped, 16_384)?),
        Err(DecodeError::Unsupported(UnsupportedFeature::Interlaced))
    ));

    let response = sdp_changed(HEVC_DESCRIPTION, |body| {
        body.replace(ORIGINAL_SPS, FIELD_SPS)
    })?;
    let mut dump = HEVC_RTP.to_vec();
    let mut changed_packets = 0;
    for span in packet_spans(HEVC_RTP)? {
        let packet = RtpPacket::parse(&HEVC_RTP[span.clone()], PacketLimits::default())?;
        if packet.payload() == original {
            let payload = packet.payload_range();
            dump[span.start + payload.start..span.start + payload.end]
                .copy_from_slice(&changed_sps);
            changed_packets += 1;
        }
    }
    assert_eq!(changed_packets, 1);
    // In-band and SDP parameter bytes agree, every RTP packet remains complete,
    // and EOS still closes all three groups. Field signaling itself must refuse.
    assert_eq!(
        measure_probe(
            &manifest,
            SOURCE,
            &selection(ProbeCodec::Hevc),
            &response,
            &dump,
        ),
        Err(SiteProbeError::Codec)
    );
    Ok(())
}

#[test]
fn recorded_jpeg_uses_native_static_and_dynamic_payload_selection_without_fallback() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let dynamic = sdp_changed(JPEG_DESCRIPTION, |body| {
        body.replace(
            "m=video 0 RTP/AVP 26\r\n",
            "m=video 0 RTP/AVP 99\r\na=rtpmap:99 JPEG/90000\r\n",
        )
    })?;
    let mut dump = JPEG_RTP.to_vec();
    for span in packet_spans(JPEG_RTP)? {
        dump[span.start + 1] = (dump[span.start + 1] & 0x80) | 99;
    }
    let result = measured(ProbeCodec::Jpeg, &dynamic, &dump)?;
    assert_eq!(result.receipt().payload_type, 99);
    assert_eq!(result.receipt().observed_frames, 3);
    assert!(result.receipt().parameter_set_digests.is_empty());

    for bad in [
        sdp_changed(&dynamic, |body| {
            body.replace("a=rtpmap:99 JPEG/90000\r\n", "")
        })?,
        sdp_changed(&dynamic, |body| body.replace("JPEG/90000", "H264/90000"))?,
        sdp_changed(&dynamic, |body| body.replace("RTP/AVP 99", "RTP/AVP 26 99"))?,
        sdp_changed(&dynamic, |body| format!("{body}a=fmtp:99 quality=50\r\n"))?,
        sdp_changed(JPEG_DESCRIPTION, |body| {
            format!("{body}a=rtpmap:26 H264/90000\r\n")
        })?,
    ] {
        assert_eq!(
            measure_probe(&manifest, SOURCE, &selection(ProbeCodec::Jpeg), &bad, &dump),
            Err(SiteProbeError::Description)
        );
    }
    Ok(())
}

#[test]
fn recorded_jpeg_requires_whole_frames_and_contiguous_single_source_cadence() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let spans = packet_spans(JPEG_RTP)?;
    let records = record_spans(JPEG_RTP)?;
    let missing_end = &JPEG_RTP[..records.last().ok_or("fixture record")?.start];
    assert_eq!(
        measure_probe(
            &manifest,
            SOURCE,
            &selection(ProbeCodec::Jpeg),
            JPEG_DESCRIPTION,
            missing_end
        ),
        Err(SiteProbeError::IncompletePicture)
    );
    for (fault, expected) in [
        (0, SiteProbeError::Sequence),
        (1, SiteProbeError::StreamChanged),
        (2, SiteProbeError::Cadence),
        (3, SiteProbeError::IncompletePicture),
        (4, SiteProbeError::Codec),
    ] {
        let mut dump = JPEG_RTP.to_vec();
        let second = spans[1].start;
        match fault {
            0 => dump[second + 3] ^= 1,
            1 => dump[second + 11] ^= 1,
            2 => replace_timestamp(
                &mut dump,
                FIRST.wrapping_add(2 * TICKS),
                FIRST.wrapping_add(2 * TICKS + 1),
            )?,
            3 => dump[spans.last().ok_or("fixture last packet")?.start + 1] &= 0x7f,
            _ => dump[spans[0].start + 15] = 1,
        }
        assert_eq!(
            measure_probe(
                &manifest,
                SOURCE,
                &selection(ProbeCodec::Jpeg),
                JPEG_DESCRIPTION,
                &dump
            ),
            Err(expected)
        );
    }
    Ok(())
}
