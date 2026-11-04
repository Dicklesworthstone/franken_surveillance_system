#![forbid(unsafe_code)]

use super::*;
use crate::ingest::rtpdump::{RtpDumpKind, RtpDumpLimits, RtpDumpReader};
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
const FIRST: u32 = 0xffff_f000;
const TICKS: u32 = 3600;
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn body(response: &[u8]) -> Test<&[u8]> {
    let (_, body) = std::str::from_utf8(response)?
        .split_once("\r\n\r\n")
        .ok_or("fixture header boundary")?;
    Ok(body.as_bytes())
}

fn from_sdp<'a>(
    manifest: &'a SiteManifest,
    codec: ProbeCodec,
    sdp: &[u8],
) -> Result<RtspProbeObserver<'a>, ObservationError> {
    let (payload_type, parameters) = match codec {
        ProbeCodec::Avc => {
            let session = select_h264_description(sdp, 0, Some(96))
                .map_err(|_| ObservationError::Negotiation)?;
            let media = session.media.first().ok_or(ObservationError::Negotiation)?;
            (
                96,
                vec![
                    media.sps.clone().ok_or(ObservationError::Negotiation)?,
                    media.pps.clone().ok_or(ObservationError::Negotiation)?,
                ],
            )
        }
        ProbeCodec::Hevc => {
            let (session, projected) = select_h265_description(sdp, 0, Some(98))
                .map_err(|_| ObservationError::Negotiation)?;
            let media = session.media.first().ok_or(ObservationError::Negotiation)?;
            let selected =
                hevc::negotiate(&projected, 0, media).map_err(|_| ObservationError::Negotiation)?;
            let ([vps], [sps], [pps]) = (selected.vps(), selected.sps(), selected.pps()) else {
                return Err(ObservationError::Negotiation);
            };
            (98, vec![vps.clone(), sps.clone(), pps.clone()])
        }
        ProbeCodec::Jpeg => (26, Vec::new()),
    };
    let parameters = parameters.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RtspProbeObserver::new(
        manifest,
        0,
        NegotiatedProbe {
            sdp,
            media_index: 0,
            rtp_channel: 0,
            codec,
            payload_type,
            parameter_sets: &parameters,
            server_identity: "fixture",
        },
    )
}

fn probe(manifest: &SiteManifest, codec: ProbeCodec) -> Test<RtspProbeObserver<'_>> {
    let description = match codec {
        ProbeCodec::Avc => AVC_DESCRIPTION,
        ProbeCodec::Hevc => HEVC_DESCRIPTION,
        ProbeCodec::Jpeg => JPEG_DESCRIPTION,
    };
    Ok(from_sdp(manifest, codec, body(description)?)?)
}

fn packets(codec: ProbeCodec) -> Test<Vec<Vec<u8>>> {
    let bytes = match codec {
        ProbeCodec::Avc => AVC_RTP,
        ProbeCodec::Hevc => HEVC_RTP,
        ProbeCodec::Jpeg => JPEG_RTP,
    };
    let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())?;
    let mut packets = Vec::new();
    while let Some(record) = reader.next_record()? {
        if record.kind() == RtpDumpKind::Rtp {
            packets.push(record.packet().to_vec());
        }
    }
    Ok(packets)
}

fn marked_packet(seq: u16, timestamp: u32, payload_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0x80 | payload_type];
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&0x1122_3344u32.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn real_native_groups_preserve_sequence_and_timestamp_wrap() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    for (codec, count, ssrc) in [
        (ProbeCodec::Avc, 4, 0x1122_3344),
        (ProbeCodec::Hevc, 3, 0x5566_7788),
        (ProbeCodec::Jpeg, 3, 0x99aa_bbcc),
    ] {
        let mut observer = probe(&manifest, codec)?;
        let input = packets(codec)?;
        assert!(input.len() > count as usize);
        for packet in &input {
            observer.observe_rtp(0, packet)?;
        }
        assert_eq!(observer.confirmed_pictures(), count);
        let receipt = observer.finish()?;
        assert_eq!(receipt.observed_frames, count);
        assert_eq!(receipt.ssrc, ssrc);
        assert_eq!(receipt.frame_duration_ticks, TICKS);
        assert_eq!(receipt.first_rtp_timestamp, FIRST);
        assert_eq!(
            receipt.last_rtp_timestamp,
            FIRST.wrapping_add(TICKS * (count - 1))
        );
        receipt.validate_for(&manifest)?;
    }
    Ok(())
}

#[test]
fn native_avc_prefix_without_markers_has_an_explicit_unverified_tail() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let mut observer = probe(&manifest, ProbeCodec::Avc)?;
    let mut input = packets(ProbeCodec::Avc)?;
    for packet in &mut input {
        packet[1] &= 0x7f;
    }
    let mut admitted = 0;
    for packet in &input {
        observer.observe_rtp(0, packet)?;
        admitted += 1;
        if observer.confirmed_pictures() >= 3 {
            break;
        }
    }
    assert_eq!(observer.confirmed_pictures(), 3);
    assert!(admitted > 3);
    assert!(admitted < input.len());
    let tail = observer.freeze_prefix()?;
    assert!(tail.unverified_nal_bytes_excluded > 0);
    assert_eq!(tail.unfinished_fragment_bytes_excluded, 0);
    assert_eq!(observer.freeze_prefix(), Err(ObservationError::Incomplete));
    let receipt = observer.finish_prefix()?;
    assert_eq!(receipt.observed_frames, 3);
    assert_eq!(receipt.last_rtp_timestamp, FIRST.wrapping_add(TICKS * 2));
    assert_eq!(receipt.frame_duration_ticks, TICKS);
    Ok(())
}

#[test]
fn strict_evidence_and_explicit_live_prefix_have_different_tail_contracts() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let mut input = packets(ProbeCodec::Avc)?;
    for packet in &mut input {
        packet[1] &= 0x7f;
    }
    let mut strict = probe(&manifest, ProbeCodec::Avc)?;
    let mut live = probe(&manifest, ProbeCodec::Avc)?;
    for packet in &input {
        strict.observe_rtp(0, packet)?;
        live.observe_rtp(0, packet)?;
    }
    assert_eq!(strict.confirmed_pictures(), 3);
    assert!(matches!(strict.finish(), Err(ObservationError::Incomplete)));
    let tail = live.freeze_prefix()?;
    assert!(tail.unverified_nal_bytes_excluded > 0);
    assert_eq!(live.finish_prefix()?.observed_frames, 3);
    Ok(())
}

#[test]
fn hevc_marker_does_not_replace_the_missing_final_syntax_boundary() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let mut input = packets(ProbeCodec::Hevc)?;
    let eos = input.pop().ok_or("fixture EOS")?;
    let eos = RtpPacket::parse(&eos, PacketLimits::default())?;
    assert_eq!(eos.payload(), &[0x48, 0x01, 0x80]);
    let mut observer = probe(&manifest, ProbeCodec::Hevc)?;
    for packet in &input {
        observer.observe_rtp(0, packet)?;
    }
    assert_eq!(observer.confirmed_pictures(), 2);
    assert_eq!(observer.freeze_prefix(), Err(ObservationError::Incomplete));
    assert!(matches!(
        observer.finish(),
        Err(ObservationError::Incomplete)
    ));
    Ok(())
}

#[test]
fn arbitrary_marked_payloads_never_become_picture_observations() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    for (codec, payload_type, payload) in [
        (ProbeCodec::Avc, 96, &[0x65, 0x00][..]),
        (ProbeCodec::Hevc, 98, &[0x02, 0x01, 0x00][..]),
    ] {
        let mut observer = probe(&manifest, codec)?;
        for index in 0..3 {
            let packet = marked_packet(index, u32::from(index) * TICKS, payload_type, payload);
            if observer.observe_rtp(0, &packet).is_err() {
                break;
            }
        }
        assert!(observer.confirmed_pictures() < 3);
        assert!(observer.freeze_prefix().is_err());
        assert!(observer.finish_prefix().is_err());
    }
    Ok(())
}

#[test]
fn continuity_refusals_poison_the_whole_native_sample() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let input = packets(ProbeCodec::Avc)?;
    for change in 0..4 {
        let mut observer = probe(&manifest, ProbeCodec::Avc)?;
        observer.observe_rtp(0, &input[0])?;
        let mut next = input[1].clone();
        let channel = match change {
            0 => {
                next[2..4].copy_from_slice(&0u16.to_be_bytes());
                0
            }
            1 => {
                next[8..12].copy_from_slice(&99u32.to_be_bytes());
                0
            }
            2 => {
                next[1] = (next[1] & 0x80) | 97;
                0
            }
            _ => 2,
        };
        assert!(observer.observe_rtp(channel, &next).is_err());
        assert_eq!(
            observer.observe_rtp(0, &input[1]),
            Err(ObservationError::Continuity)
        );
        assert!(matches!(
            observer.finish(),
            Err(ObservationError::Continuity)
        ));
    }
    Ok(())
}

#[test]
fn codec_configuration_change_and_native_cadence_drift_refuse() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let input = packets(ProbeCodec::Avc)?;
    for configuration_change in [true, false] {
        let mut observer = probe(&manifest, ProbeCodec::Avc)?;
        let mut refusal = None;
        for original in &input {
            let parsed = RtpPacket::parse(original, PacketLimits::default())?;
            let mut packet = original.clone();
            if configuration_change && parsed.payload().first().is_some_and(|b| b & 0x1f == 7) {
                let last = packet.last_mut().ok_or("fixture SPS")?;
                *last ^= 1;
            } else if !configuration_change && parsed.timestamp() == FIRST.wrapping_add(TICKS * 2) {
                packet[4..8].copy_from_slice(&FIRST.wrapping_add(TICKS * 2 + 1).to_be_bytes());
            }
            if let Err(error) = observer.observe_rtp(0, &packet) {
                refusal = Some(error);
                break;
            }
        }
        assert_eq!(
            refusal,
            Some(if configuration_change {
                ObservationError::Negotiation
            } else {
                ObservationError::Cadence
            })
        );
        assert!(observer.finish_prefix().is_err());
    }
    Ok(())
}

#[test]
fn field_coded_avc_and_hevc_descriptions_cannot_measure_frame_cadence() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let original_avc = std::str::from_utf8(body(AVC_DESCRIPTION)?)?;
    for field_sps in ["Z0IAH/QUIJA=", "Z0IAH/QUIZA="] {
        let changed = original_avc.replace(
            "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=",
            &format!("{field_sps},aM44gA=="),
        );
        assert_ne!(changed, original_avc);
        assert!(matches!(
            from_sdp(&manifest, ProbeCodec::Avc, changed.as_bytes()),
            Err(ObservationError::Negotiation)
        ));
    }
    let original_hevc = std::str::from_utf8(body(HEVC_DESCRIPTION)?)?;
    let changed = original_hevc.replace(
        "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaAgAAADACAAAAMBQQ==",
        "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaEgAAADACAAAAMBQQ==",
    );
    assert_ne!(changed, original_hevc);
    assert!(matches!(
        from_sdp(&manifest, ProbeCodec::Hevc, changed.as_bytes()),
        Err(ObservationError::Negotiation)
    ));
    Ok(())
}

#[test]
fn live_cut_accounts_for_an_unfinished_next_fragment_without_counting_it() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let mut observer = probe(&manifest, ProbeCodec::Avc)?;
    let mut cut = false;
    for packet in packets(ProbeCodec::Avc)? {
        let parsed = RtpPacket::parse(&packet, PacketLimits::default())?;
        let payload = parsed.payload();
        let starts_fragment =
            payload.len() >= 2 && payload[0] & 0x1f == 28 && payload[1] & 0x80 != 0;
        observer.observe_rtp(0, &packet)?;
        if observer.confirmed_pictures() == 3 && starts_fragment {
            cut = true;
            break;
        }
    }
    assert!(cut);
    let tail = observer.freeze_prefix()?;
    assert!(tail.unfinished_fragment_bytes_excluded > 0);
    assert_eq!(observer.finish_prefix()?.observed_frames, 3);
    Ok(())
}

#[test]
fn live_fragment_lifetime_uses_the_actual_owner_clock() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let mut observer = probe(&manifest, ProbeCodec::Avc)?;
    let input = packets(ProbeCodec::Avc)?;
    let mut fragment_started = false;
    let mut refused = false;
    for packet in input {
        let parsed = RtpPacket::parse(&packet, PacketLimits::default())?;
        let payload = parsed.payload();
        let starts_fragment =
            payload.len() >= 2 && payload[0] & 0x1f == 28 && payload[1] & 0x80 != 0;
        if fragment_started {
            assert!(observer.observe_rtp_at(0, &packet, 2_000_000_100).is_err());
            refused = true;
            break;
        }
        observer.observe_rtp_at(0, &packet, 1)?;
        fragment_started = starts_fragment;
    }
    assert!(refused);
    assert!(observer.finish_prefix().is_err());
    Ok(())
}

#[test]
fn a_frozen_prefix_cannot_accept_more_input_or_hide_a_prior_refusal() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let mut observer = probe(&manifest, ProbeCodec::Avc)?;
    let input = packets(ProbeCodec::Avc)?;
    for packet in &input {
        observer.observe_rtp(0, packet)?;
        if observer.confirmed_pictures() >= 3 {
            break;
        }
    }
    observer.freeze_prefix()?;
    assert_eq!(
        observer.observe_rtp(0, &input[0]),
        Err(ObservationError::Continuity)
    );
    assert!(matches!(
        observer.finish_prefix(),
        Err(ObservationError::Continuity)
    ));
    Ok(())
}

#[test]
fn jpeg_counts_complete_reconstruction_and_accepts_exact_dynamic_selection() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    for payload_type in [26, 99] {
        let sdp = std::str::from_utf8(body(JPEG_DESCRIPTION)?)?.replace(
            "m=video 0 RTP/AVP 26\r\n",
            &format!("m=video 0 RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} JPEG/90000\r\n"),
        );
        let mut observer = RtspProbeObserver::new(
            &manifest,
            0,
            NegotiatedProbe {
                sdp: sdp.as_bytes(),
                media_index: 0,
                rtp_channel: 0,
                codec: ProbeCodec::Jpeg,
                payload_type,
                parameter_sets: &[],
                server_identity: "fixture",
            },
        )?;
        for (index, mut packet) in packets(ProbeCodec::Jpeg)?.into_iter().enumerate() {
            packet[1] = (packet[1] & 0x80) | payload_type;
            observer.observe_rtp(0, &packet)?;
            assert_eq!(observer.confirmed_pictures(), (index as u32 + 1) / 2);
        }
        assert_eq!(observer.freeze_prefix()?, ProbeTail::default());
        let receipt = observer.finish_prefix()?;
        assert_eq!(receipt.codec, ProbeCodec::Jpeg);
        assert_eq!(receipt.payload_type, payload_type);
        assert!(receipt.parameter_set_digests.is_empty());
        assert_eq!(receipt.observed_frames, 3);
        receipt.validate_for(&manifest)?;
    }
    Ok(())
}

#[test]
fn jpeg_marker_without_reconstructable_header_cannot_mint_a_picture() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    for fault in 0..5 {
        let mut observer = probe(&manifest, ProbeCodec::Jpeg)?;
        let mut packet = packets(ProbeCodec::Jpeg)?.remove(0);
        packet[1] |= 0x80;
        match fault {
            0 => packet.truncate(12), // Marker-only empty payload.
            1 => packet[15] = 1,      // Nonzero fragment offset without an image start.
            2 => packet[16] = 2,      // Unsupported RFC 2435 type.
            3 => packet[17] = 100,    // Reserved quantizer selector.
            _ => packet[18] = 0,      // Unsupported zero-sized dimension.
        }
        assert!(observer.observe_rtp(0, &packet).is_err());
        assert_eq!(observer.confirmed_pictures(), 0);
        assert!(matches!(
            observer.finish(),
            Err(ObservationError::Continuity)
        ));
    }
    Ok(())
}

#[test]
fn jpeg_fragment_expiry_uses_owner_time_and_incomplete_tail_never_becomes_a_frame() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let input = packets(ProbeCodec::Jpeg)?;
    let mut expired = probe(&manifest, ProbeCodec::Jpeg)?;
    expired.observe_rtp_at(0, &input[0], 1)?;
    assert_eq!(expired.confirmed_pictures(), 0);
    assert!(expired.observe_rtp_at(0, &input[1], 2_000_000_001).is_err());
    assert!(matches!(
        expired.finish(),
        Err(ObservationError::Continuity)
    ));

    let mut strict = probe(&manifest, ProbeCodec::Jpeg)?;
    let mut live = probe(&manifest, ProbeCodec::Jpeg)?;
    for packet in &input {
        strict.observe_rtp(0, packet)?;
        live.observe_rtp(0, packet)?;
    }
    // A fourth image starts, but its second fragment is absent. An explicit
    // live cut may exclude that unfinished derivative; strict evidence cannot.
    let mut pending = input[0].clone();
    let last = RtpPacket::parse(
        input.last().ok_or("fixture packet")?,
        PacketLimits::default(),
    )?;
    pending[2..4].copy_from_slice(&last.sequence().wrapping_add(1).to_be_bytes());
    pending[4..8].copy_from_slice(&FIRST.wrapping_add(3 * TICKS).to_be_bytes());
    strict.observe_rtp(0, &pending)?;
    live.observe_rtp(0, &pending)?;
    assert_eq!(live.confirmed_pictures(), 3);
    assert!(matches!(strict.finish(), Err(ObservationError::Incomplete)));
    let tail = live.freeze_prefix()?;
    assert_eq!(tail.unverified_nal_bytes_excluded, 0);
    assert!(tail.unfinished_fragment_bytes_excluded > 0);
    assert_eq!(live.finish_prefix()?.observed_frames, 3);
    Ok(())
}

#[test]
fn jpeg_quantizer_cache_reuse_is_valid_but_redefinition_invalidates_the_sample() -> Test {
    let manifest = parse_manifest(MANIFEST)?;
    let input = packets(ProbeCodec::Jpeg)?;
    let mut scan = input[0][20..].to_vec();
    scan.extend_from_slice(&input[1][20..]);
    let packet = |index: u16, tables: &[u8]| {
        let mut bytes = input[0][..12].to_vec();
        bytes[1] |= 0x80;
        bytes[2..4].copy_from_slice(&65534u16.wrapping_add(index).to_be_bytes());
        bytes[4..8].copy_from_slice(&FIRST.wrapping_add(u32::from(index) * TICKS).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 128, 4, 3, 0, 0]);
        bytes.extend_from_slice(&(tables.len() as u16).to_be_bytes());
        bytes.extend_from_slice(tables);
        bytes.extend_from_slice(&scan);
        bytes
    };
    let mut valid = probe(&manifest, ProbeCodec::Jpeg)?;
    valid.observe_rtp(0, &packet(0, &[8; 128]))?;
    valid.observe_rtp(0, &packet(1, &[]))?;
    valid.observe_rtp(0, &packet(2, &[]))?;
    assert_eq!(valid.finish()?.observed_frames, 3);

    let mut changed = probe(&manifest, ProbeCodec::Jpeg)?;
    changed.observe_rtp(0, &packet(0, &[8; 128]))?;
    assert!(changed.observe_rtp(0, &packet(1, &[9; 128])).is_err());
    assert!(matches!(
        changed.finish(),
        Err(ObservationError::Continuity)
    ));
    Ok(())
}
