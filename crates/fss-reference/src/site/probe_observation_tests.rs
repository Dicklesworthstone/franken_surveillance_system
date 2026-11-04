#![forbid(unsafe_code)]

use super::*;
use crate::ingest::rtpdump::{RtpDumpKind, RtpDumpLimits, RtpDumpReader};
use crate::site::parse_manifest;

const MANIFEST: &[u8] = include_bytes!("../../../../fixtures/site_probe/manifest.v1.json");
const AVC_DESCRIPTION: &[u8] = include_bytes!("../../../../fixtures/site_probe/avc.describe.rtsp");
const AVC_RTP: &[u8] = include_bytes!("../../../../fixtures/site_probe/avc.rtpdump");
const HEVC_DESCRIPTION: &[u8] = include_bytes!("../../../../fixtures/site_probe/hevc.describe.rtsp");
const HEVC_RTP: &[u8] = include_bytes!("../../../../fixtures/site_probe/hevc.rtpdump");
const FIRST: u32 = 0xffff_f000;
const TICKS: u32 = 3600;
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn body(response: &[u8]) -> Test<&[u8]> {
    let (_, body) = std::str::from_utf8(response)?.split_once("\r\n\r\n")
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
            (96, vec![
                media.sps.clone().ok_or(ObservationError::Negotiation)?,
                media.pps.clone().ok_or(ObservationError::Negotiation)?,
            ])
        }
        ProbeCodec::Hevc => {
            let (session, projected) = select_h265_description(sdp, 0, Some(98))
                .map_err(|_| ObservationError::Negotiation)?;
            let media = session.media.first().ok_or(ObservationError::Negotiation)?;
            let selected = hevc::negotiate(&projected, 0, media)
                .map_err(|_| ObservationError::Negotiation)?;
            let ([vps], [sps], [pps]) = (selected.vps(), selected.sps(), selected.pps()) else {
                return Err(ObservationError::Negotiation);
            };
            (98, vec![vps.clone(), sps.clone(), pps.clone()])
        }
        ProbeCodec::Jpeg => return Err(ObservationError::Negotiation),
    };
    let parameters = parameters.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RtspProbeObserver::new(manifest, 0, NegotiatedProbe {
        sdp, media_index: 0, rtp_channel: 0, codec, payload_type,
        parameter_sets: &parameters, server_identity: "fixture",
    })
}

fn probe(manifest: &SiteManifest, codec: ProbeCodec) -> Test<RtspProbeObserver<'_>> {
    let description = match codec {
        ProbeCodec::Avc => AVC_DESCRIPTION,
        ProbeCodec::Hevc => HEVC_DESCRIPTION,
        ProbeCodec::Jpeg => return Err("fixture codec".into()),
    };
    Ok(from_sdp(manifest, codec, body(description)?)?)
}

fn packets(codec: ProbeCodec) -> Test<Vec<Vec<u8>>> {
    let bytes = match codec {
        ProbeCodec::Avc => AVC_RTP,
        ProbeCodec::Hevc => HEVC_RTP,
        ProbeCodec::Jpeg => return Err("fixture codec".into()),
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
        assert_eq!(receipt.last_rtp_timestamp, FIRST.wrapping_add(TICKS * (count - 1)));
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
    assert!(matches!(observer.finish(), Err(ObservationError::Incomplete)));
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
        assert_eq!(observer.observe_rtp(0, &input[1]), Err(ObservationError::Continuity));
        assert!(matches!(observer.finish(), Err(ObservationError::Continuity)));
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
        assert_eq!(refusal, Some(if configuration_change {
            ObservationError::Negotiation
        } else {
            ObservationError::Cadence
        }));
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
        let starts_fragment = payload.len() >= 2 && payload[0] & 0x1f == 28
            && payload[1] & 0x80 != 0;
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
        let starts_fragment = payload.len() >= 2 && payload[0] & 0x1f == 28
            && payload[1] & 0x80 != 0;
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
    assert_eq!(observer.observe_rtp(0, &input[0]), Err(ObservationError::Continuity));
    assert!(matches!(observer.finish_prefix(), Err(ObservationError::Continuity)));
    Ok(())
}
