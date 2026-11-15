#![forbid(unsafe_code)]

use super::*;
use crate::demux::{DemuxLimits, MatroskaVideo};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const AVC_MKV: &[u8] = include_bytes!("../../../../tests/fixtures/avc_av.mkv");
const AVC_LIVE: &[u8] = include_bytes!("../../../../tests/fixtures/avc_live.mkv");
const HEVC_MKV: &[u8] = include_bytes!("../../../../tests/fixtures/hevc_av.mkv");
const BASE: &[u8] = include_bytes!("../../../../tests/fixtures/baseline_init.bin");
const CROPPED: &[u8] = include_bytes!("../../../../tests/fixtures/high_cropped_init.bin");
const AVC_ID: &[u8] = b"V_MPEG4/ISO/AVC";
const HEVC_ID: &[u8] = b"V_MPEGH/ISO/HEVC";

fn element(id: u32, body: &[u8]) -> Vec<u8> {
    let id = id.to_be_bytes();
    let mut bytes = id
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let width = (1..=8)
        .find(|width| (body.len() as u64) < (1_u64 << (width * 7)) - 1)
        .unwrap_or(8);
    let size = ((1_u64 << (width * 7)) | body.len() as u64).to_be_bytes();
    bytes.extend_from_slice(&size[8 - width..]);
    bytes.extend_from_slice(body);
    bytes
}

fn uint(id: u32, value: u64) -> Vec<u8> {
    element(id, &value.to_be_bytes())
}

fn video(number: u64, codec: &[u8], private: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut entry = uint(0xD7, number);
    entry.extend(uint(0x83, 1));
    entry.extend(element(0x86, codec));
    entry.extend(element(0x63A2, private));
    let mut dimensions = uint(0xB0, 64);
    dimensions.extend(uint(0xBA, 48));
    entry.extend(element(0xE0, &dimensions));
    entry.extend_from_slice(extra);
    element(0xAE, &entry)
}

fn audio(number: u64) -> Vec<u8> {
    let mut entry = uint(0xD7, number);
    entry.extend(uint(0x83, 2));
    element(0xAE, &entry)
}

fn document(segment: &[u8], unknown: bool) -> Vec<u8> {
    let mut bytes = element(0x1A45_DFA3, &element(0x4282, b"matroska"));
    if unknown {
        bytes.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0xff]);
        bytes.extend_from_slice(segment);
    } else {
        bytes.extend(element(0x1853_8067, segment));
    }
    bytes
}

fn probe(bytes: &[u8]) -> Result<VideoParameters<'_>, ParameterError> {
    probe_parameters(bytes, false, ParameterLimits::default(), || false)
}

fn checked(body: &[u8]) -> Vec<u8> {
    let mut crc = !0_u32;
    for byte in body {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    let mut bytes = element(0xBF, &(!crc).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn retained_avc_hevc_and_live_prefixes_keep_original_parameter_spans() -> Test {
    for (bytes, codec, units) in [
        (AVC_MKV, ParameterCodec::Avc, 2),
        (AVC_LIVE, ParameterCodec::Avc, 2),
        (HEVC_MKV, ParameterCodec::Hevc, 3),
    ] {
        let native = MatroskaVideo::parse(bytes, None, DemuxLimits::default())?;
        let end = native
            .elements()
            .iter()
            .find(|item| item.name == "tracks")
            .ok_or("fixture Tracks")?
            .range
            .end;
        let report = probe(bytes)?;
        assert_eq!(report.container, ContainerKind::Matroska);
        assert_eq!(report.track_id, None);
        assert_eq!(report.track_number, Some(1));
        assert_eq!(report.codec, codec);
        assert_eq!(report.coded_dimensions, (64, 48));
        assert_eq!(report.display_dimensions, (64, 48));
        assert_eq!(report.inspected_bytes, end);
        assert_eq!(report.inspected_units, units);
        for source in report.vps.iter().chain([&report.sps, &report.pps]) {
            assert_eq!(source.bytes(), &bytes[source.range.clone()]);
            assert!(native.parameter_sets().contains(&source.range));
            assert!(source.range.end <= end);
        }
        let exact = ParameterLimits {
            max_bytes: end,
            ..ParameterLimits::default()
        };
        assert_eq!(
            probe_parameters(&bytes[..end], false, exact, || false)?,
            report
        );
        let mut changed_tail = bytes[..end].to_vec();
        changed_tail.extend_from_slice(&[0xff; 4096]);
        assert_eq!(probe(&changed_tail)?, report);
    }
    Ok(())
}

#[test]
fn main10_and_full_width_track_numbers_are_preserved() -> Test {
    let record = super::mp4::hevc_record(10)?;
    let bytes = document(
        &element(0x1654_AE6B, &video(u64::MAX, HEVC_ID, &record, &[])),
        true,
    );
    let report = probe(&bytes)?;
    assert_eq!(report.track_number, Some(u64::MAX));
    assert_eq!(report.bit_depth, 10);
    assert_eq!(report.profile, 2);
    assert_eq!(report.coded_dimensions, (64, 48));
    assert_eq!(report.inspected_units, 3);
    Ok(())
}

#[test]
fn native_sps_geometry_retains_crop_instead_of_applying_container_display_fields() -> Test {
    let record = super::mp4::record(CROPPED, b"avcC")?;
    let bytes = document(
        &element(0x1654_AE6B, &video(7, AVC_ID, &record, &[])),
        false,
    );
    let report = probe(&bytes)?;
    assert_eq!(report.coded_dimensions, (64, 48));
    assert_eq!(report.display_dimensions, (64, 36));
    assert_eq!(report.profile, 100);
    Ok(())
}

#[test]
fn one_byte_short_budget_and_observed_eof_have_distinct_refusals() -> Test {
    let end = probe(AVC_MKV)?.inspected_bytes;
    let limits = ParameterLimits {
        max_bytes: end - 1,
        ..ParameterLimits::default()
    };
    for eof in [false, true] {
        assert_eq!(
            probe_parameters(AVC_MKV, eof, limits, || false),
            Err(ParameterError::Limit)
        );
    }
    assert_eq!(probe(&AVC_MKV[..end - 1]), Err(ParameterError::Truncated));
    assert_eq!(
        probe_parameters(
            &AVC_MKV[..end - 1],
            true,
            ParameterLimits::default(),
            || false
        ),
        Err(ParameterError::Truncated)
    );
    assert_eq!(
        probe_parameters(
            AVC_MKV,
            false,
            ParameterLimits {
                max_units: 1,
                ..ParameterLimits::default()
            },
            || false,
        ),
        Err(ParameterError::Limit)
    );
    assert_eq!(
        probe_parameters(
            AVC_MKV,
            false,
            ParameterLimits {
                max_width: 63,
                ..ParameterLimits::default()
            },
            || false,
        ),
        Err(ParameterError::Limit)
    );
    Ok(())
}

#[test]
fn all_declared_tracks_are_checked_before_a_configuration_can_escape() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let first = video(1, AVC_ID, &record, &[]);
    let mut tracks = first.clone();
    tracks.extend(audio(2));
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &tracks), false))?.track_number,
        Some(1)
    );
    let mut multiple = first.clone();
    multiple.extend(video(2, AVC_ID, &record, &[]));
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &multiple), false)),
        Err(ParameterError::Unsupported)
    );
    let mut duplicate = first.clone();
    duplicate.extend(audio(1));
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &duplicate), false)),
        Err(ParameterError::Malformed)
    );
    let mut incomplete = first;
    incomplete.extend_from_slice(&[0xAE, 0x88, 0xD7, 0x81, 2]);
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &incomplete), false)),
        Err(ParameterError::Malformed)
    );
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &audio(1)), false)),
        Err(ParameterError::Unsupported)
    );
    Ok(())
}

#[test]
fn required_field_duplicates_and_transformed_tracks_refuse() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    for extra in [uint(0xD7, 1), uint(0x83, 1), element(0x63A2, &record)] {
        let bytes = document(
            &element(0x1654_AE6B, &video(1, AVC_ID, &record, &extra)),
            false,
        );
        assert_eq!(probe(&bytes), Err(ParameterError::Contradictory));
    }
    for extra in [element(0x6D80, &[]), element(0xE2, &[])] {
        let bytes = document(
            &element(0x1654_AE6B, &video(1, AVC_ID, &record, &extra)),
            false,
        );
        assert_eq!(probe(&bytes), Err(ParameterError::Unsupported));
    }
    let unsupported = document(
        &element(0x1654_AE6B, &video(1, b"V_VP9", &record, &[])),
        false,
    );
    assert_eq!(probe(&unsupported), Err(ParameterError::Unsupported));
    Ok(())
}

#[test]
fn checksums_bind_complete_metadata_and_segment_crc_cannot_be_ignored() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let tracks = element(0x1654_AE6B, &checked(&video(1, AVC_ID, &record, &[])));
    let mut segment = element(0x1549_A966, &checked(&uint(0x2A_D7B1, 1_000_000)));
    segment.extend_from_slice(&tracks);
    let bytes = document(&segment, false);
    assert!(probe(&bytes).is_ok());
    let locations = bytes
        .windows(2)
        .enumerate()
        .filter_map(|(i, word)| (word == [0xBF, 0x84]).then_some(i + 2))
        .collect::<Vec<_>>();
    assert_eq!(locations.len(), 2);
    for at in locations {
        let mut broken = bytes.clone();
        broken[at] ^= 1;
        assert_eq!(probe(&broken), Err(ParameterError::Malformed));
    }
    assert_eq!(
        probe(&document(&checked(&tracks), false)),
        Err(ParameterError::Unsupported)
    );
    let mut misplaced = video(1, AVC_ID, &record, &[]);
    misplaced.extend(element(0xBF, &[0; 4]));
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &misplaced), false)),
        Err(ParameterError::Malformed)
    );
    Ok(())
}

#[test]
fn closed_metadata_truncation_and_record_contradictions_are_not_more_input_requests() -> Test {
    let good = super::mp4::record(BASE, b"avcC")?;
    let mut wrong_profile = good.clone();
    wrong_profile[1] ^= 1;
    let bytes = document(
        &element(0x1654_AE6B, &video(1, AVC_ID, &wrong_profile, &[])),
        false,
    );
    assert_eq!(probe(&bytes), Err(ParameterError::Contradictory));
    for end in [0, 1, good.len() - 1] {
        let bytes = document(
            &element(0x1654_AE6B, &video(1, AVC_ID, &good[..end], &[])),
            false,
        );
        assert_eq!(probe(&bytes), Err(ParameterError::Malformed));
    }
    let mut wrong_depth = super::mp4::hevc_record(10)?;
    wrong_depth[17] = 0xf8;
    let bytes = document(
        &element(0x1654_AE6B, &video(1, HEVC_ID, &wrong_depth, &[])),
        false,
    );
    assert_eq!(probe(&bytes), Err(ParameterError::Contradictory));
    Ok(())
}

#[test]
fn unknown_metadata_sizes_early_media_and_crossed_parent_boundaries_refuse() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let tracks = element(0x1654_AE6B, &video(1, AVC_ID, &record, &[]));
    let mut early_media = element(0x1F43_B675, &[]);
    early_media.extend_from_slice(&tracks);
    assert_eq!(
        probe(&document(&early_media, true)),
        Err(ParameterError::Unsupported)
    );
    let mut unknown = vec![0x16, 0x54, 0xAE, 0x6B, 0xff];
    unknown.extend(video(1, AVC_ID, &record, &[]));
    assert_eq!(
        probe(&document(&unknown, false)),
        Err(ParameterError::Unsupported)
    );
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &[0xAE, 0xff]), false)),
        Err(ParameterError::Unsupported)
    );
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &[0]), false)),
        Err(ParameterError::Malformed)
    );
    let mut crossed = document(&[], false);
    crossed.extend_from_slice(&tracks);
    assert_eq!(probe(&crossed), Err(ParameterError::Malformed));
    let mut declared = document(&[0x16, 0x54, 0xAE, 0x6B, 0x88], false);
    declared.extend_from_slice(&[0; 8]);
    assert_eq!(probe(&declared), Err(ParameterError::Malformed));
    Ok(())
}

#[test]
fn unsupported_ebml_header_and_internal_header_truncation_refuse() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let segment = element(
        0x1853_8067,
        &element(0x1654_AE6B, &video(1, AVC_ID, &record, &[])),
    );
    for doc in [b"webm".as_slice(), b"matroska"] {
        let mut bytes = element(0x1A45_DFA3, &element(0x4282, doc));
        bytes.extend_from_slice(&segment);
        assert!(probe(&bytes).is_ok());
    }
    for body in [
        element(0x4282, b"invalid"),
        [element(0x4282, b"matroska"), uint(0x42F7, 2)].concat(),
    ] {
        let mut bytes = element(0x1A45_DFA3, &body);
        bytes.extend_from_slice(&segment);
        assert_eq!(probe(&bytes), Err(ParameterError::Unsupported));
    }
    let mut bytes = element(0x1A45_DFA3, &[0x42, 0x82, 0x88, b'm']);
    bytes.extend_from_slice(&segment);
    assert_eq!(probe(&bytes), Err(ParameterError::Malformed));
    Ok(())
}

#[test]
fn metadata_element_and_track_counts_are_independently_bounded() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let video = video(1, AVC_ID, &record, &[]);
    let mut many_tracks = video.clone();
    for number in 2..=17 {
        many_tracks.extend(audio(number));
    }
    assert_eq!(
        probe(&document(&element(0x1654_AE6B, &many_tracks), false)),
        Err(ParameterError::Limit)
    );
    let mut many_elements = Vec::new();
    for _ in 0..128 {
        many_elements.extend(element(0xEC, &[]));
    }
    many_elements.extend(element(0x1654_AE6B, &video));
    assert_eq!(
        probe(&document(&many_elements, false)),
        Err(ParameterError::Limit)
    );
    Ok(())
}

#[test]
fn every_observed_checkpoint_can_withhold_a_configuration_result() -> Test {
    for bytes in [AVC_MKV, HEVC_MKV] {
        let mut checks = 0;
        probe_parameters(bytes, false, ParameterLimits::default(), || {
            checks += 1;
            false
        })?;
        assert!(checks > 10 && checks < 512);
        for stop in 1..=checks {
            let mut seen = 0;
            assert_eq!(
                probe_parameters(bytes, false, ParameterLimits::default(), || {
                    seen += 1;
                    seen == stop
                }),
                Err(ParameterError::Cancelled),
                "checkpoint {stop}/{checks}"
            );
        }
    }
    Ok(())
}
