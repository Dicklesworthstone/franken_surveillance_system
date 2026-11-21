#![forbid(unsafe_code)]

use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BASE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/baseline_init.bin"
));
const CROPPED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/high_cropped_init.bin"
));

fn header(flags: u8, extension: &[u8]) -> Vec<u8> {
    let mut bytes = b"FLV\x01".to_vec();
    bytes.push(flags);
    bytes.extend_from_slice(&(9_u32 + extension.len() as u32).to_be_bytes());
    bytes.extend_from_slice(extension);
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

fn tag(bytes: &mut Vec<u8>, kind: u8, payload: &[u8]) -> Range<usize> {
    let start = bytes.len();
    bytes.push(kind);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&(11_u32 + payload.len() as u32).to_be_bytes());
    start..bytes.len()
}

fn configuration(bytes: &mut Vec<u8>, record: &[u8]) -> Range<usize> {
    let mut payload = vec![0x17, 0, 0, 0, 0];
    payload.extend_from_slice(record);
    tag(bytes, 9, &payload)
}

fn source(record: &[u8]) -> Vec<u8> {
    let mut bytes = header(1, &[]);
    configuration(&mut bytes, record);
    bytes
}

fn probe(bytes: &[u8]) -> Result<VideoParameters<'_>, ParameterError> {
    probe_parameters(bytes, false, ParameterLimits::default(), || false)
}

#[test]
fn retained_native_configurations_keep_exact_flv_spans_and_metadata() -> Test {
    for (fixture, coded, display, profile, level) in [
        (BASE, (160, 128), (160, 128), 66, 11),
        (CROPPED, (64, 48), (64, 36), 100, 10),
    ] {
        let record = super::mp4::record(fixture, b"avcC")?;
        let expected = probe(fixture)?;
        let mut bytes = header(5, &[0x67, 0, 0, 1]);
        tag(&mut bytes, 18, b"opaque metadata FLV avcC");
        tag(&mut bytes, 8, &[0xaf, 0, 0x12, 0x10]);
        let video = configuration(&mut bytes, &record);
        // Later payload/configuration validity is deliberately outside this prefix claim.
        bytes.extend_from_slice(&[0xff; 64]);
        let report = probe(&bytes)?;
        assert_eq!(report.container, ContainerKind::Flv);
        assert_eq!(report.codec, ParameterCodec::Avc);
        assert_eq!(report.coded_dimensions, coded);
        assert_eq!(report.display_dimensions, display);
        assert_eq!(
            (report.profile, report.level, report.bit_depth),
            (profile, level, 8)
        );
        assert_eq!(report.track_id, None);
        assert_eq!(report.track_number, None);
        assert!(report.vps.is_none());
        assert_eq!(report.inspected_bytes, video.end);
        assert_eq!(report.inspected_units, 2);
        assert_eq!(report.sps.bytes(), expected.sps.bytes());
        assert_eq!(report.pps.bytes(), expected.pps.bytes());
        for parameter in [&report.sps, &report.pps] {
            assert!(parameter.range.start >= video.start + 16);
            assert!(parameter.range.end <= video.end - 4);
            assert_eq!(parameter.bytes(), &bytes[parameter.range.clone()]);
            assert_eq!(
                format!("{parameter:?}"),
                format!("ParameterSource {{ range: {:?}, .. }}", parameter.range)
            );
        }
    }
    Ok(())
}

#[test]
fn every_partial_tag_and_back_reference_withholds_parameters() -> Test {
    let bytes = source(&super::mp4::record(BASE, b"avcC")?);
    for end in 0..bytes.len() {
        assert_eq!(
            probe(&bytes[..end]),
            Err(ParameterError::Truncated),
            "prefix {end}"
        );
        assert_eq!(
            probe_parameters(&bytes[..end], true, ParameterLimits::default(), || false),
            Err(ParameterError::Truncated),
            "observed EOF at {end}"
        );
    }
    let report = probe(&bytes)?;
    let exact = ParameterLimits {
        max_bytes: bytes.len(),
        ..ParameterLimits::default()
    };
    assert_eq!(probe_parameters(&bytes, false, exact, || false)?, report);
    assert_eq!(probe_parameters(&bytes, true, exact, || false)?, report);
    let short = ParameterLimits {
        max_bytes: bytes.len() - 1,
        ..exact
    };
    assert_eq!(
        probe_parameters(&bytes, false, short, || false),
        Err(ParameterError::Limit)
    );
    assert_eq!(
        probe_parameters(&bytes, true, short, || false),
        Err(ParameterError::Limit)
    );
    let mut longer = bytes.clone();
    longer.extend_from_slice(&[0xff; 64]);
    assert_eq!(probe_parameters(&longer, false, exact, || false)?, report);
    assert_eq!(probe_parameters(&longer, true, exact, || false)?, report);
    Ok(())
}

#[test]
fn malformed_flags_offsets_stream_ids_and_tag_back_references_refuse() -> Test {
    let bytes = source(&super::mp4::record(BASE, b"avcC")?);
    for (at, value) in [
        (3, 2),               // unadmitted FLV version
        (4, 0x81),            // reserved file-header flag
        (8, 8),               // header ends before its fixed fields
        (12, 1),              // initial previous-tag size
        (13, 0x49),           // reserved tag-header bit
        (13 + 8, 1),          // nonzero stream ID
        (13 + 13, 1),         // nonzero sequence-header composition offset
        (bytes.len() - 1, 0), // wrong previous-tag size
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert_eq!(probe(&bad), Err(ParameterError::Malformed), "byte {at}");
    }
    Ok(())
}

#[test]
fn filtered_vendor_and_nonconfiguration_video_are_explicitly_unsupported() -> Test {
    let bytes = source(&super::mp4::record(BASE, b"avcC")?);
    for (at, value) in [
        (4, 4),          // audio-only header
        (13, 0x29),      // filtered/encrypted video
        (13, 10),        // vendor audio extension
        (13 + 11, 0x12), // non-AVC codec
        (13 + 11, 0x1c), // legacy vendor HEVC codec
        (13 + 11, 0x97), // enhanced video-header grammar
        (13 + 12, 1),    // coded data before initialization
        (13 + 12, 2),    // end-of-sequence before initialization
        (13 + 12, 3),    // unregistered AVC packet type
    ] {
        let mut unsupported = bytes.clone();
        unsupported[at] = value;
        assert_eq!(
            probe(&unsupported),
            Err(ParameterError::Unsupported),
            "byte {at}: {value}"
        );
    }
    for frame_type in [0_u8, 2, 3, 4, 5, 15] {
        let mut unsupported = bytes.clone();
        unsupported[13 + 11] = (frame_type << 4) | 7;
        assert_eq!(probe(&unsupported), Err(ParameterError::Unsupported));
    }
    Ok(())
}

#[test]
fn skipped_payloads_cannot_supply_a_configuration_or_bypass_framing() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let video = source(&record);
    let mut bytes = header(5, &[]);
    let metadata = tag(&mut bytes, 18, &video[13..]);
    let audio = tag(&mut bytes, 8, &[0xaf, 0, 0x12, 0x10]);
    assert_eq!(probe(&bytes), Err(ParameterError::Truncated));
    let real = configuration(&mut bytes, &record);
    assert_eq!(probe(&bytes)?.inspected_bytes, real.end);

    let mut missing_audio_flag = bytes.clone();
    missing_audio_flag[4] = 1;
    assert_eq!(
        probe(&missing_audio_flag),
        Err(ParameterError::Contradictory)
    );
    for at in [metadata.end - 1, audio.end - 1] {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 1;
        assert_eq!(probe(&corrupt), Err(ParameterError::Malformed));
    }
    // No heuristic scan may recover a candidate through an unknown vendor trailer.
    let mut trailer = bytes[..metadata.end].to_vec();
    trailer.extend_from_slice(&[0xff; 8]);
    trailer.extend_from_slice(&video[13..]);
    assert_eq!(probe(&trailer), Err(ParameterError::Malformed));
    Ok(())
}

#[test]
fn complete_but_short_or_contradictory_configuration_records_refuse() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    for length in 0..record.len() {
        let bytes = source(&record[..length]);
        assert_eq!(
            probe(&bytes),
            Err(ParameterError::Malformed),
            "record {length}"
        );
    }
    for at in [0, 4, 5] {
        let mut bad = record.clone();
        bad[at] = 0;
        assert_eq!(probe(&source(&bad)), Err(ParameterError::Malformed));
    }
    let mut conflicting = record;
    conflicting[1] ^= 1;
    assert_eq!(
        probe(&source(&conflicting)),
        Err(ParameterError::Contradictory)
    );
    let mut short_video = header(1, &[]);
    tag(&mut short_video, 9, &[0x17, 0, 0, 0]);
    assert_eq!(probe(&short_video), Err(ParameterError::Malformed));
    Ok(())
}

#[test]
fn multiple_sps_candidates_use_the_existing_native_consistency_rules() -> Test {
    let original = probe(AVC)?;
    let sps = original.sps.bytes();
    let pps = original.pps.bytes();
    let mut record = vec![1, sps[1], sps[2], sps[3], 0xff, 0xe2];
    for _ in 0..2 {
        record.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        record.extend_from_slice(sps);
    }
    record.push(1);
    record.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    record.extend_from_slice(pps);
    let bytes = source(&record);
    let report = probe(&bytes)?;
    assert_eq!(report.inspected_units, 3);
    assert_eq!(report.sps.bytes(), sps);
    assert_eq!(
        probe_parameters(
            &bytes,
            false,
            ParameterLimits {
                max_units: 2,
                ..ParameterLimits::default()
            },
            || false
        ),
        Err(ParameterError::Limit)
    );
    record[6 + 2 + sps.len() + 2 + 3] ^= 1;
    assert_eq!(probe(&source(&record)), Err(ParameterError::Contradictory));
    Ok(())
}

#[test]
fn nal_geometry_and_declared_byte_limits_apply_before_return() -> Test {
    let bytes = source(&super::mp4::record(BASE, b"avcC")?);
    for limits in [
        ParameterLimits {
            max_units: 1,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_width: 159,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_height: 127,
            ..ParameterLimits::default()
        },
        ParameterLimits {
            max_luma_samples: 160 * 128 - 1,
            ..ParameterLimits::default()
        },
    ] {
        assert_eq!(
            probe_parameters(&bytes, false, limits, || false),
            Err(ParameterError::Limit)
        );
    }
    let mut huge_header = bytes.clone();
    huge_header[5..9].copy_from_slice(&(MAX_PROBE_BYTES as u32).to_be_bytes());
    assert_eq!(probe(&huge_header), Err(ParameterError::Limit));
    let mut huge_payload = bytes;
    huge_payload[14..17].fill(0xff);
    assert_eq!(probe(&huge_payload), Err(ParameterError::Limit));
    Ok(())
}

#[test]
fn bounded_tag_work_counts_metadata_and_audio_before_initialization() -> Test {
    let record = super::mp4::record(BASE, b"avcC")?;
    let mut exact = header(5, &[]);
    for n in 0..127 {
        tag(&mut exact, if n % 2 == 0 { 18 } else { 8 }, &[0]);
    }
    let mut excessive = exact.clone();
    configuration(&mut exact, &record);
    assert_eq!(probe(&exact)?.inspected_bytes, exact.len());
    tag(&mut excessive, 18, &[0]);
    configuration(&mut excessive, &record);
    assert!(excessive.len() < MAX_PROBE_BYTES);
    assert_eq!(probe(&excessive), Err(ParameterError::Limit));
    Ok(())
}

#[test]
fn every_cancellation_checkpoint_including_final_delivery_withholds_result() -> Test {
    let mut bytes = header(5, &[]);
    tag(&mut bytes, 18, b"opaque");
    tag(&mut bytes, 8, &[0xaf, 0, 0x12, 0x10]);
    configuration(&mut bytes, &super::mp4::record(BASE, b"avcC")?);
    let original = bytes.clone();
    let mut count = 0;
    probe_parameters(&bytes, false, ParameterLimits::default(), || {
        count += 1;
        false
    })?;
    assert!(count > 8);
    for stop in 1..=count {
        let mut at = 0;
        assert_eq!(
            probe_parameters(&bytes, false, ParameterLimits::default(), || {
                at += 1;
                at == stop
            }),
            Err(ParameterError::Cancelled),
            "checkpoint {stop}"
        );
    }
    assert_eq!(bytes, original);
    Ok(())
}

#[test]
fn mutations_remain_deterministic_bounded_and_source_linked() -> Test {
    let original = source(&super::mp4::record(BASE, b"avcC")?);
    for at in 0..original.len() {
        for mask in [1, 0x80, 0xff] {
            let mut bytes = original.clone();
            bytes[at] ^= mask;
            let first = probe(&bytes);
            assert_eq!(first, probe(&bytes));
            if let Ok(report) = first {
                assert!(report.inspected_bytes <= bytes.len());
                assert!(report.inspected_bytes <= MAX_PROBE_BYTES);
                assert!(report.inspected_units <= ParameterLimits::default().max_units);
                for parameter in [&report.sps, &report.pps] {
                    assert_eq!(bytes.get(parameter.range.clone()), Some(parameter.bytes()));
                    assert!(parameter.range.end <= report.inspected_bytes);
                }
            }
        }
    }
    Ok(())
}
