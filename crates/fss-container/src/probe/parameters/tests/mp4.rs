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
const FRAGMENTED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fragmented_av.mp4"
));
const HEVC_FRAGMENTED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/hevc_fragmented_av.mp4"
));
const TAIL_MOOV: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/hevc_av.mp4"
));

fn atom(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(body);
    bytes
}

fn extended_atom(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = 1_u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(&((body.len() + 16) as u64).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn field(bytes: &[u8], kind: &[u8; 4]) -> Test<usize> {
    Ok(bytes
        .windows(4)
        .position(|word| word == kind)
        .ok_or("missing fixture box")?
        + 4)
}

pub(super) fn record(bytes: &[u8], kind: &[u8; 4]) -> Test<Vec<u8>> {
    let start = field(bytes, kind)?;
    let size = u32::from_be_bytes(bytes[start - 8..start - 4].try_into()?);
    Ok(bytes[start..start - 8 + size as usize].to_vec())
}

fn video_track(
    id: u32,
    kind: &[u8; 4],
    config_kind: &[u8; 4],
    config: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut visual = vec![0_u8; 78];
    visual[6..8].copy_from_slice(&1_u16.to_be_bytes());
    visual[24..26].copy_from_slice(&64_u16.to_be_bytes());
    visual[26..28].copy_from_slice(&48_u16.to_be_bytes());
    visual.extend(atom(config_kind, config));
    visual.extend_from_slice(extra);
    let mut stsd = vec![0, 0, 0, 0, 0, 0, 0, 1];
    stsd.extend(atom(kind, &visual));
    let minf = atom(b"minf", &atom(b"stbl", &atom(b"stsd", &stsd)));
    track(id, b"vide", &minf)
}

fn track(id: u32, handler: &[u8; 4], media: &[u8]) -> Vec<u8> {
    let mut tkhd = vec![0_u8; 84];
    tkhd[3] = 3;
    tkhd[12..16].copy_from_slice(&id.to_be_bytes());
    let mut hdlr = vec![0_u8; 24];
    hdlr[8..12].copy_from_slice(handler);
    let mut mdia = atom(b"hdlr", &hdlr);
    mdia.extend_from_slice(media);
    let mut body = atom(b"tkhd", &tkhd);
    body.extend(atom(b"mdia", &mdia));
    atom(b"trak", &body)
}

fn movie(tracks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = atom(b"ftyp", b"isom\0\0\0\0isom");
    let body: Vec<u8> = tracks.iter().flatten().copied().collect();
    bytes.extend(atom(b"moov", &body));
    bytes
}

pub(super) fn hevc_record(depth: u8) -> Test<Vec<u8>> {
    let (vps, sps) = if depth == 8 {
        (VPS8, SPS8)
    } else {
        (VPS10, SPS10)
    };
    let mut bytes = vec![1];
    bytes.extend(hex(if depth == 8 {
        "01600000009000000000001e"
    } else {
        "02200000009000000000001e"
    })?);
    bytes.extend_from_slice(&[
        0xf0,
        0,
        0xfc,
        0xfd,
        0xf8 | (depth - 8),
        0xf8 | (depth - 8),
        0x03,
        0xe8,
        0x0f,
        3,
    ]);
    for (kind, nal) in [(32, hex(vps)?), (33, hex(sps)?), (34, hex(PPS)?)] {
        bytes.push(0x80 | kind);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        bytes.extend(nal);
    }
    Ok(bytes)
}

#[test]
fn retained_initializations_report_native_metadata_and_exact_original_spans() -> Test {
    for (bytes, codec, coded, display, profile, level, end) in [
        (
            BASE,
            ParameterCodec::Avc,
            (160, 128),
            (160, 128),
            66,
            11,
            655,
        ),
        (
            CROPPED,
            ParameterCodec::Avc,
            (64, 48),
            (64, 36),
            100,
            10,
            662,
        ),
        (
            FRAGMENTED,
            ParameterCodec::Avc,
            (64, 48),
            (64, 48),
            77,
            10,
            1214,
        ),
        (
            HEVC_FRAGMENTED,
            ParameterCodec::Hevc,
            (64, 48),
            (64, 48),
            1,
            30,
            1294,
        ),
    ] {
        let report = probe_parameters(bytes, false, ParameterLimits::default(), || false)?;
        assert_eq!(report.container, ContainerKind::IsoBmff);
        assert_eq!(report.track_id, Some(1));
        assert_eq!(report.codec, codec);
        assert_eq!(report.coded_dimensions, coded);
        assert_eq!(report.display_dimensions, display);
        assert_eq!(
            (report.profile, report.level, report.bit_depth),
            (profile, level, 8)
        );
        assert_eq!(report.inspected_bytes, end);
        assert_eq!(
            report.inspected_units,
            if codec == ParameterCodec::Avc { 2 } else { 3 }
        );
        for source in [&report.sps, &report.pps]
            .into_iter()
            .chain(report.vps.as_ref())
        {
            assert_eq!(source.bytes(), &bytes[source.range.clone()]);
            assert!(source.range.end <= end);
        }
    }
    Ok(())
}

#[test]
fn retained_hevc_tuples_work_in_main_and_main10_records() -> Test {
    for depth in [8, 10] {
        let bytes = movie(&[video_track(9, b"hvc1", b"hvcC", &hevc_record(depth)?, &[])]);
        let report = probe_parameters(&bytes, true, ParameterLimits::default(), || false)?;
        assert_eq!(report.codec, ParameterCodec::Hevc);
        assert_eq!(report.track_id, Some(9));
        assert_eq!(report.coded_dimensions, (64, 48));
        assert_eq!(
            report.display_dimensions,
            if depth == 8 { (62, 46) } else { (64, 48) }
        );
        assert_eq!(report.bit_depth, depth);
        assert_eq!(report.profile, if depth == 8 { 1 } else { 2 });
        assert_eq!(report.level, 30);
    }
    Ok(())
}

#[test]
fn a_complete_moov_closes_metadata_without_reading_later_media_or_claiming_file_validity() -> Test {
    let report = probe_parameters(FRAGMENTED, false, ParameterLimits::default(), || false)?;
    let exact = ParameterLimits {
        max_bytes: report.inspected_bytes,
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(FRAGMENTED, false, exact, || false)?,
        report
    );
    assert_eq!(
        probe_parameters(&FRAGMENTED[..exact.max_bytes], false, exact, || false)?,
        report
    );
    let mut changed = FRAGMENTED.to_vec();
    changed[exact.max_bytes..].fill(0xff);
    assert_eq!(
        probe_parameters(&changed, false, ParameterLimits::default(), || false)?,
        report
    );
    // Subsequent initialization is outside the explicit first-complete-moov result.
    let mut second = FRAGMENTED[..exact.max_bytes].to_vec();
    second.extend_from_slice(BASE);
    assert_eq!(
        probe_parameters(&second, true, ParameterLimits::default(), || false)?,
        report
    );
    assert_eq!(
        probe_parameters(
            FRAGMENTED,
            false,
            ParameterLimits {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            || false
        ),
        Err(ParameterError::Limit)
    );
    assert_eq!(
        probe_parameters(
            &FRAGMENTED[..exact.max_bytes - 1],
            true,
            ParameterLimits::default(),
            || false
        ),
        Err(ParameterError::Truncated)
    );
    // moov lies after a media box outside the hard prefix; the probe cannot seek to it.
    assert_eq!(
        probe_parameters(TAIL_MOOV, true, ParameterLimits::default(), || false),
        Err(ParameterError::Limit)
    );
    Ok(())
}

#[test]
fn complete_movie_checks_every_track_before_releasing_a_configuration() -> Test {
    let config = record(BASE, b"avcC")?;
    let selected = video_track(1, b"avc1", b"avcC", &config, &[]);
    let audio = track(2, b"soun", &[]);
    let bytes = movie(&[audio.clone(), selected.clone()]);
    assert_eq!(
        probe_parameters(&bytes, true, ParameterLimits::default(), || false)?.track_id,
        Some(1)
    );
    for other in [
        video_track(2, b"avc1", b"avcC", &config, &[]),
        video_track(2, b"encv", b"avcC", &config, &[]),
        track(1, b"soun", &[]),
    ] {
        let bytes = movie(&[selected.clone(), other]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Contradictory)
        );
    }
    let mut hidden = movie(&[selected, audio]);
    let at = hidden
        .windows(4)
        .rposition(|word| word == b"hdlr")
        .ok_or("fixture handler")?;
    hidden[at..at + 4].copy_from_slice(b"free");
    assert_eq!(
        probe_parameters(&hidden, true, ParameterLimits::default(), || false),
        Err(ParameterError::Malformed)
    );
    Ok(())
}

#[test]
fn unsupported_entries_encryption_and_competing_configuration_are_explicit() -> Test {
    let config = record(BASE, b"avcC")?;
    for kind in [b"encv", b"avc3", b"hev1", b"vp09"] {
        let bytes = movie(&[video_track(1, kind, b"avcC", &config, &[])]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Unsupported)
        );
    }
    let protected = movie(&[video_track(
        1,
        b"avc1",
        b"avcC",
        &config,
        &atom(b"sinf", &[]),
    )]);
    assert_eq!(
        probe_parameters(&protected, true, ParameterLimits::default(), || false),
        Err(ParameterError::Unsupported)
    );
    for extra in [atom(b"avcC", &config), atom(b"hvcC", &hevc_record(8)?)] {
        let bytes = movie(&[video_track(1, b"avc1", b"avcC", &config, &extra)]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Contradictory)
        );
    }
    Ok(())
}

#[test]
fn extended_boxes_and_zero_size_require_correct_parent_and_eof_evidence() -> Test {
    let ftyp_end = u32::from_be_bytes(BASE[..4].try_into()?) as usize;
    let body = &BASE[ftyp_end + 8..];
    let mut extended = extended_atom(b"ftyp", b"isom\0\0\0\0");
    extended.extend(extended_atom(b"moov", body));
    assert_eq!(
        probe_parameters(&extended, false, ParameterLimits::default(), || false)?.coded_dimensions,
        (160, 128)
    );
    let mut zero = BASE.to_vec();
    zero[ftyp_end..ftyp_end + 4].fill(0);
    assert!(probe_parameters(&zero, true, ParameterLimits::default(), || false).is_ok());
    assert_eq!(
        probe_parameters(&zero, false, ParameterLimits::default(), || false),
        Err(ParameterError::Truncated)
    );
    let exact = ParameterLimits {
        max_bytes: zero.len(),
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(&zero, false, exact, || false),
        Err(ParameterError::Limit)
    );
    zero.extend_from_slice(&[0; 8]);
    assert_eq!(
        probe_parameters(&zero, true, exact, || false),
        Err(ParameterError::Limit)
    );
    for declared in [0_u32, 4, u32::MAX] {
        let mut invalid = BASE.to_vec();
        let at = field(&invalid, b"trak")? - 8;
        invalid[at..at + 4].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            probe_parameters(&invalid, false, ParameterLimits::default(), || false),
            Err(ParameterError::Malformed)
        );
    }
    let short = &extended[..12];
    assert_eq!(
        probe_parameters(short, true, ParameterLimits::default(), || false),
        Err(ParameterError::Truncated)
    );
    assert_eq!(
        probe_parameters(
            short,
            false,
            ParameterLimits {
                max_bytes: 12,
                ..ParameterLimits::default()
            },
            || false
        ),
        Err(ParameterError::Limit)
    );
    Ok(())
}

#[test]
fn mp4_record_metadata_cannot_disagree_with_native_avc_parameters() -> Test {
    for field_offset in [1, 2, 3] {
        let mut bytes = BASE.to_vec();
        let at = field(&bytes, b"avcC")?;
        bytes[at + field_offset] ^= 1;
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Contradictory)
        );
    }
    let original = record(CROPPED, b"avcC")?;
    for offset in [0, 1, 2] {
        let mut config = original.clone();
        let at = config.len() - 4 + offset;
        config[at] = if offset == 0 { 0xfe } else { 0xfa };
        let bytes = movie(&[video_track(1, b"avc1", b"avcC", &config, &[])]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Contradictory)
        );
    }
    Ok(())
}

#[test]
fn mp4_hevc_record_offsets_reserved_bits_and_tuple_declarations_are_checked() -> Test {
    let original = hevc_record(8)?;
    for offset in [1, 12, 16, 17, 18] {
        let mut config = original.clone();
        config[offset] ^= 1;
        let bytes = movie(&[video_track(1, b"hvc1", b"hvcC", &config, &[])]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Contradictory)
        );
    }
    for offset in [13, 15, 16, 17, 18] {
        let mut config = original.clone();
        config[offset] &= 0x7f;
        let bytes = movie(&[video_track(1, b"hvc1", b"hvcC", &config, &[])]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(ParameterError::Malformed)
        );
    }
    for (mask, expected) in [
        (0x40, ParameterError::Malformed),
        (0x80, ParameterError::Unsupported),
    ] {
        let mut config = original.clone();
        config[23] ^= mask;
        let bytes = movie(&[video_track(1, b"hvc1", b"hvcC", &config, &[])]);
        assert_eq!(
            probe_parameters(&bytes, true, ParameterLimits::default(), || false),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn complete_configuration_with_short_native_nal_is_malformed_not_a_larger_prefix_request() -> Test {
    let known = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    let mut config = vec![1, 66, 192, 11, 0xff, 0xe1, 0, 4];
    config.extend_from_slice(&known.sps.bytes()[..4]);
    config.push(1);
    config.extend_from_slice(&(known.pps.bytes().len() as u16).to_be_bytes());
    config.extend_from_slice(known.pps.bytes());
    let bytes = movie(&[video_track(1, b"avc1", b"avcC", &config, &[])]);
    assert_eq!(
        probe_parameters(&bytes, false, ParameterLimits::default(), || false),
        Err(ParameterError::Malformed)
    );
    Ok(())
}

#[test]
fn mp4_work_and_geometry_are_bounded_before_success() -> Test {
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
            probe_parameters(BASE, true, limits, || false),
            Err(ParameterError::Limit)
        );
    }
    let config = record(BASE, b"avcC")?;
    let selected = video_track(1, b"avc1", b"avcC", &config, &[]);
    let mut tracks = vec![selected.clone()];
    tracks.extend((2..=17).map(|id| track(id, b"soun", &[])));
    assert_eq!(
        probe_parameters(&movie(&tracks), true, ParameterLimits::default(), || false),
        Err(ParameterError::Limit)
    );
    let mut body = selected;
    for _ in 0..128 {
        body.extend(atom(b"free", &[]));
    }
    let mut bytes = atom(b"ftyp", b"isom\0\0\0\0");
    bytes.extend(atom(b"moov", &body));
    assert_eq!(
        probe_parameters(&bytes, true, ParameterLimits::default(), || false),
        Err(ParameterError::Limit)
    );
    Ok(())
}

#[test]
fn every_mp4_cancellation_checkpoint_withholds_the_complete_result() -> Test {
    for bytes in [BASE, HEVC_FRAGMENTED] {
        let mut checkpoints = 0;
        probe_parameters(bytes, false, ParameterLimits::default(), || {
            checkpoints += 1;
            false
        })?;
        assert!(checkpoints > 10);
        for stop in 1..=checkpoints {
            let mut at = 0;
            assert_eq!(
                probe_parameters(bytes, false, ParameterLimits::default(), || {
                    at += 1;
                    at == stop
                }),
                Err(ParameterError::Cancelled)
            );
        }
    }
    Ok(())
}

#[test]
fn duplicate_or_missing_mandatory_boxes_and_changed_configurations_refuse() -> Test {
    let config = record(BASE, b"avcC")?;
    for kind in [b"tkhd", b"mdia", b"hdlr", b"minf", b"stbl", b"stsd"] {
        let mut bytes = movie(&[video_track(1, b"avc1", b"avcC", &config, &[])]);
        let at = field(&bytes, kind)? - 4;
        bytes[at..at + 4].copy_from_slice(b"free");
        assert_eq!(
            probe_parameters(&bytes, false, ParameterLimits::default(), || false),
            Err(ParameterError::Malformed)
        );
    }
    let known = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
    let mut duplicate = vec![1, 66, 192, 11, 0xff, 0xe2];
    for changed in [false, true] {
        let mut sps = known.sps.bytes().to_vec();
        if changed {
            sps[3] ^= 1;
        }
        duplicate.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        duplicate.extend(sps);
    }
    duplicate.push(1);
    duplicate.extend_from_slice(&(known.pps.bytes().len() as u16).to_be_bytes());
    duplicate.extend_from_slice(known.pps.bytes());
    let bytes = movie(&[video_track(1, b"avc1", b"avcC", &duplicate, &[])]);
    assert_eq!(
        probe_parameters(&bytes, false, ParameterLimits::default(), || false),
        Err(ParameterError::Contradictory)
    );
    Ok(())
}
