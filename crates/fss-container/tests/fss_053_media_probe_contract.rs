#![forbid(unsafe_code)]
//! Contract, multi-container parameter extraction, cooperative cancellation, hard bounds,
//! and hostile-input refusal verification for `FSS-053` (`fss-x4a.12.2`: bounded pure-Rust
//! media probe engine).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_container::probe::parameters::{
    ParameterCodec, ParameterError, ParameterLimits, probe_parameters,
};
use fss_container::probe::{
    ContainerKind, MAX_PREFIX, ProbeLimits, ProbeOutcome, TRANSPORT_PREFIX, probe,
};
use fss_core::ContentDigest;
use fss_core::identity::MediaKind;

type TestResult = Result<(), Box<dyn Error>>;

const AVC_ANNEXB: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
const MP4_AVC: &[u8] = include_bytes!("fixtures/fragmented_av.mp4");
const MP4_HEVC: &[u8] = include_bytes!("fixtures/hevc_fragmented_av.mp4");
const MP4_BASELINE_INIT: &[u8] = include_bytes!("fixtures/baseline_init.bin");
const MKV_AVC: &[u8] = include_bytes!("fixtures/avc_av.mkv");
const MKV_AVC_LIVE: &[u8] = include_bytes!("fixtures/avc_live.mkv");
const MKV_HEVC: &[u8] = include_bytes!("fixtures/hevc_av.mkv");

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn build_flv_avc_prefix_from_mp4_init() -> Result<Vec<u8>, Box<dyn Error>> {
    let avcc_pos = MP4_BASELINE_INIT
        .windows(4)
        .position(|w| w == b"avcC")
        .ok_or("baseline_init.bin missing avcC box")?;
    let size_bytes: [u8; 4] = MP4_BASELINE_INIT[avcc_pos - 4..avcc_pos].try_into()?;
    let box_size = u32::from_be_bytes(size_bytes) as usize;
    let avcc_payload = &MP4_BASELINE_INIT[avcc_pos + 4..avcc_pos - 4 + box_size];

    let mut flv = Vec::new();
    // FLV v1 header with video flag (0x01), header size = 9, PreviousTagSize0 = 0.
    flv.extend_from_slice(b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00");
    // Video tag (type = 9): 5-byte AVC sequence-header prefix + avcC record.
    let body_len = 5 + avcc_payload.len();
    flv.push(9);
    flv.push(((body_len >> 16) & 0xFF) as u8);
    flv.push(((body_len >> 8) & 0xFF) as u8);
    flv.push((body_len & 0xFF) as u8);
    flv.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]); // timestamp=0, stream_id=0
    flv.extend_from_slice(&[0x17, 0x00, 0x00, 0x00, 0x00]); // keyframe + AVC + seq header + cts=0
    flv.extend_from_slice(avcc_payload);
    let prev_tag_size = (11 + body_len) as u32;
    flv.extend_from_slice(&prev_tag_size.to_be_bytes());
    Ok(flv)
}

#[test]
fn fss_053_family_probe_covers_all_containers_and_contradictions() -> TestResult {
    let limits = ProbeLimits::default();

    // 1. All 7 container families.
    let mut avi = *b"RIFF\x24\x00\x00\x00AVI ";
    assert_eq!(
        probe(&avi, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::Avi,
            media: MediaKind::Video,
            brand: None,
        }
    );
    avi[8..12].copy_from_slice(b"WAVE");
    assert_eq!(probe(&avi, &limits), ProbeOutcome::Unsupported);

    assert_eq!(
        probe(MP4_AVC, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::IsoBmff,
            media: MediaKind::Video,
            brand: Some(&MP4_AVC[8..12]),
        }
    );
    assert_eq!(
        probe(MKV_AVC, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::Matroska,
            media: MediaKind::Video,
            brand: None,
        }
    );
    assert_eq!(
        probe(AVC_ANNEXB, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::AnnexB,
            media: MediaKind::Video,
            brand: None,
        }
    );
    let flv = build_flv_avc_prefix_from_mp4_init()?;
    assert_eq!(
        probe(&flv, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::Flv,
            media: MediaKind::Video,
            brand: None,
        }
    );
    let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        probe(&jpeg, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::Jpeg,
            media: MediaKind::Image,
            brand: None,
        }
    );
    let mut ts = vec![0u8; TRANSPORT_PREFIX + 16];
    ts[0] = 0x47;
    ts[188] = 0x47;
    assert_eq!(
        probe(&ts, &limits),
        ProbeOutcome::Identified {
            container: ContainerKind::MpegTs,
            media: MediaKind::Video,
            brand: None,
        }
    );

    // 2. Budget & shortfall bounds.
    assert_eq!(
        probe(&ts, &ProbeLimits::new(64)),
        ProbeOutcome::Insufficient {
            needed: TRANSPORT_PREFIX
        }
    );
    assert_eq!(
        probe(b"FLV", &limits),
        ProbeOutcome::Insufficient { needed: MAX_PREFIX }
    );

    // 3. Conflicting signatures refuse as Contradictory (never precedence-resolved).
    let contradictory = b"\x00\x00\x01\x67ftypisom";
    assert_eq!(probe(contradictory, &limits), ProbeOutcome::Contradictory);

    emit_caplog(
        "fss_053_family_probe_all_containers",
        "7_container_families_bounds_and_contradiction_refusal_verified",
        "7_container_families_bounds_and_contradiction_refusal_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_053_parameter_probe_extracts_exact_spans_across_annexb_mp4_mkv_and_flv() -> TestResult {
    let limits = ParameterLimits::default();

    // Annex-B AVC.
    let avc = probe_parameters(AVC_ANNEXB, true, limits, || false)?;
    assert_eq!(avc.container, ContainerKind::AnnexB);
    assert_eq!(avc.codec, ParameterCodec::Avc);
    assert_eq!(avc.coded_dimensions, (160, 128));
    assert_eq!(avc.bit_depth, 8);
    assert!(avc.vps.is_none());
    assert_eq!(avc.sps.bytes(), &AVC_ANNEXB[avc.sps.range.clone()]);
    assert_eq!(avc.pps.bytes(), &AVC_ANNEXB[avc.pps.range.clone()]);

    // MP4 AVC & HEVC.
    let mp4_avc = probe_parameters(MP4_AVC, false, limits, || false)?;
    assert_eq!(mp4_avc.container, ContainerKind::IsoBmff);
    assert_eq!(mp4_avc.codec, ParameterCodec::Avc);
    assert_eq!(mp4_avc.track_id, Some(1));
    assert_eq!(mp4_avc.track_number, None);
    assert_eq!(mp4_avc.sps.bytes(), &MP4_AVC[mp4_avc.sps.range.clone()]);
    assert_eq!(mp4_avc.pps.bytes(), &MP4_AVC[mp4_avc.pps.range.clone()]);

    let mp4_hevc = probe_parameters(MP4_HEVC, false, limits, || false)?;
    assert_eq!(mp4_hevc.container, ContainerKind::IsoBmff);
    assert_eq!(mp4_hevc.codec, ParameterCodec::Hevc);
    let mp4_vps = mp4_hevc.vps.as_ref().ok_or("hevc must carry vps")?;
    assert_eq!(mp4_vps.bytes(), &MP4_HEVC[mp4_vps.range.clone()]);
    assert_eq!(mp4_hevc.sps.bytes(), &MP4_HEVC[mp4_hevc.sps.range.clone()]);
    assert_eq!(mp4_hevc.pps.bytes(), &MP4_HEVC[mp4_hevc.pps.range.clone()]);

    // Matroska AVC, live unknown-size Matroska AVC, and Matroska HEVC.
    for (bytes, want_codec) in [
        (MKV_AVC, ParameterCodec::Avc),
        (MKV_AVC_LIVE, ParameterCodec::Avc),
        (MKV_HEVC, ParameterCodec::Hevc),
    ] {
        let mkv = probe_parameters(bytes, false, limits, || false)?;
        assert_eq!(mkv.container, ContainerKind::Matroska);
        assert_eq!(mkv.codec, want_codec);
        assert_eq!(mkv.track_number, Some(1));
        assert_eq!(mkv.track_id, None);
        assert_eq!(mkv.sps.bytes(), &bytes[mkv.sps.range.clone()]);
        assert_eq!(mkv.pps.bytes(), &bytes[mkv.pps.range.clone()]);
    }

    // FLV AVC.
    let flv_bytes = build_flv_avc_prefix_from_mp4_init()?;
    let flv_a = probe_parameters(&flv_bytes, false, limits, || false)?;
    let flv_b = probe_parameters(&flv_bytes, false, limits, || false)?;
    assert_eq!(flv_a, flv_b);
    assert_eq!(flv_a.container, ContainerKind::Flv);
    assert_eq!(flv_a.codec, ParameterCodec::Avc);
    assert_eq!(flv_a.track_id, None);
    assert_eq!(flv_a.track_number, None);
    assert_eq!(flv_a.sps.bytes(), &flv_bytes[flv_a.sps.range.clone()]);
    assert_eq!(flv_a.pps.bytes(), &flv_bytes[flv_a.pps.range.clone()]);
    assert_eq!(
        ContentDigest::sha256(flv_a.sps.bytes()),
        ContentDigest::sha256(flv_b.sps.bytes())
    );

    emit_caplog(
        "fss_053_parameter_probe_multi_container",
        "annexb_mp4_matroska_flv_exact_borrowed_parameter_spans_verified",
        "annexb_mp4_matroska_flv_exact_borrowed_parameter_spans_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_053_parameter_probe_enforces_limits_cancellation_and_hostile_refusals() -> TestResult {
    // 1. Invalid configuration fails closed without widening.
    let bad_cfg = ParameterLimits {
        max_bytes: 4,
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(MP4_AVC, true, bad_cfg, || false),
        Err(ParameterError::Configuration)
    );

    // 2. Byte, unit, and geometry limits fail closed as Limit.
    let unit_cap = ParameterLimits {
        max_units: 1,
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(AVC_ANNEXB, true, unit_cap, || false),
        Err(ParameterError::Limit)
    );
    let geom_cap = ParameterLimits {
        max_width: 32,
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(MP4_AVC, true, geom_cap, || false),
        Err(ParameterError::Limit)
    );

    // 3. Truncated prefix with observed EOF returns Truncated; without EOF at exact budget returns Limit.
    assert_eq!(
        probe_parameters(&MP4_AVC[..128], true, ParameterLimits::default(), || false),
        Err(ParameterError::Truncated)
    );
    let byte_cap = ParameterLimits {
        max_bytes: 128,
        ..ParameterLimits::default()
    };
    assert_eq!(
        probe_parameters(MP4_AVC, false, byte_cap, || false),
        Err(ParameterError::Limit)
    );

    // 4. Unsupported sample entry (`avc3`) fails closed.
    let mut unsupported_mp4 = MP4_BASELINE_INIT.to_vec();
    let avc1_at = unsupported_mp4
        .windows(4)
        .rposition(|w| w == b"avc1")
        .ok_or("baseline_init missing avc1")?;
    unsupported_mp4[avc1_at..avc1_at + 4].copy_from_slice(b"avc3");
    assert_eq!(
        probe_parameters(&unsupported_mp4, true, ParameterLimits::default(), || false),
        Err(ParameterError::Unsupported)
    );

    // 5. Malformed SPS bytes inside a complete `moov` refuse as Malformed.
    let mut corrupt_mp4 = MP4_BASELINE_INIT.to_vec();
    let avcc_pos = corrupt_mp4
        .windows(4)
        .position(|w| w == b"avcC")
        .ok_or("baseline_init missing avcC")?;
    corrupt_mp4[avcc_pos + 4] = 99; // invalid avcC configurationVersion != 1
    assert_eq!(
        probe_parameters(&corrupt_mp4, true, ParameterLimits::default(), || false),
        Err(ParameterError::Malformed)
    );

    // 6. Cooperative cancellation at every checkpoint withholds the result cleanly.
    for target_fixture in [AVC_ANNEXB, MP4_AVC, MKV_AVC] {
        // Count total checkpoints on an uncancelled run, then cancel at 1st, middle, and final check.
        let total = AtomicUsize::new(0);
        assert!(
            probe_parameters(target_fixture, true, ParameterLimits::default(), || {
                total.fetch_add(1, Ordering::Relaxed);
                false
            })
            .is_ok()
        );
        let n = total.load(Ordering::Relaxed);
        assert!(
            n >= 2,
            "probe must observe multiple cancellation checkpoints"
        );
        for trigger_at in [0, n / 2, n - 1] {
            let seen = AtomicUsize::new(0);
            let res = probe_parameters(target_fixture, true, ParameterLimits::default(), || {
                seen.fetch_add(1, Ordering::Relaxed) >= trigger_at
            });
            assert_eq!(res, Err(ParameterError::Cancelled));
        }
    }

    emit_caplog(
        "fss_053_limits_cancellation_hostile_refusals",
        "configuration_limit_truncated_unsupported_malformed_and_cancelled_fail_closed",
        "configuration_limit_truncated_unsupported_malformed_and_cancelled_fail_closed",
        "pass",
    );
    Ok(())
}
