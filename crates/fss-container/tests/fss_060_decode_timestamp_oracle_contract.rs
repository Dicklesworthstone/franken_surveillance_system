#![forbid(unsafe_code)]
//! Contract, real-MP4 demux differential parity, B-frame display-order permutation check,
//! gap-witness preservation, negative/adversarial divergence reproducers, canonical round-trip,
//! tamper refusal, and cooperative cancellation tests for `FSS-060` (`fss-x4a.12.9`: decode and
//! timestamp differential oracle).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_container::timestamp_oracle::{
    CandidateDecodedFrame, OracleVerdict, ReferenceDecodedFrame, TimestampOracleError,
    TimestampOraclePolicy, TimestampOracleReceipt, evaluate_decode_timestamp_oracle,
    ticks_to_ns_exact,
};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
};

type TestResult = Result<(), Box<dyn Error>>;

const REAL_MP4_FIXTURE: &[u8] = include_bytes!("fixtures/fragmented_av.mp4");

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn fss_060_real_mp4_demux_differential_parity_and_b_frame_reorder() -> TestResult {
    // 1. Parse a real fragmented AVC MP4 fixture and verify exact rational 90 kHz parity.
    let parsed = AvcMp4::parse(REAL_MP4_FIXTURE, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), VideoCodec::Avc);
    assert!(!parsed.samples().is_empty());

    let timescale = parsed.timescale();
    assert!(timescale > 0);

    let mut reference = Vec::with_capacity(parsed.samples().len());
    let mut candidate = Vec::with_capacity(parsed.samples().len());
    for (idx, sample) in parsed.samples().iter().enumerate() {
        let dts_ticks = i64::try_from(sample.decode_time)?;
        let pts_ticks = i64::try_from(sample.presentation_time())?;
        let duration_ticks = sample.duration.max(1);
        let sample_bytes = REAL_MP4_FIXTURE
            .get(sample.source.clone())
            .ok_or("sample source slice out of bounds")?;
        let digest = ContentDigest::sha256(sample_bytes);
        reference.push(ReferenceDecodedFrame {
            decode_index: idx as u64,
            dts_ticks,
            pts_ticks,
            duration_ticks,
            follows_gap: false,
            pixel_digest: digest,
        });
        let dts_ns = ticks_to_ns_exact(dts_ticks, timescale)?;
        let pts_ns = ticks_to_ns_exact(pts_ticks, timescale)?;
        let duration_ns = u64::try_from(ticks_to_ns_exact(i64::from(duration_ticks), timescale)?)?;
        candidate.push(CandidateDecodedFrame {
            decode_index: idx as u64,
            dts_ns,
            pts_ns,
            duration_ns,
            gap_witnessed: false,
            pixel_digest: digest,
        });
    }

    let policy = TimestampOraclePolicy {
        fixture_id: "fixture:fragmented_av.mp4".to_owned(),
        timescale_hz: timescale,
        max_rounding_error_ns: 1,
        generation: Generation(4),
    };
    let receipt = evaluate_decode_timestamp_oracle(&policy, &reference, &candidate, || false)?;
    assert_eq!(receipt.verdict, OracleVerdict::ExactParity);
    assert!(receipt.first_divergence.is_none());
    assert_eq!(receipt.max_observed_dts_delta_ns, 0);
    assert_eq!(receipt.max_observed_pts_delta_ns, 0);
    assert_eq!(receipt.reference_frame_count, parsed.samples().len() as u64);
    assert!(receipt.verify_digest());

    // Canonical binary round-trip + tamper refusal.
    let mut enc = CanonicalEncoder::new();
    receipt.encode_canonical(&mut enc);
    let raw = enc.finish();
    let decoded = TimestampOracleReceipt::decode_canonical(&mut CanonicalDecoder::new(&raw))?;
    assert_eq!(decoded, receipt);

    // 2. Explicit B-frame reorder (I, P, B with PTS [0, 7200, 3600] @ 90kHz) + explicit gap witness.
    let b_policy = TimestampOraclePolicy {
        fixture_id: "fixture:b-frame-pyramid-gap".to_owned(),
        timescale_hz: 90_000,
        max_rounding_error_ns: 1,
        generation: Generation(4),
    };
    let b_ref = vec![
        ReferenceDecodedFrame {
            decode_index: 0,
            dts_ticks: 0,
            pts_ticks: 0,
            duration_ticks: 3_600,
            follows_gap: false,
            pixel_digest: ContentDigest::sha256(b"frame-I0"),
        },
        ReferenceDecodedFrame {
            decode_index: 1,
            dts_ticks: 3_600,
            pts_ticks: 7_200,
            duration_ticks: 3_600,
            follows_gap: false,
            pixel_digest: ContentDigest::sha256(b"frame-P2"),
        },
        ReferenceDecodedFrame {
            decode_index: 2,
            dts_ticks: 7_200,
            pts_ticks: 3_600,
            duration_ticks: 3_600,
            follows_gap: false,
            pixel_digest: ContentDigest::sha256(b"frame-B1"),
        },
        ReferenceDecodedFrame {
            decode_index: 3,
            dts_ticks: 21_600,
            pts_ticks: 21_600,
            duration_ticks: 3_600,
            follows_gap: true,
            pixel_digest: ContentDigest::sha256(b"frame-IDR3-post-gap"),
        },
    ];
    let b_cand: Vec<CandidateDecodedFrame> = b_ref
        .iter()
        .map(|r| -> Result<CandidateDecodedFrame, Box<dyn Error>> {
            Ok(CandidateDecodedFrame {
                decode_index: r.decode_index,
                dts_ns: ticks_to_ns_exact(r.dts_ticks, 90_000)?,
                pts_ns: ticks_to_ns_exact(r.pts_ticks, 90_000)?,
                duration_ns: u64::try_from(ticks_to_ns_exact(
                    i64::from(r.duration_ticks),
                    90_000,
                )?)?,
                gap_witnessed: r.follows_gap,
                pixel_digest: r.pixel_digest,
            })
        })
        .collect::<Result<_, _>>()?;
    let b_rcpt = evaluate_decode_timestamp_oracle(&b_policy, &b_ref, &b_cand, || false)?;
    assert_eq!(b_rcpt.verdict, OracleVerdict::ExactParity);
    assert_eq!(b_rcpt.verified_gap_witnesses, 1);

    emit_caplog(
        "fss_060_real_mp4_and_b_frame_parity",
        "real_mp4_and_b_frame_gap_streams_match_rational_oracle_exactly",
        "real_mp4_and_b_frame_gap_streams_match_rational_oracle_exactly",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_060_all_adversarial_divergences_tamper_and_cancellation_fail_closed() -> TestResult {
    let policy = TimestampOraclePolicy {
        fixture_id: "fixture:adversarial-mutations".to_owned(),
        timescale_hz: 90_000,
        max_rounding_error_ns: 10,
        generation: Generation(4),
    };
    let reference = vec![
        ReferenceDecodedFrame {
            decode_index: 0,
            dts_ticks: 0,
            pts_ticks: 0,
            duration_ticks: 3_600,
            follows_gap: false,
            pixel_digest: ContentDigest::sha256(b"px-0"),
        },
        ReferenceDecodedFrame {
            decode_index: 1,
            dts_ticks: 3_600,
            pts_ticks: 3_600,
            duration_ticks: 3_600,
            follows_gap: true,
            pixel_digest: ContentDigest::sha256(b"px-1"),
        },
    ];
    let baseline_cand = vec![
        CandidateDecodedFrame {
            decode_index: 0,
            dts_ns: 0,
            pts_ns: 0,
            duration_ns: 40_000_000,
            gap_witnessed: false,
            pixel_digest: ContentDigest::sha256(b"px-0"),
        },
        CandidateDecodedFrame {
            decode_index: 1,
            dts_ns: 40_000_000,
            pts_ns: 40_000_000,
            duration_ns: 40_000_000,
            gap_witnessed: true,
            pixel_digest: ContentDigest::sha256(b"px-1"),
        },
    ];

    // 1. FrameCountMismatch (silent frame drop).
    let drop_res =
        evaluate_decode_timestamp_oracle(&policy, &reference, &baseline_cand[..1], || false)?;
    assert_eq!(drop_res.verdict, OracleVerdict::FrameCountMismatch);
    assert!(drop_res.first_divergence.is_some());

    // 2. DtsDivergence (drift beyond max_rounding_error_ns).
    let mut bad_dts = baseline_cand.clone();
    bad_dts[1].dts_ns += 500;
    let dts_res = evaluate_decode_timestamp_oracle(&policy, &reference, &bad_dts, || false)?;
    assert_eq!(dts_res.verdict, OracleVerdict::DtsDivergence);

    // 3. PtsDivergence (presentation timestamp drift).
    let mut bad_pts = baseline_cand.clone();
    bad_pts[1].pts_ns += 500;
    let pts_res = evaluate_decode_timestamp_oracle(&policy, &reference, &bad_pts, || false)?;
    assert_eq!(pts_res.verdict, OracleVerdict::PtsDivergence);

    // 4. DurationDivergence.
    let mut bad_dur = baseline_cand.clone();
    bad_dur[1].duration_ns += 500;
    let dur_res = evaluate_decode_timestamp_oracle(&policy, &reference, &bad_dur, || false)?;
    assert_eq!(dur_res.verdict, OracleVerdict::DurationDivergence);

    // 5. GapWitnessMismatch (candidate silently concealed upstream gap!).
    let mut concealed_gap = baseline_cand.clone();
    concealed_gap[1].gap_witnessed = false;
    let gap_res = evaluate_decode_timestamp_oracle(&policy, &reference, &concealed_gap, || false)?;
    assert_eq!(gap_res.verdict, OracleVerdict::GapWitnessMismatch);

    // 6. PixelDigestMismatch (1-bit pixel difference).
    let mut bad_px = baseline_cand.clone();
    bad_px[1].pixel_digest = ContentDigest::sha256(b"px-1-corrupted");
    let px_res = evaluate_decode_timestamp_oracle(&policy, &reference, &bad_px, || false)?;
    assert_eq!(px_res.verdict, OracleVerdict::PixelDigestMismatch);

    // 7. Forged ExactParity receipt hiding a divergence fails decode even with recomputed SHA-256!
    let mut forged = px_res.clone();
    forged.verdict = OracleVerdict::ExactParity;
    forged.receipt_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        TimestampOracleReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    // 8. Cooperative cancellation at every checkpoint fails closed cleanly.
    let total = AtomicUsize::new(0);
    assert!(
        evaluate_decode_timestamp_oracle(&policy, &reference, &baseline_cand, || {
            total.fetch_add(1, Ordering::Relaxed);
            false
        })
        .is_ok()
    );
    let checks = total.load(Ordering::Relaxed);
    assert!(checks >= 3);
    for cancel_at in [0, checks / 2, checks - 1] {
        let seen = AtomicUsize::new(0);
        assert_eq!(
            evaluate_decode_timestamp_oracle(&policy, &reference, &baseline_cand, || {
                seen.fetch_add(1, Ordering::Relaxed) >= cancel_at
            }),
            Err(TimestampOracleError::Cancelled)
        );
    }

    emit_caplog(
        "fss_060_adversarial_divergences_and_cancellation",
        "all_six_divergence_classes_tamper_and_cancellation_caught",
        "all_six_divergence_classes_tamper_and_cancellation_caught",
        "pass",
    );
    Ok(())
}
