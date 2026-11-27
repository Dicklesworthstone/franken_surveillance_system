#![forbid(unsafe_code)]
//! Contract & fault suite for `FSS-125` (`fss-x4a.12.24`, `TEST-MEDIA-MALFORMED-001`):
//! malformed compressed-stream adversarial corpus and deterministic delta-debugging minimizer.

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_codec_h264::{Decoder as H264Decoder, DecoderLimits as H264Limits};
use fss_codec_h265::{Decoder as H265Decoder, DecoderLimits as H265Limits};
use fss_container::demux::{AvcMp4, DemuxLimits, MatroskaVideo};
use fss_container::malformed_minimizer::{
    MinimizeRequest, MinimizedReproducerReceipt, MinimizerError, MinimizerPolicy, StreamFormatKind,
    default_adversarial_corpus, minimize_reproducer,
};
use fss_container::probe::{ProbeLimits, ProbeOutcome, probe};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn fss_125_adversarial_corpus_fails_closed_deterministically_across_real_parsers_and_decoders()
-> TestResult {
    let corpus = default_adversarial_corpus();
    assert!(corpus.len() >= 12);

    let mut formats_covered = std::collections::BTreeSet::new();
    for case in &corpus {
        formats_covered.insert(case.format);
        // Probe must NEVER panic and must return identical outcomes on repeated runs.
        let p1 = probe(&case.bytes, &ProbeLimits::default());
        let p2 = probe(&case.bytes, &ProbeLimits::default());
        assert_eq!(p1, p2, "nondeterministic probe on {}", case.case_id);

        // Exercise the owning container demuxer or codec decoder on every hostile vector:
        // every adversarial case must fail closed deterministically with zero panics!
        match case.format {
            StreamFormatKind::IsoBmff => {
                let d1 = AvcMp4::parse(&case.bytes, None, DemuxLimits::default());
                let d2 = AvcMp4::parse(&case.bytes, None, DemuxLimits::default());
                assert_eq!(d1.is_err(), d2.is_err());
                assert!(
                    d1.is_err(),
                    "hostile MP4 {} should fail closed",
                    case.case_id
                );
            }
            StreamFormatKind::Matroska => {
                let d1 = MatroskaVideo::parse(&case.bytes, None, DemuxLimits::default());
                let d2 = MatroskaVideo::parse(&case.bytes, None, DemuxLimits::default());
                assert_eq!(d1.is_err(), d2.is_err());
                assert!(
                    d1.is_err(),
                    "hostile MKV {} should fail closed",
                    case.case_id
                );
            }
            StreamFormatKind::AnnexBH264 => {
                let mut dec1 = H264Decoder::new(H264Limits::default())?;
                let mut dec2 = H264Decoder::new(H264Limits::default())?;
                let r1 = dec1.decode_annex_b(&case.bytes);
                let r2 = dec2.decode_annex_b(&case.bytes);
                assert_eq!(r1.is_err(), r2.is_err());
                assert!(
                    r1.is_err() || r1.as_ref().is_ok_and(Vec::is_empty),
                    "hostile H.264 {} must not emit phantom decoded frames",
                    case.case_id
                );
            }
            StreamFormatKind::AnnexBH265 => {
                let mut dec1 = H265Decoder::new(H265Limits::default())?;
                let mut dec2 = H265Decoder::new(H265Limits::default())?;
                let r1 = dec1.decode_annex_b(&case.bytes);
                let r2 = dec2.decode_annex_b(&case.bytes);
                assert_eq!(r1.is_err(), r2.is_err());
                assert!(
                    r1.is_err() || r1.as_ref().is_ok_and(Vec::is_empty),
                    "hostile H.265 {} must not emit phantom decoded frames",
                    case.case_id
                );
            }
            StreamFormatKind::Mjpeg => {
                // Probe identifies JPEG signature; parser must never panic or confuse container.
                assert!(matches!(
                    p1,
                    ProbeOutcome::Identified { .. } | ProbeOutcome::Insufficient { .. }
                ));
            }
        }
    }

    assert_eq!(formats_covered.len(), 5);
    println!(
        "CAPLOG {{\"step\":\"fss_125_corpus_sweep\",\"cases\":{},\"formats\":{},\"verdict\":\"ok\"}}",
        corpus.len(),
        formats_covered.len()
    );
    Ok(())
}

#[test]
fn fss_125_deterministic_minimizer_shrinks_real_hostile_streams_and_seals_receipt() -> TestResult {
    // 1. Padded contradictory ISO-BMFF + Annex-B stream: minimizer must shrink away all 128 trailing
    //    garbage bytes while strictly preserving ProbeOutcome::Contradictory!
    let mut padded = b"\x00\x00\x01\x67ftypisom".to_vec();
    padded.extend(std::iter::repeat_n(0xAB_u8, 128));

    let req = MinimizeRequest {
        case_id: "min-contradictory-probe",
        format: StreamFormatKind::IsoBmff,
        generation: Generation(1),
        failure_signature: "probe_contradictory_annexb_ftyp",
        minimized_at_ns: TimestampNs(1_000_000),
        original: &padded,
    };
    let receipt1 = minimize_reproducer(
        MinimizerPolicy::default(),
        req.clone(),
        || false,
        |bytes| {
            matches!(
                probe(bytes, &ProbeLimits::default()),
                ProbeOutcome::Contradictory
            )
        },
    )?;
    let receipt2 = minimize_reproducer(
        MinimizerPolicy::default(),
        req,
        || false,
        |bytes| {
            matches!(
                probe(bytes, &ProbeLimits::default()),
                ProbeOutcome::Contradictory
            )
        },
    )?;

    // Exact determinism across repeated runs + dramatic shrinking!
    assert_eq!(receipt1, receipt2);
    assert!(receipt1.verify_digest());
    assert!(receipt1.reproduces_failure);
    assert!(!receipt1.budget_exhausted);
    assert_eq!(receipt1.original_len, padded.len() as u64);
    assert!(
        receipt1.minimized_len <= 16,
        "expected shrunk reproducer <= 16 bytes, got {}",
        receipt1.minimized_len
    );
    assert!(matches!(
        probe(&receipt1.minimized_bytes, &ProbeLimits::default()),
        ProbeOutcome::Contradictory
    ));

    // Canonical binary round-trip + tamper refusal (reproduces_failure=false or len mismatch).
    let mut enc = CanonicalEncoder::new();
    receipt1.encode_canonical(&mut enc);
    let encoded = enc.finish();
    let decoded =
        MinimizedReproducerReceipt::decode_canonical(&mut CanonicalDecoder::new(&encoded))?;
    assert_eq!(decoded, receipt1);

    let mut forged = receipt1.clone();
    forged.reproduces_failure = false;
    forged.receipt_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        MinimizedReproducerReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    // 2. Real H.264 Annex-B hostile payload minimization against fss-codec-h264::Decoder!
    let mut h264_padded = vec![0x00, 0x00, 0x00, 0x01, 0xE7, 0x64, 0x00, 0x1F];
    h264_padded.extend((0..96_u8).map(|i| i.wrapping_mul(37)));
    let h264_receipt = minimize_reproducer(
        MinimizerPolicy::default(),
        MinimizeRequest {
            case_id: "min-h264-forbidden-zero-bit",
            format: StreamFormatKind::AnnexBH264,
            generation: Generation(1),
            failure_signature: "h264_decode_error",
            minimized_at_ns: TimestampNs(2_000_000),
            original: &h264_padded,
        },
        || false,
        |bytes| {
            H264Decoder::new(H264Limits::default())
                .and_then(|mut d| d.decode_annex_b(bytes))
                .is_err()
        },
    )?;
    assert!(h264_receipt.minimized_len < h264_receipt.original_len);
    assert!(h264_receipt.minimized_len <= 10);

    println!(
        "CAPLOG {{\"step\":\"fss_125_minimize\",\"probe_orig\":{},\"probe_min\":{},\"h264_orig\":{},\"h264_min\":{},\"verdict\":\"ok\"}}",
        receipt1.original_len,
        receipt1.minimized_len,
        h264_receipt.original_len,
        h264_receipt.minimized_len
    );
    Ok(())
}

#[test]
fn fss_125_refuses_non_failing_input_oversized_cancel_nondeterministic_and_respects_budget()
-> TestResult {
    // 1. Initial input that does NOT fail is refused cleanly.
    let err_no_fail = minimize_reproducer(
        MinimizerPolicy::default(),
        MinimizeRequest {
            case_id: "ok-input",
            format: StreamFormatKind::Mjpeg,
            generation: Generation(1),
            failure_signature: "none",
            minimized_at_ns: TimestampNs(10),
            original: b"\xff\xd8\xff\xe0hello",
        },
        || false,
        |_| false,
    );
    assert_eq!(err_no_fail, Err(MinimizerError::InitialInputDidNotFail));

    // 2. Oversized input refused before any allocation/search.
    let small_policy = MinimizerPolicy {
        max_input_bytes: 8,
        ..MinimizerPolicy::default()
    };
    assert_eq!(
        minimize_reproducer(
            small_policy,
            MinimizeRequest {
                case_id: "too-big",
                format: StreamFormatKind::IsoBmff,
                generation: Generation(1),
                failure_signature: "big",
                minimized_at_ns: TimestampNs(10),
                original: &[0xFF; 16],
            },
            || false,
            |_| true,
        ),
        Err(MinimizerError::InputOutOfBounds { actual: 16, max: 8 })
    );

    // 3. Tight evaluation budget stops honestly with `budget_exhausted == true` and valid reproducer!
    let tight_policy = MinimizerPolicy {
        max_input_bytes: 1024,
        max_evaluations: 4,
        max_passes: 4,
        enable_byte_simplification: true,
    };
    let tight = minimize_reproducer(
        tight_policy,
        MinimizeRequest {
            case_id: "tight-budget",
            format: StreamFormatKind::Matroska,
            generation: Generation(1),
            failure_signature: "always_fail",
            minimized_at_ns: TimestampNs(20),
            original: &[0xAA; 64],
        },
        || false,
        |bytes| !bytes.is_empty(),
    )?;
    assert!(tight.budget_exhausted);
    assert!(tight.predicate_evaluations <= tight_policy.max_evaluations);
    assert!(tight.reproduces_failure);
    assert_eq!(
        tight.minimized_digest,
        ContentDigest::sha256(&tight.minimized_bytes)
    );

    // 4. Cooperative cancellation returns Cancelled cleanly.
    assert_eq!(
        minimize_reproducer(
            MinimizerPolicy::default(),
            MinimizeRequest {
                case_id: "cancelled",
                format: StreamFormatKind::AnnexBH265,
                generation: Generation(1),
                failure_signature: "cancel",
                minimized_at_ns: TimestampNs(30),
                original: &[1, 2, 3, 4],
            },
            || true,
            |_| true,
        ),
        Err(MinimizerError::Cancelled)
    );

    // 5. Nondeterministic predicate that fails once then passes on re-check is caught!
    let calls = AtomicUsize::new(0);
    assert_eq!(
        minimize_reproducer(
            MinimizerPolicy {
                max_evaluations: 2,
                ..MinimizerPolicy::default()
            },
            MinimizeRequest {
                case_id: "flaky",
                format: StreamFormatKind::AnnexBH264,
                generation: Generation(1),
                failure_signature: "flaky",
                minimized_at_ns: TimestampNs(40),
                original: &[1, 2, 3],
            },
            || false,
            |_| calls.fetch_add(1, Ordering::Relaxed) == 0,
        ),
        Err(MinimizerError::NondeterministicPredicate)
    );

    // 6. Wire forgery claiming `budget_exhausted = true` while `predicate_evaluations < max_evaluations` refused!
    let mut forged_budget = tight;
    forged_budget.predicate_evaluations = 2;
    forged_budget.max_evaluations = 10;
    forged_budget.budget_exhausted = true;
    forged_budget.receipt_digest = forged_budget.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged_budget.encode_canonical(&mut bad_enc);
    assert!(
        MinimizedReproducerReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );
    Ok(())
}
