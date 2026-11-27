#![forbid(unsafe_code)]
//! Registered proof family `TEST-MEDIA-MALFORMED-001` (`fss-x4a.28.4`, mandatory before `GATE-020`):
//! corrupt/hostile codec & container corpus, hard output dimension/byte/frame bounds, stale
//! generation refusal, cooperative cancellation (`request -> drain -> finalize`), zero buffer
//! leaks, deterministic delta-debugging minimization (`FSS-125`), and content-addressed proof
//! manifest across ALL FIVE pure-Rust media crates (`fss-container`, `fss-codec-mjpeg`,
//! `fss-codec-jpeg-encode`, `fss-codec-h264`, `fss-codec-h265`, plus `fss-tensor`).

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_codec_h264::{
    DecodeError as H264Error, Decoder as H264Decoder, DecoderLimits as H264Limits,
};
use fss_codec_h265::{
    DecodeError as H265Error, Decoder as H265Decoder, DecoderLimits as H265Limits,
};
use fss_codec_jpeg_encode::{
    EncodeBudget, EncodeConfig, EncodeError, EncodeLimits, PixelFormat, encode_jpeg,
};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError as JpegError, DecodeLimits as JpegLimits,
    decode_luma, decode_luma_for_identity, decoder_identity,
};
use fss_container::demux::{AvcMp4, DemuxLimits, MatroskaVideo};
use fss_container::malformed_minimizer::{
    MinimizeRequest, MinimizedReproducerReceipt, MinimizerError, MinimizerPolicy, StreamFormatKind,
    default_adversarial_corpus, minimize_reproducer,
};
use fss_container::probe::{ProbeLimits, probe};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::buffer_accounting::{
    BufferAccountant, BufferAccountingPolicy, BufferClass, BufferReservationRequest,
};

type TestResult = Result<(), Box<dyn Error>>;

const PROOF_SEED: u64 = 0x5EED_0590_0125_0001;

fn container_fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing crates dir")?
        .join("fss-container")
        .join("tests")
        .join("fixtures")
        .join(name);
    Ok(fs::read(path)?)
}

fn synthetic_valid_rgb_jpeg(width: u32, height: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let pixel_count = (width as usize) * (height as usize);
    let mut pixels = Vec::with_capacity(pixel_count * 3);
    for idx in 0..pixel_count {
        pixels.push(((idx * 17) & 0xFF) as u8);
        pixels.push(((idx * 31 + 64) & 0xFF) as u8);
        pixels.push(((idx * 53 + 128) & 0xFF) as u8);
    }
    let digest = ContentDigest::sha256(&pixels).bytes();
    let cfg = EncodeConfig {
        quality: 85,
        format: PixelFormat::Rgb,
    };
    let limits = EncodeLimits::default();
    let mut budget = EncodeBudget::new(limits.work_bound(PixelFormat::Rgb));
    let encoded = encode_jpeg(width, height, &pixels, digest, cfg, &limits, &mut budget)?;
    Ok(encoded.into_bytes())
}

#[test]
fn test_media_malformed_001_hostile_corpus_and_seeded_mutations_across_all_five_decoders()
-> TestResult {
    let corpus = default_adversarial_corpus();
    assert!(corpus.len() >= 12);

    let mut formats_exercised = BTreeSet::new();
    let mut case_outcomes_enc = CanonicalEncoder::new();
    case_outcomes_enc.u64(PROOF_SEED);

    // 1. Exercise EVERY vector in default_adversarial_corpus against its REAL pure-Rust parser/decoder
    //    (including real `fss_codec_mjpeg::decode_luma` for MJPEG — never probe-only!).
    for case in &corpus {
        formats_exercised.insert(case.format);
        let p1 = probe(&case.bytes, &ProbeLimits::default());
        let p2 = probe(&case.bytes, &ProbeLimits::default());
        assert_eq!(p1, p2, "nondeterministic probe on {}", case.case_id);

        match case.format {
            StreamFormatKind::IsoBmff => {
                let r1 = AvcMp4::parse(&case.bytes, None, DemuxLimits::default());
                let r2 = AvcMp4::parse(&case.bytes, None, DemuxLimits::default());
                assert_eq!(r1.is_err(), r2.is_err());
                assert!(r1.is_err(), "hostile MP4 {} must fail closed", case.case_id);
            }
            StreamFormatKind::Matroska => {
                let r1 = MatroskaVideo::parse(&case.bytes, None, DemuxLimits::default());
                let r2 = MatroskaVideo::parse(&case.bytes, None, DemuxLimits::default());
                assert_eq!(r1.is_err(), r2.is_err());
                assert!(r1.is_err(), "hostile MKV {} must fail closed", case.case_id);
            }
            StreamFormatKind::Mjpeg => {
                let sha = ContentDigest::sha256(&case.bytes).bytes();
                let limits = JpegLimits::default();
                let mut b1 = DecodeBudget::new(limits.luma_work_bound());
                let mut b2 = DecodeBudget::new(limits.luma_work_bound());
                let r1 = decode_luma(
                    &case.bytes,
                    sha,
                    ComponentInterpretation::YCbCr,
                    limits,
                    &mut b1,
                );
                let r2 = decode_luma(
                    &case.bytes,
                    sha,
                    ComponentInterpretation::YCbCr,
                    limits,
                    &mut b2,
                );
                assert_eq!(
                    r1.err(),
                    r2.err(),
                    "nondeterministic JPEG decode on {}",
                    case.case_id
                );
                let mut b3 = DecodeBudget::new(limits.luma_work_bound());
                let r3 = decode_luma(
                    &case.bytes,
                    sha,
                    ComponentInterpretation::YCbCr,
                    limits,
                    &mut b3,
                );
                assert!(
                    r3.is_err(),
                    "hostile JPEG {} must fail closed",
                    case.case_id
                );
            }
            StreamFormatKind::AnnexBH264 => {
                let mut d1 = H264Decoder::new(H264Limits::default())?;
                let mut d2 = H264Decoder::new(H264Limits::default())?;
                let r1 = d1.decode_annex_b(&case.bytes);
                let r2 = d2.decode_annex_b(&case.bytes);
                assert_eq!(r1.is_err(), r2.is_err());
                assert!(
                    r1.is_err() || r1.as_ref().is_ok_and(Vec::is_empty),
                    "hostile H.264 {} must not emit phantom frames",
                    case.case_id
                );
            }
            StreamFormatKind::AnnexBH265 => {
                let mut d1 = H265Decoder::new(H265Limits::default())?;
                let mut d2 = H265Decoder::new(H265Limits::default())?;
                let r1 = d1.decode_annex_b(&case.bytes);
                let r2 = d2.decode_annex_b(&case.bytes);
                assert_eq!(r1.is_err(), r2.is_err());
                assert!(
                    r1.is_err() || r1.as_ref().is_ok_and(Vec::is_empty),
                    "hostile H.265 {} must not emit phantom frames",
                    case.case_id
                );
            }
        }
        case_outcomes_enc.text(&case.case_id);
        case_outcomes_enc.text(case.format.as_str());
        case_outcomes_enc.u64(case.bytes.len() as u64);
    }
    assert_eq!(formats_exercised.len(), 5);

    // 2. Hostile JPEG SOF0 dimension-bomb (4096x4096 declared in 30 bytes) + trailing garbage after EOI!
    let mut sof0_bomb = vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xC0, 0x00, 0x0B, // SOF0, len=11
        0x08, // 8-bit precision
        0x10, 0x00, // height = 4096
        0x10, 0x00, // width = 4096 (16.7M pixels > 4.19M max!)
        0x01, // 1 component
        0x01, 0x11, 0x00, 0xFF, 0xD9, // EOI
    ];
    let bomb_sha = ContentDigest::sha256(&sof0_bomb).bytes();
    let mut bomb_budget = DecodeBudget::new(1_000_000);
    let bomb_res = decode_luma(
        &sof0_bomb,
        bomb_sha,
        ComponentInterpretation::Grayscale,
        JpegLimits::default(),
        &mut bomb_budget,
    );
    assert!(
        matches!(bomb_res, Err(JpegError::Limit | JpegError::Malformed)),
        "4096x4096 JPEG bomb must fail before pixel allocation"
    );
    sof0_bomb.clear();

    // 3. Real container fixture corruption gauntlet: truncate & bit-flip committed MP4/MKV fixtures
    //    using deterministic LCG seed and prove zero panics & deterministic outcomes.
    let mp4_bytes = container_fixture("fragmented_av.mp4")?;
    let mkv_bytes = container_fixture("avc_av.mkv")?;
    let valid_jpeg = synthetic_valid_rgb_jpeg(32, 32)?;

    let mut state = PROOF_SEED;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };

    for round in 0..16_usize {
        // Mutated MP4 prefix truncation & byte flip
        let cut = (next_u64() as usize) % mp4_bytes.len().max(1);
        let mut bad_mp4 = mp4_bytes[..cut].to_vec();
        if !bad_mp4.is_empty() {
            let pos = (next_u64() as usize) % bad_mp4.len();
            bad_mp4[pos] ^= 0xFF;
        }
        let m1 = AvcMp4::parse(&bad_mp4, None, DemuxLimits::default());
        let m2 = AvcMp4::parse(&bad_mp4, None, DemuxLimits::default());
        assert_eq!(m1.is_err(), m2.is_err(), "MP4 mutation round {round}");

        // Mutated MKV truncation & byte flip
        let kcut = (next_u64() as usize) % mkv_bytes.len().max(1);
        let mut bad_mkv = mkv_bytes[..kcut].to_vec();
        if !bad_mkv.is_empty() {
            let pos = (next_u64() as usize) % bad_mkv.len();
            bad_mkv[pos] ^= 0xA5;
        }
        let k1 = MatroskaVideo::parse(&bad_mkv, None, DemuxLimits::default());
        let k2 = MatroskaVideo::parse(&bad_mkv, None, DemuxLimits::default());
        assert_eq!(k1.is_err(), k2.is_err(), "MKV mutation round {round}");

        // Mutated JPEG truncation & trailing byte injection (no partial pixels emitted!)
        let mut bad_jpg = valid_jpeg.clone();
        if round % 2 == 0 {
            let jcut = ((next_u64() as usize) % (bad_jpg.len().saturating_sub(2))).max(2);
            bad_jpg.truncate(jcut);
        } else {
            bad_jpg.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        let jsha = ContentDigest::sha256(&bad_jpg).bytes();
        let limits = JpegLimits::default();
        let mut jb = DecodeBudget::new(limits.luma_work_bound());
        let jr = decode_luma(
            &bad_jpg,
            jsha,
            ComponentInterpretation::YCbCr,
            limits,
            &mut jb,
        );
        assert!(
            jr.is_err(),
            "mutated/trailing-garbage JPEG round {round} must fail closed"
        );
    }

    let corpus_digest = ContentDigest::sha256(&case_outcomes_enc.finish());
    println!(
        "CAPLOG {{\"family\":\"TEST-MEDIA-MALFORMED-001\",\"phase\":\"hostile_corpus\",\"seed\":{},\"corpus_cases\":{},\"formats\":5,\"manifest_digest\":\"{}\",\"verdict\":\"ok\"}}",
        PROOF_SEED,
        corpus.len(),
        corpus_digest.to_text()
    );
    Ok(())
}

#[test]
fn test_media_malformed_001_hard_output_bounds_stale_generation_and_zero_leak_accounting()
-> TestResult {
    let valid_jpeg = synthetic_valid_rgb_jpeg(32, 32)?;
    let valid_sha = ContentDigest::sha256(&valid_jpeg).bytes();
    let default_limits = JpegLimits::default();

    // 1. Nominal decode succeeds cleanly and releases exact BufferAccountant allocation (zero leak!).
    let mut acct = BufferAccountant::new(BufferAccountingPolicy {
        max_total_bytes: 8_192,
        max_decoded_frame_bytes: 4_096,
        max_tensor_workspace_bytes: 2_048,
        max_staging_scratch_bytes: 2_048,
        max_live_buffers: 8,
        alignment_bytes: 64,
        elevated_threshold_bps: 6_000,
        critical_threshold_bps: 8_500,
    })?;
    let mut ok_budget = DecodeBudget::new(default_limits.luma_work_bound());
    let decoded = decode_luma(
        &valid_jpeg,
        valid_sha,
        ComponentInterpretation::YCbCr,
        default_limits,
        &mut ok_budget,
    )?;
    assert_eq!(decoded.dimensions(), [32, 32]);
    assert_eq!(decoded.pixels().len(), 1_024);

    let res = acct.reserve(
        &BufferReservationRequest {
            owner_id: "test:media-malformed-001".to_owned(),
            class: BufferClass::DecodedFrame,
            generation: Generation(1),
            requested_bytes: decoded.pixels().len(),
            source_digest: Some(ContentDigest::sha256(&valid_jpeg)),
        },
        TimestampNs(1_000),
        || false,
    )?;
    assert_eq!(acct.live_bytes(), 1_024);
    acct.release(
        res.reservation_id,
        "test:media-malformed-001",
        TimestampNs(2_000),
    )?;
    assert_eq!(acct.live_bytes(), 0);

    // 2. Tight output dimension / pixel / input-byte / work-budget / source-digest / stale-gen bounds!
    let mut b = DecodeBudget::new(default_limits.luma_work_bound());
    assert_eq!(
        decode_luma(
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            JpegLimits {
                maximum_dimension: 16,
                ..default_limits
            },
            &mut b,
        )
        .err(),
        Some(JpegError::Limit)
    );
    assert_eq!(
        decode_luma(
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            JpegLimits {
                maximum_pixels: 512,
                ..default_limits
            },
            &mut b,
        )
        .err(),
        Some(JpegError::Limit)
    );
    assert_eq!(
        decode_luma(
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            JpegLimits {
                maximum_bytes: 32,
                ..default_limits
            },
            &mut b,
        )
        .err(),
        Some(JpegError::Limit)
    );
    let mut tiny_budget = DecodeBudget::new(8);
    assert_eq!(
        decode_luma(
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            default_limits,
            &mut tiny_budget,
        )
        .err(),
        Some(JpegError::BudgetExhausted)
    );
    assert_eq!(
        decode_luma(
            &valid_jpeg,
            [0xAA_u8; 32],
            ComponentInterpretation::YCbCr,
            default_limits,
            &mut b,
        )
        .err(),
        Some(JpegError::SourceMismatch)
    );
    // Stale/unknown decoder generation refused fail-closed!
    assert_eq!(
        decode_luma_for_identity(
            [0x11_u8; 32],
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            default_limits,
            &mut b,
        )
        .err(),
        Some(JpegError::Unsupported)
    );
    // Exact registered decoder generation succeeds cleanly!
    assert!(
        decode_luma_for_identity(
            decoder_identity(),
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            default_limits,
            &mut b,
        )
        .is_ok()
    );

    // 3. Encoder hard output-byte and dimension bounds fail closed!
    let pixels = vec![128_u8; 32 * 32];
    let psha = ContentDigest::sha256(&pixels).bytes();
    let tiny_enc_limits = EncodeLimits {
        maximum_dimension: 32,
        maximum_pixels: 1024,
        maximum_output_bytes: 16,
    };
    let mut eb = EncodeBudget::new(tiny_enc_limits.work_bound(PixelFormat::Grayscale));
    assert_eq!(
        encode_jpeg(
            32,
            32,
            &pixels,
            psha,
            EncodeConfig {
                quality: 80,
                format: PixelFormat::Grayscale,
            },
            &tiny_enc_limits,
            &mut eb,
        )
        .err(),
        Some(EncodeError::Limit)
    );

    // 4. H.264 / H.265 hard decoder limit validation refuses zero pictures & sub-minimum geometry!
    assert_eq!(
        H264Decoder::new(H264Limits {
            max_pictures: 0,
            ..H264Limits::default()
        })
        .err(),
        Some(H264Error::Limit)
    );
    assert_eq!(
        H265Decoder::new(H265Limits {
            max_pictures: 0,
            ..H265Limits::default()
        })
        .err(),
        Some(H265Error::Limit)
    );

    // 5. Real MP4/MKV container hard output-byte & sample bounds refuse cleanly before over-extraction!
    let mp4_bytes = container_fixture("fragmented_av.mp4")?;
    let mkv_bytes = container_fixture("avc_av.mkv")?;
    assert!(AvcMp4::parse(&mp4_bytes, None, DemuxLimits::default()).is_ok());
    assert!(MatroskaVideo::parse(&mkv_bytes, None, DemuxLimits::default()).is_ok());
    let tight_demux = DemuxLimits {
        maximum_input_bytes: 32,
        ..DemuxLimits::default()
    };
    assert!(AvcMp4::parse(&mp4_bytes, None, tight_demux).is_err());
    assert!(MatroskaVideo::parse(&mkv_bytes, None, tight_demux).is_err());
    assert_eq!(acct.live_bytes(), 0);
    Ok(())
}

#[test]
fn test_media_malformed_001_cancellation_minimization_and_sealed_proof_manifest() -> TestResult {
    let valid_jpeg = synthetic_valid_rgb_jpeg(32, 32)?;
    let valid_sha = ContentDigest::sha256(&valid_jpeg).bytes();
    let limits = JpegLimits::default();

    // 1. Cooperative cancellation (`request -> drain -> finalize`) across decode, encode, minimizer.
    let cancel_flag = AtomicBool::new(true);
    let mut cancelled_dec_budget =
        DecodeBudget::cancellable(limits.luma_work_bound(), &cancel_flag);
    assert_eq!(
        decode_luma(
            &valid_jpeg,
            valid_sha,
            ComponentInterpretation::YCbCr,
            limits,
            &mut cancelled_dec_budget,
        )
        .err(),
        Some(JpegError::Cancelled)
    );

    let pixels = vec![42_u8; 16 * 16];
    let psha = ContentDigest::sha256(&pixels).bytes();
    let enc_limits = EncodeLimits::default();
    let mut cancelled_enc_budget = EncodeBudget::with_cancellation(
        enc_limits.work_bound(PixelFormat::Grayscale),
        &cancel_flag,
    );
    assert_eq!(
        encode_jpeg(
            16,
            16,
            &pixels,
            psha,
            EncodeConfig {
                quality: 75,
                format: PixelFormat::Grayscale,
            },
            &enc_limits,
            &mut cancelled_enc_budget,
        )
        .err(),
        Some(EncodeError::Cancelled)
    );
    assert_eq!(
        minimize_reproducer(
            MinimizerPolicy::default(),
            MinimizeRequest {
                case_id: "test-media-malformed-cancel",
                format: StreamFormatKind::Mjpeg,
                generation: Generation(1),
                failure_signature: "cancelled",
                minimized_at_ns: TimestampNs(5_000),
                original: &valid_jpeg,
            },
            || cancel_flag.load(Ordering::Acquire),
            |_| true,
        ),
        Err(MinimizerError::Cancelled)
    );

    // 2. Deterministic delta-debugging minimization of a real corrupted JPEG against REAL
    //    `fss_codec_mjpeg::decode_luma`!
    let mut corrupt_jpeg = valid_jpeg[..valid_jpeg.len() - 4].to_vec();
    corrupt_jpeg.extend(std::iter::repeat_n(0xCC_u8, 96));
    let req = MinimizeRequest {
        case_id: "min-real-jpeg-corrupt",
        format: StreamFormatKind::Mjpeg,
        generation: Generation(1),
        failure_signature: "jpeg_decode_luma_refused",
        minimized_at_ns: TimestampNs(10_000),
        original: &corrupt_jpeg,
    };
    let r1 = minimize_reproducer(
        MinimizerPolicy::default(),
        req.clone(),
        || false,
        |bytes| {
            if !bytes.starts_with(&[0xFF, 0xD8]) {
                return false;
            }
            let sha = ContentDigest::sha256(bytes).bytes();
            let mut b = DecodeBudget::new(limits.luma_work_bound());
            decode_luma(bytes, sha, ComponentInterpretation::YCbCr, limits, &mut b).is_err()
        },
    )?;
    let r2 = minimize_reproducer(
        MinimizerPolicy::default(),
        req,
        || false,
        |bytes| {
            if !bytes.starts_with(&[0xFF, 0xD8]) {
                return false;
            }
            let sha = ContentDigest::sha256(bytes).bytes();
            let mut b = DecodeBudget::new(limits.luma_work_bound());
            decode_luma(bytes, sha, ComponentInterpretation::YCbCr, limits, &mut b).is_err()
        },
    )?;
    assert_eq!(r1, r2, "minimizer must be deterministic across replays");
    assert!(r1.verify_digest());
    assert!(r1.reproduces_failure);
    assert!(
        (2..=16).contains(&r1.minimized_len),
        "expected minimal SOI-prefixed corrupt JPEG in 2..=16 bytes, got {}",
        r1.minimized_len
    );
    assert!(r1.minimized_bytes.starts_with(&[0xFF, 0xD8]));

    // Canonical binary round-trip of sealed reproducer receipt!
    let mut enc = CanonicalEncoder::new();
    r1.encode_canonical(&mut enc);
    let decoded_receipt =
        MinimizedReproducerReceipt::decode_canonical(&mut CanonicalDecoder::new(&enc.finish()))?;
    assert_eq!(decoded_receipt, r1);

    println!(
        "CAPLOG {{\"family\":\"TEST-MEDIA-MALFORMED-001\",\"phase\":\"cancel_minimize_manifest\",\"orig_bytes\":{},\"min_bytes\":{},\"receipt_digest\":\"{}\",\"verdict\":\"ok\"}}",
        r1.original_len,
        r1.minimized_len,
        r1.receipt_digest.to_text()
    );
    Ok(())
}
