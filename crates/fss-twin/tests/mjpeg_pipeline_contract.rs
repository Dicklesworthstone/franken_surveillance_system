#![forbid(unsafe_code)]
//! End-to-end MJPEG pipeline contracts: decode, screening, and tracking composition.
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::foreground::{BackgroundPolicy, ForegroundPolicy};
use fss_twin::mjpeg::*;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};

type Test = Result<(), Box<dyn std::error::Error>>;
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const QUERY: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
fn binding(encoded: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding {
        encoded_sha256: ContentDigest::sha256(encoded).bytes(),
        exposure: [exposure; 32],
        allowed_mask: ContentDigest::sha256(mask).bytes(),
        camera_image_domain: [7; 32],
        calibration: [8; 32],
        interpretation: Color::Grayscale,
    }
}
fn plan(budget: &mut WorkBudget<'_>) -> Result<RectificationPlan, Box<dyn std::error::Error>> {
    let k = PinholeIntrinsics::new(17, 13, 20.0, 20.0, 8.5, 6.5)?;
    Ok(RectificationPlan::compile(
        RectificationSpec {
            source: k,
            target: k,
            distortion: LensDistortion::Pinhole,
            maximum_radius: 1.0,
            source_domain: decoded_image_domain([7; 32], Color::Grayscale),
            calibration: [8; 32],
            range: LumaRange::Full,
        },
        budget,
    )?)
}
fn baseline(
    plan: &RectificationPlan,
    mask: &[u8],
    decoder: &mut DecodeBudget<'_>,
    geometry: &mut WorkBudget<'_>,
) -> Result<JpegBackground, Box<dyn std::error::Error>> {
    let a = decode_rectified(
        plan,
        BACKGROUND,
        mask,
        binding(BACKGROUND, mask, 1),
        DecodeLimits::default(),
        decoder,
        geometry,
    )?;
    let b = decode_rectified(
        plan,
        BACKGROUND,
        mask,
        binding(BACKGROUND, mask, 2),
        DecodeLimits::default(),
        decoder,
        geometry,
    )?;
    let c = decode_rectified(
        plan,
        BACKGROUND,
        mask,
        binding(BACKGROUND, mask, 3),
        DecodeLimits::default(),
        decoder,
        geometry,
    )?;
    let references = [
        JpegReference {
            image: &a,
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [10, 10],
            },
        },
        JpegReference {
            image: &b,
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [20, 20],
            },
        },
        JpegReference {
            image: &c,
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [30, 30],
            },
        },
    ];
    Ok(JpegBackground::build(
        plan,
        &references,
        BackgroundPolicy {
            selection_evidence: [9; 32],
            validity: [0, 100],
            maximum_spread: 0,
        },
        geometry,
    )?)
}
fn policy() -> ForegroundPolicy {
    ForegroundPolicy {
        minimum_change: 10,
        minimum_area: 1,
        maximum_regions: 128,
        widespread_per_mille: 900,
    }
}
#[test]
fn real_compressed_frames_reach_existing_foreground_and_crop_pipeline() -> Test {
    let mut decoder = DecodeBudget::new(100_000_000);
    let mut geometry = WorkBudget::new(100_000_000);
    let plan = plan(&mut geometry)?;
    let mask = vec![1; 221];
    let model = baseline(&plan, &mask, &mut decoder, &mut geometry)?;
    let capture = FrameCapture {
        camera: 1,
        clock: 2,
        capture: [40, 40],
    };
    let result = model.detect(
        &plan,
        QUERY,
        &mask,
        binding(QUERY, &mask, 4),
        capture,
        policy(),
        DecodeLimits::default(),
        &mut decoder,
        &mut geometry,
    )?;
    assert!(!result.analysis().report().regions().is_empty());
    assert_eq!(
        result.receipt().source.encoded_sha256,
        ContentDigest::sha256(QUERY).bytes()
    );
    assert_eq!(
        result.analysis().frame().receipt().source.storage,
        result.receipt().decode.luma_sha256
    );
    assert_eq!(model.reference_receipts().len(), 3);
    let region = result.analysis().report().regions()[0];
    let crop = result.analysis().crop(region.id, 1, 221, &mut geometry)?;
    assert!(crop.membership().contains(&1));
    assert_eq!(crop.source().image.exposure, [4; 32]);
    Ok(())
}
#[test]
fn unchanged_compressed_frame_does_not_invent_regions() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let model = baseline(&p, &mask, &mut d, &mut g)?;
    let result = model.detect(
        &p,
        BACKGROUND,
        &mask,
        binding(BACKGROUND, &mask, 4),
        FrameCapture {
            camera: 1,
            clock: 2,
            capture: [40, 40],
        },
        policy(),
        DecodeLimits::default(),
        &mut d,
        &mut g,
    )?;
    assert!(result.analysis().report().regions().is_empty());
    Ok(())
}
#[test]
fn mask_and_compressed_source_identity_travel_together() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mut mask = vec![1; 221];
    mask[55] = 0;
    let out = decode_rectified(
        &p,
        QUERY,
        &mask,
        binding(QUERY, &mask, 4),
        DecodeLimits::default(),
        &mut d,
        &mut g,
    )?;
    assert_eq!(out.frame().pixels()[55], 0);
    assert_eq!(out.frame().allowed()[55], 0);
    assert_eq!(
        out.receipt().source.allowed_mask,
        ContentDigest::sha256(&mask).bytes()
    );
    assert_eq!(out.frame().identity().exposure, [4; 32]);
    Ok(())
}
#[test]
fn wrong_generation_mask_hash_and_corrupt_suffix_fail() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let original = binding(QUERY, &mask, 4);
    for source in [
        JpegFrameBinding {
            calibration: [9; 32],
            ..original
        },
        JpegFrameBinding {
            allowed_mask: [5; 32],
            ..original
        },
        JpegFrameBinding {
            camera_image_domain: [6; 32],
            ..original
        },
    ] {
        assert!(matches!(
            decode_rectified(
                &p,
                QUERY,
                &mask,
                source,
                DecodeLimits::default(),
                &mut d,
                &mut g
            ),
            Err(JpegPipelineError::BasisMismatch)
        ));
    }
    let mut corrupted = QUERY.to_vec();
    corrupted.push(0);
    assert!(matches!(
        decode_rectified(
            &p,
            &corrupted,
            &mask,
            binding(&corrupted, &mask, 4),
            DecodeLimits::default(),
            &mut d,
            &mut g
        ),
        Err(JpegPipelineError::Decode(_))
    ));
    Ok(())
}
#[test]
fn decoder_budget_failure_does_not_change_background() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let model = baseline(&p, &mask, &mut d, &mut g)?;
    let before = model.background().model().digest();
    assert!(
        model
            .detect(
                &p,
                QUERY,
                &mask,
                binding(QUERY, &mask, 4),
                FrameCapture {
                    camera: 1,
                    clock: 2,
                    capture: [40, 40]
                },
                policy(),
                DecodeLimits::default(),
                &mut DecodeBudget::new(0),
                &mut g
            )
            .is_err()
    );
    assert_eq!(before, model.background().model().digest());
    Ok(())
}

use fss_codec_mjpeg::stream::{FramingLimits, JpegStream, StreamBasis};
use fss_twin::mjpeg::stream::{FramedQuery, detect_framed};
#[test]
fn concatenated_stream_frame_keeps_its_byte_range_through_foreground() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let model = baseline(&p, &mask, &mut d, &mut g)?;
    let mut bytes = BACKGROUND.to_vec();
    bytes.extend_from_slice(QUERY);
    let basis = StreamBasis {
        source: ContentDigest::sha256(&bytes).bytes(),
        generation: 1,
    };
    let mut stream = JpegStream::new(basis, FramingLimits::default())?;
    let first = stream.push(0, &bytes, &mut d)?;
    assert!(first.frame.is_some());
    let second = stream
        .push(first.consumed as u64, &bytes[first.consumed..], &mut d)?
        .frame
        .ok_or("missing query frame")?;
    let result = detect_framed(
        &model,
        &p,
        FramedQuery {
            expected_stream: basis,
            frame: &second,
            mask: &mask,
            binding: binding(QUERY, &mask, 4),
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [40, 40],
            },
            policy: policy(),
            limits: DecodeLimits::default(),
        },
        &mut d,
        &mut g,
    )?;
    assert_eq!(result.source().ordinal, 2);
    assert_eq!(
        result.source().byte_range,
        [BACKGROUND.len() as u64, bytes.len() as u64]
    );
    assert_eq!(result.source().basis, basis);
    assert_eq!(result.foreground().receipt().source.exposure, [4; 32]);
    assert!(!result.foreground().analysis().report().regions().is_empty());
    assert_eq!(stream.finish(&mut d)?.frames, 2);
    Ok(())
}
#[test]
fn framed_source_mismatch_is_refused_before_decoding() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let model = baseline(&p, &mask, &mut d, &mut g)?;
    let basis = StreamBasis {
        source: [2; 32],
        generation: 1,
    };
    let mut stream = JpegStream::new(basis, FramingLimits::default())?;
    let frame = stream
        .push(0, QUERY, &mut d)?
        .frame
        .ok_or("missing frame")?;
    let query = FramedQuery {
        expected_stream: StreamBasis {
            generation: 2,
            ..basis
        },
        frame: &frame,
        mask: &mask,
        binding: binding(QUERY, &mask, 4),
        capture: FrameCapture {
            camera: 1,
            clock: 2,
            capture: [40, 40],
        },
        policy: policy(),
        limits: DecodeLimits::default(),
    };
    assert!(matches!(
        detect_framed(&model, &p, query, &mut DecodeBudget::new(0), &mut g),
        Err(JpegPipelineError::BasisMismatch)
    ));
    let query = FramedQuery {
        expected_stream: basis,
        binding: JpegFrameBinding {
            encoded_sha256: [3; 32],
            ..query.binding
        },
        ..query
    };
    assert!(matches!(
        detect_framed(&model, &p, query, &mut DecodeBudget::new(0), &mut g),
        Err(JpegPipelineError::BasisMismatch)
    ));
    Ok(())
}
#[test]
fn valid_framing_with_invalid_coding_cannot_become_foreground() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let model = baseline(&p, &mask, &mut d, &mut g)?;
    let mut bytes = QUERY.to_vec();
    let at = bytes
        .windows(2)
        .position(|p| p == [255, 192])
        .ok_or("missing SOF0")?;
    bytes[at + 4] = 16;
    let basis = StreamBasis {
        source: [2; 32],
        generation: 1,
    };
    let mut stream = JpegStream::new(basis, FramingLimits::default())?;
    let frame = stream
        .push(0, &bytes, &mut d)?
        .frame
        .ok_or("missing framed bytes")?;
    let before = model.background().model().digest();
    let query = FramedQuery {
        expected_stream: basis,
        frame: &frame,
        mask: &mask,
        binding: binding(&bytes, &mask, 4),
        capture: FrameCapture {
            camera: 1,
            clock: 2,
            capture: [40, 40],
        },
        policy: policy(),
        limits: DecodeLimits::default(),
    };
    assert!(matches!(
        detect_framed(&model, &p, query, &mut d, &mut g),
        Err(JpegPipelineError::Decode(_))
    ));
    assert_eq!(model.background().model().digest(), before);
    Ok(())
}

use fss_codec_mjpeg::multipart::{MultipartLimits, MultipartStream};
use fss_twin::mjpeg::multipart::{MultipartQuery, detect_multipart};
#[test]
fn multipart_source_ranges_reach_actual_foreground_and_preserve_capture() -> Test {
    let mut d = DecodeBudget::new(100_000_000);
    let mut g = WorkBudget::new(100_000_000);
    let p = plan(&mut g)?;
    let mask = vec![1; 221];
    let model = baseline(&p, &mask, &mut d, &mut g)?;
    let mut entity =
        b"--frame\r\nContent-Type: image/jpeg\r\nX-Timestamp: not-capture-time\r\n\r\n".to_vec();
    let begin = entity.len();
    entity.extend_from_slice(QUERY);
    entity.extend_from_slice(b"\r\n--frame--\r\n");
    let source = StreamBasis {
        source: ContentDigest::sha256(&entity).bytes(),
        generation: 4,
    };
    let mut parser = MultipartStream::new(
        source,
        "multipart/x-mixed-replace; boundary=frame",
        MultipartLimits::default(),
        &mut d,
    )?;
    let part = parser.push(0, &entity, &mut d)?.frame.ok_or("no part")?;
    let query = MultipartQuery {
        expected_entity: source,
        frame: &part,
        mask: &mask,
        binding: binding(QUERY, &mask, 4),
        capture: FrameCapture {
            camera: 1,
            clock: 2,
            capture: [40, 40],
        },
        policy: policy(),
        limits: DecodeLimits::default(),
    };
    let result = detect_multipart(&model, &p, query, &mut d, &mut g)?;
    assert_eq!(
        result.source().jpeg_range,
        [begin as u64, (begin + QUERY.len()) as u64]
    );
    assert_eq!(
        result.foreground().analysis().report().source().capture,
        [40, 40]
    );
    assert_eq!(result.foreground().receipt().source.exposure, [4; 32]);
    assert!(!result.foreground().analysis().report().regions().is_empty());
    let denied = MultipartQuery {
        expected_entity: StreamBasis {
            generation: 5,
            ..source
        },
        ..query
    };
    assert!(matches!(
        detect_multipart(&model, &p, denied, &mut DecodeBudget::new(0), &mut g),
        Err(JpegPipelineError::BasisMismatch)
    ));
    assert_eq!(parser.finish(&mut d)?.end.frames, 1);
    Ok(())
}
