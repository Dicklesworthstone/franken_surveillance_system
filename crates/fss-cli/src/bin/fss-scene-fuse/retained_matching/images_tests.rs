#![forbid(unsafe_code)]
//! Actual native JPEG, lens maps, masked resampling and FAST/BRIEF with pure source snapshots.
//! These tests verify image composition and binding, not retained custody or calibration quality.

use super::*;
use crate::matching::fixtures::{HEIGHT, LEFT, WIDTH};
use fss_cli::json_input;
use fss_cli::json_output::{object, string};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::{
    CapsuleId, CaptureInterval, ClockBasis, SensorCapsule, SensorId, SensorSourceBytesSpec,
    StreamId, TimestampNs,
};
use fss_twin::localization::FeatureFrame;
use fss_twin::localization::native::{ExtractionOptions, extract_gray};
use fss_twin::rectification::{RawFrameIdentity, RawGrayFrame, RectificationReceipt};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WORK: u64 = 100_000_000;

fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn checked<T>(value: Result<T>) -> TestResult<T> {
    value.map_err(|error| format!("{error:?}").into())
}
fn target() -> TestResult<PinholeIntrinsics> {
    Ok(PinholeIntrinsics::new(128, 96, 160.0, 160.0, 64.0, 48.0)?)
}
fn raw_document(lens: &str, range: &str) -> TestResult<Value> {
    Ok(json_input::parse(&object(&[
        ("kind", string("rectified")),
        (
            "source_domain_digest",
            string(&h("native source image mode").to_text()),
        ),
        (
            "lens_basis",
            string(&h("explicit fixture lens assumption").to_text()),
        ),
        (
            "source_intrinsics",
            r#"{"width":192,"height":128,"fx":160,"fy":160,"cx":96,"cy":64}"#.into(),
        ),
        ("distortion", lens.into()),
        ("maximum_radius", "1.0".into()),
        ("luma_range", string(range)),
    ]))?)
}
fn change(value: &mut Value, path: &[&str], replacement: Value) -> TestResult {
    let Some((key, rest)) = path.split_first() else {
        *value = replacement;
        return Ok(());
    };
    let next = match value {
        Value::Object(fields) => fields.get_mut(*key).ok_or("fixture field")?,
        Value::Array(values) => values.get_mut(key.parse::<usize>()?).ok_or("fixture row")?,
        _ => return Err("fixture object or array".into()),
    };
    change(next, rest, replacement)
}

struct NativeImage {
    declaration: ImageDeclaration,
    target: PinholeIntrinsics,
    spec: RectificationSpec,
    receipt: RectificationReceipt,
    frame: FeatureFrame,
    capsule: SensorCapsule,
}
impl NativeImage {
    fn new(lens: &str, range: &str, masked: bool) -> TestResult<Self> {
        let declaration = checked(parse(&raw_document(lens, range)?))?;
        let target = target()?;
        let mut work = WorkBudget::new(WORK);
        let prepared = checked(declaration.prepare(target, &mut work))?;
        let plan = prepared.rectifier.ok_or("missing native rectifier")?;
        assert_eq!(prepared.domain.bytes(), plan.output_domain());
        let decoded = decode_luma(
            LEFT,
            h(LEFT).bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(WORK),
        )?;
        let mut allowed = vec![1; (WIDTH * HEIGHT) as usize];
        if masked {
            for y in 30..90 {
                for x in 80..105 {
                    allowed[(y * WIDTH + x) as usize] = 0;
                }
            }
        }
        let spec = plan.spec();
        let raw = RawGrayFrame::new(
            RawFrameIdentity {
                exposure: h("unchanged original exposure").bytes(),
                storage: h(decoded.pixels()).bytes(),
                allowed_mask: h(&allowed).bytes(),
                image_domain: spec.source_domain,
                calibration: spec.calibration,
                dimensions: decoded.dimensions(),
                row_stride: WIDTH,
                range: spec.range,
            },
            decoded.pixels(),
            &allowed,
            &mut work,
        )?;
        let corrected = plan.apply(&raw, &mut work)?;
        let extracted = extract_gray(
            &corrected.as_gray_image(&mut work)?,
            ExtractionOptions {
                threshold: 20,
                maximum_features: 32,
                separation: 6,
            },
            &mut work,
        )?;
        assert_eq!(
            extracted.selection.mask_digest,
            corrected.receipt().allowed_mask
        );
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse("capsule:pure-lens-snapshot")?,
            sensor_id: SensorId::parse("sensor:pure-lens-snapshot")?,
            stream_id: StreamId::parse("stream:pure-lens-snapshot:g1")?,
            sequence: 0,
            capture: CaptureInterval::new(TimestampNs(1000), TimestampNs(1100))?,
            receive_time: TimestampNs(1200),
            clock_basis: ClockBasis::Estimated,
            source: LEFT,
            frame_count: 1,
            gap_before: false,
        })?;
        Ok(Self {
            declaration,
            target,
            spec,
            receipt: corrected.receipt(),
            frame: extracted.frame,
            capsule,
        })
    }
    fn resolved(&self) -> ResolvedFrame<'_> {
        ResolvedFrame {
            capsule: &self.capsule,
            import_identity: h("pure snapshot import"),
            segment: 0,
            dimensions: self.receipt.source.dimensions,
            exposure: ContentDigest::new(DigestAlgorithm::Sha256, self.receipt.source.exposure),
            luma: ContentDigest::new(DigestAlgorithm::Sha256, self.receipt.source.storage),
            frame: &self.frame,
            allowed_mask_digest: self.receipt.allowed_mask,
            codec: "jpeg",
            range_start: 0,
            range_count: 1,
            rectification: Some((self.spec, self.receipt)),
        }
    }
}

#[test]
fn all_explicit_lens_families_bind_real_corrected_features_without_source_substitution()
-> TestResult {
    for lens in [
        r#"{"kind":"pinhole"}"#,
        r#"{"kind":"brown_conrady","radial":[0.04,-0.005,0.0001],"tangential":[0.001,-0.001]}"#,
        r#"{"kind":"fisheye","coefficients":[0.02,0.001,0,0]}"#,
    ] {
        let f = NativeImage::new(lens, "full", true)?;
        let resolved = f.resolved();
        let domain = checked(bind(f.declaration, f.target, &resolved))?;
        assert_eq!(domain.bytes(), f.frame.identity().image_domain);
        assert_eq!(resolved.dimensions, [192, 128]);
        assert_eq!(f.frame.identity().dimensions, [128, 96]);
        assert_eq!(f.frame.identity().exposure, f.receipt.source.exposure);
        assert_ne!(f.frame.identity().pixels, resolved.luma.bytes());
        assert_ne!(f.frame.identity().image_domain, f.spec.source_domain);
        assert!(!f.frame.features().is_empty());
        assert!(f.receipt.privacy_rejected > 0);
        assert!(f.receipt.allowed_pixels < 128 * 96);
    }
    Ok(())
}

#[test]
fn sample_range_and_zero_fisheye_are_explicit_distinct_image_derivations() -> TestResult {
    let pinhole = NativeImage::new(r#"{"kind":"pinhole"}"#, "full", false)?;
    let video = NativeImage::new(r#"{"kind":"pinhole"}"#, "video", false)?;
    let fisheye = NativeImage::new(
        r#"{"kind":"fisheye","coefficients":[0,0,0,0]}"#,
        "full",
        false,
    )?;
    assert_ne!(pinhole.receipt.output.pixels, video.receipt.output.pixels);
    assert_ne!(
        pinhole.receipt.output.image_domain,
        video.receipt.output.image_domain
    );
    assert_ne!(pinhole.receipt.map_digest, fisheye.receipt.map_digest);
    assert_ne!(
        pinhole.receipt.output.image_domain,
        fisheye.receipt.output.image_domain
    );
    for f in [&pinhole, &video, &fisheye] {
        checked(bind(f.declaration, f.target, &f.resolved()))?;
    }
    Ok(())
}

#[test]
fn raw_and_pinhole_paths_require_their_own_exact_receipt_shape() -> TestResult {
    let f = NativeImage::new(r#"{"kind":"pinhole"}"#, "full", false)?;
    let mut resolved = f.resolved();
    let domain = ContentDigest::new(DigestAlgorithm::Sha256, f.receipt.output.image_domain);
    assert!(bind(ImageDeclaration::Pinhole(domain), f.target, &resolved).is_err());
    resolved.rectification = None;
    assert!(bind(f.declaration, f.target, &resolved).is_err());
    assert!(bind(ImageDeclaration::Pinhole(domain), f.target, &resolved).is_err());
    // An ordinary direct-pinhole snapshot is still admitted when all its own pins agree.
    resolved.dimensions = f.receipt.output.dimensions;
    resolved.luma = ContentDigest::new(DigestAlgorithm::Sha256, f.receipt.output.pixels);
    checked(bind(ImageDeclaration::Pinhole(domain), f.target, &resolved))?;
    Ok(())
}

#[test]
fn every_declared_lens_and_target_field_is_bound_to_the_native_spec() -> TestResult {
    let f = NativeImage::new(r#"{"kind":"pinhole"}"#, "full", false)?;
    let mut variants = Vec::new();
    let mut spec = f.spec;
    spec.source_domain = h("other raw mode").bytes();
    variants.push(spec);
    let mut spec = f.spec;
    spec.calibration = h("other lens basis").bytes();
    variants.push(spec);
    let mut spec = f.spec;
    spec.range = LumaRange::Video;
    variants.push(spec);
    let mut spec = f.spec;
    spec.maximum_radius = 0.9;
    variants.push(spec);
    let mut spec = f.spec;
    spec.distortion = LensDistortion::Fisheye {
        coefficients: [0.0; 4],
    };
    variants.push(spec);
    let mut spec = f.spec;
    spec.source = PinholeIntrinsics::new(192, 128, 159.0, 160.0, 96.0, 64.0)?;
    variants.push(spec);
    let mut spec = f.spec;
    spec.target = PinholeIntrinsics::new(128, 96, 161.0, 160.0, 64.0, 48.0)?;
    variants.push(spec);
    for spec in variants {
        let mut resolved = f.resolved();
        resolved.rectification = Some((spec, f.receipt));
        assert!(bind(f.declaration, f.target, &resolved).is_err());
    }
    let changed_target = PinholeIntrinsics::new(128, 96, 160.0, 160.0, 63.5, 48.0)?;
    assert!(bind(f.declaration, changed_target, &f.resolved()).is_err());
    Ok(())
}

#[test]
fn raw_receipt_source_output_masks_and_complete_scope_cannot_be_swapped() -> TestResult {
    let f = NativeImage::new(
        r#"{"kind":"brown_conrady","radial":[0.04,0,0],"tangential":[0,0]}"#,
        "full",
        true,
    )?;
    let other = h("unrelated frame or map").bytes();
    let mut changes: Vec<RectificationReceipt> = Vec::new();
    let mut r = f.receipt;
    r.source.exposure = other;
    changes.push(r);
    let mut r = f.receipt;
    r.source.storage = other;
    changes.push(r);
    let mut r = f.receipt;
    r.source.image_domain = other;
    changes.push(r);
    let mut r = f.receipt;
    r.source.calibration = other;
    changes.push(r);
    let mut r = f.receipt;
    r.source.dimensions[0] -= 1;
    changes.push(r);
    let mut r = f.receipt;
    r.source.row_stride += 1;
    changes.push(r);
    let mut r = f.receipt;
    r.source.range = LumaRange::Video;
    changes.push(r);
    let mut r = f.receipt;
    r.source.allowed_mask = [0; 32];
    changes.push(r);
    let mut r = f.receipt;
    r.output.exposure = other;
    changes.push(r);
    let mut r = f.receipt;
    r.output.pixels = other;
    changes.push(r);
    let mut r = f.receipt;
    r.output.image_domain = other;
    changes.push(r);
    let mut r = f.receipt;
    r.output.dimensions[1] -= 1;
    changes.push(r);
    let mut r = f.receipt;
    r.allowed_mask = other;
    changes.push(r);
    let mut r = f.receipt;
    r.map_digest = [0; 32];
    changes.push(r);
    let mut r = f.receipt;
    r.coverage.mapped += 1;
    changes.push(r);
    let mut r = f.receipt;
    r.coverage.outside_lens_domain = usize::MAX;
    changes.push(r);
    let mut r = f.receipt;
    r.allowed_pixels += 1;
    changes.push(r);
    let mut r = f.receipt;
    r.privacy_rejected = usize::MAX;
    changes.push(r);
    for receipt in changes {
        let mut resolved = f.resolved();
        resolved.rectification = Some((f.spec, receipt));
        assert!(bind(f.declaration, f.target, &resolved).is_err());
    }
    let mut resolved = f.resolved();
    resolved.dimensions[0] -= 1;
    assert!(bind(f.declaration, f.target, &resolved).is_err());
    let mut resolved = f.resolved();
    resolved.allowed_mask_digest = other;
    assert!(bind(f.declaration, f.target, &resolved).is_err());
    Ok(())
}

#[test]
fn field_sets_and_lens_arity_refuse_unknown_or_implicit_image_interpretations() -> TestResult {
    let lens = r#"{"kind":"brown_conrady","radial":[0.04,0,0],"tangential":[0,0]}"#;
    let valid = raw_document(lens, "full")?;
    for key in [
        "target_intrinsics",
        "output_domain_digest",
        "pixels",
        "mask",
        "orientation",
        "calibration_activated",
    ] {
        let mut document = valid.clone();
        let Value::Object(fields) = &mut document else {
            return Err("image object".into());
        };
        fields.insert(key.into(), Value::Null);
        assert!(parse(&document).is_err(), "accepted {key}");
    }
    for (path, value) in [
        (vec!["kind"], Value::Text("auto".into())),
        (vec!["luma_range"], Value::Text("unspecified".into())),
        (
            vec!["source_domain_digest"],
            Value::Text(format!("sha256:{}", "00".repeat(32))),
        ),
        (vec!["lens_basis"], Value::Text("unverified".into())),
        (
            vec!["distortion", "kind"],
            Value::Text("brown_rational".into()),
        ),
        (
            vec!["distortion", "radial"],
            Value::Array(vec![Value::Number("0".into()); 2]),
        ),
        (
            vec!["distortion", "tangential"],
            Value::Array(vec![Value::Number("0".into()); 3]),
        ),
        (vec!["distortion", "radial", "0"], Value::Text("0.1".into())),
    ] {
        let mut document = valid.clone();
        change(&mut document, &path, value)?;
        assert!(parse(&document).is_err(), "accepted {path:?}");
    }
    assert!(
        parse(&raw_document(
            r#"{"kind":"pinhole","coefficients":[]}"#,
            "full"
        )?)
        .is_err()
    );
    assert!(
        parse(&raw_document(
            r#"{"kind":"fisheye","coefficients":[0,0,0]}"#,
            "full"
        )?)
        .is_err()
    );
    assert!(
        parse(&json_input::parse(
            r#"{"kind":"pinhole","image_domain_digest":"bad","luma_range":"full"}"#
        )?)
        .is_err()
    );
    Ok(())
}

#[test]
fn source_bounds_are_explicit_and_model_admission_never_falls_back_to_pinhole() -> TestResult {
    let valid = raw_document(r#"{"kind":"pinhole"}"#, "full")?;
    for (path, value) in [
        (vec!["source_intrinsics", "width"], "4097"),
        (vec!["source_intrinsics", "height"], "0"),
        (vec!["source_intrinsics", "fx"], "0.0000009"),
        (vec!["source_intrinsics", "fy"], "1000000001"),
        (vec!["source_intrinsics", "cx"], "-1000000001"),
        (vec!["source_intrinsics", "cy"], "1e999"),
        (vec!["maximum_radius"], "0"),
        (vec!["maximum_radius"], "64.000001"),
    ] {
        let mut document = valid.clone();
        change(&mut document, &path, Value::Number(value.into()))?;
        assert!(parse(&document).is_err(), "accepted {path:?}={value}");
    }
    let mut oversized = valid.clone();
    change(
        &mut oversized,
        &["source_intrinsics", "width"],
        Value::Number("4096".into()),
    )?;
    change(
        &mut oversized,
        &["source_intrinsics", "height"],
        Value::Number("1025".into()),
    )?;
    assert!(parse(&oversized).is_err());
    let folded = checked(parse(&raw_document(
        r#"{"kind":"brown_conrady","radial":[-1,0,0],"tangential":[0,0]}"#,
        "full",
    )?))?;
    assert!(
        folded
            .prepare(target()?, &mut WorkBudget::new(WORK))
            .is_err()
    );
    let invalid = raw_document(r#"{"kind":"fisheye","coefficients":[101,0,0,0]}"#, "full")?;
    assert!(parse(&invalid).is_err());
    Ok(())
}

#[test]
fn preparation_uses_only_the_rig_target_and_obeys_work_and_cancellation() -> TestResult {
    let image = checked(parse(&raw_document(r#"{"kind":"pinhole"}"#, "full")?))?;
    let prepared = checked(image.prepare(target()?, &mut WorkBudget::new(WORK)))?;
    let plan = prepared.rectifier.ok_or("missing map")?;
    assert_eq!(plan.spec().target, target()?);
    assert_eq!(plan.spec().source.dimensions(), [192, 128]);
    assert_eq!(prepared.domain.bytes(), plan.output_domain());
    let second = checked(image.prepare(
        PinholeIntrinsics::new(64, 48, 80.0, 80.0, 32.0, 24.0)?,
        &mut WorkBudget::new(WORK),
    ))?;
    assert_ne!(prepared.domain, second.domain);
    assert!(image.prepare(target()?, &mut WorkBudget::new(1)).is_err());
    let cancelled = || true;
    assert!(
        image
            .prepare(
                target()?,
                &mut WorkBudget::with_cancellation_probe(WORK, &cancelled)
            )
            .is_err()
    );
    let pinhole = ImageDeclaration::Pinhole(h("unchanged direct pinhole domain"));
    let direct = checked(pinhole.prepare(target()?, &mut WorkBudget::new(0)))?;
    assert_eq!(direct.domain, h("unchanged direct pinhole domain"));
    assert!(direct.rectifier.is_none());
    assert!(
        pinhole
            .prepare(
                target()?,
                &mut WorkBudget::with_cancellation_probe(WORK, &cancelled)
            )
            .is_err()
    );
    Ok(())
}
