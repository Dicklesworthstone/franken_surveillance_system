#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::{ContentDigest, SensorId};
use fss_twin::redaction::LumaRedaction;

use super::super::{
    MASK_FILL_LUMA, MaskBinding, PrivacyMaskError, PrivacyMaskPolicy, RetainedMaskPolicy,
};
use super::MaskRefusal;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GRAY: &[u8] = include_bytes!("../../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
/// Native luma decode of `gray.jpg` before any masking existed (captured at 40bf5a6).
const GRAY_LUMA: &str = "sha256:5875da5ed7274432c2e42d253dae128c4a7d4be02f9122f72f3688a0a0b86f1d";

fn bound(resolution: [u32; 2], rectangles: &[[u32; 4]]) -> TestResult<MaskBinding> {
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:privacy-live-unit")?,
        resolution,
        rectangles,
    )?;
    Ok(MaskBinding::Policy(Box::new(RetainedMaskPolicy {
        digest: policy.digest(),
        policy,
        generation: 1,
    })))
}

#[test]
fn an_owner_grid_admitting_a_masked_pixel_is_unmasked_access() -> TestResult {
    let mask = bound([6, 4], &[[2, 1, 2, 2]])?;
    let exact = mask.allowed([6, 4])?;
    mask.refuse_admitted(&exact, [6, 4])?;
    // Denying more than the policy is the owner's choice and stays admitted.
    mask.refuse_admitted(&[0; 24], [6, 4])?;
    let mut leaking = exact.clone();
    leaking[6 + 2] = 1;
    assert!(matches!(
        mask.refuse_admitted(&leaking, [6, 4]),
        Err(PrivacyMaskError::UnmaskedAccessRefused)
    ));
    assert!(matches!(
        mask.refuse_admitted(&[1; 20], [5, 4]),
        Err(PrivacyMaskError::ResolutionMismatch { .. })
    ));
    MaskBinding::NoPolicy.refuse_admitted(&[1; 24], [6, 4])?;
    Ok(())
}

#[test]
fn only_a_policy_changes_a_derived_identity() -> TestResult {
    let base = [7_u8; 32];
    assert_eq!(MaskBinding::NoPolicy.fold_identity("label", base), base);
    let first = bound([6, 4], &[[0, 0, 1, 1]])?;
    let second = bound([6, 4], &[[0, 0, 2, 1]])?;
    assert_ne!(first.fold_identity("label", base), base);
    assert_ne!(
        first.fold_identity("label", base),
        second.fold_identity("label", base)
    );
    assert_ne!(
        first.fold_identity("label", base),
        first.fold_identity("other", base)
    );
    assert!(MaskBinding::NoPolicy.luma_redaction().is_none());
    assert_eq!(
        first.redaction_identity(),
        Some(first.digest().bytes()),
        "the redaction a native decode records is the binding digest"
    );
    Ok(())
}

#[test]
fn masked_luma_is_the_single_enforcement_and_its_receipt_names_the_masked_plane() -> TestResult {
    let decode = || {
        decode_luma(
            GRAY,
            ContentDigest::sha256(GRAY).bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )
    };
    let open = MaskBinding::NoPolicy.mask_luma(decode()?)?;
    assert_eq!(ContentDigest::sha256(open.pixels()).to_text(), GRAY_LUMA);
    assert_eq!(open.receipt(), decode()?.receipt());
    assert_eq!(open.mask_policy(), None);
    let mask = bound([17, 13], &[[0, 0, 8, 8]])?;
    let masked = mask.mask_luma(decode()?)?;
    let mut expected = open.pixels().to_vec();
    mask.apply_luma(&mut expected, [17, 13])?;
    assert_eq!(masked.pixels(), expected.as_slice());
    assert!(masked.pixels()[..8].iter().all(|v| *v == MASK_FILL_LUMA));
    assert_eq!(
        masked.receipt().luma_sha256,
        ContentDigest::sha256(&expected).bytes()
    );
    assert_eq!(masked.mask_policy(), mask.policy_digest());
    assert_eq!(masked.mask_generation(), Some(1));
    // The native-pipeline redaction is the same enforcement.
    let mut plane = open.pixels().to_vec();
    mask.redact(&mut plane, [17, 13])?;
    assert_eq!(plane, expected);
    assert!(mask.redact(&mut plane, [13, 17]).is_err());
    assert!(matches!(
        bound([16, 13], &[[0, 0, 8, 8]])?.mask_luma(decode()?),
        Err(PrivacyMaskError::ResolutionMismatch { .. })
    ));
    Ok(())
}

#[test]
fn copyable_refusals_keep_the_registered_identities() {
    for error in [
        PrivacyMaskError::UnmaskedAccessRefused,
        PrivacyMaskError::ResolutionMismatch {
            declared: [1, 1],
            decoded: [2, 2],
        },
        PrivacyMaskError::InvalidRecord,
    ] {
        assert_eq!(MaskRefusal::from(&error).stable_id(), error.stable_id());
    }
}

fn sources(root: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "tests" {
                sources(&path, out)?;
            }
        } else if path.extension().is_some_and(|e| e == "rs") && name != "tests.rs" {
            out.push(path);
        }
    }
    Ok(())
}

/// Capture and custody modules must stay free of pixel decoders: RTSP live capture and archive,
/// HTTP acquisition, wire custody, archived wire replay, completion records and the synthetic
/// source. Every pixel derivation from their custody goes through a masked consumer. A decoder
/// added here without the sensor's mask would be an unmasked derivation path.
#[test]
fn capture_and_custody_modules_contain_no_pixel_decoder() -> TestResult {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src.join("rtsp"), &mut files)?;
    for file in [
        "rtsp.rs",
        "ingest/http_camera.rs",
        "ingest/http_camera/rgb/custody.rs",
        "ingest/http_archive.rs",
        "ingest/http_replay.rs",
        "ingest/http_replay/completion.rs",
        "ingest/virtual_mjpeg.rs",
        "ingest/virtual_mjpeg/scene.rs",
    ] {
        files.push(src.join(file));
    }
    assert!(files.len() > 40, "the RTSP tree was scanned");
    for file in &files {
        let text = std::fs::read_to_string(file)?;
        for decoder in [
            "decode_luma",
            "decode_rgb",
            "fss_codec_h264",
            "fss_codec_h265",
            "DecodedLuma",
            "DecodedRgb",
            "ComponentInterpretation",
            "screen_jpeg",
            "decode_rectified",
            "run_jpeg",
        ] {
            assert!(
                !text.contains(decoder),
                "{} names pixel decoder `{decoder}`",
                file.display()
            );
        }
    }
    Ok(())
}
