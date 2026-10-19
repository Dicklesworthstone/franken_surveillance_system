#![forbid(unsafe_code)]
//! Separate CLI processes retain and natively replay complete localization inputs.

#[path = "../../fss-reference/tests/recorded_twin_localization/archive_fixture.rs"]
mod archive_fixture;
#[path = "../../fss-twin/tests/common/mod.rs"]
mod twin_fixture;

use fss_core::ContentDigest;
use fss_geometry::{PinholeIntrinsics, PoseSolverOptions, WorkBudget};
use fss_twin::PropertyTwin;
use fss_twin::atlas_archive::{ReferenceProvenance, encode_atlas};
use fss_twin::localization::native::*;
use fss_twin::localization::*;
use fss_twin::rectification::*;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../../tests/fixtures/media/jpeg/brown_luma_q100.jpg");
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir()
                .join(format!("fss-localization-cli-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command(root: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg(action)
        .arg("--root")
        .arg(root)
        .args(["--site", "site:localization-cli"]);
    command
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn field(output: &Output, name: &str) -> Test<String> {
    let prefix = format!("{name}=");
    std::str::from_utf8(&output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| format!("missing output {name}").into())
}

fn options() -> ImageLocalizationOptions {
    ImageLocalizationOptions {
        extraction: ExtractionOptions {
            maximum_features: 200,
            ..ExtractionOptions::default()
        },
        matching: MatchOptions::default(),
        solving: PoseSolverOptions {
            ransac_trials: 0,
            ..PoseSolverOptions::default()
        },
    }
}
fn setup(exposure: [u8; 32]) -> Test<(PropertyTwin, LocalizationAtlas, RectificationSpec)> {
    let mut budget = WorkBudget::new(2_000_000_000);
    let twin = twin_fixture::twin(&[0.0], None)?;
    let mut state = 1973_u32;
    let pixels: Vec<u8> = (0..96 * 96)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            20 + ((state >> 16) % 180) as u8
        })
        .collect();
    let allowed = vec![1; pixels.len()];
    let gray = GrayImage::new(
        ImageIdentity {
            exposure,
            pixels: ContentDigest::sha256(&pixels).bytes(),
            image_domain: [9; 32],
            dimensions: [96, 96],
        },
        &pixels,
        &allowed,
        &mut budget,
    )?;
    let frame = extract_gray(&gray, options().extraction, &mut budget)?.frame;
    let mut landmarks = Vec::new();
    let mut bindings = Vec::new();
    for (i, point) in frame.features().iter().enumerate() {
        let depth = 6.0 + (i % 7) as f64 * 0.5;
        landmarks.push(AtlasLandmark {
            id: i as u64 + 1,
            physical_group: i as u64 + 1,
            feature: 0,
            world: [
                (point.pixel[0] - 48.0) * depth / 80.0,
                (point.pixel[1] - 48.0) * depth / 80.0,
                depth,
            ],
            evidence: [8; 32],
            error: None,
        });
        bindings.push(AtlasBinding {
            landmark: i as u64 + 1,
            reference: 1,
            image_feature: point.id,
        });
    }
    let atlas = LocalizationAtlas::new(
        &twin,
        landmarks,
        vec![AtlasReference { id: 1, frame }],
        bindings,
        &mut budget,
    )?;
    let camera = PinholeIntrinsics::new(96, 96, 80.0, 80.0, 48.0, 48.0)?;
    Ok((
        twin,
        atlas,
        RectificationSpec {
            source: camera,
            target: camera,
            distortion: LensDistortion::BrownConrady {
                radial: [-0.1, 0.001, 0.0001],
                tangential: [0.001, -0.001],
            },
            maximum_radius: 1.0,
            source_domain: [3; 32],
            calibration: [4; 32],
            range: LumaRange::Full,
        },
    ))
}
#[test]
fn retained_localization_replays_from_only_deployment_bytes_in_a_fresh_process() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    let original = directory.0.join("camera.jpg");
    fs::write(&original, JPEG)?;
    let imported = command(&root, "import")
        .arg("--input")
        .arg(&original)
        .args([
            "--sensor",
            "sensor:localization-cli",
            "--stream",
            "stream:localization-cli",
            "--receive-time-ns",
            "1000000000",
        ])
        .output()?;
    success(&imported);
    let import_identity = field(&imported, "import_identity")?;
    let (twin, atlas, _) = setup([1; 32])?;
    let twin_bytes = archive_fixture::twin_archive(&[0.0], None)?;
    assert_eq!(ContentDigest::sha256(&twin_bytes).bytes(), twin.digest());
    let atlas_bytes = encode_atlas(
        &atlas,
        [7; 32],
        &[ReferenceProvenance {
            reference: 1,
            source_record: [6; 32],
            allowed_mask: [5; 32],
        }],
        &mut WorkBudget::new(2_000_000_000),
    )?;
    let twin_path = directory.0.join("owner.fsstwin");
    let atlas_path = directory.0.join("owner.fssatlas");
    fs::write(&twin_path, &twin_bytes)?;
    fs::write(&atlas_path, &atlas_bytes)?;
    let pin = |value| ContentDigest::new(fss_core::DigestAlgorithm::Sha256, value).to_text();
    let report_path = directory.0.join("pose.json");
    let receipt_path = directory.0.join("candidate.receipt");
    let localized = command(&root, "localize")
        .args([
            "--import-id",
            &import_identity,
            "--segment",
            "0",
            "--interpretation",
            "gray",
            "--twin-sha256",
            &ContentDigest::sha256(&twin_bytes).to_text(),
            "--scene-sha256",
            &pin([1; 32]),
            "--property",
            "9",
            "--revision",
            "4",
            "--atlas-sha256",
            &ContentDigest::sha256(&atlas_bytes).to_text(),
            "--atlas-provenance-sha256",
            &pin([7; 32]),
            "--image-mode",
            "raw",
            "--camera",
            "96,96,80,80,48,48",
            "--source-camera",
            "96,96,80,80,48,48",
            "--image-domain",
            &pin([3; 32]),
            "--distortion",
            "brown,-0.1,0.001,0.0001,0.001,-0.001",
            "--maximum-radius",
            "1",
            "--calibration-sha256",
            &pin([4; 32]),
            "--luma-range",
            "full",
            "--maximum-features",
            "200",
            "--ransac-trials",
            "0",
            "--retain-result",
            "yes",
        ])
        .arg("--twin")
        .arg(&twin_path)
        .arg("--atlas")
        .arg(&atlas_path)
        .arg("--report-out")
        .arg(&report_path)
        .arg("--receipt-out")
        .arg(&receipt_path)
        .output()?;
    success(&localized);
    let identity = field(&localized, "localization_identity")?;
    let expected_root = field(&localized, "localization_root")?;
    let expected_receipt = field(&localized, "localization_receipt")?;
    assert!(field(&localized, "localization_report")?.contains("\"outcome\":\"candidates\""));
    assert_eq!(
        ContentDigest::sha256(&fs::read(&receipt_path)?).to_text(),
        expected_receipt
    );
    fs::remove_file(original)?;
    fs::remove_file(twin_path)?;
    fs::remove_file(atlas_path)?;
    let journal = fs::read(root.join("ledger/journal.fssj"))?;
    let pins = [
        "--localization-id",
        identity.as_str(),
        "--expected-root",
        expected_root.as_str(),
        "--expected-receipt",
        expected_receipt.as_str(),
    ];
    let read_receipt = directory.0.join("read.receipt");
    let read = command(&root, "read-localization")
        .args(pins)
        .arg("--receipt-out")
        .arg(&read_receipt)
        .output()?;
    success(&read);
    assert_eq!(field(&read, "native_replay_verified")?, "false");
    assert_eq!(field(&read, "jpeg_work_units")?, "0");
    assert_eq!(fs::read(read_receipt)?, fs::read(&receipt_path)?);
    let replay_report = directory.0.join("replayed.json");
    let replay = command(&root, "verify-localization")
        .args(pins)
        .args(["--execute-perception", "yes"])
        .arg("--report-out")
        .arg(&replay_report)
        .output()?;
    success(&replay);
    assert_eq!(field(&replay, "native_replay_verified")?, "true");
    assert!(field(&replay, "jpeg_work_units")?.parse::<u64>()? > 0);
    assert_eq!(field(&replay, "calibration_activated")?, "false");
    assert_eq!(field(&replay, "coverage_certifiable")?, "false");
    assert_eq!(fs::read(replay_report)?, fs::read(report_path)?);
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, journal);
    let refused = command(&root, "verify-localization").args(pins).output()?;
    assert!(!refused.status.success(), "execution must be explicit");
    let wrong = command(&root, "verify-localization")
        .args([
            "--localization-id",
            &identity,
            "--expected-root",
            &pin([99; 32]),
            "--expected-receipt",
            &expected_receipt,
            "--execute-perception",
            "yes",
        ])
        .output()?;
    assert!(!wrong.status.success());
    assert!(!String::from_utf8_lossy(&wrong.stdout).contains("native_replay_verified=true"));
    let too_small = command(&root, "verify-localization")
        .args(pins)
        .args(["--execute-perception", "yes", "--geometry-work-units", "1"])
        .output()?;
    assert!(!too_small.status.success());
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, journal);
    Ok(())
}
