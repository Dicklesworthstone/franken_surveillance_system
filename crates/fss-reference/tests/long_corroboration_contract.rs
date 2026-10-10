#![forbid(unsafe_code)]
//! Native ground projection beyond former windows, discontinuities and publication prerequisites.
//! Synthetic recordings prove the executable composition, not detection quality or calibration.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, EventState, LedgerAnchor, OperationId, SensorId, StreamId,
    TimestampNs,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_corroboration::streaming::{
    LongCorroborationLimits, LongCorroborationRecipe, LongCorroborationReport,
    MAX_LONG_CORROBORATION_RECIPE_BYTES, STAGE_LONG_CORROBORATION_COMMIT,
};
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationDependencies, CorroborationError, CorroborationGates,
    CorroborationOptions, CorroborationPlan, CorroborationStatus, EntryDisposition,
    FailureDomainDeclaration, GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-corroboration-contract";
const PRINCIPAL: &str = "principal:long-corroboration-contract";
const IDENTITY: [f64; 9] = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-long-corroboration-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-corroboration-contract".into(),
        operation_id: OperationId::parse("operation:long-corroboration-contract")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn jpeg(x: Option<usize>) -> Test<Vec<u8>> {
    let mut pixels = vec![40_u8; 48 * 32];
    if let Some(x) = x {
        for y in 8..24 {
            for column in x..x + 16 {
                pixels[y * 48 + column] = 220;
            }
        }
    }
    Ok(encode_jpeg(
        48,
        32,
        &pixels,
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?)
}
fn scene(frames: usize, moving: bool, decode_gap: bool, source_gap: bool) -> Test<Vec<u8>> {
    let quiet = jpeg(None)?;
    let squares = (0..=24).map(|x| jpeg(Some(x))).collect::<Test<Vec<_>>>()?;
    let mut unsupported = quiet.clone();
    let sof = unsupported
        .windows(2)
        .position(|w| w == [0xff, 0xc0])
        .ok_or("SOF0")?;
    unsupported[sof + 1] = 0xc2;
    let mut result = Vec::new();
    for position in 0..frames {
        if source_gap && position == 20 {
            result.extend_from_slice(b"unaccounted-source-gap");
        }
        if decode_gap && position == 20 {
            result.extend_from_slice(&unsupported);
        } else if position < 3 || ((decode_gap || source_gap) && (20..24).contains(&position)) {
            result.extend_from_slice(&quiet);
        } else {
            let x = if moving {
                4 + position.saturating_sub(128).min(20)
            } else {
                8
            };
            result.extend_from_slice(&squares[x]);
        }
    }
    Ok(result)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: CorroborationPlan,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], extension: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut imports = Vec::new();
        for name in ["east", "west"] {
            let input = directory.0.join(format!("{name}.{extension}"));
            fs::write(&input, bytes)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = 1024;
            limits.chunk_bytes = 4096;
            let request = FileIngestRequest::new(
                &input,
                SensorId::parse(format!("sensor:long-corroboration-{name}"))?,
                StreamId::parse(format!("stream:long-corroboration-{name}"))?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
            imports.push(FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity);
            fs::remove_file(input)?;
        }
        let plan = CorroborationPlan {
            cameras: [
                CorroborationCamera {
                    name: "east".into(),
                    import_identity: imports[0],
                    homography: GroundHomography { matrix: IDENTITY },
                },
                CorroborationCamera {
                    name: "west".into(),
                    import_identity: imports[1],
                    homography: GroundHomography { matrix: IDENTITY },
                },
            ],
            interpretation: if extension == "mjpeg" {
                ComponentInterpretation::Grayscale
            } else {
                ComponentInterpretation::YCbCr
            },
            zones: vec![GroundZone {
                zone_id: "door".into(),
                x: 8.0,
                y: 16.0,
                width: 16.0,
                height: 16.0,
            }],
            gates: CorroborationGates {
                time_gate_ns: 200_000_000,
                distance_gate: 4.0,
            },
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            _directory: directory,
        })
    }
    fn analyze(&self, tolerant: bool) -> Test<LongCorroborationReport> {
        Ok(LongCorroborationReport::analyze(
            &self.deployment,
            &self.plan,
            CorroborationOptions {
                tolerate_decode_refusals: tolerant,
            },
            &LongCorroborationLimits::default(),
            &CorroborationDependencies::default(),
            &self.cx,
        )?)
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
    fn mask(&mut self, camera: &str, rectangle: [u32; 4]) -> Test {
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse(format!("sensor:long-corroboration-{camera}"))?,
            [48, 32],
            &[rectangle],
        )?;
        let approval = preview_mask(&self.deployment, &policy)?.approval;
        declare_mask(&mut self.deployment, &policy, approval, &self.cx)?;
        Ok(())
    }
}

#[test]
fn a_confirmed_track_first_seen_outside_the_ground_zone_can_enter_after_frame_128() -> Test {
    let mut f = Fixture::new("moving", &scene(300, true, false, false)?, "mjpeg")?;
    f.plan.zones[0].x = 28.0;
    let before = f.snapshot();
    let report = f.analyze(false)?;
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(report.entries().len(), 2);
    assert!(
        report
            .samples()
            .iter()
            .all(|sample| sample.entry_position > 128 && sample.tracker_epoch == 0)
    );
    // The already-confirmed local track survives the long outside-zone portion of the recording.
    assert_eq!(
        report.samples()[0].local_track_id,
        report.samples()[1].local_track_id
    );
    assert!(report.to_json(0, None)?.contains("\"confirmed_tracks\":1"));
    assert_eq!(
        report.candidates()[0].event().state,
        EventState::Corroborated
    );
    assert!(
        report.candidates()[0]
            .event()
            .uncertainty_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("does not prove physical arrival"))
    );
    assert_eq!(f.snapshot(), before);
    assert_eq!(
        report.analysis_digest(),
        f.analyze(false)?.analysis_digest()
    );
    Ok(())
}

#[test]
fn decoder_recovery_separates_track_keys_but_keeps_retained_capture_hints() -> Test {
    let f = Fixture::new("decode-gap", &scene(40, false, true, false)?, "mjpeg")?;
    let before = f.snapshot();
    assert!(f.analyze(false).is_err());
    let report = f.analyze(true)?;
    assert_eq!(report.candidates().len(), 2);
    assert_eq!(report.entries().len(), 4);
    let left: Vec<_> = report
        .entries()
        .iter()
        .zip(report.samples())
        .filter(|(entry, _)| entry.camera == 0)
        .collect();
    assert_eq!(
        left.iter()
            .map(|(_, sample)| (sample.entry_position, sample.tracker_epoch))
            .collect::<Vec<_>>(),
        [(5, 0), (26, 1)]
    );
    assert_eq!(left[0].1.local_track_id, left[1].1.local_track_id);
    assert_ne!(left[0].0.track_id, left[1].0.track_id);
    assert!(
        report
            .entries()
            .iter()
            .all(|entry| entry.disposition == EntryDisposition::Corroborated)
    );
    let json = report.to_json(0, None)?;
    assert!(json.contains("\"frames_decoded\":39"));
    assert!(json.contains("\"tracking_restarts\":1"));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn source_gap_entries_remain_diagnostic_and_never_enter_cross_camera_assignment() -> Test {
    let f = Fixture::new("source-gap", &scene(40, false, false, true)?, "mjpeg")?;
    let before = f.snapshot();
    assert!(f.analyze(false).is_err());
    let report = f.analyze(true)?;
    assert_eq!(report.entries().len(), 4);
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(
        report
            .entries()
            .iter()
            .filter(|entry| entry.disposition == EntryDisposition::CaptureTimeUnreliableAfterGap)
            .count(),
        2
    );
    assert!(
        report
            .to_json(0, None)?
            .contains("\"unreliable_time_frames\":20")
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn any_masked_ground_preimage_withdraws_that_cameras_support_even_with_an_unmasked_target() -> Test
{
    let mut f = Fixture::new("mask-preimage", &scene(40, false, false, false)?, "mjpeg")?;
    assert_eq!(f.analyze(false)?.candidates().len(), 1);
    // A bottom corner of the ground zone, completely outside the foreground target at y8..24.
    f.mask("east", [8, 30, 2, 2])?;
    let before = f.snapshot();
    let report = f.analyze(false)?;
    assert_eq!(report.entries().len(), 1);
    assert_eq!(report.entries()[0].camera, 1);
    assert_eq!(
        report.entries()[0].disposition,
        EntryDisposition::NoCounterpartEntry
    );
    assert!(report.candidates().is_empty());
    assert!(
        report
            .to_json(0, None)?
            .contains("\"masked_zones\":[\"door\"]")
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn second_camera_privacy_a_to_b_to_a_refuses_old_reports_and_proposal_tokens() -> Test {
    let mut f = Fixture::new(
        "privacy-generation",
        &scene(40, false, false, false)?,
        "mjpeg",
    )?;
    f.mask("west", [40, 0, 4, 4])?;
    let mut old = f.analyze(false)?;
    let approvals = BTreeSet::from([old.candidates()[0].proposal_digest()]);
    f.mask("west", [44, 0, 4, 4])?;
    f.mask("west", [40, 0, 4, 4])?;
    let before = f.snapshot();
    assert!(old.publish(&mut f.deployment, &approvals, &f.cx).is_err());
    let mut fresh = f.analyze(false)?;
    assert_ne!(old.analysis_digest(), fresh.analysis_digest());
    assert!(matches!(
        fresh.publish(&mut f.deployment, &approvals, &f.cx),
        Err(CorroborationError::StaleApproval(_))
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn damaged_second_camera_source_or_background_capsule_blocks_first_publish_and_retry() -> Test {
    for capsule in [false, true] {
        for published in [false, true] {
            let mut f = Fixture::new("custody", &scene(40, false, false, false)?, "mjpeg")?;
            let mut report = f.analyze(false)?;
            let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
            if published {
                assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 1);
            }
            let retained = RetainedFileImport::open(
                &f.deployment,
                f.plan.cameras[1].import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )?;
            let digest = if capsule {
                let object = format!(
                    "object:capsule:{}",
                    retained.manifest().segment_spans[1].capsule_id
                );
                f.deployment
                    .ledger()
                    .batches()
                    .iter()
                    .flat_map(|batch| &batch.deltas)
                    .find(|delta| delta.object_id.as_str() == object)
                    .ok_or("capsule authority")?
                    .payload_digest
            } else {
                retained.manifest().ordered_chunks[0]
            };
            let path = f.deployment.publisher().spool().object_path(digest);
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("empty object")? ^= 0x80;
            fs::write(path, bytes)?;
            let before = f.snapshot();
            assert!(
                report
                    .publish(&mut f.deployment, &approvals, &f.cx)
                    .is_err()
            );
            assert_eq!(f.snapshot(), before);
        }
    }
    Ok(())
}

#[test]
fn entry_provenance_cancellation_reopens_the_retained_full_recipe_and_one_exact_event() -> Test {
    let mut f = Fixture::new("cancel-recipe", &scene(40, false, false, false)?, "mjpeg")?;
    f.plan.cameras[1].homography.matrix[2] = 0.125;
    f.plan.cameras[1].homography.matrix[5] = -0.25;
    f.plan.zones[0].x = 8.125;
    f.plan.zones[0].width = 15.5;
    f.plan.gates.time_gate_ns = 123_456_789;
    f.plan.gates.distance_gate = 3.25;
    f.plan.detector.base_threshold = 31;
    f.plan.detector.threshold_sigma = 2;
    f.plan.detector.learning_rate_den = 17;
    f.plan.detector.minimum_region_pixels = 20;
    f.plan.tracker.confirmation_hits = 4;
    f.plan.tracker.maximum_missed_frames = 4;
    f.plan.tracker.minimum_iou_ppm = 220_000;
    let options = CorroborationOptions {
        tolerate_decode_refusals: true,
    };
    let limits = nondefault_recipe_limits();
    let dependencies = CorroborationDependencies::new(vec![
        FailureDomainDeclaration {
            domain: "clock:east".into(),
            cameras: vec!["east".into()],
        },
        FailureDomainDeclaration {
            domain: "clock:west".into(),
            cameras: vec!["west".into()],
        },
    ])?;
    let mut report = LongCorroborationReport::analyze(
        &f.deployment,
        &f.plan,
        options,
        &limits,
        &dependencies,
        &f.cx,
    )?;
    let expected_analysis = report.analysis_digest();
    let recipe_digest = report.plan_digest();
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let event_id = report.candidates()[0].event().event_id.clone();
    f.cx.set_cancel_at_checkpoint(STAGE_LONG_CORROBORATION_COMMIT);
    assert!(
        report
            .publish(&mut f.deployment, &approvals, &f.cx)
            .is_err()
    );
    assert!(f.deployment.current_event_authority(&event_id).is_err());
    let root = f.deployment.root().to_path_buf();
    // Reconstruct the execution from retained bytes after discarding the ephemeral report.
    drop(report);
    drop(f.deployment);
    let cx = context(&root)?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let recipe_bytes = reopened.publisher().spool().read(recipe_digest)?;
    let recipe = LongCorroborationRecipe::from_retained_bytes(&recipe_bytes, recipe_digest)?;
    assert_eq!(recipe.plan(), &f.plan);
    assert_eq!(recipe.options(), options);
    assert_eq!(recipe.dependencies(), &dependencies);
    assert!(!recipe.health_screened());
    assert_recipe_limits(recipe.limits(), &limits);
    assert_eq!(recipe.to_bytes(), recipe_bytes);
    let mut retry = recipe.analyze(&reopened, &cx)?;
    assert_eq!(retry.analysis_digest(), expected_analysis);
    assert_eq!(retry.publish(&mut reopened, &approvals, &cx)?, 1);
    assert_eq!(
        retry.candidates()[0].status(),
        CorroborationStatus::Published
    );
    let anchor = reopened.current_anchor().clone();
    assert_eq!(retry.publish(&mut reopened, &approvals, &cx)?, 0);
    assert_eq!(*reopened.current_anchor(), anchor);
    assert_eq!(reopened.effects().operations().count(), 0);
    // Health selection and its exact fixed policy also round-trip without running a screen.
    let screened = LongCorroborationRecipe::new(&f.plan, options, &limits, &dependencies, true)?;
    assert!(
        LongCorroborationRecipe::from_retained_bytes(&screened.to_bytes(), screened.digest())?
            .health_screened()
    );
    let mut wrong_plan = f.plan.clone();
    wrong_plan.zones[0].width += 0.25;
    let wrong_bytes =
        LongCorroborationRecipe::new(&wrong_plan, options, &limits, &dependencies, false)?
            .to_bytes();
    assert!(LongCorroborationRecipe::from_retained_bytes(&wrong_bytes, recipe_digest).is_err());
    assert_eq!(wrong_bytes.len(), recipe_bytes.len());
    let overlong = vec![0; MAX_LONG_CORROBORATION_RECIPE_BYTES + 1];
    assert!(matches!(
        LongCorroborationRecipe::from_retained_bytes(&overlong, recipe_digest),
        Err(CorroborationError::Limit)
    ));
    let mut trailing = recipe_bytes.clone();
    trailing.push(0);
    assert!(
        LongCorroborationRecipe::from_retained_bytes(&trailing, ContentDigest::sha256(&trailing))
            .is_err()
    );
    // A different valid recipe cannot replace the pinned payload under an already published root.
    let path = reopened.publisher().spool().object_path(recipe_digest);
    let mut on_disk = fs::read(&path)?;
    let start = on_disk
        .windows(recipe_bytes.len())
        .position(|window| window == recipe_bytes.as_slice())
        .ok_or("recipe payload")?;
    on_disk[start..start + recipe_bytes.len()].copy_from_slice(&wrong_bytes);
    fs::write(path, on_disk)?;
    assert!(reopened.publisher().spool().read(recipe_digest).is_err());
    assert!(retry.publish(&mut reopened, &approvals, &cx).is_err());
    assert_eq!(*reopened.current_anchor(), anchor);
    assert_eq!(reopened.effects().operations().count(), 0);
    Ok(())
}

fn nondefault_recipe_limits() -> LongCorroborationLimits {
    let mut value = LongCorroborationLimits::default();
    value.maximum_source_chunk_bytes = 2 * 1024 * 1024;
    value.maximum_pixel_samples = 2_000_000;
    value.maximum_assignment_work = 32_000_000;
    value.maximum_trace_bytes = 262_144;
    value.decode.read_limits = RetainedReadLimits {
        max_source_bytes: 2 * 1024 * 1024,
        max_chunk_bytes: 4096,
        max_segment_bytes: 65_536,
    };
    value.decode.jpeg_limits = fss_codec_mjpeg::DecodeLimits {
        maximum_bytes: 1_048_576,
        maximum_dimension: 128,
        maximum_pixels: 8192,
        maximum_markers: 99,
    };
    value.decode.jpeg_work_units = 11_000_000;
    value.decode.h264_limits = fss_codec_h264::DecoderLimits {
        max_width: 128,
        max_height: 96,
        max_macroblocks: 512,
        max_pictures: 512,
        max_nal_bytes: 262_144,
        max_slices_per_picture: 9,
        max_reference_frames: 4,
    };
    value.decode.h265_limits = fss_codec_h265::DecoderLimits {
        max_width: 128,
        max_height: 96,
        max_luma_samples: 16_384,
        max_pictures: 512,
        max_nal_bytes: 524_288,
        max_slices_per_picture: 7,
        max_dpb_pictures: 8,
    };
    value
}
fn assert_recipe_limits(actual: &LongCorroborationLimits, expected: &LongCorroborationLimits) {
    assert_eq!(
        actual.maximum_source_chunk_bytes,
        expected.maximum_source_chunk_bytes
    );
    assert_eq!(actual.maximum_pixel_samples, expected.maximum_pixel_samples);
    assert_eq!(
        actual.maximum_assignment_work,
        expected.maximum_assignment_work
    );
    assert_eq!(actual.maximum_trace_bytes, expected.maximum_trace_bytes);
    assert_eq!(actual.decode.read_limits, expected.decode.read_limits);
    assert_eq!(
        actual.decode.jpeg_work_units,
        expected.decode.jpeg_work_units
    );
    assert_eq!(
        actual.decode.jpeg_limits.maximum_bytes,
        expected.decode.jpeg_limits.maximum_bytes
    );
    assert_eq!(
        actual.decode.jpeg_limits.maximum_dimension,
        expected.decode.jpeg_limits.maximum_dimension
    );
    assert_eq!(
        actual.decode.jpeg_limits.maximum_pixels,
        expected.decode.jpeg_limits.maximum_pixels
    );
    assert_eq!(
        actual.decode.jpeg_limits.maximum_markers,
        expected.decode.jpeg_limits.maximum_markers
    );
    assert_eq!(actual.decode.h264_limits, expected.decode.h264_limits);
    assert_eq!(actual.decode.h265_limits, expected.decode.h265_limits);
}

#[test]
fn a_whole_recording_entry_inventory_overflow_refuses_instead_of_dropping_tracks() -> Test {
    let quiet = jpeg(None)?;
    let target = jpeg(Some(8))?;
    let mut bytes = quiet.clone();
    for _ in 0..65 {
        for _ in 0..3 {
            bytes.extend_from_slice(&target);
        }
        for _ in 0..3 {
            bytes.extend_from_slice(&quiet);
        }
    }
    let f = Fixture::new("entry-bound", &bytes, "mjpeg")?;
    let before = f.snapshot();
    assert!(matches!(
        LongCorroborationReport::analyze(
            &f.deployment,
            &f.plan,
            CorroborationOptions::default(),
            &LongCorroborationLimits::default(),
            &CorroborationDependencies::default(),
            &f.cx
        ),
        Err(CorroborationError::Limit)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn invalid_observed_ground_projection_keeps_its_typed_error_and_writes_nothing() -> Test {
    let mut f = Fixture::new("horizon", &scene(40, false, false, false)?, "mjpeg")?;
    f.plan.cameras[1].homography.matrix = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.01, -1.0];
    let before = f.snapshot();
    assert!(
        matches!(LongCorroborationReport::analyze(&f.deployment, &f.plan,
        CorroborationOptions::default(), &LongCorroborationLimits::default(),
        &CorroborationDependencies::default(), &f.cx), Err(CorroborationError::InvalidHomography { camera, .. }) if camera == "west")
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn native_inter_coded_sources_keep_the_same_cumulative_per_camera_read_ceiling() -> Test {
    for (label, bytes) in [
        (
            "avc",
            include_bytes!("fixtures/long_dwell_h264/square_300.mp4").as_slice(),
        ),
        (
            "hevc",
            include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.mp4").as_slice(),
        ),
    ] {
        let f = Fixture::new(label, bytes, "mp4")?;
        let before = f.snapshot();
        for tolerant in [false, true] {
            let limits = LongCorroborationLimits {
                maximum_source_chunk_bytes: 1,
                ..LongCorroborationLimits::default()
            };
            let error = LongCorroborationReport::analyze(
                &f.deployment,
                &f.plan,
                CorroborationOptions {
                    tolerate_decode_refusals: tolerant,
                },
                &limits,
                &CorroborationDependencies::default(),
                &f.cx,
            )
            .err()
            .ok_or("read bound must refuse")?;
            assert_eq!(error.stable_id(), "ERR-WATCH-LIMIT-001");
            assert_eq!(f.snapshot(), before);
        }
        let source = RetainedFileImport::open(
            &f.deployment,
            f.plan.cameras[0].import_identity,
            RetainedReadLimits::default(),
            &f.cx,
        )?;
        let expected = source.manifest().segment_spans.len();
        if label == "avc" {
            assert_eq!(expected, 300);
        }
        let report = f.analyze(false)?;
        let json = report.to_json(0, None)?;
        assert_eq!(
            json.matches(&format!("\"frames_decoded\":{expected}"))
                .count(),
            2
        );
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}
