#![forbid(unsafe_code)]
//! Two-camera corroboration remains available without acquiring the active capture publisher.

#[allow(clippy::duplicate_mod)]
#[path = "../../../../../fss-reference/tests/cascade_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_reference::ingest::{FileFormatHint, RetainedFileImport};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

use super::*;
use support::{Fixture, SITE, TestResult as Test};

const AVC: &[u8] =
    include_bytes!("../../../../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!(
    "../../../../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.h265"
);

fn scene() -> Test<Vec<u8>> {
    scene_with_background(40)
}

fn scene_with_background(background: u8) -> Test<Vec<u8>> {
    let mut stream = Vec::new();
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    for index in 0..14_usize {
        let mut pixels = vec![background; 96 * 48];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(stream)
}

fn ingest_pair(
    fixture: &mut Fixture,
    name: &str,
    bytes: &[u8],
    format: FileFormatHint,
) -> Test<[ContentDigest; 2]> {
    // Separate MJPEG payloads make damage to the second camera independent of the first.
    let alternate = matches!(format, FileFormatHint::JpegStream)
        .then(|| scene_with_background(41))
        .transpose()?;
    Ok([
        fixture.ingest(&format!("{name}-east"), bytes, format, Some(0))?,
        fixture.ingest(
            &format!("{name}-west"),
            alternate.as_deref().unwrap_or(bytes),
            format,
            Some(0),
        )?,
    ])
}

fn request_args(
    root: &Path,
    imports: [ContentDigest; 2],
    interpretation: &str,
    zone: &str,
) -> Vec<OsString> {
    vec![
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--principal".into(),
        "principal:cascade".into(),
        "--camera".into(),
        format!("east:{}", imports[0].to_text()).into(),
        "--camera".into(),
        format!("west:{}", imports[1].to_text()).into(),
        "--ground".into(),
        "east:1,0,0,0,1,0,0,0,1".into(),
        "--ground".into(),
        "west:1,0,0,0,1,0,0,0,1".into(),
        "--interpretation".into(),
        interpretation.into(),
        "--zone".into(),
        zone.into(),
        "--time-gate-ns".into(),
        "250000000".into(),
        "--distance-gate".into(),
        "16".into(),
    ]
}

fn request_mode(root: &Path, imports: [ContentDigest; 2], whole: bool) -> Test<CorroborateAction> {
    let mut args = request_args(root, imports, "gray", "door:64,0,32,32");
    if whole {
        args.push("--stream-corroborate".into());
    }
    Ok(super::super::parse(&args)?)
}

fn read_context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:corroborate-immutable".into(),
        operation_id: OperationId::parse("operation:corroborate-immutable")?,
        principal: "principal:cascade".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(
        &authority,
        root.to_path_buf(),
    )?)
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(root, &path, files)?;
            } else {
                assert!(entry.file_type()?.is_file(), "unexpected test fixture link");
                files.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files)?;
    Ok(files)
}

#[test]
fn active_writer_previews_preserve_native_mjpeg_avc_hevc_and_screened_reports() -> Test {
    active_writer_previews(false)
}

#[test]
fn whole_active_writer_previews_preserve_native_mjpeg_avc_hevc_and_screened_reports() -> Test {
    active_writer_previews(true)
}

fn active_writer_previews(whole: bool) -> Test {
    let mut fixture = Fixture::new(&format!("immutable-corroborate-native-{whole}"))?;
    let root = fixture.deployment.root().to_path_buf();
    let mjpeg = ingest_pair(
        &mut fixture,
        "sensor:immutable-mjpeg",
        &scene()?,
        FileFormatHint::JpegStream,
    )?;
    let avc = ingest_pair(
        &mut fixture,
        "sensor:immutable-avc",
        AVC,
        FileFormatHint::AnnexB,
    )?;
    let hevc = ingest_pair(
        &mut fixture,
        "sensor:immutable-hevc",
        HEVC,
        FileFormatHint::Hevc,
    )?;
    fs::write(
        root.join("LAYOUT.tmp.immutable-must-preserve"),
        b"unrelated recovery state",
    )?;
    let before = tree(&root)?;
    let scalar = ScalarExecCx::new();
    for (import, interpretation, zone, mode) in [
        (mjpeg, "gray", "door:64,0,32,32", "plain"),
        (avc, "ycbcr", "scene:0,0,176,144", "plain"),
        (hevc, "ycbcr", "door:64,0,32,32", "plain"),
        (mjpeg, "gray", "door:64,0,32,32", "screened"),
        (mjpeg, "gray", "door:64,0,32,32", "dependent"),
        (mjpeg, "gray", "door:64,0,32,32", "posed"),
    ] {
        let mut args = request_args(&root, import, interpretation, zone);
        if whole {
            args.push("--stream-corroborate".into());
        }
        match mode {
            "screened" => args.extend(["--sensor-health".into(), "conservative-v1".into()]),
            "dependent" => {
                args.extend(["--failure-domain".into(), "power:mains=east,west".into()]);
            }
            "posed" => {
                args.extend([
                    "--pose".into(),
                    "east:96,48,1,1,0,0,1,0,0,0,1,0,0,0,1,0,0,1".into(),
                ]);
            }
            _ => {}
        }
        let action = super::super::parse(&args)?;
        let mut native = Vec::new();
        super::super::run_with(
            &action,
            &mut fixture.deployment,
            &root,
            &fixture.cx,
            &scalar,
            &mut native,
        )?;
        // Exercise the actual command dispatch while the original publisher remains open.
        args.insert(0, "corroborate".into());
        let options = crate::parse(&args)?.ok_or("corroborate unexpectedly parsed as help")?;
        let mut preview = Vec::new();
        crate::run(options, &mut preview)?;
        assert_eq!(preview, native, "{interpretation}, mode={mode}");
        assert_eq!(tree(&root)?, before, "preview mutated an active deployment");
    }
    for retain_health in [false, true] {
        if retain_health && !whole {
            continue;
        }
        let mut approval = request_args(&root, mjpeg, "gray", "door:64,0,32,32");
        if whole {
            approval.push("--stream-corroborate".into());
        }
        if retain_health {
            approval.extend(["--sensor-health".into(), "conservative-v1".into()]);
        }
        approval.extend([
            if retain_health {
                "--retain-health"
            } else {
                "--approve"
            }
            .into(),
            ContentDigest::sha256(b"explicit approval").to_text().into(),
        ]);
        approval.insert(0, "corroborate".into());
        let options = crate::parse(&approval)?.ok_or("corroborate unexpectedly parsed as help")?;
        let mut output = Vec::new();
        let refused =
            crate::run(options, &mut output).expect_err("approval bypassed active publisher");
        assert!(matches!(
            refused.downcast_ref::<fss_reference::ReferenceError>(),
            Some(fss_reference::ReferenceError::DeploymentLocked { .. })
        ));
        assert!(output.is_empty());
        assert_eq!(tree(&root)?, before);
    }
    scalar.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn whole_preview_finds_both_camera_entries_beyond_the_short_window() -> Test {
    let mut fixture = Fixture::new("immutable-corroborate-long-entry")?;
    let mut imports = Vec::new();
    for (camera, background) in [("east", 40), ("west", 41)] {
        let quiet = encode_jpeg(
            96,
            48,
            &vec![background; 96 * 48],
            &JpegConfig {
                quality: 90,
                subsampling: Subsampling::Grayscale,
                restart_interval: 0,
                custom_markers: Vec::new(),
            },
        )?;
        let mut recording = quiet.repeat(128);
        recording.extend(scene_with_background(background)?);
        imports.push(fixture.ingest(
            &format!("sensor:immutable-long-{camera}"),
            &recording,
            FileFormatHint::JpegStream,
            Some(0),
        )?);
    }
    let root = fixture.deployment.root();
    let action = request_mode(root, [imports[0], imports[1]], true)?;
    let before = tree(root)?;
    let scalar = ScalarExecCx::new();
    let limits = action.streaming.as_ref().ok_or("missing whole limits")?;
    let (native, fusion) =
        streaming::analyze(&action, &fixture.deployment, limits, &fixture.cx, &scalar)?;
    assert_eq!(native.candidates().len(), 1);
    assert_eq!(native.entries().len(), 2);
    assert!(native.entries().iter().all(|entry| entry.segment >= 128));
    assert!(
        native
            .source_cameras()
            .all(|(camera, _)| camera.frames == 142)
    );
    let expected = format!(
        "{}\n",
        streaming::render(
            &action,
            &native,
            fixture.deployment.current_anchor().commit_sequence,
            None,
            fusion.as_ref(),
        )?
    );
    let mut preview = Vec::new();
    run(&action, &mut preview)?;
    assert_eq!(preview, expected.as_bytes());
    assert_eq!(tree(root)?, before);
    scalar.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn whole_health_degraded_quiet_preview_preserves_diagnostics_and_blocks_derived_use() -> Test {
    let mut fixture = Fixture::new("immutable-corroborate-health-degraded")?;
    let quiet = encode_jpeg(
        96,
        48,
        &vec![0; 96 * 48],
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?
    .repeat(40);
    let east = fixture.ingest(
        "sensor:immutable-dark-east",
        &quiet,
        FileFormatHint::JpegStream,
        Some(0),
    )?;
    let west = fixture.ingest(
        "sensor:immutable-dark-west",
        &quiet,
        FileFormatHint::JpegStream,
        Some(0),
    )?;
    let root = fixture.deployment.root();
    let mut args = request_args(root, [east, west], "gray", "door:64,0,32,32");
    args.extend([
        "--stream-corroborate".into(),
        "--sensor-health".into(),
        "conservative-v1".into(),
    ]);
    let action = super::super::parse(&args)?;
    let before = tree(root)?;
    let scalar = ScalarExecCx::new();
    let (native, fusion) = streaming::analyze(
        &action,
        &fixture.deployment,
        action.streaming.as_ref().ok_or("missing whole limits")?,
        &fixture.cx,
        &scalar,
    )?;
    assert!(native.publication_blocked());
    assert!(native.candidates().is_empty());
    assert_eq!(native.health_diagnostics().count(), 2);
    assert!(
        native
            .revalidate_derived_sources(&fixture.deployment, &fixture.cx)
            .is_err()
    );
    let expected = format!(
        "{}\n",
        streaming::render(
            &action,
            &native,
            fixture.deployment.current_anchor().commit_sequence,
            None,
            fusion.as_ref(),
        )?
    );
    let mut preview = Vec::new();
    run(&action, &mut preview)?;
    assert_eq!(preview, expected.as_bytes());
    assert!(expected.contains("\"publication_blocked\":true"));
    assert_eq!(tree(root)?, before);
    scalar.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn final_rereads_share_exact_allowance_and_short_allowances_emit_and_save_nothing() -> Test {
    final_rereads(false)
}

#[test]
fn whole_fusion_delivery_keeps_the_final_cancellation_boundary_with_either_owner() -> Test {
    for immutable in [false, true] {
        let mut fixture = Fixture::new(&format!("immutable-fusion-delivery-{immutable}"))?;
        let imports = ingest_pair(
            &mut fixture,
            "sensor:immutable-fusion-delivery",
            &scene()?,
            FileFormatHint::JpegStream,
        )?;
        let root = fixture.deployment.root();
        let action = request_mode(root, imports, true)?;
        let before = tree(root)?;
        let cx = read_context(root)?;
        let scalar = ScalarExecCx::new();
        let source = ImmutableRetainedSource::open(root, action.read_limits, &cx)?;
        let owner: &dyn RetainedSource = if immutable {
            &source
        } else {
            &fixture.deployment
        };
        let (native, _) = streaming::analyze(
            &action,
            owner,
            action.streaming.as_ref().ok_or("missing whole limits")?,
            &cx,
            &scalar,
        )?;
        streaming::revalidate_fusion_delivery(&native, owner, &cx)?;
        cx.set_cancel_at_checkpoint("event_fusion:long_corroboration_delivery");
        assert!(streaming::revalidate_fusion_delivery(&native, owner, &cx).is_err());
        assert!(cx.is_cancelled(), "the final advice boundary was skipped");
        assert_eq!(tree(root)?, before);
        scalar.drain_and_finalize();
        cx.drain_and_finalize();
        fixture.cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn whole_final_rereads_share_exact_allowance_and_short_allowances_emit_and_save_nothing() -> Test {
    final_rereads(true)
}

fn final_rereads(whole: bool) -> Test {
    let mut fixture = Fixture::new(&format!("immutable-corroborate-budget-{whole}"))?;
    let import = ingest_pair(
        &mut fixture,
        "sensor:immutable-budget",
        &scene()?,
        FileFormatHint::JpegStream,
    )?;
    let root = fixture.deployment.root();
    let before = tree(root)?;
    let mut action = request_mode(root, import, whole)?;
    let cx = read_context(root)?;
    let scalar = ScalarExecCx::new();
    let mut expected = Vec::new();
    let total = run_with(&action, root, &cx, &scalar, &|| false, &mut expected)?;
    action.read_limits.max_read_bytes = usize::try_from(total.read_bytes)?;
    action.read_limits.max_read_objects = usize::try_from(total.read_objects)?;
    let exact = action.read_limits;
    let mut output = Vec::new();
    assert_eq!(
        run_with(&action, root, &cx, &scalar, &|| false, &mut output)?,
        total
    );
    assert_eq!(output, expected);
    let report = fixture.directory.0.join("refused-report.json");
    action.report_out = Some(report.clone());
    for bytes in [true, false] {
        action.read_limits = exact;
        if bytes {
            action.read_limits.max_read_bytes -= 1;
        } else {
            action.read_limits.max_read_objects -= 1;
        }
        let mut refused = Vec::new();
        assert!(run_with(&action, root, &cx, &scalar, &|| false, &mut refused).is_err());
        assert!(refused.is_empty());
        assert!(
            !report.exists(),
            "refused final revalidation saved a report"
        );
        assert_eq!(tree(root)?, before);
    }
    action.read_limits = exact;
    let mut exported = Vec::new();
    run_with(&action, root, &cx, &scalar, &|| false, &mut exported)?;
    assert_eq!(exported, expected);
    assert_eq!(fs::read(report)?, expected);
    assert_eq!(tree(root)?, before);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cancellation_at_the_last_admission_withholds_stdout_and_external_report() -> Test {
    cancellation_at_delivery(false)
}

#[test]
fn whole_cancellation_at_the_last_admission_withholds_stdout_and_external_report() -> Test {
    cancellation_at_delivery(true)
}

fn cancellation_at_delivery(whole: bool) -> Test {
    let mut fixture = Fixture::new(&format!("immutable-corroborate-final-cancel-{whole}"))?;
    let import = ingest_pair(
        &mut fixture,
        "sensor:immutable-cancel",
        &scene()?,
        FileFormatHint::JpegStream,
    )?;
    let root = fixture.deployment.root();
    let before = tree(root)?;
    let mut action = request_mode(root, import, whole)?;
    let cx = read_context(root)?;
    let scalar = ScalarExecCx::new();
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    run_with(&action, root, &cx, &scalar, &count, &mut Vec::new())?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > 1);
    calls.store(0, Ordering::SeqCst);
    let cancel_last = || calls.fetch_add(1, Ordering::SeqCst) + 1 >= last;
    let report = fixture.directory.0.join("cancelled-report.json");
    action.report_out = Some(report.clone());
    let mut output = Vec::new();
    assert!(run_with(&action, root, &cx, &scalar, &cancel_last, &mut output).is_err());
    // Error classification may observe the already-signalled cancellation once more.
    assert!(calls.load(Ordering::SeqCst) >= last);
    assert!(output.is_empty());
    assert!(!report.exists());
    assert_eq!(tree(root)?, before);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn late_quiet_capsule_or_source_damage_refuses_without_output_export_or_repair() -> Test {
    late_damage(false)
}

#[test]
fn whole_late_quiet_capsule_or_source_damage_refuses_without_output_export_or_repair() -> Test {
    late_damage(true)
}

fn late_damage(whole: bool) -> Test {
    for capsule in [true, false] {
        let mut fixture = Fixture::new(&format!(
            "immutable-corroborate-late-damage-{whole}-{capsule}"
        ))?;
        let import = ingest_pair(
            &mut fixture,
            "sensor:immutable-damage",
            &scene()?,
            FileFormatHint::JpegStream,
        )?;
        let root = fixture.deployment.root();
        let mut action = request_mode(root, import, whole)?;
        // Tolerant decode still cannot excuse damaged retained source custody.
        if !capsule {
            action.recovery.tolerate_decode_refusals = true;
        }
        let retained = RetainedFileImport::open(
            &fixture.deployment,
            import[1],
            action.limits.read_limits,
            &fixture.cx,
        )?;
        let digest = if capsule {
            // The second camera's first frame is quiet. Its custody still belongs to the result.
            let object = format!(
                "object:capsule:{}",
                retained.manifest().capsule_ids[0].as_str()
            );
            fixture
                .deployment
                .ledger()
                .batches()
                .iter()
                .flat_map(|batch| &batch.deltas)
                .find(|delta| delta.object_id.as_str() == object)
                .ok_or("missing quiet capsule")?
                .payload_digest
        } else {
            retained.manifest().ordered_chunks[0]
        };
        let path = fixture.deployment.publisher().spool().object_path(digest);
        let mut damaged = fs::read(&path)?;
        *damaged.last_mut().ok_or("empty retained payload")? ^= 1;
        let mut permissions = fs::metadata(&path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions)?;
        let scalar = ScalarExecCx::new();
        let calibration = read_context(root)?;
        calibration.set_cancel_at_checkpoint("corroborate_preview:delivery");
        let calls = AtomicUsize::new(0);
        let count = || {
            calls.fetch_add(1, Ordering::SeqCst);
            false
        };
        let mut refused = Vec::new();
        assert!(run_with(&action, root, &calibration, &scalar, &count, &mut refused).is_err());
        assert!(refused.is_empty());
        let selected_calls = calls.load(Ordering::SeqCst);
        calibration.drain_and_finalize();
        calls.store(0, Ordering::SeqCst);
        let fired = AtomicBool::new(false);
        let mutate_after_analysis = || {
            if calls.fetch_add(1, Ordering::SeqCst) == selected_calls {
                fired.store(fs::write(&path, &damaged).is_ok(), Ordering::SeqCst);
            }
            false
        };
        let report = fixture.directory.0.join("damaged-report.json");
        action.report_out = Some(report.clone());
        let cx = read_context(root)?;
        let mut output = Vec::new();
        assert!(
            run_with(
                &action,
                root,
                &cx,
                &scalar,
                &mutate_after_analysis,
                &mut output
            )
            .is_err()
        );
        assert!(
            fired.load(Ordering::SeqCst),
            "damage injection was not reached"
        );
        assert!(output.is_empty());
        assert!(!report.exists());
        assert_eq!(fs::read(&path)?, damaged, "refusal repaired source custody");
        scalar.drain_and_finalize();
        cx.drain_and_finalize();
        fixture.cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn an_uncommitted_journal_tail_refuses_without_recovery_or_a_partial_report() -> Test {
    torn_tail(false)
}

#[test]
fn whole_uncommitted_journal_tail_refuses_without_recovery_or_a_partial_report() -> Test {
    torn_tail(true)
}

fn torn_tail(whole: bool) -> Test {
    let mut fixture = Fixture::new(&format!("immutable-corroborate-torn-tail-{whole}"))?;
    let import = ingest_pair(
        &mut fixture,
        "sensor:immutable-tail",
        &scene()?,
        FileFormatHint::JpegStream,
    )?;
    let root = fixture.deployment.root();
    let report = fixture.directory.0.join("torn-report.json");
    let mut args = request_args(root, import, "gray", "door:64,0,32,32");
    if whole {
        args.push("--stream-corroborate".into());
    }
    args.extend(["--report-out".into(), report.as_os_str().to_owned()]);
    args.insert(0, "corroborate".into());
    let journal = root.join(fss_reference::reference_deployment::RELATIVE_PATH_LEDGER);
    fs::OpenOptions::new()
        .append(true)
        .open(journal)?
        .write_all(b"torn native journal tail")?;
    let before = tree(root)?;
    let options = crate::parse(&args)?.ok_or("corroborate unexpectedly parsed as help")?;
    let mut output = Vec::new();
    assert!(crate::run(options, &mut output).is_err());
    assert!(output.is_empty());
    assert!(!report.exists());
    assert_eq!(
        tree(root)?,
        before,
        "immutable preview repaired an uncommitted tail"
    );
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn read_allowances_admit_whole_previews_but_never_route_publication_to_an_immutable_owner() -> Test
{
    let root = Path::new("/existing/deployment");
    let imports = [
        ContentDigest::sha256(b"east request-only fixture"),
        ContentDigest::sha256(b"west request-only fixture"),
    ];
    let base = request_args(root, imports, "gray", "door:64,0,32,32");
    let mut preview = base.clone();
    preview.extend([
        "--max-read-bytes".into(),
        "4096".into(),
        "--max-read-objects".into(),
        "100".into(),
    ]);
    let action = super::super::parse(&preview)?;
    assert!(action.is_immutable_preview());
    assert_eq!(action.read_limits.max_read_bytes, 4096);
    assert_eq!(action.read_limits.max_read_objects, 100);
    assert!(
        !action.rerun.contains("--max-read-"),
        "approval hint carries preview-only options"
    );
    let mut whole_preview = preview.clone();
    whole_preview.push("--stream-corroborate".into());
    let whole = super::super::parse(&whole_preview)?;
    assert!(whole.is_immutable_preview());
    assert!(whole.streaming.is_some());
    assert_eq!(whole.read_limits, action.read_limits);
    assert!(!whole.rerun.contains("--max-read-"));
    let approval = imports[0].to_text();
    for suffix in [
        vec!["--approve", approval.as_str()],
        vec!["--retain-coverage", approval.as_str()],
        vec!["--stream-corroborate", "--approve", approval.as_str()],
        vec![
            "--stream-corroborate",
            "--sensor-health",
            "conservative-v1",
            "--retain-health",
            approval.as_str(),
        ],
    ] {
        let mut legacy = base.clone();
        legacy.extend(suffix.iter().map(|value| OsString::from(*value)));
        assert!(!super::super::parse(&legacy)?.is_immutable_preview());
        let mut invalid = preview.clone();
        invalid.extend(suffix.iter().map(|value| OsString::from(*value)));
        assert!(super::super::parse(&invalid).is_err());
    }
    for invalid in ["0", "01", "+1", "4294967297"] {
        let mut args = base.clone();
        args.extend(["--max-read-bytes".into(), invalid.into()]);
        assert!(super::super::parse(&args).is_err(), "{invalid}");
    }
    Ok(())
}

#[test]
fn a_committed_companion_privacy_change_at_delivery_withholds_the_stale_pair() -> Test {
    privacy_change_at_delivery(false)
}

#[test]
fn whole_committed_companion_privacy_change_at_delivery_withholds_the_stale_pair() -> Test {
    privacy_change_at_delivery(true)
}

fn privacy_change_at_delivery(whole: bool) -> Test {
    use fss_core::SensorId;
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};

    let mut fixture = Fixture::new(&format!("immutable-corroboration-privacy-drift-{whole}"))?;
    let imports = ingest_pair(
        &mut fixture,
        "sensor:immutable-policy",
        &scene()?,
        FileFormatHint::JpegStream,
    )?;
    let root = fixture.deployment.root().to_path_buf();
    let mut action = request_mode(&root, imports, whole)?;
    let scalar = ScalarExecCx::new();

    // Build a real committed authority successor with the ordinary owner API. Replaying its
    // journal bytes at the chosen boundary changes valid policy, rather than corrupting bytes.
    let journal = root.join(fss_reference::reference_deployment::RELATIVE_PATH_LEDGER);
    let old_journal = fs::read(&journal)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:immutable-policy-west")?,
        [96, 48],
        &[[64, 0, 32, 32]],
    )?;
    let approval = preview_mask(&fixture.deployment, &policy)?.approval;
    declare_mask(&mut fixture.deployment, &policy, approval, &fixture.cx)?;
    let new_journal = fs::read(&journal)?;
    assert_ne!(new_journal, old_journal);
    let current = read_context(&root)?;
    let mut masked = Vec::new();
    run_with(&action, &root, &current, &scalar, &|| false, &mut masked)?;
    assert!(
        !masked.is_empty(),
        "committed successor is not a readable deployment"
    );
    current.drain_and_finalize();

    // The policy object stays immutable and readable; only the committed prefix is restored
    // until the simulated concurrent writer publishes the valid successor. Calibrate after
    // restoration so the final run sees exactly the same metadata and extra immutable objects.
    fs::write(&journal, &old_journal)?;
    let calibration = read_context(&root)?;
    calibration.set_cancel_at_checkpoint("corroborate_preview:delivery");
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    assert!(
        run_with(
            &action,
            &root,
            &calibration,
            &scalar,
            &count,
            &mut Vec::new(),
        )
        .is_err()
    );
    let selected_calls = calls.load(Ordering::SeqCst);
    assert!(selected_calls > 0);
    calibration.drain_and_finalize();

    let mut expected = tree(&root)?;
    expected.insert(
        PathBuf::from(fss_reference::reference_deployment::RELATIVE_PATH_LEDGER),
        new_journal.clone(),
    );
    calls.store(0, Ordering::SeqCst);
    let fired = AtomicBool::new(false);
    let advance_after_analysis = || {
        if calls.fetch_add(1, Ordering::SeqCst) == selected_calls {
            fired.store(fs::write(&journal, &new_journal).is_ok(), Ordering::SeqCst);
        }
        false
    };
    let report = fixture.directory.0.join("stale-pair-report.json");
    action.report_out = Some(report.clone());
    let cx = read_context(&root)?;
    let mut output = Vec::new();
    assert!(
        run_with(
            &action,
            &root,
            &cx,
            &scalar,
            &advance_after_analysis,
            &mut output,
        )
        .is_err()
    );
    assert!(
        fired.load(Ordering::SeqCst),
        "authority advance was not reached"
    );
    assert!(output.is_empty());
    assert!(!report.exists());
    assert_eq!(
        tree(&root)?,
        expected,
        "preview repaired or rewrote current policy"
    );
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}
