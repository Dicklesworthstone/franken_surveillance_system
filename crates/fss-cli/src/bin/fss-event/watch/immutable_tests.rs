#![forbid(unsafe_code)]
//! Short native watch results remain stable while one recorder owns the publisher.

#[path = "../../../../../fss-reference/tests/cascade_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_reference::ingest::FileFormatHint;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

use super::*;
use support::{Fixture, SITE, TestResult as Test};

const AVC: &[u8] =
    include_bytes!("../../../../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!(
    "../../../../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.h265"
);

fn scene() -> Test<Vec<u8>> {
    let mut stream = Vec::new();
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    for index in 0..14_usize {
        let mut pixels = vec![40; 96 * 48];
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

fn request_args(
    root: &Path,
    import: ContentDigest,
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
        "--import-id".into(),
        import.to_text().into(),
        "--interpretation".into(),
        interpretation.into(),
        "--zone".into(),
        zone.into(),
    ]
}

fn request(root: &Path, import: ContentDigest) -> Test<WatchAction> {
    Ok(super::super::parse(&request_args(
        root,
        import,
        "gray",
        "door:64,0,32,32",
    ))?)
}

fn read_context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:watch-immutable".into(),
        operation_id: OperationId::parse("operation:watch-immutable")?,
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
    let mut fixture = Fixture::new("immutable-watch-native")?;
    let root = fixture.deployment.root().to_path_buf();
    let mjpeg = fixture.ingest(
        "sensor:immutable-mjpeg",
        &scene()?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let avc = fixture.ingest("sensor:immutable-avc", AVC, FileFormatHint::AnnexB, None)?;
    let hevc = fixture.ingest("sensor:immutable-hevc", HEVC, FileFormatHint::Hevc, None)?;
    fs::write(
        root.join("LAYOUT.tmp.immutable-must-preserve"),
        b"unrelated recovery state",
    )?;
    let before = tree(&root)?;
    let scalar = ScalarExecCx::new();
    for (import, interpretation, zone, screened) in [
        (mjpeg, "gray", "door:64,0,32,32", false),
        (avc, "ycbcr", "scene:0,0,176,144", false),
        (hevc, "ycbcr", "door:64,0,32,32", false),
        (mjpeg, "gray", "door:64,0,32,32", true),
    ] {
        let mut args = request_args(&root, import, interpretation, zone);
        if screened {
            args.extend(["--sensor-health".into(), "conservative-v1".into()]);
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
        args.insert(0, "watch".into());
        let options = crate::parse(&args)?.ok_or("watch unexpectedly parsed as help")?;
        let mut preview = Vec::new();
        crate::run(options, &mut preview)?;
        assert_eq!(preview, native, "{interpretation}, screened={screened}");
        assert_eq!(tree(&root)?, before, "preview mutated an active deployment");
    }
    let mut approval = request_args(&root, mjpeg, "gray", "door:64,0,32,32");
    approval.extend([
        "--approve".into(),
        ContentDigest::sha256(b"explicit approval").to_text().into(),
    ]);
    approval.insert(0, "watch".into());
    let options = crate::parse(&approval)?.ok_or("watch unexpectedly parsed as help")?;
    let mut output = Vec::new();
    let refused = crate::run(options, &mut output).expect_err("approval bypassed active publisher");
    assert!(matches!(
        refused.downcast_ref::<fss_reference::ReferenceError>(),
        Some(fss_reference::ReferenceError::DeploymentLocked { .. })
    ));
    assert!(output.is_empty());
    assert_eq!(tree(&root)?, before);
    scalar.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn final_rereads_share_exact_allowance_and_short_allowances_emit_and_save_nothing() -> Test {
    let mut fixture = Fixture::new("immutable-watch-budget")?;
    let import = fixture.ingest(
        "sensor:immutable-budget",
        &scene()?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let root = fixture.deployment.root();
    let before = tree(root)?;
    let mut action = request(root, import)?;
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
    let mut fixture = Fixture::new("immutable-watch-final-cancel")?;
    let import = fixture.ingest(
        "sensor:immutable-cancel",
        &scene()?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let root = fixture.deployment.root();
    let before = tree(root)?;
    let mut action = request(root, import)?;
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
    for capsule in [true, false] {
        let mut fixture = Fixture::new(&format!("immutable-watch-late-damage-{capsule}"))?;
        let import = fixture.ingest(
            "sensor:immutable-damage",
            &scene()?,
            FileFormatHint::JpegStream,
            None,
        )?;
        let root = fixture.deployment.root();
        let mut action = request(root, import)?;
        // Tolerant decode still cannot excuse damaged retained source custody.
        if !capsule {
            action.options.tolerate_decode_refusals = true;
        }
        let retained = RetainedFileImport::open(
            &fixture.deployment,
            import,
            action.limits.read_limits,
            &fixture.cx,
        )?;
        let digest = if capsule {
            // The first frame is quiet. Its custody is still part of every complete result.
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
        calibration.set_cancel_at_checkpoint("watch_preview:delivery");
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
    let mut fixture = Fixture::new("immutable-watch-torn-tail")?;
    let import = fixture.ingest(
        "sensor:immutable-tail",
        &scene()?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let root = fixture.deployment.root();
    let report = fixture.directory.0.join("torn-report.json");
    let mut args = request_args(root, import, "gray", "door:64,0,32,32");
    args.extend(["--report-out".into(), report.as_os_str().to_owned()]);
    args.insert(0, "watch".into());
    let journal = root.join(fss_reference::reference_deployment::RELATIVE_PATH_LEDGER);
    fs::OpenOptions::new()
        .append(true)
        .open(journal)?
        .write_all(b"torn native journal tail")?;
    let before = tree(root)?;
    let options = crate::parse(&args)?.ok_or("watch unexpectedly parsed as help")?;
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
fn read_allowances_cover_temporal_previews_but_never_mutation_or_checkpoints() -> Test {
    let root = Path::new("/existing/deployment");
    let import = ContentDigest::sha256(b"request-only fixture");
    let base = request_args(root, import, "gray", "door:64,0,32,32");
    let mut preview = base.clone();
    preview.extend([
        "--max-read-bytes".into(),
        "4096".into(),
        "--max-read-objects".into(),
        "100".into(),
    ]);
    for suffix in [
        vec![],
        vec!["--stream-watch"],
        vec!["--dwell-for-ns", "100", "--dwell-max-gap-ns", "200"],
        vec![
            "--stream-dwell",
            "--dwell-for-ns",
            "100",
            "--dwell-max-gap-ns",
            "200",
        ],
    ] {
        let mut args = preview.clone();
        args.extend(suffix.iter().map(|value| OsString::from(*value)));
        let action = super::super::parse(&args)?;
        assert!(action.is_immutable_preview());
        assert_eq!(action.read_limits.max_read_bytes, 4096);
        assert_eq!(action.read_limits.max_read_objects, 100);
        assert!(
            !action.rerun.contains("--max-read-"),
            "approval hint carries preview-only options"
        );
    }
    let approval = import.to_text();
    for suffix in [
        vec!["--approve", approval.as_str()],
        vec!["--retain-coverage", approval.as_str()],
        vec![
            "--stream-watch",
            "--sensor-health",
            "conservative-v1",
            "--retain-health",
            approval.as_str(),
        ],
        vec![
            "--stream-dwell",
            "--dwell-for-ns",
            "100",
            "--dwell-max-gap-ns",
            "200",
            "--dwell-step-frames",
            "4",
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

#[path = "immutable_temporal_tests.rs"]
mod temporal;

#[test]
fn optical_watch_preserves_exact_policy_and_native_report_beside_capture() -> Test {
    let mut fixture = Fixture::new("immutable-watch-optical")?;
    let root = fixture.deployment.root().to_path_buf();
    let import = fixture.ingest(
        "sensor:immutable-optical",
        &scene()?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let before = tree(&root)?;
    let scalar = ScalarExecCx::new();
    let mut args = request_args(&root, import, "gray", "door:64,0,32,32");
    args.extend([
        "--sensor-health".into(),
        "conservative-optical-v1".into(),
        "--min-laplacian-variance-x1000".into(),
        u64::MAX.to_string().into(),
        "--glare-luma-min".into(),
        "239".into(),
        "--max-glare-ppm".into(),
        "75000".into(),
    ]);
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
    let report = std::str::from_utf8(&native)?;
    for expected in [
        "\"policy\":\"conservative-optical-v1\"",
        "severe_blur",
        "\"glare_luma_min\":239",
        "\"max_glare_ppm\":75000",
        "sensor_health_degraded",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
    assert!(action.rerun.contains("conservative-optical-v1"));
    assert!(action.rerun.contains("--min-laplacian-variance-x1000"));
    assert!(action.rerun.contains(&u64::MAX.to_string()));
    args.insert(0, "watch".into());
    let options = crate::parse(&args)?.ok_or("watch unexpectedly parsed as help")?;
    let mut preview = Vec::new();
    crate::run(options, &mut preview)?;
    assert_eq!(preview, native);
    assert_eq!(
        tree(&root)?,
        before,
        "optical preview mutated active capture state"
    );
    fixture.deployment.drain()?;
    Ok(())
}

#[test]
fn optical_watch_cannot_silently_downgrade_in_stream_or_dwell_modes() -> Test {
    let root = Path::new("/optical-policy-parse-only");
    let import = ContentDigest::sha256(b"parse-only-optical-import");
    for extra in [
        vec!["--stream-watch"],
        vec!["--stream-dwell"],
        vec!["--dwell-for-ns", "1000000", "--dwell-max-gap-ns", "1000000"],
    ] {
        let mut args = request_args(root, import, "gray", "door:64,0,32,32");
        args.extend(["--sensor-health".into(), "conservative-optical-v1".into()]);
        args.extend(extra.into_iter().map(OsString::from));
        let error = super::super::parse(&args).expect_err("unsupported optical mode");
        assert!(
            error.contains("requires short entry watch or short corroboration"),
            "{error}"
        );
    }
}
