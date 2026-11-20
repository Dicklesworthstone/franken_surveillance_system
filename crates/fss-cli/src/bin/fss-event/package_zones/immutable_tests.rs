#![forbid(unsafe_code)]
//! Native trained-zone reads retain their exact semantics without acquiring a publisher.

#[path = "../../../../../fss-reference/tests/qsr_observations_support/mod.rs"]
mod support;

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use support::{Fixture, PRINCIPAL, SITE, Test};

use super::*;

fn arguments(fixture: &Fixture, mode: &str) -> Vec<OsString> {
    let mut args = vec![
        mode.into(),
        "--root".into(),
        fixture.source.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--principal".into(),
        PRINCIPAL.into(),
    ];
    if mode == "analyze" {
        args.extend([
            "--package-report".into(),
            fixture.source.report.to_text().into(),
            "--label".into(),
            "numeric-a".into(),
            "--zone".into(),
            "image:0:0:32:16".into(),
            "--maximum-sample-gap-ns".into(),
            "110000000".into(),
            "--minimum-iou-ppm".into(),
            "0".into(),
            "--require-health-screening".into(),
            "yes".into(),
        ]);
    } else {
        args.extend(["--report-digest".into(), fixture.report.to_text().into()]);
    }
    args
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:immutable-package-zones".into(),
        operation_id: OperationId::parse("operation:immutable-package-zones")?,
        principal: PRINCIPAL.into(),
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

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn walk(root: &Path, dir: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) -> Test {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                result.insert(relative, None);
                walk(root, &path, result)?;
            } else {
                assert!(entry.file_type()?.is_file());
                result.insert(relative, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn active_writer_package_reads_and_previews_preserve_exact_native_reports() -> Test {
    let fixture = Fixture::new("immutable-zone-writer")?;
    let cx = support::context(&fixture.source.root)?;
    let writer = ReferenceDeployment::open(&fixture.source.root, SITE, &cx)?;
    fs::write(
        fixture.source.root.join("LAYOUT.tmp.immutable-zone"),
        b"unrelated recovery state must remain untouched",
    )?;
    let before = tree(&fixture.source.root)?;
    for mode in ["read", "occupancy", "analyze"] {
        let expected = match mode {
            "occupancy" => PackageOccupancyReport::open(&writer, fixture.report, &cx)?
                .to_json()
                .to_owned(),
            _ => {
                let mut report = PackageZoneReport::open(&writer, fixture.report, &cx)?;
                let operation = if mode == "read" {
                    PackageZoneOperation::ReadVerified
                } else {
                    report.admit_retention_json()?;
                    PackageZoneOperation::Analyzed
                };
                let initial_usage = report.health_usage().ok_or("screened source usage")?;
                assert!(initial_usage.records_loaded > 0);
                report.revalidate(&writer, &cx)?;
                let final_usage = report.health_usage().ok_or("revalidated source usage")?;
                assert_eq!(final_usage.records_loaded, 2 * initial_usage.records_loaded);
                assert!(final_usage.metadata_reads > initial_usage.metadata_reads);
                report.to_json(operation)?
            }
        };
        assert_eq!(run(parse(&arguments(&fixture, mode))?)?, expected, "{mode}");
        assert_eq!(tree(&fixture.source.root)?, before);
    }
    // The unscreened v1 preview keeps its original report, approval and uncertainty.
    let mut args = arguments(&fixture, "analyze");
    args.truncate(args.len() - 2);
    let options = parse(&args)?;
    let Action::Analyze {
        package,
        label,
        tracking,
        config,
        ..
    } = &options.action
    else {
        return Err("expected analysis".into());
    };
    let native =
        PackageZoneReport::analyze(&writer, *package, label, *tracking, config.clone(), &cx)?;
    native.admit_retention_json()?;
    assert_eq!(
        run(options)?,
        native.to_json(PackageZoneOperation::Analyzed)?
    );
    assert_eq!(tree(&fixture.source.root)?, before);
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn native_reads_leave_unresolved_effects_and_recovery_artifacts_untouched() -> Test {
    let fixture = Fixture::new("immutable-zone-effects")?;
    fs::write(fixture.source.root.join("LAYOUT.tmp.unrelated"), b"keep")?;
    let before = tree(&fixture.source.root)?;
    for mode in ["read", "occupancy", "analyze"] {
        assert!(!run(parse(&arguments(&fixture, mode))?)?.is_empty());
        assert_eq!(tree(&fixture.source.root)?, before, "{mode} ran recovery");
        let mut options = parse(&arguments(&fixture, mode))?;
        options.site = "site:foreign".into();
        assert!(run(options).is_err());
        assert_eq!(tree(&fixture.source.root)?, before);
    }
    Ok(())
}

#[test]
fn exact_byte_and_attempt_allowances_include_every_final_verification_pass() -> Test {
    let fixture = Fixture::new("immutable-zone-budget")?;
    let root = &fixture.source.root;
    let cx = context(root)?;
    let before = tree(root)?;
    for mode in ["read", "occupancy", "analyze"] {
        let mut options = parse(&arguments(&fixture, mode))?;
        let (expected, usage) = run_immutable_with(&options, root, &cx, &|| false)?;
        options.read_limits.max_read_bytes = usize::try_from(usage.read_bytes)?;
        options.read_limits.max_read_objects = usize::try_from(usage.read_objects)?;
        let (exact, measured) = run_immutable_with(&options, root, &cx, &|| false)?;
        assert_eq!(exact, expected, "{mode}");
        assert_eq!(measured, usage, "{mode}");
        options.read_limits.max_read_bytes -= 1;
        assert!(run_immutable_with(&options, root, &cx, &|| false).is_err());
        options.read_limits.max_read_bytes += 1;
        options.read_limits.max_read_objects -= 1;
        assert!(run_immutable_with(&options, root, &cx, &|| false).is_err());
        assert_eq!(tree(root)?, before);
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn last_admission_cancellation_withholds_complete_native_results() -> Test {
    let fixture = Fixture::new("immutable-zone-cancel")?;
    let root = &fixture.source.root;
    let cx = context(root)?;
    let before = tree(root)?;
    for mode in ["read", "occupancy", "analyze"] {
        let options = parse(&arguments(&fixture, mode))?;
        let calls = AtomicUsize::new(0);
        let count = || {
            calls.fetch_add(1, Ordering::SeqCst);
            false
        };
        run_immutable_with(&options, root, &cx, &count)?;
        let final_call = calls.load(Ordering::SeqCst);
        assert!(final_call > 1);
        calls.store(0, Ordering::SeqCst);
        let cancel_final = || calls.fetch_add(1, Ordering::SeqCst) + 1 >= final_call;
        assert!(run_immutable_with(&options, root, &cx, &cancel_final).is_err());
        assert_eq!(tree(root)?, before);
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn late_original_capsule_or_report_damage_refuses_without_repair() -> Test {
    for (mode, damaged_kind) in [
        ("read", "original"),
        ("analyze", "capsule"),
        ("occupancy", "report"),
    ] {
        let fixture = Fixture::new(&format!("immutable-zone-damage-{damaged_kind}"))?;
        let root = &fixture.source.root;
        let options = parse(&arguments(&fixture, mode))?;
        let cx = support::context(root)?;
        let writer = ReferenceDeployment::open(root, SITE, &cx)?;
        let path = match damaged_kind {
            "original" => fixture.source.chunk.clone(),
            "report" => writer.publisher().spool().object_path(fixture.report),
            _ => {
                let retained = RetainedFileImport::open(
                    &writer,
                    fixture.source.import,
                    RetainedReadLimits::default(),
                    &cx,
                )?;
                let id = format!(
                    "object:capsule:{}",
                    retained.manifest().capsule_ids[0].as_str()
                );
                let digest = writer
                    .ledger()
                    .batches()
                    .iter()
                    .flat_map(|batch| &batch.deltas)
                    .find(|delta| delta.object_id.as_str() == id)
                    .ok_or("source capsule")?
                    .payload_digest;
                writer.publisher().spool().object_path(digest)
            }
        };
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().ok_or("retained bytes")? ^= 1;
        let calibration = context(root)?;
        calibration.set_cancel_at_checkpoint("package_zones_preview:delivery");
        let calls = AtomicUsize::new(0);
        let count = || {
            calls.fetch_add(1, Ordering::SeqCst);
            false
        };
        assert!(run_immutable_with(&options, root, &calibration, &count).is_err());
        let after_analysis = calls.load(Ordering::SeqCst);
        calibration.drain_and_finalize();
        let before = tree(root)?;
        let read = context(root)?;
        calls.store(0, Ordering::SeqCst);
        let fired = AtomicBool::new(false);
        let corrupt = || {
            if calls.fetch_add(1, Ordering::SeqCst) == after_analysis {
                fired.store(fs::write(&path, &bytes).is_ok(), Ordering::SeqCst);
            }
            false
        };
        assert!(run_immutable_with(&options, root, &read, &corrupt).is_err());
        assert!(fired.load(Ordering::SeqCst), "late mutation not reached");
        let mut expected = before;
        expected.insert(path.strip_prefix(root)?.to_path_buf(), Some(bytes));
        assert_eq!(
            tree(root)?,
            expected,
            "read changed anything beyond injected damage"
        );
        read.drain_and_finalize();
        drop(writer);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn torn_tails_refuse_without_repair_and_retention_keeps_the_publisher_route() -> Test {
    use std::io::Write;
    for relative in [
        fss_reference::reference_deployment::RELATIVE_PATH_LEDGER,
        fss_reference::reference_deployment::RELATIVE_PATH_EFFECTS,
    ] {
        let fixture = Fixture::new("immutable-zone-tail")?;
        let path = fixture.source.root.join(relative);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(b"torn")?;
        let before = tree(&fixture.source.root)?;
        for mode in ["read", "occupancy", "analyze"] {
            assert!(run(parse(&arguments(&fixture, mode))?).is_err());
            assert_eq!(tree(&fixture.source.root)?, before);
        }
    }
    let fixture = Fixture::new("immutable-zone-routing")?;
    let mut args = arguments(&fixture, "analyze");
    let plain = parse(&args)?;
    assert!(!plain.action.requires_publisher());
    args.extend([
        "--retain".into(),
        ContentDigest::sha256(b"explicit approval").to_text().into(),
    ]);
    let approved = parse(&args)?;
    assert!(approved.action.requires_publisher());
    let before = tree(&fixture.source.root)?;
    let cx = context(&fixture.source.root)?;
    assert!(run_immutable_with(&approved, &fixture.source.root, &cx, &|| false).is_err());
    assert_eq!(tree(&fixture.source.root)?, before);
    for key in ["--max-read-bytes", "--max-read-objects"] {
        let mut mixed = args.clone();
        mixed.extend([key.into(), "1024".into()]);
        assert!(
            parse(&mixed).is_err(),
            "{key} silently ignored by retention"
        );
        for invalid in ["0", "01", "+1", "18446744073709551616"] {
            let mut bounded = arguments(&fixture, "read");
            bounded.extend([key.into(), invalid.into()]);
            assert!(parse(&bounded).is_err(), "{key}={invalid}");
        }
    }
    cx.drain_and_finalize();
    Ok(())
}
