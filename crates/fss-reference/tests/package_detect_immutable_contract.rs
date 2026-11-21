#![forbid(unsafe_code)]
//! Fresh native detection while capture owns the writer, with final immutable custody checks.
//! The tiny first-party numeric model proves mechanics, not trained detection quality.

mod package_zone_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::package_detect::sentinel::{SentinelConfig, run_sentinel_detection};
use fss_reference::ingest::package_detect::{
    PackageDetectError, PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};
use fss_reference::{ReferenceDeployment, ReplayCx, RetainedSource, ScalarExecCx};
use package_zone_support::Test;

const SITE: &str = "site:immutable-package-detect";
const SENSOR: &str = "sensor:immutable-package-detect";
const AVC: &[u8] = include_bytes!("fixtures/long_dwell_h264/square_300.h264");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.h265");
const SENTINEL: SentinelConfig = SentinelConfig {
    every_frames: 2,
    burst_frames: 1,
    max_inferences: 2,
};

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-immutable-package-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
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

fn context(root: &Path, read_only: bool) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:immutable-package-detect".into(),
        operation_id: OperationId::parse("operation:immutable-package-detect")?,
        principal: "principal:immutable-package-detect".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(100_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(if read_only {
        ReplayCx::from_context_authority_read_only(&authority, root.to_path_buf())?
    } else {
        ReplayCx::from_context_authority(&authority, root.to_path_buf())?
    })
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    request: PackageDetectRequest,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], extension: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let input = directory.0.join(format!("source.{extension}"));
        fs::write(&input, bytes)?;
        let cx = context(&root, false)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 1024;
        let receipt = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse(SENSOR)?,
                StreamId::parse("stream:immutable-package-detect")?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(input)?;
        assert!(receipt.capsule_count >= 5);
        Ok(Self {
            deployment,
            cx,
            request: PackageDetectRequest {
                import_identity: receipt.import_identity,
                first_segment: 0,
                segment_count: 5,
                interpretation: ComponentInterpretation::YCbCr,
                minimum_score_ppm: None,
            },
            _directory: directory,
        })
    }

    fn package(&self, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
        let bytes = package_zone_support::package()?;
        Ok(RgbDetectorPackage::load(
            &bytes,
            ContentDigest::sha256(&bytes),
            1 << 36,
            &self.cx,
            scalar,
        )?)
    }

    fn jpeg(label: &str) -> Test<Self> {
        Self::new(label, &jpeg_footage(), "mjpeg")
    }
}

fn jpeg_footage() -> Vec<u8> {
    [32, 64, 96, 128, 160]
        .into_iter()
        .flat_map(package_zone_support::jpeg)
        .collect()
}

fn read_limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 256 * 1024 * 1024,
        max_read_objects: 100_000,
    }
}

// Keep directories as well as exact bytes: even creating an empty recovery entry is a mutation.
fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                entries.insert(name, None);
                visit(root, &path, entries)?;
            } else {
                entries.insert(name, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

fn finalize(source: &ImmutableRetainedSource<'_>) -> Test<RetainedReadUsage> {
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok(source.usage())
}

fn permit_test_damage(path: &Path) -> Test {
    let mut permissions = fs::metadata(path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn analyze(
    source: &dyn RetainedSource,
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    sentinel: bool,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<(String, ContentDigest), PackageDetectError> {
    if sentinel {
        let report = run_sentinel_detection(
            source,
            package,
            request,
            SENTINEL,
            &PackageDetectLimits::default(),
            cx,
            scalar,
        )?;
        Ok((report.json().to_owned(), report.digest()))
    } else {
        let report = run_package_detection(
            source,
            package,
            request,
            &PackageDetectLimits::default(),
            cx,
            scalar,
        )?;
        Ok((report.json, report.digest))
    }
}

#[test]
fn active_writer_allows_exact_native_mjpeg_avc_hevc_detection_and_sentinel_reports() -> Test {
    for (name, bytes, extension) in [
        ("jpeg", jpeg_footage(), "mjpeg"),
        ("avc", AVC.to_vec(), "h264"),
        ("hevc", HEVC.to_vec(), "h265"),
    ] {
        let f = Fixture::new(name, &bytes, extension)?;
        let scalar = ScalarExecCx::new();
        let package = f.package(&scalar)?;
        let root = f.deployment.root();
        let cx = context(root, true)?;
        let before = snapshot(root)?;
        for sentinel in [false, true] {
            let expected = if sentinel {
                let report = run_sentinel_detection(
                    &f.deployment,
                    &package,
                    &f.request,
                    SENTINEL,
                    &PackageDetectLimits::default(),
                    &f.cx,
                    &scalar,
                )?;
                (report.json().to_owned(), report.digest())
            } else {
                let report = run_package_detection(
                    &f.deployment,
                    &package,
                    &f.request,
                    &PackageDetectLimits::default(),
                    &f.cx,
                    &scalar,
                )?;
                (report.json, report.digest)
            };
            let source = ImmutableRetainedSource::open(root, read_limits(), &cx)?;
            let result = analyze(&source, &package, &f.request, sentinel, &cx, &scalar)?;
            assert_eq!(result, expected, "{name}, sentinel={sentinel}");
            assert_eq!(result.1, ContentDigest::sha256(result.0.as_bytes()));
            assert!(result.0.contains("\"effects_authorized\":false"));
            if sentinel {
                assert!(result.0.contains("\"continuous_coverage\":false"));
                assert!(result.0.contains("\"budget_exhausted\""));
            }
            let usage = finalize(&source)?;
            assert!(usage.read_bytes > 0 && usage.read_objects > 0);
            assert_eq!(snapshot(root)?, before);
        }
        scalar.drain_and_finalize();
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn one_nonrenewing_allowance_covers_analysis_and_every_final_read() -> Test {
    let f = Fixture::jpeg("budgets")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let root = f.deployment.root();
    let cx = context(root, true)?;
    let before = snapshot(root)?;
    for sentinel in [false, true] {
        let measured = ImmutableRetainedSource::open(root, read_limits(), &cx)?;
        let expected = analyze(&measured, &package, &f.request, sentinel, &cx, &scalar)?;
        let used = finalize(&measured)?;
        let exact = ImmutableRetainedReadLimits {
            max_read_bytes: usize::try_from(used.read_bytes)?,
            max_read_objects: usize::try_from(used.read_objects)?,
            ..read_limits()
        };
        let admitted = ImmutableRetainedSource::open(root, exact, &cx)?;
        assert_eq!(
            analyze(&admitted, &package, &f.request, sentinel, &cx, &scalar)?,
            expected
        );
        assert_eq!(finalize(&admitted)?, used);
        for short in [
            ImmutableRetainedReadLimits {
                max_read_bytes: exact.max_read_bytes - 1,
                ..exact
            },
            ImmutableRetainedReadLimits {
                max_read_objects: exact.max_read_objects - 1,
                ..exact
            },
        ] {
            let source = ImmutableRetainedSource::open(root, short, &cx)?;
            assert_eq!(
                analyze(&source, &package, &f.request, sentinel, &cx, &scalar)?,
                expected
            );
            assert!(finalize(&source).is_err());
            assert!(
                finalize(&source).is_err(),
                "final read replenished its allowance"
            );
            assert!(analyze(&source, &package, &f.request, sentinel, &cx, &scalar).is_err());
        }
    }
    assert_eq!(snapshot(root)?, before);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn late_selected_source_capsule_manifest_and_publication_damage_refuse_delivery() -> Test {
    let f = Fixture::jpeg("late-custody")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let root = f.deployment.root();
    let cx = context(root, true)?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.request.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let ordinary = run_package_detection(
        &f.deployment,
        &package,
        &f.request,
        &PackageDetectLimits::default(),
        &f.cx,
        &scalar,
    )?;
    let capsule = ordinary
        .frames
        .first()
        .ok_or("first native frame")?
        .capsule_digest;
    let digests = [
        retained.manifest().ordered_chunks[0],
        capsule,
        retained.manifest_digest(),
        retained.import_root(),
    ];
    for sentinel in [false, true] {
        for digest in digests {
            let path = f.deployment.publisher().spool().object_path(digest);
            let original = fs::read(&path)?;
            permit_test_damage(&path)?;
            for missing in [false, true] {
                let source = ImmutableRetainedSource::open(root, read_limits(), &cx)?;
                analyze(&source, &package, &f.request, sentinel, &cx, &scalar)?;
                if missing {
                    fs::remove_file(&path)?;
                } else {
                    let mut changed = original.clone();
                    changed[0] ^= 1;
                    fs::write(&path, changed)?;
                }
                let before = snapshot(root)?;
                assert!(finalize(&source).is_err(), "{digest}, missing={missing}");
                assert_eq!(snapshot(root)?, before, "failed read attempted repair");
                fs::write(&path, &original)?;
            }
        }
        let source = ImmutableRetainedSource::open(root, read_limits(), &cx)?;
        analyze(&source, &package, &f.request, sentinel, &cx, &scalar)?;
        let slot = fss_publication::SlotName::parse(&format!(
            "fi-{}",
            f.request
                .import_identity
                .to_text()
                .trim_start_matches("sha256:")
        ))?;
        let published = f
            .deployment
            .publisher()
            .root(&slot)
            .ok_or("import publication")?;
        let path = root.join("objects/roots").join(format!("{slot}.root"));
        let original = fs::read(&path)?;
        permit_test_damage(&path)?;
        fs::write(
            &path,
            fss_publication::root_record_bytes(&slot, published.root, published.child_count + 1)?,
        )?;
        let before = snapshot(root)?;
        assert!(finalize(&source).is_err());
        assert_eq!(snapshot(root)?, before);
        fs::write(path, original)?;
    }
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn privacy_drift_invalidates_pinned_results_and_fresh_masked_reads_match_native() -> Test {
    let mut f = Fixture::jpeg("privacy")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let root = f.deployment.root().to_path_buf();
    let cx = context(&root, true)?;
    let source = ImmutableRetainedSource::open(&root, read_limits(), &cx)?;
    let sentinel_source = ImmutableRetainedSource::open(&root, read_limits(), &cx)?;
    let unmasked = analyze(&source, &package, &f.request, false, &cx, &scalar)?;
    let mask = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approval = preview_mask(&f.deployment, &mask)?.approval;
    declare_mask(&mut f.deployment, &mask, approval, &f.cx)?;
    let before = snapshot(&root)?;
    for (sentinel, pinned) in [(false, &source), (true, &sentinel_source)] {
        assert!(
            analyze(pinned, &package, &f.request, sentinel, &cx, &scalar).is_err(),
            "a stale source owner completed inference after privacy authority advanced"
        );
        assert!(finalize(pinned).is_err());
    }
    for sentinel in [false, true] {
        let expected = analyze(
            &f.deployment,
            &package,
            &f.request,
            sentinel,
            &f.cx,
            &scalar,
        )?;
        let fresh = ImmutableRetainedSource::open(&root, read_limits(), &cx)?;
        let masked = analyze(&fresh, &package, &f.request, sentinel, &cx, &scalar)?;
        assert_eq!(masked, expected);
        assert_ne!(masked.1, unmasked.1);
        assert!(masked.0.contains(&mask.digest().to_text()));
        finalize(&fresh)?;
    }
    assert_eq!(snapshot(&root)?, before);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn owner_mismatch_and_cancellation_never_release_a_complete_report() -> Test {
    let f = Fixture::jpeg("authority-cancel")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let root = f.deployment.root();
    let cx = context(root, true)?;
    let source = ImmutableRetainedSource::open(root, read_limits(), &cx)?;
    let before = snapshot(root)?;
    let unrelated = Directory::new("unrelated")?;
    let wrong_cx = context(&unrelated.0, true)?;
    let usage = source.usage();
    assert!(analyze(&source, &package, &f.request, false, &wrong_cx, &scalar).is_err());
    assert_eq!(
        source.usage(),
        usage,
        "wrong-root request read source payloads"
    );
    for sentinel in [false, true] {
        let cancelled_scalar = ScalarExecCx::new();
        cancelled_scalar.request_cancellation();
        assert!(matches!(
            analyze(
                &source,
                &package,
                &f.request,
                sentinel,
                &cx,
                &cancelled_scalar
            ),
            Err(PackageDetectError::Cancelled)
        ));
        assert_eq!(
            source.usage(),
            usage,
            "cancelled inference read source payloads"
        );
        let cancelled_cx = context(root, true)?;
        let late = ImmutableRetainedSource::open(root, read_limits(), &cancelled_cx)?;
        cancelled_cx.set_cancel_at_checkpoint("package_detect:complete");
        assert!(matches!(
            analyze(
                &late,
                &package,
                &f.request,
                sentinel,
                &cancelled_cx,
                &scalar
            ),
            Err(PackageDetectError::Cancelled)
        ));
        assert!(
            late.usage().read_bytes > usage.read_bytes,
            "late cancellation preceded analysis"
        );
        cancelled_cx.drain_and_finalize();

        // Calibrate the exact final authority-read callback, then request scalar
        // cancellation there. No decoded or rendered report may escape that late request.
        let calls = AtomicUsize::new(0);
        let count = || {
            calls.fetch_add(1, Ordering::SeqCst);
            false
        };
        let measured = ImmutableRetainedSource::open_cancellable(root, read_limits(), &cx, &count)?;
        calls.store(0, Ordering::SeqCst);
        analyze(&measured, &package, &f.request, sentinel, &cx, &scalar)?;
        let final_read = calls.load(Ordering::SeqCst);
        assert!(final_read > 0);
        let late_scalar = ScalarExecCx::new();
        let armed = AtomicBool::new(false);
        let calls = AtomicUsize::new(0);
        let cancel_at_final_read = || {
            if armed.load(Ordering::SeqCst)
                && calls.fetch_add(1, Ordering::SeqCst) + 1 == final_read
            {
                late_scalar.request_cancellation();
            }
            false
        };
        let late =
            ImmutableRetainedSource::open_cancellable(root, read_limits(), &cx, &cancel_at_final_read)?;
        let opening = late.usage();
        armed.store(true, Ordering::SeqCst);
        assert!(matches!(
            analyze(&late, &package, &f.request, sentinel, &cx, &late_scalar),
            Err(PackageDetectError::Cancelled)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), final_read);
        assert!(late.usage().read_bytes > opening.read_bytes);
        late_scalar.drain_and_finalize();
    }
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let late = ImmutableRetainedSource::open_cancellable(root, read_limits(), &cx, &probe)?;
    analyze(&late, &package, &f.request, false, &cx, &scalar)?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(finalize(&late).is_err());
    cancelled.store(false, Ordering::SeqCst);
    assert!(finalize(&late).is_err(), "cancelled read owner was renewed");
    assert_eq!(snapshot(root)?, before);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    wrong_cx.drain_and_finalize();
    Ok(())
}
