#![forbid(unsafe_code)]
//! Native previews beside an active writer: exact output, bounded custody and refusal.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};

use super::*;

#[path = "../../../../../fss-reference/tests/package_zone_support/mod.rs"]
mod numeric;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:immutable-package-preview";
const SENSOR: &str = "sensor:immutable-package-preview";
const AVC: &[u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/baseline.264");
const HEVC: &[u8] = include_bytes!(
    "../../../../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.h265"
);

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
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
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

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:immutable-package-preview".into(),
        operation_id: OperationId::parse("operation:immutable-package-preview")?,
        principal: "principal:immutable-package-preview".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
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

// Include directories and every file byte, so an empty lock/recovery/cache entry is a mutation.
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

#[derive(Clone, Copy, Debug)]
enum Mode {
    Ordinary,
    Sentinel,
    WholeRecording,
}
const MODES: [Mode; 3] = [Mode::Ordinary, Mode::Sentinel, Mode::WholeRecording];

struct Fixture {
    writer: ReferenceDeployment,
    cx: ReplayCx,
    root: PathBuf,
    package: PathBuf,
    package_bytes: Vec<u8>,
    import_identity: ContentDigest,
    frames: usize,
    directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let bytes: Vec<_> = [128, 160, 192]
            .into_iter()
            .flat_map(numeric::jpeg)
            .collect();
        Self::media(label, &bytes, "mjpeg")
    }
    fn media(label: &str, bytes: &[u8], extension: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let source = directory.0.join(format!("source.{extension}"));
        let package = directory.0.join("numeric.fmpk");
        let package_bytes = numeric::package()?;
        fs::write(&source, bytes)?;
        fs::write(&package, &package_bytes)?;
        let cx = context(&root)?;
        let mut writer = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.chunk_bytes = 1024;
        let receipt = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &source,
                SensorId::parse(SENSOR)?,
                StreamId::parse("stream:immutable-package-preview")?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(10_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(1_000_000_000), 0, 10.0)?),
            &cx,
            &mut writer,
        )?;
        fs::remove_file(source)?;
        Ok(Self {
            writer,
            cx,
            root,
            package,
            package_bytes,
            import_identity: receipt.import_identity,
            frames: receipt.capsule_count.min(3),
            directory,
        })
    }
    fn args(&self, mode: Mode) -> Vec<OsString> {
        let mut args = vec![
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--import-id".into(),
            self.import_identity.to_text().into(),
            "--first-segment".into(),
            "0".into(),
            "--frames".into(),
            self.frames.to_string().into(),
            "--package".into(),
            self.package.as_os_str().to_owned(),
            "--package-digest".into(),
            ContentDigest::sha256(&self.package_bytes).to_text().into(),
            "--interpretation".into(),
            "ycbcr".into(),
        ];
        if !matches!(mode, Mode::Ordinary) {
            args.extend(
                [
                    "--sentinel-every-frames",
                    "2",
                    "--sentinel-burst-frames",
                    "1",
                    "--sentinel-max-inferences",
                    "2",
                ]
                .map(OsString::from),
            );
        }
        if matches!(mode, Mode::WholeRecording) {
            args.extend(["--stream-sentinel", "yes"].map(OsString::from));
        }
        args
    }
    fn options(&self, mode: Mode) -> Test<Options> {
        Ok(parse(&self.args(mode))?.ok_or("preview options")?)
    }
    fn model(&self, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
        Ok(RgbDetectorPackage::load_with_backend(
            &self.package_bytes,
            ContentDigest::sha256(&self.package_bytes),
            1 << 36,
            KernelBackend::OptimizedCpuV1,
            &self.cx,
            scalar,
        )?)
    }
    fn expected(
        &self,
        options: &Options,
        model: &RgbDetectorPackage,
        scalar: &ScalarExecCx,
    ) -> Test<String> {
        Ok(if let Some(stream) = &options.stream_sentinel {
            fss_reference::ingest::long_sentinel::run_long_sentinel_detection(
                &self.writer,
                model,
                &stream.request(&options.request),
                stream.config,
                &stream.limits,
                &self.cx,
                scalar,
            )?
            .json()
            .to_owned()
        } else if let Some(config) = options.sentinel {
            run_sentinel_detection(
                &self.writer,
                model,
                &options.request,
                config,
                &options.limits,
                &self.cx,
                scalar,
            )?
            .json()
            .to_owned()
        } else {
            run_package_detection(
                &self.writer,
                model,
                &options.request,
                &options.limits,
                &self.cx,
                scalar,
            )?
            .json
        })
    }
}

#[test]
fn all_native_preview_modes_match_writer_reports_while_capture_owns_the_lock() -> Test {
    let jpeg: Vec<_> = [128, 160, 192]
        .into_iter()
        .flat_map(numeric::jpeg)
        .collect();
    for (label, bytes, extension) in [
        ("jpeg", jpeg.as_slice(), "mjpeg"),
        ("avc", AVC, "h264"),
        ("hevc", HEVC, "h265"),
    ] {
        let f = Fixture::media(label, bytes, extension)?;
        let before = snapshot(&f.root)?;
        let scalar = ScalarExecCx::new();
        let model = f.model(&scalar)?;
        for mode in MODES {
            let mut options = f.options(mode)?;
            let expected = f.expected(&options, &model, &scalar)?;
            let exported = f.directory.0.join(format!("{mode:?}.json"));
            options.report = Some(exported.clone());
            let mut out = Vec::new();
            super::super::run(options, &mut out)?;
            assert_eq!(out, expected.as_bytes(), "{label}, {mode:?}");
            assert_eq!(fs::read(exported)?, out);
            assert_eq!(snapshot(&f.root)?, before, "{label}, {mode:?}");
        }
        scalar.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn final_custody_reads_share_exact_byte_and_attempt_limits_without_partial_output() -> Test {
    let f = Fixture::new("budget")?;
    let before = snapshot(&f.root)?;
    let scalar = ScalarExecCx::new();
    let model = f.model(&scalar)?;
    for mode in MODES {
        let mut options = f.options(mode)?;
        let mut expected = Vec::new();
        let used = super::run(&options, &model, &f.cx, &scalar, &|| false, &mut expected)?;
        options.read_limits.max_read_bytes = usize::try_from(used.read_bytes)?;
        options.read_limits.max_read_objects = usize::try_from(used.read_objects)?;
        let mut exact = Vec::new();
        assert_eq!(
            super::run(&options, &model, &f.cx, &scalar, &|| false, &mut exact)?,
            used
        );
        assert_eq!(exact, expected);
        let exact_limits = options.read_limits;
        options.report = Some(f.directory.0.join(format!("refused-{mode:?}.json")));
        for bytes_short in [true, false] {
            options.read_limits = exact_limits;
            if bytes_short {
                options.read_limits.max_read_bytes -= 1;
            } else {
                options.read_limits.max_read_objects -= 1;
            }
            let mut out = Vec::new();
            assert!(
                super::run(&options, &model, &f.cx, &scalar, &|| false, &mut out).is_err(),
                "{mode:?}, bytes={bytes_short}"
            );
            assert!(out.is_empty());
            assert!(!options.report.as_ref().ok_or("report path")?.exists());
        }
    }
    assert_eq!(snapshot(&f.root)?, before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn final_revalidation_refuses_late_source_capsule_and_privacy_generation_changes() -> Test {
    let mut f = Fixture::new("custody")?;
    let options = f.options(Mode::Ordinary)?;
    let scalar = ScalarExecCx::new();
    let model = f.model(&scalar)?;
    let retained = RetainedFileImport::open(
        &f.writer,
        f.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let first_chunk = retained.manifest().ordered_chunks[0];
    let native = run_package_detection(
        &f.writer,
        &model,
        &options.request,
        &options.limits,
        &f.cx,
        &scalar,
    )?;
    for digest in [
        first_chunk,
        native.frames[0].capsule_digest,
        native.import_root,
    ] {
        let path = f.writer.publisher().spool().object_path(digest);
        let original = fs::read(&path)?;
        for missing in [false, true] {
            let source = ImmutableRetainedSource::open(&f.root, options.read_limits, &f.cx)?;
            run_package_detection(
                &source,
                &model,
                &options.request,
                &options.limits,
                &f.cx,
                &scalar,
            )?;
            if missing {
                fs::remove_file(&path)?;
            } else {
                let mut changed = original.clone();
                changed[0] ^= 1;
                fs::write(&path, changed)?;
            }
            let damaged = snapshot(&f.root)?;
            assert!(source.revalidate().is_err(), "{digest}, missing={missing}");
            assert_eq!(
                snapshot(&f.root)?,
                damaged,
                "revalidation repaired the source"
            );
            fs::write(&path, &original)?;
        }
    }
    let source = ImmutableRetainedSource::open(&f.root, options.read_limits, &f.cx)?;
    let unmasked = run_package_detection(
        &source,
        &model,
        &options.request,
        &options.limits,
        &f.cx,
        &scalar,
    )?;
    assert!(
        unmasked
            .frames
            .iter()
            .any(|frame| !frame.detections.detections().is_empty())
    );
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approval = preview_mask(&f.writer, &policy)?.approval;
    declare_mask(&mut f.writer, &policy, approval, &f.cx)?;
    let masked_tree = snapshot(&f.root)?;
    assert!(
        source.revalidate().is_err(),
        "old unmasked coordinates survived a policy generation change"
    );
    for mode in MODES {
        let options = f.options(mode)?;
        let expected = f.expected(&options, &model, &scalar)?;
        let mut out = Vec::new();
        super::super::run(options, &mut out)?;
        assert_eq!(out, expected.as_bytes());
        assert_ne!(out, unmasked.json.as_bytes());
        assert_eq!(snapshot(&f.root)?, masked_tree);
    }
    let masked_source = ImmutableRetainedSource::open(&f.root, options.read_limits, &f.cx)?;
    let masked = run_package_detection(
        &masked_source,
        &model,
        &options.request,
        &options.limits,
        &f.cx,
        &scalar,
    )?;
    assert!(
        masked
            .frames
            .iter()
            .all(|frame| frame.detections.detections().is_empty())
    );
    let policy_path = f.writer.publisher().spool().object_path(policy.digest());
    let original_policy = fs::read(&policy_path)?;
    let mut changed_policy = original_policy.clone();
    changed_policy[0] ^= 1;
    fs::write(&policy_path, changed_policy)?;
    let damaged_policy = snapshot(&f.root)?;
    assert!(masked_source.revalidate().is_err());
    assert_eq!(snapshot(&f.root)?, damaged_policy);
    fs::write(policy_path, original_policy)?;
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn cancellation_and_retain_requests_cannot_release_immutable_reports() -> Test {
    let f = Fixture::new("cancel")?;
    let before = snapshot(&f.root)?;
    let scalar = ScalarExecCx::new();
    let model = f.model(&scalar)?;
    for mode in MODES {
        let mut options = f.options(mode)?;
        options.report = Some(f.directory.0.join(format!("cancelled-{mode:?}.json")));
        let mut out = Vec::new();
        assert!(super::run(&options, &model, &f.cx, &scalar, &|| true, &mut out).is_err());
        assert!(out.is_empty());
        assert!(!options.report.as_ref().ok_or("report path")?.exists());
        let cancelled = context(&f.root)?;
        cancelled.set_cancel_at_checkpoint(if matches!(mode, Mode::WholeRecording) {
            "long_sentinel:complete"
        } else {
            "package_detect:complete"
        });
        assert!(super::run(&options, &model, &cancelled, &scalar, &|| false, &mut out).is_err());
        assert!(out.is_empty());
        assert!(!options.report.as_ref().ok_or("report path")?.exists());
        cancelled.drain_and_finalize();
        options.retain = true;
        assert!(super::run(&options, &model, &f.cx, &scalar, &|| false, &mut out).is_err());
        assert!(out.is_empty());
        // The public retained path still requires the exclusive publisher already held by f.
        assert!(super::super::run(options, &mut out).is_err());
        assert!(out.is_empty());
    }
    assert_eq!(snapshot(&f.root)?, before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn damaged_authority_wrong_site_and_missing_deployments_refuse_without_recovery() -> Test {
    let f = Fixture::new("refusal")?;
    for journal in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let path = f.root.join(journal);
        let original = fs::read(&path)?;
        let mut damaged = original.clone();
        damaged.extend_from_slice(b"\x01\x02\x03");
        fs::write(&path, damaged)?;
        let before = snapshot(&f.root)?;
        for mode in MODES {
            let mut out = Vec::new();
            assert!(super::super::run(f.options(mode)?, &mut out).is_err());
            assert!(out.is_empty());
            assert_eq!(snapshot(&f.root)?, before, "recovered {journal}");
        }
        fs::write(path, original)?;
    }
    let before = snapshot(&f.root)?;
    let mut options = f.options(Mode::Ordinary)?;
    options.site = "site:wrong-package-preview".into();
    let mut out = Vec::new();
    assert!(super::super::run(options, &mut out).is_err());
    assert!(out.is_empty());
    assert_eq!(snapshot(&f.root)?, before);
    let mut options = f.options(Mode::Ordinary)?;
    let absent = f.directory.0.join("absent");
    options.root = absent.clone();
    assert!(super::super::run(options, &mut out).is_err());
    assert!(out.is_empty());
    assert!(!absent.exists());
    Ok(())
}

#[test]
fn aggregate_read_flags_are_bounded_and_only_admitted_for_unretained_previews() -> Test {
    let f = Fixture::new("parse")?;
    for mode in MODES {
        for (key, maximum) in [
            ("--max-read-bytes", "4294967296"),
            ("--max-read-objects", "4000000"),
        ] {
            let mut valid = f.args(mode);
            valid.extend([key, maximum].map(OsString::from));
            assert!(parse(&valid)?.is_some());
            valid.extend(["--retain", "yes"].map(OsString::from));
            assert!(parse(&valid).is_err());
            for invalid in ["0", "01", "+1", "18446744073709551616"] {
                let mut args = f.args(mode);
                args.extend([key, invalid].map(OsString::from));
                assert!(parse(&args).is_err(), "{mode:?}: {key}={invalid}");
            }
        }
    }
    Ok(())
}

#[test]
fn scalar_cancellation_at_the_last_read_withholds_all_preview_outputs() -> Test {
    let f = Fixture::new("last-scalar-cancel")?;
    let before = snapshot(&f.root)?;
    for mode in MODES {
        let scalar = ScalarExecCx::new();
        let model = f.model(&scalar)?;
        let mut options = f.options(mode)?;
        let calls = AtomicUsize::new(0);
        let mut expected = Vec::new();
        super::run(
            &options,
            &model,
            &f.cx,
            &scalar,
            &|| {
                calls.fetch_add(1, Ordering::SeqCst);
                false
            },
            &mut expected,
        )?;
        let last = calls.load(Ordering::SeqCst);
        assert!(last > 0);
        assert!(!expected.is_empty());
        calls.store(0, Ordering::SeqCst);
        options.report = Some(f.directory.0.join(format!("late-scalar-{mode:?}.json")));
        let mut out = Vec::new();
        let result = super::run(
            &options,
            &model,
            &f.cx,
            &scalar,
            &|| {
                if calls.fetch_add(1, Ordering::SeqCst) + 1 == last {
                    scalar.request_cancellation();
                }
                false
            },
            &mut out,
        );
        assert!(result.is_err(), "{mode:?}");
        assert!(scalar.is_cancelled());
        assert!(out.is_empty());
        assert!(!options.report.as_ref().ok_or("report path")?.exists());
        assert_eq!(snapshot(&f.root)?, before);
        scalar.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn late_effect_journal_damage_is_refused_before_preview_delivery_without_repair() -> Test {
    let f = Fixture::new("late-effect-journal")?;
    let scalar = ScalarExecCx::new();
    let model = f.model(&scalar)?;
    let journal = f.root.join("effects/journal.fssj");
    let original = fs::read(&journal)?;
    let mut torn = original.clone();
    torn.extend_from_slice(b"\x01\x02\x03");
    for mode in MODES {
        let mut options = f.options(mode)?;
        let calibrate = context(&f.root)?;
        calibrate.set_cancel_at_checkpoint("package_preview:delivery");
        let calls = AtomicUsize::new(0);
        let mut out = Vec::new();
        assert!(
            super::run(
                &options,
                &model,
                &calibrate,
                &scalar,
                &|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    false
                },
                &mut out,
            )
            .is_err()
        );
        assert!(out.is_empty());
        let before_delivery = calls.load(Ordering::SeqCst);
        calibrate.drain_and_finalize();
        calls.store(0, Ordering::SeqCst);
        options.report = Some(f.directory.0.join(format!("late-journal-{mode:?}.json")));
        let result = super::run(
            &options,
            &model,
            &f.cx,
            &scalar,
            &|| {
                if calls.fetch_add(1, Ordering::SeqCst) == before_delivery {
                    fs::write(&journal, &torn).expect("damage temporary journal");
                }
                false
            },
            &mut out,
        );
        assert!(result.is_err(), "{mode:?}");
        assert_eq!(fs::read(&journal)?, torn);
        assert!(out.is_empty());
        assert!(!options.report.as_ref().ok_or("report path")?.exists());
        fs::write(&journal, &original)?;
    }
    scalar.drain_and_finalize();
    Ok(())
}
