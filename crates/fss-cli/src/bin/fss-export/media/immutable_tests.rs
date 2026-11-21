#![forbid(unsafe_code)]
//! Real media previews retain exact native approval identity without acquiring the writer.

use super::*;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{SensorId, StreamId};
use fss_reference::ingest::long_dwell::LongDwellLimits;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

const SITE: &str = "site:immutable-media-cli";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> RunResult<Self> {
        for index in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-media-immutable-cli-{label}-{}-{index}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::other("temporary-directory capacity").into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority() -> RunResult<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:immutable-media-cli".into(),
        operation_id: OperationId::parse("operation:immutable-media-cli")?,
        principal: "principal:local-operator".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            CAP_EXPORT_PREPARE.into(),
            CAP_EXPORT_COMMIT.into(),
            CAP_EXPORT_ORIGINAL_MEDIA.into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(DEFAULT_PREVIEW_READ_BYTES)
            .storage_operations(DEFAULT_PREVIEW_READ_OBJECTS)
            .build()?,
        privacy_scope: "privacy:approved-whole-original-media-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

struct Fixture {
    directory: Directory,
    deployment: ReferenceDeployment,
    authority: ContextAuthority,
    cx: ReplayCx,
    request: OriginalMediaExportRequest,
}
impl Fixture {
    fn new(label: &str) -> RunResult<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = authority()?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut source = Vec::new();
        for frame in 0..24 {
            let mut pixels = vec![40_u8; 48 * 32];
            if frame >= 3 {
                for y in 8..24 {
                    for x in 8..24 {
                        pixels[y * 48 + x] = 220;
                    }
                }
            }
            source.extend(encode_jpeg(48, 32, &pixels, &config)?);
        }
        let input = directory.0.join("input.mjpeg");
        fs::write(&input, &source)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 4096;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse("sensor:immutable-media-cli")?,
                StreamId::parse("stream:immutable-media-cli")?,
            )
            .with_limits(limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(input)?;
        let plan = WatchPlan {
            import_identity: imported.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: imported.capsule_count,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 48,
                height: 32,
            }],
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        let mut watch = LongWatchReport::analyze(
            &deployment,
            &plan,
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &cx,
        )?;
        let candidate = watch.candidates().first().ok_or("native event required")?;
        let event_id = candidate.event().event_id.clone();
        let approval = candidate.proposal_digest();
        assert_eq!(
            watch.publish(&mut deployment, &BTreeSet::from([approval]), &cx)?,
            1
        );
        let (event, _) = deployment.current_event_authority(&event_id)?;
        let retained = RetainedFileImport::open(
            &deployment,
            imported.import_identity,
            Default::default(),
            &cx,
        )?;
        let request = OriginalMediaExportRequest {
            event: EventExportRequest {
                event_id,
                expected_revision: event.revision_digest(),
                recipient: "recipient:incident-owner".into(),
                purpose: "Review the complete original recording".into(),
                expires_at: TimestampNs(2_000_000_000_000),
            },
            import_identity: imported.import_identity,
            expected_import_root: retained.import_root(),
            whole_source_authorized: true,
            destination_binding: ContentDigest::sha256(b"unbound-test-destination"),
            max_source_bytes: u64::try_from(source.len())?,
            attested_now: CaptureInterval {
                earliest: TimestampNs(1_000_000_000_000),
                latest: TimestampNs(1_000_000_001_000),
            },
        };
        Ok(Self {
            directory,
            deployment,
            authority,
            cx,
            request,
        })
    }

    fn options(&self) -> RunResult<Options> {
        let output = self.directory.0.join("export");
        let target = file::Target::new(&output, self.deployment.root())?;
        let mut request = self.request.clone();
        request.destination_binding = target.binding()?;
        Ok(Options {
            root: self.deployment.root().to_path_buf(),
            site: SITE.into(),
            principal: "principal:local-operator".into(),
            request,
            output,
            approval: None,
            read_limits: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: usize::try_from(DEFAULT_PREVIEW_READ_BYTES)?,
                max_read_objects: usize::try_from(DEFAULT_PREVIEW_READ_OBJECTS)?,
            },
            timeout: Duration::from_secs(60),
        })
    }
}

fn tree(root: &Path) -> RunResult<BTreeMap<PathBuf, ContentDigest>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, ContentDigest>) -> RunResult<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let relative = entry.path().strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                out.insert(relative, ContentDigest::sha256(b"directory"));
                walk(root, &entry.path(), out)?;
            } else {
                out.insert(relative, ContentDigest::sha256(&fs::read(entry.path())?));
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn media_preview_matches_native_json_and_approval_with_an_active_writer() -> RunResult<()> {
    let f = Fixture::new("parity")?;
    let options = f.options()?;
    let native =
        preview_original_media_export(&f.deployment, &options.request, &f.authority, &f.cx)?;
    let expected = report(&native, &options.output, "awaiting_approval", false)?;
    let before = tree(&f.directory.0)?;
    assert_eq!(run(options)?, expected);
    assert_eq!(tree(&f.directory.0)?, before);
    assert!(!f.directory.0.join("export").exists());

    let mut held_writer = f.options()?;
    held_writer.approval = Some(native.approval());
    assert!(run(held_writer).is_err());
    assert_eq!(tree(&f.directory.0)?, before);
    let mut approved = f.options()?;
    approved.approval = Some(native.approval());
    drop(f.deployment);
    let result = run(approved)?;
    assert!(result.contains("\"status\":\"exported_original_media\""));
    assert!(f.directory.0.join("export/COMPLETE.json").is_file());
    Ok(())
}

#[test]
fn media_preview_charges_open_source_and_final_validation_to_one_allowance() -> RunResult<()> {
    let f = Fixture::new("budget")?;
    let mut options = f.options()?;
    let cx = ReplayCx::from_context_authority_read_only(&f.authority, options.root.clone())?;
    let (expected, measured) = run_with(&options, &options.output, &f.authority, &cx, &|| false)?;
    options.read_limits.max_read_bytes = usize::try_from(measured.read_bytes)?;
    options.read_limits.max_read_objects = usize::try_from(measured.read_objects)?;
    let exact = options.read_limits;
    let (actual, used) = run_with(&options, &options.output, &f.authority, &cx, &|| false)?;
    assert_eq!(actual, expected);
    assert_eq!(used, measured);
    options.read_limits.max_read_bytes -= 1;
    assert!(run_with(&options, &options.output, &f.authority, &cx, &|| false).is_err());
    options.read_limits = exact;
    options.read_limits.max_read_objects -= 1;
    assert!(run_with(&options, &options.output, &f.authority, &cx, &|| false).is_err());
    assert!(!options.output.exists());
    Ok(())
}

#[test]
fn media_preview_cancellation_at_delivery_or_final_read_releases_no_output() -> RunResult<()> {
    let f = Fixture::new("cancellation")?;
    let options = f.options()?;
    let before = tree(&f.directory.0)?;
    for checkpoint in [
        "original_media_export:source_verified",
        "original_media_export:preview_delivery",
    ] {
        let cx = ReplayCx::from_context_authority_read_only(&f.authority, options.root.clone())?;
        cx.set_cancel_at_checkpoint(checkpoint);
        assert!(run_with(&options, &options.output, &f.authority, &cx, &|| false).is_err());
        assert_eq!(tree(&f.directory.0)?, before);
    }
    let cx = ReplayCx::from_context_authority_read_only(&f.authority, options.root.clone())?;
    let count = AtomicUsize::new(0);
    let _ = run_with(&options, &options.output, &f.authority, &cx, &|| {
        count.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let final_admission = count.load(Ordering::SeqCst);
    assert!(final_admission > 1);
    let count = AtomicUsize::new(0);
    assert!(
        run_with(&options, &options.output, &f.authority, &cx, &|| {
            count.fetch_add(1, Ordering::SeqCst) + 1 == final_admission
        })
        .is_err()
    );
    assert_eq!(tree(&f.directory.0)?, before);
    assert!(!options.output.exists());
    Ok(())
}

#[test]
fn media_preview_refuses_missing_or_late_torn_effect_history_without_repair() -> RunResult<()> {
    let f = Fixture::new("no-repair")?;
    let options = f.options()?;
    let cx = ReplayCx::from_context_authority_read_only(&f.authority, options.root.clone())?;
    let layout =
        DeploymentLayout::parse_canonical_text(&fs::read_to_string(options.root.join("LAYOUT"))?)?;
    let effects = options.root.join(layout.effects_relpath);
    let original = fs::read(&effects)?;
    fs::remove_file(&effects)?;
    let missing = tree(&f.directory.0)?;
    assert!(run_with(&options, &options.output, &f.authority, &cx, &|| false).is_err());
    assert_eq!(tree(&f.directory.0)?, missing);
    assert!(!effects.exists());
    fs::write(&effects, &original)?;

    let count = AtomicUsize::new(0);
    let _ = run_with(&options, &options.output, &f.authority, &cx, &|| {
        count.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let final_admission = count.load(Ordering::SeqCst);
    assert!(final_admission > 1);
    let mut torn = original;
    torn.extend_from_slice(b"incomplete concurrent effect tail");
    let mut expected = tree(&f.directory.0)?;
    expected.insert(
        effects.strip_prefix(&f.directory.0)?.to_path_buf(),
        ContentDigest::sha256(&torn),
    );
    let count = AtomicUsize::new(0);
    let result = run_with(&options, &options.output, &f.authority, &cx, &|| {
        if count.fetch_add(1, Ordering::SeqCst) + 1 == final_admission {
            fs::write(&effects, &torn).expect("inject late fixture history damage");
        }
        false
    });
    assert!(result.is_err());
    assert_eq!(tree(&f.directory.0)?, expected);
    assert!(!options.output.exists());
    Ok(())
}
