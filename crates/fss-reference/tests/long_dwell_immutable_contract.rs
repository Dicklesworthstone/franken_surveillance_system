#![forbid(unsafe_code)]
//! Real retained JPEG, foreground/tracker/dwell and publication, then independent cold replay.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::{ContentDigest, EventId, LedgerAnchor};
use fss_reference::ReferenceDeployment;
use fss_reference::ReplayCx;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::RetainedFileImport;
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::long_dwell_replay::{
    DwellReplayLimits, DwellReplayPins, inspect_dwell, replay_dwell,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:dwell-immutable-replay";
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-dwell-immutable-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
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
fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:dwell-native-replay".into(),
        operation_id: OperationId::parse("operation:dwell-native-replay")?,
        principal: principal.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    event: EventId,
    pins: DwellReplayPins,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, frames: usize, screened: bool, publish: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let input = directory.0.join("original.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut bytes = Vec::new();
        for index in 0..frames {
            let mut pixels = vec![40_u8 + (index % 2) as u8 * 8; 48 * 32];
            if index >= 3 {
                for y in 8..24 {
                    for x in 8..24 {
                        pixels[y * 48 + x] = 220;
                    }
                }
            }
            bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
        }
        fs::write(&input, bytes)?;
        let cx = context(&root, "principal:dwell-native-replay")?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = frames + 1;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:dwell-replay")?,
            StreamId::parse("stream:dwell-replay")?,
        )
        .with_limits(limits)
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000));
        let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        fs::remove_file(input)?;
        let plan = WatchPlan {
            import_identity: identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: frames,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 32,
                height: 32,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        let run = if screened {
            LongDwellReport::analyze_screened
        } else {
            LongDwellReport::analyze
        };
        let mut report = run(
            &deployment,
            &plan,
            rule(),
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &cx,
        )?;
        assert_eq!(report.candidates().len(), 1);
        let event = report.candidates()[0].event().event_id.clone();
        let revision = report.candidates()[0].event().revision_digest();
        if publish {
            let approval = report.candidates()[0].proposal_digest();
            assert_eq!(
                report.publish(&mut deployment, &BTreeSet::from([approval]), &cx)?,
                1
            );
        }
        let pins = if publish {
            inspect_dwell(&deployment, &event, &DwellReplayLimits::default(), &cx)?.pins()
        } else {
            DwellReplayPins {
                event_revision: revision,
                analysis_root: ContentDigest::sha256(b"not published"),
            }
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            event,
            pins,
            _directory: directory,
        })
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().object_count(),
        )
    }
}
fn rule() -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: 500_000_000,
        maximum_sample_gap_ns: 100_000_000,
        minimum_observations: 3,
    }
}

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 512 * 1024 * 1024,
        max_read_objects: 1_000_000,
    }
}

fn complete(
    f: &Fixture,
    bounds: ImmutableRetainedReadLimits,
    verify: bool,
) -> Test<RetainedReadUsage> {
    let owner = ImmutableRetainedSource::open(f.deployment.root(), bounds, &f.cx)?;
    if verify {
        let actual = replay_dwell(
            &owner,
            &f.event,
            f.pins,
            &DwellReplayLimits::default(),
            &f.cx,
        )?;
        assert_eq!(actual.inspection().pins(), f.pins);
        assert_eq!(actual.frames_replayed(), f.plan.segment_count);
    } else {
        let actual = inspect_dwell(&owner, &f.event, &DwellReplayLimits::default(), &f.cx)?;
        assert_eq!(actual.pins(), f.pins);
    }
    owner.revalidate_snapshot_metadata()?;
    owner.revalidate()?;
    Ok(owner.usage())
}

#[test]
fn writer_held_inspection_and_replay_match_native_event_and_recipe() -> Test {
    for screened in [false, true] {
        let f = Fixture::new(
            if screened { "screened" } else { "ordinary" },
            40,
            screened,
            true,
        )?;
        let before = f.snapshot();
        let native = replay_dwell(
            &f.deployment,
            &f.event,
            f.pins,
            &DwellReplayLimits::default(),
            &f.cx,
        )?;
        let owner = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
        let inspected = inspect_dwell(&owner, &f.event, &DwellReplayLimits::default(), &f.cx)?;
        let actual = replay_dwell(
            &owner,
            &f.event,
            f.pins,
            &DwellReplayLimits::default(),
            &f.cx,
        )?;
        assert_eq!(inspected.event(), native.inspection().event());
        assert_eq!(inspected.event_root(), native.inspection().event_root());
        assert_eq!(
            inspected.analysis_digest(),
            native.inspection().analysis_digest()
        );
        assert_eq!(
            inspected.recipe().plan(),
            native.inspection().recipe().plan()
        );
        assert_eq!(actual.inspection().pins(), native.inspection().pins());
        assert_eq!(actual.frames_replayed(), native.frames_replayed());
        assert_eq!(
            actual.source_chunk_bytes_read(),
            native.source_chunk_bytes_read()
        );
        owner.revalidate_snapshot_metadata()?;
        owner.revalidate()?;
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn one_exact_allowance_covers_open_native_work_and_final_revalidation() -> Test {
    let f = Fixture::new("bounds", 40, false, true)?;
    let before = f.snapshot();
    for verify in [false, true] {
        let usage = complete(&f, limits(), verify)?;
        let exact = ImmutableRetainedReadLimits {
            max_read_bytes: usize::try_from(usage.read_bytes)?,
            max_read_objects: usize::try_from(usage.read_objects)?,
            ..limits()
        };
        assert_eq!(complete(&f, exact, verify)?, usage);
        assert!(
            complete(
                &f,
                ImmutableRetainedReadLimits {
                    max_read_bytes: exact.max_read_bytes - 1,
                    ..exact
                },
                verify
            )
            .is_err()
        );
        assert!(
            complete(
                &f,
                ImmutableRetainedReadLimits {
                    max_read_objects: exact.max_read_objects - 1,
                    ..exact
                },
                verify
            )
            .is_err()
        );
    }
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn final_read_rejects_late_source_event_and_publication_damage() -> Test {
    for target in ["source", "event", "publication"] {
        let f = Fixture::new(target, 40, false, true)?;
        let owner = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
        let actual = replay_dwell(
            &owner,
            &f.event,
            f.pins,
            &DwellReplayLimits::default(),
            &f.cx,
        )?;
        let path = match target {
            "source" => {
                let retained = RetainedFileImport::open(
                    &f.deployment,
                    f.plan.import_identity,
                    Default::default(),
                    &f.cx,
                )?;
                // A quiet leading chunk is part of the full replay, not only the chosen event.
                f.deployment
                    .publisher()
                    .spool()
                    .object_path(retained.manifest().ordered_chunks[0])
            }
            "event" => f
                .deployment
                .publisher()
                .spool()
                .object_path(actual.inspection().event_root()),
            _ => {
                let digest = actual.inspection().analysis_digest();
                let hex: String = digest
                    .bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                f.deployment
                    .root()
                    .join("objects/roots")
                    .join(format!("ld-a-{hex}.root"))
            }
        };
        assert!(
            path.is_file(),
            "missing test corruption target {}",
            path.display()
        );
        let original = fs::read(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(&path, b"late damage")?;
        assert!(owner.revalidate().is_err());
        fs::write(&path, original)?;
        // A poisoned read owner must not recover its allowance or release an earlier result.
        assert!(owner.revalidate().is_err());
    }
    Ok(())
}

#[test]
fn current_privacy_and_effect_journal_changes_invalidate_finished_replay() -> Test {
    let mut f = Fixture::new("authority", 40, false, true)?;
    let owner = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
    replay_dwell(
        &owner,
        &f.event,
        f.pins,
        &DwellReplayLimits::default(),
        &f.cx,
    )?;
    let mask = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:dwell-replay")?,
        [48, 32],
        &[[40, 0, 8, 32]],
    )?;
    let approval = preview_mask(&f.deployment, &mask)?.approval;
    declare_mask(&mut f.deployment, &mask, approval, &f.cx)?;
    assert!(owner.revalidate().is_err());

    let f = Fixture::new("effects", 40, false, true)?;
    let owner = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
    inspect_dwell(&owner, &f.event, &DwellReplayLimits::default(), &f.cx)?;
    let path = f.deployment.root().join("effects/journal.fssj");
    let mut bytes = fs::read(&path)?;
    bytes.extend_from_slice(b"torn-tail");
    fs::write(&path, &bytes)?;
    assert!(owner.revalidate().is_err());
    assert_eq!(fs::read(path)?, bytes, "read may not repair effect history");
    Ok(())
}

#[test]
fn cancellation_and_wrong_root_never_return_a_deliverable_replay() -> Test {
    let f = Fixture::new("cancel", 40, false, true)?;
    let cancelled = AtomicBool::new(false);
    let stop = || cancelled.load(Ordering::SeqCst);
    let owner =
        ImmutableRetainedSource::open_cancellable(f.deployment.root(), limits(), &f.cx, &stop)?;
    replay_dwell(
        &owner,
        &f.event,
        f.pins,
        &DwellReplayLimits::default(),
        &f.cx,
    )?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(owner.revalidate_snapshot_metadata().is_err());
    assert!(owner.revalidate().is_err());

    let other = Fixture::new("other-root", 40, false, true)?;
    let reader = ImmutableRetainedSource::open(f.deployment.root(), limits(), &f.cx)?;
    assert!(inspect_dwell(&reader, &f.event, &DwellReplayLimits::default(), &other.cx).is_err());
    assert!(
        replay_dwell(
            &reader,
            &f.event,
            f.pins,
            &DwellReplayLimits::default(),
            &other.cx
        )
        .is_err()
    );
    let early = AtomicBool::new(true);
    assert!(
        ImmutableRetainedSource::open_cancellable(f.deployment.root(), limits(), &f.cx, &|| early
            .load(Ordering::SeqCst))
        .is_err()
    );
    Ok(())
}
