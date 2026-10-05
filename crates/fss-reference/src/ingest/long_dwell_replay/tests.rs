#![forbid(unsafe_code)]
//! Real retained JPEG, foreground/tracker/dwell and publication, then independent cold replay.

use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone};
use crate::ingest::zone_dwell::DwellPolicy;
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use crate::{ReferencePolicyAction, ReferencePolicyDecision};
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:dwell-native-replay";
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-dwell-replay-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:dwell-native-replay".into(), operation_id: OperationId::parse("operation:dwell-native-replay")?,
        principal: principal.into(), capabilities: vec!["ADP-REPLAY-001".into()], deadline: None,
        priority: 10, budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
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
        let config = JpegConfig { quality: 90, subsampling: Subsampling::Grayscale, restart_interval: 0, custom_markers: Vec::new() };
        let mut bytes = Vec::new();
        for index in 0..frames {
            let mut pixels = vec![40_u8 + (index % 2) as u8 * 8; 48 * 32];
            if index >= 3 { for y in 8..24 { for x in 8..24 { pixels[y * 48 + x] = 220; } } }
            bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
        }
        fs::write(&input, bytes)?;
        let cx = context(&root, "principal:dwell-native-replay")?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = frames + 1;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(&input, SensorId::parse("sensor:dwell-replay")?, StreamId::parse("stream:dwell-replay")?)
            .with_limits(limits).with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000));
        let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        fs::remove_file(input)?;
        let plan = WatchPlan {
            import_identity: identity, interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0, segment_count: frames,
            zones: vec![WatchZone { zone_id: "porch".into(), x: 0, y: 0, width: 32, height: 32 }],
            detector: WatchDetectorConfig::default(), tracker: WatchTrackerConfig::default(),
        };
        let run = if screened { LongDwellReport::analyze_screened } else { LongDwellReport::analyze };
        let mut report = run(&deployment, &plan, rule(), WatchOptions::default(), &LongDwellLimits::default(), &cx)?;
        assert_eq!(report.candidates().len(), 1);
        let event = report.candidates()[0].event().event_id.clone();
        let revision = report.candidates()[0].event().revision_digest();
        if publish {
            let approval = report.candidates()[0].proposal_digest();
            assert_eq!(report.publish(&mut deployment, &BTreeSet::from([approval]), &cx)?, 1);
        }
        let pins = if publish { inspect_dwell(&deployment, &event, &DwellReplayLimits::default(), &cx)?.pins() }
            else { DwellReplayPins { event_revision: revision, analysis_root: ContentDigest::sha256(b"not published") } };
        Ok(Self { deployment, cx, plan, event, pins, _directory: directory })
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (self.deployment.current_anchor().clone(), self.deployment.effects().last_root(), self.deployment.publisher().spool().object_count())
    }
}
fn rule() -> DwellPolicy {
    DwellPolicy { minimum_duration_ns: 500_000_000, maximum_sample_gap_ns: 100_000_000, minimum_observations: 3 }
}

#[test]
fn reconstructs_and_replays_three_hundred_frames_after_cold_restart_without_a_command_or_input() -> Test {
    let f = Fixture::new("cold", 300, false, true)?;
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    let inspected = inspect_dwell(&f.deployment, &f.event, &DwellReplayLimits::default(), &f.cx)?;
    assert_eq!(inspected.recipe().plan(), &f.plan);
    assert_eq!(inspected.recipe().rule(), rule());
    assert!(!inspected.recipe().screened());
    assert_eq!(f.snapshot(), before);
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let result = replay_dwell(&reopened, &f.event, f.pins, &DwellReplayLimits::default(), &f.cx)?;
    assert_eq!(result.frames_replayed(), 300);
    assert_eq!(result.inspection().pins(), f.pins);
    assert_eq!(result.inspection().event().revision_digest(), f.pins.event_revision);
    assert!(result.source_chunk_bytes_read() > 0);
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    Ok(())
}

#[test]
fn screened_replay_reconstructs_the_exact_health_policy_and_never_writes_authority() -> Test {
    let f = Fixture::new("screened", 40, true, true)?;
    let before = f.snapshot();
    let result = replay_dwell(&f.deployment, &f.event, f.pins, &DwellReplayLimits::default(), &f.cx)?;
    assert!(result.inspection().recipe().screened());
    assert_eq!(result.frames_replayed(), 40);
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn stale_event_and_analysis_pins_refuse_before_any_perception_stage() -> Test {
    let f = Fixture::new("pins", 40, false, true)?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint("long_dwell:frame");
    for pins in [
        DwellReplayPins { event_revision: ContentDigest::sha256(b"another event"), ..f.pins },
        DwellReplayPins { analysis_root: ContentDigest::sha256(b"another analysis"), ..f.pins },
    ] {
        assert!(matches!(replay_dwell(&f.deployment, &f.event, pins, &DwellReplayLimits::default(), &f.cx), Err(DwellReplayError::StaleSelection)));
        assert!(!f.cx.is_cancelled());
    }
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn a_preview_is_not_a_committed_event_even_when_its_source_is_retained() -> Test {
    let f = Fixture::new("preview", 40, false, false)?;
    let before = f.snapshot();
    assert!(inspect_dwell(&f.deployment, &f.event, &DwellReplayLimits::default(), &f.cx).is_err());
    assert!(replay_dwell(&f.deployment, &f.event, f.pins, &DwellReplayLimits::default(), &f.cx).is_err());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn changed_privacy_refuses_before_the_original_unmasked_recipe_can_execute() -> Test {
    let mut f = Fixture::new("privacy", 40, true, true)?;
    let mask = PrivacyMaskPolicy::new(SensorId::parse("sensor:dwell-replay")?, [48, 32], &[[40, 0, 8, 32]])?;
    let approval = preview_mask(&f.deployment, &mask)?.approval;
    declare_mask(&mut f.deployment, &mask, approval, &f.cx)?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint("long_dwell:frame");
    assert!(matches!(replay_dwell(&f.deployment, &f.event, f.pins, &DwellReplayLimits::default(), &f.cx), Err(DwellReplayError::PrivacyChanged)));
    assert!(!f.cx.is_cancelled());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn metadata_and_every_whole_scan_budget_fail_without_a_verified_result_or_write() -> Test {
    let f = Fixture::new("limits", 40, false, true)?;
    let before = f.snapshot();
    for index in 0..6 {
        let mut limits = DwellReplayLimits::default();
        match index {
            0 => limits.maximum_metadata_bytes = 1,
            1 => limits.execution.maximum_source_chunk_bytes = 1,
            2 => limits.execution.maximum_pixel_samples = 1,
            3 => limits.execution.maximum_assignment_work = 1,
            4 => limits.execution.maximum_trace_bytes = 1,
            _ => limits.execution.decode.jpeg_work_units = 1,
        }
        assert!(replay_dwell(&f.deployment, &f.event, f.pins, &limits, &f.cx).is_err());
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn cancellation_during_native_execution_returns_no_verification_and_leaves_no_work() -> Test {
    let f = Fixture::new("cancel", 40, true, true)?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint_occurrence("sensor_health:row", 3);
    assert!(replay_dwell(&f.deployment, &f.event, f.pins, &DwellReplayLimits::default(), &f.cx).is_err());
    assert!(f.cx.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn missing_source_cannot_be_hidden_by_a_valid_stored_analysis() -> Test {
    let f = Fixture::new("missing", 40, false, true)?;
    let retained = RetainedFileImport::open(&f.deployment, f.plan.import_identity, Default::default(), &f.cx)?;
    let chunk = retained.manifest().ordered_chunks[0];
    fs::remove_file(f.deployment.publisher().spool().object_path(chunk))?;
    let before = f.snapshot();
    assert!(replay_dwell(&f.deployment, &f.event, f.pins, &DwellReplayLimits::default(), &f.cx).is_err());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn bounded_reader_refuses_truncated_trailing_and_unknown_profile_records() -> Test {
    let f = Fixture::new("syntax", 40, true, true)?;
    let loaded = load(&f.deployment, &f.event, None, &DwellReplayLimits::default(), &f.cx)?;
    for end in [0, 1, 7, 31, loaded.analysis.len() / 2, loaded.analysis.len() - 1] {
        assert!(DwellReplayRecipe::decode(&loaded.analysis[..end], &mut || Ok(())).is_err());
    }
    let mut appended = loaded.analysis.clone(); appended.push(0);
    assert!(DwellReplayRecipe::decode(&appended, &mut || Ok(())).is_err());
    let mut unknown = loaded.analysis; unknown[8] ^= 1;
    assert!(matches!(DwellReplayRecipe::decode(&unknown, &mut || Ok(())), Err(DwellReplayError::UnsupportedProfile)));
    Ok(())
}

fn publish_graph(d: &mut ReferenceDeployment, prefix: &str, identity: ContentDigest, manifest: &ObjectManifest,
    interval: fss_core::CaptureInterval, cx: &ReplayCx) -> Test {
    let slot = SlotName::parse(&format!("{prefix}-{}", hex(identity))).map_err(|_| "test slot invalid")?;
    d.publisher_mut().stage_manifest(&slot, manifest)?;
    d.publish_and_commit(&slot, manifest, interval, cx)?;
    Ok(())
}

#[test]
fn self_consistent_forged_hashes_pass_inspection_but_fail_actual_native_replay() -> Test {
    let mut f = Fixture::new("forged", 40, false, true)?;
    let Loaded { inspection, mut analysis } = load(&f.deployment, &f.event, None, &DwellReplayLimits::default(), &f.cx)?;
    let marker = recipe::FRAME_DOMAIN.as_bytes();
    let start = analysis.windows(marker.len()).position(|w| w == marker).ok_or("frame domain missing")?;
    // Replace one claimed decoded-luma byte, not source custody or the recipe. Then rebuild
    // every containing content address and commit the forged claim through normal publishers.
    let luma_byte = start + marker.len() + 8 + 33 + 32 + 1 + 1 + 1 + 8 + 8 + 1;
    analysis[luma_byte] ^= 1;
    let analysis_digest = ContentDigest::sha256(&analysis);
    let old_shared = ObjectManifest::from_canonical_bytes(&f.deployment.publisher().spool().read(inspection.pins.analysis_root)?)?;
    let children = old_shared.children().iter().map(|&child| if child == inspection.analysis_digest { analysis_digest } else { child });
    let shared = ObjectManifest::new(ANALYSIS_KIND, children, None)?;
    let old_record = ContentDigest::parse(&format!("sha256:{}", f.event.as_str().strip_prefix("event:long-dwell:").ok_or("event prefix")?))?;
    let mut record = f.deployment.publisher().spool().read(old_record)?;
    let root_offset = 8 + recipe::EPISODE_DOMAIN.len() + 1;
    record[root_offset..root_offset + 32].copy_from_slice(&shared.root().bytes());
    let record_digest = ContentDigest::sha256(&record);
    let episode = ObjectManifest::new(EPISODE_KIND, [shared.root(), record_digest], None)?;
    let mut event = inspection.event.clone();
    event.event_id = EventId::parse(format!("event:long-dwell:{}", hex(record_digest)))?;
    event.decision_path.fingerprint = episode.root();
    for item in &mut event.evidence { if item.digest == old_record { item.digest = record_digest; } }
    event.evidence.sort_by_key(|item| item.digest);
    event.validate()?;
    for bytes in [&analysis, &record] {
        let digest = f.deployment.publisher_mut().stage_object(bytes)?;
        f.deployment.publisher_mut().verify_object(digest)?;
    }
    publish_graph(&mut f.deployment, "ld-a", analysis_digest, &shared, event.interval, &f.cx)?;
    publish_graph(&mut f.deployment, "ld-e", record_digest, &episode, event.interval, &f.cx)?;
    f.deployment.publish_event(&ReferencePolicyDecision { event: event.clone(), action: ReferencePolicyAction::Hold }, &f.cx)?;
    let inspected = inspect_dwell(&f.deployment, &event.event_id, &DwellReplayLimits::default(), &f.cx)?;
    assert_eq!(inspected.analysis_digest(), analysis_digest);
    let before = f.snapshot();
    assert!(matches!(replay_dwell(&f.deployment, &event.event_id, inspected.pins(), &DwellReplayLimits::default(), &f.cx), Err(DwellReplayError::Diverged)));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn another_authorized_reader_can_replay_without_inheriting_publication_approval() -> Test {
    let f = Fixture::new("reader", 40, false, true)?;
    let reader = context(f.deployment.root(), "principal:independent-reader")?;
    let before = f.snapshot();
    let result = replay_dwell(&f.deployment, &f.event, f.pins, &DwellReplayLimits::default(), &reader)?;
    assert_eq!(result.inspection().pins(), f.pins);
    assert_eq!(f.snapshot(), before);
    reader.drain_and_finalize();
    Ok(())
}
