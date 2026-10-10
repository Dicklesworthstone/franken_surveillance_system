#![forbid(unsafe_code)]
//! Real retained media and current authority, then independent read-only native recomputation.

use super::*;
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationDependencies, CorroborationGates, CorroborationOptions,
    CorroborationPlan, FailureDomainDeclaration, GroundHomography, GroundZone,
};
use crate::ingest::recorded_corroboration::streaming::LongCorroborationReport;
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use crate::{ReferencePolicyAction, ReferencePolicyDecision};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, EventState, OperationId, SensorId, StreamId, TimestampNs};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-event-replay";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-long-event-replay-{label}-{}-{attempt}",
                std::process::id()
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
fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-event-replay".into(),
        operation_id: OperationId::parse("operation:long-event-replay")?,
        principal: principal.into(),
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
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn scene(frames: usize, appearance: usize, moving: bool) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for position in 0..frames {
        // Avoid repeated whole frames when the screened profile is selected.
        let mut pixels = vec![40_u8 + (position % 2) as u8 * 8; 48 * 32];
        if position >= appearance {
            let left = if moving { 4 + position.saturating_sub(128).min(20) } else { 8 };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 48 + x] = 220;
                }
            }
        }
        bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
    }
    Ok(bytes)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root, "principal:long-event-replay")?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self { deployment, cx, directory })
    }
    fn import(&mut self, name: &str, bytes: &[u8], extension: &str) -> Test<(ContentDigest, usize)> {
        let input = self.directory.0.join(format!("{name}.{extension}"));
        fs::write(&input, bytes)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse(format!("sensor:long-event-{name}"))?,
            StreamId::parse(format!("stream:long-event-{name}"))?,
        )
        .with_limits(limits)
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000));
        let receipt = FileIngestAdapter::ingest(request, &self.cx, &mut self.deployment)?;
        fs::remove_file(input)?;
        Ok((receipt.import_identity, receipt.capsule_count))
    }
    fn watch(
        &mut self, bytes: &[u8], extension: &str, size: [u32; 2], late: bool, screened: bool,
    ) -> Test<(WatchPlan, EventId, LongEventReplayPins)> {
        let (identity, count) = self.import("watch", bytes, extension)?;
        let plan = WatchPlan {
            import_identity: identity,
            interpretation: if extension == "mjpeg" {
                ComponentInterpretation::Grayscale
            } else {
                ComponentInterpretation::YCbCr
            },
            first_segment: 0,
            segment_count: count,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: if late { 28 } else { 0 },
                y: 0,
                width: if late { size[0] - 28 } else { size[0] },
                height: size[1],
            }],
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        let run = if screened {
            LongWatchReport::analyze_screened
        } else {
            LongWatchReport::analyze
        };
        let mut report = run(
            &self.deployment, &plan, WatchOptions::default(), &LongDwellLimits::default(), &self.cx,
        )?;
        let candidate = report.candidates().first().ok_or("native watch entry missing")?;
        if late {
            assert!(candidate.entry().position() > 140);
        }
        let event = candidate.event().event_id.clone();
        let approval = candidate.proposal_digest();
        assert_eq!(report.publish(&mut self.deployment, &BTreeSet::from([approval]), &self.cx)?, 1);
        let pins = inspect_long_event(
            &self.deployment, &event, &LongEventReplayLimits::default(), &self.cx,
        )?.pins();
        Ok((plan, event, pins))
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().object_count(),
        )
    }
}

#[test]
fn cold_watch_replays_a_late_entry_across_three_hundred_frames_without_the_original_input() -> Test {
    let mut f = Fixture::new("late")?;
    let (plan, event, pins) = f.watch(&scene(300, 3, true)?, "mjpeg", [48, 32], true, false)?;
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    let inspected = inspect_long_event(
        &f.deployment, &event, &LongEventReplayLimits::default(), &f.cx,
    )?;
    let LongEventReplayRecipe::Watch(recipe) = inspected.recipe() else {
        return Err("watch recipe expected".into());
    };
    assert_eq!(recipe.plan(), &plan);
    assert_eq!(recipe.media_format(), "mjpeg");
    assert!(!recipe.complete_codec_limits_retained());
    assert_eq!(inspected.profile(), "long_watch");
    assert_eq!(inspected.analysis_roots().len(), 1);
    assert!(inspected.metadata_bytes_read() > 0);
    assert_eq!(f.snapshot(), before);
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let reader = context(&root, "principal:another-authorized-reader")?;
    let verified = replay_long_event(
        &reopened, &event, pins, &LongEventReplayLimits::default(), &reader,
    )?;
    assert_eq!(verified.frames_replayed(), 300);
    assert_eq!(verified.inspection().pins(), pins);
    assert!(verified.source_chunk_bytes_read() > 0);
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    Ok(())
}

#[test]
fn native_avc_b_pictures_and_hevc_parameter_sets_replay_the_complete_original_analysis() -> Test {
    for (label, bytes, size, frames) in [
        (
            "avc",
            include_bytes!("../../../tests/fixtures/long_dwell_h264/square_300.mp4").as_slice(),
            [48, 32],
            300,
        ),
        (
            "hevc",
            include_bytes!("../../../tests/fixtures/hevc_ingest/watch_96x48_moving.mp4").as_slice(),
            [96, 48],
            14,
        ),
    ] {
        let mut f = Fixture::new(label)?;
        let (_, event, pins) = f.watch(bytes, "mp4", size, false, false)?;
        let before = f.snapshot();
        let root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
        let verified = replay_long_event(
            &reopened, &event, pins, &LongEventReplayLimits::default(), &f.cx,
        )?;
        assert_eq!(verified.frames_replayed(), frames);
        assert_eq!(verified.inspection().pins(), pins);
        if label == "hevc" {
            assert!(verified.source_chunk_bytes_read() > bytes.len() as u64);
        }
        assert_eq!(*reopened.current_anchor(), before.0);
        assert_eq!(reopened.effects().last_root(), before.1);
        assert_eq!(reopened.publisher().spool().object_count(), before.2);
    }
    Ok(())
}

#[test]
fn screened_recipe_and_every_retained_scan_reservation_survive_cold_reconstruction() -> Test {
    let mut f = Fixture::new("screened")?;
    let (_, event, pins) = f.watch(&scene(40, 3, false)?, "mjpeg", [48, 32], false, true)?;
    let before = f.snapshot();
    let verified = replay_long_event(
        &f.deployment, &event, pins, &LongEventReplayLimits::default(), &f.cx,
    )?;
    let LongEventReplayRecipe::Watch(recipe) = verified.inspection().recipe() else {
        return Err("watch recipe expected".into());
    };
    assert!(recipe.screened());
    assert_eq!(verified.frames_replayed(), 40);
    for index in 0..6 {
        let mut limits = LongEventReplayLimits::default();
        match index {
            0 => limits.maximum_metadata_bytes = 1,
            1 => limits.execution.maximum_source_chunk_bytes = 1,
            2 => limits.execution.maximum_pixel_samples = 1,
            3 => limits.execution.maximum_assignment_work = 1,
            4 => limits.execution.maximum_trace_bytes = 1,
            _ => limits.execution.decode.jpeg_work_units = 1,
        }
        assert!(replay_long_event(&f.deployment, &event, pins, &limits, &f.cx).is_err());
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn stale_pins_and_changed_privacy_refuse_before_any_native_perception() -> Test {
    let mut f = Fixture::new("selection")?;
    let (_, event, pins) = f.watch(&scene(40, 3, false)?, "mjpeg", [48, 32], false, false)?;
    f.cx.set_cancel_at_checkpoint("long_event_replay:execute");
    let before = f.snapshot();
    for stale in [
        LongEventReplayPins { event_revision: ContentDigest::sha256(b"other event"), ..pins },
        LongEventReplayPins { provenance_root: ContentDigest::sha256(b"other root"), ..pins },
    ] {
        assert!(matches!(
            replay_long_event(&f.deployment, &event, stale, &LongEventReplayLimits::default(), &f.cx),
            Err(LongEventReplayError::StaleSelection)
        ));
        assert!(!f.cx.is_cancelled());
        assert_eq!(f.snapshot(), before);
    }
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-event-watch")?, [48, 32], &[[40, 0, 8, 32]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = f.snapshot();
    assert!(matches!(
        replay_long_event(&f.deployment, &event, pins, &LongEventReplayLimits::default(), &f.cx),
        Err(LongEventReplayError::PrivacyChanged)
    ));
    assert!(!f.cx.is_cancelled());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn quiet_source_capsules_and_original_chunks_remain_required_after_event_publication() -> Test {
    for capsule in [false, true] {
        let mut f = Fixture::new(if capsule { "capsule" } else { "chunk" })?;
        let (plan, event, pins) = f.watch(&scene(40, 3, false)?, "mjpeg", [48, 32], false, false)?;
        let retained = RetainedFileImport::open(
            &f.deployment, plan.import_identity, Default::default(), &f.cx,
        )?;
        let damaged = if capsule {
            // Background frame 1 does not supply the selected event's direct source edge.
            source_capsule(&f.deployment, &retained, 1)?.1
        } else {
            retained.manifest().ordered_chunks[0]
        };
        fs::remove_file(f.deployment.publisher().spool().object_path(damaged))?;
        let before = f.snapshot();
        if capsule {
            assert!(inspect_long_event(
                &f.deployment, &event, &LongEventReplayLimits::default(), &f.cx,
            ).is_err());
        }
        assert!(replay_long_event(
            &f.deployment, &event, pins, &LongEventReplayLimits::default(), &f.cx,
        ).is_err());
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn reviewed_successors_are_not_silently_verified_as_the_original_observation() -> Test {
    let mut f = Fixture::new("reviewed")?;
    let (_, event, _) = f.watch(&scene(40, 3, false)?, "mjpeg", [48, 32], false, false)?;
    let (mut revised, _) = f.deployment.current_event_authority(&event)?;
    revised.supersedes = Some(revised.revision_digest());
    revised.revision = 2;
    f.deployment.publish_event(
        &ReferencePolicyDecision { event: revised, action: ReferencePolicyAction::Hold }, &f.cx,
    )?;
    let before = f.snapshot();
    assert!(matches!(
        inspect_long_event(&f.deployment, &event, &LongEventReplayLimits::default(), &f.cx),
        Err(LongEventReplayError::UnsupportedProfile)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn cancellation_during_native_health_work_returns_no_verified_result_and_no_writes() -> Test {
    let mut f = Fixture::new("cancel")?;
    let (_, event, pins) = f.watch(&scene(40, 3, false)?, "mjpeg", [48, 32], false, true)?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint_occurrence("sensor_health:row", 3);
    assert!(replay_long_event(
        &f.deployment, &event, pins, &LongEventReplayLimits::default(), &f.cx,
    ).is_err());
    assert!(f.cx.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

fn corroboration_plan(
    left: ContentDigest, right: ContentDigest, size: [u32; 2], interpretation: ComponentInterpretation,
    late: bool,
) -> CorroborationPlan {
    CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".into(), import_identity: left,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
            CorroborationCamera {
                name: "west".into(), import_identity: right,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
        ],
        interpretation,
        zones: vec![GroundZone {
            zone_id: "door".into(),
            x: if late { 28.0 } else { 0.0 },
            y: 0.0,
            width: f64::from(size[0]) - if late { 28.0 } else { 0.0 },
            height: f64::from(size[1]),
        }],
        gates: CorroborationGates { time_gate_ns: 200_000_000, distance_gate: 4.0 },
        detector: WatchDetectorConfig { learning_rate_num: 0, ..WatchDetectorConfig::default() },
        tracker: WatchTrackerConfig::default(),
    }
}

fn cold_corroboration(
    label: &str, bytes: &[u8], extension: &str, size: [u32; 2], late: bool, shared: bool,
) -> Test {
    let mut f = Fixture::new(label)?;
    let (left, left_frames) = f.import("east", bytes, extension)?;
    let (right, right_frames) = f.import("west", bytes, extension)?;
    let plan = corroboration_plan(
        left, right, size,
        if extension == "mjpeg" { ComponentInterpretation::Grayscale } else { ComponentInterpretation::YCbCr },
        late,
    );
    let declarations = if shared {
        CorroborationDependencies::new(vec![FailureDomainDeclaration {
            domain: "power:one_supply".into(),
            cameras: vec!["east".into(), "west".into()],
        }])?
    } else {
        CorroborationDependencies::default()
    };
    let limits = LongDwellLimits {
        maximum_source_chunk_bytes: 1024 * 1024,
        maximum_pixel_samples: 1024 * 1024,
        maximum_assignment_work: 1024 * 1024,
        maximum_trace_bytes: 1024 * 1024,
        ..LongDwellLimits::default()
    };
    let mut report = LongCorroborationReport::analyze(
        &f.deployment, &plan, CorroborationOptions::default(), &limits, &declarations, &f.cx,
    )?;
    let recipe_digest = report.plan_digest();
    if late {
        assert!(report.samples().iter().all(|sample| sample.entry_position > 140));
    }
    let candidate = report.candidates().first().ok_or("native cross-camera candidate missing")?;
    let event = candidate.event().event_id.clone();
    let original = candidate.event().clone();
    assert_eq!(original.state, if shared { EventState::Witnessed } else { EventState::Corroborated });
    let pins = LongEventReplayPins {
        event_revision: original.revision_digest(), provenance_root: candidate.provenance_root(),
    };
    let approval = candidate.proposal_digest();
    assert_eq!(report.publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx)?, 1);
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    // The caller may admit a larger ceiling. The retained recipe itself must remain exact.
    let admitted = LongEventReplayLimits::default();
    let inspection = inspect_long_event(&reopened, &event, &admitted, &f.cx)?;
    assert_eq!(inspection.profile(), "long_corroboration");
    assert_eq!(inspection.analysis_roots().len(), 2);
    assert_eq!(inspection.analysis_digests().len(), 2);
    assert_eq!(inspection.pins(), pins);
    let LongEventReplayRecipe::Corroboration(recipe) = inspection.recipe() else {
        return Err("corroboration recipe expected".into());
    };
    assert_eq!(recipe.digest(), recipe_digest);
    assert_eq!(recipe.dependencies(), &declarations);
    assert_eq!(recipe.limits().maximum_source_chunk_bytes, limits.maximum_source_chunk_bytes);
    assert_eq!(recipe.limits().maximum_pixel_samples, limits.maximum_pixel_samples);
    assert!(!recipe.health_screened());
    let verified = replay_long_event(&reopened, &event, pins, &admitted, &f.cx)?;
    assert_eq!(verified.frames_replayed(), left_frames + right_frames);
    assert_eq!(verified.inspection().event(), &original);
    assert!(verified.source_chunk_bytes_read() > 0);
    let mut too_small = admitted;
    too_small.execution.maximum_pixel_samples = limits.maximum_pixel_samples - 1;
    assert!(matches!(
        replay_long_event(&reopened, &event, pins, &too_small, &f.cx),
        Err(LongEventReplayError::Limit)
    ));
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    Ok(())
}

#[test]
fn cold_two_camera_replay_preserves_both_independent_and_declared_common_cause_states() -> Test {
    let bytes = scene(300, 3, true)?;
    for shared in [false, true] {
        cold_corroboration(
            if shared { "shared-cause" } else { "separate-causes" },
            &bytes, "mjpeg", [48, 32], true, shared,
        )?;
    }
    Ok(())
}

#[test]
fn both_inter_coded_camera_profiles_replay_the_full_retained_recipe_after_restart() -> Test {
    for (name, bytes, size) in [
        (
            "corroboration-avc",
            include_bytes!("../../../tests/fixtures/long_dwell_h264/square_300.mp4").as_slice(),
            [48, 32],
        ),
        (
            "corroboration-hevc",
            include_bytes!("../../../tests/fixtures/hevc_ingest/watch_96x48_moving.mp4").as_slice(),
            [96, 48],
        ),
    ] {
        cold_corroboration(name, bytes, "mp4", size, false, false)?;
    }
    Ok(())
}

fn publish_graph(
    deployment: &mut ReferenceDeployment, prefix: &str, identity: ContentDigest,
    manifest: &ObjectManifest, interval: fss_core::CaptureInterval, cx: &ReplayCx,
) -> Test {
    let slot = slot(prefix, identity)?;
    deployment.publisher_mut().stage_manifest(&slot, manifest)?;
    deployment.publish_and_commit(&slot, manifest, interval, cx)?;
    Ok(())
}

#[test]
fn self_consistent_forged_trace_hashes_are_inspectable_but_fail_actual_native_replay() -> Test {
    let mut f = Fixture::new("forged")?;
    let (_, event_id, pins) = f.watch(&scene(40, 3, false)?, "mjpeg", [48, 32], false, false)?;
    let inspection = inspect_long_event(
        &f.deployment, &event_id, &LongEventReplayLimits::default(), &f.cx,
    )?;
    let old_analysis_digest = inspection.analysis_digests()[0];
    let old_analysis_root = inspection.analysis_roots()[0];
    let mut analysis = f.deployment.publisher().spool().read(old_analysis_digest)?;
    let marker = b"fss.long_watch_frame.v1";
    let start = analysis.windows(marker.len()).position(|window| window == marker)
        .ok_or("native watch frame missing")?;
    // Alter a claimed luma identity in the first JPEG frame, preserving all source and recipe
    // bindings. Rehash every containing publication through ordinary guarded owners.
    let luma_byte = start + marker.len() + 8 + 33 + 32 + 1 + 1 + 1 + 8 + 8 + 1;
    analysis[luma_byte] ^= 1;
    let new_analysis_digest = ContentDigest::sha256(&analysis);
    let old_analysis_manifest = ObjectManifest::from_canonical_bytes(
        &f.deployment.publisher().spool().read(old_analysis_root)?,
    )?;
    let new_analysis_manifest = ObjectManifest::new(
        "recorded-long-watch-analysis-v1",
        old_analysis_manifest.children().iter().map(|&child| {
            if child == old_analysis_digest { new_analysis_digest } else { child }
        }),
        None,
    )?;
    let old_identity = event_identity(&event_id, "event:long-watch:")?;
    let mut record = f.deployment.publisher().spool().read(old_identity)?;
    let root_offset = 8 + crate::ingest::long_watch::ENTRY_DOMAIN.len() + 1;
    record[root_offset..root_offset + 32].copy_from_slice(&new_analysis_manifest.root().bytes());
    let identity = ContentDigest::sha256(&record);
    let entry = ObjectManifest::new(
        "recorded-long-watch-entry-v1", [new_analysis_manifest.root(), identity], None,
    )?;
    let mut forged = inspection.event().clone();
    forged.event_id = EventId::parse(format!("event:long-watch:{}", hex(identity)))?;
    forged.decision_path.fingerprint = entry.root();
    for evidence in &mut forged.evidence {
        if evidence.digest == old_identity {
            evidence.digest = identity;
        }
    }
    forged.evidence.sort_by_key(|evidence| evidence.digest);
    forged.validate()?;
    for bytes in [&analysis, &record] {
        let digest = f.deployment.publisher_mut().stage_object(bytes)?;
        f.deployment.publisher_mut().verify_object(digest)?;
    }
    publish_graph(
        &mut f.deployment, "lw-a", new_analysis_digest, &new_analysis_manifest, forged.interval, &f.cx,
    )?;
    publish_graph(&mut f.deployment, "lw-e", identity, &entry, forged.interval, &f.cx)?;
    f.deployment.publish_event(
        &ReferencePolicyDecision { event: forged.clone(), action: ReferencePolicyAction::Hold }, &f.cx,
    )?;
    let inspected = inspect_long_event(
        &f.deployment, &forged.event_id, &LongEventReplayLimits::default(), &f.cx,
    )?;
    assert_eq!(inspected.analysis_digests(), &[new_analysis_digest]);
    assert_ne!(inspected.pins(), pins);
    let before = f.snapshot();
    assert!(matches!(
        replay_long_event(
            &f.deployment, &forged.event_id, inspected.pins(), &LongEventReplayLimits::default(), &f.cx,
        ),
        Err(LongEventReplayError::Diverged)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}
