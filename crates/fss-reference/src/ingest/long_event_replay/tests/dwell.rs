#![forbid(unsafe_code)]
//! Existing canonical dwell producers replay through the general cold event owner.
//! Real native source/model execution is required; synthetic scenes do not qualify field accuracy.

use super::*;
use crate::ScalarExecCx;
use crate::ingest::detector_cascade::{CascadeConfig, SelectionReason};
use crate::ingest::long_dwell::{EPISODE_DOMAIN, LongDwellDetector, LongDwellReport};
use crate::ingest::long_watch::detector::{OUTCOME_DOMAIN, retained_inventory};
use crate::ingest::package_detect::PackageDetectLimits;
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::ingest::zone_dwell::DwellPolicy;
use fss_core::{CanonicalDecoder, EvidenceEdgeRelation};

const AVC: &[u8] = include_bytes!("../../../../tests/fixtures/long_dwell_h264/square_300.mp4");
const HEVC: &[u8] = include_bytes!("../../../../tests/fixtures/hevc_ingest/watch_96x48_moving.mp4");
const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn rule(bytes: &[u8]) -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: if bytes == AVC { 20_000_000_000 } else { 1 },
        maximum_sample_gap_ns: 1_000_000_000,
        minimum_observations: 3,
    }
}

fn publish_dwell(
    f: &mut Fixture,
    bytes: &[u8],
    extension: &str,
    size: [u32; 2],
    trained: bool,
    screened: bool,
) -> Test<(WatchPlan, EventId, LongEventReplayPins)> {
    let (identity, count) = f.import("dwell", bytes, extension)?;
    let plan = WatchPlan {
        import_identity: identity,
        first_segment: 0,
        segment_count: count,
        zones: vec![WatchZone {
            zone_id: "porch".into(),
            x: 0,
            y: 0,
            width: size[0],
            height: size[1],
        }],
        interpretation: if extension == "mjpeg" {
            ComponentInterpretation::Grayscale
        } else {
            ComponentInterpretation::YCbCr
        },
        detector: WatchDetectorConfig {
            learning_rate_num: 0,
            ..WatchDetectorConfig::default()
        },
        tracker: WatchTrackerConfig::default(),
    };
    let before = f.snapshot();
    let mut report = if trained {
        let scalar = ScalarExecCx::new();
        let result = (|| -> Test<LongDwellReport> {
            let package = RgbDetectorPackage::load(
                PACKAGE,
                ContentDigest::parse(PACKAGE_DIGEST)?,
                1 << 36,
                &f.cx,
                &scalar,
            )?;
            let detector = LongDwellDetector::new(
                &package,
                PACKAGE,
                CascadeConfig {
                    frames_per_track: 3,
                    max_inferences: 1,
                    ..CascadeConfig::default()
                },
                PackageDetectLimits::default(),
                &scalar,
            )?;
            Ok(LongDwellReport::analyze_with_detector(
                &f.deployment,
                &plan,
                rule(bytes),
                WatchOptions::default(),
                &LongDwellLimits::default(),
                &detector,
                screened,
                &f.cx,
            )?)
        })();
        scalar.drain_and_finalize();
        result?
    } else if screened {
        LongDwellReport::analyze_screened(
            &f.deployment,
            &plan,
            rule(bytes),
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &f.cx,
        )?
    } else {
        LongDwellReport::analyze(
            &f.deployment,
            &plan,
            rule(bytes),
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &f.cx,
        )?
    };
    assert_eq!(f.snapshot(), before);
    assert!(!report.publication_blocked());
    let candidate = report
        .candidates()
        .first()
        .ok_or("qualifying native dwell episode missing")?;
    let event = candidate.event().event_id.clone();
    let approval = candidate.proposal_digest();
    let first = candidate.span().first.position;
    let last = candidate.span().last.position;
    let track = candidate.event().track_ids[0].clone();
    assert!(candidate.span().trigger.position > first);
    assert!(candidate.event().evidence.iter().all(|edge| !edge.supports));
    assert!(
        candidate
            .event()
            .evidence
            .iter()
            .all(|edge| edge.relation == EvidenceEdgeRelation::DerivedFrom)
    );
    assert!(candidate.event().decision_path.abstained);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    if trained {
        assert_eq!(candidate.class_evidence().len(), 3);
        assert_eq!(
            candidate.class_evidence()[0].reason,
            SelectionReason::DwellStart
        );
        assert!(
            candidate.class_evidence()[1..]
                .iter()
                .all(|class| class.reason == SelectionReason::FollowingMatch)
        );
        assert_eq!(
            report
                .detector_cascade()
                .ok_or("trained outcome")?
                .inferred_segments()
                .len(),
            1
        );
    }
    assert_eq!(
        report.publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx)?,
        1
    );
    let inspection = inspect_long_event(
        &f.deployment,
        &event,
        &LongEventReplayLimits::default(),
        &f.cx,
    )?;
    // The upstream episode root has only these two children; class evidence belongs to the
    // shared analysis and must not be moved into a different canonical episode graph.
    let episode = ObjectManifest::from_canonical_bytes(
        &f.deployment
            .publisher()
            .spool()
            .read(inspection.pins().provenance_root)?,
    )?;
    assert_eq!(episode.children().len(), 2);
    if trained {
        let analysis = ObjectManifest::from_canonical_bytes(
            &f.deployment
                .publisher()
                .spool()
                .read(inspection.analysis_roots()[0])?,
        )?;
        let mut inventory = None;
        for child in analysis.children() {
            let bytes = f.deployment.publisher().spool().read(*child)?;
            if CanonicalDecoder::new(&bytes).text().ok() == Some(OUTCOME_DOMAIN) {
                inventory = Some(retained_inventory(&bytes)?);
            }
        }
        let inventory = inventory.ok_or("retained trained outcome")?;
        let selected: Vec<_> = inventory
            .classes
            .iter()
            .filter(|class| {
                class.entry_position == first
                    && class.zone == 0
                    && format!("track:{}:{}", class.epoch, class.track) == track
            })
            .collect();
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].position, first);
        assert!(
            selected
                .iter()
                .all(|class| (first..=last).contains(&class.position))
        );
        if bytes == AVC {
            assert!(
                selected.iter().any(|class| class.position != class.segment),
                "B-picture display positions must retain their own coding-segment associations"
            );
        }
    }
    Ok((plan, event, inspection.pins()))
}

#[test]
fn native_trained_dwell_cold_replays_jpeg_avc_and_hevc_from_exact_retained_packages() -> Test {
    let jpeg = scene(40, 3, false)?;
    for (label, bytes, extension, size, frames, format) in [
        (
            "dwell-trained-jpeg",
            jpeg.as_slice(),
            "mjpeg",
            [48, 32],
            40,
            "mjpeg",
        ),
        ("dwell-trained-avc", AVC, "mp4", [48, 32], 300, "mp4avc"),
        ("dwell-trained-hevc", HEVC, "mp4", [96, 48], 14, "mp4hevc"),
    ] {
        let mut f = Fixture::new(label)?;
        let (plan, event, pins) = publish_dwell(&mut f, bytes, extension, size, true, false)?;
        let before = f.snapshot();
        let root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
        let reader = context(&root, "principal:another-authorized-reader")?;
        let inspection = inspect_long_event(
            &reopened,
            &event,
            &LongEventReplayLimits::default(),
            &reader,
        )?;
        let LongEventReplayRecipe::Dwell(recipe) = inspection.recipe() else {
            return Err("dwell recipe expected".into());
        };
        assert_eq!(recipe.plan(), &plan);
        assert_eq!(recipe.rule(), rule(bytes));
        assert_eq!(recipe.media_format(), format);
        assert!(recipe.complete_codec_limits_retained());
        assert_eq!(
            recipe
                .detector_recipe()
                .ok_or("retained detector recipe")?
                .package_digest(),
            ContentDigest::parse(PACKAGE_DIGEST)?
        );
        let verified = replay_long_event(
            &reopened,
            &event,
            pins,
            &LongEventReplayLimits::default(),
            &reader,
        )?;
        assert_eq!(verified.frames_replayed(), frames);
        assert_eq!(verified.inspection().profile(), "long_dwell");
        assert_eq!(verified.inspection().pins(), pins);
        assert_eq!(verified.inspection().event(), inspection.event());
        assert!(verified.source_chunk_bytes_read() > bytes.len() as u64);
        assert_eq!(*reopened.current_anchor(), before.0);
        assert_eq!(reopened.effects().last_root(), before.1);
        assert_eq!(reopened.publisher().spool().object_count(), before.2);

        // Replay cannot fall back to a repository or loose model when retained custody is lost.
        fs::remove_file(
            reopened
                .publisher()
                .spool()
                .object_path(ContentDigest::parse(PACKAGE_DIGEST)?),
        )?;
        assert!(
            inspect_long_event(
                &reopened,
                &event,
                &LongEventReplayLimits::default(),
                &reader,
            )
            .is_err()
        );
        assert!(
            replay_long_event(
                &reopened,
                &event,
                pins,
                &LongEventReplayLimits::default(),
                &reader,
            )
            .is_err()
        );
        assert_eq!(*reopened.current_anchor(), before.0);
        assert_eq!(reopened.effects().last_root(), before.1);
    }
    Ok(())
}

#[test]
fn native_model_free_dwell_replay_preserves_historical_limits_and_mjpeg_screening() -> Test {
    let jpeg = scene(40, 3, false)?;
    for (label, bytes, extension, size, frames, screened) in [
        (
            "dwell-plain-jpeg",
            jpeg.as_slice(),
            "mjpeg",
            [48, 32],
            40,
            true,
        ),
        ("dwell-plain-avc", AVC, "mp4", [48, 32], 300, false),
        ("dwell-plain-hevc", HEVC, "mp4", [96, 48], 14, false),
    ] {
        let mut f = Fixture::new(label)?;
        let (_, event, pins) = publish_dwell(&mut f, bytes, extension, size, false, screened)?;
        let before = f.snapshot();
        let root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
        let verified = replay_long_event(
            &reopened,
            &event,
            pins,
            &LongEventReplayLimits::default(),
            &f.cx,
        )?;
        let LongEventReplayRecipe::Dwell(recipe) = verified.inspection().recipe() else {
            return Err("dwell recipe expected".into());
        };
        assert!(recipe.detector_recipe().is_none());
        assert!(!recipe.complete_codec_limits_retained());
        assert_eq!(recipe.screened(), screened);
        assert_eq!(verified.frames_replayed(), frames);
        assert_eq!(*reopened.current_anchor(), before.0);
        assert_eq!(reopened.effects().last_root(), before.1);
        assert_eq!(reopened.publisher().spool().object_count(), before.2);
    }
    Ok(())
}

#[test]
fn dwell_replay_requires_current_privacy_pins_and_original_trained_reservations() -> Test {
    let mut f = Fixture::new("dwell-bounds")?;
    let (_, event, pins) = publish_dwell(
        &mut f,
        &scene(40, 3, false)?,
        "mjpeg",
        [48, 32],
        true,
        false,
    )?;
    f.cx.set_cancel_at_checkpoint("long_event_replay:execute");
    let before = f.snapshot();
    for stale in [
        LongEventReplayPins {
            event_revision: ContentDigest::sha256(b"other event"),
            ..pins
        },
        LongEventReplayPins {
            provenance_root: ContentDigest::sha256(b"other root"),
            ..pins
        },
    ] {
        assert!(matches!(
            replay_long_event(
                &f.deployment,
                &event,
                stale,
                &LongEventReplayLimits::default(),
                &f.cx
            ),
            Err(LongEventReplayError::StaleSelection)
        ));
    }
    let tighter = LongEventReplayLimits {
        execution: LongDwellLimits {
            maximum_pixel_samples: LongDwellLimits::default().maximum_pixel_samples - 1,
            ..LongDwellLimits::default()
        },
        ..LongEventReplayLimits::default()
    };
    assert!(replay_long_event(&f.deployment, &event, pins, &tighter, &f.cx).is_err());
    assert!(
        !f.cx.is_cancelled(),
        "pin/recipe admission must precede native execution"
    );
    assert_eq!(f.snapshot(), before);
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-event-dwell")?,
        [48, 32],
        &[[40, 0, 8, 32]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = f.snapshot();
    assert!(matches!(
        inspect_long_event(
            &f.deployment,
            &event,
            &LongEventReplayLimits::default(),
            &f.cx
        ),
        Err(LongEventReplayError::PrivacyChanged)
    ));
    assert!(matches!(
        replay_long_event(
            &f.deployment,
            &event,
            pins,
            &LongEventReplayLimits::default(),
            &f.cx
        ),
        Err(LongEventReplayError::PrivacyChanged)
    ));
    assert!(!f.cx.is_cancelled());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn missing_inter_coded_dwell_chunks_and_background_capsules_refuse_without_writes() -> Test {
    for capsule in [false, true] {
        let mut f = Fixture::new(if capsule {
            "dwell-capsule"
        } else {
            "dwell-chunk"
        })?;
        let (plan, event, pins) = publish_dwell(&mut f, AVC, "mp4", [48, 32], false, false)?;
        let retained = RetainedFileImport::open(
            &f.deployment,
            plan.import_identity,
            Default::default(),
            &f.cx,
        )?;
        let missing = if capsule {
            source_capsule(&f.deployment, &retained, 1)?.1
        } else {
            retained.manifest().ordered_chunks[0]
        };
        fs::remove_file(f.deployment.publisher().spool().object_path(missing))?;
        let before = f.snapshot();
        if capsule {
            assert!(
                inspect_long_event(
                    &f.deployment,
                    &event,
                    &LongEventReplayLimits::default(),
                    &f.cx,
                )
                .is_err()
            );
        }
        assert!(
            replay_long_event(
                &f.deployment,
                &event,
                pins,
                &LongEventReplayLimits::default(),
                &f.cx,
            )
            .is_err()
        );
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn a_self_consistent_forged_inter_coded_dwell_trace_still_requires_native_recomputation() -> Test {
    let mut f = Fixture::new("dwell-forged")?;
    let (_, event_id, pins) = publish_dwell(&mut f, AVC, "mp4", [48, 32], false, false)?;
    let inspection = inspect_long_event(
        &f.deployment,
        &event_id,
        &LongEventReplayLimits::default(),
        &f.cx,
    )?;
    let old_analysis_digest = inspection.analysis_digests()[0];
    let old_analysis_root = inspection.analysis_roots()[0];
    let mut analysis = f.deployment.publisher().spool().read(old_analysis_digest)?;
    let marker = b"fss.long_dwell_frame.v1";
    let start = analysis
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("native dwell frame missing")?;
    // Keep the display position, coding segment, capsule and capture claims intact; alter
    // only a native luma identity and republish its complete containing graph honestly.
    let luma_byte = start + marker.len() + 8 + 8 + 33 + 32 + 1 + 1 + 1 + 8 + 8 + 1;
    analysis[luma_byte] ^= 1;
    let new_analysis_digest = ContentDigest::sha256(&analysis);
    let old_analysis = ObjectManifest::from_canonical_bytes(
        &f.deployment.publisher().spool().read(old_analysis_root)?,
    )?;
    let new_analysis = ObjectManifest::new(
        "recorded-long-dwell-analysis-v1",
        old_analysis.children().iter().map(|&child| {
            if child == old_analysis_digest {
                new_analysis_digest
            } else {
                child
            }
        }),
        None,
    )?;
    let old_identity = event_identity(&event_id, "event:long-dwell:")?;
    let mut record = f.deployment.publisher().spool().read(old_identity)?;
    let root_offset = 8 + EPISODE_DOMAIN.len() + 1;
    record[root_offset..root_offset + 32].copy_from_slice(&new_analysis.root().bytes());
    let identity = ContentDigest::sha256(&record);
    let episode = ObjectManifest::new(
        "recorded-long-dwell-episode-v1",
        [new_analysis.root(), identity],
        None,
    )?;
    let mut forged = inspection.event().clone();
    forged.event_id = EventId::parse(format!("event:long-dwell:{}", hex(identity)))?;
    forged.decision_path.fingerprint = episode.root();
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
        &mut f.deployment,
        "ld-a",
        new_analysis_digest,
        &new_analysis,
        forged.interval,
        &f.cx,
    )?;
    publish_graph(
        &mut f.deployment,
        "ld-e",
        identity,
        &episode,
        forged.interval,
        &f.cx,
    )?;
    f.deployment.publish_event(
        &ReferencePolicyDecision {
            event: forged.clone(),
            action: ReferencePolicyAction::Hold,
        },
        &f.cx,
    )?;
    let inspected = inspect_long_event(
        &f.deployment,
        &forged.event_id,
        &LongEventReplayLimits::default(),
        &f.cx,
    )?;
    assert_eq!(inspected.analysis_digests(), &[new_analysis_digest]);
    assert_ne!(inspected.pins(), pins);
    let before = f.snapshot();
    assert!(matches!(
        replay_long_event(
            &f.deployment,
            &forged.event_id,
            inspected.pins(),
            &LongEventReplayLimits::default(),
            &f.cx,
        ),
        Err(LongEventReplayError::Diverged)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn cancellation_during_dwell_native_screening_returns_no_verified_result() -> Test {
    let mut f = Fixture::new("dwell-cancel")?;
    let (_, event, pins) = publish_dwell(
        &mut f,
        &scene(40, 3, false)?,
        "mjpeg",
        [48, 32],
        false,
        true,
    )?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint_occurrence("sensor_health:row", 3);
    assert!(
        replay_long_event(
            &f.deployment,
            &event,
            pins,
            &LongEventReplayLimits::default(),
            &f.cx,
        )
        .is_err()
    );
    assert!(f.cx.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}
