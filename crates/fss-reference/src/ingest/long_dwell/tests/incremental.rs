#![forbid(unsafe_code)]
//! Native source -> resumable foreground/tracker/dwell -> unchanged event publication.

use super::*;
use crate::ingest::long_dwell::incremental::{
    DwellCheckpointPin, DwellRestoreLimits, DwellWork, PreparedIncrementalDwell,
    RetainedDwellCheckpoint,
};

fn prepare(
    f: &Fixture,
    limits: LongDwellLimits,
    options: WatchOptions,
) -> Test<PreparedIncrementalDwell> {
    Ok(PreparedIncrementalDwell::new(
        &f.deployment,
        f.plan.clone(),
        rule(),
        options,
        limits,
        &f.cx,
    )?)
}
fn restore_limits() -> DwellRestoreLimits {
    DwellRestoreLimits {
        maximum_prefix_frames: FRAMES,
        execution: LongDwellLimits::default(),
    }
}
fn same_report(actual: &LongDwellReport, expected: &LongDwellReport) {
    assert_eq!(actual.analysis, expected.analysis);
    assert_eq!(actual.analysis_manifest, expected.analysis_manifest);
    assert_eq!(actual.source_bytes, expected.source_bytes);
    assert_eq!(actual.pixel_samples, expected.pixel_samples);
    assert_eq!(actual.assignment_work, expected.assignment_work);
    assert_eq!(actual.jpeg_work, expected.jpeg_work);
    assert_eq!(actual.decoded, expected.decoded);
    assert_eq!(actual.candidates.len(), expected.candidates.len());
    for (a, b) in actual.candidates.iter().zip(&expected.candidates) {
        assert_eq!(a.event, b.event);
        assert_eq!(a.record, b.record);
        assert_eq!(a.manifest, b.manifest);
        assert_eq!(a.approval, b.approval);
    }
}

#[test]
fn native_hot_steps_keep_long_episode_and_exact_whole_recording_identity() -> Test {
    let f = Fixture::new("incremental-hot", &scene(true, None, None, false)?, true)?;
    let expected = f.analyze(rule())?;
    assert_eq!(expected.candidates().len(), 1);
    let before = f.snapshot();
    for chunk in [1, 17, 128, 299] {
        let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
        let mut running = prepared.start()?;
        let mut previous = DwellWork::default();
        while !running.complete() {
            let work = running.advance(&f.deployment, chunk, &f.cx)?;
            assert_eq!(
                work.source_positions,
                (previous.source_positions + chunk).min(FRAMES)
            );
            assert_eq!(work.frames_decoded, work.source_positions);
            assert!(work.source_chunk_bytes >= previous.source_chunk_bytes);
            assert!(work.jpeg_work >= previous.jpeg_work);
            assert_eq!(running.restoration_work(), DwellWork::default());
            previous = work;
        }
        assert_eq!(previous.source_chunk_bytes, expected.source_bytes);
        let report = running.finish(&f.deployment, &f.cx)?;
        same_report(&report, &expected);
    }
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn durable_cold_prefix_restores_state_without_resetting_budget_or_duplicate_publication() -> Test {
    let mut f = Fixture::new("incremental-cold", &scene(true, None, None, false)?, true)?;
    let expected = f.analyze(rule())?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    let prefix = running.advance(&f.deployment, 127, &f.cx)?;
    assert!(!running.complete());
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let after = f.snapshot();
    assert_eq!(running.retain(&mut f.deployment, &f.cx)?, pin);
    assert_eq!(f.snapshot(), after);
    drop(running);
    drop(prepared);
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let cx = context(&root, "principal:long-dwell-test")?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let saved = RetainedDwellCheckpoint::open(&reopened, pin, &restore_limits(), &cx)?;
    assert_eq!(saved.prefix_work(), prefix);
    let before_restore = reopened.current_anchor().clone();
    let mut resumed = saved.resume(&reopened, &restore_limits(), &cx)?;
    assert_eq!(resumed.work(), prefix);
    assert_eq!(resumed.restoration_work(), prefix);
    resumed.advance(&reopened, 129, &cx)?;
    assert_eq!(resumed.work().source_positions, 256);
    resumed.advance(&reopened, 128, &cx)?;
    let final_work = resumed.work();
    assert_eq!(resumed.restoration_work(), prefix);
    let complete_pin = resumed.retain(&mut reopened, &cx)?;
    assert_ne!(pin, complete_pin);
    let mut actual = resumed.finish(&reopened, &cx)?;
    same_report(&actual, &expected);
    assert_eq!(final_work.jpeg_work, expected.jpeg_work);
    assert!(reopened.current_anchor().commit_sequence > before_restore.commit_sequence);
    let approvals = BTreeSet::from([expected.candidates()[0].proposal_digest()]);
    assert_eq!(actual.publish(&mut reopened, &approvals, &cx)?, 1);
    let after_event = reopened.current_anchor().clone();
    let complete = RetainedDwellCheckpoint::open(&reopened, complete_pin, &restore_limits(), &cx)?;
    let retry = complete.resume(&reopened, &restore_limits(), &cx)?;
    assert!(retry.complete());
    let mut retry_report = retry.finish(&reopened, &cx)?;
    assert_eq!(retry_report.analysis_digest(), expected.analysis_digest());
    assert_eq!(retry_report.publish(&mut reopened, &approvals, &cx)?, 0);
    assert_eq!(reopened.current_anchor(), &after_event);
    Ok(())
}

#[test]
fn miss_gap_and_decode_refusal_keep_the_existing_reset_semantics_across_steps() -> Test {
    for (label, bytes) in [
        ("incremental-miss", scene(true, Some(150), None, false)?),
        ("incremental-refusal", scene(true, None, Some(150), false)?),
        ("incremental-gap", scene(true, None, None, true)?),
    ] {
        let f = Fixture::new(label, &bytes, true)?;
        let options = WatchOptions {
            tolerate_decode_refusals: true,
        };
        let expected = LongDwellReport::analyze(
            &f.deployment,
            &f.plan,
            rule(),
            options,
            &LongDwellLimits::default(),
            &f.cx,
        )?;
        let prepared = prepare(&f, LongDwellLimits::default(), options)?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 150, &f.cx)?;
        running.advance(&f.deployment, 1, &f.cx)?;
        running.advance(&f.deployment, 149, &f.cx)?;
        same_report(&running.finish(&f.deployment, &f.cx)?, &expected);
    }
    Ok(())
}

#[test]
fn step_failure_poisoning_and_cold_resume_cannot_refill_original_work() -> Test {
    let mut f = Fixture::new("incremental-budget", &scene(true, None, None, false)?, true)?;
    let limits = LongDwellLimits {
        maximum_pixel_samples: u64::from(WIDTH * HEIGHT) * 100,
        ..LongDwellLimits::default()
    };
    let prepared = prepare(&f, limits, WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let after = f.snapshot();
    assert!(matches!(
        running.advance(&f.deployment, 64, &f.cx),
        Err(WatchError::Limit)
    ));
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert!(!running.complete());
    assert_eq!(f.snapshot(), after);
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.work().source_positions, 64);
    assert!(matches!(
        resumed.advance(&f.deployment, 64, &f.cx),
        Err(WatchError::Limit)
    ));
    assert_eq!(f.snapshot(), after);
    Ok(())
}

#[test]
fn insufficient_restore_admission_and_stale_privacy_refuse_before_decode() -> Test {
    let mut f = Fixture::new(
        "incremental-admission",
        &scene(true, None, None, false)?,
        true,
    )?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let before = f.snapshot();
    let denied = context(f.deployment.root(), "principal:long-dwell-test")?;
    denied.set_cancel_at_checkpoint("long_dwell:decoded");
    let low = DwellRestoreLimits {
        maximum_prefix_frames: 63,
        ..restore_limits()
    };
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &low, &denied).is_err());
    assert!(!denied.is_cancelled());
    let low = DwellRestoreLimits {
        execution: LongDwellLimits {
            maximum_pixel_samples: 1,
            ..LongDwellLimits::default()
        },
        ..restore_limits()
    };
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &low, &denied).is_err());
    assert!(!denied.is_cancelled());
    assert_eq!(f.snapshot(), before);
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-dwell")?,
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let masked = f.snapshot();
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &denied).is_err());
    assert!(!denied.is_cancelled());
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert_eq!(f.snapshot(), masked);
    Ok(())
}

#[test]
fn missing_checkpoint_or_source_custody_never_heals_from_cached_native_state() -> Test {
    for remove_source in [false, true] {
        let mut f = Fixture::new(
            if remove_source {
                "incremental-source-gone"
            } else {
                "incremental-checkpoint-gone"
            },
            &scene(true, None, None, false)?,
            true,
        )?;
        let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 64, &f.cx)?;
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let missing = if remove_source {
            let source = RetainedFileImport::open(
                &f.deployment,
                f.plan.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )?;
            source.manifest().ordered_chunks[0]
        } else {
            pin.record_digest
        };
        fs::remove_file(f.deployment.publisher().spool().object_path(missing))?;
        let after = f.snapshot();
        assert!(running.retain(&mut f.deployment, &f.cx).is_err());
        assert!(
            RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx).is_err()
        );
        assert!(
            saved
                .resume(&f.deployment, &restore_limits(), &f.cx)
                .is_err()
        );
        assert_eq!(f.snapshot(), after);
    }
    Ok(())
}

#[test]
fn a_self_consistent_forged_prefix_cannot_install_a_tracker_state() -> Test {
    let mut f = Fixture::new(
        "incremental-divergence",
        &scene(true, None, None, false)?,
        true,
    )?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let mut bytes = f.deployment.publisher().spool().read(pin.record_digest)?;
    // The final length-framed field is opaque native trace. Retain its same length and work
    // claims, change one byte, and publish a valid content-addressed graph around the forgery.
    let last = bytes.last_mut().ok_or("empty checkpoint")?;
    *last ^= 1;
    let changed_record = f.deployment.stage_payload(&bytes)?;
    let original = f.deployment.publisher().spool().read(pin.provenance_root)?;
    let original = ObjectManifest::from_canonical_bytes(&original)?;
    let changed = ObjectManifest::new(
        original.kind(),
        original.children().iter().map(|digest| {
            if *digest == pin.record_digest {
                changed_record
            } else {
                *digest
            }
        }),
        None,
    )?;
    let target = super::super::slot("ld-c", changed_record)?;
    super::super::publish_manifest(
        &mut f.deployment,
        &target,
        &changed,
        CaptureInterval::point(TimestampNs(0)),
        &f.cx,
    )?;
    let forged = DwellCheckpointPin {
        record_digest: changed_record,
        provenance_root: changed.root(),
    };
    let saved = RetainedDwellCheckpoint::open(&f.deployment, forged, &restore_limits(), &f.cx)?;
    let before = f.snapshot();
    assert!(matches!(
        saved.resume(&f.deployment, &restore_limits(), &f.cx),
        Err(WatchError::InvalidPlan(
            "native checkpoint reconstruction diverged"
        ))
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn cancellation_drains_native_reconstruction_and_checkpoint_retry_is_exact() -> Test {
    let mut f = Fixture::new("incremental-cancel", &scene(true, None, None, false)?, true)?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let publication = context(f.deployment.root(), "principal:long-dwell-test")?;
    publication
        .set_cancel_at_checkpoint(crate::reference_deployment::STAGE_AFTER_CHILDREN_VERIFIED);
    let before = f.deployment.current_anchor().clone();
    assert!(running.retain(&mut f.deployment, &publication).is_err());
    assert!(publication.is_drain_completed());
    assert_eq!(f.deployment.current_anchor(), &before);
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let after = f.snapshot();
    assert_eq!(running.retain(&mut f.deployment, &f.cx)?, pin);
    assert_eq!(f.snapshot(), after);
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let interrupted = context(f.deployment.root(), "principal:long-dwell-test")?;
    interrupted.set_cancel_at_checkpoint_occurrence("long_dwell:decoded", 10);
    assert!(
        saved
            .resume(&f.deployment, &restore_limits(), &interrupted)
            .is_err()
    );
    assert!(interrupted.is_drain_completed());
    assert_eq!(f.snapshot(), after);
    let resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.work().source_positions, 64);
    Ok(())
}

#[test]
fn unsupported_video_empty_checkpoint_and_incomplete_finish_are_explicit() -> Test {
    let f = inter_fixture("incremental-avc-refused", SQUARE_MP4)?;
    let before = f.snapshot();
    assert!(matches!(
        PreparedIncrementalDwell::new(
            &f.deployment,
            f.plan.clone(),
            rule(),
            WatchOptions::default(),
            LongDwellLimits::default(),
            &f.cx
        ),
        Err(WatchError::InvalidPlan(
            "incremental dwell currently requires retained MJPEG"
        ))
    ));
    assert_eq!(f.snapshot(), before);
    let mut f = Fixture::new("incremental-empty", &scene(true, None, None, false)?, true)?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert!(running.advance(&f.deployment, 0, &f.cx).is_err());
    assert_eq!(running.work(), DwellWork::default());
    running.advance(&f.deployment, 1, &f.cx)?;
    assert!(running.finish(&f.deployment, &f.cx).is_err());
    Ok(())
}

#[test]
fn partitioned_source_refuses_before_decode_until_checkpoint_has_part_closure() -> Test {
    let directory = Directory::new("incremental-partitioned")?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("source.mjpeg");
    fs::write(&path, scene(true, None, None, false)?)?;
    let cx = context(&root, "principal:long-dwell-test")?;
    let mut deployment = ReferenceDeployment::open_with_limits(
        &root,
        SITE,
        crate::DeploymentLimits {
            manifest_children_max: 64,
            ..crate::DeploymentLimits::standard()
        },
        &cx,
    )?;
    let mut ingest_limits = FileIngestLimits::standard();
    ingest_limits.max_segments = FRAMES + 1;
    ingest_limits.chunk_bytes = 4096;
    let receipt = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &path,
            SensorId::parse("sensor:long-dwell")?,
            StreamId::parse("stream:long-dwell")?,
        )
        .with_limits(ingest_limits)
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    fs::remove_file(path)?;
    let limits = LongDwellLimits::default();
    let retained = RetainedFileImport::open(
        &deployment,
        receipt.import_identity,
        limits.decode.read_limits,
        &cx,
    )?;
    assert!(!retained.manifest().part_roots.is_empty());
    let before = deployment.current_anchor().clone();
    let denied = context(&root, "principal:long-dwell-test")?;
    denied.set_cancel_at_checkpoint("long_dwell:decoded");
    let result = PreparedIncrementalDwell::new(
        &deployment,
        WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: WIDTH,
                height: HEIGHT,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        },
        rule(),
        WatchOptions::default(),
        limits,
        &denied,
    );
    assert!(matches!(
        result,
        Err(WatchError::InvalidPlan(
            "incremental dwell currently requires a flat retained import"
        ))
    ));
    assert!(!denied.is_cancelled());
    assert_eq!(deployment.current_anchor(), &before);
    Ok(())
}
