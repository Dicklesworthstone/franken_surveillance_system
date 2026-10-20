#![forbid(unsafe_code)]
//! Screened native checkpoints preserve health state, work, custody and publication fences.

use super::*;
use crate::ingest::long_dwell::incremental::{
    CHECKPOINT_DOMAIN, CHECKPOINT_DOMAIN_V2, CHECKPOINT_MANIFEST_KIND, CHECKPOINT_MANIFEST_KIND_V2,
    DwellHealthWork, DwellRestoreLimits, DwellWork, PreparedIncrementalDwell,
    RetainedDwellCheckpoint,
};
use fss_core::CanonicalDecoder;
use std::path::Path;

fn prepare(f: &Fixture, limits: LongDwellLimits, tolerant: bool) -> Test<PreparedIncrementalDwell> {
    Ok(PreparedIncrementalDwell::new_screened(
        &f.deployment,
        f.plan.clone(),
        rule(),
        WatchOptions {
            tolerate_decode_refusals: tolerant,
        },
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

fn health_work(frames: usize) -> DwellHealthWork {
    DwellHealthWork {
        frames_screened: frames,
        samples_screened: frames as u64 * u64::from(WIDTH * HEIGHT),
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:dwell-health".into(),
        operation_id: OperationId::parse("operation:dwell-health")?,
        principal: "principal:dwell-health".into(),
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

fn snapshot(deployment: &ReferenceDeployment) -> (LedgerAnchor, ContentDigest, usize) {
    (
        deployment.current_anchor().clone(),
        deployment.effects().last_root(),
        deployment.publisher().spool().digests().count(),
    )
}

fn same_native(actual: &LongDwellReport, expected: &LongDwellReport) -> Test {
    assert_eq!(actual.analysis, expected.analysis);
    assert_eq!(actual.analysis_manifest, expected.analysis_manifest);
    assert_eq!(actual.health_summary(), expected.health_summary());
    assert_eq!(actual.publication_blocked(), expected.publication_blocked());
    assert_eq!(actual.jpeg_work, expected.jpeg_work);
    assert_eq!(actual.to_json(0, None)?, expected.to_json(0, None)?);
    Ok(())
}

#[test]
fn screened_hot_steps_match_one_shot_measurements_and_single_decode_work() -> Test {
    for (label, scene, masked) in [
        ("health-incremental-changing", Scene::Changing, false),
        ("health-incremental-frozen", Scene::Frozen, false),
        ("health-incremental-masked", Scene::MaskedChange, true),
    ] {
        let mut f = Fixture::new(label, scene, false, false)?;
        if masked {
            f.mask()?;
        }
        let expected = f.scan(true, false, &LongDwellLimits::default())?;
        let before = f.snapshot();
        // Seven-frame steps cross the repetition threshold; larger steps cross frame 128.
        for step in [7, 128] {
            let prepared = prepare(&f, LongDwellLimits::default(), false)?;
            assert!(prepared.screened());
            let mut running = prepared.start()?;
            assert_eq!(running.health_work(), Some(DwellHealthWork::default()));
            while !running.complete() {
                let work = running.advance(&f.deployment, step, &f.cx)?;
                assert_eq!(
                    running.health_work(),
                    Some(health_work(work.source_positions))
                );
                assert_eq!(running.restoration_work(), DwellWork::default());
                assert_eq!(
                    running.restoration_health_work(),
                    Some(DwellHealthWork::default())
                );
            }
            assert_eq!(running.work().frames_decoded, FRAMES);
            assert_eq!(running.work().source_chunk_bytes, f.input_bytes);
            assert_eq!(running.work().jpeg_work, expected.jpeg_work);
            same_native(&running.finish(&f.deployment, &f.cx)?, &expected)?;
        }
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn a_frozen_finding_crosses_cold_boundaries_without_losing_its_publication_fence() -> Test {
    for boundary in [7, 127] {
        let mut f = Fixture::new(
            &format!("health-incremental-frozen-cold-{boundary}"),
            Scene::Frozen,
            false,
            false,
        )?;
        let prepared = prepare(&f, LongDwellLimits::default(), false)?;
        let mut running = prepared.start()?;
        let prefix = running.advance(&f.deployment, boundary, &f.cx)?;
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let expected = f.scan(true, false, &LongDwellLimits::default())?;
        let before = f.snapshot();
        assert!(!f._directory.0.join("camera.mjpeg").exists());
        drop(running);
        drop(prepared);
        let root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        let cx = context(&root)?;
        let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
        let saved = RetainedDwellCheckpoint::open(&reopened, pin, &restore_limits(), &cx)?;
        assert!(saved.prepared().screened());
        assert_eq!(saved.prefix_work(), prefix);
        assert_eq!(saved.prefix_health_work(), Some(health_work(boundary)));
        let mut resumed = saved.resume(&reopened, &restore_limits(), &cx)?;
        assert_eq!(resumed.work(), prefix);
        assert_eq!(resumed.restoration_work(), prefix);
        assert_eq!(
            resumed.restoration_health_work(),
            Some(health_work(boundary))
        );
        resumed.advance(&reopened, FRAMES - boundary, &cx)?;
        let mut actual = resumed.finish(&reopened, &cx)?;
        same_native(&actual, &expected)?;
        let finding = actual
            .health_summary()
            .ok_or("missing health summary")?
            .findings()
            .iter()
            .find(|run| run.finding == HealthFinding::ExactFrameRepetition)
            .ok_or("missing frozen-frame finding")?;
        assert_eq!(finding.last_segment, (FRAMES - 1) as u64);
        if boundary == 127 {
            assert!(finding.first_segment < boundary as u64);
            assert!(finding.last_segment >= boundary as u64);
        } else {
            assert!(finding.first_segment >= boundary as u64);
        }
        let approved = approvals(&actual);
        assert!(!approved.is_empty());
        assert!(matches!(
            actual.publish(&mut reopened, &approved, &cx),
            Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED))
        ));
        assert_eq!(snapshot(&reopened), before);
    }
    Ok(())
}

#[test]
fn screened_cold_continuation_keeps_exact_records_counters_and_idempotent_publication() -> Test {
    let mut f = Fixture::new("health-incremental-cold", Scene::Changing, false, false)?;
    let prepared = prepare(&f, LongDwellLimits::default(), false)?;
    let mut running = prepared.start()?;
    let prefix = running.advance(&f.deployment, 128, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let record = f.deployment.publisher().spool().read(pin.record_digest)?;
    let after_prefix = f.snapshot();
    assert_eq!(running.retain(&mut f.deployment, &f.cx)?, pin);
    assert_eq!(f.snapshot(), after_prefix);
    drop(running);
    drop(prepared);
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let cx = context(&root)?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let saved = RetainedDwellCheckpoint::open(&reopened, pin, &restore_limits(), &cx)?;
    let mut resumed = saved.resume(&reopened, &restore_limits(), &cx)?;
    assert_eq!(resumed.work(), prefix);
    assert_eq!(resumed.health_work(), Some(health_work(128)));
    assert_eq!(resumed.restoration_health_work(), Some(health_work(128)));
    assert_eq!(resumed.retain(&mut reopened, &cx)?, pin);
    assert_eq!(snapshot(&reopened), after_prefix);
    resumed.advance(&reopened, 172, &cx)?;
    assert_eq!(resumed.health_work(), Some(health_work(FRAMES)));
    assert_eq!(resumed.restoration_work(), prefix);
    assert_eq!(resumed.restoration_health_work(), Some(health_work(128)));
    let complete_pin = resumed.retain(&mut reopened, &cx)?;
    assert_ne!(pin, complete_pin);
    assert_eq!(
        reopened.publisher().spool().read(pin.record_digest)?,
        record
    );
    assert_eq!(
        reopened.publisher().spool().read(health_policy_digest())?,
        health_policy_bytes()
    );
    let before_analysis = snapshot(&reopened);
    let expected = LongDwellReport::analyze_screened(
        &reopened,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &cx,
    )?;
    let mut actual = resumed.finish(&reopened, &cx)?;
    same_native(&actual, &expected)?;
    assert_eq!(snapshot(&reopened), before_analysis);
    let approved = approvals(&actual);
    assert_eq!(actual.publish(&mut reopened, &approved, &cx)?, 1);
    let after_event = snapshot(&reopened);
    let complete = RetainedDwellCheckpoint::open(&reopened, complete_pin, &restore_limits(), &cx)?;
    assert_eq!(complete.prefix_health_work(), Some(health_work(FRAMES)));
    let retry = complete.resume(&reopened, &restore_limits(), &cx)?;
    assert!(retry.complete());
    assert_eq!(retry.restoration_health_work(), Some(health_work(FRAMES)));
    let mut report = retry.finish(&reopened, &cx)?;
    assert_eq!(report.analysis_digest(), expected.analysis_digest());
    assert_eq!(report.health_summary(), expected.health_summary());
    assert_eq!(report.publish(&mut reopened, &approved, &cx)?, 0);
    assert_eq!(snapshot(&reopened), after_event);
    assert_eq!(reopened.effects().operations().count(), 0);
    Ok(())
}

#[test]
fn decode_refusal_and_source_gap_at_the_cold_boundary_preserve_incomplete_health() -> Test {
    for (label, corrupt, gap) in [
        ("health-incremental-refusal", true, false),
        ("health-incremental-gap", false, true),
    ] {
        let mut f = Fixture::new(label, Scene::Changing, corrupt, gap)?;
        let prepared = prepare(&f, LongDwellLimits::default(), true)?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 150, &f.cx)?;
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        drop(running);
        drop(prepared);
        let expected = f.scan(true, true, &LongDwellLimits::default())?;
        let before = f.snapshot();
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(resumed.restoration_health_work(), Some(health_work(150)));
        resumed.advance(&f.deployment, 1, &f.cx)?;
        resumed.advance(&f.deployment, 149, &f.cx)?;
        assert_eq!(resumed.work().source_positions, FRAMES);
        let screened_frames = FRAMES - usize::from(corrupt);
        assert_eq!(resumed.health_work(), Some(health_work(screened_frames)));
        let mut actual = resumed.finish(&f.deployment, &f.cx)?;
        same_native(&actual, &expected)?;
        assert!(
            !actual
                .health_summary()
                .ok_or("missing health summary")?
                .complete()
        );
        if corrupt {
            assert_eq!(actual.refusals[0].first_segment, 150);
        }
        assert!(matches!(
            actual.publish(&mut f.deployment, &approvals(&expected), &f.cx),
            Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED))
        ));
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn screened_restore_cannot_refill_samples_and_cancelled_rows_leave_the_checkpoint_intact() -> Test {
    let mut f = Fixture::new("health-incremental-budget", Scene::Changing, false, false)?;
    let limits = LongDwellLimits {
        maximum_pixel_samples: health_work(100).samples_screened,
        ..LongDwellLimits::default()
    };
    let prepared = prepare(&f, limits, false)?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let after = f.snapshot();
    running.advance(&f.deployment, 36, &f.cx)?;
    assert_eq!(running.health_work(), Some(health_work(100)));
    assert!(matches!(
        running.advance(&f.deployment, 1, &f.cx),
        Err(WatchError::Limit)
    ));
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    assert_eq!(
        saved.prepared().limits().maximum_pixel_samples,
        limits.maximum_pixel_samples
    );
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.health_work(), Some(health_work(64)));
    assert_eq!(resumed.restoration_health_work(), Some(health_work(64)));
    resumed.advance(&f.deployment, 36, &f.cx)?;
    assert_eq!(resumed.health_work(), Some(health_work(100)));
    assert!(matches!(
        resumed.advance(&f.deployment, 1, &f.cx),
        Err(WatchError::Limit)
    ));
    assert!(resumed.retain(&mut f.deployment, &f.cx).is_err());
    assert_eq!(f.snapshot(), after);

    let interrupted = context(f.deployment.root())?;
    interrupted.set_cancel_at_checkpoint_occurrence("sensor_health:row", 40);
    assert!(
        saved
            .resume(&f.deployment, &restore_limits(), &interrupted)
            .is_err()
    );
    assert!(interrupted.is_drain_completed());
    assert_eq!(f.snapshot(), after);
    let retry = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(retry.health_work(), Some(health_work(64)));
    assert_eq!(f.snapshot(), after);
    Ok(())
}

#[test]
fn screened_checkpoint_source_policy_and_privacy_damage_never_repair_cached_custody() -> Test {
    for (label, remove_source, corrupt_policy, positions) in [
        ("health-incremental-source-missing", true, false, 64),
        ("health-incremental-policy-missing", false, false, 64),
        ("health-incremental-policy-corrupt", false, true, 64),
        ("health-incremental-policy-later-prefix", false, false, 65),
        ("health-incremental-policy-at-finish", false, false, FRAMES),
    ] {
        let mut f = Fixture::new(label, Scene::Changing, false, false)?;
        let prepared = prepare(&f, LongDwellLimits::default(), false)?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 64, &f.cx)?;
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        if positions > 64 {
            running.advance(&f.deployment, positions - 64, &f.cx)?;
        }
        let damaged = if remove_source {
            let source = RetainedFileImport::open(
                &f.deployment,
                f.plan.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )?;
            source.manifest().ordered_chunks[0]
        } else {
            health_policy_digest()
        };
        let path = f.deployment.publisher().spool().object_path(damaged);
        if corrupt_policy {
            fs::write(&path, b"damaged retained health policy")?;
        } else {
            fs::remove_file(&path)?;
        }
        let before = f.snapshot();
        let denied = context(f.deployment.root())?;
        denied.set_cancel_at_checkpoint("long_dwell:decoded");
        assert!(
            RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &denied).is_err()
        );
        assert!(
            saved
                .resume(&f.deployment, &restore_limits(), &denied)
                .is_err()
        );
        assert!(!denied.is_cancelled());
        // A later prefix has a new target. It cannot recreate policy bytes which an earlier
        // checkpoint already retained, even though the policy is compiled into this process.
        assert!(running.retain(&mut f.deployment, &f.cx).is_err());
        if !remove_source {
            if positions == FRAMES {
                assert!(running.complete());
                assert!(running.finish(&f.deployment, &denied).is_err());
            } else {
                let work = running.work();
                let screened = running.health_work();
                assert!(running.advance(&f.deployment, 1, &denied).is_err());
                assert_eq!(running.work(), work);
                assert_eq!(running.health_work(), screened);
            }
            assert!(!denied.is_cancelled());
        }
        if corrupt_policy {
            assert_eq!(fs::read(&path)?, b"damaged retained health policy");
        } else {
            assert!(!path.exists());
        }
        assert_eq!(f.snapshot(), before);
    }

    let mut f = Fixture::new("health-incremental-privacy", Scene::Changing, false, false)?;
    let prepared = prepare(&f, LongDwellLimits::default(), false)?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    f.mask()?;
    let before = f.snapshot();
    let denied = context(f.deployment.root())?;
    denied.set_cancel_at_checkpoint("long_dwell:decoded");
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &denied).is_err());
    assert!(
        saved
            .resume(&f.deployment, &restore_limits(), &denied)
            .is_err()
    );
    assert!(!denied.is_cancelled());
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn unscreened_v1_and_screened_v2_checkpoints_recover_through_distinct_native_domains() -> Test {
    let mut f = Fixture::new("health-incremental-versions", Scene::Changing, false, false)?;
    let plain = PreparedIncrementalDwell::new(
        &f.deployment,
        f.plan.clone(),
        rule(),
        WatchOptions::default(),
        LongDwellLimits::default(),
        &f.cx,
    )?;
    let screened = prepare(&f, LongDwellLimits::default(), false)?;
    assert!(!plain.screened());
    assert!(screened.screened());
    assert_ne!(plain.request_digest()?, screened.request_digest()?);
    for (prepared, domain, kind, recipe, health) in [
        (
            &plain,
            CHECKPOINT_DOMAIN,
            CHECKPOINT_MANIFEST_KIND,
            "fss.incremental-dwell.recipe.v1",
            None,
        ),
        (
            &screened,
            CHECKPOINT_DOMAIN_V2,
            CHECKPOINT_MANIFEST_KIND_V2,
            "fss.incremental-dwell.recipe.v2",
            Some(health_work(64)),
        ),
    ] {
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 64, &f.cx)?;
        assert_eq!(running.health_work(), health);
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let bytes = f.deployment.publisher().spool().read(pin.record_digest)?;
        let mut decoder = CanonicalDecoder::new(&bytes);
        assert_eq!(decoder.text()?, domain);
        let mut recipe_decoder = CanonicalDecoder::new(decoder.bytes()?);
        assert_eq!(recipe_decoder.text()?, recipe);
        let manifest = f.deployment.publisher().spool().read(pin.provenance_root)?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest)?;
        assert_eq!(manifest.kind(), kind);
        assert_eq!(
            manifest.children().contains(&health_policy_digest()),
            health.is_some()
        );
        drop(running);
        let expected = f.scan(health.is_some(), false, &LongDwellLimits::default())?;
        let before = f.snapshot();
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        assert_eq!(saved.prefix_health_work(), health);
        let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(resumed.restoration_health_work(), health);
        resumed.advance(&f.deployment, FRAMES - 64, &f.cx)?;
        same_native(&resumed.finish(&f.deployment, &f.cx)?, &expected)?;
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}
