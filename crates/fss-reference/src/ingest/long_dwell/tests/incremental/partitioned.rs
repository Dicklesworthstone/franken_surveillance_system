#![forbid(unsafe_code)]
//! Multipart native recordings retain their exact part custody across durable continuation.

use super::*;
use crate::ingest::long_dwell::incremental::{
    CHECKPOINT_MANIFEST_KIND_V4, MAX_SOURCE_CLOSURE_BYTES, SOURCE_CLOSURE_DOMAIN,
};

fn fixture(label: &str, bytes: &[u8], inter: bool, part_width: usize) -> Test<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("source.media");
    fs::write(&path, bytes)?;
    let cx = context(&root, "principal:long-dwell-test")?;
    let mut deployment = ReferenceDeployment::open_with_limits(
        &root,
        SITE,
        crate::DeploymentLimits {
            manifest_children_max: part_width,
            ..crate::DeploymentLimits::standard()
        },
        &cx,
    )?;
    let mut limits = FileIngestLimits::standard();
    limits.max_segments = FRAMES + 1;
    limits.chunk_bytes = 4096;
    let receipt = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &path,
            SensorId::parse("sensor:long-dwell")?,
            StreamId::parse("stream:long-dwell")?,
        )
        .with_limits(limits)
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    fs::remove_file(path)?;
    let retained = RetainedFileImport::open(
        &deployment,
        receipt.import_identity,
        RetainedReadLimits::default(),
        &cx,
    )?;
    assert!(retained.manifest().part_roots.len() > 1);
    Ok(Fixture {
        deployment,
        cx,
        plan: WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: if inter {
                ComponentInterpretation::YCbCr
            } else {
                ComponentInterpretation::Grayscale
            },
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
        input_bytes: bytes.len() as u64,
        _directory: directory,
    })
}

fn inventory(f: &Fixture) -> Test<(RetainedFileImport, ContentDigest, Vec<u8>)> {
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.plan.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let mut e = CanonicalEncoder::new();
    e.text(SOURCE_CLOSURE_DOMAIN);
    e.digest(retained.import_identity());
    e.digest(retained.import_root());
    e.digest(retained.manifest_digest());
    e.u64(retained.manifest().part_roots.len() as u64);
    for part in &retained.manifest().part_roots {
        e.digest(*part);
    }
    let bytes = e.finish_checked()?;
    assert!(bytes.len() <= MAX_SOURCE_CLOSURE_BYTES);
    Ok((retained, ContentDigest::sha256(&bytes), bytes))
}

#[test]
fn partitioned_mjpeg_cold_resume_preserves_exact_report_and_health_work() -> Test {
    for screened in [false, true] {
        let mut f = fixture(
            "incremental-multipart-cold",
            &scene(true, None, None, false)?,
            false,
            64,
        )?;
        let expected = if screened {
            LongDwellReport::analyze_screened(
                &f.deployment,
                &f.plan,
                rule(),
                WatchOptions::default(),
                &LongDwellLimits::default(),
                &f.cx,
            )?
        } else {
            f.analyze(rule())?
        };
        let prepared = if screened {
            PreparedIncrementalDwell::new_screened(
                &f.deployment,
                f.plan.clone(),
                rule(),
                WatchOptions::default(),
                LongDwellLimits::default(),
                &f.cx,
            )?
        } else {
            prepare(&f, LongDwellLimits::default(), WatchOptions::default())?
        };
        let mut running = prepared.start()?;
        let prefix = running.advance(&f.deployment, 127, &f.cx)?;
        let health = running.health_work();
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let (source, closure, bytes) = inventory(&f)?;
        assert_eq!(f.deployment.publisher().spool().read(closure)?, bytes);
        let manifest = ObjectManifest::from_canonical_bytes(
            &f.deployment.publisher().spool().read(pin.provenance_root)?,
        )?;
        assert_eq!(manifest.kind(), CHECKPOINT_MANIFEST_KIND_V4);
        assert!(manifest.children().len() <= 6);
        assert!(manifest.children().contains(&closure));
        assert!(manifest.children().contains(&source.import_root()));
        for part in &source.manifest().part_roots {
            assert!(!manifest.children().contains(part));
        }
        let after = f.snapshot();
        assert_eq!(running.retain(&mut f.deployment, &f.cx)?, pin);
        assert_eq!(f.snapshot(), after);
        drop(running);
        drop(prepared);
        let root = f.deployment.root().to_path_buf();
        let limits = *f.deployment.limits();
        drop(f.deployment);
        let cx = context(&root, "principal:long-dwell-test")?;
        let mut deployment = ReferenceDeployment::open_with_limits(&root, SITE, limits, &cx)?;
        let saved = RetainedDwellCheckpoint::open(&deployment, pin, &restore_limits(), &cx)?;
        let mut resumed = saved.resume(&deployment, &restore_limits(), &cx)?;
        assert_eq!(resumed.work(), prefix);
        assert_eq!(resumed.restoration_work(), prefix);
        assert_eq!(resumed.health_work(), health);
        assert_eq!(resumed.restoration_health_work(), health);
        while !resumed.complete() {
            resumed.advance(&deployment, 71, &cx)?;
        }
        resumed.retain(&mut deployment, &cx)?;
        let actual = resumed.finish(&deployment, &cx)?;
        same_report(&actual, &expected);
        assert_eq!(actual.health_summary(), expected.health_summary());
    }
    Ok(())
}

#[test]
fn partitioned_avc_cold_resume_keeps_delayed_native_output_after_coding_eof() -> Test {
    let mut f = fixture("incremental-multipart-avc", SQUARE_MP4, true, 64)?;
    let expected = f.analyze(rule())?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    let prefix = running.advance(&f.deployment, FRAMES - 1, &f.cx)?;
    assert_eq!(prefix.source_positions, FRAMES);
    assert_eq!(prefix.frames_decoded, FRAMES - 1);
    assert!(!running.complete());
    let progress = running.video_progress().ok_or("video progress")?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    drop(running);
    drop(prepared);
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    assert_eq!(saved.video_progress(), Some(&progress));
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.work(), prefix);
    let complete = resumed.advance(&f.deployment, 1, &f.cx)?;
    assert_eq!(complete.source_positions, FRAMES);
    assert_eq!(complete.frames_decoded, FRAMES);
    assert!(resumed.complete());
    same_report(&resumed.finish(&f.deployment, &f.cx)?, &expected);
    Ok(())
}

#[test]
fn partitioned_hevc_continuation_keeps_native_codec_and_source_identity() -> Test {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4"
    ));
    let mut f = fixture("incremental-multipart-hevc", bytes, true, 8)?;
    f.plan.segment_count = 14;
    f.plan.zones[0].width = 96;
    f.plan.zones[0].height = 48;
    let rule = DwellPolicy {
        minimum_duration_ns: 1,
        maximum_sample_gap_ns: 1_000_000_000,
        minimum_observations: 3,
    };
    let expected = f.analyze(rule)?;
    let prepared = PreparedIncrementalDwell::new(
        &f.deployment,
        f.plan.clone(),
        rule,
        WatchOptions::default(),
        LongDwellLimits::default(),
        &f.cx,
    )?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 5, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    while !resumed.complete() {
        resumed.advance(&f.deployment, 3, &f.cx)?;
    }
    assert_eq!(
        resumed.video_progress().ok_or("video progress")?.codec,
        "h265"
    );
    same_report(&resumed.finish(&f.deployment, &f.cx)?, &expected);
    Ok(())
}

#[test]
fn partitioned_resume_does_not_join_holes_misses_or_tolerated_decode_refusals() -> Test {
    for bytes in [
        scene(true, Some(150), None, false)?,
        scene(true, None, Some(150), false)?,
        scene(true, None, None, true)?,
    ] {
        let mut f = fixture("incremental-multipart-break", &bytes, false, 64)?;
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
        assert!(expected.candidates().is_empty());
        let prepared = prepare(&f, LongDwellLimits::default(), options)?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 150, &f.cx)?;
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        resumed.advance(&f.deployment, 1, &f.cx)?;
        resumed.advance(&f.deployment, 149, &f.cx)?;
        same_report(&resumed.finish(&f.deployment, &f.cx)?, &expected);
    }
    Ok(())
}

#[test]
fn missing_inventory_or_part_refuses_cold_and_cached_owners_without_repair() -> Test {
    for remove_part in [false, true] {
        let mut f = fixture(
            "incremental-multipart-missing",
            &scene(true, None, None, false)?,
            false,
            64,
        )?;
        let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 64, &f.cx)?;
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let (source, closure, _) = inventory(&f)?;
        let missing = if remove_part {
            source.manifest().part_roots[0]
        } else {
            closure
        };
        let path = f.deployment.publisher().spool().object_path(missing);
        fs::remove_file(&path)?;
        let after = f.snapshot();
        let denied = context(f.deployment.root(), "principal:long-dwell-test")?;
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
        assert!(running.retain(&mut f.deployment, &f.cx).is_err());
        assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
        assert!(!path.exists());
        assert_eq!(f.snapshot(), after);
    }
    Ok(())
}

#[test]
fn partitioned_continuation_checks_original_authority_and_never_refills_work() -> Test {
    let mut f = fixture(
        "incremental-multipart-authority-budget",
        &scene(true, None, None, false)?,
        false,
        64,
    )?;
    let limits = LongDwellLimits {
        maximum_pixel_samples: u64::from(WIDTH * HEIGHT) * 100,
        ..LongDwellLimits::default()
    };
    let prepared = prepare(&f, limits, WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let before = f.snapshot();
    let other = context(f.deployment.root(), "principal:another-actor")?;
    other.set_cancel_at_checkpoint("incremental_dwell:verify_source_closure");
    assert!(matches!(
        running.retain(&mut f.deployment, &other),
        Err(WatchError::Conflict)
    ));
    assert!(matches!(
        saved.resume(&f.deployment, &restore_limits(), &other),
        Err(WatchError::Conflict)
    ));
    // Scope refusal precedes any read of the retained private part inventory.
    assert!(!other.is_cancelled());
    assert!(matches!(
        running.advance(&f.deployment, 64, &f.cx),
        Err(WatchError::Limit)
    ));
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.work().source_positions, 64);
    assert!(matches!(
        resumed.advance(&f.deployment, 64, &f.cx),
        Err(WatchError::Limit)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn reordered_inventory_cannot_replace_the_imports_exact_part_custody() -> Test {
    let mut f = fixture(
        "incremental-multipart-forged",
        &scene(true, None, None, false)?,
        false,
        64,
    )?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let (source, original_closure, mut bytes) = inventory(&f)?;
    // Publish a self-consistent replacement: same original import, different ordered part
    // inventory, matching recipe digest, body address and native manifest. The retained
    // source reader is the authority; matching attacker-controlled hashes is insufficient.
    let parts = &source.manifest().part_roots;
    let start = bytes.len() - parts.len() * 33;
    let first = bytes[start..start + 33].to_vec();
    let second = bytes[start + 33..start + 66].to_vec();
    bytes[start..start + 33].copy_from_slice(&second);
    bytes[start + 33..start + 66].copy_from_slice(&first);
    let forged_closure = f.deployment.stage_payload(&bytes)?;
    let mut record = f.deployment.publisher().spool().read(pin.record_digest)?;
    let offsets: Vec<_> = record
        .windows(32)
        .enumerate()
        .filter_map(|(i, window)| (window == original_closure.bytes()).then_some(i))
        .collect();
    assert_eq!(offsets.len(), 1);
    record[offsets[0]..offsets[0] + 32].copy_from_slice(&forged_closure.bytes());
    let forged_record = f.deployment.stage_payload(&record)?;
    let original = ObjectManifest::from_canonical_bytes(
        &f.deployment.publisher().spool().read(pin.provenance_root)?,
    )?;
    let forged = ObjectManifest::new(
        original.kind(),
        original.children().iter().map(|digest| {
            if *digest == pin.record_digest {
                forged_record
            } else if *digest == original_closure {
                forged_closure
            } else {
                *digest
            }
        }),
        None,
    )?;
    let target = super::super::super::slot("ld-c", forged_record)?;
    super::super::super::publish_manifest(
        &mut f.deployment,
        &target,
        &forged,
        CaptureInterval::point(TimestampNs(0)),
        &f.cx,
    )?;
    let before = f.snapshot();
    assert!(
        RetainedDwellCheckpoint::open(
            &f.deployment,
            DwellCheckpointPin {
                record_digest: forged_record,
                provenance_root: forged.root()
            },
            &restore_limits(),
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn deletion_reaches_multipart_checkpoint_inventory_and_independent_part_roots() -> Test {
    let mut f = fixture(
        "incremental-multipart-delete",
        &scene(true, None, None, false)?,
        false,
        64,
    )?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let (source, closure, _) = inventory(&f)?;
    let plan = crate::deletion::plan_deletion(&f.deployment, f.plan.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [pin.record_digest, pin.provenance_root, closure]
        .into_iter()
        .chain(source.manifest().part_roots.iter().copied())
    {
        assert!(
            plan.deletable.iter().any(|object| object.digest == digest),
            "{digest}"
        );
    }
    crate::deletion::commit_deletion(
        &mut f.deployment,
        plan.digest()?,
        plan.approval_digest("principal:long-dwell-test")?,
        "principal:long-dwell-test",
        &f.cx,
    )?;
    for digest in [pin.record_digest, pin.provenance_root, closure] {
        assert!(
            !f.deployment
                .publisher()
                .spool()
                .object_path(digest)
                .exists()
        );
    }
    let after = f.snapshot();
    assert!(
        saved
            .resume(&f.deployment, &restore_limits(), &f.cx)
            .is_err()
    );
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert_eq!(f.snapshot(), after);
    Ok(())
}
