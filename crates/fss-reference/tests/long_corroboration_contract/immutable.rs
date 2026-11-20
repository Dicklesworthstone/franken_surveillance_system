#![forbid(unsafe_code)]
//! Whole-recording previews share immutable custody and never acquire the active writer.

use super::*;
use std::collections::BTreeMap;

use fss_reference::agent_orient::OrientLimits;
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};

fn read_limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 256 * 1024 * 1024,
        max_read_objects: 100_000,
    }
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
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

fn analyze(f: &Fixture, source: &dyn RetainedSource) -> Test<LongCorroborationReport> {
    Ok(LongCorroborationReport::analyze(
        source,
        &f.plan,
        CorroborationOptions {
            tolerate_decode_refusals: false,
        },
        &LongCorroborationLimits::default(),
        &CorroborationDependencies::default(),
        &f.cx,
    )?)
}

fn finish(
    report: &LongCorroborationReport,
    source: &ImmutableRetainedSource<'_>,
    cx: &ReplayCx,
) -> Test {
    report.revalidate_preview_sources(source, cx)?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok(())
}

#[test]
fn native_analysis_keeps_the_deployment_refusal_when_the_durable_head_changes() -> Test {
    let f = Fixture::new(
        "immutable-admission-error",
        &jpeg(None)?.repeat(12),
        "mjpeg",
    )?;
    let journal = f
        .deployment
        .root()
        .join(fss_reference::reference_deployment::RELATIVE_PATH_LEDGER);
    let mut bytes = fs::read(&journal)?;
    bytes.push(0);
    fs::write(&journal, bytes)?;
    let before = tree(f.deployment.root())?;
    assert!(matches!(
        LongCorroborationReport::analyze(
            &f.deployment,
            &f.plan,
            CorroborationOptions {
                tolerate_decode_refusals: false,
            },
            &LongCorroborationLimits::default(),
            &CorroborationDependencies::default(),
            &f.cx,
        ),
        Err(CorroborationError::Reference(_)),
    ));
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn live_writer_allows_full_recording_preview_and_native_recipe_replay_without_mutation() -> Test {
    let mut f = Fixture::new(
        "immutable-whole-recording",
        &scene(300, true, false, false)?,
        "mjpeg",
    )?;
    f.plan.zones[0].x = 28.0;
    let expected = f.analyze(false)?;
    let sequence = f.deployment.current_anchor().commit_sequence;
    let expected_json = expected.to_json(sequence, None)?;
    let before = tree(f.deployment.root())?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    let report = analyze(&f, &source)?;
    assert_eq!(report.to_json(sequence, None)?, expected_json);
    assert_eq!(report.analysis_digest(), expected.analysis_digest());
    assert_eq!(report.candidates().len(), 1);
    assert!(
        report
            .samples()
            .iter()
            .all(|sample| sample.entry_position > 128)
    );
    assert_eq!(
        report.candidates()[0].proposal_digest(),
        expected.candidates()[0].proposal_digest(),
    );
    assert_eq!(
        report
            .source_cameras()
            .map(|(_, root)| root)
            .collect::<Vec<_>>(),
        expected
            .source_cameras()
            .map(|(_, root)| root)
            .collect::<Vec<_>>(),
    );
    report.revalidate_derived_sources(&source, &f.cx)?;
    let recipe = LongCorroborationRecipe::new(
        &f.plan,
        CorroborationOptions {
            tolerate_decode_refusals: false,
        },
        &LongCorroborationLimits::default(),
        &CorroborationDependencies::default(),
        false,
    )?;
    let restored =
        LongCorroborationRecipe::from_retained_bytes(&recipe.to_bytes(), recipe.digest())?;
    let replayed = restored.analyze(&source, &f.cx)?;
    assert_eq!(replayed.to_json(sequence, None)?, expected_json);
    replayed.revalidate_derived_sources(&source, &f.cx)?;
    finish(&report, &source, &f.cx)?;
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn final_preview_checks_both_cameras_quiet_capsules_and_complete_sources_with_no_candidates() -> Test
{
    let f = Fixture::new("immutable-quiet-custody", &jpeg(None)?.repeat(40), "mjpeg")?;
    for camera in &f.plan.cameras {
        let retained = RetainedFileImport::open(
            &f.deployment,
            camera.import_identity,
            RetainedReadLimits::default(),
            &f.cx,
        )?;
        let capsule_object = format!(
            "object:capsule:{}",
            retained.manifest().segment_spans[1].capsule_id,
        );
        let capsule = f
            .deployment
            .ledger()
            .batches()
            .iter()
            .flat_map(|batch| &batch.deltas)
            .find(|delta| delta.object_id.as_str() == capsule_object)
            .ok_or("quiet capsule authority")?
            .payload_digest;
        let chunk = *retained
            .manifest()
            .ordered_chunks
            .last()
            .ok_or("source chunk")?;
        for digest in [capsule, chunk] {
            let source = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
            let report = analyze(&f, &source)?;
            assert!(report.candidates().is_empty());
            let path = f.deployment.publisher().spool().object_path(digest);
            let original = fs::read(&path)?;
            let mut damaged = original.clone();
            *damaged.last_mut().ok_or("empty retained object")? ^= 0x80;
            fs::write(&path, damaged)?;
            let before = tree(f.deployment.root())?;
            assert!(
                report.revalidate_preview_sources(&source, &f.cx).is_err(),
                "late {} custody change: {digest}",
                camera.name,
            );
            assert!(source.revalidate().is_err());
            assert_eq!(tree(f.deployment.root())?, before);
            fs::write(&path, original)?;
        }
    }
    Ok(())
}

#[test]
fn degraded_health_remains_visible_in_preview_but_cannot_authorize_derived_advice_or_publish()
-> Test {
    let mut f = Fixture::new("immutable-health", &jpeg(None)?.repeat(40), "mjpeg")?;
    let root = f.deployment.root().to_path_buf();
    let before = tree(&root)?;
    let source = ImmutableRetainedSource::open(&root, read_limits(), &f.cx)?;
    let mut report = LongCorroborationReport::analyze_screened(
        &source,
        &f.plan,
        CorroborationOptions {
            tolerate_decode_refusals: false,
        },
        &LongCorroborationLimits::default(),
        &CorroborationDependencies::default(),
        &f.cx,
    )?;
    assert!(report.publication_blocked());
    let json = report.to_json(source.current_anchor().commit_sequence, None)?;
    assert!(json.contains("\"status\":\"suspected_degradation\""));
    assert_eq!(report.health_diagnostics().count(), 2);
    finish(&report, &source, &f.cx)?;
    assert!(matches!(
        report.revalidate_derived_sources(&source, &f.cx),
        Err(CorroborationError::InvalidPlan(
            fss_reference::ingest::recorded_corroboration::streaming::HEALTH_PUBLICATION_BLOCKED
        )),
    ));
    assert!(
        report
            .publish(&mut f.deployment, &BTreeSet::new(), &f.cx)
            .is_err()
    );
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn preview_delivery_shares_the_original_aggregate_read_allowance() -> Test {
    let f = Fixture::new(
        "immutable-budget",
        &scene(40, false, false, false)?,
        "mjpeg",
    )?;
    let before = tree(f.deployment.root())?;
    let measured = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    let report = analyze(&f, &measured)?;
    let analyzed = measured.usage();
    finish(&report, &measured, &f.cx)?;
    let total = measured.usage();
    assert!(total.read_bytes > analyzed.read_bytes);
    assert!(total.read_objects > analyzed.read_objects);
    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(total.read_bytes)?,
        max_read_objects: usize::try_from(total.read_objects)?,
        ..read_limits()
    };
    let admitted = ImmutableRetainedSource::open(f.deployment.root(), exact, &f.cx)?;
    let report = analyze(&f, &admitted)?;
    finish(&report, &admitted, &f.cx)?;
    assert_eq!(admitted.usage(), total);
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
        let source = ImmutableRetainedSource::open(f.deployment.root(), short, &f.cx)?;
        let report = analyze(&f, &source)?;
        assert_eq!(source.usage(), analyzed);
        assert!(finish(&report, &source, &f.cx).is_err());
        assert!(
            source.revalidate().is_err(),
            "delivery refilled a refused owner"
        );
    }
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn late_privacy_changes_and_final_cancellation_refuse_a_buffered_preview() -> Test {
    let mut f = Fixture::new(
        "immutable-privacy",
        &scene(40, false, false, false)?,
        "mjpeg",
    )?;
    let root = f.deployment.root().to_path_buf();
    let source = ImmutableRetainedSource::open(&root, read_limits(), &f.cx)?;
    let report = analyze(&f, &source)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-corroboration-west")?,
        [48, 32],
        &[[40, 0, 4, 4]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = tree(&root)?;
    assert!(report.revalidate_preview_sources(&source, &f.cx).is_err());
    assert!(source.revalidate().is_err());
    assert_eq!(tree(&root)?, before);

    let f = Fixture::new(
        "immutable-final-cancel",
        &scene(40, false, false, false)?,
        "mjpeg",
    )?;
    let before = tree(f.deployment.root())?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    let report = analyze(&f, &source)?;
    f.cx.set_cancel_at_checkpoint("long_corroboration:preview_sources_checked");
    assert!(report.revalidate_preview_sources(&source, &f.cx).is_err());
    assert!(f.cx.is_cancelled());
    assert!(source.revalidate().is_err());
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}
