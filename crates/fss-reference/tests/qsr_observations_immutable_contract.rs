#![forbid(unsafe_code)]
//! Immutable QSR reconstruction through the existing native source and health owners.

mod qsr_observations_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{EffectState, OperationId, TimestampNs};
use fss_reference::ReferenceDeployment;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::FileIngestError;
use fss_reference::ingest::qsr_observations::{QsrObservationReport, QsrZoneRole};
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};
use qsr_observations_support::{Fixture, SITE, Test, config, context};

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 64 * 1024 * 1024,
        max_read_objects: 65_536,
    }
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn walk(
        root: &Path,
        directory: &Path,
        entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>,
    ) -> Test {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                entries.insert(relative, None);
                walk(root, &path, entries)?;
            } else {
                entries.insert(relative, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries)?;
    Ok(entries)
}

#[test]
fn immutable_qsr_matches_native_output_while_writer_lock_is_held_without_any_store_changes() -> Test
{
    let fixture = Fixture::new("qsr-immutable-held-writer")?;
    let cx = context(&fixture.source.root)?;
    let writer = ReferenceDeployment::open(&fixture.source.root, SITE, &cx)?;
    let temporary = fixture
        .source
        .root
        .join("LAYOUT.tmp.immutable-must-preserve");
    fs::write(&temporary, b"local recovery must not run")?;
    let before = tree(&fixture.source.root)?;
    let source = ImmutableRetainedSource::open(&fixture.source.root, limits(), &cx)?;
    let report = QsrObservationReport::open_retained(&source, fixture.report, config(), &cx)?;
    assert_eq!(report.encoded(), fixture.expected_bytes);
    assert_eq!(report.to_json()?, fixture.expected_json);
    let used_before_final = source.usage();
    source.revalidate()?;
    assert!(source.usage().read_bytes > used_before_final.read_bytes);
    assert!(source.usage().read_objects > used_before_final.read_objects);
    assert_eq!(source.current_anchor(), writer.current_anchor());
    assert_eq!(tree(&fixture.source.root)?, before);
    drop(source);
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn immutable_qsr_preserves_unresolved_effects_and_final_work_cannot_refill_its_allowance() -> Test {
    let fixture = Fixture::new("qsr-immutable-allowance")?;
    let before = tree(&fixture.source.root)?;
    let cx = context(&fixture.source.root)?;
    let complete = ImmutableRetainedSource::open(&fixture.source.root, limits(), &cx)?;
    let report = QsrObservationReport::open_retained(&complete, fixture.report, config(), &cx)?;
    assert_eq!(report.to_json()?, fixture.expected_json);
    complete.revalidate()?;
    let total = complete.usage();
    drop(complete);

    let mut tight = limits();
    tight.max_read_objects =
        usize::try_from(total.read_objects.checked_sub(1).ok_or("read usage")?)?;
    let source = ImmutableRetainedSource::open(&fixture.source.root, tight, &cx)?;
    QsrObservationReport::open_retained(&source, fixture.report, config(), &cx)?;
    assert!(
        source.revalidate().is_err(),
        "final authority read must share the same allowance"
    );
    assert!(
        source.read_object(fixture.report).is_err(),
        "exhaustion permanently poisons the owner"
    );
    assert!(
        source.revalidate().is_err(),
        "a retry cannot replenish source authority"
    );
    assert_eq!(tree(&fixture.source.root)?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cancellation_after_complete_qsr_derivation_refuses_final_delivery_and_poisons_the_owner() -> Test
{
    let fixture = Fixture::new("qsr-immutable-cancel")?;
    let before = tree(&fixture.source.root)?;
    let cx = context(&fixture.source.root)?;
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let source =
        ImmutableRetainedSource::open_cancellable(&fixture.source.root, limits(), &cx, &probe)?;
    QsrObservationReport::open_retained(&source, fixture.report, config(), &cx)?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(matches!(
        source.revalidate(),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    cancelled.store(false, Ordering::SeqCst);
    assert!(source.read_object(fixture.report).is_err());
    assert_eq!(tree(&fixture.source.root)?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn changed_original_source_bytes_refuse_immutable_qsr_without_repair() -> Test {
    let fixture = Fixture::new("qsr-immutable-original-custody")?;
    let mut corrupt = fs::read(&fixture.source.chunk)?;
    *corrupt.last_mut().ok_or("source bytes")? ^= 1;
    fs::write(&fixture.source.chunk, &corrupt)?;
    let before = tree(&fixture.source.root)?;
    let cx = context(&fixture.source.root)?;
    let source = ImmutableRetainedSource::open(&fixture.source.root, limits(), &cx)?;
    assert!(QsrObservationReport::open_retained(&source, fixture.report, config(), &cx).is_err());
    assert_eq!(tree(&fixture.source.root)?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn concurrent_effect_head_change_refuses_a_fully_derived_immutable_report() -> Test {
    let fixture = Fixture::new("qsr-immutable-head-change")?;
    let cx = context(&fixture.source.root)?;
    let mut writer = ReferenceDeployment::open(&fixture.source.root, SITE, &cx)?;
    let source = ImmutableRetainedSource::open(&fixture.source.root, limits(), &cx)?;
    QsrObservationReport::open_retained(&source, fixture.report, config(), &cx)?;
    writer.effects_mut().transition(
        &OperationId::parse("operation:qsr-read:prepared")?,
        EffectState::Committed,
        TimestampNs(4),
        None,
        None,
    )?;
    let before_final = tree(&fixture.source.root)?;
    assert!(source.revalidate().is_err());
    assert_eq!(tree(&fixture.source.root)?, before_final);
    drop(source);
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn request_shape_rejects_role_conflicts_before_any_source_is_opened() {
    for role in [QsrZoneRole::Area, QsrZoneRole::Queue, QsrZoneRole::Register] {
        let mut request = config();
        request.zone_roles[0].role = role;
        request.lane_stages = vec!["image".into(), "next".into()];
        assert!(request.validate_shape().is_err());
    }
    let mut request = config();
    request.zone_roles[0].role = QsrZoneRole::LaneStage;
    assert!(request.validate_shape().is_err());
    request.lane_stages = vec!["image".into(), "next".into()];
    assert!(request.validate_shape().is_ok());
}
