#![forbid(unsafe_code)]
//! Full retained localization custody through one immutable owner, without native replay.

#[path = "twin_localization_query_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{ContentDigest, PrincipalId, SensorId};
use fss_geometry::WorkBudget;
use fss_publication::{LOCAL_ROOTS_DIR, ROOT_RECORD_SUFFIX, root_record_bytes};
use fss_reference::ReplayCx;
use fss_reference::agent_localizations::{
    LocalizationsQueryFilter, LocalizationsQueryLimits, LocalizationsQueryRequest,
    query_localizations,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::twin_localization::retained::{
    MAX_PACKAGE_BYTES, MAX_TWIN_BYTES, RetainedLocalization,
};
use fss_reference::ingest::twin_localization::{MAX_RECEIPT_BYTES, STAGE_LOCALIZATION_SOURCE};
use fss_reference::ingest::{FileIngestError, RetainedReadLimits};
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};
use fss_twin::atlas_archive::MAX_ATLAS_BYTES;
use support::{Fixture, PRINCIPAL, Record, Test, context};

const WORK_LIMIT: u64 = 2_000_000_000;

fn limits() -> ImmutableRetainedReadLimits {
    LocalizationsQueryLimits::default().read
}

fn inspect(
    source: &ImmutableRetainedSource<'_>,
    record: &Record,
    budget: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Test<RetainedLocalization> {
    Ok(RetainedLocalization::open(
        source,
        record.identity,
        RetainedReadLimits::default(),
        budget,
        cx,
    )?)
}

#[allow(clippy::result_large_err)]
fn finish(source: &ImmutableRetainedSource<'_>) -> Result<(), FileIngestError> {
    source.revalidate_snapshot_metadata()?;
    source.revalidate()
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let key = path.strip_prefix(root)?.to_owned();
        if metadata.is_dir() {
            result.insert(key, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(key, (false, fs::read(path)?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

#[test]
fn full_custody_opens_all_outcomes_with_a_live_writer_and_without_encoded_or_decoded_pixels() -> Test
{
    let fixture = Fixture::new("full-open-live-writer")?;
    let root = fixture.root();
    let mut media = BTreeSet::new();
    for record in &fixture.records {
        media.extend([record.source_blob, record.luma_blob]);
    }
    for digest in media {
        fs::remove_file(fixture.object_path(digest))?;
    }
    fs::write(
        root.join("LAYOUT.tmp.full-open-preserve"),
        b"no reader recovery",
    )?;
    let before = tree(root)?;
    let cx = context(root)?;
    // Entering native image processing would cancel this inspection. Missing source pixels
    // also prevent any accidental source decode from masquerading as successful inspection.
    cx.set_cancel_at_checkpoint(STAGE_LOCALIZATION_SOURCE);
    let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
    let mut budget = WorkBudget::new(WORK_LIMIT);
    for record in &fixture.records {
        let package = inspect(&source, record, &mut budget, &cx)?;
        assert_eq!(package.identity(), record.identity);
        assert_eq!(package.publication_root(), record.root);
        assert_eq!(package.receipt_digest(), record.receipt);
        assert_eq!(package.twin_digest(), record.twin_blob);
        assert_eq!(package.atlas_package(), record.atlas_blob);
        assert_eq!(package.source().import_identity(), record.import_identity);
        assert_eq!(package.source().segment(), 0);
        assert_eq!(
            ContentDigest::sha256(package.receipt_bytes()),
            record.receipt
        );
        let original_receipt = fixture
            .deployment
            .publisher()
            .spool()
            .read_bounded(record.receipt, MAX_RECEIPT_BYTES)?;
        assert_eq!(package.receipt_bytes(), original_receipt.as_slice());
    }
    let before_final = source.usage();
    finish(&source)?;
    assert!(source.usage().read_bytes > before_final.read_bytes);
    assert!(source.usage().read_objects > before_final.read_objects);
    assert!(
        !cx.is_cancelled(),
        "inspection entered native pixel execution"
    );
    assert!(budget.used() >= 3 * (MAX_TWIN_BYTES + MAX_ATLAS_BYTES) as u64);
    assert_eq!(tree(root)?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn missing_or_corrupt_archives_refuse_full_inspection_but_preserve_h0_discovery() -> Test {
    let fixture = Fixture::new("full-open-archive-custody")?;
    let root = fixture.root();
    let record = &fixture.records[0];
    let cx = context(root)?;
    let request = LocalizationsQueryRequest {
        filter: LocalizationsQueryFilter::default(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        max_entries: 16,
        expected_anchor: None,
        continuation: None,
    };
    let original = query_localizations(
        root,
        &request,
        LocalizationsQueryLimits::default(),
        &cx,
        &|| false,
    )?;
    for digest in [record.twin_blob, record.atlas_blob] {
        let path = fixture.object_path(digest);
        let bytes = fs::read(&path)?;
        for missing in [true, false] {
            if missing {
                fs::remove_file(&path)?;
            } else {
                let mut corrupted = bytes.clone();
                *corrupted.last_mut().ok_or("archive envelope")? ^= 1;
                fs::write(&path, corrupted)?;
            }
            let damaged = tree(root)?;
            let metadata = query_localizations(
                root,
                &request,
                LocalizationsQueryLimits::default(),
                &cx,
                &|| false,
            )?;
            assert_eq!(metadata.rows, original.rows);
            assert_eq!(metadata.decision_digest, original.decision_digest);
            let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
            assert!(inspect(&source, record, &mut WorkBudget::new(WORK_LIMIT), &cx).is_err());
            assert!(
                finish(&source).is_err(),
                "failed full custody allowance was reused"
            );
            assert_eq!(tree(root)?, damaged, "full inspection repaired an archive");
            drop(source);
            fs::write(&path, &bytes)?;
        }
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn complete_open_and_final_custody_use_exact_shared_io_and_conservative_work_allowances() -> Test {
    let fixture = Fixture::new("full-open-exact-budget")?;
    let root = fixture.root();
    let record = &fixture.records[0];
    let cx = context(root)?;
    let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
    let mut work = WorkBudget::new(WORK_LIMIT);
    inspect(&source, record, &mut work, &cx)?;
    let selected = source.usage();
    finish(&source)?;
    let total = source.usage();
    let reserved_work = work.used();
    assert_eq!(
        reserved_work,
        (2 * MAX_PACKAGE_BYTES + MAX_RECEIPT_BYTES + MAX_TWIN_BYTES + MAX_ATLAS_BYTES) as u64
    );
    assert!(total.read_bytes > selected.read_bytes + 1);
    assert!(total.read_objects > selected.read_objects + 1);
    drop(source);

    let mut exact = limits();
    exact.max_read_bytes = usize::try_from(total.read_bytes)?;
    exact.max_read_objects = usize::try_from(total.read_objects)?;
    let source = ImmutableRetainedSource::open(root, exact, &cx)?;
    let mut work = WorkBudget::new(reserved_work);
    inspect(&source, record, &mut work, &cx)?;
    finish(&source)?;
    assert_eq!(source.usage(), total);
    assert_eq!(work.remaining(), 0);
    assert!(
        inspect(&source, record, &mut work, &cx).is_err(),
        "repeated full open renewed work"
    );
    drop(source);

    for short_bytes in [true, false] {
        let mut short = exact;
        if short_bytes {
            short.max_read_bytes -= 1;
        } else {
            short.max_read_objects -= 1;
        }
        let source = ImmutableRetainedSource::open(root, short, &cx)?;
        inspect(&source, record, &mut WorkBudget::new(reserved_work), &cx)?;
        assert_eq!(source.usage(), selected);
        assert!(
            finish(&source).is_err(),
            "final custody renewed its I/O allowance"
        );
        assert!(
            source
                .read_object_bounded(record.receipt, MAX_RECEIPT_BYTES)
                .is_err()
        );
        assert!(source.revalidate().is_err());
    }
    let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
    assert!(
        inspect(
            &source,
            record,
            &mut WorkBudget::new(reserved_work - 1),
            &cx
        )
        .is_err()
    );
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn selected_archive_recipe_receipt_and_source_metadata_changes_refuse_final_release() -> Test {
    let fixture = Fixture::new("full-open-final-payload")?;
    let root = fixture.root();
    let record = &fixture.records[0];
    let cx = context(root)?;
    for digest in [
        record.identity,
        record.root,
        record.receipt,
        record.twin_blob,
        record.atlas_blob,
        record.capsule,
        record.source_manifest,
    ] {
        let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
        inspect(&source, record, &mut WorkBudget::new(WORK_LIMIT), &cx)?;
        let path = fixture.object_path(digest);
        let original = fs::read(&path)?;
        let mut changed = original.clone();
        *changed.last_mut().ok_or("retained payload")? ^= 1;
        fs::write(&path, changed)?;
        let damaged = tree(root)?;
        assert!(finish(&source).is_err(), "final custody ignored {digest}");
        assert_eq!(tree(root)?, damaged);
        drop(source);
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn validly_encoded_publication_child_count_changes_refuse_final_release() -> Test {
    let fixture = Fixture::new("full-open-final-publication")?;
    let root = fixture.root();
    let record = &fixture.records[0];
    let cx = context(root)?;
    let mut roots = vec![record.root, record.import_root];
    roots.extend(record.decode_root);
    for digest in roots {
        let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
        inspect(&source, record, &mut WorkBudget::new(WORK_LIMIT), &cx)?;
        let publisher = fixture.deployment.publisher();
        let visible = publisher
            .visible_roots()
            .find(|value| value.root == digest)
            .ok_or("native publication")?;
        let path = publisher
            .root_dir()
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{}{ROOT_RECORD_SUFFIX}", visible.slot));
        let original = fs::read(&path)?;
        let changed = root_record_bytes(&visible.slot, digest, visible.child_count + 1)?;
        assert_ne!(original, changed);
        fs::write(&path, changed)?;
        let damaged = tree(root)?;
        assert!(finish(&source).is_err(), "native publication count changed");
        assert_eq!(tree(root)?, damaged);
        drop(source);
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn authority_append_and_selected_privacy_change_invalidate_finished_inspection() -> Test {
    for selected_privacy in [false, true] {
        let mut fixture = Fixture::new(&format!("full-open-head-{selected_privacy}"))?;
        let root = fixture.root().to_path_buf();
        let record = fixture.records[0].clone();
        let cx = context(&root)?;
        let source = ImmutableRetainedSource::open(&root, limits(), &cx)?;
        inspect(&source, &record, &mut WorkBudget::new(WORK_LIMIT), &cx)?;
        let sensor = if selected_privacy {
            record.sensor_id.clone()
        } else {
            SensorId::parse("sensor:unrelated-full-open-reader")?
        };
        let policy = PrivacyMaskPolicy::new(sensor, [96, 96], &[[0, 0, 8, 8]])?;
        let approval = preview_mask(&fixture.deployment, &policy)?.approval;
        declare_mask(&mut fixture.deployment, &policy, approval, &fixture.cx)?;
        let changed = tree(&root)?;
        assert!(
            finish(&source).is_err(),
            "finished inspection accepted changed authority"
        );
        assert_eq!(tree(&root)?, changed);
        drop(source);
        let fresh = ImmutableRetainedSource::open(&root, limits(), &cx)?;
        let reopened = inspect(&fresh, &record, &mut WorkBudget::new(WORK_LIMIT), &cx);
        if selected_privacy {
            assert!(
                reopened.is_err(),
                "fresh inspection accepted an obsolete source mask"
            );
        } else {
            assert_eq!(reopened?.receipt_digest(), record.receipt);
            finish(&fresh)?;
        }
        assert_eq!(tree(&root)?, changed);
        drop(fresh);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn cancellation_during_open_or_the_last_live_read_prevents_finalization_without_repair() -> Test {
    let fixture = Fixture::new("full-open-cancellation")?;
    let root = fixture.root();
    let record = &fixture.records[0];
    let before = tree(root)?;
    for stage in [
        "recorded_localization:open",
        "recorded_localization:read_package",
        "recorded_localization:opened",
    ] {
        let cx = context(root)?;
        let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
        cx.set_cancel_at_checkpoint(stage);
        assert!(inspect(&source, record, &mut WorkBudget::new(WORK_LIMIT), &cx).is_err());
        assert!(finish(&source).is_err());
        assert_eq!(tree(root)?, before);
        drop(source);
        cx.drain_and_finalize();
    }
    let cx = context(root)?;
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let source = ImmutableRetainedSource::open_cancellable(root, limits(), &cx, &count)?;
    inspect(&source, record, &mut WorkBudget::new(WORK_LIMIT), &cx)?;
    let selected_calls = calls.load(Ordering::SeqCst);
    finish(&source)?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > selected_calls);
    drop(source);
    calls.store(0, Ordering::SeqCst);
    let fired = AtomicBool::new(false);
    let cancel_last = || {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == last {
            fired.store(true, Ordering::SeqCst);
        }
        fired.load(Ordering::SeqCst)
    };
    let source = ImmutableRetainedSource::open_cancellable(root, limits(), &cx, &cancel_last)?;
    inspect(&source, record, &mut WorkBudget::new(WORK_LIMIT), &cx)?;
    assert!(finish(&source).is_err());
    assert!(fired.load(Ordering::SeqCst));
    fired.store(false, Ordering::SeqCst);
    assert!(
        source
            .read_object_bounded(record.receipt, MAX_RECEIPT_BYTES)
            .is_err()
    );
    assert!(source.revalidate().is_err());
    assert_eq!(tree(root)?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn incomplete_authority_and_effect_journals_are_never_recovered_by_full_inspection() -> Test {
    let fixture = Fixture::new("full-open-journal-tails")?;
    let root = fixture.root();
    let cx = context(root)?;
    for journal in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let source = ImmutableRetainedSource::open(root, limits(), &cx)?;
        inspect(
            &source,
            &fixture.records[0],
            &mut WorkBudget::new(WORK_LIMIT),
            &cx,
        )?;
        let path = root.join(journal);
        let original = fs::read(&path)?;
        let mut incomplete = original.clone();
        incomplete.extend_from_slice(b"\x01\x02\x03");
        fs::write(&path, incomplete)?;
        let damaged = tree(root)?;
        assert!(
            finish(&source).is_err(),
            "final release ignored changed {journal}"
        );
        drop(source);
        assert!(ImmutableRetainedSource::open(root, limits(), &cx).is_err());
        assert_eq!(tree(root)?, damaged, "immutable open recovered {journal}");
        fs::write(path, original)?;
    }
    let absent = root.join("absent-immutable-inspection");
    let absent_cx = context(&absent)?;
    assert!(ImmutableRetainedSource::open(&absent, limits(), &absent_cx).is_err());
    assert!(!absent.exists());
    absent_cx.drain_and_finalize();
    cx.drain_and_finalize();
    Ok(())
}
