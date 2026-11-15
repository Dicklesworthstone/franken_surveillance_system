#![forbid(unsafe_code)]
//! Immutable aggregate custody while the recorder owns its writer, including the final read.

use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn read_limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 256 * 1024 * 1024,
        max_read_objects: 100_000,
    }
}

// Include directories and exact bytes, so even an empty recovery/cache/lock entry is a change.
pub(super) fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
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

fn retained_fixture(label: &str) -> Test<(Fixture, RetainedLongSentinel)> {
    let mut f = Fixture::new(label, &JPEG.repeat(3), "mjpeg")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let report = run_long_sentinel_detection(
        &f.deployment,
        &package,
        &f.request,
        config(3, 1, 1),
        &LongSentinelLimits::default(),
        &f.cx,
        &scalar,
    )?;
    let retained =
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)?;
    scalar.drain_and_finalize();
    Ok((f, retained))
}

#[test]
fn live_writer_allows_exact_inspection_and_jpeg_replay_without_mutation() -> Test {
    let (f, retained) = retained_fixture("immutable-jpeg")?;
    let before = snapshot(f.deployment.root())?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    let restored = RetainedLongSentinel::open(
        &source,
        retained.report_digest(),
        &LongSentinelReplayLimits::default(),
        &f.cx,
    )?;
    assert_eq!(restored.root(), retained.root());
    assert_eq!(restored.recipe_digest(), retained.recipe_digest());
    assert_eq!(restored.report_json(), retained.report_json());
    assert_eq!(restored.child_reports(), retained.child_reports());
    assert_eq!(restored.authority_anchor(), retained.authority_anchor());
    assert!(restored.replay_compatible());
    let scalar = ScalarExecCx::new();
    let replayed = rerun_long_sentinel_detection(
        &source,
        retained.report_digest(),
        &LongSentinelReplayLimits::default(),
        &f.cx,
        &scalar,
    )?;
    assert_eq!(replayed.json().as_bytes(), retained.report_json());
    assert_eq!(replayed.digest(), retained.report_digest());
    source.revalidate()?;
    assert!(source.usage().read_bytes > PACKAGE.len() as u64);
    assert_eq!(snapshot(f.deployment.root())?, before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn final_read_shares_exact_original_byte_and_attempt_allowances_without_refill() -> Test {
    let (f, retained) = retained_fixture("immutable-budget")?;
    let before = snapshot(f.deployment.root())?;
    let inspect = |source: &ImmutableRetainedSource<'_>| {
        RetainedLongSentinel::open(
            source,
            retained.report_digest(),
            &LongSentinelReplayLimits::default(),
            &f.cx,
        )
    };
    let measured = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    inspect(&measured)?;
    measured.revalidate()?;
    let used = measured.usage();
    let exact = ImmutableRetainedReadLimits {
        // The final empty effect-journal probe consumes an attempt but no extra byte.
        max_read_bytes: usize::try_from(used.read_bytes)?,
        max_read_objects: usize::try_from(used.read_objects)?,
        ..read_limits()
    };
    let admitted = ImmutableRetainedSource::open(f.deployment.root(), exact, &f.cx)?;
    inspect(&admitted)?;
    admitted.revalidate()?;
    assert_eq!(admitted.usage(), used);
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
        inspect(&source)?;
        assert!(source.revalidate().is_err());
        assert!(
            source.revalidate().is_err(),
            "retry replenished the exhausted allowance"
        );
        assert!(inspect(&source).is_err());
    }
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn corrupt_missing_and_late_changed_selected_custody_are_refused_without_repair() -> Test {
    let (f, retained) = retained_fixture("immutable-corrupt")?;
    for digest in [
        retained.report_digest(),
        retained.recipe_digest(),
        retained.package_digest(),
        retained.root(),
        retained.child_reports()[0],
        f.late_chunk()?,
    ] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let original = fs::read(&path)?;
        for missing in [false, true] {
            let source = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
            RetainedLongSentinel::open(
                &source,
                retained.report_digest(),
                &LongSentinelReplayLimits::default(),
                &f.cx,
            )?;
            if missing {
                fs::remove_file(&path)?;
            } else {
                let mut changed = original.clone();
                changed[0] ^= 1;
                fs::write(&path, changed)?;
            }
            let before = snapshot(f.deployment.root())?;
            assert!(
                source.revalidate().is_err(),
                "late change: {digest}, {missing}"
            );
            let fresh = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
            assert!(
                RetainedLongSentinel::open(
                    &fresh,
                    retained.report_digest(),
                    &LongSentinelReplayLimits::default(),
                    &f.cx,
                )
                .is_err(),
                "changed custody: {digest}, {missing}",
            );
            assert_eq!(snapshot(f.deployment.root())?, before);
            fs::write(&path, &original)?;
        }
    }
    Ok(())
}

#[test]
fn final_read_refuses_changed_publication_child_count() -> Test {
    let (f, retained) = retained_fixture("immutable-publication")?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    RetainedLongSentinel::open(
        &source,
        retained.report_digest(),
        &LongSentinelReplayLimits::default(),
        &f.cx,
    )?;
    let slot = fss_publication::SlotName::parse(&format!(
        "ls-{}",
        retained
            .report_digest()
            .to_text()
            .trim_start_matches("sha256:")
    ))?;
    let published = f
        .deployment
        .publisher()
        .root(&slot)
        .ok_or("sentinel root")?;
    fs::write(
        f.deployment
            .root()
            .join("objects/roots")
            .join(format!("{slot}.root")),
        fss_publication::root_record_bytes(&slot, published.root, published.child_count + 1)?,
    )?;
    let before = snapshot(f.deployment.root())?;
    assert!(source.revalidate().is_err());
    let fresh = ImmutableRetainedSource::open(f.deployment.root(), read_limits(), &f.cx)?;
    assert!(
        RetainedLongSentinel::open(
            &fresh,
            retained.report_digest(),
            &LongSentinelReplayLimits::default(),
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(snapshot(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn live_privacy_change_and_cancelled_owner_cannot_release_saved_coordinates() -> Test {
    let (mut f, retained) = retained_fixture("immutable-privacy")?;
    let root = f.deployment.root().to_path_buf();
    let source = ImmutableRetainedSource::open(&root, read_limits(), &f.cx)?;
    RetainedLongSentinel::open(
        &source,
        retained.report_digest(),
        &LongSentinelReplayLimits::default(),
        &f.cx,
    )?;
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let cancellable =
        ImmutableRetainedSource::open_cancellable(&root, read_limits(), &f.cx, &probe)?;
    let admitted = cancellable.usage();
    cancelled.store(true, Ordering::SeqCst);
    assert!(
        RetainedLongSentinel::open(
            &cancellable,
            retained.report_digest(),
            &LongSentinelReplayLimits::default(),
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(cancellable.usage(), admitted);
    cancelled.store(false, Ordering::SeqCst);
    assert!(
        cancellable.revalidate().is_err(),
        "cancelled owner was renewed"
    );

    let mask = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [64, 48], &[[0, 0, 64, 1]])?;
    let approval = preview_mask(&f.deployment, &mask)?.approval;
    declare_mask(&mut f.deployment, &mask, approval, &f.cx)?;
    let before = snapshot(&root)?;
    assert!(source.revalidate().is_err());
    let fresh = ImmutableRetainedSource::open(&root, read_limits(), &f.cx)?;
    assert!(
        RetainedLongSentinel::open(
            &fresh,
            retained.report_digest(),
            &LongSentinelReplayLimits::default(),
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}
