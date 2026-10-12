#![forbid(unsafe_code)]
//! Later-page admission and recovery regressions over the same real native publication fixture.

use super::*;
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIoCall};
use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
use fss_reference::reference_deployment::DeploymentLimits;
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
use fss_reference::rtsp::recording_catalog::MAX_CATALOG_BYTES;
use std::sync::Arc;

fn attempt(
    fixture: &mut PagesFixture,
    work: &mut WorkBudget<'_>,
) -> Result<RtspCatalogPagesImportReceipt, RtspImportError> {
    import_rtsp_catalog_pages(
        fixture.inner.source.as_ref().expect("source fixture"),
        fixture.inner.target.as_mut().expect("target fixture"),
        &fixture.request,
        &Owner(Cell::new(true)),
        &fixture.inner.cx,
        work,
    )
}

fn bytes_under(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn collect(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                collect(root, &path, files)?;
            } else {
                assert!(entry.file_type()?.is_file(), "unexpected fixture link");
                files.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(&path)?);
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files)?;
    Ok(files)
}

fn target_bytes(fixture: &PagesFixture) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    bytes_under(fixture.inner.target()?.root())
}

fn recorded_source(fixture: &mut PagesFixture) -> Test<Arc<RecordingSpoolIo>> {
    drop(fixture.inner.source.take());
    let io = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    fixture.inner.source = Some(LocalRootPublisher::open_with_io(
        fixture.inner.directory.0.join("archive"),
        archive_limits(),
        io.clone(),
    )?);
    io.clear();
    Ok(io)
}

fn later_page_objects(fixture: &PagesFixture) -> Test<[ContentDigest; 2]> {
    let root = fixture.request.pages[1].root;
    let manifest = ObjectManifest::from_canonical_bytes(
        fixture
            .inner
            .originals
            .get(&root)
            .ok_or("later catalog root")?,
    )?;
    Ok([
        root,
        manifest.metadata_digest().ok_or("later catalog index")?,
    ])
}

#[test]
fn complete_page_pins_and_cumulative_limits_refuse_without_a_partial_import() -> Test {
    // The first page fits every reduced bound. Only the second page exceeds the whole selection.
    let mut fixture = PagesFixture::avc("pages-admission", [1, 2], 2, 0, false)?;
    let original = fixture.request.clone();
    let before = target_bytes(&fixture)?;
    for case in 0..11 {
        fixture.request = original.clone();
        match case {
            0 => fixture.request.max_pages = 1,
            1 => fixture.request.max_windows = 2,
            2 => fixture.request.max_frames = 5,
            3 => fixture.request.max_original_bytes = fixture.inner.original_bytes - 1,
            4 => fixture.request.max_media_bytes = fixture.inner.mp4.len() as u64 - 1,
            5 => fixture.request.pages[1] = fixture.request.pages[0].clone(),
            6 => fixture.request.pages[1].slot = fixture.request.pages[0].slot.clone(),
            7 => fixture.request.pages[1].root = fixture.request.pages[0].root,
            8 => fixture.request.pages.swap(0, 1),
            9 => fixture.request.pages[1].root = ContentDigest::sha256(b"stale second page"),
            _ => fixture.request.scope.decode_clock = ContentDigest::sha256(b"other decode clock"),
        }
        assert!(attempt(&mut fixture, &mut work()).is_err(), "case {case}");
        assert_eq!(target_bytes(&fixture)?, before, "case {case}");
    }
    fixture.request = original;
    let receipt = fixture.run()?;
    assert_eq!(receipt.pages, 2);
    assert_eq!(receipt.catalog.windows, 3);
    assert_eq!(receipt.catalog.import.frames, 6);
    Ok(())
}

#[test]
fn all_page_and_window_work_is_admitted_before_the_first_corresponding_read() -> Test {
    let mut fixture = PagesFixture::hevc("pages-work")?;
    let io = recorded_source(&mut fixture)?;
    let before = target_bytes(&fixture)?;
    let page_work = 2 * (MAX_RECORDING_BYTES as u64 + MAX_CATALOG_BYTES as u64);
    let window_work = 2 * (2 * MAX_RECORDING_BYTES as u64);

    let mut insufficient_pages = WorkBudget::new(page_work - 1);
    assert!(matches!(
        attempt(&mut fixture, &mut insufficient_pages),
        Err(RtspImportError::Source(detail)) if detail.contains("BudgetExhausted")
    ));
    assert_eq!(insufficient_pages.used(), 0);
    assert!(
        io.calls().is_empty(),
        "a page was read before the total page reservation"
    );
    assert_eq!(target_bytes(&fixture)?, before);

    io.clear();
    let mut insufficient_windows = WorkBudget::new(page_work + window_work - 1);
    assert!(matches!(
        attempt(&mut fixture, &mut insufficient_windows),
        Err(RtspImportError::Source(detail)) if detail.contains("BudgetExhausted")
    ));
    assert_eq!(insufficient_windows.used(), page_work);
    assert_eq!(
        io.call_count(SpoolIoCall::OpenRead),
        4,
        "only two catalog roots and indexes may be read"
    );
    assert!(io.is_read_only());
    assert_eq!(target_bytes(&fixture)?, before);

    // At the exact reservation boundary all native windows are read; the following MP4 scan
    // needs its own additional work and cannot borrow a fresh per-page allowance.
    io.clear();
    let mut native_only = WorkBudget::new(page_work + window_work);
    assert!(matches!(
        attempt(&mut fixture, &mut native_only),
        Err(RtspImportError::Source(detail)) if detail.contains("BudgetExhausted")
    ));
    assert_eq!(native_only.used(), page_work + window_work);
    assert_eq!(
        io.call_count(SpoolIoCall::OpenRead),
        14,
        "four catalog objects and ten native window objects"
    );
    assert!(io.is_read_only());
    assert_eq!(target_bytes(&fixture)?, before);
    assert_eq!(fixture.run()?.catalog.import.frames, 8);
    Ok(())
}

#[test]
fn missing_or_corrupt_later_page_metadata_cannot_publish_an_earlier_prefix() -> Test {
    for case in 0..4 {
        let mut fixture = PagesFixture::hevc(&format!("pages-source-{case}"))?;
        let object = later_page_objects(&fixture)?[case / 2];
        let path = fixture
            .inner
            .source
            .as_ref()
            .ok_or("source")?
            .spool()
            .object_path(object);
        let original = fs::read(&path)?;
        if case % 2 == 0 {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"corrupt later catalog envelope")?;
        }
        let before = target_bytes(&fixture)?;
        assert!(matches!(
            attempt(&mut fixture, &mut work()),
            Err(RtspImportError::Source(_))
        ));
        assert_eq!(target_bytes(&fixture)?, before);
        if case % 2 == 0 {
            assert!(!path.exists(), "import recreated a missing source object");
        } else {
            assert_eq!(fs::read(&path)?, b"corrupt later catalog envelope");
        }
        // Restore only this synthetic test fault to establish that the same otherwise admitted
        // request succeeds. Production import has no object-repair authority.
        fs::write(&path, original)?;
        assert_eq!(fixture.run()?.catalog.import.frames, 8);
    }
    Ok(())
}

#[test]
fn later_page_origin_damage_blocks_cold_replay_and_cannot_heal_from_the_archive() -> Test {
    for index in 0..2 {
        let mut fixture = PagesFixture::hevc(&format!("pages-cold-damage-{index}"))?;
        let receipt = fixture.run()?;
        let retained = fixture.inner.retained(&receipt.catalog)?;
        assert!(
            !retained
                .read_segment(
                    fixture.inner.target()?,
                    0,
                    RetainedReadLimits::default(),
                    &fixture.inner.cx,
                )?
                .is_empty()
        );
        let digest = later_page_objects(&fixture)?[index];
        let path = fixture
            .inner
            .target()?
            .publisher()
            .spool()
            .object_path(digest);
        fs::write(&path, b"damaged later-page original")?;
        let before = target_bytes(&fixture)?;
        assert!(
            retained
                .read_segment(
                    fixture.inner.target()?,
                    0,
                    RetainedReadLimits::default(),
                    &fixture.inner.cx,
                )
                .is_err()
        );
        assert!(
            retained
                .verify_source(
                    fixture.inner.target()?,
                    RetainedReadLimits::default(),
                    &fixture.inner.cx,
                )
                .is_err()
        );
        assert!(fixture.run().is_err());
        assert_eq!(target_bytes(&fixture)?, before);
        assert_eq!(fs::read(path)?, b"damaged later-page original");
    }
    Ok(())
}

#[test]
fn current_deletion_reaches_later_pages_and_fences_an_already_warm_sample_cache() -> Test {
    let mut fixture = PagesFixture::hevc("pages-current-delete")?;
    let receipt = fixture.run()?;
    let retained = fixture.inner.retained(&receipt.catalog)?;
    let mut cache = VerifiedChunkCache::default();
    assert!(
        !retained
            .read_segment_cached(
                fixture.inner.target()?,
                0,
                RetainedReadLimits::default(),
                &fixture.inner.cx,
                &mut cache,
            )?
            .is_empty()
    );
    let later = later_page_objects(&fixture)?;
    let plan = plan_deletion(
        fixture.inner.target()?,
        receipt.catalog.import.import_identity,
        &fixture.inner.cx,
    )?;
    for digest in later {
        assert!(plan.deletable.iter().any(|entry| entry.digest == digest));
    }
    let principal = fixture.inner.cx.io_authority().principal().to_owned();
    let deletion = commit_deletion(
        fixture.inner.target.as_mut().ok_or("target")?,
        plan.digest()?,
        plan.approval_digest(&principal)?,
        &principal,
        &fixture.inner.cx,
    )?;
    assert_eq!(deletion.outcome, CommitOutcome::Completed);
    for digest in later {
        assert!(
            fixture
                .inner
                .target()?
                .publisher()
                .tombstones()
                .any(|current| *current == digest)
        );
        assert!(
            !fixture
                .inner
                .target()?
                .publisher()
                .object_name_present(digest)
        );
    }
    let before = target_bytes(&fixture)?;
    assert!(
        retained
            .read_segment_cached(
                fixture.inner.target()?,
                0,
                RetainedReadLimits::default(),
                &fixture.inner.cx,
                &mut cache,
            )
            .is_err()
    );
    assert!(
        fixture.run().is_err(),
        "an available archive cannot resurrect deleted page custody"
    );
    assert_eq!(target_bytes(&fixture)?, before);
    Ok(())
}

#[test]
fn partial_page_import_preserves_visible_custody_and_resumes_only_the_exact_suffix() -> Test {
    let mut fixture = PagesFixture::hevc("pages-partial")?;
    let root = fixture.inner.directory.0.join("small-destination");
    drop(fixture.inner.target.take());
    fixture.inner.cx = context(&root)?;
    let limits = DeploymentLimits {
        manifest_children_max: 8,
        batch_entries_max: 64,
        ..DeploymentLimits::standard()
    };
    fixture.inner.target = Some(ReferenceDeployment::open_with_limits(
        &root,
        SITE,
        limits,
        &fixture.inner.cx,
    )?);
    fixture.inner.cx.set_cancel_at_checkpoint("file_parts:root");
    assert!(fixture.run().is_err());
    assert!(fixture.inner.target()?.publisher().visible_roots().count() > 0);
    let later_root = fixture.request.pages[1].root;
    let path = fixture
        .inner
        .target()?
        .publisher()
        .spool()
        .object_path(later_root);
    let original = fs::read(&path)?;
    fs::write(&path, b"damaged already-published page child")?;
    fixture.inner.cx = context(&root)?;
    let damaged = target_bytes(&fixture)?;
    assert!(fixture.run().is_err());
    assert_eq!(target_bytes(&fixture)?, damaged);
    assert_eq!(fs::read(&path)?, b"damaged already-published page child");

    // The test removes its own injected fault; production retry must never do this repair.
    fs::write(&path, original)?;
    let receipt = fixture.run()?;
    assert!(!receipt.catalog.import.reused);
    let anchor = fixture.inner.target()?.current_anchor().clone();
    let complete = target_bytes(&fixture)?;
    drop(fixture.inner.target.take());
    drop(fixture.inner.source.take());
    fixture.inner.cx = context(&root)?;
    fixture.inner.target = Some(ReferenceDeployment::open_with_limits(
        &root,
        SITE,
        limits,
        &fixture.inner.cx,
    )?);
    fixture.inner.source = Some(LocalRootPublisher::open(
        fixture.inner.directory.0.join("archive"),
        archive_limits(),
    )?);
    let retried = fixture.run()?;
    assert!(retried.catalog.import.reused);
    assert_eq!(
        retried.catalog.import.import_root,
        receipt.catalog.import.import_root
    );
    assert_eq!(retried.catalog.import.proof, receipt.catalog.import.proof);
    assert_eq!(fixture.inner.target()?.current_anchor(), &anchor);
    assert_eq!(target_bytes(&fixture)?, complete);
    Ok(())
}
