#![forbid(unsafe_code)]
//! Refusals preserve the destination, and late failures report durable uncertainty.

use super::*;

#[test]
fn aggregate_metadata_bounds_refuse_read_only_and_bind_approval() -> Test {
    let f = Fixture::avc("query-limits", 4, 0, false)?;
    let request = request(&f, 0..28_800)?;
    let baseline = preview(&f, 0..28_800)?;
    let before = integrity::snapshot(&f.directory.0)?;
    for kind in 0..3 {
        let mut settings = settings(&f);
        match kind {
            0 => settings.max_frames = baseline.frames() - 1,
            1 => settings.max_original_bytes = baseline.original_bytes() - 1,
            _ => settings.max_work = 2 * fss_reference::ingest::rtsp_import::MAX_ORIGINAL_BYTES - 1,
        }
        let refused = preview_rtsp_query_import(
            &HostSpoolIo,
            &f.directory.0.join("destination"),
            &f.directory.0.join("archive"),
            &request,
            &RecordingContextLimits::default(),
            &settings,
            &|| false,
        );
        assert!(matches!(refused, Err(RtspQueryImportError::Invalid(_))));
    }
    let mut changed = settings(&f);
    changed.max_media_bytes -= 1;
    let different = preview_rtsp_query_import(
        &HostSpoolIo,
        &f.directory.0.join("destination"),
        &f.directory.0.join("archive"),
        &request,
        &RecordingContextLimits::default(),
        &changed,
        &|| false,
    )?;
    assert_ne!(baseline.digest(), different.digest());
    assert_eq!(integrity::snapshot(&f.directory.0)?, before);
    Ok(())
}

#[test]
fn cumulative_media_bound_refuses_second_window_before_its_publication() -> Test {
    let mut f = Fixture::avc("query-media-bound", 4, 0, false)?;
    let first_media = f.initialization_bytes
        + f.originals
            .get(&f.original_fragments[0])
            .ok_or("first fragment")?
            .len();
    let second_media = f.initialization_bytes
        + f.originals
            .get(&f.original_fragments[1])
            .ok_or("second fragment")?
            .len();
    let mut settings = settings(&f);
    settings.max_media_bytes = u64::try_from(first_media + second_media - 1)?;
    let plan = preview_rtsp_query_import(
        &HostSpoolIo,
        &f.directory.0.join("destination"),
        &f.directory.0.join("archive"),
        &request(&f, 0..28_800)?,
        &RecordingContextLimits::default(),
        &settings,
        &|| false,
    )?;
    let refused = acquire(&mut f, &plan).expect_err("aggregate media exhausted");
    assert_eq!(refused.completed.len(), 1);
    assert_eq!(refused.next_window, 1);
    assert!(!refused.current_import_may_be_durable);
    assert!(
        !f.target()?
            .publisher()
            .spool()
            .digests()
            .any(|d| d == f.original_packs[1])
    );
    let retained = RetainedFileImport::open(
        f.target()?,
        refused.completed[0].import.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    assert_eq!(retained.manifest().segment_spans.len(), 4);
    Ok(())
}

struct RevokingOwner {
    calls: Cell<usize>,
}
impl RtspQueryImportAuthority for RevokingOwner {
    fn permit_open(&self, _: &RtspQueryImportPlan) -> bool {
        true
    }

    fn permit(&self, _: &RtspQueryImportPlan, _: &ReferenceDeployment) -> bool {
        let calls = self.calls.get() + 1;
        self.calls.set(calls);
        calls < 4
    }
}

#[test]
fn current_authority_is_rechecked_after_query_before_native_source_access() -> Test {
    let mut f = Fixture::avc("query-revocation", 4, 0, false)?;
    let plan = preview(&f, 0..1)?;
    let owner = RevokingOwner {
        calls: Cell::new(0),
    };
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let mut allowance = work();
    let refused = import_rtsp_query(
        &HostSpoolIo,
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("destination")?,
        &plan,
        &owner,
        &f.cx,
        &mut allowance,
        &|| false,
    )
    .expect_err("live authority revoked");
    assert_eq!(owner.calls.get(), 4);
    assert_eq!(allowance.used(), 0);
    assert!(refused.completed.is_empty());
    assert!(!refused.current_import_may_be_durable);
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn source_corruption_after_preview_refuses_before_destination_staging() -> Test {
    let mut f = Fixture::avc("query-selected-corrupt", 4, 0, false)?;
    let plan = preview(&f, 14_400..14_401)?;
    let pack = f
        .originals
        .get(&f.original_packs[1])
        .ok_or("selected original")?;
    let path = integrity::object_file(&f.directory.0.join("archive"), pack)?;
    fs::write(path, b"damaged selected original RTP")?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let refused = acquire(&mut f, &plan).expect_err("selected original source verification");
    assert!(refused.completed.is_empty());
    assert_eq!(refused.next_window, 0);
    assert!(!refused.current_import_may_be_durable);
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn refused_before_open_cannot_initialize_or_reconcile_a_missing_destination() -> Test {
    let mut f = Fixture::avc("query-existing-only", 4, 0, false)?;
    let plan = preview(&f, 0..1)?;
    drop(f.target.take());
    fs::rename(
        f.directory.0.join("destination"),
        f.directory.0.join("prior-destination"),
    )?;
    let denied = import_rtsp_query_existing(
        &HostSpoolIo,
        f.source.as_ref().ok_or("source")?,
        &plan,
        &Owner(Cell::new(false)),
        &f.cx,
        &mut work(),
        &|| false,
    )
    .expect_err("before-open permission");
    assert!(matches!(denied.reason, RtspQueryImportError::Denied));
    assert!(!f.directory.0.join("destination").exists());
    let missing = import_rtsp_query_existing(
        &HostSpoolIo,
        f.source.as_ref().ok_or("source")?,
        &plan,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
        &|| false,
    )
    .expect_err("existing deployment required");
    assert!(matches!(
        missing.reason,
        RtspQueryImportError::Destination(_)
    ));
    assert!(!f.directory.0.join("destination").exists());
    Ok(())
}

#[test]
fn late_publication_refusal_reports_current_durable_uncertainty() -> Test {
    let mut f = Fixture::avc("query-late-refusal", 4, 0, false)?;
    let plan = preview(&f, 0..1)?;
    f.cx.set_cancel_at_checkpoint("file_parts:root");
    let refused = acquire(&mut f, &plan).expect_err("late root boundary");
    assert!(refused.completed.is_empty());
    assert_eq!(refused.next_window, 0);
    assert!(refused.current_import_may_be_durable);
    Ok(())
}

#[test]
fn a_different_source_owner_and_excess_work_account_are_rejected_before_writes() -> Test {
    let mut f = Fixture::avc("query-owner-binding", 4, 0, false)?;
    let plan = preview(&f, 0..1)?;
    let other = LocalRootPublisher::open(f.directory.0.join("other-archive"), archive_limits())?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let refused = import_rtsp_query(
        &HostSpoolIo,
        &other,
        f.target.as_mut().ok_or("destination")?,
        &plan,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
        &|| false,
    )
    .expect_err("different opened archive owner");
    assert!(matches!(refused.reason, RtspQueryImportError::Invalid(_)));
    let mut excess = WorkBudget::new(settings(&f).max_work + 1);
    let refused = import_rtsp_query(
        &HostSpoolIo,
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("destination")?,
        &plan,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut excess,
        &|| false,
    )
    .expect_err("unapproved work account");
    assert!(matches!(refused.reason, RtspQueryImportError::Invalid(_)));
    assert_eq!(excess.used(), 0);
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn existing_wrapper_imports_without_reconciling_an_unrelated_pending_effect() -> Test {
    use fss_core::{EffectIntent, EffectState, IdempotencyKey, ObligationId};

    let mut f = Fixture::avc("query-pending-effect", 4, 0, false)?;
    let operation = OperationId::parse("operation:query:unrelated-alert")?;
    let journal = f.target.as_mut().ok_or("destination")?.effects_mut();
    journal.prepare(
        EffectIntent {
            operation_id: operation.clone(),
            idempotency_key: IdempotencyKey::parse("idempotency:query:unrelated-alert")?,
            effect_class: "alert.dispatch".to_owned(),
            request_digest: ContentDigest::sha256(b"unrelated alert request"),
            precondition_digest: ContentDigest::sha256(b"unrelated alert precondition"),
        },
        ObligationId::parse("obligation:query:unrelated-alert")?,
        "delivery_ack",
        TimestampNs(100),
    )?;
    journal.transition(
        &operation,
        EffectState::Committed,
        TimestampNs(110),
        None,
        None,
    )?;
    let effect_path = journal.path().to_path_buf();
    let before = fs::read(&effect_path)?;
    let plan = preview(&f, 0..1)?;
    drop(f.target.take());
    let result = import_rtsp_query_existing(
        &HostSpoolIo,
        f.source.as_ref().ok_or("source")?,
        &plan,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
        &|| false,
    )?;
    assert_eq!(result.imports.len(), 1);
    assert_eq!(result.frames, 4);
    // A normal deployment open reclassifies a committed alert without a provider record.
    // The acquisition wrapper must preserve that unrelated effect's exact durable history.
    assert_eq!(fs::read(effect_path)?, before);
    Ok(())
}
