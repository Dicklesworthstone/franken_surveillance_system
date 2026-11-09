#![forbid(unsafe_code)]
//! No stale, incomplete, unauthorized or underpriced selection becomes successful retention.

use super::*;

#[test]
fn invalid_whole_selection_bounds_refuse_before_metadata_io_and_unknowns_consume_every_quota()
-> Test {
    let f = session_fixture::Fixture::new("utc-bounds", &[Avc, Hevc], 2, 1, &[0])?;
    let destination = Destination::new("bounds")?;
    for value in [0, 33, 64] {
        let mut input = session_input(&f)?;
        if let RtspUtcQueryImportInput::Sessions { request, .. } = &mut input {
            request.recording.max_windows = value;
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(matches!(
            preview_rtsp_utc_query_import(
                &io,
                &destination.root,
                &f.root,
                &input,
                &settings(),
                &|| false
            ),
            Err(RtspQueryImportError::Invalid(_))
        ));
        assert!(io.calls().is_empty());
    }
    let input = session_input(&f)?;
    let plan = preview(&destination, &f.root, &input)?;
    for variant in 0..4 {
        let mut input = input.clone();
        let mut limits = settings();
        match variant {
            0 => limits.max_original_bytes = plan.original_bytes() - 1,
            1 => limits.max_frames = plan.frames() - 1,
            2 => {
                limits.max_work = 3 * rtsp_import::MAX_ORIGINAL_BYTES * plan.windows().len() as u64
            }
            _ => {
                if let RtspUtcQueryImportInput::Sessions { request, .. } = &mut input {
                    request.recording.max_windows = 1;
                }
            }
        }
        assert!(
            preview_rtsp_utc_query_import(
                &HostSpoolIo,
                &destination.root,
                &f.root,
                &input,
                &limits,
                &|| false
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn current_approval_and_exact_reader_limits_refuse_before_any_native_payload_or_destination_write()
-> Test {
    let f = session_fixture::Fixture::new("utc-denied", &[Avc], 2, 1, &[0])?;
    retain_native_payloads(&f)?;
    let mut destination = Destination::new("denied")?;
    let plan = preview(&destination, &f.root, &session_input(&f)?)?;
    let before = integrity::snapshot(&destination.root)?;
    for refusal_mode in 0..3 {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let mut limits = plan.source_limits();
        if refusal_mode == 1 {
            limits.max_io_calls += 1;
        }
        let mut reader = PinnedClosureReader::new(&io, &f.root, limits, &|| false)?;
        let owner = Owner::new(&plan);
        if refusal_mode == 0 {
            owner.enabled.set(false);
        }
        let mut work = WorkBudget::new(settings().max_work);
        if refusal_mode == 2 {
            let required = 3 * rtsp_import::MAX_ORIGINAL_BYTES * plan.windows().len() as u64
                + plan.original_bytes();
            work.charge(settings().max_work - required + 1)?;
        }
        let result = import_rtsp_utc_query_pinned(
            &io,
            &mut reader,
            destination.owner.as_mut().ok_or("owner")?,
            &plan,
            &owner,
            &destination.cx,
            &mut work,
            &|| false,
        );
        let refusal = result.expect_err("current authority/allowance refusal");
        assert!(matches!(
            refusal.reason,
            RtspQueryImportError::Denied | RtspQueryImportError::Invalid(_)
        ));
        assert!(refusal.completed.is_empty());
        assert!(!refusal.current_import_may_be_durable);
        assert_eq!(io.call_count(SpoolIoCall::OpenRead), 0);
        assert_eq!(reader.usage().objects, 0);
        assert_eq!(integrity::snapshot(&destination.root)?, before);
    }
    Ok(())
}

#[test]
fn changed_clock_publication_and_selected_corruption_refuse_without_publishing_a_child() -> Test {
    for corrupt_payload in [false, true] {
        let f = session_fixture::Fixture::new("utc-changed", &[Avc], 2, 1, &[0])?;
        retain_native_payloads(&f)?;
        let mut destination = Destination::new("changed")?;
        let input = session_input(&f)?;
        let plan = preview(&destination, &f.root, &input)?;
        let before = integrity::snapshot(&destination.root)?;
        if corrupt_payload {
            // Keep all published metadata intact but damage one selected original packet object.
            let digest = f.sessions[0].windows[1].1.plan().children()[0].1;
            fs::write(f.object(digest), b"corrupt selected original")?;
        } else {
            fs::write(
                f.record(&f.request.sessions[0].clock_slot),
                b"changed clock publication",
            )?;
        }
        let (result, usage) = acquire(&mut destination, &plan)?;
        let refusal = result.expect_err("changed native source or clock");
        assert!(refusal.completed.is_empty());
        assert_eq!(refusal.next_window, 0);
        assert!(!refusal.current_import_may_be_durable);
        if !corrupt_payload {
            assert_eq!(usage.objects, 0);
        }
        assert_eq!(integrity::snapshot(&destination.root)?, before);
    }
    Ok(())
}

#[test]
fn partial_mixed_union_requires_fresh_approval_and_reuses_completed_native_identity() -> Test {
    let f = session_fixture::Fixture::new("utc-partial", &[Avc, Hevc], 2, 1, &[0])?;
    retain_native_payloads(&f)?;
    let mut destination = Destination::new("partial")?;
    let input = session_input(&f)?;
    let plan = preview(&destination, &f.root, &input)?;
    destination
        .cx
        .set_cancel_at_checkpoint_occurrence(STAGE_QUERY_WINDOW, 2);
    let (result, usage) = acquire(&mut destination, &plan)?;
    let refusal = result.expect_err("second candidate cancelled");
    assert_eq!(refusal.completed.len(), 1);
    assert_eq!(refusal.next_window, 1);
    assert!(!refusal.current_import_may_be_durable);
    assert_eq!(usage.completed_roots, 1);
    let first_identity = refusal.completed[0].import.import_identity;
    destination.cx = context(&destination.root)?;
    let before = integrity::snapshot(&destination.root)?;
    let (result, _) = acquire(&mut destination, &plan)?;
    assert!(matches!(
        result.expect_err("stale context approval").reason,
        RtspQueryImportError::StalePlan
    ));
    assert_eq!(integrity::snapshot(&destination.root)?, before);
    let fresh = preview(&destination, &f.root, &input)?;
    assert_ne!(plan.digest(), fresh.digest());
    assert!(!Owner::new(&plan).permit_open(&fresh));
    let (result, usage) = acquire(&mut destination, &fresh)?;
    let receipt = result?;
    assert_eq!(receipt.imports.len(), 2);
    assert_eq!(receipt.imports[0].import.import_identity, first_identity);
    assert!(receipt.imports[0].import.reused);
    assert!(!receipt.imports[1].import.reused);
    assert_eq!(usage.completed_roots, 2);
    assert!(receipt.work_used > 0);
    Ok(())
}

#[test]
fn approved_existing_wrapper_never_creates_a_missing_destination() -> Test {
    let f = session_fixture::Fixture::new("utc-no-create", &[Avc], 2, 1, &[0])?;
    retain_native_payloads(&f)?;
    let mut destination = Destination::new("missing")?;
    let plan = preview(&destination, &f.root, &session_input(&f)?)?;
    drop(destination.owner.take());
    let retired = destination.directory.0.join("retired");
    fs::rename(&destination.root, &retired)?;
    let before = integrity::snapshot(&destination.directory.0)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &f.root, plan.source_limits(), &|| false)?;
    let result = import_rtsp_utc_query_pinned_existing(
        &io,
        &mut reader,
        &plan,
        &Owner::new(&plan),
        &destination.cx,
        &mut WorkBudget::new(settings().max_work),
        &|| false,
    );
    assert!(matches!(
        result.expect_err("missing existing owner").reason,
        RtspQueryImportError::Destination(_)
    ));
    assert!(!destination.root.exists());
    assert_eq!(reader.usage().objects, 0);
    assert_eq!(integrity::snapshot(&destination.directory.0)?, before);
    Ok(())
}

#[test]
fn known_empty_interval_is_distinct_from_unknown_candidates_and_imports_no_source() -> Test {
    let f = session_fixture::Fixture::new("utc-empty", &[Avc, Hevc], 2, 1, &[0, 1])?;
    // Metadata-only fixture: successful empty acquisition cannot depend on source payloads.
    let mut destination = Destination::new("empty")?;
    let plan = preview(&destination, &f.root, &session_input(&f)?)?;
    assert!(plan.windows().is_empty());
    assert_eq!(plan.frames(), 0);
    assert_eq!(plan.original_bytes(), 0);
    let RtspUtcQueryImportObservation::Sessions(query) = plan.query() else {
        return Err("sessions".into());
    };
    assert_eq!(query.native.indexed_gaps, vec![0..1]);
    let before = integrity::snapshot(&destination.root)?;
    let (result, usage) = acquire(&mut destination, &plan)?;
    let receipt = result?;
    assert!(receipt.imports.is_empty());
    assert_eq!(receipt.work_used, 0);
    assert_eq!(usage.objects, 0);
    assert_eq!(usage.completed_roots, 0);
    assert_eq!(integrity::snapshot(&destination.root)?, before);
    Ok(())
}

#[test]
fn final_source_cancellation_returns_the_complete_durable_prefix_without_aggregate_success() -> Test
{
    let f = session_fixture::Fixture::new("utc-final-cancel", &[Avc, Hevc], 2, 1, &[0])?;
    retain_native_payloads(&f)?;
    let mut destination = Destination::new("final-cancel")?;
    let plan = preview(&destination, &f.root, &session_input(&f)?)?;
    destination.cx.set_cancel_at_checkpoint_occurrence(
        fss_reference::ingest::rtsp_import::query::STAGE_QUERY_FINALIZE,
        1,
    );
    let (result, usage) = acquire(&mut destination, &plan)?;
    let refusal = result.expect_err("final source observation cancelled");
    assert!(matches!(refusal.reason, RtspQueryImportError::Denied));
    assert_eq!(refusal.completed.len(), 2);
    assert_eq!(refusal.next_window, 2);
    assert!(!refusal.current_import_may_be_durable);
    assert_eq!(usage.completed_roots, 2);
    Ok(())
}
