#![forbid(unsafe_code)]
//! Derivative-only expiry, preserving sources and exercising the existing deletion protocol.

use super::*;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::review_expiry::{
    REVIEW_EXPIRY_SELECTION_DOMAIN, ReviewExpiryDisposition, ReviewExpiryRequest,
    STAGE_REVIEW_EXPIRY_READ, assess_review_expiry, commit_review_expiry,
};
use fss_reference::deletion::{
    CommitOutcome, DELETION_CUT_POINTS, DELETION_REVIEW_EXPIRY_COMPLETION_DOMAIN,
    DELETION_REVIEW_EXPIRY_PLAN_DOMAIN, DeletionCompletion, DeletionIndex, DeletionPlan,
    plan_scope_deletion,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::review_media::review_grant_revoked;

fn expiry_request(first: i128, last: i128) -> TestResult<ReviewExpiryRequest> {
    Ok(ReviewExpiryRequest::new(
        SensorId::parse(SENSOR)?,
        now(first, last)?,
    )?)
}

fn hold(f: &mut Fixture, state: HoldState) -> TestResult {
    let a = authority(
        OWNER,
        &[CAP_HOLD_PREPARE, CAP_HOLD_COMMIT],
        1024 * 1024 * 1024,
    )?;
    let cx = ReplayCx::from_context_authority(&a, f.root.clone())?;
    let request = HoldRequest {
        hold_id: "hold:review-expiry".into(),
        import_identity: f.source.import_identity,
        state,
        reason: "Owner preserves original evidence and its review derivatives".into(),
    };
    let prepared = preview_hold(&f.deployment, &request, &a, &cx)?;
    commit_hold(
        &mut f.deployment,
        &request,
        prepared.record.approval(),
        &a,
        &cx,
    )?;
    Ok(())
}

fn source_readable(f: &Fixture) -> TestResult {
    let source = RetainedFileImport::open(
        &f.deployment,
        f.source.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    assert_eq!(
        source.verify_source(&f.deployment, RetainedReadLimits::default(), &f.cx)?,
        f.source.input_sha256
    );
    assert!(
        DeletionIndex::read(&f.deployment)?
            .import(f.source.import_identity)
            .is_none()
    );
    Ok(())
}

fn publish_later(f: &mut Fixture) -> TestResult<ReviewMediaRecord> {
    let mut request = f.request()?;
    request.access.expires_at = TimestampNs(200);
    request.access.purpose = "A separately approved review which is still live".into();
    let preview = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
    let record = preview.record().clone();
    commit_review_media(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.owner,
        &f.cx,
    )?;
    Ok(record)
}

#[test]
fn expiry_boundary_uncertainty_and_inventory_are_read_only() -> TestResult {
    let mut f = Fixture::new("review-expiry-time", "indexed_avc.mp4")?;
    let (_, record) = f.publish()?;
    let before = snapshot(&f.root)?;
    for (first, last, expected) in [
        (98, 99, ReviewExpiryDisposition::NotDue),
        (99, 100, ReviewExpiryDisposition::ExpiryUncertain),
        (99, 101, ReviewExpiryDisposition::ExpiryUncertain),
        (100, 100, ReviewExpiryDisposition::Expired),
        (100, 101, ReviewExpiryDisposition::Expired),
    ] {
        let assessment = assess_review_expiry(&f.deployment, &expiry_request(first, last)?, &f.cx)?;
        assert_eq!(
            assessment.selection.domain(),
            REVIEW_EXPIRY_SELECTION_DOMAIN
        );
        assert_eq!(assessment.selection.candidates().len(), 1);
        let candidate = &assessment.selection.candidates()[0];
        assert_eq!(candidate.root(), record.root());
        assert_eq!(candidate.record_digest(), record.digest());
        assert_eq!(candidate.import_identity(), f.source.import_identity);
        assert_eq!(candidate.expires_at(), TimestampNs(100));
        assert_eq!(candidate.disposition(), expected);
        assert_eq!(
            assessment.deletion.is_some(),
            expected == ReviewExpiryDisposition::Expired
        );
    }
    assert_eq!(snapshot(&f.root)?, before);
    let other = ReviewExpiryRequest::new(SensorId::parse("sensor:unrelated")?, now(100, 100)?)?;
    let assessment = assess_review_expiry(&f.deployment, &other, &f.cx)?;
    assert!(assessment.selection.candidates().is_empty());
    assert!(assessment.deletion.is_none());
    let invalid = CaptureInterval {
        earliest: TimestampNs(101),
        latest: TimestampNs(100),
    };
    assert!(ReviewExpiryRequest::new(SensorId::parse(SENSOR)?, invalid).is_err());
    let stop = ReplayCx::from_context_authority(&f.owner, f.root.clone())?;
    stop.set_cancel_at_checkpoint(STAGE_REVIEW_EXPIRY_READ);
    assert!(matches!(
        assess_review_expiry(&f.deployment, &expiry_request(100, 100)?, &stop),
        Err(DeletionError::Cancelled {
            stage: STAGE_REVIEW_EXPIRY_READ
        })
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn expiry_removes_derivatives_preserves_source_and_keeps_owner_provenance() -> TestResult {
    let mut f = Fixture::new("review-expiry-provenance", "indexed_avc.mp4")?;
    let (_, record) = f.publish()?;
    // An unheld full-source copy is still an ancestor named by review provenance. The
    // derivative walk must not follow that outgoing reference and treat it as review media.
    let source_bytes = fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../fss-container/tests/fixtures/indexed_avc.mp4"),
    )?;
    assert_eq!(
        f.deployment.stage_payload(&source_bytes)?,
        f.source.input_sha256
    );
    let request = expiry_request(100, 100)?;
    let plan = assess_review_expiry(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("missing expiry plan")?;
    assert_eq!(plan.domain(), DELETION_REVIEW_EXPIRY_PLAN_DOMAIN);
    assert!(plan.imports.is_empty());
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(
        plan.units
            .iter()
            .all(|unit| !unit.id.starts_with("batch:file-import:")
                && !unit.id.starts_with("slot:fi-"))
    );
    assert!(
        plan.deletable
            .iter()
            .any(|object| object.digest == record.media_digest())
    );
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == record.digest())
    );
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == f.source.input_sha256)
    );
    assert!(
        plan.retained
            .iter()
            .any(|object| object.digest == record.digest()
                && object.reason == "review_expiry_audit_metadata")
    );
    assert!(
        plan.unknown_copies
            .iter()
            .any(|finding| finding.kind == "delivered_review_copies")
    );
    let digest = plan.digest()?;
    assert_eq!(
        DeletionPlan::decode(&plan.canonical_bytes()?, digest)?,
        plan
    );
    assert_eq!(
        plan_scope_deletion(&f.deployment, &plan.scope, &f.cx)?,
        plan
    );
    let complete = commit_review_expiry(
        &mut f.deployment,
        &request,
        digest,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    assert_eq!(complete.outcome, CommitOutcome::Completed);
    assert_eq!(
        complete.completion.domain(),
        DELETION_REVIEW_EXPIRY_COMPLETION_DOMAIN
    );
    assert_eq!(
        DeletionCompletion::decode(
            &complete.completion.canonical_bytes()?,
            complete.completion_digest
        )?,
        complete.completion
    );
    assert!(complete.completion.imports.is_empty());
    for digest in [
        record.root(),
        record.media_digest(),
        record.render_receipt_digest(),
    ] {
        assert!(
            !f.deployment
                .publisher()
                .spool()
                .object_path(digest)
                .exists(),
            "still present: {digest}"
        );
    }
    assert!(
        f.deployment
            .publisher()
            .spool()
            .object_path(record.digest())
            .exists()
    );
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(f.source.input_sha256)?,
        source_bytes
    );
    source_readable(&f)?;
    f = f.cold_reopen()?;
    assert_eq!(
        inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx)?,
        record
    );
    assert!(!review_grant_revoked(
        &f.deployment,
        record.root(),
        &f.owner,
        &f.cx
    )?);
    assert!(
        DeletionIndex::read(&f.deployment)?
            .review(record.root())
            .is_some_and(|entry| entry.is_complete())
    );
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    // Even an earlier asserted reader time cannot resurrect the durable deletion.
    assert!(matches!(
        read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::Deleted)
    ));
    let after = snapshot(&f.root)?;
    let next = assess_review_expiry(&f.deployment, &request, &f.cx)?;
    assert!(next.selection.candidates().is_empty());
    assert!(next.deletion.is_none());
    assert_eq!(snapshot(&f.root)?, after);
    source_readable(&f)?;
    Ok(())
}

#[test]
fn live_sibling_preserves_shared_media_then_later_expiry_reclaims_it() -> TestResult {
    let mut f = Fixture::new("review-expiry-shared", "indexed_avc.mp4")?;
    let (_, old) = f.publish()?;
    let live = publish_later(&mut f)?;
    assert_ne!(live.root(), old.root());
    assert_eq!(live.media_digest(), old.media_digest());
    let first = expiry_request(100, 101)?;
    let assessment = assess_review_expiry(&f.deployment, &first, &f.cx)?;
    assert_eq!(assessment.selection.roots(), vec![old.root()]);
    assert!(
        assessment
            .selection
            .candidates()
            .iter()
            .any(|candidate| candidate.root() == live.root()
                && candidate.disposition() == ReviewExpiryDisposition::NotDue)
    );
    let plan = assessment.deletion.ok_or("missing first expiry")?;
    assert!(
        plan.retained
            .iter()
            .any(|object| object.digest == old.media_digest())
    );
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == old.media_digest())
    );
    commit_review_expiry(
        &mut f.deployment,
        &first,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    assert_eq!(
        read_review_media(&f.deployment, live.root(), now(110, 111)?, &reader, &cx)?.media_digest(),
        live.media_digest()
    );
    source_readable(&f)?;
    let second = expiry_request(200, 200)?;
    let plan = assess_review_expiry(&f.deployment, &second, &f.cx)?
        .deletion
        .ok_or("missing second expiry")?;
    assert!(
        plan.deletable
            .iter()
            .any(|object| object.digest == live.media_digest())
    );
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == old.digest())
    );
    commit_review_expiry(
        &mut f.deployment,
        &second,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    f = f.cold_reopen()?;
    assert_eq!(
        inspect_review_media(&f.deployment, old.root(), &f.owner, &f.cx)?,
        old
    );
    assert_eq!(
        inspect_review_media(&f.deployment, live.root(), &f.owner, &f.cx)?,
        live
    );
    assert!(
        !f.deployment
            .publisher()
            .spool()
            .object_path(live.media_digest())
            .exists()
    );
    source_readable(&f)?;
    Ok(())
}

#[test]
fn source_hold_blocks_expiry_and_invalidates_an_earlier_approval() -> TestResult {
    let mut f = Fixture::new("review-expiry-hold", "indexed_avc.mp4")?;
    let (_, record) = f.publish()?;
    let request = expiry_request(100, 100)?;
    let plan = assess_review_expiry(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("missing plan")?;
    hold(&mut f, HoldState::Held)?;
    let before = snapshot(&f.root)?;
    assert!(matches!(
        commit_review_expiry(
            &mut f.deployment,
            &request,
            plan.digest()?,
            plan.approval_digest(OWNER)?,
            OWNER,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    let held = assess_review_expiry(&f.deployment, &request, &f.cx)?;
    assert!(held.deletion.is_none());
    let candidate = &held.selection.candidates()[0];
    assert_eq!(
        candidate.disposition(),
        ReviewExpiryDisposition::ClosureBlocked
    );
    assert!(
        candidate
            .blockers()
            .iter()
            .any(|finding| finding.kind == "evidence_hold")
    );
    assert!(candidate.closure_witness().is_some());
    assert_eq!(snapshot(&f.root)?, before);
    hold(&mut f, HoldState::Released)?;
    let plan = assess_review_expiry(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("release did not restore eligibility")?;
    commit_review_expiry(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    assert!(
        DeletionIndex::read(&f.deployment)?
            .review(record.root())
            .is_some()
    );
    source_readable(&f)?;
    Ok(())
}

#[test]
fn held_review_does_not_prevent_an_independent_expired_review_cleanup() -> TestResult {
    let mut f = Fixture::new("review-expiry-independent", "indexed_avc.mp4")?;
    let (_, held) = f.publish()?;
    let input = f._directory.0.join("independent.mp4");
    fs::write(
        &input,
        fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../fss-container/tests/fixtures/indexed_avc.mp4"),
        )?,
    )?;
    let source = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &input,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:independent-review")?,
        )
        .with_receive_time(TimestampNs(2_000_000_000)),
        &f.cx,
        &mut f.deployment,
    )?;
    fs::remove_file(input)?;
    assert_ne!(source.import_identity, f.source.import_identity);
    let mut request = f.request()?;
    request.movie.import_identity = source.import_identity;
    request.access.import_identity = source.import_identity;
    request.access.import_root = source.import_root;
    let preview = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
    let independent = preview.record().clone();
    commit_review_media(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.owner,
        &f.cx,
    )?;
    hold(&mut f, HoldState::Held)?;
    let request = expiry_request(100, 100)?;
    let assessed = assess_review_expiry(&f.deployment, &request, &f.cx)?;
    assert_eq!(assessed.selection.roots(), vec![independent.root()]);
    let excluded = assessed
        .selection
        .candidates()
        .iter()
        .find(|candidate| candidate.root() == held.root())
        .ok_or("held review omitted from complete inventory")?;
    assert_eq!(
        excluded.disposition(),
        ReviewExpiryDisposition::ClosureBlocked
    );
    assert!(excluded.closure_witness().is_some());
    let plan = assessed.deletion.ok_or("independent review was blocked")?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    commit_review_expiry(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    assert_eq!(
        read_review_media(&f.deployment, held.root(), now(20, 21)?, &reader, &cx)?.media_digest(),
        held.media_digest()
    );
    source_readable(&f)?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        source.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    assert_eq!(
        retained.verify_source(&f.deployment, RetainedReadLimits::default(), &f.cx)?,
        source.input_sha256
    );
    Ok(())
}

#[test]
fn exact_request_approval_and_selected_import_list_cannot_be_relabelled() -> TestResult {
    let mut f = Fixture::new("review-expiry-exact", "indexed_avc.mp4")?;
    f.publish()?;
    let request = expiry_request(100, 100)?;
    let plan = assess_review_expiry(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("missing plan")?;
    let digest = plan.digest()?;
    let approval = plan.approval_digest(OWNER)?;
    let before = snapshot(&f.root)?;
    assert!(matches!(
        commit_review_expiry(
            &mut f.deployment,
            &expiry_request(100, 101)?,
            digest,
            approval,
            OWNER,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert!(matches!(
        commit_review_expiry(
            &mut f.deployment,
            &request,
            digest,
            ContentDigest::sha256(b"wrong approval"),
            OWNER,
            &f.cx
        ),
        Err(DeletionError::ApprovalMismatch(_))
    ));
    let mut widened = plan.clone();
    widened.imports.push(f.source.import_identity);
    assert!(matches!(
        widened.canonical_bytes(),
        Err(DeletionError::RecordMismatch)
    ));
    let mut bytes = plan.canonical_bytes()?;
    replace_one(&mut bytes, b"fss.deletion_plan.v4", b"fss.deletion_plan.v3");
    assert!(DeletionPlan::decode(&bytes, ContentDigest::sha256(&bytes)).is_err());
    assert_eq!(snapshot(&f.root)?, before);
    commit_review_expiry(&mut f.deployment, &request, digest, approval, OWNER, &f.cx)?;
    let after = snapshot(&f.root)?;
    assert!(matches!(
        commit_review_expiry(
            &mut f.deployment,
            &expiry_request(100, 101)?,
            digest,
            approval,
            OWNER,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(&f.root)?, after);
    Ok(())
}

#[test]
fn every_deletion_cutpoint_resumes_exactly_and_keeps_source_bytes() -> TestResult {
    for (index, stage) in DELETION_CUT_POINTS.iter().enumerate() {
        let mut f = Fixture::new(&format!("review-expiry-cut-{index}"), "indexed_avc.mp4")?;
        let (_, record) = f.publish()?;
        let request = expiry_request(100, 100)?;
        let plan = assess_review_expiry(&f.deployment, &request, &f.cx)?
            .deletion
            .ok_or("missing plan")?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(OWNER)?;
        let stop = ReplayCx::from_context_authority(&f.owner, f.root.clone())?;
        stop.set_cancel_at_checkpoint(stage);
        assert!(
            matches!(commit_review_expiry(&mut f.deployment, &request, digest, approval, OWNER, &stop), Err(DeletionError::Cancelled { stage: actual }) if actual == *stage)
        );
        let committed = DeletionIndex::read(&f.deployment)?
            .review(record.root())
            .is_some();
        if committed {
            let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
            assert!(matches!(
                read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
                Err(ReviewMediaError::Deleted)
            ));
            assert_eq!(
                inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx)?,
                record
            );
        }
        f = f.cold_reopen()?;
        let complete =
            commit_review_expiry(&mut f.deployment, &request, digest, approval, OWNER, &f.cx)?;
        assert_eq!(
            complete.outcome,
            if committed {
                CommitOutcome::Resumed
            } else {
                CommitOutcome::Completed
            }
        );
        let after = snapshot(&f.root)?;
        let again =
            commit_review_expiry(&mut f.deployment, &request, digest, approval, OWNER, &f.cx)?;
        assert_eq!(again.outcome, CommitOutcome::AlreadyComplete);
        assert_eq!(snapshot(&f.root)?, after);
        assert_eq!(
            inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx)?,
            record
        );
        source_readable(&f)?;
    }
    Ok(())
}

#[test]
fn revoked_review_is_expired_without_losing_its_withdrawal_history() -> TestResult {
    let mut f = Fixture::new("review-expiry-withdrawn", "indexed_avc.mp4")?;
    let (_, record) = f.publish()?;
    let approval = revocation_approval(&f.deployment, record.root(), &f.owner, &f.cx)?;
    revoke_review_media(&mut f.deployment, record.root(), approval, &f.owner, &f.cx)?;
    let request = expiry_request(100, 100)?;
    let plan = assess_review_expiry(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("missing revoked expiry")?;
    commit_review_expiry(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    f = f.cold_reopen()?;
    assert_eq!(
        inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx)?,
        record
    );
    assert!(review_grant_revoked(
        &f.deployment,
        record.root(),
        &f.owner,
        &f.cx
    )?);
    source_readable(&f)?;
    Ok(())
}

#[test]
fn source_deleted_reviews_are_not_reopened_by_the_expiry_inventory() -> TestResult {
    let mut f = Fixture::new("review-expiry-source-deleted", "indexed_avc.mp4")?;
    f.publish()?;
    let plan = plan_deletion(&f.deployment, f.source.import_identity, &f.cx)?;
    commit_deletion(
        &mut f.deployment,
        plan.digest()?,
        plan.approval_digest(OWNER)?,
        OWNER,
        &f.cx,
    )?;
    f = f.cold_reopen()?;
    let assessment = assess_review_expiry(&f.deployment, &expiry_request(100, 100)?, &f.cx)?;
    assert!(assessment.selection.candidates().is_empty());
    assert!(assessment.deletion.is_none());
    Ok(())
}
