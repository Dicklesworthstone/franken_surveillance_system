#![forbid(unsafe_code)]
use super::*;
use std::fs;

#[path = "fixture.rs"]
mod fixture;
use fixture::{Fixture, TestResult, inventory};
use fss_core::{Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_publication::tombstone_record_bytes;

fn read(f: &Fixture) -> TestResult<DeploymentSnapshot> {
    Ok(read_deployment(&f.root, &OrientLimits::default())?)
}
fn checked(f: &Fixture) -> TestResult<CustodyReview> {
    Ok(check_event(&f.root, &read(f)?, &f.event.event_id, CustodyAuditLimits::default(), &|| false)?)
}
fn text(review: &CustodyReview) -> String {
    review.propositions().iter().map(|p| format!("{} {} {:?}", p.id, p.statement, p.evidence))
        .collect::<Vec<_>>().join("\n")
}

#[test]
fn real_slotless_current_event_has_stable_read_only_custody_observations() -> TestResult {
    let f = Fixture::new("intact")?;
    let before = inventory(&f.root)?;
    let result = checked(&f)?;
    assert!(result.audit().all_verified());
    assert_eq!(result.audit().objects().len(), 5);
    assert_eq!(result.audit().roots(), [f.event_root]);
    assert_eq!(result.receipt().subject(), f.event.revision_digest());
    assert_eq!(result.receipt().receipt_digest(), checked(&f)?.receipt().receipt_digest());
    assert!(result.recheck_bytes() > 0 && result.recheck_files() > 0);
    assert!(text(&result).contains("all_verified=true"));
    assert!(!text(&result).contains(std::str::from_utf8(fixture::SOURCE)?));
    assert!(!text(&result).contains(std::str::from_utf8(fixture::COUNTER)?));
    assert_eq!(read(&f)?.event(&f.event.event_id).ok_or("event")?.event, f.event);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn source_and_counterevidence_faults_stay_distinct_and_change_the_receipt() -> TestResult {
    let f = Fixture::new("faults")?;
    let healthy = checked(&f)?.receipt().receipt_digest();
    fs::remove_file(f.object_path(f.source))?;
    fs::write(f.object_path(f.counter), b"damaged envelope")?;
    let result = checked(&f)?;
    let rendered = text(&result);
    assert!(rendered.contains("object is missing"));
    assert!(rendered.contains("object is corrupt"));
    assert!(rendered.contains(&f.source.to_text()) && rendered.contains(&f.counter.to_text()));
    assert!(!result.audit().all_verified());
    assert_ne!(healthy, result.receipt().receipt_digest());
    assert_eq!(read(&f)?.event(&f.event.event_id).ok_or("event")?.event, f.event);
    Ok(())
}

#[test]
fn missing_manifest_preserves_unexamined_descendants_instead_of_claiming_complete_custody() -> TestResult {
    let f = Fixture::new("unknown-descendants")?;
    fs::remove_file(f.object_path(f.provenance))?;
    let result = checked(&f)?;
    assert!(!result.audit().manifest_expansion_complete());
    let outside = result.propositions().iter().find(|p| p.id.ends_with(":unexamined-references"))
        .ok_or("unknown descendants omitted")?;
    assert_eq!(outside.state, KnowledgeState::Unknown);
    assert!(outside.evidence.contains(&f.source.to_text()));
    assert!(outside.evidence.contains(&f.counter.to_text()));
    assert!(!result.audit().objects().iter().any(|o| o.digest == f.source));
    Ok(())
}

#[test]
fn local_tombstones_deny_existing_damaged_payloads_and_keep_the_denial_identity() -> TestResult {
    let f = Fixture::new("tombstone")?;
    let record = TombstoneRecord::new(ObjectId::parse("object:custody-source")?,
        Generation(2), Generation(1), TombstoneReason::Deleted,
        Some(f.source), ContentDigest::sha256(b"privacy"))?;
    let bytes = tombstone_record_bytes(&record)?;
    fs::write(f.root.join("objects/tombstones").join(format!("{}.tomb", f.source.to_text().replacen(':', "-", 1))), &bytes)?;
    fs::write(f.object_path(f.source), b"denied bytes must not be opened by custody")?;
    let result = checked(&f)?;
    let fault = result.propositions().iter().find(|p| p.id.ends_with(&format!(":fault:{}", f.source)))
        .ok_or("tombstone observation absent")?;
    assert!(fault.statement.contains("locally_tombstoned"));
    assert!(fault.evidence.contains(&ContentDigest::sha256(&bytes).to_text()));
    Ok(())
}

#[test]
fn binding_and_complete_chain_are_checked_before_any_payload_walk() -> TestResult {
    let f = Fixture::new("binding")?;
    let mut before = read(&f)?;
    before.events[0].revisions.clear();
    let mut called = false;
    let result = check_with(&f.root, &before, &f.event.event_id, CustodyAuditLimits::default(),
        &HostSpoolIo, || { called = true; read_deployment(&f.root, &OrientLimits::default()) }, &|| false);
    assert!(matches!(result, Err(CustodyReviewError::InvalidBinding)));
    assert!(!called);
    Ok(())
}

#[test]
fn every_observed_authority_change_refuses_the_whole_result() -> TestResult {
    let f = Fixture::new("authority-change")?;
    let before = read(&f)?;
    for change in 0..6 {
        let mut after = before.clone();
        match change {
            0 => after.ledger_root = ContentDigest::sha256(b"different ledger"),
            1 => after.effect_journal_root = ContentDigest::sha256(b"different effect journal"),
            2 => after.ledger_tail_uncommitted = !after.ledger_tail_uncommitted,
            3 => after.effect_tail_uncommitted = !after.effect_tail_uncommitted,
            4 => after.events[0].event_root = ContentDigest::sha256(b"different publication"),
            _ => after.events.clear(),
        }
        assert!(matches!(check_with(&f.root, &before, &f.event.event_id,
            CustodyAuditLimits::default(), &HostSpoolIo, || Ok(after), &|| false),
            Err(CustodyReviewError::BasisChanged)));
    }
    Ok(())
}

#[test]
fn cancellation_and_zero_io_allowance_cannot_return_an_intact_answer() -> TestResult {
    let f = Fixture::new("cancel")?;
    let before = read(&f)?;
    let mut called = false;
    let result = check_with(&f.root, &before, &f.event.event_id, CustodyAuditLimits::default(),
        &HostSpoolIo, || { called = true; Ok(before.clone()) }, &|| true);
    assert!(matches!(result, Err(CustodyReviewError::Cancelled)));
    assert!(!called);
    assert!(matches!(check_event(&f.root, &before, &f.event.event_id,
        CustodyAuditLimits { max_io_calls: 0, ..CustodyAuditLimits::default() }, &|| false),
        Err(CustodyReviewError::Audit(CustodyAuditError::Limit(_)))));
    Ok(())
}

#[test]
fn a_failed_recheck_never_falls_back_to_the_earlier_snapshot() -> TestResult {
    let f = Fixture::new("failed-recheck")?;
    let before = read(&f)?;
    let result = check_with(&f.root, &before, &f.event.event_id, CustodyAuditLimits::default(),
        &HostSpoolIo, || Err(DeploymentReadError::Unreadable { reason: "unavailable".to_owned() }), &|| false);
    assert!(matches!(result, Err(CustodyReviewError::RecheckFailed)));
    Ok(())
}

#[test]
fn detail_ceiling_never_drops_faults_to_make_a_summary_fit() -> TestResult {
    let f = Fixture::with_extra("fault-ceiling", MAX_CUSTODY_DETAILS + 1)?;
    for digest in &f.extras { fs::remove_file(f.object_path(*digest))?; }
    assert!(matches!(check_event(&f.root, &read(&f)?, &f.event.event_id,
        CustodyAuditLimits::default(), &|| false), Err(CustodyReviewError::ContextBound)));
    Ok(())
}

#[test]
fn recheck_accounting_admission_is_explicit_and_not_a_refill() -> TestResult {
    let f = Fixture::new("recheck-admission")?;
    let before = read(&f)?;
    let mut after = before.clone();
    after.bytes_read = MAX_RECHECK_ACCOUNTED_BYTES + 1;
    assert!(matches!(check_with(&f.root, &before, &f.event.event_id,
        CustodyAuditLimits::default(), &HostSpoolIo, || Ok(after), &|| false),
        Err(CustodyReviewError::ContextBound)));
    Ok(())
}
