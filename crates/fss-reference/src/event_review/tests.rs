#![forbid(unsafe_code)]
//! Real event authority and publication; synthetic assertions test contracts, not scene truth.
use super::*;
use fss_core::region::RootAuthoritySpec;
use fss_core::{
    BudgetVector, CaptureInterval, EventKind, OperationId, ProbabilityInterval, TimestampNs,
};
use std::fs;
use std::path::PathBuf;

pub(super) type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:event-review";
const ACTOR: &str = "principal:event-review";

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Test<Self> {
        for n in 0..100 {
            let path =
                std::env::temp_dir().join(format!("fss-review-{name}-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(capabilities: &[&str]) -> Test<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-review".into(),
        operation_id: OperationId::parse("operation:event-review")?,
        principal: ACTOR.into(),
        capabilities: capabilities.iter().map(|c| (*c).into()).collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

fn initial_event(tamper: bool) -> Test<EventHypothesis> {
    Ok(EventHypothesis {
        schema: EventHypothesis::SCHEMA.into(),
        event_id: EventId::parse("event:review-fixture")?,
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        uncertainty_reason: Some("Synthetic fixture, not a calibrated observation".into()),
        zone_ids: vec!["door".into()],
        track_ids: vec!["track:synthetic".into()],
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: vec![EventEvidence {
            digest: ContentDigest::sha256(b"synthetic source assertion"),
            class: EvidenceClass::Assertion,
            failure_domain: "synthetic-source".into(),
            supports: false,
            relation: if tamper {
                EvidenceEdgeRelation::SensorTamper
            } else {
                EvidenceEdgeRelation::DerivedFrom
            },
            capsule_digest: None,
            identity_digest: Some(ContentDigest::sha256(b"synthetic-source")),
        }],
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"synthetic policy"),
            fingerprint: ContentDigest::sha256(b"synthetic decision"),
            abstained: true,
            abstention_reason: Some("Synthetic unclassified fixture".into()),
        },
    })
}

pub(super) struct Fixture {
    pub(super) deployment: ReferenceDeployment,
    pub(super) cx: ReplayCx,
    pub(super) authority: ContextAuthority,
    pub(super) event: EventHypothesis,
    _directory: Directory,
}
impl Fixture {
    pub(super) fn new(name: &str, tamper: bool) -> Test<Self> {
        let directory = Directory::new(name)?;
        let authority = authority(&["ADP-REPLAY-001", CAP_REVIEW_PREPARE, CAP_REVIEW_COMMIT])?;
        let root = directory.0.join("deployment");
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let event = initial_event(tamper)?;
        deployment.stage_payload(b"synthetic source assertion")?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(Self {
            deployment,
            cx,
            authority,
            event,
            _directory: directory,
        })
    }
    pub(super) fn request(&self, disposition: ReviewDisposition) -> ReviewRequest {
        ReviewRequest {
            event_id: self.event.event_id.clone(),
            expected_revision: self.event.revision_digest(),
            disposition,
            reason: "Owner reviewed the available evidence".into(),
        }
    }
    fn fresh_cx(&self) -> Test<ReplayCx> {
        Ok(ReplayCx::from_context_authority(
            &self.authority,
            self.deployment.root().to_path_buf(),
        )?)
    }
    pub(super) fn snapshot(&self) -> Test<(LedgerAnchor, usize, Vec<u8>)> {
        Ok((
            self.deployment.current_anchor().clone(),
            self.deployment.publisher().spool().digests().count(),
            fs::read(self.deployment.root().join("effects/journal.fssj"))?,
        ))
    }
}

#[test]
fn read_and_preview_write_nothing_and_preserve_every_source_field() -> Test {
    let f = Fixture::new("preview", false)?;
    let before = f.snapshot()?;
    assert_eq!(
        read_review_event(&f.deployment, &f.event.event_id, &f.authority, &f.cx)?.0,
        f.event
    );
    let preview = preview_review(
        &f.deployment,
        &f.request(ReviewDisposition::Reject),
        &f.authority,
        &f.cx,
    )?;
    assert!(!preview.already_published());
    let event = preview.event();
    assert_eq!(event.supersedes, Some(f.event.revision_digest()));
    assert_eq!(event.revision, 2);
    assert_eq!(event.kind, f.event.kind);
    assert_eq!(event.interval, f.event.interval);
    assert_eq!(event.probability, f.event.probability);
    assert_eq!(event.uncertainty_reason, f.event.uncertainty_reason);
    assert_eq!(event.zone_ids, f.event.zone_ids);
    assert_eq!(event.track_ids, f.event.track_ids);
    assert_eq!(event.model_receipts, f.event.model_receipts);
    assert_eq!(&event.evidence[..f.event.evidence.len()], &f.event.evidence);
    let assertion = event.evidence.last().ok_or("missing assertion")?;
    assert_eq!(assertion.class, EvidenceClass::Assertion);
    assert_eq!(assertion.relation, EvidenceEdgeRelation::Contradicts);
    assert!(!assertion.supports);
    assert!(!event.analyze_corroboration().is_corroborated);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn rejection_publishes_once_survives_reopen_and_never_mutates_effects() -> Test {
    let mut f = Fixture::new("reopen", false)?;
    let request = f.request(ReviewDisposition::Reject);
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let effects = f.snapshot()?.2;
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert!(receipt.published);
    assert_eq!(receipt.review.event().state, EventState::Rejected);
    assert_eq!(
        crate::committed_reference_policy_action(receipt.review.event()),
        ReferencePolicyAction::Hold
    );
    let after = f.snapshot()?;
    assert_eq!(after.2, effects);
    let Fixture {
        deployment,
        cx,
        authority,
        event,
        _directory,
    } = f;
    let root = deployment.root().to_path_buf();
    drop(deployment);
    let mut deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let retry = commit_review(
        &mut deployment,
        &request,
        preview.approval(),
        &authority,
        &cx,
    )?;
    assert!(!retry.published);
    assert_eq!(*deployment.current_anchor(), after.0);
    assert_eq!(deployment.publisher().spool().digests().count(), after.1);
    assert_eq!(retry.review.record(), receipt.review.record());
    assert_eq!(
        deployment
            .publisher()
            .spool()
            .read(receipt.review.record().digest())?,
        receipt.review.record().to_bytes()
    );
    // A previously prepared producer cannot overwrite the operator successor with revision one.
    assert!(
        deployment
            .publish_event(
                &ReferencePolicyDecision {
                    event,
                    action: ReferencePolicyAction::Hold
                },
                &cx
            )
            .is_err()
    );
    assert_eq!(*deployment.current_anchor(), after.0);
    Ok(())
}

#[test]
fn stale_approval_or_competing_review_never_writes() -> Test {
    let mut f = Fixture::new("stale", false)?;
    let request = f.request(ReviewDisposition::Reject);
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let before = f.snapshot()?;
    let mut changed = request.clone();
    changed.reason.push('!');
    assert!(matches!(
        commit_review(
            &mut f.deployment,
            &changed,
            preview.approval(),
            &f.authority,
            &f.cx
        ),
        Err(ReviewError::StaleApproval)
    ));
    assert_eq!(f.snapshot()?, before);
    let competing = f.request(ReviewDisposition::Resolve);
    let competing_preview = preview_review(&f.deployment, &competing, &f.authority, &f.cx)?;
    commit_review(
        &mut f.deployment,
        &competing,
        competing_preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    let after = f.snapshot()?;
    assert!(matches!(
        commit_review(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.authority,
            &f.cx
        ),
        Err(ReviewError::StaleRevision)
    ));
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn capabilities_site_and_cancellation_are_checked_before_event_disclosure() -> Test {
    let mut f = Fixture::new("authority", false)?;
    let request = f.request(ReviewDisposition::Reject);
    let denied = authority(&["ADP-REPLAY-001"])?;
    let before = f.snapshot()?;
    assert!(matches!(
        preview_review(&f.deployment, &request, &denied, &f.cx),
        Err(ReviewError::Unauthorized)
    ));
    let prepare_only = authority(&["ADP-REPLAY-001", CAP_REVIEW_PREPARE])?;
    let preview = preview_review(&f.deployment, &request, &prepare_only, &f.cx)?;
    assert!(matches!(
        commit_review(
            &mut f.deployment,
            &request,
            preview.approval(),
            &prepare_only,
            &f.cx
        ),
        Err(ReviewError::Unauthorized)
    ));
    let mut foreign = f.authority.clone();
    foreign.anchor_universe = ContentDigest::sha256(b"foreign");
    assert!(matches!(
        preview_review(&f.deployment, &request, &foreign, &f.cx),
        Err(ReviewError::Unauthorized)
    ));
    f.cx.request_cancellation();
    assert!(matches!(
        preview_review(&f.deployment, &request, &f.authority, &f.cx),
        Err(ReviewError::Cancelled)
    ));
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn provenance_cut_resumes_with_original_approval_without_duplicating_root() -> Test {
    let mut f = Fixture::new("provenance", false)?;
    let request = f.request(ReviewDisposition::Resolve);
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    f.cx.set_cancel_at_checkpoint(STAGE_REVIEW_PROVENANCE);
    assert!(matches!(
        commit_review(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.authority,
            &f.cx
        ),
        Err(ReviewError::Cancelled)
    ));
    assert_eq!(
        f.deployment.current_event_authority(&request.event_id)?.0,
        f.event
    );
    let head = f.deployment.current_anchor().clone();
    let cx = f.fresh_cx()?;
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.authority,
        &cx,
    )?;
    assert!(receipt.published);
    assert_eq!(
        f.deployment.current_anchor().commit_sequence,
        head.commit_sequence + 1
    );
    assert_eq!(receipt.review.event().state, EventState::Resolved);
    Ok(())
}

#[test]
fn prepublication_cancellation_has_no_writes_postcommit_cancellation_reports_success() -> Test {
    let mut f = Fixture::new("cancel", false)?;
    let request = f.request(ReviewDisposition::Reject);
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let before = f.snapshot()?;
    f.cx.set_cancel_at_checkpoint(STAGE_REVIEW_REVALIDATED);
    assert!(matches!(
        commit_review(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.authority,
            &f.cx
        ),
        Err(ReviewError::Cancelled)
    ));
    assert_eq!(f.snapshot()?, before);
    let cx = f.fresh_cx()?;
    cx.set_cancel_at_checkpoint(STAGE_REVIEW_COMMITTED);
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.authority,
        &cx,
    )?;
    assert!(receipt.published);
    assert!(cx.is_drain_completed());
    assert_eq!(
        f.deployment
            .current_event_authority(&request.event_id)?
            .0
            .state,
        EventState::Rejected
    );
    Ok(())
}

#[test]
fn investigation_then_resolution_keeps_tamper_and_full_lineage() -> Test {
    let mut f = Fixture::new("tamper", true)?;
    let request = f.request(ReviewDisposition::Investigate);
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert!(receipt.authority.lineage_tamper_status.has_open_tamper());
    let request = ReviewRequest {
        expected_revision: receipt.review.event().revision_digest(),
        disposition: ReviewDisposition::Resolve,
        ..request
    };
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert_eq!(receipt.review.event().revision, 3);
    assert!(receipt.authority.lineage_tamper_status.has_open_tamper());
    assert!(
        receipt
            .review
            .event()
            .evidence
            .iter()
            .any(EventEvidence::reports_sensor_tamper)
    );
    assert_eq!(receipt.authority.prior_revision_encodings.len(), 2);
    let terminal = ReviewRequest {
        expected_revision: receipt.review.event().revision_digest(),
        disposition: ReviewDisposition::Investigate,
        ..request
    };
    assert!(preview_review(&f.deployment, &terminal, &f.authority, &f.cx).is_err());
    Ok(())
}

#[test]
fn record_roundtrip_truncation_tamper_and_approval_binding() -> Test {
    let f = Fixture::new("codec", false)?;
    let preview = preview_review(
        &f.deployment,
        &f.request(ReviewDisposition::Reject),
        &f.authority,
        &f.cx,
    )?;
    let record = preview.record();
    let bytes = record.to_bytes();
    assert_eq!(ReviewRecord::from_bytes(&bytes, record.digest())?, *record);
    for n in 0..bytes.len() {
        assert!(ReviewRecord::from_bytes(&bytes[..n], ContentDigest::sha256(&bytes[..n])).is_err());
        let mut changed = bytes.clone();
        changed[n] ^= 1;
        assert!(ReviewRecord::from_bytes(&changed, record.digest()).is_err());
    }
    let mut suffix = bytes.clone();
    suffix.push(0);
    assert!(ReviewRecord::from_bytes(&suffix, ContentDigest::sha256(&suffix)).is_err());
    let mut request = record.request.clone();
    request.reason.push('!');
    let other = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    assert_ne!(preview.approval(), other.approval());
    let mut actor = f.authority.clone();
    actor.principal = "principal:other".into();
    let other = preview_review(&f.deployment, &record.request, &actor, &f.cx)?;
    assert_ne!(preview.approval(), other.approval());
    Ok(())
}

#[test]
fn direct_transition_table_and_effect_guard_never_invent_authority() {
    for value in [
        "corroborate",
        "adjudicate",
        "alert_delivered",
        "verified",
        "",
    ] {
        assert!(ReviewDisposition::parse(value).is_err());
    }
    assert!(!ReviewDisposition::Resolve.allowed_from(EventState::Corroborated));
    assert!(ReviewDisposition::Investigate.allowed_from(EventState::Corroborated));
    assert!(ReviewDisposition::Resolve.allowed_from(EventState::Indeterminate));
    assert!(!ReviewDisposition::Reject.allowed_from(EventState::Resolved));
    assert!(effect_blocks_review(EffectState::Prepared));
    assert!(effect_blocks_review(EffectState::Committed));
    assert!(effect_blocks_review(EffectState::Indeterminate));
    assert!(!effect_blocks_review(EffectState::Verified));
    assert!(!effect_blocks_review(EffectState::Failed));
    assert!(!effect_blocks_review(EffectState::Cancelled));
}

#[test]
fn newly_prepared_unrelated_effect_blocks_old_review_approval_without_mutating_either_journal()
-> Test {
    use fss_core::{EffectIntent, IdempotencyKey, ObligationId};
    let mut f = Fixture::new("open-effect", false)?;
    let request = f.request(ReviewDisposition::Resolve);
    let preview = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
    let intent = EffectIntent::new(
        OperationId::parse("operation:unrelated-review-test")?,
        IdempotencyKey::parse("idempotency:unrelated-review-test")?,
        "test.review-boundary",
        ContentDigest::sha256(b"synthetic request"),
        ContentDigest::sha256(b"synthetic precondition"),
    )?;
    f.deployment.effects_mut().prepare(
        intent,
        ObligationId::parse("obligation:unrelated-review-test")?,
        "test-only pending work; no transport",
        TimestampNs(100),
    )?;
    let before = f.snapshot()?;
    assert!(matches!(
        preview_review(&f.deployment, &request, &f.authority, &f.cx),
        Err(ReviewError::OpenEffects)
    ));
    assert!(matches!(
        commit_review(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.authority,
            &f.cx
        ),
        Err(ReviewError::OpenEffects)
    ));
    assert_eq!(f.snapshot()?, before);
    assert_eq!(
        f.deployment.current_event_authority(&request.event_id)?.0,
        f.event
    );
    assert_eq!(
        f.deployment
            .effects()
            .operations()
            .next()
            .ok_or("missing prepared operation")?
            .state,
        EffectState::Prepared
    );
    Ok(())
}
