#![forbid(unsafe_code)]
//! Current operator review → complete verified lineage → unchanged original source export.

use super::*;
use fss_core::{CanonicalEncode, EventState};
use fss_publication::SlotName;
use fss_reference::event_review::{ReviewError, ReviewReceipt};
use fss_reference::ingest::long_event_replay::{
    LongEventReplayError, LongEventReplayLimits, inspect_long_event,
};
use fss_reference::original_media_export::{
    OriginalMediaExportRecord, REVIEWED_ORIGINAL_MEDIA_EXPORT_PROFILE,
};
use fss_reference::{ReferencePolicyAction, ReferencePolicyDecision};

const PRIVATE_REVIEWER: &str = "principal:private-case-reviewer";
const PRIVATE_REASON: &str =
    "private reviewer rationale must not be disclosed with original footage";

fn review(f: &mut Fixture, disposition: ReviewDisposition) -> Test<ReviewReceipt> {
    let mut authority = f.authority.clone();
    authority.principal = PRIVATE_REVIEWER.into();
    let cx = ReplayCx::from_context_authority(&authority, f.deployment.root().to_path_buf())?;
    let request = ReviewRequest {
        event_id: f.request.event.event_id.clone(),
        expected_revision: f.request.event.expected_revision,
        disposition,
        reason: PRIVATE_REASON.into(),
    };
    let preview = preview_review(&f.deployment, &request, &authority, &cx)?;
    let receipt = commit_review(
        &mut f.deployment,
        &request,
        preview.approval(),
        &authority,
        &cx,
    )?;
    f.request.event.expected_revision = receipt.review.event().revision_digest();
    Ok(receipt)
}

#[test]
fn cold_multi_review_export_binds_current_case_to_exact_native_source_and_redacted_history() -> Test
{
    let mut f = Fixture::new("review-chain-cold")?;
    let original_request = f.request.clone();
    let (_, origin) = f
        .deployment
        .current_event_authority(&f.request.event.event_id)?;
    let original = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let mut reviews = Vec::new();
    for disposition in [
        ReviewDisposition::Investigate,
        ReviewDisposition::Investigate,
        ReviewDisposition::Resolve,
    ] {
        reviews.push(review(&mut f, disposition)?);
    }
    assert!(matches!(
        preview_original_media_export(&f.deployment, &original_request, &f.authority, &f.cx),
        Err(OriginalMediaExportError::Event(_))
    ));
    assert!(matches!(
        approve_original_media_export(
            &f.deployment,
            &f.request,
            original.approval(),
            &f.authority,
            &f.cx
        ),
        Err(OriginalMediaExportError::StaleApproval)
    ));
    // Native replay still means reexecuting the native event, not an operator's later assertion.
    assert!(matches!(
        inspect_long_event(
            &f.deployment,
            &f.request.event.event_id,
            &LongEventReplayLimits::default(),
            &f.cx
        ),
        Err(LongEventReplayError::UnsupportedProfile)
    ));
    // Original-media release uses its own existing positive grants. Verifying redacted review
    // pins must not require access to the separate plaintext-review hydration surface.
    f.authority = f.authority.narrow(fss_core::region::ContextNarrowingSpec {
        operation_id: f.authority.operation_id.clone(),
        capabilities: f
            .authority
            .capabilities()
            .iter()
            .filter(|capability| {
                capability.as_str() != CAP_REVIEW_PREPARE
                    && capability.as_str() != CAP_REVIEW_COMMIT
            })
            .cloned()
            .collect(),
        deadline: f.authority.deadline,
        priority: f.authority.priority,
        budgets: f.authority.budgets,
        privacy_scope: f.authority.privacy_scope.clone(),
        retention_scope: f.authority.retention_scope.clone(),
        lease_fence: f.authority.lease_fence,
        idempotency_key: f.authority.idempotency_key.clone(),
        lab_controls: f.authority.lab_controls.clone(),
    })?;
    f.cx = ReplayCx::from_context_authority(&f.authority, f.deployment.root().to_path_buf())?;
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let preview = preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx)?;
    assert_eq!(preview.profile(), REVIEWED_ORIGINAL_MEDIA_EXPORT_PROFILE);
    assert_eq!(preview.media_bytes(), original.media_bytes());
    assert_eq!(preview.media_bytes(), f.source);
    assert_ne!(preview.approval(), original.approval());
    assert_ne!(preview.root(), original.root());
    let json = preview.record_json();
    for field in [
        "\"schema\":\"fss.original_media_export.v2\"".to_owned(),
        "\"reviewed_event\":true".to_owned(),
        "\"review_count\":3".to_owned(),
        "\"review_reasons_included\":false".to_owned(),
        "\"reviewer_identity_included\":false".to_owned(),
        "\"review_is_sensor_recomputation\":false".to_owned(),
        "\"native_perception_reexecuted\":false".to_owned(),
        format!(
            "\"native_origin_revision\":\"{}\"",
            original_request.event.expected_revision
        ),
        format!("\"native_origin_event_root\":\"{}\"", origin.event_root),
        format!(
            "\"native_origin_authority_sequence\":{}",
            origin.authority_anchor.commit_sequence
        ),
        format!(
            "\"native_origin_authority_anchor_digest\":\"{}\"",
            origin
                .authority_anchor
                .canonical_digest("fss.original_media_export_basis.v1")
        ),
    ] {
        assert!(json.contains(&field), "missing {field}: {json}");
    }
    assert!(!json.contains(PRIVATE_REASON));
    assert!(!json.contains(PRIVATE_REVIEWER));
    let mut previous = 0;
    for (index, receipt) in reviews.iter().enumerate() {
        let event = receipt.review.event();
        let marker = format!(
            "\"revision\":{},\"event_revision\":\"{}\"",
            index + 2,
            event.revision_digest()
        );
        let position = json.find(&marker).ok_or("missing ordered review pin")?;
        assert!(position > previous);
        previous = position;
        for field in [
            format!("\"event_root\":\"{}\"", receipt.authority.event_root),
            format!(
                "\"statement_digest\":\"{}\"",
                receipt.review.record().digest()
            ),
            format!(
                "\"statement_root\":\"{}\"",
                receipt.review.provenance_root()
            ),
            format!(
                "\"authority_sequence\":{}",
                receipt.authority.authority_anchor.commit_sequence
            ),
        ] {
            assert!(json.contains(&field), "missing {field}");
        }
    }
    assert_eq!(
        reviews.last().ok_or("no reviews")?.review.event().state,
        EventState::Resolved
    );
    let prepared = approve_original_media_export(
        &reopened,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    revalidate_original_media_export(&reopened, &prepared, &f.authority, &f.cx)?;
    let decoded = verify_original_media_export(
        preview.manifest_bytes(),
        preview.record_bytes(),
        preview.media_bytes(),
        preview.root(),
    )?;
    assert_eq!(decoded.to_bytes(), preview.record_bytes());
    assert_eq!(decoded.to_json(), json);
    assert_eq!(decoded.request(), &f.request);
    assert_eq!(decoded.profile(), REVIEWED_ORIGINAL_MEDIA_EXPORT_PROFILE);
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    Ok(())
}

#[test]
fn superficially_linked_operator_successor_cannot_change_native_facts() -> Test {
    // Each case has a valid immutable statement, predecessor root, committed root reachability,
    // supersedes digest and event-authority row. Exact review derivation must still reject it.
    for mutation in [
        "interval",
        "probability",
        "source",
        "zone",
        "model",
        "uncertainty",
    ] {
        let mut f = Fixture::new(&format!("forged-review-{mutation}"))?;
        let (_, original) = f
            .deployment
            .current_event_authority(&f.request.event.event_id)?;
        let request = ReviewRequest {
            event_id: f.request.event.event_id.clone(),
            expected_revision: f.request.event.expected_revision,
            disposition: ReviewDisposition::Investigate,
            reason: PRIVATE_REASON.into(),
        };
        let review = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
        let statement = review.record().to_bytes();
        let previous = f.deployment.publisher().spool().read(original.event_root)?;
        let slot = SlotName::parse(&format!(
            "review-{}",
            review
                .record()
                .digest()
                .to_text()
                .strip_prefix("sha256:")
                .ok_or("hash format")?
        ))?;
        let staged = f
            .deployment
            .stage_and_publish(&slot, &[&statement, &previous], &f.cx)?;
        assert_eq!(staged.root, review.provenance_root());
        f.deployment
            .publish_and_commit(&slot, &staged.manifest, review.event().interval, &f.cx)?;
        let mut forged = review.event().clone();
        match mutation {
            "interval" => forged.interval.latest.0 += 1,
            "probability" => {
                forged.probability.lower = 0.125;
                forged.probability.upper = 0.875;
            }
            "source" => {
                forged
                    .evidence
                    .first_mut()
                    .ok_or("no source evidence")?
                    .digest = ContentDigest::sha256(b"different retained source claim")
            }
            "zone" => forged.zone_ids = vec!["another-zone".into()],
            "model" => forged.model_receipts.push(
                f.deployment
                    .publisher_mut()
                    .stage_object(b"different retained model claim")?,
            ),
            "uncertainty" => forged.uncertainty_reason = Some("changed native uncertainty".into()),
            _ => return Err("unknown mutation".into()),
        }
        let receipt = f.deployment.publish_event(
            &ReferencePolicyDecision {
                event: forged.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &f.cx,
        )?;
        assert_eq!(receipt.event_revision_digest, forged.revision_digest());
        f.request.event.expected_revision = forged.revision_digest();
        let before = f.snapshot();
        let result = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx);
        assert!(
            matches!(result,
            Err(OriginalMediaExportError::Review(ref error))
                if matches!(error.as_ref(), ReviewError::CustodyMismatch)),
            "{mutation} was not refused by exact review derivation: {result:?}"
        );
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn reviewed_package_rechecks_current_review_privacy_and_deletion_before_delivery() -> Test {
    for change in ["review", "mask", "deletion"] {
        let mut f = Fixture::new(&format!("reviewed-revalidation-{change}"))?;
        review(&mut f, ReviewDisposition::Investigate)?;
        let preview =
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
        let prepared = approve_original_media_export(
            &f.deployment,
            &f.request,
            preview.approval(),
            &f.authority,
            &f.cx,
        )?;
        match change {
            "review" => {
                review(&mut f, ReviewDisposition::Reject)?;
            }
            "mask" => {
                let policy = PrivacyMaskPolicy::new(
                    SensorId::parse("sensor:original-media")?,
                    [48, 32],
                    &[[40, 0, 8, 32]],
                )?;
                let approval = preview_mask(&f.deployment, &policy)?.approval;
                declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
            }
            "deletion" => {
                let plan = plan_deletion(&f.deployment, f.request.import_identity, &f.cx)?;
                assert!(
                    plan.blockers.is_empty(),
                    "unexpected blockers: {:?}",
                    plan.blockers
                );
                let approval = plan.approval_digest(ACTOR)?;
                commit_deletion(&mut f.deployment, plan.digest()?, approval, ACTOR, &f.cx)?;
            }
            _ => return Err("unknown change".into()),
        }
        assert!(matches!(
            revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx),
            Err(OriginalMediaExportError::AuthorityChanged)
        ));
        if change == "review" {
            let current =
                preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
            assert_eq!(current.media_bytes(), f.source);
            assert!(current.record_json().contains("\"disposition\":\"reject\""));
            assert_ne!(current.approval(), preview.approval());
        } else {
            assert!(
                preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)
                    .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn intermediate_review_corruption_and_cancellation_never_return_original_media() -> Test {
    for corrupt in [false, true] {
        let mut f = Fixture::new(if corrupt {
            "middle-review-corrupt"
        } else {
            "middle-review-cancel"
        })?;
        review(&mut f, ReviewDisposition::Investigate)?;
        let middle = review(&mut f, ReviewDisposition::Investigate)?;
        review(&mut f, ReviewDisposition::Resolve)?;
        let before = f.snapshot();
        if corrupt {
            // The current event and its last review still exist. Checking only that last review
            // would release media despite a broken middle link.
            fs::write(
                f.deployment
                    .publisher()
                    .spool()
                    .object_path(middle.review.record().digest()),
                b"corrupt middle statement",
            )?;
        } else {
            f.cx.set_cancel_at_checkpoint_occurrence("event_review:lineage_link", 2);
        }
        assert!(
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx).is_err()
        );
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn offline_reviewed_record_rejects_inconsistent_current_summary_and_unbounded_or_trailing_chain()
-> Test {
    let mut f = Fixture::new("reviewed-wire")?;
    let original_revision = f.request.event.expected_revision;
    let (_, origin) = f
        .deployment
        .current_event_authority(&f.request.event.event_id)?;
    let receipt = review(&mut f, ReviewDisposition::Reject)?;
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let bytes = preview.record_bytes();
    let digest = receipt.review.event().revision_digest().bytes();
    // The final occurrence belongs to the review link; the earlier occurrence is in the nested
    // current event request. Altering only the link cannot be hidden in a self-consistent summary.
    let position = bytes
        .windows(digest.len())
        .rposition(|bytes| bytes == digest)
        .ok_or("missing last review digest")?;
    let mut changed = bytes.to_vec();
    changed[position] ^= 1;
    assert!(matches!(
        OriginalMediaExportRecord::from_bytes(&changed),
        Err(OriginalMediaExportError::CustodyMismatch)
    ));
    changed = bytes.to_vec();
    changed.push(0);
    assert!(OriginalMediaExportRecord::from_bytes(&changed).is_err());
    let mut lineage_prefix = fss_core::CanonicalEncoder::new();
    lineage_prefix.digest(original_revision);
    lineage_prefix.digest(origin.event_root);
    origin
        .authority_anchor
        .encode_canonical(&mut lineage_prefix);
    let prefix = lineage_prefix.finish();
    let count_position = bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .ok_or("missing origin lineage prefix")?
        + prefix.len();
    for count in [0_u32, fss_core::event::MAX_LINEAGE_DEPTH as u32, u32::MAX] {
        changed = bytes.to_vec();
        changed[count_position..count_position + 4].copy_from_slice(&count.to_be_bytes());
        assert!(matches!(
            OriginalMediaExportRecord::from_bytes(&changed),
            Err(OriginalMediaExportError::Limit)
        ));
    }
    // Each package remains explicitly versioned; changing v2 to the package-event version cannot
    // reinterpret a reviewed long event or drop its complete review lineage.
    let mut version_prefix = fss_core::CanonicalEncoder::new();
    version_prefix.bytes(b"FSSEXM01");
    let position = version_prefix.finish().len();
    changed = bytes.to_vec();
    changed[position..position + 4].copy_from_slice(&3_u32.to_be_bytes());
    assert!(matches!(
        OriginalMediaExportRecord::from_bytes(&changed),
        Err(OriginalMediaExportError::UnsupportedProfile)
    ));
    Ok(())
}
