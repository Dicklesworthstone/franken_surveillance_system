#![forbid(unsafe_code)]
//! Exact readback of the current operator assertion, without knowing its original reason.
use super::*;

/// Read and verify the current revision's review statement. A non-review event returns `None`;
/// an event naming this review policy with missing or altered provenance fails closed instead.
/// This is metadata access only, not renewed source-media availability or effect authority.
pub fn read_current_review(
    deployment: &ReferenceDeployment,
    event_id: &EventId,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<Option<ReviewPreview>, ReviewError> {
    authorize(deployment, authority, cx, CAP_REVIEW_PREPARE)?;
    if event_id.as_str().len() > MAX_EVENT_ID_LEN {
        return Err(ReviewError::Limit);
    }
    let revisions = history(deployment, event_id, cx)?;
    let current = revisions.last().ok_or(ReviewError::StaleRevision)?;
    let (event, _) = deployment.current_event_authority(event_id)?;
    if event != current.event {
        return Err(ReviewError::CustodyMismatch);
    }
    if event.decision_path.policy_generation != ContentDigest::sha256(POLICY) {
        return Ok(None);
    }
    let index = revisions
        .len()
        .checked_sub(2)
        .ok_or(ReviewError::CustodyMismatch)?;
    let prior = &revisions[index];
    let root = event.decision_path.fingerprint;
    let bytes = deployment.publisher().spool().read(root)?;
    let manifest = ObjectManifest::from_canonical_bytes(&bytes)?;
    if manifest.children().len() != 2 || !manifest.children().contains(&prior.root) {
        return Err(ReviewError::CustodyMismatch);
    }
    let digest = manifest
        .children()
        .iter()
        .copied()
        .find(|d| *d != prior.root)
        .ok_or(ReviewError::CustodyMismatch)?;
    let bytes = deployment.publisher().spool().read(digest)?;
    let record = ReviewRecord::from_bytes(&bytes, digest)?;
    if record.site != deployment.site_lineage()
        || record.request.event_id != *event_id
        || record.request.expected_revision != prior.event.revision_digest()
        || record.previous_event_root != prior.root
        || record.previous_anchor != prior.anchor
    {
        return Err(ReviewError::CustodyMismatch);
    }
    let chain: Vec<_> = revisions[..=index]
        .iter()
        .map(|r| r.event.clone())
        .collect();
    let mut preview = derive(record, &chain)?;
    if preview.provenance_root != root || preview.event.canonical_bytes() != event.canonical_bytes()
    {
        return Err(ReviewError::CustodyMismatch);
    }
    verify_provenance(deployment, &preview)?;
    checkpoint(cx, "event_review:readback")?;
    preview.already_published = true;
    Ok(Some(preview))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_review::tests::{Fixture, Test};

    #[test]
    fn readback_keeps_original_actor_even_for_a_different_reader() -> Test {
        let mut f = Fixture::new("readback", false)?;
        assert!(
            read_current_review(&f.deployment, &f.event.event_id, &f.authority, &f.cx)?.is_none()
        );
        let request = f.request(ReviewDisposition::Resolve);
        let p = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
        let receipt = commit_review(
            &mut f.deployment,
            &request,
            p.approval(),
            &f.authority,
            &f.cx,
        )?;
        let mut reader = f.authority.clone();
        reader.principal = "principal:another-reader".into();
        let before = f.snapshot()?;
        let read = read_current_review(&f.deployment, &request.event_id, &reader, &f.cx)?
            .ok_or("missing review")?;
        assert_eq!(read.record(), receipt.review.record());
        assert_eq!(read.approval(), receipt.review.approval());
        assert!(read.already_published());
        assert_eq!(f.snapshot()?, before);
        Ok(())
    }
}
