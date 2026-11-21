#![forbid(unsafe_code)]
//! Bounded proof that every successor of an original event is an unchanged-source operator review.
//! This internal owner discloses only immutable pins to the separately authorized media exporter.

use super::*;
use fss_core::ObjectId;

/// Includes history, review statements, current-event rereads and export-summary verification.
const MAX_LINEAGE_READ_BYTES: usize = 64 * 1024 * 1024;
const MAX_REVIEW_MANIFEST_BYTES: usize = 1024;

/// Redacted pins of one verified operator assertion. No rationale or principal plaintext escapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedReviewLink {
    pub(crate) revision: u64,
    pub(crate) event_revision: ContentDigest,
    pub(crate) event_root: ContentDigest,
    pub(crate) event_anchor: LedgerAnchor,
    pub(crate) statement_digest: ContentDigest,
    pub(crate) statement_root: ContentDigest,
    pub(crate) disposition: ReviewDisposition,
}

/// The exact current chain, constructible only by complete authority and derivation checks.
pub(crate) struct VerifiedReviewLineage {
    original: Revision,
    current: Revision,
    links: Vec<VerifiedReviewLink>,
    basis: LedgerAnchor,
}
impl VerifiedReviewLineage {
    pub(crate) fn original(&self) -> &EventHypothesis {
        &self.original.event
    }
    pub(crate) fn original_root(&self) -> ContentDigest {
        self.original.root
    }
    pub(crate) fn original_anchor(&self) -> &LedgerAnchor {
        &self.original.anchor
    }
    pub(crate) fn current(&self) -> &EventHypothesis {
        &self.current.event
    }
    pub(crate) fn links(&self) -> &[VerifiedReviewLink] {
        &self.links
    }
    /// A sealed lineage can be used only against the same uninterrupted current authority.
    pub(crate) fn revalidate_basis(
        &self,
        deployment: &dyn RetainedSource,
        cx: &ReplayCx,
    ) -> Result<(), ReviewError> {
        checkpoint(cx, "event_review:lineage_current")?;
        if cx.root_dir() != deployment.root() || deployment.current_anchor() != &self.basis {
            return Err(ReviewError::StaleRevision);
        }
        let object = ObjectId::parse(format!(
            "object:event:{}",
            self.current.event.event_id.as_str()
        ))?;
        let current = deployment
            .ledger()
            .current()
            .objects
            .get(&object)
            .ok_or(ReviewError::StaleRevision)?;
        if current.family != FAMILY_EVENT_REVISION
            || current.generation != self.current.event.revision
            || current.payload_digest != self.current.root
        {
            return Err(ReviewError::StaleRevision);
        }
        Ok(())
    }
}

/// The original media exporter has already checked media-read/export authority before calling.
/// This is not public review hydration and never grants a caller access to review plaintext.
pub(crate) fn inspect_review_lineage(
    deployment: &dyn RetainedSource,
    event_id: &EventId,
    cx: &ReplayCx,
) -> Result<VerifiedReviewLineage, ReviewError> {
    inspect_review_lineage_with_limit(deployment, event_id, cx, MAX_LINEAGE_READ_BYTES)
}

/// A smaller allowance preserves the same complete proof and cannot raise the fixed ceiling.
pub(super) fn inspect_review_lineage_with_limit(
    deployment: &dyn RetainedSource,
    event_id: &EventId,
    cx: &ReplayCx,
    maximum: usize,
) -> Result<VerifiedReviewLineage, ReviewError> {
    checkpoint(cx, "event_review:lineage")?;
    if cx.root_dir() != deployment.root() {
        return Err(ReviewError::Unauthorized);
    }
    if event_id.as_str().len() > MAX_EVENT_ID_LEN {
        return Err(ReviewError::Limit);
    }
    let basis = deployment.current_anchor().clone();
    let mut reader = ReviewReadBudget::new(maximum.min(MAX_LINEAGE_READ_BYTES));
    let mut revisions = history_budgeted(deployment, event_id, cx, &mut reader)?;
    if !(2..=MAX_LINEAGE_DEPTH).contains(&revisions.len()) {
        return Err(ReviewError::CustodyMismatch);
    }
    let history_bytes = reader.used;
    let first = revisions.first().ok_or(ReviewError::CustodyMismatch)?;
    if first.event.revision != 1 || first.event.supersedes.is_some() {
        return Err(ReviewError::CustodyMismatch);
    }
    // Match the event publisher's exact manifest, not merely an arbitrary root containing the
    // same metadata. Shared model receipts still belong to the original native source owner.
    for revision in &revisions {
        let expected = ObjectManifest::new(
            "event-revision",
            revision.event.model_receipts.iter().copied(),
            Some(ContentDigest::sha256(&revision.event.canonical_bytes())),
        )?;
        if expected.root() != revision.root {
            return Err(ReviewError::CustodyMismatch);
        }
    }
    let chain: Vec<_> = revisions
        .iter()
        .map(|revision| revision.event.clone())
        .collect();
    let mut links = Vec::with_capacity(revisions.len() - 1);
    for index in 1..revisions.len() {
        checkpoint(cx, "event_review:lineage_link")?;
        let previous = &revisions[index - 1];
        let revision = &revisions[index];
        if revision.event.decision_path.policy_generation != ContentDigest::sha256(POLICY)
            || revision.event.supersedes != Some(previous.event.revision_digest())
            || revision.anchor.commit_sequence <= previous.anchor.commit_sequence
        {
            return Err(ReviewError::CustodyMismatch);
        }
        let root = revision.event.decision_path.fingerprint;
        let manifest_bytes = reader.read(deployment, root, MAX_REVIEW_MANIFEST_BYTES)?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
        if manifest.children().len() != 2
            || manifest.metadata_digest().is_some()
            || !manifest.children().contains(&previous.root)
        {
            return Err(ReviewError::CustodyMismatch);
        }
        let digest = manifest
            .children()
            .iter()
            .copied()
            .find(|digest| *digest != previous.root)
            .ok_or(ReviewError::CustodyMismatch)?;
        let bytes = reader.read(deployment, digest, MAX_REVIEW_RECORD_BYTES)?;
        let record = ReviewRecord::from_bytes(&bytes, digest)?;
        if record.site != deployment.site_lineage()
            || record.request.event_id != *event_id
            || record.request.expected_revision != previous.event.revision_digest()
            || record.previous_event_root != previous.root
            || record.previous_anchor != previous.anchor
            || record.manifest()?.canonical_bytes() != manifest_bytes
        {
            return Err(ReviewError::CustodyMismatch);
        }
        let slot = record.slot()?;
        deployment
            .check_publication(&slot, root, manifest.children().len())
            .map_err(retained_error)?;
        let object = ObjectId::parse(format!("object:local-root:{}", slot.as_str()))?;
        let authority = deployment
            .ledger()
            .current()
            .objects
            .get(&object)
            .ok_or(ReviewError::CustodyMismatch)?;
        if authority.family != fss_publication::ROOT_REACHABILITY_FAMILY
            || authority.generation != 1
            || authority.payload_digest != root
        {
            return Err(ReviewError::CustodyMismatch);
        }
        // Reexecute the existing pure review derivation. This proves exact preservation of
        // source/model evidence, kind, intervals, probability, zones, tracks and tamper history;
        // a lookalike successor or a digest-only supersedes chain is insufficient.
        let expected = derive(record, &chain[..index])?;
        if expected.provenance_root != root || expected.event != revision.event {
            return Err(ReviewError::CustodyMismatch);
        }
        links.push(VerifiedReviewLink {
            revision: revision.event.revision,
            event_revision: revision.event.revision_digest(),
            event_root: revision.root,
            event_anchor: revision.anchor.clone(),
            statement_digest: digest,
            statement_root: root,
            disposition: expected.record.request.disposition,
        });
    }
    let last = revisions.last().ok_or(ReviewError::CustodyMismatch)?;
    // The shared current-revision owner verifies every history root/payload and each
    // independently retained revision witness. The later export summary first reconstructs
    // that history, then verifies the same lineage and witnesses. Reserve all three history
    // passes and both witness passes before either owner can allocate retained payloads.
    for _ in 0..3 {
        reader.reserve(history_bytes)?;
    }
    for _ in 0..2 {
        for revision in &revisions {
            reader.reserve(crate::alert::event_revision_encoding(&revision.event).len())?;
        }
    }
    let (current, receipt) = current_revision(deployment, event_id, &revisions, cx)?;
    if current != last.event
        || receipt.event_root != last.root
        || receipt.authority_anchor != last.anchor
        || deployment.current_anchor() != &basis
    {
        return Err(ReviewError::CustodyMismatch);
    }
    let current = revisions.pop().ok_or(ReviewError::CustodyMismatch)?;
    let original = revisions
        .into_iter()
        .next()
        .ok_or(ReviewError::CustodyMismatch)?;
    let verified = VerifiedReviewLineage {
        original,
        current,
        links,
        basis,
    };
    verified.revalidate_basis(deployment, cx)?;
    Ok(verified)
}
