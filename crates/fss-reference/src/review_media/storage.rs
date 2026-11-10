#![forbid(unsafe_code)]
//! Guarded root-last publication, cold readback and irreversible local grant withdrawal.

use super::record::{hex, slot, valid_digest};
use super::*;
use crate::deletion::DeletionIndex;
use fss_core::{BatchId, EvidenceDelta, ObjectId, Plane};
use fss_object::ObjectManifest;
use fss_publication::{
    LocalPublicationState, ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY,
    root_reachability_batch_id, root_reachability_object_id,
};

fn interval(record: &ReviewMediaRecord) -> CaptureInterval {
    CaptureInterval {
        earliest: record.grant().request().issued_at,
        latest: record.grant().request().expires_at,
    }
}
fn batch_id(record: &ReviewMediaRecord, revoked: bool) -> Result<BatchId, ReviewMediaError> {
    Ok(BatchId::parse(format!(
        "batch:review-media:{}:{}",
        hex(record.identity()),
        if revoked { "revoke" } else { "publish" }
    ))?)
}
fn publication_delta(record: &ReviewMediaRecord) -> Result<EvidenceDelta, ReviewMediaError> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:review-media:{}:publish", hex(record.identity())),
        family: FAMILY_REVIEW_MEDIA.into(),
        object_id: record.object_id()?,
        prior_generation: None,
        new_generation: 1,
        validity: interval(record),
        plane: Plane::Authority,
        payload_digest: record.root(),
        witness_digest: Some(record.digest()),
        operation_id: None,
    })
}
fn revocation_bytes(record: &ReviewMediaRecord) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.review_media_revocation.v1");
    e.digest(record.root());
    e.digest(record.digest());
    e.text(record.grant().owner().as_str());
    e.text(record.grant().site());
    e.text("local-grant-withdrawal:not-copy-recall:not-erasure");
    e.finish()
}
fn revocation_delta(record: &ReviewMediaRecord) -> Result<EvidenceDelta, ReviewMediaError> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:review-media:{}:revoke", hex(record.identity())),
        family: FAMILY_REVIEW_REVOCATION.into(),
        object_id: record.object_id()?,
        prior_generation: Some(1),
        new_generation: 2,
        validity: interval(record),
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(&revocation_bytes(record)),
        witness_digest: Some(record.root()),
        operation_id: None,
    })
}
fn publication_children(record: &ReviewMediaRecord) -> Vec<ContentDigest> {
    let mut children = vec![
        record.root(),
        record.digest(),
        record.media_digest(),
        record.render_receipt_digest(),
    ];
    children.sort_unstable();
    children.dedup();
    children
}

pub(super) fn not_deleted(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
) -> Result<(), ReviewMediaError> {
    let deleted = DeletionIndex::read(d).map_err(|_| ReviewMediaError::AuthorityChanged)?;
    if deleted
        .import(record.grant().request().import_identity)
        .is_some()
        || deleted.review(record.root()).is_some()
        || [
            record.root(),
            record.digest(),
            record.media_digest(),
            record.render_receipt_digest(),
            record.grant().request().import_root,
            record.source_manifest(),
        ]
        .into_iter()
        .any(|digest| deleted.object(digest).is_some())
        || deleted.unit_deleted(&format!("slot:{}", record.slot()?.as_str()))
    {
        return Err(ReviewMediaError::Deleted);
    }
    Ok(())
}

fn graph_record(
    d: &ReferenceDeployment,
    root: ContentDigest,
    cx: &ReplayCx,
) -> Result<ReviewMediaRecord, ReviewMediaError> {
    if !valid_digest(root) {
        return Err(ReviewMediaError::InvalidRequest);
    }
    checkpoint(cx, "review_media:read_record")?;
    let deleted = DeletionIndex::read(d).map_err(|_| ReviewMediaError::AuthorityChanged)?;
    if deleted.object(root).is_some() || deleted.review(root).is_some() {
        return Err(ReviewMediaError::Deleted);
    }
    let spool = d.publisher().spool();
    let manifest_bytes = spool.read_bounded(root, 1024)?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
    if manifest.root() != root
        || manifest.kind() != REVIEW_PROFILE
        || manifest.children().len() != 3
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    let record_digest = manifest
        .metadata_digest()
        .ok_or(ReviewMediaError::CustodyMismatch)?;
    let bytes = spool.read_bounded(record_digest, MAX_REVIEW_RECORD_BYTES)?;
    let record = ReviewMediaRecord::from_bytes(&bytes, record_digest)?;
    if record.root() != root
        || record.manifest()? != manifest
        || record.grant().site() != d.site_lineage()
        || d.publisher()
            .root(&record.slot()?)
            .is_none_or(|r| r.root != root)
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    not_deleted(d, &record)?;
    verify_preparation_basis(d, &record, cx)?;
    Ok(record)
}

/// Root publication owns the durable proof of the preparation head. A matching historical
/// anchor elsewhere is insufficient: it could predate source completion or mask declaration.
/// A root whose publication was interrupted before its reachability append has no such row;
/// it is recoverable only while its exact original preparation head remains current.
fn verify_preparation_basis(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
    cx: &ReplayCx,
) -> Result<(), ReviewMediaError> {
    let slot = record.slot()?;
    let object =
        root_reachability_object_id(&slot).map_err(|_| ReviewMediaError::CustodyMismatch)?;
    for batch in d.ledger().batches() {
        checkpoint(cx, "review_media:publication_basis")?;
        if !batch.deltas.iter().any(|delta| delta.object_id == object) {
            continue;
        }
        let expected = EvidenceDelta {
            delta_id: format!("{ROOT_REACHABILITY_DELTA_PREFIX}{slot}"),
            family: ROOT_REACHABILITY_FAMILY.into(),
            object_id: object,
            prior_generation: None,
            new_generation: 1,
            validity: interval(record),
            plane: Plane::Authority,
            payload_digest: record.root(),
            witness_digest: None,
            operation_id: None,
        };
        if batch.batch_id
            != root_reachability_batch_id(&slot).map_err(|_| ReviewMediaError::CustodyMismatch)?
            || batch.deltas.as_slice() != [expected]
            || batch.children != record.manifest()?.children()
            || &batch.basis_anchor != record.basis()
        {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        return Ok(());
    }
    if record.basis() != d.current_anchor() {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    Ok(())
}

/// Verify both the immutable issuance and any terminal withdrawal. An unrelated generation or
/// a disguised family in this namespace can never turn a revoked grant back into a live one.
fn state(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
    cx: &ReplayCx,
) -> Result<Option<bool>, ReviewMediaError> {
    state_through(d, record, cx, None)
}

/// After an approved expiry, the append-only issuance/withdrawal prefix remains inspectable.
/// This path is metadata-only: a deleted revocation payload is reconstructed deterministically
/// and matched to its ledger digest. It is never used to authorize media delivery.
fn state_through(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
    cx: &ReplayCx,
    through: Option<u64>,
) -> Result<Option<bool>, ReviewMediaError> {
    let object = record.object_id()?;
    let expected_publish = publication_delta(record)?;
    let expected_revoke = revocation_delta(record)?;
    let mut published = false;
    let mut revoked = false;
    for (position, batch) in d.ledger().batches().iter().enumerate() {
        if through.is_some_and(|last| position as u64 >= last) {
            break;
        }
        checkpoint(cx, "review_media:history")?;
        for delta in &batch.deltas {
            if delta.object_id != object {
                continue;
            }
            if !published
                && *delta == expected_publish
                && batch.batch_id == batch_id(record, false)?
                && batch.deltas.len() == 1
                && batch.children == publication_children(record)
            {
                published = true;
            } else if published
                && !revoked
                && *delta == expected_revoke
                && batch.batch_id == batch_id(record, true)?
                && batch.deltas.len() == 1
            {
                if through.is_none() {
                    let bytes = d
                        .publisher()
                        .spool()
                        .read_bounded(delta.payload_digest, MAX_REVIEW_RECORD_BYTES)?;
                    if bytes != revocation_bytes(record) {
                        return Err(ReviewMediaError::CustodyMismatch);
                    }
                }
                let mut expected = vec![record.root(), delta.payload_digest];
                expected.sort_unstable();
                if batch.children != expected {
                    return Err(ReviewMediaError::CustodyMismatch);
                }
                revoked = true;
            } else {
                return Err(ReviewMediaError::CustodyMismatch);
            }
        }
    }
    if through.is_some() {
        return Ok(published.then_some(revoked));
    }
    match d.ledger().current().objects.get(&object) {
        None if !published => Ok(None),
        Some(current) if published => {
            let expected = if revoked {
                expected_revoke
            } else {
                expected_publish
            };
            if current.family != expected.family
                || current.generation != expected.new_generation
                || current.payload_digest != expected.payload_digest
            {
                return Err(ReviewMediaError::CustodyMismatch);
            }
            Ok(Some(revoked))
        }
        _ => Err(ReviewMediaError::CustodyMismatch),
    }
}

pub(super) fn read_record(
    d: &ReferenceDeployment,
    root: ContentDigest,
    cx: &ReplayCx,
    allow_revoked: bool,
) -> Result<ReviewMediaRecord, ReviewMediaError> {
    let record = graph_record(d, root, cx)?;
    // The publisher's in-memory visibility is not a fresh proof that the durable root record
    // still exists. Missing or corrupt custody is not a committed deletion declaration.
    d.publisher()
        .require_durable_record(&record.slot()?)
        .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    match state(d, &record, cx)? {
        None => Err(ReviewMediaError::CustodyMismatch),
        Some(true) if !allow_revoked => Err(ReviewMediaError::Revoked),
        Some(_) => Ok(record),
    }
}

/// Read-only deletion-owner inspection of a currently retained issuance, including withdrawal.
pub(crate) fn inspect_for_expiry(
    d: &ReferenceDeployment,
    root: ContentDigest,
    cx: &ReplayCx,
) -> Result<ReviewMediaRecord, ReviewMediaError> {
    read_record(d, root, cx, true)
}

fn expired_record(
    d: &ReferenceDeployment,
    root: ContentDigest,
    cx: &ReplayCx,
) -> Result<Option<ReviewMediaRecord>, ReviewMediaError> {
    checkpoint(cx, "review_media:expiry_metadata")?;
    let deleted = DeletionIndex::read(d).map_err(|_| ReviewMediaError::AuthorityChanged)?;
    let Some(entry) = deleted.review(root) else {
        return Ok(None);
    };
    let crate::deletion::DeletionScope::ReviewExpiry(selection) = &entry.plan.scope else {
        return Err(ReviewMediaError::CustodyMismatch);
    };
    let candidate = selection
        .candidates()
        .iter()
        .find(|candidate| candidate.root() == root)
        .ok_or(ReviewMediaError::CustodyMismatch)?;
    let bytes = d
        .publisher()
        .spool()
        .read_bounded(candidate.record_digest(), MAX_REVIEW_RECORD_BYTES)?;
    let record = ReviewMediaRecord::from_bytes(&bytes, candidate.record_digest())?;
    if record.root() != root
        || record.identity() != candidate.identity()
        || record.grant().request().import_identity != candidate.import_identity()
        || record.grant().request().expires_at != candidate.expires_at()
        || &record.grant().request().sensor != selection.request().sensor()
        || record.grant().site() != d.site_lineage()
        || !entry.plan.retained.iter().any(|retained| {
            retained.digest == record.digest() && retained.reason == "review_expiry_audit_metadata"
        })
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    verify_preparation_basis(d, &record, cx)?;
    state_through(
        d,
        &record,
        cx,
        Some(entry.plan.basis_anchor.commit_sequence),
    )?
    .ok_or(ReviewMediaError::CustodyMismatch)?;
    Ok(Some(record))
}

fn read_receipt(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
) -> Result<Vec<u8>, ReviewMediaError> {
    let bytes = d.publisher().spool().read_bounded(
        record.render_receipt_digest(),
        usize::try_from(record.render_receipt_bytes()).map_err(|_| ReviewMediaError::Limit)?,
    )?;
    if bytes.len() as u64 != record.render_receipt_bytes() {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    Ok(bytes)
}
pub(super) fn read_media(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
    cx: &ReplayCx,
) -> Result<Vec<u8>, ReviewMediaError> {
    let _ = read_receipt(d, record)?;
    checkpoint(cx, "review_media:read_bytes")?;
    let bytes = d.publisher().spool().read_bounded(
        record.media_digest(),
        usize::try_from(record.media_bytes()).map_err(|_| ReviewMediaError::Limit)?,
    )?;
    if bytes.len() as u64 != record.media_bytes() {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    Ok(bytes)
}

pub(super) fn recover_preview(
    d: &ReferenceDeployment,
    identity: ContentDigest,
    request: &ReviewMediaRequest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<Option<ReviewMediaPreview>, ReviewMediaError> {
    let review_slot = slot(identity)?;
    let Some(visible) = d.publisher().root(&review_slot) else {
        let deleted = DeletionIndex::read(d).map_err(|_| ReviewMediaError::AuthorityChanged)?;
        if deleted.unit_deleted(&format!("slot:{review_slot}")) {
            return Err(ReviewMediaError::Deleted);
        }
        let object = ObjectId::parse(format!("{REVIEW_OBJECT_PREFIX}{}", hex(identity)))?;
        let root_object = root_reachability_object_id(&review_slot)
            .map_err(|_| ReviewMediaError::CustodyMismatch)?;
        if d.ledger().current().objects.contains_key(&object)
            || d.ledger().current().objects.contains_key(&root_object)
            || d.publisher().is_broken_slot(&review_slot)
        {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        return Ok(None);
    };
    let record = graph_record(d, visible.root, cx)?;
    if record.identity() != identity
        || record.request_digest() != request.digest()?
        || record.grant().request() != &request.access
        || record.authority() != authority_binding(a)
        || record.grant().owner().as_str() != a.principal
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    let already_committed = match state(d, &record, cx)? {
        Some(true) => return Err(ReviewMediaError::Revoked),
        Some(false) => true,
        None => false,
    };
    if already_committed || visible.state != LocalPublicationState::Staged {
        d.publisher()
            .require_durable_record(&review_slot)
            .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    }
    source_current(d, &record, cx)?;
    if !already_committed {
        // A visible root is not a native-rendering witness. The low-level publisher can stage
        // arbitrary graphs, so a crash between publication and guarded issuance must replay
        // the actual decoder/selector/mask path before that candidate can acquire authority.
        // Rendering receipts bind source authority; the enclosing record separately binds the
        // preparation head, allowing equality after this operation's root-reachability append.
        let rendered = render_movie(d, &request.movie, cx)
            .map_err(|e| ReviewMediaError::Render(Box::new(e)))?;
        record.verify_rendered(request, &rendered)?;
    }
    let render_receipt = read_receipt(d, &record)?;
    let media = read_media(d, &record, cx)?;
    checkpoint(cx, "review_media:retry_verified")?;
    Ok(Some(ReviewMediaPreview {
        record,
        media,
        render_receipt,
        already_committed,
    }))
}

pub(super) fn publish(
    d: &mut ReferenceDeployment,
    preview: ReviewMediaPreview,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewMediaReceipt, ReviewMediaError> {
    let record = &preview.record;
    let slot = record.slot()?;
    let manifest = record.manifest()?;
    if let Some(existing) = d.publisher().root(&slot) {
        if existing.root != record.root() {
            return Err(ReviewMediaError::CustodyMismatch);
        }
    } else {
        for (bytes, expected) in [
            (&preview.media[..], record.media_digest()),
            (&preview.render_receipt[..], record.render_receipt_digest()),
            (record.to_bytes(), record.digest()),
        ] {
            checkpoint(cx, "review_media:stage_child")?;
            if d.publisher_mut()
                .stage_object(bytes)
                .map_err(ReferenceError::from)?
                != expected
            {
                return Err(ReviewMediaError::CustodyMismatch);
            }
        }
        checkpoint(cx, "review_media:children_staged")?;
        if d.publisher_mut()
            .stage_manifest(&slot, &manifest)
            .map_err(ReferenceError::from)?
            != record.root()
        {
            return Err(ReviewMediaError::CustodyMismatch);
        }
    }
    // The exclusive deployment publisher prevents concurrent owners. Check durable history and
    // privacy again after all child writes and before making this graph reachable.
    authorize(d, a, cx, CAP_EXPORT_COMMIT)?;
    source_current(d, record, cx)?;
    d.publish_and_commit(&slot, &manifest, interval(record), cx)?;
    checkpoint(cx, "review_media:root_published")?;
    let anchor = d.append_review_media_batch(
        batch_id(record, false)?,
        vec![publication_delta(record)?],
        publication_children(record),
        cx,
    )?;
    cx.checkpoint_post_commit("review_media:committed");
    Ok(ReviewMediaReceipt {
        root: record.root(),
        anchor,
        published: true,
    })
}

/// Owner-only metadata inspection. Revoked/expired grants remain inspectable, never readable.
pub fn inspect_review_media(
    d: &ReferenceDeployment,
    root: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewMediaRecord, ReviewMediaError> {
    authorize(d, a, cx, CAP_EXPORT_PREPARE)?;
    let record = match expired_record(d, root, cx)? {
        Some(record) => record,
        None => read_record(d, root, cx, true)?,
    };
    if record.grant().owner().as_str() != a.principal || record.authority() != authority_binding(a)
    {
        return Err(ReviewMediaError::Unauthorized);
    }
    Ok(record)
}

/// Owner-visible current withdrawal state, separate from immutable issuance metadata.
pub fn review_grant_revoked(
    d: &ReferenceDeployment,
    root: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<bool, ReviewMediaError> {
    let record = inspect_review_media(d, root, a, cx)?;
    let deleted = DeletionIndex::read(d).map_err(|_| ReviewMediaError::AuthorityChanged)?;
    let through = deleted
        .review(root)
        .map(|entry| entry.plan.basis_anchor.commit_sequence);
    state_through(d, &record, cx, through)?.ok_or(ReviewMediaError::CustodyMismatch)
}

/// Prepare an exact local revocation. This never deletes source/derivative bytes or recalls copies.
pub fn revocation_approval(
    d: &ReferenceDeployment,
    root: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ContentDigest, ReviewMediaError> {
    let record = inspect_review_media(d, root, a, cx)?;
    not_deleted(d, &record)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.review_media_revoke_approval.v1");
    e.digest(record.root());
    e.digest(ContentDigest::sha256(&revocation_bytes(&record)));
    e.digest(authority_binding(a));
    // Revocation has one immutable terminal meaning. Keeping approval independent of unrelated
    // appends makes a lost-ack retry safe; it cannot select a different grant or revive access.
    Ok(ContentDigest::sha256(&e.finish()))
}

/// Irreversibly withdraw the exact local grant, with verified idempotent cold retries.
pub fn revoke_review_media(
    d: &mut ReferenceDeployment,
    root: ContentDigest,
    approval: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewRevocationReceipt, ReviewMediaError> {
    authorize(d, a, cx, CAP_EXPORT_COMMIT)?;
    let expected = revocation_approval(d, root, a, cx)?;
    if approval != expected {
        return Err(ReviewMediaError::StaleApproval);
    }
    let record = read_record(d, root, cx, true)?;
    if state(d, &record, cx)? == Some(true) {
        return Ok(ReviewRevocationReceipt {
            root,
            anchor: d.current_anchor().clone(),
            published: false,
        });
    }
    checkpoint(cx, "review_media:revoke_revalidated")?;
    let bytes = revocation_bytes(&record);
    let digest = d.stage_payload(&bytes)?;
    if digest != ContentDigest::sha256(&bytes) {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    let anchor = d.append_review_media_batch(
        batch_id(&record, true)?,
        vec![revocation_delta(&record)?],
        vec![root, digest],
        cx,
    )?;
    cx.checkpoint_post_commit("review_media:revoked");
    Ok(ReviewRevocationReceipt {
        root,
        anchor,
        published: true,
    })
}
