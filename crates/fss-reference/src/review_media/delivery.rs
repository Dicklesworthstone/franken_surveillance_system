#![forbid(unsafe_code)]
//! Durable, destination-bound local delivery of an existing screened review clip.
//!
//! A started operation is not evidence that a file exists or is complete. Only this owner's
//! bounded readback of a held regular file can publish a verified receipt. A retry keeps the
//! same operation identity while revalidating the caller's newly attested time. No function
//! here creates, replaces or deletes an output; the local output owner supplies and checks the
//! held destination. Receipt inspection discloses metadata only, including after revocation.

mod wire;

pub use wire::{
    MAX_DELIVERY_RECORD_BYTES, ReviewDeliveryFileIdentity, ReviewDeliveryRecord,
    ReviewDeliveryRecordError, ReviewDeliveryState,
};

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use fss_core::{
    BatchId, CanonicalEncoder, CaptureInterval, ContentDigest, ContextAuthority, DigestAlgorithm,
    EvidenceDelta, LedgerAnchor, ObjectId, OperationId, Plane, PrincipalId, Sha256Hasher,
};

use super::record::{hex, valid_digest};
use super::{
    CAP_REVIEW_MEDIA_READ, ReviewMediaError, ReviewMediaRecord, authority_binding, authorize,
    checkpoint, read_review_media, revalidate_review_media,
};
use crate::evidence_export::CAP_EXPORT_COMMIT;
use crate::{ReferenceDeployment, ReplayCx};
use wire::Completion;

/// Guarded authority family recording permission to begin one exact local delivery.
pub const FAMILY_REVIEW_DELIVERY_STARTED: &str = "review_media_delivery_started";
/// Guarded authority family recording complete local file readback, never remote receipt.
pub const FAMILY_REVIEW_DELIVERY_VERIFIED: &str = "review_media_delivery_verified";
/// Reserved object namespace; unrelated families cannot shadow a delivery record.
pub const DELIVERY_OBJECT_PREFIX: &str = "object:review-delivery:";
/// Last cancellable boundary before the started authority transition.
pub const STAGE_DELIVERY_BEGIN: &str = "review_delivery:begin";
/// A committed start exists; output may not yet exist.
pub const STAGE_DELIVERY_STARTED: &str = "review_delivery:started";
/// Bounded, actual file readback checkpoint.
pub const STAGE_DELIVERY_READBACK: &str = "review_delivery:readback";
/// Last cancellable seam before final source/destination revalidation and verification append.
pub const STAGE_DELIVERY_VERIFY: &str = "review_delivery:verify";
/// Durable local verification completed, including on a lost-response retry.
pub const STAGE_DELIVERY_VERIFIED: &str = "review_delivery:verified";

const READ_CHUNK: usize = 64 * 1024;

impl From<ReviewDeliveryRecordError> for ReviewMediaError {
    fn from(error: ReviewDeliveryRecordError) -> Self {
        match error {
            ReviewDeliveryRecordError::Contract(error) => error.into(),
            ReviewDeliveryRecordError::Limit => Self::Limit,
            ReviewDeliveryRecordError::Invalid => Self::CustodyMismatch,
        }
    }
}

impl ReviewDeliveryRecord {
    fn matches_review(&self, review: &ReviewMediaRecord) -> bool {
        self.review_root == review.root()
            && self.review_record == review.digest()
            && self.media_digest == review.media_digest()
            && self.media_bytes == review.media_bytes()
            && self.recipient == review.grant().request().recipient
    }

    fn same_start(&self, start: &Self) -> bool {
        self.identity == start.identity
            && self.site == start.site
            && self.recipient == start.recipient
            && self.review_root == start.review_root
            && self.review_record == start.review_record
            && self.media_digest == start.media_digest
            && self.media_bytes == start.media_bytes
            && self.destination == start.destination
            && self.reader_authority == start.reader_authority
            && self.started_at == start.started_at
    }
}

/// Read-only admission and current progress for one exact destination.
#[derive(Clone, Debug)]
pub struct ReviewDeliveryPreview {
    identity: ContentDigest,
    approval: ContentDigest,
    state: Option<ReviewDeliveryState>,
    record: ReviewMediaRecord,
}

impl ReviewDeliveryPreview {
    /// Stable operation identity; keep this for cold inspection.
    pub fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Approval binds the exact destination, current authority and attested interval.
    pub fn approval(&self) -> ContentDigest {
        self.approval
    }
    /// None means no durable attempt exists. It does not prove a destination is absent.
    pub fn state(&self) -> Option<ReviewDeliveryState> {
        self.state
    }
    /// Exact screened media and grant metadata.
    pub fn record(&self) -> &ReviewMediaRecord {
        &self.record
    }
}

/// Durable start, or verified replay of an existing operation.
#[derive(Clone, Debug)]
pub struct ReviewDeliveryProgress {
    /// Current canonical record.
    pub record: ReviewDeliveryRecord,
    /// True only for a newly committed start; an existing attempt must never recreate output.
    pub started: bool,
    /// Authority head after the verified transition/readback.
    pub anchor: LedgerAnchor,
}

/// Receipt after complete file verification. This never claims remote delivery or copy recall.
#[derive(Clone, Debug)]
pub struct ReviewDeliveryReceipt {
    /// Exact retained verification metadata.
    pub record: ReviewDeliveryRecord,
    /// False for an already terminal operation whose file was nevertheless reverified now.
    pub published: bool,
    /// Current authority head after readback and any new verification transition.
    pub anchor: LedgerAnchor,
}

fn identity(
    site: &str,
    recipient: &PrincipalId,
    review: &ReviewMediaRecord,
    destination: ContentDigest,
) -> ContentDigest {
    wire::delivery_identity(
        site,
        recipient,
        review.root(),
        review.digest(),
        review.media_digest(),
        review.media_bytes(),
        destination,
    )
}

fn object_id(identity: ContentDigest) -> Result<ObjectId, ReviewMediaError> {
    Ok(ObjectId::parse(format!(
        "{DELIVERY_OBJECT_PREFIX}{}",
        hex(identity)
    ))?)
}

fn operation_id(identity: ContentDigest) -> Result<OperationId, ReviewMediaError> {
    Ok(OperationId::parse(format!(
        "operation:review-delivery:{}",
        hex(identity)
    ))?)
}

fn batch_id(record: &ReviewDeliveryRecord) -> Result<BatchId, ReviewMediaError> {
    Ok(BatchId::parse(format!(
        "batch:review-delivery:{}:{}",
        hex(record.identity),
        if record.completion.is_some() {
            "verified"
        } else {
            "started"
        }
    ))?)
}

fn delta(record: &ReviewDeliveryRecord) -> Result<EvidenceDelta, ReviewMediaError> {
    let (family, prior, generation, validity, witness) = match &record.completion {
        None => (
            FAMILY_REVIEW_DELIVERY_STARTED,
            None,
            1,
            record.started_at,
            record.digest(),
        ),
        Some(c) => (
            FAMILY_REVIEW_DELIVERY_VERIFIED,
            Some(1),
            2,
            c.now,
            c.started_record,
        ),
    };
    Ok(EvidenceDelta {
        delta_id: format!(
            "delta:review-delivery:{}:{generation}",
            hex(record.identity)
        ),
        family: family.into(),
        object_id: object_id(record.identity)?,
        prior_generation: prior,
        new_generation: generation,
        validity,
        plane: Plane::Authority,
        payload_digest: record.digest(),
        witness_digest: Some(witness),
        operation_id: Some(operation_id(record.identity)?),
    })
}

fn children(record: &ReviewDeliveryRecord) -> Vec<ContentDigest> {
    // These are audit metadata only. Direct media/root children would pin deleted footage.
    let mut result = vec![record.digest()];
    if let Some(c) = &record.completion {
        result.push(c.started_record);
    }
    result.sort_unstable();
    result.dedup();
    result
}

fn load(
    d: &ReferenceDeployment,
    identity: ContentDigest,
    cx: &ReplayCx,
) -> Result<Option<ReviewDeliveryRecord>, ReviewMediaError> {
    if !valid_digest(identity) {
        return Err(ReviewMediaError::InvalidRequest);
    }
    let object = object_id(identity)?;
    let mut record: Option<ReviewDeliveryRecord> = None;
    for batch in d.ledger().batches() {
        checkpoint(cx, "review_delivery:history")?;
        for entry in &batch.deltas {
            if entry.object_id != object {
                continue;
            }
            let bytes = d
                .publisher()
                .spool()
                .read_bounded(entry.payload_digest, MAX_DELIVERY_RECORD_BYTES)?;
            let candidate = ReviewDeliveryRecord::from_bytes(&bytes, entry.payload_digest)?;
            if candidate.identity != identity
                || candidate.site != d.site_lineage()
                || candidate.basis != batch.basis_anchor
                || batch.batch_id != batch_id(&candidate)?
                || batch.deltas.as_slice() != [delta(&candidate)?]
                || batch.children != children(&candidate)
            {
                return Err(ReviewMediaError::CustodyMismatch);
            }
            match (&record, &candidate.completion) {
                (None, None) => {}
                (Some(start), Some(done))
                    if start.completion.is_none()
                        && candidate.same_start(start)
                        && done.started_record == start.digest() => {}
                _ => return Err(ReviewMediaError::CustodyMismatch),
            }
            record = Some(candidate);
        }
    }
    match (&record, d.ledger().current().objects.get(&object)) {
        (None, None) => Ok(None),
        (Some(value), Some(current)) => {
            let expected = delta(value)?;
            if current.family != expected.family
                || current.generation != expected.new_generation
                || current.payload_digest != expected.payload_digest
            {
                return Err(ReviewMediaError::CustodyMismatch);
            }
            Ok(record)
        }
        _ => Err(ReviewMediaError::CustodyMismatch),
    }
}

/// Inspect the exact recipient's audit metadata, even after grant expiry, revocation or deletion.
/// This verifies guarded history and does not authorize release or read any media bytes.
pub fn inspect_review_delivery(
    d: &ReferenceDeployment,
    identity: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<Option<ReviewDeliveryRecord>, ReviewMediaError> {
    authorize(d, a, cx, CAP_REVIEW_MEDIA_READ)?;
    let value = load(d, identity, cx)?;
    if value
        .as_ref()
        .is_some_and(|r| r.recipient.as_str() != a.principal)
    {
        return Err(ReviewMediaError::Unauthorized);
    }
    Ok(value)
}

/// Read-only current grant admission and exact approval. No delivery state or file is created.
pub fn prepare_review_delivery(
    d: &ReferenceDeployment,
    root: ContentDigest,
    destination: ContentDigest,
    now: CaptureInterval,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewDeliveryPreview, ReviewMediaError> {
    if !valid_digest(destination) {
        return Err(ReviewMediaError::InvalidRequest);
    }
    let media = read_review_media(d, root, now, a, cx)?;
    let recipient = PrincipalId::parse(a.principal.clone())?;
    let id = identity(d.site_lineage(), &recipient, media.record(), destination);
    let existing = inspect_review_delivery(d, id, a, cx)?;
    if existing
        .as_ref()
        .is_some_and(|r| !r.matches_review(media.record()))
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    if existing
        .as_ref()
        .is_some_and(|r| r.reader_authority != authority_binding(a))
    {
        return Err(ReviewMediaError::StaleApproval);
    }
    revalidate_review_media(d, &media, now, a, cx)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.review_delivery_approval.v1");
    e.digest(id);
    e.digest(authority_binding(a));
    e.i128(now.earliest.0);
    e.i128(now.latest.0);
    Ok(ReviewDeliveryPreview {
        identity: id,
        approval: ContentDigest::sha256(&e.finish()),
        state: existing.as_ref().map(ReviewDeliveryRecord::state),
        record: media.record().clone(),
    })
}

/// Commit one attempt before file creation. Existing Started operations require reconciliation;
/// neither this API nor a fresh time assertion authorizes recreating a missing/partial output.
pub fn begin_review_delivery(
    d: &mut ReferenceDeployment,
    root: ContentDigest,
    destination: ContentDigest,
    now: CaptureInterval,
    approval: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewDeliveryProgress, ReviewMediaError> {
    authorize(d, a, cx, CAP_EXPORT_COMMIT)?;
    let prepared = prepare_review_delivery(d, root, destination, now, a, cx)?;
    if approval != prepared.approval {
        return Err(ReviewMediaError::StaleApproval);
    }
    if let Some(record) = inspect_review_delivery(d, prepared.identity, a, cx)? {
        return Ok(ReviewDeliveryProgress {
            record,
            started: false,
            anchor: d.current_anchor().clone(),
        });
    }
    let mut record = ReviewDeliveryRecord {
        identity: prepared.identity,
        site: d.site_lineage().into(),
        recipient: PrincipalId::parse(a.principal.clone())?,
        review_root: root,
        review_record: prepared.record.digest(),
        media_digest: prepared.record.media_digest(),
        media_bytes: prepared.record.media_bytes(),
        destination,
        reader_authority: authority_binding(a),
        started_at: now,
        basis: d.current_anchor().clone(),
        completion: None,
        wire: Vec::new(),
    };
    record.seal()?;
    checkpoint(cx, STAGE_DELIVERY_BEGIN)?;
    let anchor = append(d, &record, cx)?;
    cx.checkpoint_post_commit(STAGE_DELIVERY_STARTED);
    Ok(ReviewDeliveryProgress {
        record,
        started: true,
        anchor,
    })
}

fn append(
    d: &mut ReferenceDeployment,
    record: &ReviewDeliveryRecord,
    cx: &ReplayCx,
) -> Result<LedgerAnchor, ReviewMediaError> {
    if d.current_anchor() != &record.basis {
        return Err(ReviewMediaError::AuthorityChanged);
    }
    if d.stage_payload(record.to_bytes())? != record.digest() {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    Ok(d.append_review_delivery_batch(
        batch_id(record)?,
        vec![delta(record)?],
        children(record),
        cx,
    )?)
}

/// Verify the actual held file and publish a receipt only after current source, privacy,
/// recipient, expiry and destination checks. The callback is the output owner's protected
/// pathname/inode check and runs before readback and immediately before the guarded append.
/// A completed retry repeats verification and never grants authority to emit media again.
pub fn verify_review_delivery(
    d: &mut ReferenceDeployment,
    identity: ContentDigest,
    destination: ContentDigest,
    now: CaptureInterval,
    file: &mut File,
    check_destination: &mut impl FnMut(&File) -> Result<(), ReviewMediaError>,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewDeliveryReceipt, ReviewMediaError> {
    authorize(d, a, cx, CAP_EXPORT_COMMIT)?;
    let prior =
        inspect_review_delivery(d, identity, a, cx)?.ok_or(ReviewMediaError::InvalidRequest)?;
    if prior.destination != destination || prior.reader_authority != authority_binding(a) {
        return Err(ReviewMediaError::StaleApproval);
    }
    if now.earliest < prior.started_at.earliest || now.latest < prior.started_at.latest {
        return Err(ReviewMediaError::InvalidRequest);
    }
    let media = read_review_media(d, prior.review_root, now, a, cx)?;
    if !prior.matches_review(media.record()) {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    checkpoint(cx, STAGE_DELIVERY_READBACK)?;
    check_destination(file)?;
    file.sync_all()
        .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    let before = file_snapshot(file, prior.media_bytes)?;
    if prior.completion.as_ref().is_some_and(|c| {
        c.file != before.identity || c.modified != before.modified || c.changed != before.changed
    }) {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    let mut hash = Sha256Hasher::new();
    let mut buffer = [0_u8; READ_CHUNK];
    let mut remaining = prior.media_bytes;
    while remaining > 0 {
        checkpoint(cx, STAGE_DELIVERY_READBACK)?;
        let wanted = usize::try_from(remaining.min(READ_CHUNK as u64))
            .map_err(|_| ReviewMediaError::Limit)?;
        let count = file
            .read(&mut buffer[..wanted])
            .map_err(|_| ReviewMediaError::CustodyMismatch)?;
        if count == 0 {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    checkpoint(cx, STAGE_DELIVERY_READBACK)?;
    if file
        .read(&mut buffer[..1])
        .map_err(|_| ReviewMediaError::CustodyMismatch)?
        != 0
        || ContentDigest::new(DigestAlgorithm::Sha256, hash.finalize()?) != prior.media_digest
        || file_snapshot(file, prior.media_bytes)? != before
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    // Complete explicit cancellation and admission before the final destination checks.
    checkpoint(cx, STAGE_DELIVERY_VERIFY)?;
    authorize(d, a, cx, CAP_EXPORT_COMMIT)?;
    revalidate_review_media(d, &media, now, a, cx)?;
    // A descriptor's content match does not replace the path owner's current destination check.
    check_destination(file)?;
    if file_snapshot(file, prior.media_bytes)? != before {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    if prior.completion.is_some() {
        return Ok(ReviewDeliveryReceipt {
            record: prior,
            published: false,
            anchor: d.current_anchor().clone(),
        });
    }
    let started_record = prior.digest();
    let mut record = prior;
    record.basis = d.current_anchor().clone();
    record.completion = Some(Completion {
        started_record,
        now,
        file: before.identity,
        modified: before.modified,
        changed: before.changed,
    });
    record.seal()?;
    let anchor = append(d, &record, cx)?;
    cx.checkpoint_post_commit(STAGE_DELIVERY_VERIFIED);
    Ok(ReviewDeliveryReceipt {
        record,
        published: true,
        anchor,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: ReviewDeliveryFileIdentity,
    modified: (i64, u32),
    changed: (i64, u32),
    owner: u32,
    mode: u32,
}

#[cfg(unix)]
fn file_snapshot(file: &File, bytes: u64) -> Result<FileSnapshot, ReviewMediaError> {
    use std::os::unix::fs::MetadataExt;
    let m = file
        .metadata()
        .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    if !m.is_file()
        || m.len() != bytes
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || !(0..1_000_000_000).contains(&m.mtime_nsec())
        || !(0..1_000_000_000).contains(&m.ctime_nsec())
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    Ok(FileSnapshot {
        identity: ReviewDeliveryFileIdentity {
            device: m.dev(),
            inode: m.ino(),
        },
        modified: (m.mtime(), m.mtime_nsec() as u32),
        changed: (m.ctime(), m.ctime_nsec() as u32),
        owner: m.uid(),
        mode: m.mode(),
    })
}

#[cfg(not(unix))]
fn file_snapshot(_file: &File, _bytes: u64) -> Result<FileSnapshot, ReviewMediaError> {
    Err(ReviewMediaError::InvalidRequest)
}
