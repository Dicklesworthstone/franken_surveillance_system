#![forbid(unsafe_code)]
//! Retained, privacy-screened movie derivatives with exact local reviewer grants.
//!
//! Preparation renders through the existing native source and privacy owners. Publication binds
//! the clip, rendering receipt and grant in one root-last object graph. A root is an identity,
//! not a capability: every read checks current recipient authority, expiry, privacy, revocation
//! and deletion. This local profile is not FLDT authentication or payment-mask attestation.

pub mod delivery;
pub mod grant;
mod record;
pub mod render;
mod storage;

use std::fmt;

use fss_core::region::ContextAuthority;
use fss_core::{CanonicalEncoder, CaptureInterval, ContentDigest, ContractError, LedgerAnchor};
use fss_object::{ObjectError, SpoolError};

use crate::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE};
use crate::ingest::privacy_mask::{PrivacyMaskError, current_mask};
use crate::ingest::{FileIngestError, RetainedFileImport};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};
use grant::{GrantError, ReviewAccessRequest, ReviewGrant};
use render::{ReviewMovieRequest, render_movie};

pub use record::{MAX_REVIEW_RECORD_BYTES, ReviewMediaRecord};
pub(crate) use storage::inspect_for_expiry;
pub use storage::{
    inspect_review_media, review_grant_revoked, revocation_approval, revoke_review_media,
};

/// Guarded authority family of a retained review clip and its grant.
pub const FAMILY_REVIEW_MEDIA: &str = "review_media";
/// Guarded terminal withdrawal of one exact review grant; never a deletion claim.
pub const FAMILY_REVIEW_REVOCATION: &str = "review_media_revocation";
/// Reserved namespace shared by active and revoked generations.
pub const REVIEW_OBJECT_PREFIX: &str = "object:review-media:";
/// Portable graph profile; the original video is never a manifest child.
pub const REVIEW_PROFILE: &str = "screened-movie-local-review-v1";
/// Positive media-read capability, distinct from export preparation and commitment.
pub const CAP_REVIEW_MEDIA_READ: &str = "CAP-READ-MEDIA-001";
/// Bound on authority history inspected by a review request.
pub const MAX_REVIEW_BATCHES: usize = 65_536;

/// Exact rendering controls and disclosure scope. Changing either requires a new approval.
#[derive(Clone, Debug)]
pub struct ReviewMediaRequest {
    /// Existing native movie timeline selection, decode and allocation bounds.
    pub movie: ReviewMovieRequest,
    /// Exact source, recipient, privacy generation, purpose and validity.
    pub access: ReviewAccessRequest,
}
impl ReviewMediaRequest {
    /// Reject inconsistent selections and output limits before source access.
    pub fn validate(&self) -> Result<(), ReviewMediaError> {
        self.access.validate()?;
        self.movie
            .validate()
            .map_err(|e| ReviewMediaError::Render(Box::new(e)))?;
        if self.access.import_identity != self.movie.import_identity
            || self.access.movie_start_tick != self.movie.movie_start_tick
            || self.access.movie_end_tick != self.movie.movie_end_tick
            || self.movie.limits.max_output_bytes > self.access.maximum_media_bytes
        {
            return Err(ReviewMediaError::InvalidRequest);
        }
        Ok(())
    }
    /// Canonical identity of all rendering controls and disclosure coordinates.
    pub fn digest(&self) -> Result<ContentDigest, ReviewMediaError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.review_media_request.v1");
        e.digest(self.access.digest()?);
        e.bytes(&self.movie.canonical_bytes());
        Ok(ContentDigest::sha256(&e.finish()))
    }
}

/// Complete, private preparation. Only metadata is exposed before commitment.
#[derive(Debug)]
pub struct ReviewMediaPreview {
    record: ReviewMediaRecord,
    media: Vec<u8>,
    render_receipt: Vec<u8>,
    already_committed: bool,
}
impl ReviewMediaPreview {
    /// Final root identity, independently useful for later readback.
    pub fn root(&self) -> ContentDigest {
        self.record.root()
    }
    /// Exact approval; it binds source, recipient, time, masks, bytes and render controls.
    pub fn approval(&self) -> ContentDigest {
        self.record.approval()
    }
    /// Byte-free, typed custody record.
    pub fn record(&self) -> &ReviewMediaRecord {
        &self.record
    }
    /// True only when the guarded authority row and complete custody already verify.
    pub fn already_committed(&self) -> bool {
        self.already_committed
    }
}

/// Successful local publication, not a remote delivery or production-qualification claim.
#[derive(Clone, Debug)]
pub struct ReviewMediaReceipt {
    /// Published immutable graph.
    pub root: ContentDigest,
    /// Exact authority anchor after publication.
    pub anchor: LedgerAnchor,
    /// False for an exact verified retry.
    pub published: bool,
}

/// Terminal local grant withdrawal; existing copies cannot be recalled by this operation.
#[derive(Clone, Debug)]
pub struct ReviewRevocationReceipt {
    /// Withdrawn review graph.
    pub root: ContentDigest,
    /// Exact authority anchor of the terminal transition.
    pub anchor: LedgerAnchor,
    /// False for an already verified withdrawal.
    pub published: bool,
}

/// A currently authorized local read; callers must revalidate before releasing output.
#[derive(Debug)]
pub struct ReviewedMedia {
    record: ReviewMediaRecord,
    bytes: Vec<u8>,
    read_anchor: LedgerAnchor,
    reader_binding: ContentDigest,
}
impl ReviewedMedia {
    /// Screened video-only Matroska bytes; no source video is exposed.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Canonical disclosure and lineage metadata.
    pub fn record(&self) -> &ReviewMediaRecord {
        &self.record
    }
    /// Independent graph identity.
    pub fn root(&self) -> ContentDigest {
        self.record.root()
    }
    /// Digest of the exact screened bytes.
    pub fn media_digest(&self) -> ContentDigest {
        self.record.media_digest()
    }
}

/// Typed refusal; no error returns partial media or silently broadens a grant.
#[derive(Debug)]
pub enum ReviewMediaError {
    /// Inconsistent, malformed or unsupported request.
    InvalidRequest,
    /// Missing current explicit authority or scope.
    Unauthorized,
    /// Approval differs from the exact prepared operation.
    StaleApproval,
    /// Authority changed or cannot be verified.
    AuthorityChanged,
    /// Stored canonical graph, record or bytes do not match.
    CustodyMismatch,
    /// A current privacy generation differs from the rendered generation.
    PrivacyChanged,
    /// The grant has been durably withdrawn.
    Revoked,
    /// A committed deletion covers the source or derivative, even before unlink completes.
    Deleted,
    /// An explicit history, record or allocation bound was exceeded.
    Limit,
    /// Cooperative cancellation.
    Cancelled,
    /// Grant owner refusal.
    Grant(GrantError),
    /// Native source/decoder/timeline owner refusal.
    Render(Box<dyn std::error::Error>),
    /// Source custody owner refusal.
    Source(Box<FileIngestError>),
    /// Privacy policy owner refusal.
    Privacy(PrivacyMaskError),
    /// Canonical format refusal.
    Contract(ContractError),
    /// Manifest refusal.
    Object(ObjectError),
    /// Spool refusal.
    Spool(SpoolError),
    /// Durable publication refusal or indeterminate append; reopen before retrying.
    Reference(Box<ReferenceError>),
}
impl ReviewMediaError {
    /// Existing registered export/error identity; reasons preserve the narrower failure.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::InvalidRequest => "ERR-EXPORT-REQUEST-001",
            Self::StaleApproval | Self::AuthorityChanged => "ERR-EXPORT-APPROVAL-STALE-001",
            Self::PrivacyChanged => "ERR-PRIVACY-MASK-001",
            Self::Revoked => "ERR-AUTH-DENIED-001",
            Self::Deleted => "ERR-EVIDENCE-DELETED-001",
            Self::Limit => "ERR-EXPORT-BOUND-001",
            Self::Cancelled => "ERR-EXPORT-CANCELLED-001",
            Self::Grant(e) => e.stable_id(),
            Self::Privacy(e) => e.stable_id(),
            _ => "ERR-EXPORT-CUSTODY-001",
        }
    }
    /// Bounded stable diagnostic; arbitrary source bytes never enter the message.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_review_request",
            Self::Unauthorized => "review_authority_denied",
            Self::StaleApproval => "review_approval_mismatch",
            Self::AuthorityChanged => "review_authority_changed",
            Self::CustodyMismatch => "review_custody_mismatch",
            Self::PrivacyChanged => "review_privacy_changed",
            Self::Revoked => "review_grant_revoked",
            Self::Deleted => "review_or_source_deleted",
            Self::Limit => "review_bound_exceeded",
            Self::Cancelled => "review_cancelled",
            Self::Grant(_) => "review_grant_refused",
            Self::Render(_) => "native_movie_render_refused",
            Self::Source(_) => "review_source_refused",
            Self::Privacy(_) => "review_privacy_refused",
            Self::Contract(_) | Self::Object(_) | Self::Spool(_) => "review_custody_refused",
            Self::Reference(_) => "review_publication_refused_or_indeterminate",
        }
    }
}
impl fmt::Display for ReviewMediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stable_id(), self.reason())
    }
}
impl std::error::Error for ReviewMediaError {}
macro_rules! from_error {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for ReviewMediaError {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
    ($ty:ty, $variant:ident, boxed) => {
        impl From<$ty> for ReviewMediaError {
            fn from(value: $ty) -> Self {
                Self::$variant(Box::new(value))
            }
        }
    };
}
from_error!(GrantError, Grant);
from_error!(ContractError, Contract);
from_error!(ObjectError, Object);
from_error!(SpoolError, Spool);
from_error!(PrivacyMaskError, Privacy);
from_error!(FileIngestError, Source, boxed);
from_error!(ReferenceError, Reference, boxed);

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), ReviewMediaError> {
    cx.checkpoint(stage)
        .map_err(|_| ReviewMediaError::Cancelled)
}

fn authority_binding(authority: &ContextAuthority) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.review_media_authority.v1");
    e.text(&authority.principal);
    e.text(&authority.privacy_scope);
    e.text(&authority.retention_scope);
    e.digest(authority.anchor_universe);
    e.u64(authority.generation);
    ContentDigest::sha256(&e.finish())
}

fn authorize(
    d: &ReferenceDeployment,
    a: &ContextAuthority,
    cx: &ReplayCx,
    cap: &str,
) -> Result<(), ReviewMediaError> {
    a.validate()?;
    checkpoint(cx, "review_media:authority")?;
    if !a.has_capability(cap)
        || a.cancellation_reason.is_some()
        || a.deadline.is_some()
        || a.principal != cx.io_authority().principal()
        || cx.root_dir() != d.root()
        || a.anchor_universe != ContentDigest::sha256(d.site_lineage().as_bytes())
        || d.ledger().batches().len() > MAX_REVIEW_BATCHES
    {
        return Err(ReviewMediaError::Unauthorized);
    }
    d.ledger()
        .verify_durable_head()
        .map_err(|_| ReviewMediaError::AuthorityChanged)?;
    Ok(())
}

fn source_current(
    d: &ReferenceDeployment,
    record: &ReviewMediaRecord,
    cx: &ReplayCx,
) -> Result<(), ReviewMediaError> {
    storage::not_deleted(d, record)?;
    let request = record.grant().request();
    // Retained metadata can outlive the publisher's last observed root record. Delivery must
    // prove current on-disk source custody as well as the derivative's own durable root.
    let source_slot =
        fss_publication::SlotName::parse(&format!("fi-{}", record::hex(request.import_identity)))
            .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    d.publisher()
        .require_durable_record(&source_slot)
        .map_err(|_| ReviewMediaError::CustodyMismatch)?;
    let retained = RetainedFileImport::open(d, request.import_identity, record.read_limits(), cx)?;
    if retained.import_root() != request.import_root
        || retained.manifest_digest() != record.source_manifest()
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    let mask = current_mask(d, &request.sensor)?;
    if mask.digest() != request.expected_privacy || mask.generation() != record.privacy_generation()
    {
        return Err(ReviewMediaError::PrivacyChanged);
    }
    Ok(())
}

/// Prepare a bounded screened clip without writing media, grants, roots or authority.
pub fn prepare_review_media(
    d: &ReferenceDeployment,
    request: &ReviewMediaRequest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewMediaPreview, ReviewMediaError> {
    authorize(d, a, cx, CAP_EXPORT_PREPARE)?;
    request.validate()?;
    if !a.has_capability(CAP_REVIEW_MEDIA_READ)
        || a.budgets.bytes < request.access.maximum_media_bytes
    {
        return Err(ReviewMediaError::Unauthorized);
    }
    let identity = record::request_identity(request.digest()?, a, d.site_lineage());
    if let Some(preview) = storage::recover_preview(d, identity, request, a, cx)? {
        return Ok(preview);
    }
    let rendered =
        render_movie(d, &request.movie, cx).map_err(|e| ReviewMediaError::Render(Box::new(e)))?;
    if rendered.source_import_root() != request.access.import_root
        || rendered.sensor() != &request.access.sensor
        || rendered.privacy().digest() != request.access.expected_privacy
        || rendered.bytes().len() as u64 > request.access.maximum_media_bytes
    {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    let grant = ReviewGrant::prepare(
        request.access.clone(),
        a,
        d.site_lineage(),
        rendered.receipt_digest(),
    )?;
    let record = ReviewMediaRecord::new(identity, request, grant, &rendered, authority_binding(a))?;
    // The renderer has completed the source's full EOF and current-mask revalidation; the
    // approval additionally requires its current durable source root. Nothing persists here.
    source_current(d, &record, cx)?;
    let (media, render_receipt) = rendered.into_parts();
    checkpoint(cx, "review_media:prepared")?;
    Ok(ReviewMediaPreview {
        record,
        media,
        render_receipt,
        already_committed: false,
    })
}

/// Recompute the exact preparation, revalidate, and retain the screened graph root last.
pub fn commit_review_media(
    d: &mut ReferenceDeployment,
    request: &ReviewMediaRequest,
    approval: ContentDigest,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewMediaReceipt, ReviewMediaError> {
    authorize(d, a, cx, CAP_EXPORT_COMMIT)?;
    let preview = prepare_review_media(d, request, a, cx)?;
    if preview.approval() != approval {
        return Err(ReviewMediaError::StaleApproval);
    }
    if preview.already_committed {
        return Ok(ReviewMediaReceipt {
            root: preview.root(),
            anchor: d.current_anchor().clone(),
            published: false,
        });
    }
    source_current(d, &preview.record, cx)?;
    checkpoint(cx, "review_media:revalidated")?;
    storage::publish(d, preview, a, cx)
}

/// Open only the exact retained derivative authorized for this recipient and time interval.
pub fn read_review_media(
    d: &ReferenceDeployment,
    root: ContentDigest,
    now: CaptureInterval,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<ReviewedMedia, ReviewMediaError> {
    authorize(d, a, cx, CAP_REVIEW_MEDIA_READ)?;
    let record = storage::read_record(d, root, cx, false)?;
    record.grant().authorize_reader(
        a,
        d.site_lineage(),
        record.render_receipt_digest(),
        record.grant().request().expected_privacy,
        now,
        false,
    )?;
    source_current(d, &record, cx)?;
    if a.budgets.bytes < record.media_bytes() {
        return Err(ReviewMediaError::Limit);
    }
    let bytes = storage::read_media(d, &record, cx)?;
    let result = ReviewedMedia {
        record,
        bytes,
        read_anchor: d.current_anchor().clone(),
        reader_binding: authority_binding(a),
    };
    revalidate_review_media(d, &result, now, a, cx)?;
    Ok(result)
}

/// Final release check for an output adapter, including in-memory bytes and current authority.
pub fn revalidate_review_media(
    d: &ReferenceDeployment,
    media: &ReviewedMedia,
    now: CaptureInterval,
    a: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(), ReviewMediaError> {
    authorize(d, a, cx, CAP_REVIEW_MEDIA_READ)?;
    if d.current_anchor() != &media.read_anchor || authority_binding(a) != media.reader_binding {
        return Err(ReviewMediaError::AuthorityChanged);
    }
    let current = storage::read_record(d, media.root(), cx, false)?;
    if a.budgets.bytes < current.media_bytes() {
        return Err(ReviewMediaError::Limit);
    }
    if current != media.record || ContentDigest::sha256(&media.bytes) != current.media_digest() {
        return Err(ReviewMediaError::CustodyMismatch);
    }
    source_current(d, &current, cx)?;
    current.grant().authorize_reader(
        a,
        d.site_lineage(),
        current.render_receipt_digest(),
        current.grant().request().expected_privacy,
        now,
        false,
    )?;
    checkpoint(cx, "review_media:release")
}
