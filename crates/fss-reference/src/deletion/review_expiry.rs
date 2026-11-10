#![forbid(unsafe_code)]
//! Exact, owner-approved cleanup of expired local review derivatives.
//!
//! The immutable grant supplies the expiry; the owner supplies a bounded current-time
//! assertion. Only certainly expired reviews are eligible. Original imports are never
//! members of this scope. Holds, shared objects and the normal tombstone-first deletion
//! protocol still apply. This module supplies no clock, scheduler or standing authority.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, SensorId, TimestampNs,
};

use super::{CommitReceipt, DeletionError, DeletionIndex, DeletionPlan, DeletionScope, Finding};
use crate::review_media::{
    FAMILY_REVIEW_MEDIA, MAX_REVIEW_BATCHES, MAX_REVIEW_RECORD_BYTES, ReviewMediaError,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Canonical selection embedded in v4 deletion plans.
pub const REVIEW_EXPIRY_SELECTION_DOMAIN: &str = "fss.review_expiry_selection.v1";
/// Maximum retained reviews inspected, including reviews of other sensors.
pub const MAX_REVIEW_EXPIRY_REVIEWS: usize = 256;
/// Maximum ledger entries inspected during inventory. Overflow refuses without truncation.
pub const MAX_REVIEW_EXPIRY_LEDGER_ENTRIES: usize = 1_000_000;
/// Maximum findings across all excluded closures.
pub const MAX_REVIEW_EXPIRY_BLOCKERS: usize = 4096;
const MAX_BLOCKER_TEXT_BYTES: usize = 4096;
/// Cooperative inventory checkpoint.
pub const STAGE_REVIEW_EXPIRY_READ: &str = "review_expiry:read";
/// Cooperative closure-assessment checkpoint.
pub const STAGE_REVIEW_EXPIRY_COHORT: &str = "review_expiry:cohort";

/// One explicit request. Time is an owner assertion in the grant's clock coordinates.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReviewExpiryRequest {
    sensor: SensorId,
    now_earliest_ns: i128,
    now_latest_ns: i128,
}

impl ReviewExpiryRequest {
    /// Validate the time interval before accessing custody.
    pub fn new(sensor: SensorId, attested_now: CaptureInterval) -> Result<Self, DeletionError> {
        CaptureInterval::new(attested_now.earliest, attested_now.latest)?;
        Ok(Self {
            sensor,
            now_earliest_ns: attested_now.earliest.0,
            now_latest_ns: attested_now.latest.0,
        })
    }
    /// Exact source sensor of the derivative grants.
    #[must_use]
    pub fn sensor(&self) -> &SensorId {
        &self.sensor
    }
    /// Explicit current-time bounds; no host clock is consulted.
    #[must_use]
    pub fn attested_now(&self) -> CaptureInterval {
        CaptureInterval {
            earliest: TimestampNs(self.now_earliest_ns),
            latest: TimestampNs(self.now_latest_ns),
        }
    }
    fn classify(&self, expiry: TimestampNs) -> ReviewExpiryDisposition {
        if self.now_earliest_ns >= expiry.0 {
            ReviewExpiryDisposition::Expired
        } else if self.now_latest_ns < expiry.0 {
            ReviewExpiryDisposition::NotDue
        } else {
            ReviewExpiryDisposition::ExpiryUncertain
        }
    }
    fn encode(&self, e: &mut CanonicalEncoder) {
        self.sensor.encode_canonical(e);
        TimestampNs(self.now_earliest_ns).encode_canonical(e);
        TimestampNs(self.now_latest_ns).encode_canonical(e);
    }
    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        let sensor = SensorId::decode_canonical(d)?;
        let earliest = TimestampNs::decode_canonical(d)?;
        let latest = TimestampNs::decode_canonical(d)?;
        Self::new(sensor, CaptureInterval::new(earliest, latest)?)
    }
}

/// Why a retained local review is selected or retained.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReviewExpiryDisposition {
    /// Every possible asserted current time is at or after the immutable grant expiry.
    Expired,
    /// The entire asserted interval precedes expiry.
    NotDue,
    /// The assertion overlaps expiry; retain until it is certainly expired.
    ExpiryUncertain,
    /// Certainly expired, but adding its closure would violate a hold or another constraint.
    ClosureBlocked,
}

impl ReviewExpiryDisposition {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::NotDue => "not_due",
            Self::ExpiryUncertain => "expiry_uncertain",
            Self::ClosureBlocked => "closure_blocked",
        }
    }
    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        match d.text()? {
            "expired" => Ok(Self::Expired),
            "not_due" => Ok(Self::NotDue),
            "expiry_uncertain" => Ok(Self::ExpiryUncertain),
            "closure_blocked" => Ok(Self::ClosureBlocked),
            _ => Err(DeletionError::RecordMismatch),
        }
    }
}

/// Immutable review metadata and its decision. No source media is embedded.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReviewExpiryCandidate {
    root: ContentDigest,
    identity: ContentDigest,
    record_digest: ContentDigest,
    import_identity: ContentDigest,
    expires_at_ns: i128,
    disposition: ReviewExpiryDisposition,
    blockers: Vec<Finding>,
    closure_witness: Option<ContentDigest>,
}

impl ReviewExpiryCandidate {
    /// Exact retained derivative root.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// Issuance metadata preserved for owner inspection after local deletion.
    #[must_use]
    pub const fn record_digest(&self) -> ContentDigest {
        self.record_digest
    }
    /// Source import, retained by this scope.
    #[must_use]
    pub const fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Immutable expiry in the grant's clock coordinates.
    #[must_use]
    pub const fn expires_at(&self) -> TimestampNs {
        TimestampNs(self.expires_at_ns)
    }
    /// Selection decision, never itself authority to unlink bytes.
    #[must_use]
    pub const fn disposition(&self) -> ReviewExpiryDisposition {
        self.disposition
    }
    /// Exact reasons a proposed addition was refused.
    #[must_use]
    pub fn blockers(&self) -> &[Finding] {
        &self.blockers
    }
    /// Digest of the refused trial union plan, when applicable.
    #[must_use]
    pub const fn closure_witness(&self) -> Option<ContentDigest> {
        self.closure_witness
    }
    pub(crate) const fn identity(&self) -> ContentDigest {
        self.identity
    }
}

/// Complete bounded same-sensor inventory. Fresh commits always recompute it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReviewExpirySelection {
    request: ReviewExpiryRequest,
    candidates: Vec<ReviewExpiryCandidate>,
}

impl ReviewExpirySelection {
    /// Exact owner request.
    #[must_use]
    pub fn request(&self) -> &ReviewExpiryRequest {
        &self.request
    }
    /// Every retained, published review of the requested sensor, including exclusions.
    #[must_use]
    pub fn candidates(&self) -> &[ReviewExpiryCandidate] {
        &self.candidates
    }
    /// Canonical encoding domain.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        REVIEW_EXPIRY_SELECTION_DOMAIN
    }
    /// Selected review roots in strictly ascending digest order.
    #[must_use]
    pub fn roots(&self) -> Vec<ContentDigest> {
        self.candidates
            .iter()
            .filter(|c| c.disposition == ReviewExpiryDisposition::Expired)
            .map(|c| c.root)
            .collect()
    }
    /// Identity binds the request, source provenance, selected roots and exclusions.
    pub fn digest(&self) -> Result<ContentDigest, DeletionError> {
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(REVIEW_EXPIRY_SELECTION_DOMAIN);
        self.request.encode(e);
        e.u64(self.candidates.len() as u64);
        for candidate in &self.candidates {
            e.digest(candidate.root);
            e.digest(candidate.identity);
            e.digest(candidate.record_digest);
            e.digest(candidate.import_identity);
            candidate.expires_at().encode_canonical(e);
            e.text(candidate.disposition.as_str());
            e.bool(candidate.closure_witness.is_some());
            if let Some(witness) = candidate.closure_witness {
                e.digest(witness);
            }
            e.u64(candidate.blockers.len() as u64);
            for blocker in &candidate.blockers {
                e.text(&blocker.kind);
                e.text(&blocker.subject);
                e.text(&blocker.detail);
            }
        }
    }
    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        if d.text()? != REVIEW_EXPIRY_SELECTION_DOMAIN {
            return Err(DeletionError::RecordMismatch);
        }
        let request = ReviewExpiryRequest::decode(d)?;
        let count = usize::try_from(d.u64()?).map_err(|_| DeletionError::RecordMismatch)?;
        if count > MAX_REVIEW_EXPIRY_REVIEWS || count > d.remaining() / 148 {
            return Err(DeletionError::Bound {
                limit: "review_expiry_reviews",
            });
        }
        let mut candidates = Vec::with_capacity(count);
        let mut total_blockers = 0;
        for _ in 0..count {
            let root = digest(d)?;
            let identity = digest(d)?;
            let record_digest = digest(d)?;
            let import_identity = digest(d)?;
            let expiry = TimestampNs::decode_canonical(d)?;
            let disposition = ReviewExpiryDisposition::decode(d)?;
            let closure_witness = if d.bool()? { Some(digest(d)?) } else { None };
            let n = usize::try_from(d.u64()?).map_err(|_| DeletionError::RecordMismatch)?;
            if n > MAX_REVIEW_EXPIRY_BLOCKERS - total_blockers || n > d.remaining() / 24 {
                return Err(DeletionError::Bound {
                    limit: "review_expiry_blockers",
                });
            }
            total_blockers += n;
            let mut blockers = Vec::with_capacity(n);
            for _ in 0..n {
                let mut field = || -> Result<String, DeletionError> {
                    let text = d.text()?;
                    if text.is_empty() || text.len() > MAX_BLOCKER_TEXT_BYTES {
                        return Err(DeletionError::RecordMismatch);
                    }
                    Ok(text.to_owned())
                };
                blockers.push(Finding {
                    kind: field()?,
                    subject: field()?,
                    detail: field()?,
                });
            }
            let blocked = disposition == ReviewExpiryDisposition::ClosureBlocked;
            if blocked != (closure_witness.is_some() && !blockers.is_empty())
                || !blocked && (closure_witness.is_some() || !blockers.is_empty())
                || blockers.windows(2).any(|pair| pair[0] >= pair[1])
                || request.classify(expiry)
                    != if blocked {
                        ReviewExpiryDisposition::Expired
                    } else {
                        disposition
                    }
            {
                return Err(DeletionError::RecordMismatch);
            }
            candidates.push(ReviewExpiryCandidate {
                root,
                identity,
                record_digest,
                import_identity,
                expires_at_ns: expiry.0,
                disposition,
                blockers,
                closure_witness,
            });
        }
        if candidates
            .windows(2)
            .any(|pair| pair[0].root >= pair[1].root)
        {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        Ok(Self {
            request,
            candidates,
        })
    }
}

fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, DeletionError> {
    let digest = d.digest()?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(DeletionError::RecordMismatch);
    }
    Ok(digest)
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), DeletionError> {
    cx.checkpoint(stage)
        .map_err(|_| DeletionError::Cancelled { stage })
}
fn inventory(
    deployment: &ReferenceDeployment,
    request: &ReviewExpiryRequest,
    cx: &ReplayCx,
) -> Result<ReviewExpirySelection, DeletionError> {
    checkpoint(cx, STAGE_REVIEW_EXPIRY_READ)?;
    if cx.root_dir() != deployment.root() {
        return Err(DeletionError::RecordMismatch);
    }
    if deployment.ledger().batches().len() > MAX_REVIEW_BATCHES {
        return Err(DeletionError::Bound {
            limit: "review_expiry_batches",
        });
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| DeletionError::RecordMismatch)?;
    let deleted = DeletionIndex::read(deployment)?;
    let mut roots = BTreeMap::new();
    let mut entries = 0_usize;
    for batch in deployment.ledger().batches() {
        checkpoint(cx, STAGE_REVIEW_EXPIRY_READ)?;
        entries = entries
            .checked_add(1 + batch.deltas.len())
            .filter(|count| *count <= MAX_REVIEW_EXPIRY_LEDGER_ENTRIES)
            .ok_or(DeletionError::Bound {
                limit: "review_expiry_ledger_entries",
            })?;
        if deleted.unit_deleted(batch.batch_id.as_str()) {
            continue;
        }
        for delta in &batch.deltas {
            if delta.family != FAMILY_REVIEW_MEDIA {
                continue;
            }
            if deleted.review(delta.payload_digest).is_some() {
                continue;
            }
            if roots.len() >= MAX_REVIEW_EXPIRY_REVIEWS {
                return Err(DeletionError::Bound {
                    limit: "review_expiry_reviews",
                });
            }
            if roots
                .insert(delta.payload_digest, delta.witness_digest)
                .is_some()
            {
                return Err(DeletionError::RecordMismatch);
            }
        }
    }
    let mut candidates = Vec::new();
    for (root, witness) in roots {
        checkpoint(cx, STAGE_REVIEW_EXPIRY_READ)?;
        let record =
            crate::review_media::inspect_for_expiry(deployment, root, cx).map_err(|error| {
                match error {
                    ReviewMediaError::Cancelled => DeletionError::Cancelled {
                        stage: STAGE_REVIEW_EXPIRY_READ,
                    },
                    _ => DeletionError::RecordMismatch,
                }
            })?;
        // The inventory is bounded before reads; each immutable record is at most 64 KiB.
        if witness != Some(record.digest()) || record.to_bytes().len() > MAX_REVIEW_RECORD_BYTES {
            return Err(DeletionError::RecordMismatch);
        }
        let grant = record.grant().request();
        if &grant.sensor != request.sensor() {
            continue;
        }
        candidates.push(ReviewExpiryCandidate {
            root,
            identity: record.identity(),
            record_digest: record.digest(),
            import_identity: grant.import_identity,
            expires_at_ns: grant.expires_at.0,
            disposition: request.classify(grant.expires_at),
            blockers: Vec::new(),
            closure_witness: None,
        });
    }
    Ok(ReviewExpirySelection {
        request: request.clone(),
        candidates,
    })
}

/// Read-only assessment and the complete prospective deletion, absent when nothing is eligible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewExpiryAssessment {
    /// All retained same-sensor reviews and their exact decisions.
    pub selection: ReviewExpirySelection,
    /// One union-closure plan; any remaining blockers refuse commit.
    pub deletion: Option<DeletionPlan>,
}

/// Assess one explicit expiry request. Shared bytes stay retained; held closures are excluded.
pub fn assess_review_expiry(
    deployment: &ReferenceDeployment,
    request: &ReviewExpiryRequest,
    cx: &ReplayCx,
) -> Result<ReviewExpiryAssessment, DeletionError> {
    let age_selection = inventory(deployment, request, cx)?;
    if age_selection.roots().is_empty() {
        return Ok(ReviewExpiryAssessment {
            selection: age_selection,
            deletion: None,
        });
    }
    let index = DeletionIndex::read(deployment)?;
    let holds = super::holds::HoldIndex::read(deployment, cx)?;
    let universe = super::walk::Universe::scan(deployment, &index, cx)?;
    let protection = holds.protection(&universe, deployment, cx)?;
    let evaluate = |selection: &ReviewExpirySelection| -> Result<DeletionPlan, DeletionError> {
        checkpoint(cx, STAGE_REVIEW_EXPIRY_COHORT)?;
        let plan = universe.plan(deployment, &DeletionScope::ReviewExpiry(selection.clone()))?;
        let plan = protection.protect(plan, cx)?;
        super::commit::admit_plan(deployment, plan, cx)
    };
    let whole = evaluate(&age_selection)?;
    if whole.blockers.is_empty() {
        return Ok(ReviewExpiryAssessment {
            selection: age_selection,
            deletion: Some(whole),
        });
    }
    let mut selection = age_selection.clone();
    let mut selected = BTreeSet::new();
    let mut total_blockers = 0;
    for candidate in &mut selection.candidates {
        if candidate.disposition != ReviewExpiryDisposition::Expired {
            continue;
        }
        let trial = ReviewExpirySelection {
            request: request.clone(),
            candidates: age_selection
                .candidates
                .iter()
                .filter(|c| selected.contains(&c.root) || c.root == candidate.root)
                .cloned()
                .collect(),
        };
        let plan = evaluate(&trial)?;
        if plan.blockers.is_empty() {
            selected.insert(candidate.root);
        } else {
            if plan.blockers.len() > MAX_REVIEW_EXPIRY_BLOCKERS - total_blockers
                || plan.blockers.iter().any(|f| {
                    [&f.kind, &f.subject, &f.detail]
                        .iter()
                        .any(|text| text.is_empty() || text.len() > MAX_BLOCKER_TEXT_BYTES)
                })
            {
                return Err(DeletionError::Bound {
                    limit: "review_expiry_blockers",
                });
            }
            total_blockers += plan.blockers.len();
            candidate.disposition = ReviewExpiryDisposition::ClosureBlocked;
            candidate.closure_witness = Some(plan.digest()?);
            candidate.blockers = plan.blockers;
        }
    }
    let deletion = if selected.is_empty() {
        None
    } else {
        Some(evaluate(&selection)?)
    };
    Ok(ReviewExpiryAssessment {
        selection,
        deletion,
    })
}

pub(super) fn revalidate_plan(
    deployment: &ReferenceDeployment,
    selection: &ReviewExpirySelection,
    cx: &ReplayCx,
) -> Result<DeletionPlan, DeletionError> {
    let current = assess_review_expiry(deployment, selection.request(), cx)?;
    if current.selection != *selection {
        return Err(DeletionError::RecordMismatch);
    }
    current.deletion.ok_or_else(|| {
        DeletionError::ScopeEmpty(DeletionScope::ReviewExpiry(selection.clone()).text())
    })
}

/// Commit exactly the approved derivative cohort or resume its durable tombstone-first plan.
pub fn commit_review_expiry(
    deployment: &mut ReferenceDeployment,
    request: &ReviewExpiryRequest,
    plan_digest: ContentDigest,
    approval: ContentDigest,
    principal: &str,
    cx: &ReplayCx,
) -> Result<CommitReceipt, DeletionError> {
    checkpoint(cx, STAGE_REVIEW_EXPIRY_READ)?;
    super::commit::commit_review_expiry(deployment, request, plan_digest, approval, principal, cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    type Test = Result<(), Box<dyn std::error::Error>>;

    fn selection() -> Result<ReviewExpirySelection, DeletionError> {
        Ok(ReviewExpirySelection {
            request: ReviewExpiryRequest::new(
                SensorId::parse("sensor:expiry-wire")?,
                CaptureInterval::new(TimestampNs(100), TimestampNs(100))?,
            )?,
            candidates: vec![ReviewExpiryCandidate {
                root: ContentDigest::sha256(b"review-root"),
                identity: ContentDigest::sha256(b"review-identity"),
                record_digest: ContentDigest::sha256(b"review-record"),
                import_identity: ContentDigest::sha256(b"source-import"),
                expires_at_ns: 100,
                disposition: ReviewExpiryDisposition::Expired,
                blockers: Vec::new(),
                closure_witness: None,
            }],
        })
    }
    fn decode(value: &ReviewExpirySelection) -> Result<ReviewExpirySelection, DeletionError> {
        let mut e = CanonicalEncoder::new();
        value.encode(&mut e);
        let bytes = e.finish_checked()?;
        let mut d = CanonicalDecoder::new(&bytes);
        let value = ReviewExpirySelection::decode(&mut d)?;
        d.ensure_finished()?;
        Ok(value)
    }

    #[test]
    fn selection_wire_binds_exact_expiry_and_refusal_witness() -> Test {
        let mut value = selection()?;
        assert_eq!(decode(&value)?, value);
        let selected_digest = value.digest()?;
        value.candidates[0].disposition = ReviewExpiryDisposition::ClosureBlocked;
        value.candidates[0].closure_witness = Some(ContentDigest::sha256(b"blocked trial"));
        value.candidates[0].blockers = vec![Finding {
            kind: "evidence_hold".into(),
            subject: "hold:preserve".into(),
            detail: "Owner preservation remains active".into(),
        }];
        assert_eq!(decode(&value)?, value);
        assert_ne!(value.digest()?, selected_digest);
        value.candidates[0].closure_witness = None;
        assert!(decode(&value).is_err());
        let mut uncertain = selection()?;
        uncertain.candidates[0].expires_at_ns = 101;
        assert!(decode(&uncertain).is_err());
        let mut duplicate = selection()?;
        duplicate.candidates.push(duplicate.candidates[0].clone());
        assert!(decode(&duplicate).is_err());
        Ok(())
    }

    #[test]
    fn selection_wire_refuses_oversized_inventory_and_diagnostics() -> Test {
        let value = selection()?;
        let mut e = CanonicalEncoder::new();
        e.text(REVIEW_EXPIRY_SELECTION_DOMAIN);
        value.request.encode(&mut e);
        e.u64(MAX_REVIEW_EXPIRY_REVIEWS as u64 + 1);
        let bytes = e.finish_checked()?;
        assert!(matches!(
            ReviewExpirySelection::decode(&mut CanonicalDecoder::new(&bytes)),
            Err(DeletionError::Bound {
                limit: "review_expiry_reviews"
            })
        ));
        let mut value = value;
        value.candidates[0].disposition = ReviewExpiryDisposition::ClosureBlocked;
        value.candidates[0].closure_witness = Some(ContentDigest::sha256(b"oversized trial"));
        value.candidates[0].blockers = vec![Finding {
            kind: "evidence_hold".into(),
            subject: "hold:preserve".into(),
            detail: "x".repeat(MAX_BLOCKER_TEXT_BYTES + 1),
        }];
        assert!(decode(&value).is_err());
        Ok(())
    }
}
