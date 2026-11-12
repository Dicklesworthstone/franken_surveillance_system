#![forbid(unsafe_code)]
//! Exact rederivation of an interrupted, unowned audit proposal for one requested operation.
//! A canonical spelling, local anchor, or caller-supplied digest is not deletion authority.

use super::walk::Universe;
use super::{DeletionError, DeletionPlan, STAGE_DELETION_SCAN};
use crate::ReplayCx;
use fss_core::ContentDigest;

/// Bound semantic retries independently of the spool's byte/object inventory limit.
pub(super) const MAX_RETRY_CANDIDATES: usize = 64;

pub(super) trait Projection {
    fn deletion(&self) -> Option<&DeletionPlan>;
}

impl Projection for DeletionPlan {
    fn deletion(&self) -> Option<&DeletionPlan> {
        Some(self)
    }
}
impl Projection for super::retention::RetentionPlan {
    fn deletion(&self) -> Option<&DeletionPlan> {
        self.deletion.as_ref()
    }
}
impl Projection for super::review_expiry::ReviewExpiryAssessment {
    fn deletion(&self) -> Option<&DeletionPlan> {
        self.deletion.as_ref()
    }
}

/// Reuse one complete custody scan. Only a candidate for this explicit request can be tried;
/// every other proposal remains visible during that trial. A complete fresh projection must
/// reproduce the candidate digest, including its holds, exclusions, counts and all plan fields.
/// If no candidate verifies, prepare normally with every proposal accounted as ordinary content.
pub(super) fn derive<T: Projection>(
    universe: &mut Universe,
    cx: &ReplayCx,
    matches: impl Fn(ContentDigest, &DeletionPlan) -> bool,
    evaluate: impl Fn(&Universe) -> Result<T, DeletionError>,
) -> Result<T, DeletionError> {
    let candidates: Vec<_> = universe
        .proposed_plans()
        .filter_map(|(digest, plan)| matches(digest, plan).then_some(digest))
        .take(MAX_RETRY_CANDIDATES + 1)
        .collect();
    if candidates.len() > MAX_RETRY_CANDIDATES {
        return Err(DeletionError::Bound {
            limit: "audit_retry_candidates",
        });
    }
    let mut verified = None;
    for digest in candidates {
        checkpoint(cx)?;
        let projected = universe.with_proposals_omitted(&[digest], &evaluate)?;
        if projected
            .deletion()
            .map(DeletionPlan::digest)
            .transpose()?
            == Some(digest)
        {
            if verified.is_some() {
                return Err(DeletionError::RecordMismatch);
            }
            verified = Some(projected);
        }
    }
    let projected = match verified {
        Some(projected) => projected,
        None => {
            checkpoint(cx)?;
            evaluate(universe)?
        }
    };
    checkpoint(cx)?;
    Ok(projected)
}

fn checkpoint(cx: &ReplayCx) -> Result<(), DeletionError> {
    cx.checkpoint(STAGE_DELETION_SCAN)
        .map_err(|_| DeletionError::Cancelled {
            stage: STAGE_DELETION_SCAN,
        })
}
