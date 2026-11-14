#![forbid(unsafe_code)]
//! Complete native publication index, then owner metadata admission, then exact selection.

use std::collections::BTreeMap;

use fss_core::Plane;
use fss_publication::{ROOT_REACHABILITY_FAMILY, ROOT_RETRACTION_FAMILY};

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::ingest::recorded_decode::RecordedDecodeError;
use crate::ingest::twin_localization::RecordedLocalizationError;
use crate::retained_source::{ImmutableRetainedSource, RetainedSource};

const OBJECT_PREFIX: &str = "object:local-root:recorded-localization-";
const BATCH_PREFIX: &str = "batch:local-root:recorded-localization-";
const DELTA_PREFIX: &str = "delta:local-root:recorded-localization-";

fn identity(text: &str) -> Result<ContentDigest, LocalizationsQueryError> {
    let hex = text
        .strip_prefix(OBJECT_PREFIX)
        .ok_or(LocalizationsQueryError::InvalidRecord)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LocalizationsQueryError::InvalidRecord);
    }
    let digest = ContentDigest::parse(&format!("sha256:{hex}"))
        .map_err(|_| LocalizationsQueryError::InvalidRecord)?;
    if digest.bytes() == [0; 32] {
        return Err(LocalizationsQueryError::InvalidRecord);
    }
    Ok(digest)
}

pub(super) fn query(
    root: &Path,
    request: &LocalizationsQueryRequest,
    limits: LocalizationsQueryLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentLocalizationsQuery, LocalizationsQueryError> {
    request.validate()?;
    limits.validate()?;
    if root != cx.root_dir() || request.principal.as_str() != cx.io_authority().principal() {
        return Err(LocalizationsQueryError::Unauthorized);
    }
    if cancelled() || cx.checkpoint("localizations:open").is_err() {
        return Err(LocalizationsQueryError::Cancelled);
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, cx, cancelled)
        .map_err(LocalizationsQueryError::Source)?;
    let anchor = snapshot_anchor_token(owner.snapshot());
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|pin| pin.as_str() != anchor)
    {
        return Err(LocalizationsQueryError::AnchorChanged);
    }
    let ledger = owner.ledger();
    if ledger.current().objects.len() > limits.max_objects
        || ledger.batches().len() > limits.max_objects
    {
        return Err(LocalizationsQueryError::OverBudget);
    }
    let mut expected_count = 0;
    let mut retracted_localizations = 0;
    for (object, revision) in &ledger.current().objects {
        if object.as_str().starts_with(OBJECT_PREFIX) {
            let package = identity(object.as_str())?;
            if revision.family == ROOT_RETRACTION_FAMILY {
                let slot = format!("recorded-localization-{}", hex(package));
                let deletion = owner
                    .snapshot()
                    .deletions
                    .plan(revision.payload_digest)
                    .ok_or(LocalizationsQueryError::InvalidRecord)?;
                // Only the deletion owner's verified plan can exclude a native package.
                // A family label alone is not evidence of authorized lifecycle progress.
                if !owner
                    .snapshot()
                    .deletions
                    .unit_deleted(&format!("slot:{slot}"))
                    || revision.plane != Plane::Authority
                    || revision.generation != 2
                    || !deletion.plan.retractions.iter().any(|retraction| {
                        retraction.slot == slot
                            && retraction.prior_generation == Some(1)
                            && retraction.validity == revision.validity
                    })
                {
                    return Err(LocalizationsQueryError::InvalidRecord);
                }
                retracted_localizations += 1;
            } else {
                expected_count += 1;
            }
        }
    }
    if expected_count > limits.max_localizations {
        return Err(LocalizationsQueryError::OverBudget);
    }
    // Native retained localization packages use authority root reachability declarations,
    // not cognition report deltas. Prefixes must agree; changing only the object namespace
    // cannot hide a malformed would-be native publication from complete-index verification.
    let mut current = BTreeMap::new();
    for batch in ledger.batches() {
        if cancelled() || cx.checkpoint("localizations:index").is_err() {
            return Err(LocalizationsQueryError::Cancelled);
        }
        for delta in &batch.deltas {
            let selected = delta.object_id.as_str().starts_with(OBJECT_PREFIX)
                || batch.batch_id.as_str().starts_with(BATCH_PREFIX)
                || delta.delta_id.starts_with(DELTA_PREFIX);
            if !selected {
                continue;
            }
            let id = identity(delta.object_id.as_str())?;
            let revision = ledger
                .current()
                .objects
                .get(&delta.object_id)
                .ok_or(LocalizationsQueryError::InvalidRecord)?;
            if revision.family == ROOT_RETRACTION_FAMILY {
                // Committed retraction is an explicit unfiltered lifecycle boundary. Its
                // receipt is not returned or implied available by this current catalog.
                continue;
            }
            let suffix = hex(id);
            if batch.batch_id.as_str() != format!("{BATCH_PREFIX}{suffix}")
                || delta.delta_id != format!("{DELTA_PREFIX}{suffix}")
                || delta.family != ROOT_REACHABILITY_FAMILY
                || delta.plane != Plane::Authority
                || delta.prior_generation.is_some()
                || delta.new_generation != 1
                || delta.witness_digest.is_some()
                || delta.operation_id.is_some()
                || revision.family != delta.family
                || revision.generation != delta.new_generation
                || revision.payload_digest != delta.payload_digest
                || revision.validity != delta.validity
                || revision.plane != delta.plane
                || batch.deltas.len() != 1
                || batch.batch_digest != batch.computed_digest()
                || !batch.is_canonically_ordered()
                || batch.new_anchor.site_lineage != owner.site_lineage()
                || current
                    .insert(id, (delta.payload_digest, batch.new_anchor.commit_sequence))
                    .is_some()
            {
                return Err(LocalizationsQueryError::InvalidRecord);
            }
            if current.len() > limits.max_localizations {
                return Err(LocalizationsQueryError::OverBudget);
            }
        }
    }
    if current.len() != expected_count {
        return Err(LocalizationsQueryError::InvalidRecord);
    }
    let mut rows = Vec::with_capacity(current.len());
    for (identity, (publication_root, committed_sequence)) in current {
        if cancelled() || cx.checkpoint("localizations:metadata").is_err() {
            return Err(LocalizationsQueryError::Cancelled);
        }
        let metadata =
            RecordedLocalizationMetadata::read(&owner, identity, cx).map_err(|error| {
                if cancelled() || cx.is_cancelled() {
                    LocalizationsQueryError::Cancelled
                } else {
                    match error {
                        RecordedLocalizationError::Decode(RecordedDecodeError::Source(error)) => {
                            LocalizationsQueryError::Source(*error)
                        }
                        RecordedLocalizationError::Cancelled => LocalizationsQueryError::Cancelled,
                        _ => LocalizationsQueryError::InvalidRecord,
                    }
                }
            })?;
        if metadata.publication_root != publication_root
            || metadata.committed_sequence != committed_sequence
        {
            return Err(LocalizationsQueryError::InvalidRecord);
        }
        rows.push(LocalizationsQueryRow { metadata });
    }
    let mut result = result::compile(
        owner.snapshot().clone(),
        request,
        &limits,
        rows,
        retracted_localizations,
    )?;
    if cancelled() || cx.checkpoint("localizations:complete").is_err() {
        return Err(LocalizationsQueryError::Cancelled);
    }
    owner
        .revalidate_snapshot_metadata()
        .map_err(LocalizationsQueryError::Source)?;
    owner
        .revalidate()
        .map_err(LocalizationsQueryError::Source)?;
    // No callback or metadata operation follows the final native authority observation.
    result.read_usage = owner.usage();
    Ok(result)
}
