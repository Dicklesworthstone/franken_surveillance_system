#![forbid(unsafe_code)]
//! One immutable read owner for the native historical inventory and its protected context.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalDecode, SensorCapsule};

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::deployment_status::{StatusError, StatusLimits, inventory_from_snapshot};
use crate::retained_source::{ImmutableRetainedSource, RetainedSource};

pub(super) fn query(
    root: &Path,
    request: &SourcesQueryRequest,
    limits: SourcesQueryLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentSourcesQuery, SourcesQueryError> {
    request.validate()?;
    limits.validate()?;
    if root != cx.root_dir() || request.principal.as_str() != cx.io_authority().principal() {
        return Err(SourcesQueryError::Unauthorized);
    }
    if cancelled() || cx.checkpoint("sources:open").is_err() {
        return Err(SourcesQueryError::Cancelled);
    }
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, cx, cancelled)
        .map_err(SourcesQueryError::Source)?;
    let anchor = snapshot_anchor_token(owner.snapshot());
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|pin| pin.as_str() != anchor)
    {
        return Err(SourcesQueryError::AnchorChanged);
    }
    let ledger = owner.ledger();
    if ledger.current().objects.len() > limits.max_objects
        || ledger.batches().len() > limits.max_objects
    {
        return Err(SourcesQueryError::OverBudget);
    }
    let inventory_limits = StatusLimits {
        snapshot: limits.read.snapshot,
        max_objects: limits.max_objects,
        max_capsules: limits.max_capsules,
        max_streams: limits.max_streams,
        max_metadata_bytes: limits.max_metadata_bytes,
    };
    let mut metadata: BTreeMap<(String, String), BTreeSet<ContentDigest>> = BTreeMap::new();
    let mut source_error = None;
    // The status owner alone decides which capsules are retained, incomplete or deleted and
    // computes every count and continuity verdict. This callback only retains true proof handles
    // from the exact bytes that owner consumes; it never reads a source-media dependency.
    let inventory = inventory_from_snapshot(
        ledger.batches(),
        &inventory_limits,
        owner.snapshot(),
        &mut |digest, bound| {
            let bytes = match owner.read_object_bounded(digest, bound) {
                Ok(bytes) => bytes,
                Err(error) => {
                    source_error = Some(error);
                    return Err(StatusError::Unreadable);
                }
            };
            let capsule = SensorCapsule::from_canonical_bytes(&bytes)
                .map_err(|_| StatusError::Corrupt)?;
            metadata
                .entry((
                    capsule.sensor_id.as_str().to_owned(),
                    capsule.stream_id.as_str().to_owned(),
                ))
                .or_default()
                .insert(digest);
            Ok(bytes)
        },
        &mut || {
            if cancelled() || cx.checkpoint("sources:index").is_err() {
                Err(StatusError::Cancelled)
            } else {
                Ok(())
            }
        },
    );
    let inventory = match inventory {
        Ok(inventory) => inventory,
        Err(error) => {
            if let Some(error) = source_error {
                return Err(SourcesQueryError::Source(error));
            }
            return Err(match error {
                StatusError::OverBudget => SourcesQueryError::OverBudget,
                StatusError::Cancelled => SourcesQueryError::Cancelled,
                StatusError::Changed => SourcesQueryError::AnchorChanged,
                StatusError::NotADeployment | StatusError::Unreadable | StatusError::Corrupt => {
                    SourcesQueryError::InvalidRecord
                }
            });
        }
    };
    let summary = SourcesQuerySummary::from(&inventory);
    let mut rows = Vec::with_capacity(inventory.streams.len());
    let mut all_capsules = Vec::with_capacity(inventory.retained_capsules);
    for stream in inventory.streams {
        let handles = metadata
            .remove(&(stream.sensor_id.clone(), stream.stream_id.clone()))
            .ok_or(SourcesQueryError::InvalidRecord)?;
        if handles.len() != stream.capsules {
            return Err(SourcesQueryError::InvalidRecord);
        }
        let mut representative = BTreeSet::new();
        representative.extend(handles.first().copied());
        representative.extend(handles.last().copied());
        all_capsules.extend(handles);
        rows.push(SourcesQueryRow {
            stream,
            capsule_metadata: representative.into_iter().collect(),
        });
    }
    if !metadata.is_empty() || all_capsules.len() != summary.retained_capsules {
        return Err(SourcesQueryError::InvalidRecord);
    }
    all_capsules.sort_unstable();
    if !all_capsules.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SourcesQueryError::InvalidRecord);
    }
    let mut result = result::compile(
        owner.snapshot().clone(),
        request,
        &limits,
        summary,
        rows,
        &all_capsules,
    )?;
    if cancelled() || cx.checkpoint("sources:complete").is_err() {
        return Err(SourcesQueryError::Cancelled);
    }
    // Protected health, liveness, coverage, deletion and event metadata must still resolve,
    // including records unrelated to the selected sensor or page. This uses the original
    // owner's allowance and original index, never a fresh read budget or filtered snapshot.
    owner
        .revalidate_snapshot_metadata()
        .map_err(SourcesQueryError::Source)?;
    owner.revalidate().map_err(SourcesQueryError::Source)?;
    // No callback or metadata operation follows the final native authority observation.
    result.read_usage = owner.usage();
    Ok(result)
}
