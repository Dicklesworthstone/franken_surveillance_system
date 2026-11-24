#![forbid(unsafe_code)]
//! Retention eviction planner (`plan_retention`) and durable [`TombstoneCommitProof`] verification.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs};

use crate::error::PackError;

use super::{
    CapacityPressure, DeletionTombstone, ERR_STORAGE_QUOTA_PINNED_001, EvictionReason,
    PACK_RETENTION_EVICTION_BATCH_DOMAIN, PACK_TOMBSTONE_COMMIT_PROOF_DOMAIN, RetentionCandidate,
    RetentionEvictionBatch, RetentionPlanOutcome, RetentionRingConfig,
};

/// Cryptographic witness proving that deletion tombstones for a [`RetentionEvictionBatch`] were
/// durably committed before physical packfile compaction/unlink may proceed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TombstoneCommitProof {
    /// Canonical digest of the committed [`RetentionEvictionBatch`].
    pub batch_digest: ContentDigest,
    /// Number of deletion tombstones durably committed.
    pub committed_tombstone_count: u64,
    /// Sorted list of tombstoned import/root identifiers.
    pub committed_import_ids: Vec<String>,
    /// Sorted set of object digests whose deletion tombstones are durably committed.
    pub committed_digests: BTreeSet<ContentDigest>,
    /// Timestamp at which the tombstones were committed.
    pub committed_at_ns: TimestampNs,
    /// Optional authority ledger commit sequence witnessing the same deletion batch.
    pub ledger_commit_seq: Option<u64>,
    /// Domain-separated SHA-256 commitment under [`PACK_TOMBSTONE_COMMIT_PROOF_DOMAIN`].
    pub proof_digest: ContentDigest,
}

impl TombstoneCommitProof {
    /// Constructs a canonical [`TombstoneCommitProof`] bound to `batch` and its committed digests.
    pub fn build(
        batch: &RetentionEvictionBatch,
        committed_import_ids: Vec<String>,
        committed_digests: BTreeSet<ContentDigest>,
        committed_at_ns: TimestampNs,
        ledger_commit_seq: Option<u64>,
    ) -> Result<Self, PackError> {
        let mut sorted_ids = committed_import_ids;
        sorted_ids.sort();
        sorted_ids.dedup();
        let batch_digest = batch.batch_digest();
        let committed_tombstone_count = batch.tombstones.len() as u64;
        let proof_digest = compute_tombstone_proof_digest(
            batch_digest,
            committed_tombstone_count,
            &sorted_ids,
            &committed_digests,
            committed_at_ns,
            ledger_commit_seq,
        )?;
        Ok(Self {
            batch_digest,
            committed_tombstone_count,
            committed_import_ids: sorted_ids,
            committed_digests,
            committed_at_ns,
            ledger_commit_seq,
            proof_digest,
        })
    }

    /// Recomputes and verifies the canonical commitment digest, failing closed on tampering.
    pub fn verify(&self) -> Result<(), PackError> {
        if self.batch_digest.algorithm() != DigestAlgorithm::Sha256
            || self.proof_digest.algorithm() != DigestAlgorithm::Sha256
        {
            return Err(PackError::InvalidTombstoneProof {
                detail: "tombstone commit proof must use SHA-256 digests".to_owned(),
            });
        }
        let expected = compute_tombstone_proof_digest(
            self.batch_digest,
            self.committed_tombstone_count,
            &self.committed_import_ids,
            &self.committed_digests,
            self.committed_at_ns,
            self.ledger_commit_seq,
        )?;
        if expected != self.proof_digest {
            return Err(PackError::InvalidTombstoneProof {
                detail: format!(
                    "tombstone commit proof digest mismatch: expected {expected}, observed {}",
                    self.proof_digest
                ),
            });
        }
        Ok(())
    }

    /// Returns `true` if `digest` is covered by this committed proof.
    #[must_use]
    pub fn covers_digest(&self, digest: &ContentDigest) -> bool {
        self.committed_digests.contains(digest)
    }
}

fn compute_tombstone_proof_digest(
    batch_digest: ContentDigest,
    committed_tombstone_count: u64,
    committed_import_ids: &[String],
    committed_digests: &BTreeSet<ContentDigest>,
    committed_at_ns: TimestampNs,
    ledger_commit_seq: Option<u64>,
) -> Result<ContentDigest, PackError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(PACK_TOMBSTONE_COMMIT_PROOF_DOMAIN);
    enc.digest(batch_digest);
    enc.u64(committed_tombstone_count);
    enc.u64(committed_import_ids.len() as u64);
    for id in committed_import_ids {
        enc.text(id);
    }
    enc.u64(committed_digests.len() as u64);
    for digest in committed_digests {
        enc.digest(*digest);
    }
    committed_at_ns.encode_canonical(&mut enc);
    match ledger_commit_seq {
        Some(seq) => {
            enc.bool(true);
            enc.u64(seq);
        }
        None => enc.bool(false),
    }
    let bytes = enc.finish_checked()?;
    Ok(ContentDigest::sha256(&bytes))
}

fn tombstone_reason_digest(
    import_id: &str,
    reason: EvictionReason,
    evaluated_at_ns: TimestampNs,
) -> Result<ContentDigest, PackError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(PACK_RETENTION_EVICTION_BATCH_DOMAIN);
    enc.text(import_id);
    enc.tag(reason.to_tag());
    evaluated_at_ns.encode_canonical(&mut enc);
    let bytes = enc.finish_checked()?;
    Ok(ContentDigest::sha256(&bytes))
}

/// Evaluates `candidates` against `config` at caller-supplied timestamp `now_ns`.
///
/// Strictly enforces:
/// - Zero pinned candidates (`held_by`, `active_obligation_ids`, or `active_event_ids` non-empty)
///   are EVER evicted.
/// - Derived proxies (`is_derived_proxy == true`) are ALWAYS shed before unheld source windows.
/// - Critical capacity pinned by holds/obligations/events returns [`RetentionPlanOutcome::QuotaPinned`]
///   with [`ERR_STORAGE_QUOTA_PINNED_001`].
pub fn plan_retention(
    config: &RetentionRingConfig,
    candidates: &[RetentionCandidate],
    now_ns: TimestampNs,
) -> Result<RetentionPlanOutcome, PackError> {
    config.validate()?;

    let mut seen_ids = BTreeSet::new();
    let mut total_bytes_before = 0_u64;
    let mut pinned_bytes = 0_u64;
    for cand in candidates {
        cand.validate()?;
        if !seen_ids.insert(cand.import_id.as_str()) {
            return Err(PackError::RetentionPolicyViolation {
                detail: format!(
                    "duplicate retention candidate import_id '{}'",
                    cand.import_id
                ),
            });
        }
        total_bytes_before = total_bytes_before
            .checked_add(cand.byte_size)
            .ok_or(PackError::ArithmeticOverflow)?;
        if cand.is_pinned() {
            pinned_bytes = pinned_bytes
                .checked_add(cand.byte_size)
                .ok_or(PackError::ArithmeticOverflow)?;
        }
    }

    let pressure_before = config.classify_pressure(total_bytes_before);
    let mut evicted_reason: BTreeMap<usize, EvictionReason> = BTreeMap::new();
    let mut eviction_order: Vec<usize> = Vec::new();
    let mut sensor_bytes: BTreeMap<&str, u64> = BTreeMap::new();
    for cand in candidates {
        let entry = sensor_bytes.entry(cand.sensor_id.as_str()).or_insert(0);
        *entry = entry
            .checked_add(cand.byte_size)
            .ok_or(PackError::ArithmeticOverflow)?;
    }

    // Deterministic priority: proxies first, then oldest capture_end_ns, then import_id ascending.
    let mut unheld_indices: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.is_pinned())
        .map(|(i, _)| i)
        .collect();
    unheld_indices.sort_by(|&a, &b| {
        let ca = &candidates[a];
        let cb = &candidates[b];
        (!ca.is_derived_proxy)
            .cmp(&(!cb.is_derived_proxy))
            .then_with(|| ca.capture_end_ns.cmp(&cb.capture_end_ns))
            .then_with(|| ca.import_id.cmp(&cb.import_id))
    });

    let mut remaining_total = total_bytes_before;

    let mark_evicted = |idx: usize,
                        reason: EvictionReason,
                        evicted_reason: &mut BTreeMap<usize, EvictionReason>,
                        eviction_order: &mut Vec<usize>,
                        sensor_bytes: &mut BTreeMap<&str, u64>,
                        remaining_total: &mut u64| {
        if evicted_reason.contains_key(&idx) {
            return;
        }
        let cand = &candidates[idx];
        evicted_reason.insert(idx, reason);
        eviction_order.push(idx);
        if let Some(sb) = sensor_bytes.get_mut(cand.sensor_id.as_str()) {
            *sb = sb.saturating_sub(cand.byte_size);
        }
        *remaining_total = remaining_total.saturating_sub(cand.byte_size);
    };

    // Pass 1: Time-based hot-window expiry for unheld candidates.
    for &idx in &unheld_indices {
        let cand = &candidates[idx];
        let (retain_hot_ns, _) = config.policy_for_sensor(&cand.sensor_id);
        let expiry_ns = cand
            .capture_end_ns
            .0
            .saturating_add(i128::from(retain_hot_ns));
        if expiry_ns <= now_ns.0 {
            mark_evicted(
                idx,
                EvictionReason::ExpiredHotWindow,
                &mut evicted_reason,
                &mut eviction_order,
                &mut sensor_bytes,
                &mut remaining_total,
            );
        }
    }

    // Pass 2: Per-sensor byte caps (proxies first, then oldest unheld sources).
    let sensor_ids: Vec<&str> = sensor_bytes.keys().copied().collect();
    for sensor_id in sensor_ids {
        let (_, max_sensor_bytes) = config.policy_for_sensor(sensor_id);
        for &idx in &unheld_indices {
            if sensor_bytes.get(sensor_id).copied().unwrap_or(0) <= max_sensor_bytes {
                break;
            }
            if candidates[idx].sensor_id == sensor_id && !evicted_reason.contains_key(&idx) {
                mark_evicted(
                    idx,
                    EvictionReason::SensorQuotaExceeded,
                    &mut evicted_reason,
                    &mut eviction_order,
                    &mut sensor_bytes,
                    &mut remaining_total,
                );
            }
        }
    }

    // Pass 3: Deployment capacity watermark ladder (§13.6).
    let soft_target = config.soft_target_bytes();
    let pressure_mid = config.classify_pressure(remaining_total);
    if pressure_mid.should_shed_proxies_first() {
        for &idx in &unheld_indices {
            if remaining_total < soft_target {
                break;
            }
            if candidates[idx].is_derived_proxy && !evicted_reason.contains_key(&idx) {
                mark_evicted(
                    idx,
                    EvictionReason::DeploymentPressureProxyShed,
                    &mut evicted_reason,
                    &mut eviction_order,
                    &mut sensor_bytes,
                    &mut remaining_total,
                );
            }
        }

        let pressure_after_proxies = config.classify_pressure(remaining_total);
        if matches!(
            pressure_after_proxies,
            CapacityPressure::Constrained | CapacityPressure::Critical
        ) {
            for &idx in &unheld_indices {
                if remaining_total < soft_target {
                    break;
                }
                if !candidates[idx].is_derived_proxy && !evicted_reason.contains_key(&idx) {
                    mark_evicted(
                        idx,
                        EvictionReason::DeploymentQuotaExceeded,
                        &mut evicted_reason,
                        &mut eviction_order,
                        &mut sensor_bytes,
                        &mut remaining_total,
                    );
                }
            }
        }
    }

    let pressure_after = config.classify_pressure(remaining_total);
    let any_unheld_left = unheld_indices
        .iter()
        .any(|idx| !evicted_reason.contains_key(idx));

    let maybe_batch = if eviction_order.is_empty() {
        None
    } else {
        Some(build_eviction_batch(
            candidates,
            &eviction_order,
            &evicted_reason,
            now_ns,
            pressure_before,
            pressure_after,
            total_bytes_before,
            remaining_total,
            pinned_bytes,
        )?)
    };

    if pressure_after == CapacityPressure::Critical && !any_unheld_left {
        return Ok(RetentionPlanOutcome::QuotaPinned {
            error_id: ERR_STORAGE_QUOTA_PINNED_001,
            pressure: CapacityPressure::Critical,
            pinned_bytes,
            cap_bytes: config.max_total_deployment_bytes,
            partial_eviction: maybe_batch,
        });
    }

    match maybe_batch {
        Some(batch) => Ok(RetentionPlanOutcome::Evict(batch)),
        None => Ok(RetentionPlanOutcome::NoAction {
            pressure: pressure_after,
            total_bytes: total_bytes_before,
            pinned_bytes,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_eviction_batch(
    candidates: &[RetentionCandidate],
    eviction_order: &[usize],
    evicted_reason: &BTreeMap<usize, EvictionReason>,
    evaluated_at_ns: TimestampNs,
    pressure_before: CapacityPressure,
    pressure_after: CapacityPressure,
    total_bytes_before: u64,
    total_bytes_after: u64,
    pinned_bytes: u64,
) -> Result<RetentionEvictionBatch, PackError> {
    let mut retained_digests: BTreeSet<ContentDigest> = BTreeSet::new();
    for (idx, cand) in candidates.iter().enumerate() {
        if !evicted_reason.contains_key(&idx) {
            for &digest in &cand.object_digests {
                retained_digests.insert(digest);
            }
        }
    }

    let mut tombstones = Vec::with_capacity(eviction_order.len());
    let mut evicted_digests: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut reclaimable_bytes = 0_u64;
    let mut proxies_shed_count = 0_u64;
    let mut sources_evicted_count = 0_u64;

    for &idx in eviction_order {
        let cand = &candidates[idx];
        let reason = evicted_reason
            .get(&idx)
            .copied()
            .ok_or(PackError::ArithmeticOverflow)?;
        let mut sorted_digests = cand.object_digests.clone();
        sorted_digests.sort_unstable();
        sorted_digests.dedup();
        for &d in &sorted_digests {
            evicted_digests.insert(d);
        }
        reclaimable_bytes = reclaimable_bytes
            .checked_add(cand.byte_size)
            .ok_or(PackError::ArithmeticOverflow)?;
        if cand.is_derived_proxy {
            proxies_shed_count = proxies_shed_count.saturating_add(1);
        } else {
            sources_evicted_count = sources_evicted_count.saturating_add(1);
        }
        let reason_digest = tombstone_reason_digest(&cand.import_id, reason, evaluated_at_ns)?;
        tombstones.push(DeletionTombstone {
            import_id: cand.import_id.clone(),
            sensor_id: cand.sensor_id.clone(),
            is_derived_proxy: cand.is_derived_proxy,
            byte_size: cand.byte_size,
            object_digests: sorted_digests,
            reason,
            reason_digest,
            evicted_at_ns: evaluated_at_ns,
        });
    }

    let reclaimable_digests: Vec<ContentDigest> = evicted_digests
        .difference(&retained_digests)
        .copied()
        .collect();

    Ok(RetentionEvictionBatch {
        evaluated_at_ns,
        pressure_before,
        pressure_after,
        total_bytes_before,
        total_bytes_after,
        pinned_bytes,
        reclaimable_bytes,
        proxies_shed_count,
        sources_evicted_count,
        accelerate_compaction: pressure_before.should_accelerate_compaction()
            || pressure_after.should_accelerate_compaction(),
        tombstones,
        reclaimable_digests,
    })
}
