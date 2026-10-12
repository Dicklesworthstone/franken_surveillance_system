#![forbid(unsafe_code)]
//! Exact current source bytes behind the witnesses that permit this wait to park.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{BudgetVector, CanonicalDecode, CanonicalEncode, ContentDigest, SensorCapsule};
use fss_object::{CorruptionKind, SPOOL_OBJECT_HEADER_LEN, SpoolError};
use fss_publication::SlotName;

use super::{
    FollowWaitBinding, FollowWaitBoundary, FollowWaitControl, FollowWaitError, FollowWaitProgress,
};
use crate::agent_follow::FollowError;
use crate::agent_orient::{DeploymentHistory, DeploymentReadError, DeploymentSnapshot};
use crate::ingest::source_coverage::SourceFrame;

mod recorded;

pub(super) fn read_error(error: DeploymentReadError) -> FollowWaitError {
    FollowWaitError::Follow(FollowError::Read(error))
}

fn invalid(detail: impl Into<String>) -> FollowWaitError {
    read_error(DeploymentReadError::Corrupt {
        reason: format!("follow source custody: {}", detail.into()),
    })
}

/// One comparison owns this bounded cache. A later poll creates a new one and reads every
/// selected object again; no former custody result authorizes a later quiet observation.
struct SourceAudit<'a> {
    history: &'a DeploymentHistory,
    snapshot: &'a DeploymentSnapshot,
    binding: &'a FollowWaitBinding,
    control: &'a mut dyn FollowWaitControl,
    progress: &'a mut FollowWaitProgress,
    required_witnesses: &'a BTreeSet<ContentDigest>,
    verified_witnesses: BTreeSet<ContentDigest>,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
}

impl SourceAudit<'_> {
    fn history(&self) -> &DeploymentHistory {
        self.history
    }

    fn checkpoint(&mut self) -> Result<(), FollowWaitError> {
        super::checkpoint(
            self.binding,
            self.control,
            FollowWaitBoundary::Source,
            self.progress,
        )?;
        if self.progress.elapsed_ms >= self.binding.wait_ms() {
            return Err(FollowWaitError::SourceDeadlineReached);
        }
        Ok(())
    }

    fn requires_witness(&self, digest: ContentDigest) -> bool {
        self.required_witnesses.contains(&digest)
    }

    fn witness_verified(&mut self, digest: ContentDigest) {
        self.verified_witnesses.insert(digest);
    }

    fn remaining_objects(&self) -> usize {
        self.binding
            .max_source_reads()
            .saturating_sub(self.progress.source_read_attempts) as usize
    }

    fn reserve(&mut self, envelope: u64) -> Result<(), FollowWaitError> {
        let reads = self
            .progress
            .source_read_attempts
            .checked_add(1)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let bytes = self
            .progress
            .source_reserved_bytes
            .checked_add(envelope)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        if reads > self.binding.max_source_reads()
            || bytes > self.binding.max_source_envelope_bytes()
        {
            return Err(FollowWaitError::SourceBudgetExhausted);
        }
        let gross = self
            .progress
            .source_requested_bytes
            .checked_add(envelope)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let mut request = BudgetVector::ZERO;
        request.bytes = envelope;
        request.storage_operations = 1;
        let requested = self
            .progress
            .requested
            .checked_add(&request)
            .map_err(|_| FollowWaitError::AccountingOverflow)?;
        let mut attempt = BudgetVector::ZERO;
        attempt.storage_operations = 1;
        let consumed = self
            .progress
            .consumed
            .checked_add(&attempt)
            .map_err(|_| FollowWaitError::AccountingOverflow)?;
        self.progress.source_read_attempts = reads;
        self.progress.source_reserved_bytes = bytes;
        self.progress.source_requested_bytes = gross;
        self.progress.requested = requested;
        self.progress.consumed = consumed;
        Ok(())
    }

    fn verified(
        &mut self,
        bytes: usize,
        metadata: bool,
        reservation: u64,
    ) -> Result<(), FollowWaitError> {
        let bytes = u64::try_from(bytes).map_err(|_| FollowWaitError::AccountingOverflow)?;
        let overhead = if metadata {
            1
        } else {
            SPOOL_OBJECT_HEADER_LEN as u64 + 1
        };
        let envelope = bytes
            .checked_add(overhead)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let unused = reservation
            .checked_sub(envelope)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let charged = self
            .progress
            .source_reserved_bytes
            .checked_sub(unused)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let completed = self
            .progress
            .verified_source_reads
            .checked_add(1)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let payload_bytes = self
            .progress
            .source_payload_bytes
            .checked_add(if metadata { 0 } else { bytes })
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let metadata_bytes = self
            .progress
            .source_metadata_bytes
            .checked_add(if metadata { bytes } else { 0 })
            .ok_or(FollowWaitError::AccountingOverflow)?;
        let mut measured = BudgetVector::ZERO;
        measured.bytes = bytes;
        let consumed = self
            .progress
            .consumed
            .checked_add(&measured)
            .map_err(|_| FollowWaitError::AccountingOverflow)?;
        self.progress.source_reserved_bytes = charged;
        self.progress.verified_source_reads = completed;
        self.progress.source_payload_bytes = payload_bytes;
        self.progress.source_metadata_bytes = metadata_bytes;
        self.progress.consumed = consumed;
        Ok(())
    }

    fn read(&mut self, digest: ContentDigest) -> Result<&[u8], FollowWaitError> {
        self.checkpoint()?;
        if !self.objects.contains_key(&digest) {
            if self.snapshot.deletions.object(digest).is_some() {
                return Err(invalid(format!("selected object {digest} is deleted")));
            }
            let remaining = self
                .binding
                .max_source_envelope_bytes()
                .checked_sub(self.progress.source_reserved_bytes)
                .ok_or(FollowWaitError::AccountingOverflow)?;
            let overhead = SPOOL_OBJECT_HEADER_LEN as u64 + 1;
            let maximum = remaining
                .checked_sub(overhead)
                .filter(|maximum| *maximum > 0)
                .ok_or(FollowWaitError::SourceBudgetExhausted)?
                .min(self.binding.read_limits().max_object_bytes as u64);
            let maximum =
                usize::try_from(maximum).map_err(|_| FollowWaitError::AccountingOverflow)?;
            let reservation = maximum as u64 + overhead;
            self.reserve(reservation)?;
            self.history
                .wait_check_tombstone(digest)
                .map_err(read_error)?;
            // Tombstone checks are I/O too. Recheck the live deadline before the payload read.
            self.checkpoint()?;
            let bytes =
                self.history
                    .wait_read_object(digest, maximum)
                    .map_err(|error| match &error {
                        fss_publication::LocalPublicationError::Spool(
                            SpoolError::Corrupt {
                                kind: CorruptionKind::DeclaredLengthExceedsLimit { .. },
                                ..
                            }
                            | SpoolError::ObjectTooLarge { .. },
                        ) => FollowWaitError::SourceBudgetExhausted,
                        _ => invalid(format!("selected object {digest}: {error}")),
                    })?;
            self.verified(bytes.len(), false, reservation)?;
            super::checkpoint(
                self.binding,
                self.control,
                FollowWaitBoundary::Observe,
                self.progress,
            )?;
            self.checkpoint()?;
            self.history
                .wait_check_tombstone(digest)
                .map_err(read_error)?;
            self.objects.insert(digest, bytes);
        }
        self.objects
            .get(&digest)
            .map(Vec::as_slice)
            .ok_or_else(|| invalid("verified source cache lost an admitted object"))
    }

    fn verify_publication(
        &mut self,
        slot: &SlotName,
        root: ContentDigest,
        child_count: usize,
    ) -> Result<(), FollowWaitError> {
        self.checkpoint()?;
        let expected = fss_publication::root_record_bytes(slot, root, child_count)
            .map_err(|error| invalid(format!("publication record: {error}")))?;
        let reservation = (expected.len() as u64)
            .checked_add(1)
            .ok_or(FollowWaitError::AccountingOverflow)?;
        self.reserve(reservation)?;
        let bytes = self
            .history
            .wait_read_publication(slot, expected.len())
            .map_err(read_error)?;
        if bytes != expected {
            return Err(invalid(format!(
                "publication {slot} is not its exact durable record"
            )));
        }
        self.verified(bytes.len(), true, reservation)?;
        super::checkpoint(
            self.binding,
            self.control,
            FollowWaitBoundary::Observe,
            self.progress,
        )?;
        Ok(())
    }
}

pub(super) fn verify(
    history: &DeploymentHistory,
    snapshot: &DeploymentSnapshot,
    witnesses: &BTreeSet<ContentDigest>,
    binding: &FollowWaitBinding,
    control: &mut dyn FollowWaitControl,
    progress: &mut FollowWaitProgress,
) -> Result<(), FollowWaitError> {
    let mut audit = SourceAudit {
        history,
        snapshot,
        binding,
        control,
        progress,
        required_witnesses: witnesses,
        verified_witnesses: BTreeSet::new(),
        objects: BTreeMap::new(),
    };
    if witnesses.is_empty() {
        return Err(invalid("quiet comparison names no source coverage witness"));
    }
    for retained in &snapshot.source_coverage {
        let record = &retained.record;
        let witness = record.witness.witness_digest();
        if !audit.requires_witness(witness) {
            continue;
        }
        audit.checkpoint()?;
        if retained.verdict.is_err() {
            return Err(invalid(
                "selected source witness has no current custody verdict",
            ));
        }
        audit.read(retained.payload_digest)?;
        if audit.read(record.witness_object())? != record.witness.canonical_bytes() {
            return Err(invalid(
                "source witness bytes differ from their retained record",
            ));
        }
        if record.source_objects().collect::<BTreeSet<_>>().len() > audit.remaining_objects() {
            return Err(FollowWaitError::SourceBudgetExhausted);
        }
        for frame in &record.frames {
            let capsule = SensorCapsule::from_canonical_bytes(audit.read(frame.capsule_digest)?)
                .map_err(|error| invalid(format!("source capsule: {error}")))?;
            if SourceFrame::of(&frame.failure_domain, &capsule) != *frame {
                return Err(invalid(
                    "source capsule does not reproduce the retained frame",
                ));
            }
            audit.read(frame.source_digest)?;
        }
        audit.witness_verified(witness);
    }
    recorded::verify(&mut audit, snapshot)?;
    if audit.verified_witnesses != *witnesses {
        return Err(invalid(
            "the complete selected witness set was not source-verified",
        ));
    }
    audit.checkpoint()?;
    Ok(())
}
