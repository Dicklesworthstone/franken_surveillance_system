#![forbid(unsafe_code)]
//! Durable control intake and execution boundaries, separate from semantic effect completion.
//!
//! Retained requests are inert audit facts. Reopening restores no grant, queue entry, dispatch
//! permit, or retry authority. The supplied journal owns filesystem custody and pin verification.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use fss_core::{ContentDigest, OperationId, PrincipalId};
use fss_ipc::{BoundedControlOp, RequestContext};
use fss_object::SpoolIo;
use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};

use super::PendingControlCommand;
use crate::telemetry::escape_json;

mod codec;
mod files;

#[cfg(test)]
mod tests;

pub use files::inspect_control_history;
pub use fss_ipc::RetainedControlProgress as ControlProgress;

/// Versioned canonical control bookkeeping domain. These records are not evidence-ledger facts.
pub const CONTROL_JOURNAL_DOMAIN: &str = "fss.daemon.control_journal.v1";
/// Maximum complete control-history records, including bootstrap and transition records.
pub const MAX_CONTROL_HISTORY_RECORDS: usize = 16_384;
/// Maximum canonical payload size before the existing journal's storage envelope.
pub const MAX_CONTROL_RECORD_BYTES: usize = 16 * 1024;
/// Maximum entries copied into one inspection report; older entries remain retained.
pub const MAX_CONTROL_INSPECTION_ENTRIES: usize = 1_024;

/// Original accepted control and its most recent durable execution boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlHistoryEntry {
    /// Original stable operation identity and exact approved command.
    pub command: PendingControlCommand,
    /// Stable caller retry key, absent only for legacy unkeyed admissions.
    pub idempotency_key: Option<ContentDigest>,
    /// Original authenticated principal; recovery does not restore a live grant.
    pub principal: PrincipalId,
    /// Exact semantic universe admitted by the original connection.
    pub contract_basis_digest: ContentDigest,
    /// Normalized granted capability names, retained only as inert audit facts.
    pub granted_capabilities: Vec<String>,
    /// Original connection correlation; this is not an idempotency key.
    pub connection_id: u64,
    /// Original request correlation; this is not an idempotency key.
    pub request_id: u64,
    /// Journal record at which this operation was first retained.
    pub accepted_sequence: u64,
    /// Latest retained execution boundary.
    pub progress: ControlProgress,
    /// True when this entry predates this owner and cannot enter its live queue.
    pub recovered: bool,
}

/// Bounded inspection of complete verified history, preserving omission counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlHistoryReport {
    /// Deployment to which the complete history is bound.
    pub deployment_id: String,
    /// Exact contract basis bound by the journal bootstrap.
    pub contract_basis_digest: ContentDigest,
    /// Verified journal head, suitable for separate owner checkpoint custody.
    pub head: EffectJournalPin,
    /// Number of accepted controls in the complete history.
    pub total_entries: usize,
    /// Oldest entries omitted from this bounded report.
    pub omitted_entries: usize,
    /// Most recent entries in acceptance order; recovery never queues them.
    pub entries: Vec<ControlHistoryEntry>,
}

impl ControlHistoryReport {
    /// Renders bounded operator diagnostics without making effect completion claims.
    #[must_use]
    pub fn to_json(&self) -> String {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                let target = entry.command.target_camera_id.as_deref().map_or_else(
                    || "null".to_owned(),
                    |value| format!("\"{}\"", escape_json(value)),
                );
                let capabilities = entry
                    .granted_capabilities
                    .iter()
                    .map(|value| format!("\"{}\"", escape_json(value)))
                    .collect::<Vec<_>>()
                    .join(",");
                let key = entry.idempotency_key.map_or_else(
                    || "null".to_owned(),
                    |digest| format!("\"{}\"", digest.to_text()),
                );
                format!(
                    concat!(
                        "{{\"operation_id\":\"{}\",\"operation\":\"{}\",",
                        "\"target_camera_id\":{},\"approval_digest\":\"{}\",\"idempotency_key\":{},",
                        "\"principal\":\"{}\",\"contract_basis_digest\":\"{}\",",
                        "\"granted_capabilities\":[{}],\"connection_id\":{},\"request_id\":{},",
                        "\"accepted_sequence\":{},\"progress\":\"{}\",\"recovered\":{}}}"
                    ),
                    escape_json(entry.command.operation_id.as_str()),
                    entry.command.op.as_str(),
                    target,
                    entry.command.approval_digest.to_text(),
                    key,
                    escape_json(entry.principal.as_str()),
                    entry.contract_basis_digest.to_text(),
                    capabilities,
                    entry.connection_id,
                    entry.request_id,
                    entry.accepted_sequence,
                    entry.progress.as_str(),
                    entry.recovered,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"schema\":\"fss.daemon_control_history.v1\",\"deployment_id\":\"{}\",",
                "\"contract_basis_digest\":\"{}\",\"head_sequence\":{},\"head_root\":\"{}\",",
                "\"total_entries\":{},\"omitted_entries\":{},\"automatic_replay\":false,",
                "\"semantic_completion_proved\":false,\"entries\":[{}]}}"
            ),
            escape_json(&self.deployment_id),
            self.contract_basis_digest.to_text(),
            self.head.sequence,
            self.head.root.to_text(),
            self.total_entries,
            self.omitted_entries,
            entries,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    deployment_id: String,
    root_digest: ContentDigest,
    basis_digest: ContentDigest,
}

/// Exclusive control owner. Recovered commands remain outside the live authority set.
#[derive(Debug)]
pub struct DurableControlJournal {
    scope: Scope,
    store: Box<dyn EffectJournalStore>,
    entries: Vec<ControlHistoryEntry>,
    indexes: BTreeMap<OperationId, usize>,
    retry_indexes: BTreeMap<ContentDigest, usize>,
    live: BTreeSet<OperationId>,
    poisoned: bool,
}

pub(super) enum ControlReplayLookup<'a> {
    Missing,
    Match(&'a ControlHistoryEntry),
    Conflict,
}

impl DurableControlJournal {
    /// Opens deployment-root-backed journal and trusted local pins, or creates both fresh.
    /// Partial initialization, missing pins, and unequal custody heads are refused.
    pub fn open(
        root: &Path,
        deployment_id: &str,
        io: Arc<dyn SpoolIo>,
    ) -> Result<Self, EffectPersistenceError> {
        files::open(root, deployment_id, io, true)
    }

    fn from_store(
        scope: Scope,
        mut store: Box<dyn EffectJournalStore>,
        fresh: bool,
    ) -> Result<Self, EffectPersistenceError> {
        let header = codec::header(&scope)?;
        if fresh {
            if store.head().is_some() || !store.records().is_empty() {
                return Err(invalid("fresh control journal is not empty"));
            }
            store.reserve_capacity(1, header.len())?;
            store.append(None, &header)?;
        }
        let head = store
            .head()
            .ok_or_else(|| invalid("control bootstrap is missing"))?;
        if head.sequence as u128 != store.records().len() as u128
            || !store.contains(head)
            || store.records().len() > MAX_CONTROL_HISTORY_RECORDS
            || store.records().first() != Some(&header)
        {
            return Err(invalid(
                "control journal scope or complete history does not match",
            ));
        }
        let mut entries: Vec<ControlHistoryEntry> = Vec::new();
        let mut indexes = BTreeMap::new();
        let mut retry_indexes = BTreeMap::new();
        for (index, bytes) in store.records().iter().enumerate().skip(1) {
            match codec::decode(&scope, bytes)? {
                codec::Record::Accepted(mut entry) => {
                    if entry.accepted_sequence as u128 != index as u128 + 1 {
                        return Err(invalid(
                            "control acceptance sequence does not match history",
                        ));
                    }
                    entry.recovered = true;
                    if indexes
                        .insert(entry.command.operation_id.clone(), entries.len())
                        .is_some()
                    {
                        return Err(invalid("duplicate retained control identity"));
                    }
                    if let Some(key) = entry.idempotency_key
                        && retry_indexes.insert(key, entries.len()).is_some()
                    {
                        return Err(invalid("duplicate retained control retry key"));
                    }
                    entries.push(entry);
                }
                codec::Record::Progress {
                    operation_id,
                    progress,
                } => {
                    let index = indexes
                        .get(&operation_id)
                        .copied()
                        .ok_or_else(|| invalid("control transition precedes admission"))?;
                    let entry = &mut entries[index];
                    check_transition(entry.progress, progress)?;
                    entry.progress = progress;
                }
            }
        }
        Ok(Self {
            scope,
            store,
            entries,
            indexes,
            retry_indexes,
            live: BTreeSet::new(),
            poisoned: false,
        })
    }

    /// Copies the newest bounded entries; old history remains retained and counted.
    pub fn inspect(&self, maximum: usize) -> Result<ControlHistoryReport, EffectPersistenceError> {
        if maximum == 0 || maximum > MAX_CONTROL_INSPECTION_ENTRIES {
            return Err(EffectPersistenceError::Capacity);
        }
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        let omitted = self.entries.len().saturating_sub(maximum);
        Ok(ControlHistoryReport {
            deployment_id: self.scope.deployment_id.clone(),
            contract_basis_digest: self.scope.basis_digest,
            head: self
                .store
                .head()
                .ok_or_else(|| invalid("control bootstrap is missing"))?,
            total_entries: self.entries.len(),
            omitted_entries: omitted,
            entries: self.entries[omitted..].to_vec(),
        })
    }

    #[cfg(test)]
    pub(super) fn admit(
        &mut self,
        context: &RequestContext,
        op: BoundedControlOp,
        target: Option<&str>,
        approval: ContentDigest,
    ) -> Result<PendingControlCommand, EffectPersistenceError> {
        self.admit_request(context, op, target, approval, None)
    }

    /// Exact retry lookup does not restore live authority or append history.
    pub(super) fn replay(
        &self,
        context: &RequestContext,
        key: ContentDigest,
        op: BoundedControlOp,
        target: Option<&str>,
        approval: ContentDigest,
    ) -> Result<ControlReplayLookup<'_>, EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        if context.deployment_id != self.scope.deployment_id
            || context.contract_basis_digest != self.scope.basis_digest
            || !codec::digest_valid(key)
        {
            return Err(invalid("invalid control retry scope or key"));
        }
        let Some(&index) = self.retry_indexes.get(&key) else {
            return Ok(ControlReplayLookup::Missing);
        };
        let entry = &self.entries[index];
        let mut capabilities = context.granted_capabilities.clone();
        capabilities.sort();
        capabilities.dedup();
        if entry.principal != context.principal
            || entry.contract_basis_digest != context.contract_basis_digest
            || entry.granted_capabilities != capabilities
            || entry.command.op != op
            || entry.command.target_camera_id.as_deref() != target
            || entry.command.approval_digest != approval
        {
            return Ok(ControlReplayLookup::Conflict);
        }
        Ok(ControlReplayLookup::Match(entry))
    }

    pub(super) fn admit_request(
        &mut self,
        context: &RequestContext,
        op: BoundedControlOp,
        target: Option<&str>,
        approval: ContentDigest,
        key: Option<ContentDigest>,
    ) -> Result<PendingControlCommand, EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        if context.deployment_id != self.scope.deployment_id
            || context.contract_basis_digest != self.scope.basis_digest
        {
            return Err(invalid(
                "control admission context differs from journal scope",
            ));
        }
        if key.is_some_and(|key| !codec::digest_valid(key) || self.retry_indexes.contains_key(&key)) {
            return Err(invalid("invalid or already retained control retry key"));
        }
        let sequence = self
            .store
            .head()
            .and_then(|pin| pin.sequence.checked_add(1))
            .ok_or_else(|| invalid("control sequence exhausted"))?;
        let mut capabilities = context.granted_capabilities.clone();
        capabilities.sort();
        capabilities.dedup();
        let entry = ControlHistoryEntry {
            command: PendingControlCommand {
                operation_id: codec::operation_id(&self.scope, op, sequence)?,
                op,
                target_camera_id: target.map(str::to_owned),
                approval_digest: approval,
            },
            idempotency_key: key,
            principal: context.principal.clone(),
            contract_basis_digest: context.contract_basis_digest,
            granted_capabilities: capabilities,
            connection_id: context.connection_id,
            request_id: context.request_id,
            accepted_sequence: sequence,
            progress: ControlProgress::NeverStarted,
            recovered: false,
        };
        let bytes = codec::encode(&self.scope, &codec::Record::Accepted(entry.clone()))?;
        // Protect capacity for both remaining boundaries of every outstanding live request.
        // Recovery never revives that work, so historical inert entries need no reservation.
        let followups: usize = self
            .live
            .iter()
            .filter_map(|operation| self.indexes.get(operation))
            .map(|&index| match self.entries[index].progress {
                ControlProgress::NeverStarted => 2,
                ControlProgress::DispatchStarted => 1,
                ControlProgress::SubsystemReturned | ControlProgress::CancelledBeforeExecution => 0,
            })
            .sum();
        self.store
            .reserve_capacity(followups.saturating_add(3), bytes.len().max(512))?;
        self.append(&bytes)?;
        self.live.insert(entry.command.operation_id.clone());
        self.indexes
            .insert(entry.command.operation_id.clone(), self.entries.len());
        if let Some(key) = key {
            self.retry_indexes.insert(key, self.entries.len());
        }
        let command = entry.command.clone();
        self.entries.push(entry);
        Ok(command)
    }

    pub(super) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(super) fn transition(
        &mut self,
        operation_id: &OperationId,
        progress: ControlProgress,
    ) -> Result<(), EffectPersistenceError> {
        if !self.live.contains(operation_id) {
            return Err(invalid(
                "recovered or unknown control has no live dispatch authority",
            ));
        }
        let index = self
            .indexes
            .get(operation_id)
            .copied()
            .ok_or_else(|| invalid("control transition lacks admission"))?;
        check_transition(self.entries[index].progress, progress)?;
        let bytes = codec::encode(
            &self.scope,
            &codec::Record::Progress {
                operation_id: operation_id.clone(),
                progress,
            },
        )?;
        self.append(&bytes)?;
        self.entries[index].progress = progress;
        if matches!(
            progress,
            ControlProgress::SubsystemReturned | ControlProgress::CancelledBeforeExecution
        ) {
            self.live.remove(operation_id);
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        if self.store.records().len() >= MAX_CONTROL_HISTORY_RECORDS {
            return Err(EffectPersistenceError::Capacity);
        }
        let expected = self.store.head();
        match self.store.append(expected, bytes) {
            Ok(pin)
                if self.store.head() == Some(pin)
                    && self.store.contains(pin)
                    && Some(pin.sequence)
                        == expected.and_then(|prior| prior.sequence.checked_add(1))
                    && pin.sequence as u128 == self.store.records().len() as u128
                    && self.store.records().last().map(Vec::as_slice) == Some(bytes) =>
            {
                Ok(())
            }
            Ok(_) => {
                self.poisoned = true;
                Err(invalid("control journal append receipt mismatch"))
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

fn check_transition(
    previous: ControlProgress,
    next: ControlProgress,
) -> Result<(), EffectPersistenceError> {
    if matches!(
        (previous, next),
        (
            ControlProgress::NeverStarted,
            ControlProgress::DispatchStarted | ControlProgress::CancelledBeforeExecution
        ) | (
            ControlProgress::DispatchStarted,
            ControlProgress::SubsystemReturned
        )
    ) {
        Ok(())
    } else {
        Err(invalid("illegal or repeated control execution boundary"))
    }
}

fn invalid(detail: &'static str) -> EffectPersistenceError {
    EffectPersistenceError::InvalidHistory(detail)
}
