//! Two-phase effects owned by a retained canonical journal (FSS-027).
//!
//! Preparation binds exact intent, approval, original authority, resource and
//! lease. Only the first successful commit yields a dispatch permit. Clonable
//! preparation handles are inert: dropping or recovering them never reissues a
//! permit, erases canonical state, or discharges an outstanding obligation.
//!
//! Adapter acceptance is distinct from observation and verification. Evidence
//! and reconciliation follow `fss-core::EffectJournal`; terminal settlement is
//! checked against the original region obligation before either store advances.
//! Optional explicit storage persists each transition before its live result is
//! published. Cold recovery restores inert history for reconciliation only;
//! provider-authenticity checks remain the responsibility of their existing owners.

mod recovery;

use std::collections::BTreeMap;
use std::sync::Arc;

use fss_core::effect::{
    EffectAuthority, EffectIntent, IndeterminateEffectReason,
    PreparedEffect as CanonicalPreparedEffect,
};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContextAuthority, ContractError,
    EffectJournal, EffectJournalTransition, EffectState, IdempotencyKey, ObligationId,
    ObligationState, OperationId, OperationReceipt, RegionId, RegionTree, RuntimeGrant,
    TimestampNs,
};

use crate::authority::{AuthorityBinding, AuthorityCx};
use crate::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};
use crate::grant::GrantError;
use crate::lease::{LeaseError, LeaseRegistry, LeaseRegistryBinding, LeaseState};
use recovery::{JournalEvent, RetainedPreparation};

/// Hard bound on retained operations; terminal records are never silently evicted.
pub const MAX_RETAINED_EFFECTS: usize = 4096;
/// Maximum byte length of an effect's leased resource identity.
pub const MAX_EFFECT_RESOURCE_LEN: usize = 1024;
/// Digest domain for the complete runtime preparation and original authority binding.
pub const PREPARATION_DIGEST_DOMAIN: &str = "fss.runtime_effect_preparation.v1";

/// Inputs to [`EffectCoordinator::prepare`]. No cognition value grants authority.
#[derive(Clone, Debug)]
pub struct PrepareSpec<'a> {
    /// Operation identity.
    pub operation: &'a OperationId,
    /// Stable replay identity for this exact intent.
    pub idempotency_key: IdempotencyKey,
    /// Exact external request digest.
    pub request_digest: ContentDigest,
    /// Exact preconditions to revalidate before commitment.
    pub precondition_digest: ContentDigest,
    /// The resource under lease.
    pub resource: &'a str,
    /// The fence token captured from the lease.
    pub fence: u64,
    /// Capability required at prepare time.
    pub prepare_grant: RuntimeGrant,
    /// Capability required at commit time.
    pub commit_grant: RuntimeGrant,
    /// Terminal predicate recorded on the obligation.
    pub terminal_predicate: &'a str,
}

/// Explicit approval of one complete preparation and its current preconditions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitApproval {
    /// Digest returned by [`PreparedEffect::digest`].
    pub prepared_digest: ContentDigest,
    /// Independently revalidated current precondition digest.
    pub current_precondition_digest: ContentDigest,
}

/// Evidence-only recovery actions; none authorizes another dispatch.
#[derive(Clone, Copy, Debug)]
pub enum Reconciliation<'a> {
    /// Record an observed external outcome.
    Observed(ContentDigest),
    /// Verify the exact previously observed proof.
    Verified(ContentDigest),
    /// Establish a known failure with evidence and a bounded reason.
    Failed {
        /// Evidence of the failure.
        proof: ContentDigest,
        /// Nonempty bounded failure reason.
        reason: &'a str,
    },
    /// Retain an explicit unresolved outcome and its reconciliation note.
    Indeterminate(&'a str),
    /// Cancel an uncommitted preparation, binding the evidence to the whole record.
    Cancelled(ContentDigest),
}

/// Typed coordinator refusal. Every variant carries the operation identity.
#[derive(Clone, Debug, PartialEq)]
pub enum EffectCoordError {
    /// The durable owner refused a write or requires cold recovery after ambiguity.
    Persistence {
        /// The operation.
        operation: String,
        /// The persistence refusal.
        error: EffectPersistenceError,
    },
    /// Recovered history can reconcile outcomes but cannot authorize dispatch.
    RecoveryOnly {
        /// The operation.
        operation: String,
    },
    /// The inert handle belongs to another live coordinator.
    WrongCoordinator {
        /// The operation.
        operation: String,
    },
    /// The canonical effect journal refused a transition or conflicting retry.
    Journal {
        /// The operation.
        operation: String,
        /// The canonical refusal.
        error: ContractError,
    },
    /// Approval did not name the complete original preparation.
    ApprovalMismatch {
        /// The operation.
        operation: String,
        /// Digest of the original preparation.
        expected: ContentDigest,
        /// Digest supplied for approval.
        presented: ContentDigest,
    },
    /// Current preconditions differ from those that were prepared.
    PreconditionMismatch {
        /// The operation.
        operation: String,
        /// Original preconditions.
        expected: ContentDigest,
        /// Revalidated current preconditions.
        current: ContentDigest,
    },
    /// Retaining another operation would exceed the owner's hard bound.
    Capacity {
        /// The operation.
        operation: String,
        /// Maximum retained operations.
        limit: usize,
    },
    /// A preparation already exists for this operation in the owned tree.
    DuplicateOperation {
        /// The operation.
        operation: String,
    },
    /// The capability pair does not name one registered domain effect.
    InvalidGrantPair {
        /// The operation.
        operation: String,
        /// The requested prepare capability.
        prepare: RuntimeGrant,
        /// The requested commit capability.
        commit: RuntimeGrant,
    },
    /// A different authority attempted to use the preparing scope's token.
    WrongAuthority {
        /// The operation.
        operation: String,
    },
    /// Commit was presented with a registry other than the one that issued the
    /// prepared fence, even if the replacement has the same numeric token.
    WrongLeaseRegistry {
        /// The operation.
        operation: String,
    },
    /// The preparing scope's deadline has elapsed at the caller's commit time.
    Deadline {
        /// The operation.
        operation: String,
        /// The immutable authority deadline.
        deadline: TimestampNs,
        /// The supplied commit time.
        now: TimestampNs,
    },
    /// The current lease belongs to a different region.
    LeaseHolder {
        /// The operation.
        operation: String,
        /// The leased resource.
        resource: String,
        /// The preparing region.
        expected: String,
        /// The current lease holder.
        actual: String,
    },
    /// A required capability grant is missing.
    Grant {
        /// The operation.
        operation: String,
        /// The grant failure.
        error: GrantError,
    },
    /// The resource fence failed at commit time.
    Fence {
        /// The operation.
        operation: String,
        /// The lease failure.
        error: LeaseError,
    },
    /// An illegal state transition was attempted.
    IllegalTransition {
        /// The operation.
        operation: String,
        /// Current state.
        from: fss_core::EffectState,
        /// Attempted target.
        to: fss_core::EffectState,
    },
    /// The region tree refused the obligation step.
    Region {
        /// The operation.
        operation: String,
        /// The tree error spelled out.
        detail: String,
    },
    /// An Indeterminate terminal was attempted without a reconciliation
    /// note (INV-006).
    IndeterminateWithoutNote {
        /// The operation.
        operation: String,
    },
}

impl std::fmt::Display for EffectCoordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Persistence { operation, error } => {
                write!(f, "effect {operation}: {error}")
            }
            Self::RecoveryOnly { operation } => {
                write!(
                    f,
                    "effect {operation}: recovered owner permits reconciliation only"
                )
            }
            Self::WrongCoordinator { operation } => {
                write!(
                    f,
                    "effect {operation}: handle belongs to another coordinator"
                )
            }
            Self::Journal { operation, error } => {
                write!(f, "effect {operation}: canonical journal refusal: {error}")
            }
            Self::ApprovalMismatch {
                operation,
                expected,
                presented,
            } => {
                write!(
                    f,
                    "effect {operation}: approval {presented} differs from preparation {expected}"
                )
            }
            Self::PreconditionMismatch {
                operation,
                expected,
                current,
            } => {
                write!(
                    f,
                    "effect {operation}: preconditions changed from {expected} to {current}"
                )
            }
            Self::Capacity { operation, limit } => {
                write!(
                    f,
                    "effect {operation}: retained operation limit {limit} reached"
                )
            }
            Self::DuplicateOperation { operation } => {
                write!(
                    f,
                    "effect {operation}: operation already prepared in this tree"
                )
            }
            Self::InvalidGrantPair {
                operation,
                prepare,
                commit,
            } => {
                write!(
                    f,
                    "effect {operation}: invalid effect grant pair {prepare}/{commit}"
                )
            }
            Self::WrongAuthority { operation } => {
                write!(
                    f,
                    "effect {operation}: authority differs from the preparing scope"
                )
            }
            Self::WrongLeaseRegistry { operation } => {
                write!(
                    f,
                    "effect {operation}: lease registry differs from the preparing registry"
                )
            }
            Self::Deadline {
                operation,
                deadline,
                now,
            } => {
                write!(
                    f,
                    "effect {operation}: authority deadline {deadline:?} elapsed at {now:?}"
                )
            }
            Self::LeaseHolder {
                operation,
                resource,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "effect {operation}: resource {resource} is held by {actual}, expected {expected}"
                )
            }
            Self::Grant { operation, error } => {
                write!(f, "effect {operation}: grant failure: {error}")
            }
            Self::Fence { operation, error } => {
                write!(f, "effect {operation}: fence failure: {error}")
            }
            Self::IllegalTransition {
                operation,
                from,
                to,
            } => write!(
                f,
                "effect {operation}: illegal transition {} → {}",
                from.as_str(),
                to.as_str()
            ),
            Self::Region { operation, detail } => {
                write!(f, "effect {operation}: region tree refusal: {detail}")
            }
            Self::IndeterminateWithoutNote { operation } => {
                write!(
                    f,
                    "effect {operation}: indeterminate without reconciliation note"
                )
            }
        }
    }
}

impl std::error::Error for EffectCoordError {}

/// A refused transition together with the original, unmodified effect token.
///
/// Refusal does not abandon the pending or indeterminate obligation. Inspect
/// [`Self::error`] and recover the token with [`Self::into_token`] or
/// [`Self::into_parts`] to retry, cancel a preparation, or reconcile an effect.
/// Recovery preserves its existing authority. Every retry validates the live
/// owner; commit also revalidates its issuing registry and current lease.
///
/// Only refusals allocate storage for the retained token.
#[derive(Debug)]
pub struct EffectTransitionError<T> {
    error: EffectCoordError,
    token: Box<T>,
}

impl<T> EffectTransitionError<T> {
    /// The typed reason the transition was refused.
    #[must_use]
    pub fn error(&self) -> &EffectCoordError {
        &self.error
    }

    /// Inspect the retained token without creating another owner.
    #[must_use]
    pub fn token(&self) -> &T {
        &self.token
    }

    /// Recover the original token to retry or perform its remaining cleanup.
    #[must_use]
    pub fn into_token(self) -> T {
        *self.token
    }

    /// Recover the refusal reason and original token, in that order.
    #[must_use]
    pub fn into_parts(self) -> (EffectCoordError, T) {
        (self.error, *self.token)
    }
}

impl<T> std::fmt::Display for EffectTransitionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl<T: std::fmt::Debug> std::error::Error for EffectTransitionError<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Immutable preparation metadata. Live identities never enter the canonical digest.
#[derive(Debug)]
struct PreparationBinding {
    prepared: CanonicalPreparedEffect,
    authority: AuthorityBinding,
    lease_registry: Option<LeaseRegistryBinding>,
    context: ContextAuthority,
    owner: RegionId,
    resource: String,
    fence: u64,
    prepare_grant: RuntimeGrant,
    commit_grant: RuntimeGrant,
}

impl CanonicalEncode for PreparationBinding {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.prepared.encode_canonical(encoder);
        self.context.encode_canonical(encoder);
        self.owner.encode_canonical(encoder);
        encoder.text(&self.resource);
        encoder.u64(self.fence);
        encoder.text(self.prepare_grant.as_str());
        encoder.text(self.commit_grant.as_str());
    }
}

/// An inert handle to one retained preparation. Cloning it never grants dispatch.
/// Obtain current state from the coordinator rather than a stale handle snapshot.
#[derive(Clone, Debug)]
pub struct PreparedEffect {
    coordinator: Arc<()>,
    binding: Arc<PreparationBinding>,
}

impl PreparedEffect {
    /// Immutable operation identity.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.binding.prepared.intent.operation_id
    }

    /// The obligation registered on the preparing region.
    #[must_use]
    pub fn obligation(&self) -> &ObligationId {
        &self.binding.prepared.obligation_id
    }

    /// The exact resource named at preparation.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.binding.resource
    }

    /// The immutable fence captured at preparation.
    #[must_use]
    pub fn fence(&self) -> u64 {
        self.binding.fence
    }

    /// The terminal predicate registered at prepare time.
    #[must_use]
    pub fn terminal_predicate(&self) -> &str {
        &self.binding.prepared.terminal_predicate
    }

    /// The whole preparation, authority and resource binding that must be approved.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.binding.canonical_digest(PREPARATION_DIGEST_DOMAIN)
    }
}

impl AsRef<PreparedEffect> for PreparedEffect {
    fn as_ref(&self) -> &PreparedEffect {
        self
    }
}

/// The unique dispatch permit issued by the first successful commit.
/// Dropping it leaves canonical state and its obligation retained for reconciliation;
/// no method recovers or clones a committed permit.
#[derive(Debug)]
pub struct CommittedEffect {
    inner: PreparedEffect,
}

impl CommittedEffect {
    /// Inert preparation metadata; this reference confers no second dispatch permit.
    #[must_use]
    pub fn prepared(&self) -> &PreparedEffect {
        &self.inner
    }

    /// The operation identity.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        self.inner.operation()
    }

    /// The exact resource authorized at commit.
    #[must_use]
    pub fn resource(&self) -> &str {
        self.inner.resource()
    }

    /// The fence revalidated at commit.
    #[must_use]
    pub fn fence(&self) -> u64 {
        self.inner.fence()
    }
}

impl AsRef<PreparedEffect> for CommittedEffect {
    fn as_ref(&self) -> &PreparedEffect {
        &self.inner
    }
}

/// Bounded owner of canonical effect state and original authority bindings.
/// The journal remains available even if every caller handle is dropped. Use
/// [`Self::with_journal`] to retain transitions across process restarts.
#[derive(Debug)]
pub struct EffectCoordinator {
    identity: Arc<()>,
    journal: EffectJournal,
    bindings: BTreeMap<OperationId, Arc<PreparationBinding>>,
    unbound: BTreeMap<OperationId, RetainedPreparation>,
    persistence: Option<Box<dyn EffectJournalStore>>,
    durable_head: Option<EffectJournalPin>,
    persistence_poisoned: bool,
    reconciliation_only: bool,
}

impl Default for EffectCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl EffectCoordinator {
    /// Creates an empty live owner. This is not a durable-journal restore operation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            identity: Arc::new(()),
            journal: EffectJournal::new(),
            bindings: BTreeMap::new(),
            unbound: BTreeMap::new(),
            persistence: None,
            durable_head: None,
            persistence_poisoned: false,
            reconciliation_only: false,
        }
    }

    /// Canonical receipts and obligations, read-only to prevent bypassing runtime ownership.
    #[must_use]
    pub fn journal(&self) -> &EffectJournal {
        &self.journal
    }

    /// Recovers only inert preparation metadata, including after dispatch or settlement.
    #[must_use]
    pub fn prepared(&self, operation: &OperationId) -> Option<PreparedEffect> {
        self.bindings
            .get(operation)
            .map(|binding| self.handle(binding.clone()))
    }

    /// Reads the current canonical receipt of either kind of handle.
    pub fn receipt<T: AsRef<PreparedEffect>>(
        &self,
        effect: &T,
    ) -> Result<&OperationReceipt, EffectCoordError> {
        let prepared = effect.as_ref();
        self.require_handle(prepared)?;
        self.journal
            .operation(prepared.operation())
            .ok_or_else(|| journal_error(prepared.operation(), ContractError::NotFound))
    }

    /// Reads current state from the retained journal; a handle never caches state.
    pub fn state<T: AsRef<PreparedEffect>>(
        &self,
        effect: &T,
    ) -> Result<EffectState, EffectCoordError> {
        Ok(self.receipt(effect)?.state)
    }

    /// Prepares exact intent and a pending obligation under a live authority and lease.
    /// An exact retry returns the original inert handle without replacing original time.
    pub fn prepare(
        &mut self,
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        leases: &mut LeaseRegistry,
        spec: PrepareSpec<'_>,
        now: TimestampNs,
    ) -> Result<PreparedEffect, EffectCoordError> {
        let operation = spec.operation;
        let op_str = operation.to_string();
        self.require_persistence_ready(operation)?;
        if self.reconciliation_only {
            return Err(EffectCoordError::RecoveryOnly { operation: op_str });
        }
        let effect_class = registered_effect_class(spec.prepare_grant, spec.commit_grant)
            .ok_or_else(|| EffectCoordError::InvalidGrantPair {
                operation: op_str.clone(),
                prepare: spec.prepare_grant,
                commit: spec.commit_grant,
            })?;
        let intent = EffectIntent::new(
            operation.clone(),
            spec.idempotency_key,
            effect_class,
            spec.request_digest,
            spec.precondition_digest,
        )
        .map_err(|error| EffectCoordError::Region {
            operation: op_str.clone(),
            detail: error.to_string(),
        })?;
        if let Some(binding) = self.bindings.get(operation) {
            let handle = self.handle(binding.clone());
            self.require_scope(&handle, authority, tree)?;
            if binding.lease_registry.as_ref() != Some(leases.binding()) {
                return Err(EffectCoordError::WrongLeaseRegistry { operation: op_str });
            }
            // The core journal compares intent on duplicate keys. The runtime additionally
            // binds the exact predicate, grant pair, resource, live scope and issuing registry.
            if binding.prepared.intent != intent
                || binding.prepared.terminal_predicate != spec.terminal_predicate
                || binding.resource != spec.resource
                || binding.fence != spec.fence
                || binding.prepare_grant != spec.prepare_grant
                || binding.commit_grant != spec.commit_grant
            {
                return Err(journal_error(operation, ContractError::IdempotencyConflict));
            }
            if now < binding.prepared.prepared_at {
                return Err(journal_error(
                    operation,
                    ContractError::InvertedTimeInterval,
                ));
            }
            return Ok(handle);
        }
        authority
            .require_active(tree)
            .map_err(|error| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: error.to_string(),
            })?;
        require_deadline(authority, tree, operation, now)?;
        authority
            .require_grant_for(spec.prepare_grant, spec.resource)
            .map_err(|error| EffectCoordError::Grant {
                operation: op_str.clone(),
                error,
            })?;
        if spec.resource.trim().is_empty() || spec.resource.len() > MAX_EFFECT_RESOURCE_LEN {
            return Err(journal_error(operation, ContractError::InvalidIdentifier));
        }
        if spec.terminal_predicate.trim().is_empty()
            || spec.terminal_predicate.len() > fss_core::effect::MAX_TERMINAL_PREDICATE_LEN
        {
            return Err(EffectCoordError::Region {
                operation: op_str,
                detail: "terminal predicate is empty or exceeds the canonical bound".to_owned(),
            });
        }
        if self.bindings.len() >= MAX_RETAINED_EFFECTS {
            return Err(EffectCoordError::Capacity {
                operation: op_str,
                limit: MAX_RETAINED_EFFECTS,
            });
        }
        require_current_lease(authority, leases, &op_str, spec.resource, spec.fence)?;
        leases
            .check_fence(spec.resource, spec.fence, now)
            .map_err(|error| EffectCoordError::Fence {
                operation: op_str.clone(),
                error,
            })?;
        // A different coordinator cannot take over this tree's existing obligation.
        if tree.iter().any(|node| {
            node.obligations
                .values()
                .any(|obligation| &obligation.operation_id == operation)
        }) {
            return Err(EffectCoordError::DuplicateOperation { operation: op_str });
        }
        let obligation = crate::obligation::new_obligation(
            format!("obligation:{operation}:terminal"),
            operation.clone(),
            spec.terminal_predicate,
        )
        .map_err(|error| journal_error(operation, error))?;
        let prepared = CanonicalPreparedEffect::new(
            intent,
            obligation.obligation_id.clone(),
            spec.terminal_predicate,
            now,
        )
        .map_err(|error| EffectCoordError::Region {
            operation: op_str.clone(),
            detail: error.to_string(),
        })?;
        let context = tree
            .get(authority.region())
            .map_err(|error| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: error.to_string(),
            })?
            .authority
            .clone();
        let effect_authority = EffectAuthority::new(
            context.principal.clone(),
            spec.commit_grant.as_str(),
            Some(spec.fence),
        )
        .map_err(|error| EffectCoordError::Region {
            operation: op_str.clone(),
            detail: error.to_string(),
        })?;
        let binding = Arc::new(PreparationBinding {
            prepared: prepared.clone(),
            authority: authority.binding().clone(),
            lease_registry: Some(leases.binding().clone()),
            context,
            owner: authority.region().clone(),
            resource: spec.resource.to_owned(),
            fence: spec.fence,
            prepare_grant: spec.prepare_grant,
            commit_grant: spec.commit_grant,
        });
        let mut candidate = self.journal.clone();
        candidate
            .prepare_effect(prepared, effect_authority)
            .map_err(|error| journal_error(operation, error))?;
        // Validate the same tree insertion before making the preparation durable.
        tree.validate_obligation_registration(authority.region(), &obligation)
            .map_err(|error| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: error.to_string(),
            })?;
        self.persist_event(
            operation,
            JournalEvent::Prepare(Box::new(RetainedPreparation::from_binding(&binding))),
            &candidate,
        )?;
        authority
            .register_obligation(tree, obligation)
            .map_err(|error| {
                self.persistence_poisoned = self.persistence.is_some();
                EffectCoordError::Region {
                    operation: op_str,
                    detail: error.to_string(),
                }
            })?;
        // No fallible step remains after publishing the region obligation.
        self.journal = candidate;
        self.bindings.insert(operation.clone(), binding.clone());
        Ok(self.handle(binding))
    }

    /// Revalidates exact approval, current preconditions, authority and issuing lease.
    /// Only Prepared -> Committed creates a permit; retrying a retained handle cannot dispatch twice.
    pub fn commit(
        &mut self,
        authority: &AuthorityCx,
        tree: &RegionTree,
        leases: &mut LeaseRegistry,
        prepared: PreparedEffect,
        now: TimestampNs,
        approval: CommitApproval,
    ) -> Result<CommittedEffect, EffectTransitionError<PreparedEffect>> {
        let prepared = keep_token_on_error(prepared, |prepared| {
            self.require_scope(prepared, authority, tree)?;
            let operation = prepared.operation();
            let op_str = operation.to_string();
            self.require_persistence_ready(operation)?;
            if self.reconciliation_only {
                return Err(EffectCoordError::RecoveryOnly { operation: op_str });
            }
            require_transition(self.state(prepared)?, EffectState::Committed, &op_str)?;
            let expected = prepared.digest();
            if approval.prepared_digest != expected {
                return Err(EffectCoordError::ApprovalMismatch {
                    operation: op_str,
                    expected,
                    presented: approval.prepared_digest,
                });
            }
            let expected = prepared.binding.prepared.intent.precondition_digest;
            if approval.current_precondition_digest != expected {
                return Err(EffectCoordError::PreconditionMismatch {
                    operation: op_str,
                    expected,
                    current: approval.current_precondition_digest,
                });
            }
            authority
                .require_active(tree)
                .map_err(|error| EffectCoordError::Region {
                    operation: op_str.clone(),
                    detail: error.to_string(),
                })?;
            require_deadline(authority, tree, operation, now)?;
            authority
                .require_grant_for(prepared.binding.commit_grant, prepared.resource())
                .map_err(|error| EffectCoordError::Grant {
                    operation: op_str.clone(),
                    error,
                })?;
            if prepared.binding.lease_registry.as_ref() != Some(leases.binding()) {
                return Err(EffectCoordError::WrongLeaseRegistry { operation: op_str });
            }
            require_current_lease(
                authority,
                leases,
                &op_str,
                prepared.resource(),
                prepared.fence(),
            )?;
            self.journal
                .validate_transition(operation, EffectState::Committed, now, None, None)
                .map_err(|error| journal_error(operation, error))?;
            leases
                .check_fence(prepared.resource(), prepared.fence(), now)
                .map_err(|error| EffectCoordError::Fence {
                    operation: op_str,
                    error,
                })?;
            let mut candidate = self.journal.clone();
            candidate
                .transition(operation, EffectState::Committed, now, None, None)
                .map_err(|error| journal_error(operation, error))?;
            self.persist_event(
                operation,
                JournalEvent::Transition(EffectJournalTransition::Transition {
                    operation_id: operation.clone(),
                    next: EffectState::Committed,
                    now,
                    result_digest: None,
                    error_code: None,
                }),
                &candidate,
            )?;
            self.journal = candidate;
            Ok(())
        })?;
        Ok(CommittedEffect { inner: prepared })
    }

    /// Cancels a preparation with the core proof binding the exact record to the cancel evidence.
    pub fn cancel_prepared(
        &mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        prepared: PreparedEffect,
        evidence: ContentDigest,
        now: TimestampNs,
    ) -> Result<(), EffectTransitionError<PreparedEffect>> {
        keep_token_on_error(prepared, |prepared| {
            self.reconcile(
                tree,
                authority,
                prepared,
                Reconciliation::Cancelled(evidence),
                now,
            )
        })
        .map(|_| ())
    }

    /// Records adapter acceptance, optionally binding the accepted exchange digest.
    /// Acceptance is not observation or terminal success.
    pub fn adapter_accepted(
        &mut self,
        effect: &mut CommittedEffect,
        acceptance: Option<ContentDigest>,
        now: TimestampNs,
    ) -> Result<(), EffectCoordError> {
        self.transition_committed(effect, EffectState::AdapterAccepted, acceptance, now)
    }

    /// Records the independently observed outcome digest for later exact verification.
    pub fn observed(
        &mut self,
        effect: &mut CommittedEffect,
        proof: ContentDigest,
        now: TimestampNs,
    ) -> Result<(), EffectCoordError> {
        self.transition_committed(effect, EffectState::Observed, Some(proof), now)
    }

    /// Settles success only against the proof already recorded by observation.
    pub fn verified(
        &mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        proof: ContentDigest,
        now: TimestampNs,
    ) -> Result<(), EffectTransitionError<CommittedEffect>> {
        keep_token_on_error(effect, |effect| {
            self.reconcile(
                tree,
                authority,
                &effect.inner,
                Reconciliation::Verified(proof),
                now,
            )
        })
        .map(|_| ())
    }

    /// Settles a known failure with evidence and a nonempty bounded reason.
    /// Missing evidence or wrong ownership preserves both state and the dispatch token.
    pub fn failed(
        &mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        failure_digest: Option<ContentDigest>,
        reason: &str,
        now: TimestampNs,
    ) -> Result<(), EffectTransitionError<CommittedEffect>> {
        keep_token_on_error(effect, |effect| {
            self.require_scope(&effect.inner, authority, tree)?;
            let current = self.state(effect)?;
            if current != EffectState::Failed {
                require_transition(current, EffectState::Failed, effect.operation().as_str())?;
            }
            let proof = failure_digest.ok_or_else(|| {
                journal_error(effect.operation(), ContractError::EvidenceRequired)
            })?;
            self.reconcile(
                tree,
                authority,
                &effect.inner,
                Reconciliation::Failed { proof, reason },
                now,
            )
        })
        .map(|_| ())
    }

    /// Preserves an unresolved external outcome and its note, returning the existing permit.
    pub fn indeterminate(
        &mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        reconciliation_note: Option<&str>,
        now: TimestampNs,
    ) -> Result<CommittedEffect, EffectTransitionError<CommittedEffect>> {
        keep_token_on_error(effect, |effect| {
            self.require_scope(&effect.inner, authority, tree)?;
            let note = reconciliation_note
                .filter(|note| !note.trim().is_empty())
                .ok_or_else(|| EffectCoordError::IndeterminateWithoutNote {
                    operation: effect.operation().to_string(),
                })?;
            self.reconcile(
                tree,
                authority,
                &effect.inner,
                Reconciliation::Indeterminate(note),
                now,
            )
        })
    }

    /// Reconciles retained state using an inert handle without granting another dispatch.
    /// Storage is durable before the matching region obligation and live journal
    /// advance. An ambiguous write freezes this owner until cold recovery.
    pub fn reconcile(
        &mut self,
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        prepared: &PreparedEffect,
        reconciliation: Reconciliation<'_>,
        now: TimestampNs,
    ) -> Result<(), EffectCoordError> {
        self.require_scope(prepared, authority, tree)?;
        let operation = prepared.operation();
        self.require_persistence_ready(operation)?;
        let mut candidate = self.journal.clone();
        apply_reconciliation(&mut candidate, operation, reconciliation, now)?;
        let obligation = candidate
            .obligations()
            .find(|obligation| &obligation.obligation_id == prepared.obligation())
            .ok_or_else(|| journal_error(operation, ContractError::NotFound))?;
        let terminal = match obligation.state {
            ObligationState::Pending => None,
            ObligationState::Verified => Some(crate::obligation::ObligationTerminal::Completed),
            ObligationState::Cancelled => Some(crate::obligation::ObligationTerminal::Drained),
            ObligationState::Failed => Some(crate::obligation::ObligationTerminal::Failed),
            ObligationState::Indeterminate => {
                Some(crate::obligation::ObligationTerminal::Indeterminate)
            }
        };
        let note = if obligation.state == ObligationState::Indeterminate {
            Some(indeterminate_note(&candidate, operation)?)
        } else {
            None
        };
        if terminal.is_some() {
            tree.validate_obligation_resolution(
                authority.region(),
                prepared.obligation(),
                obligation.state,
                obligation.proof_digest,
                note,
            )
            .map_err(|error| EffectCoordError::Region {
                operation: operation.to_string(),
                detail: error.to_string(),
            })?;
        }
        self.persist_event(
            operation,
            JournalEvent::reconciliation(&self.journal, operation, reconciliation, now)?,
            &candidate,
        )?;
        if let Some(terminal) = terminal {
            authority
                .resolve_obligation(
                    tree,
                    prepared.obligation(),
                    terminal,
                    obligation.proof_digest,
                    note,
                )
                .map_err(|error| {
                    self.persistence_poisoned = self.persistence.is_some();
                    EffectCoordError::Region {
                        operation: operation.to_string(),
                        detail: error.to_string(),
                    }
                })?;
        }
        self.journal = candidate;
        Ok(())
    }

    fn handle(&self, binding: Arc<PreparationBinding>) -> PreparedEffect {
        PreparedEffect {
            coordinator: self.identity.clone(),
            binding,
        }
    }

    fn require_handle(&self, prepared: &PreparedEffect) -> Result<(), EffectCoordError> {
        if !Arc::ptr_eq(&self.identity, &prepared.coordinator)
            || !self
                .bindings
                .get(prepared.operation())
                .is_some_and(|binding| Arc::ptr_eq(binding, &prepared.binding))
        {
            return Err(EffectCoordError::WrongCoordinator {
                operation: prepared.operation().to_string(),
            });
        }
        Ok(())
    }

    fn require_scope(
        &self,
        prepared: &PreparedEffect,
        authority: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<(), EffectCoordError> {
        self.require_handle(prepared)?;
        let operation = prepared.operation();
        let op_str = operation.to_string();
        if authority.binding() != &prepared.binding.authority
            || authority.region() != &prepared.binding.owner
        {
            return Err(EffectCoordError::WrongAuthority { operation: op_str });
        }
        authority
            .require_bound(tree)
            .map_err(|error| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: error.to_string(),
            })?;
        let node = tree
            .get(authority.region())
            .map_err(|error| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: error.to_string(),
            })?;
        if node.state.is_closed() {
            return Err(EffectCoordError::Region {
                operation: op_str,
                detail: "preparing region is closed".to_owned(),
            });
        }
        let retained = self
            .journal
            .obligations()
            .find(|obligation| &obligation.obligation_id == prepared.obligation())
            .ok_or_else(|| journal_error(operation, ContractError::NotFound))?;
        if node.obligations.get(prepared.obligation()) != Some(retained) {
            return Err(EffectCoordError::Region {
                operation: op_str,
                detail: "preparing obligation differs from the retained canonical journal"
                    .to_owned(),
            });
        }
        let expected_note = if retained.state == ObligationState::Indeterminate {
            Some(indeterminate_note(&self.journal, operation)?)
        } else {
            None
        };
        if node
            .reconciliation_obligations
            .get(prepared.obligation())
            .map(String::as_str)
            != expected_note
        {
            return Err(EffectCoordError::Region {
                operation: op_str,
                detail: "reconciliation note differs from the retained canonical journal"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn transition_committed(
        &mut self,
        effect: &mut CommittedEffect,
        target: EffectState,
        proof: Option<ContentDigest>,
        now: TimestampNs,
    ) -> Result<(), EffectCoordError> {
        self.require_handle(&effect.inner)?;
        let operation = effect.operation();
        self.require_persistence_ready(operation)?;
        require_transition(self.state(effect)?, target, operation.as_str())?;
        let mut candidate = self.journal.clone();
        candidate
            .transition(operation, target, now, proof, None)
            .map_err(|error| journal_error(operation, error))?;
        self.persist_event(
            operation,
            JournalEvent::Transition(EffectJournalTransition::Transition {
                operation_id: operation.clone(),
                next: target,
                now,
                result_digest: proof,
                error_code: None,
            }),
            &candidate,
        )?;
        self.journal = candidate;
        Ok(())
    }
}

fn journal_error(operation: &OperationId, error: ContractError) -> EffectCoordError {
    EffectCoordError::Journal {
        operation: operation.to_string(),
        error,
    }
}

fn require_deadline(
    authority: &AuthorityCx,
    tree: &RegionTree,
    operation: &OperationId,
    now: TimestampNs,
) -> Result<(), EffectCoordError> {
    let node = tree
        .get(authority.region())
        .map_err(|error| EffectCoordError::Region {
            operation: operation.to_string(),
            detail: error.to_string(),
        })?;
    if let Some(deadline) = node.authority.deadline
        && now >= deadline
    {
        return Err(EffectCoordError::Deadline {
            operation: operation.to_string(),
            deadline,
            now,
        });
    }
    Ok(())
}

fn indeterminate_note<'a>(
    journal: &'a EffectJournal,
    operation: &OperationId,
) -> Result<&'a str, EffectCoordError> {
    match journal
        .operation(operation)
        .and_then(|receipt| receipt.indeterminate_reason.as_ref())
    {
        Some(IndeterminateEffectReason::Recorded(note)) => Ok(note),
        _ => Err(EffectCoordError::IndeterminateWithoutNote {
            operation: operation.to_string(),
        }),
    }
}

fn apply_reconciliation(
    journal: &mut EffectJournal,
    operation: &OperationId,
    reconciliation: Reconciliation<'_>,
    now: TimestampNs,
) -> Result<(), EffectCoordError> {
    let target = match reconciliation {
        Reconciliation::Observed(_) => EffectState::Observed,
        Reconciliation::Verified(_) => EffectState::Verified,
        Reconciliation::Failed { .. } => EffectState::Failed,
        Reconciliation::Indeterminate(_) => EffectState::Indeterminate,
        Reconciliation::Cancelled(_) => EffectState::Cancelled,
    };
    let current = journal
        .operation(operation)
        .ok_or_else(|| journal_error(operation, ContractError::NotFound))?
        .state;
    // Preserve typed lifecycle refusals while allowing exact evidence-bound retries
    // of terminal outcomes and the current indeterminate note below.
    if current != target || (!target.is_terminal() && target != EffectState::Indeterminate) {
        require_transition(current, target, operation.as_str())?;
    }
    let result = match reconciliation {
        Reconciliation::Observed(proof) => {
            journal.transition(operation, EffectState::Observed, now, Some(proof), None)
        }
        Reconciliation::Verified(proof) => journal.reconcile_verified(operation, proof, now),
        Reconciliation::Failed { proof, reason } => {
            if reason.trim().is_empty() {
                return Err(journal_error(operation, ContractError::EvidenceRequired));
            }
            if reason.len() > fss_core::effect::MAX_ERROR_CODE_LEN {
                return Err(journal_error(operation, ContractError::InvalidIdentifier));
            }
            journal.reconcile_failed(operation, proof, now, reason)
        }
        Reconciliation::Indeterminate(note) => {
            if note.trim().is_empty() {
                return Err(EffectCoordError::IndeterminateWithoutNote {
                    operation: operation.to_string(),
                });
            }
            if note.len() > fss_core::effect::MAX_DETAIL_LEN {
                return Err(journal_error(operation, ContractError::InvalidIdentifier));
            }
            if let Some(receipt) = journal.operation(operation)
                && receipt.state == EffectState::Indeterminate
            {
                if receipt.error_code.as_deref() == Some(note)
                    && indeterminate_note(journal, operation)? == note
                {
                    return Ok(());
                }
                return Err(journal_error(operation, ContractError::IdempotencyConflict));
            }
            journal.mark_indeterminate(operation, now, note)
        }
        Reconciliation::Cancelled(evidence) => {
            if let Some(receipt) = journal.operation(operation)
                && receipt.state == EffectState::Cancelled
            {
                let proof = journal
                    .cancellation_proof(operation, evidence)
                    .map_err(|error| journal_error(operation, error))?;
                return if receipt.result_digest == Some(proof) && receipt.error_code.is_none() {
                    Ok(())
                } else {
                    Err(journal_error(operation, ContractError::IdempotencyConflict))
                };
            }
            journal.cancel(operation, now, evidence, None)
        }
    };
    result
        .map(|_| ())
        .map_err(|error| journal_error(operation, error))
}

// These six pairs are the registered domain effects. Agent-plan orchestration
// and event-review authority capabilities cannot substitute for a domain grant.
fn registered_effect_class(prepare: RuntimeGrant, commit: RuntimeGrant) -> Option<&'static str> {
    match (prepare, commit) {
        (RuntimeGrant::AlertPrepare, RuntimeGrant::AlertCommit) => Some("EFFECT-ALERT-001"),
        (RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit) => Some("EFFECT-PTZ-001"),
        (RuntimeGrant::RetentionPrepare, RuntimeGrant::RetentionCommit) => {
            Some("EFFECT-RETENTION-001")
        }
        (RuntimeGrant::ExportPrepare, RuntimeGrant::ExportCommit) => Some("EFFECT-EXPORT-001"),
        (RuntimeGrant::DeletePrepare, RuntimeGrant::DeleteCommit) => {
            Some("EFFECT-ARCHIVE-DELETE-001")
        }
        (RuntimeGrant::RepairPrepare, RuntimeGrant::RepairCommit) => Some("EFFECT-REPAIR-001"),
        _ => None,
    }
}

fn require_current_lease(
    authority: &AuthorityCx,
    leases: &LeaseRegistry,
    operation: &str,
    resource: &str,
    fence: u64,
) -> Result<(), EffectCoordError> {
    let fence_error = |error| EffectCoordError::Fence {
        operation: operation.to_owned(),
        error,
    };
    if fence == 0 || leases.current_fence(resource) != Some(fence) {
        return Err(fence_error(LeaseError::StaleFence {
            resource: resource.to_owned(),
            presented: fence,
            current: leases.current_fence(resource).unwrap_or(0),
        }));
    }
    let lease = leases
        .get(&format!("lease:{resource}:{fence}"))
        .ok_or_else(|| {
            fence_error(LeaseError::NoFence {
                resource: resource.to_owned(),
            })
        })?;
    if lease.state != LeaseState::Active {
        return Err(fence_error(LeaseError::NotActive {
            lease: lease.id.clone(),
            state: lease.state,
        }));
    }
    if lease.holder != authority.region().as_str() {
        return Err(EffectCoordError::LeaseHolder {
            operation: operation.to_owned(),
            resource: resource.to_owned(),
            expected: authority.region().as_str().to_owned(),
            actual: lease.holder.clone(),
        });
    }
    Ok(())
}

/// Run validation and canonical settlement without allowing token mutation.
/// On refusal the caller receives the same token; on success its caller may
/// advance the state or consume the terminal handle.
fn keep_token_on_error<T>(
    token: T,
    operation: impl FnOnce(&T) -> Result<(), EffectCoordError>,
) -> Result<T, EffectTransitionError<T>> {
    match operation(&token) {
        Ok(()) => Ok(token),
        Err(error) => Err(EffectTransitionError {
            error,
            token: Box::new(token),
        }),
    }
}

/// State-machine guard: refuses any transition fss-core's canonical machine
/// declares illegal, naming both ends without changing the token.
fn require_transition(
    state: fss_core::EffectState,
    target: fss_core::EffectState,
    operation: &str,
) -> Result<(), EffectCoordError> {
    if state.can_transition_to(target) {
        Ok(())
    } else {
        Err(EffectCoordError::IllegalTransition {
            operation: operation.to_string(),
            from: state,
            to: target,
        })
    }
}
