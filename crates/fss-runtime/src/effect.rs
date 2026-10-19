//! Two-phase effect coordinator for the runtime authority core (FSS-027).
//!
//! An effect is never executed ad hoc: it is PREPARED (immutable intent +
//! preconditions + a pending obligation registered on the region tree) and
//! then COMMITTED (dispatch authority granted, fence revalidated). After
//! commit the adapter-facing states follow `fss-core`'s canonical
//! `EffectState` machine; terminal states resolve the obligation.
//!
//! The coordinator composes the runtime's own planes instead of duplicating
//! them:
//! - grants: prepare and commit each require their capability (`*Prepare` /
//!   `*Commit` pairs from the registered `RuntimeGrant` vocabulary);
//! - leases: commit revalidates the resource fence, so a zombie holder can
//!   never dispatch an effect after losing its lease;
//! - obligations: prepare registers the terminal predicate; terminal states
//!   resolve it (`Verified`→Verified, `Cancelled`→Cancelled,
//!   `Failed`→Failed, `Indeterminate` requires a reconciliation note);
//! - authority: every transition is scoped to the preparing region.
//!
//! Prepared and committed tokens have one owner and immutable intent. They authorize
//! reference transitions within the caller's owned region tree; durable effect journals
//! and adapter idempotency remain the responsibility of their existing owners.

use fss_core::{
    ContentDigest, ObligationId, ObligationState, OperationId, RegionTree, RuntimeGrant,
    TimestampNs,
};

use crate::authority::{AuthorityBinding, AuthorityCx};

/// Inputs to [`EffectCoordinator::prepare`], grouped to keep the surface
/// explicit without a nine-argument call.
#[derive(Clone, Copy, Debug)]
pub struct PrepareSpec<'a> {
    /// Operation identity.
    pub operation: &'a OperationId,
    /// The resource under lease (fence revalidated at commit).
    pub resource: &'a str,
    /// The fence token captured from the lease.
    pub fence: u64,
    /// Capability required at prepare time (`*Prepare` grant).
    pub prepare_grant: RuntimeGrant,
    /// Capability required at commit time (`*Commit` grant).
    pub commit_grant: RuntimeGrant,
    /// Terminal predicate recorded on the obligation.
    pub terminal_predicate: &'a str,
}
use crate::grant::GrantError;
use crate::lease::{LeaseError, LeaseRegistry, LeaseRegistryBinding, LeaseState};

/// Typed coordinator refusal. Every variant carries the operation identity.
#[derive(Clone, Debug, PartialEq)]
pub enum EffectCoordError {
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

/// A prepared effect: immutable intent plus the bookkeeping needed to
/// commit or cancel it. Construct only through `EffectCoordinator::prepare`.
#[derive(Debug)]
pub struct PreparedEffect {
    operation: OperationId,
    obligation: ObligationId,
    resource: String,
    fence: u64,
    authority: AuthorityBinding,
    lease_registry: LeaseRegistryBinding,
    /// The commit grant required later.
    commit_grant: RuntimeGrant,
    /// Terminal predicate (carried for the obligation resolution records).
    terminal_predicate: String,
    /// Current canonical state.
    state: fss_core::EffectState,
}

impl PreparedEffect {
    /// Immutable operation identity.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// The obligation registered on the preparing region.
    #[must_use]
    pub fn obligation(&self) -> &ObligationId {
        &self.obligation
    }

    /// The exact resource named at preparation.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The immutable fence captured at preparation.
    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    /// Current canonical effect state.
    #[must_use]
    pub fn state(&self) -> fss_core::EffectState {
        self.state
    }

    /// The terminal predicate registered at prepare time.
    #[must_use]
    pub fn terminal_predicate(&self) -> &str {
        &self.terminal_predicate
    }

    fn require_scope(
        &self,
        authority: &AuthorityCx,
        tree: &RegionTree,
        pending_only: bool,
    ) -> Result<(), EffectCoordError> {
        let operation = self.operation.to_string();
        if authority.binding() != &self.authority {
            return Err(EffectCoordError::WrongAuthority { operation });
        }
        authority
            .require_bound(tree)
            .map_err(|error| EffectCoordError::Region {
                operation: operation.clone(),
                detail: error.to_string(),
            })?;
        let node = tree
            .get(authority.region())
            .map_err(|error| EffectCoordError::Region {
                operation: operation.clone(),
                detail: error.to_string(),
            })?;
        let obligation =
            node.obligations
                .get(&self.obligation)
                .ok_or_else(|| EffectCoordError::Region {
                    operation: operation.clone(),
                    detail: "preparing obligation is missing".to_owned(),
                })?;
        if obligation.operation_id != self.operation
            || obligation.terminal_predicate != self.terminal_predicate
            || (obligation.state != ObligationState::Pending
                && (pending_only || obligation.state != ObligationState::Indeterminate))
        {
            return Err(EffectCoordError::Region {
                operation,
                detail: "preparing obligation changed or is already terminal".to_owned(),
            });
        }
        Ok(())
    }
}

/// A committed effect: dispatch authority was granted and the fence
/// revalidated. The adapter-facing states proceed from here.
#[derive(Debug)]
pub struct CommittedEffect {
    inner: PreparedEffect,
}

impl CommittedEffect {
    /// Current canonical effect state.
    #[must_use]
    pub fn state(&self) -> fss_core::EffectState {
        self.inner.state
    }

    /// The operation identity.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.inner.operation
    }

    /// The exact resource authorized at commit.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.inner.resource
    }

    /// The fence revalidated at commit.
    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.inner.fence
    }
}

/// The coordinator. Stateless: it threads authority, lease registry, and
/// region tree through each transition, so no effect state hides from the
/// caller's owned stores.
pub struct EffectCoordinator;

impl EffectCoordinator {
    /// Prepare phase: require the prepare grant, register the terminal
    /// obligation on the preparing region, capture the resource fence.
    pub fn prepare(
        authority: &AuthorityCx,
        tree: &mut RegionTree,
        leases: &LeaseRegistry,
        spec: PrepareSpec<'_>,
    ) -> Result<PreparedEffect, EffectCoordError> {
        let PrepareSpec {
            operation,
            resource,
            fence,
            prepare_grant,
            commit_grant,
            terminal_predicate,
        } = spec;
        let op_str = operation.to_string();
        authority
            .require_active(tree)
            .map_err(|error| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: error.to_string(),
            })?;
        if !valid_grant_pair(prepare_grant, commit_grant) {
            return Err(EffectCoordError::InvalidGrantPair {
                operation: op_str,
                prepare: prepare_grant,
                commit: commit_grant,
            });
        }
        authority
            .require_grant_for(prepare_grant, resource)
            .map_err(|error| EffectCoordError::Grant {
                operation: op_str.clone(),
                error,
            })?;
        require_current_lease(authority, leases, &op_str, resource, fence)?;
        // The canonical tree retains terminal obligations too. Re-preparation cannot
        // manufacture a second token, even after the first token was dropped or settled.
        if tree.iter().any(|node| {
            node.obligations
                .values()
                .any(|obligation| &obligation.operation_id == operation)
        }) {
            return Err(EffectCoordError::DuplicateOperation {
                operation: op_str.clone(),
            });
        }
        if terminal_predicate.trim().is_empty()
            || terminal_predicate.len() > fss_core::effect::MAX_TERMINAL_PREDICATE_LEN
        {
            return Err(EffectCoordError::Region {
                operation: op_str,
                detail: "terminal predicate is empty or exceeds the canonical bound".to_owned(),
            });
        }
        let obligation = crate::obligation::new_obligation(
            format!("obligation:{op_str}:terminal"),
            operation.clone(),
            terminal_predicate,
        )
        .map_err(|_| EffectCoordError::Region {
            operation: op_str.clone(),
            detail: "obligation id construction failed".to_string(),
        })?;
        let obligation_id = obligation.obligation_id.clone();
        authority
            .register_obligation(tree, obligation)
            .map_err(|e| EffectCoordError::Region {
                operation: op_str.clone(),
                detail: format!("{e}"),
            })?;
        Ok(PreparedEffect {
            operation: operation.clone(),
            obligation: obligation_id,
            resource: resource.to_string(),
            fence,
            authority: authority.binding().clone(),
            lease_registry: leases.binding().clone(),
            commit_grant,
            terminal_predicate: terminal_predicate.to_string(),
            state: fss_core::EffectState::Prepared,
        })
    }

    /// Commit phase: require the commit grant, revalidate the fence against
    /// caller time, transition Prepared → Committed.
    pub fn commit(
        authority: &AuthorityCx,
        tree: &RegionTree,
        leases: &mut LeaseRegistry,
        prepared: PreparedEffect,
        now: TimestampNs,
    ) -> Result<CommittedEffect, EffectCoordError> {
        let op_str = prepared.operation.to_string();
        prepared.require_scope(authority, tree, true)?;
        authority
            .require_active(tree)
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
        if let Some(deadline) = node.authority.deadline
            && now >= deadline
        {
            return Err(EffectCoordError::Deadline {
                operation: op_str,
                deadline,
                now,
            });
        }
        authority
            .require_grant_for(prepared.commit_grant, &prepared.resource)
            .map_err(|error| EffectCoordError::Grant {
                operation: op_str.clone(),
                error,
            })?;
        if leases.binding() != &prepared.lease_registry {
            return Err(EffectCoordError::WrongLeaseRegistry { operation: op_str });
        }
        require_current_lease(
            authority,
            leases,
            &op_str,
            &prepared.resource,
            prepared.fence,
        )?;
        leases
            .check_fence(&prepared.resource, prepared.fence, now)
            .map_err(|error| EffectCoordError::Fence {
                operation: op_str.clone(),
                error,
            })?;
        let mut prepared = prepared;
        transition_checked(
            &mut prepared.state,
            fss_core::EffectState::Committed,
            &op_str,
        )?;
        Ok(CommittedEffect { inner: prepared })
    }

    /// Cancellation before commit: Prepared → Cancelled, obligation
    /// resolved Cancelled. A committed effect is NOT cancellable through
    /// this path — it must run to a terminal observation.
    pub fn cancel_prepared(
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        mut prepared: PreparedEffect,
    ) -> Result<(), EffectCoordError> {
        let op_str = prepared.operation.to_string();
        prepared.require_scope(authority, tree, true)?;
        transition_checked(
            &mut prepared.state,
            fss_core::EffectState::Cancelled,
            &op_str,
        )?;
        authority
            .resolve_obligation(
                tree,
                &prepared.obligation,
                crate::obligation::ObligationTerminal::Drained,
                None,
                None,
            )
            .map_err(|e| EffectCoordError::Region {
                operation: op_str,
                detail: format!("{e}"),
            })
    }

    fn transition_committed(
        effect: &mut CommittedEffect,
        target: fss_core::EffectState,
    ) -> Result<(), EffectCoordError> {
        let op_str = effect.inner.operation.to_string();
        transition_checked(&mut effect.inner.state, target, &op_str)
    }

    /// Records adapter acceptance: Committed → AdapterAccepted.
    pub fn adapter_accepted(effect: &mut CommittedEffect) -> Result<(), EffectCoordError> {
        Self::transition_committed(effect, fss_core::EffectState::AdapterAccepted)
    }

    /// Records an external observation: AdapterAccepted → Observed (or
    /// Indeterminate → Observed when the world resolves late).
    pub fn observed(effect: &mut CommittedEffect) -> Result<(), EffectCoordError> {
        Self::transition_committed(effect, fss_core::EffectState::Observed)
    }

    /// Terminal success: Observed → Verified, obligation resolved Verified
    /// with the proof digest.
    pub fn verified(
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        proof: ContentDigest,
    ) -> Result<(), EffectCoordError> {
        let mut effect = effect;
        let op_str = effect.inner.operation.to_string();
        effect.inner.require_scope(authority, tree, false)?;
        Self::transition_committed(&mut effect, fss_core::EffectState::Verified)?;
        authority
            .resolve_obligation(
                tree,
                &effect.inner.obligation,
                crate::obligation::ObligationTerminal::Completed,
                Some(proof),
                None,
            )
            .map_err(|e| EffectCoordError::Region {
                operation: op_str,
                detail: format!("{e}"),
            })
    }

    /// Terminal failure: any non-Prepared state → Failed (where legal),
    /// obligation resolved Failed with the failure digest when available.
    /// Reconciliation from Indeterminate requires a failure digest; missing
    /// evidence leaves the canonical obligation and reconciliation note unchanged.
    pub fn failed(
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        failure_digest: Option<ContentDigest>,
    ) -> Result<(), EffectCoordError> {
        let mut effect = effect;
        let op_str = effect.inner.operation.to_string();
        effect.inner.require_scope(authority, tree, false)?;
        Self::transition_committed(&mut effect, fss_core::EffectState::Failed)?;
        authority
            .resolve_obligation(
                tree,
                &effect.inner.obligation,
                crate::obligation::ObligationTerminal::Failed,
                failure_digest,
                None,
            )
            .map_err(|e| EffectCoordError::Region {
                operation: op_str,
                detail: format!("{e}"),
            })
    }

    /// The effect may have happened but cannot be established: →
    /// Indeterminate. INV-006: a durable reconciliation note is REQUIRED.
    /// The unique token is returned for a later observation or failure; the tree
    /// retains the Indeterminate obligation and its reconciliation note.
    pub fn indeterminate(
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        reconciliation_note: Option<&str>,
    ) -> Result<CommittedEffect, EffectCoordError> {
        let mut effect = effect;
        let op_str = effect.inner.operation.to_string();
        effect.inner.require_scope(authority, tree, false)?;
        let note = reconciliation_note
            .filter(|note| !note.trim().is_empty())
            .ok_or_else(|| EffectCoordError::IndeterminateWithoutNote {
                operation: op_str.clone(),
            })?;
        Self::transition_committed(&mut effect, fss_core::EffectState::Indeterminate)?;
        authority
            .resolve_obligation(
                tree,
                &effect.inner.obligation,
                crate::obligation::ObligationTerminal::Indeterminate,
                None,
                Some(note),
            )
            .map_err(|e| EffectCoordError::Region {
                operation: op_str,
                detail: format!("{e}"),
            })?;
        Ok(effect)
    }
}

// These six pairs are the registered domain effects. Agent-plan orchestration
// and event-review authority capabilities cannot substitute for a domain grant.
fn valid_grant_pair(prepare: RuntimeGrant, commit: RuntimeGrant) -> bool {
    matches!(
        (prepare, commit),
        (RuntimeGrant::AlertPrepare, RuntimeGrant::AlertCommit)
            | (RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit)
            | (
                RuntimeGrant::RetentionPrepare,
                RuntimeGrant::RetentionCommit
            )
            | (RuntimeGrant::ExportPrepare, RuntimeGrant::ExportCommit)
            | (RuntimeGrant::DeletePrepare, RuntimeGrant::DeleteCommit)
            | (RuntimeGrant::RepairPrepare, RuntimeGrant::RepairCommit)
    )
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

/// State-machine guard: refuses any transition fss-core's canonical machine
/// declares illegal, naming both ends.
fn transition_checked(
    state: &mut fss_core::EffectState,
    target: fss_core::EffectState,
    operation: &str,
) -> Result<(), EffectCoordError> {
    if state.can_transition_to(target) {
        *state = target;
        Ok(())
    } else {
        Err(EffectCoordError::IllegalTransition {
            operation: operation.to_string(),
            from: *state,
            to: target,
        })
    }
}
