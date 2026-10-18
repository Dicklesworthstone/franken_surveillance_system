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

use fss_core::{
    ContentDigest, ObligationId, ObligationState, OperationId, RegionTree, RuntimeGrant, TimestampNs,
};

use crate::authority::AuthorityCx;
use crate::grant::GrantError;
use crate::lease::{LeaseError, LeaseRegistry};

/// Typed coordinator refusal. Every variant carries the operation identity.
#[derive(Clone, Debug, PartialEq)]
pub enum EffectCoordError {
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
                write!(f, "effect {operation}: indeterminate without reconciliation note")
            }
        }
    }
}

impl std::error::Error for EffectCoordError {}

/// A prepared effect: immutable intent plus the bookkeeping needed to
/// commit or cancel it. Construct only through `EffectCoordinator::prepare`.
#[derive(Clone, Debug)]
pub struct PreparedEffect {
    /// Operation identity.
    pub operation: OperationId,
    /// Obligation registered at prepare time.
    pub obligation: ObligationId,
    /// The resource under lease (fence-checked again at commit).
    pub resource: String,
    /// The fence token captured at prepare time.
    pub fence: u64,
    /// The commit grant required later.
    commit_grant: RuntimeGrant,
    /// Terminal predicate (carried for the obligation resolution records).
    terminal_predicate: String,
    /// Current canonical state.
    state: fss_core::EffectState,
}

impl PreparedEffect {
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
}

/// A committed effect: dispatch authority was granted and the fence
/// revalidated. The adapter-facing states proceed from here.
#[derive(Clone, Debug)]
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
        operation: OperationId,
        resource: &str,
        fence: u64,
        prepare_grant: RuntimeGrant,
        commit_grant: RuntimeGrant,
        terminal_predicate: &str,
    ) -> Result<PreparedEffect, EffectCoordError> {
        let op_str = operation.to_string();
        authority
            .require_grant(prepare_grant)
            .map_err(|error| EffectCoordError::Grant {
                operation: op_str.clone(),
                error,
            })?;
        // The fence must at least exist at prepare time; full revalidation
        // (freshness + active holder) happens at commit.
        if leases.current_fence(resource) != Some(fence) {
            return Err(EffectCoordError::Fence {
                operation: op_str.clone(),
                error: LeaseError::StaleFence {
                    resource: resource.to_string(),
                    presented: fence,
                    current: leases.current_fence(resource).unwrap_or(0),
                },
            });
        }
        let obligation = crate::obligation::new_obligation(
            &format!("obligation:{op_str}:terminal"),
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
            operation,
            obligation: obligation_id,
            resource: resource.to_string(),
            fence,
            commit_grant,
            terminal_predicate: terminal_predicate.to_string(),
            state: fss_core::EffectState::Prepared,
        })
    }

    /// Commit phase: require the commit grant, revalidate the fence against
    /// caller time, transition Prepared → Committed.
    pub fn commit(
        authority: &AuthorityCx,
        leases: &mut LeaseRegistry,
        prepared: PreparedEffect,
        now: TimestampNs,
    ) -> Result<CommittedEffect, EffectCoordError> {
        let op_str = prepared.operation.to_string();
        authority
            .require_grant(prepared.commit_grant)
            .map_err(|error| EffectCoordError::Grant {
                operation: op_str.clone(),
                error,
            })?;
        leases
            .check_fence(&prepared.resource, prepared.fence, now)
            .map_err(|error| EffectCoordError::Fence {
                operation: op_str.clone(),
                error,
            })?;
        let mut prepared = prepared;
        transition_checked(&mut prepared.state, fss_core::EffectState::Committed, &op_str)?;
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
        transition_checked(&mut prepared.state, fss_core::EffectState::Cancelled, &op_str)?;
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
    pub fn failed(
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        failure_digest: Option<ContentDigest>,
    ) -> Result<(), EffectCoordError> {
        let mut effect = effect;
        let op_str = effect.inner.operation.to_string();
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
    /// The obligation stays open in the tree as Indeterminate-with-note.
    pub fn indeterminate(
        tree: &mut RegionTree,
        authority: &AuthorityCx,
        effect: CommittedEffect,
        reconciliation_note: Option<&str>,
    ) -> Result<(), EffectCoordError> {
        let mut effect = effect;
        let op_str = effect.inner.operation.to_string();
        let note = reconciliation_note.ok_or_else(|| {
            EffectCoordError::IndeterminateWithoutNote {
                operation: op_str.clone(),
            }
        })?;
        Self::transition_committed(&mut effect, fss_core::EffectState::Indeterminate)?;
        tree.resolve_obligation(
            authority.region(),
            &effect.inner.obligation,
            ObligationState::Indeterminate,
            None,
            Some(note),
        )
        .map_err(|e| EffectCoordError::Region {
            operation: op_str,
            detail: format!("{e}"),
        })
    }

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
