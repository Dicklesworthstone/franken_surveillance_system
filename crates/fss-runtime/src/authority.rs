//! Explicit runtime authority bound to one live canonical region tree.
//!
//! Each scope owns an independent detached Asupersync cancellation context.
//! The canonical RegionTree propagates request→drain→finalize to descendants;
//! checkpoints reflect that state into the scope's local cancellation primitive.
//! No runtime effects or ambient authority are exposed by this facade.

use std::sync::Arc;

use fss_core::effect::Obligation;
use fss_core::{
    BudgetVector, ContextAuthority, ContractError, QuiescenceProof, RegionError, RegionId,
    RegionKind, RegionNode, RegionState, RegionTree, RegionTreeIdentity, RootAuthoritySpec,
    TimestampNs,
};

use crate::budget::{BudgetLedger, BudgetSpender, LedgerError};
use crate::grant::{GrantError, GrantSet};

/// One explicit scope: cancellation, immutable authority, and its reserved
/// allowance. The supplied canonical tree owns tasks, obligations, and closure;
/// this facade retains only an immutable binding and budget accounting.
pub struct AuthorityCx {
    cx: asupersync::cx::Cx<asupersync::cx::cap::None>,
    region: RegionId,
    kind: RegionKind,
    parent: Option<RegionId>,
    authority: ContextAuthority,
    budget: BudgetLedger,
    grants: GrantSet,
    binding: AuthorityBinding,
    tree_identity: RegionTreeIdentity,
    reservation_parent: Option<AuthorityBinding>,
    reservation_released: bool,
    outstanding_reservations: usize,
}

/// Identity of one in-process authority handle. Equal region labels never
/// authorize another handle's effect tokens or reservation refunds.
#[derive(Clone, Debug)]
pub(crate) struct AuthorityBinding(Arc<()>);

impl PartialEq for AuthorityBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for AuthorityBinding {}

/// Typed authority refusal.
#[derive(Debug)]
pub enum AuthorityError {
    /// A requested capability is absent, unregistered, or wider than its parent.
    Grant(GrantError),
    /// The requested scope violates canonical authority constraints.
    IllegalScope {
        /// The constraint that refused the request.
        detail: String,
    },
    /// The region tree rejected the operation.
    Region(RegionError),
    /// The supplied tree is not the immutable owner bound to this scope.
    ScopeMismatch,
    /// A canonical authority field was invalid.
    Contract(ContractError),
    /// A complete allowance could not be reserved without exceeding a limit.
    Budget(LedgerError),
    /// A reservation can only be settled by its granting authority.
    ReservationOwnerMismatch,
    /// This scope or its child already surrendered its unused allowance.
    ReservationReleased,
    /// Descendant reservations must settle before this scope settles upward.
    OutstandingReservations {
        /// Direct child reservations that have not been settled.
        count: usize,
    },
}

impl core::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Grant(e) => write!(f, "grant error: {e}"),
            Self::IllegalScope { detail } => write!(f, "illegal scope: {detail}"),
            Self::Region(e) => write!(f, "region error: {e}"),
            Self::ScopeMismatch => f.write_str("runtime region authority binding mismatch"),
            Self::Contract(e) => write!(f, "runtime authority contract: {e}"),
            Self::Budget(e) => write!(f, "runtime authority budget: {e}"),
            Self::ReservationOwnerMismatch => {
                f.write_str("reservation belongs to a different authority")
            }
            Self::ReservationReleased => f.write_str("scope reservation has already been released"),
            Self::OutstandingReservations { count } => {
                write!(f, "scope still owns {count} unsettled child reservations")
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<RegionError> for AuthorityError {
    fn from(error: RegionError) -> Self {
        Self::Region(error)
    }
}

impl AuthorityCx {
    /// Construct a Process root and its fresh canonical tree. The execution
    /// allowance must fit the scope's own canonical budgets in every dimension.
    /// Time is supplied by the caller; no ambient clock or runtime effects exist.
    pub fn root(
        spec: RootAuthoritySpec,
        process_region: RegionId,
        process_kind: RegionKind,
        budget: BudgetVector,
        now: TimestampNs,
    ) -> Result<(Self, RegionTree), AuthorityError> {
        if process_kind != RegionKind::Process {
            return Err(AuthorityError::IllegalScope {
                detail: "the root must be a ProcessRegion".to_string(),
            });
        }
        let authority = ContextAuthority::new_root(spec)?;
        authority.validate().map_err(AuthorityError::Contract)?;
        Self::validate_allowance(&authority, &budget)?;
        let grants = GrantSet::from_authority(&authority).map_err(AuthorityError::Grant)?;
        let tree = RegionTree::new(process_region.clone(), authority.clone(), now)?;
        Ok((
            Self {
                cx: asupersync::Cx::detached_cancel_context(),
                region: process_region,
                kind: process_kind,
                parent: None,
                authority,
                budget: BudgetLedger::new(budget),
                grants,
                binding: AuthorityBinding(Arc::new(())),
                tree_identity: tree.owner_identity().clone(),
                reservation_parent: None,
                reservation_released: false,
                outstanding_reservations: 0,
            },
            tree,
        ))
    }

    /// Narrow into a legal child and reserve its complete numeric allowance.
    /// Cancelled, draining, and closed parents cannot admit new children.
    /// Every fallible check precedes the parent's accounting mutation; a refused
    /// attachment leaves both the tree and the parent's allowance unchanged.
    pub fn scope_down(
        &mut self,
        tree: &mut RegionTree,
        child_id: RegionId,
        child_kind: RegionKind,
        child_budget: BudgetVector,
        child_authority_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<AuthorityCx, AuthorityError> {
        self.require_active(tree)?;
        self.kind.validate_child_kind(child_kind).map_err(|error| {
            AuthorityError::IllegalScope {
                detail: error.to_string(),
            }
        })?;
        let child_authority = ContextAuthority::new_root(child_authority_spec)?;
        child_authority
            .validate()
            .map_err(AuthorityError::Contract)?;
        Self::validate_allowance(&child_authority, &child_budget)?;
        // Opaque labels have no registered subset relation. A different label
        // cannot be assumed narrower merely because a caller supplied it.
        if child_authority.privacy_scope != self.authority.privacy_scope
            || child_authority.retention_scope != self.authority.retention_scope
        {
            return Err(AuthorityError::IllegalScope {
                detail: "privacy and retention scope changes require a proven narrowing"
                    .to_string(),
            });
        }
        let child_grants = self
            .grants
            .scope_for_child(&child_authority)
            .map_err(AuthorityError::Grant)?;
        let remaining_budget = self.budget.remaining();
        // The contract-owned continuous quantities remain constrained by the
        // immutable parent allowance, even though the ledger meters nine integers.
        if child_budget.privacy_exposure() > remaining_budget.privacy_exposure()
            || child_budget.operator_attention_seconds()
                > remaining_budget.operator_attention_seconds()
        {
            return Err(AuthorityError::IllegalScope {
                detail: "child contract quantities exceed the parent allowance".to_string(),
            });
        }
        let mut reserved = self.budget.clone();
        reserved
            .spend_vector(&child_budget)
            .map_err(AuthorityError::Budget)?;
        let outstanding_reservations =
            self.outstanding_reservations
                .checked_add(1)
                .ok_or_else(|| AuthorityError::IllegalScope {
                    detail: "child reservation count exhausted".to_string(),
                })?;
        tree.attach_child(
            &self.region,
            child_id.clone(),
            child_kind,
            child_authority.clone(),
            now,
        )?;
        self.budget = reserved;
        self.outstanding_reservations = outstanding_reservations;
        Ok(AuthorityCx {
            cx: asupersync::Cx::detached_cancel_context(),
            region: child_id,
            kind: child_kind,
            parent: Some(self.region.clone()),
            authority: child_authority,
            budget: BudgetLedger::new(child_budget),
            grants: child_grants,
            binding: AuthorityBinding(Arc::new(())),
            tree_identity: self.tree_identity.clone(),
            reservation_parent: Some(self.binding.clone()),
            reservation_released: false,
            outstanding_reservations: 0,
        })
    }

    /// Parent pressure includes its own consumption and outstanding child allocations.
    #[must_use]
    pub fn pressure(&self) -> fss_core::ResourcePressure {
        self.budget.pressure()
    }

    /// Settle an exact closed child's unused numeric allowance once. The actual
    /// tree must contain its quiescence proof, and its own delegated allowances
    /// must already be settled. Dropped child handles remain charged and block
    /// upward settlement. Spent work stays charged through every ancestor.
    pub fn release_scope_reservation(
        &mut self,
        tree: &RegionTree,
        child: &mut AuthorityCx,
    ) -> Result<BudgetVector, AuthorityError> {
        self.require_bound(tree)?;
        let child_node = child.bound_region(tree)?;
        if child.reservation_parent.as_ref() != Some(&self.binding) {
            return Err(AuthorityError::ReservationOwnerMismatch);
        }
        if self.reservation_released || child.reservation_released {
            return Err(AuthorityError::ReservationReleased);
        }
        if child_node.state != RegionState::Closed || child_node.quiescence_proof.is_none() {
            return Err(AuthorityError::IllegalScope {
                detail: "reservation settlement requires a closed child with quiescence proof"
                    .to_string(),
            });
        }
        if child.outstanding_reservations != 0 {
            return Err(AuthorityError::OutstandingReservations {
                count: child.outstanding_reservations,
            });
        }
        let outstanding_reservations =
            self.outstanding_reservations
                .checked_sub(1)
                .ok_or_else(|| AuthorityError::IllegalScope {
                    detail: "parent has no outstanding child reservation".to_string(),
                })?;
        let unused = child.budget.unused_metered();
        let mut settled = self.budget.clone();
        settled
            .refund_vector(&unused)
            .map_err(AuthorityError::Budget)?;
        self.budget = settled;
        self.outstanding_reservations = outstanding_reservations;
        child.reservation_released = true;
        Ok(unused)
    }

    /// Require a held capability. Admission checks separately require an active
    /// owner, allowing cleanup code to continue inspecting its existing grants.
    pub fn require_grant(&self, grant: fss_core::RuntimeGrant) -> Result<(), GrantError> {
        self.grants.require_grant(grant)
    }

    /// Require a held capability for one specific resource.
    pub fn require_grant_for(
        &self,
        grant: fss_core::RuntimeGrant,
        resource: &str,
    ) -> Result<(), GrantError> {
        self.grants.require_grant_for(grant, resource)
    }

    /// Read the current grants without exposing replacement authority.
    #[must_use]
    pub fn grants(&self) -> &GrantSet {
        &self.grants
    }

    /// Remove capabilities or narrow resource scopes. Refused widening changes nothing.
    pub fn narrow_grants(&mut self, grants: GrantSet) -> Result<(), GrantError> {
        self.grants.verify_narrowed_by(&grants)?;
        self.grants = grants;
        Ok(())
    }

    /// The unforgeable in-process scope binding used by owned effect tokens.
    pub(crate) fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }

    /// Validate actual tree ownership without refusing terminal cleanup.
    pub(crate) fn require_bound(&self, tree: &RegionTree) -> Result<(), AuthorityError> {
        self.bound_region(tree)?;
        Ok(())
    }

    /// The region this authority belongs to.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        &self.region
    }

    /// The normative region kind.
    #[must_use]
    pub const fn kind(&self) -> RegionKind {
        self.kind
    }

    /// Account for work, including bounded cleanup while draining. Closed and
    /// settled scopes cannot spend. The facade cannot replace or replenish the
    /// ledger, and its lifetime keeps the actual tree borrowed until completion.
    /// Spending alone does not admit new work or confer I/O authority.
    ///
    /// ```compile_fail
    /// # #![forbid(unsafe_code)]
    /// use fss_core::{BudgetDimension, RegionTree, TimestampNs};
    /// use fss_runtime::authority::AuthorityCx;
    /// fn close_before_spend(authority: &mut AuthorityCx, tree: &mut RegionTree) {
    ///     let region = authority.region().clone();
    ///     let mut spender = authority.budget_mut(tree).expect("open scope");
    ///     let _ = tree.finalize(&region, TimestampNs(1));
    ///     let _ = spender.spend(BudgetDimension::Bytes, 1);
    /// }
    /// ```
    pub fn budget_mut<'a>(
        &'a mut self,
        tree: &'a RegionTree,
    ) -> Result<BudgetSpender<'a>, AuthorityError> {
        let node = self.bound_region(tree)?;
        if self.reservation_released {
            return Err(AuthorityError::ReservationReleased);
        }
        if node.state == RegionState::Closed {
            return Err(RegionError::OrphanWork {
                region_id: self.region.clone(),
                state: node.state,
            }
            .into());
        }
        Ok(BudgetSpender::new(&mut self.budget))
    }

    /// Immutable ledger and accounting history.
    #[must_use]
    pub const fn budget(&self) -> &BudgetLedger {
        &self.budget
    }

    /// Register an obligation in the active canonical region.
    pub fn register_obligation(
        &self,
        tree: &mut RegionTree,
        obligation: Obligation,
    ) -> Result<(), AuthorityError> {
        self.require_active(tree)?;
        tree.register_obligation(&self.region, obligation)
            .map_err(AuthorityError::Region)
    }

    /// Resolve a canonical obligation. Indeterminate resolution requires the
    /// durable reconciliation record enforced by the tree.
    pub fn resolve_obligation(
        &self,
        tree: &mut RegionTree,
        obligation_id: &fss_core::ObligationId,
        terminal: crate::obligation::ObligationTerminal,
        proof_digest: Option<fss_core::ContentDigest>,
        reconciliation_note: Option<&str>,
    ) -> Result<(), AuthorityError> {
        self.bound_region(tree)?;
        tree.resolve_obligation(
            &self.region,
            obligation_id,
            terminal.to_state(),
            proof_digest,
            reconciliation_note,
        )
        .map_err(AuthorityError::Region)
    }

    /// Read pending obligations from the actual owner. A missing or mismatched
    /// tree is a typed refusal and can never produce a false empty leak report.
    pub fn leaked_obligations(
        &self,
        tree: &RegionTree,
    ) -> Result<Vec<crate::obligation::LeakedObligation>, AuthorityError> {
        let node = self.bound_region(tree)?;
        Ok(crate::obligation::leaked_in(
            node.obligations.values().cloned(),
        ))
    }

    /// Request cancellation of this scope and its canonical descendants.
    /// Parents and siblings are unaffected. Tree validation precedes the local
    /// cancellation signal, so refused requests do not cancel an unrelated owner.
    pub fn request_cancellation(
        &self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<(), AuthorityError> {
        self.bound_region(tree)?;
        tree.request_drain(&self.region, Some("runtime cancellation requested"), now)?;
        self.cx.cancel_fast(asupersync::types::CancelKind::User);
        Ok(())
    }

    /// Observe cancellation, including direct requests through the canonical tree.
    pub fn is_cancel_requested(&self, tree: &RegionTree) -> Result<bool, AuthorityError> {
        let node = self.bound_region(tree)?;
        if !node.state.is_active() || node.authority.cancellation_reason.is_some() {
            self.cx.cancel_fast(asupersync::types::CancelKind::User);
        }
        Ok(self.cx.is_cancelled())
    }

    /// Read the local leak report; this is not a subtree quiescence proof.
    pub fn finalize_report(
        &self,
        tree: &RegionTree,
    ) -> Result<Vec<crate::obligation::LeakedObligation>, AuthorityError> {
        self.leaked_obligations(tree)
    }

    /// Begin draining an already requested canonical scope.
    pub fn begin_drain(
        &self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<(), AuthorityError> {
        self.bound_region(tree)?;
        tree.begin_drain(&self.region, now)?;
        Ok(())
    }

    /// Close through canonical subtree quiescence. Live children, tasks, pending
    /// obligations, and unresolved indeterminate reconciliation refuse closure.
    pub fn finalize(
        &self,
        tree: &mut RegionTree,
        now: TimestampNs,
    ) -> Result<QuiescenceProof, AuthorityError> {
        self.bound_region(tree)?;
        tree.finalize(&self.region, now)
            .map_err(AuthorityError::Region)
    }

    fn bound_region<'a>(&self, tree: &'a RegionTree) -> Result<&'a RegionNode, AuthorityError> {
        if tree.owner_identity() != &self.tree_identity {
            return Err(AuthorityError::ScopeMismatch);
        }
        let node = tree.get(&self.region)?;
        let mut current = node.authority.clone();
        // Cancellation reason is the only authority field mutated during drain.
        current.cancellation_reason = None;
        if node.kind != self.kind || node.parent_id != self.parent || current != self.authority {
            return Err(AuthorityError::ScopeMismatch);
        }
        Ok(node)
    }

    fn validate_allowance(
        authority: &ContextAuthority,
        allowance: &BudgetVector,
    ) -> Result<(), AuthorityError> {
        if !allowance.fits_within(authority.budgets) {
            return Err(AuthorityError::IllegalScope {
                detail: "execution allowance exceeds the scope's canonical budgets".to_string(),
            });
        }
        Ok(())
    }

    pub(crate) fn require_active(&self, tree: &RegionTree) -> Result<(), AuthorityError> {
        let cancelled = self.is_cancel_requested(tree)?;
        if self.reservation_released {
            return Err(AuthorityError::ReservationReleased);
        }
        if cancelled {
            return Err(RegionError::OrphanWork {
                region_id: self.region.clone(),
                state: self.bound_region(tree)?.state,
            }
            .into());
        }
        Ok(())
    }
}
