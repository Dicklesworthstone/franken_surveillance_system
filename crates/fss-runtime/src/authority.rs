//! The explicit authority context: Asupersync `Cx` cancellation substrate
//! underneath, the fss-core region hierarchy above, and the FSS charter's
//! rule between them — every authority is constructed explicitly, passed by
//! value, and never looked up ambiently.
//!
//! Composition notes:
//! * the Asupersync side uses `detached_cancel_context()` — cancellation and
//!   budget primitives without runtime effect capabilities (spawn/timer/I/O),
//!   exactly the reference-core boundary this crate owns;
//! * scope-down shares the parent's cancellation state (asupersync `Cx` is
//!   shared-state across clones — cancellation signals cascade);
//! * region structure and obligation lifecycle live in `fss-core`'s
//!   `RegionTree` (it owns request→drain→finalize and obligation resolution);
//!   this module binds it to the budget ledger and the four-valued
//!   cancellation outcomes of [`crate::cancellation`].

use fss_core::{
    ContextAuthority, RegionError, RegionId, RegionKind, RegionTree, RootAuthoritySpec, TimestampNs,
};

use crate::budget::BudgetLedger;
use fss_core::BudgetVector;
use fss_core::effect::Obligation;

/// One explicit authority context: the cancellation substrate, the region it
/// belongs to, its budget ledger, and its obligation registry. There is no
/// ambient accessor by design.
pub struct AuthorityCx {
    cx: asupersync::cx::Cx<asupersync::cx::cap::None>,
    region: RegionId,
    kind: RegionKind,
    budget: BudgetLedger,
    grants: crate::grant::GrantSet,
}

/// Typed authority errors.
#[derive(Debug)]
pub enum AuthorityError {
    /// Capability grant failure (missing grant, unregistered capability
    /// string, or widening on scope-down).
    Grant(crate::grant::GrantError),
    /// The requested scope violates the parent region's rules or budget.
    IllegalScope {
        /// What was attempted (typed detail).
        detail: String,
    },
    /// The region tree rejected the operation.
    Region(RegionError),
}

impl core::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Grant(e) => write!(f, "grant error: {e}"),
            Self::IllegalScope { detail } => write!(f, "illegal scope: {detail}"),
            Self::Region(e) => write!(f, "region error: {e}"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<RegionError> for AuthorityError {
    fn from(e: RegionError) -> Self {
        Self::Region(e)
    }
}

impl AuthorityCx {
    /// Construct the root authority for a fresh region tree. `now` is caller
    /// time (no ambient clock). The authority carries a detached cancellation
    /// context (cancellation primitives, no runtime effects).
    pub fn root(
        spec: RootAuthoritySpec,
        process_region: RegionId,
        process_kind: RegionKind,
        budget: BudgetVector,
        now: TimestampNs,
    ) -> Result<(Self, RegionTree), AuthorityError> {
        let authority = ContextAuthority::new_root(spec)?;
        let grants =
            crate::grant::GrantSet::from_authority(&authority).map_err(AuthorityError::Grant)?;
        let tree = RegionTree::new(process_region.clone(), authority, now)?;
        Ok((
            Self {
                cx: asupersync::Cx::detached_cancel_context(),
                region: process_region,
                kind: process_kind,
                budget: BudgetLedger::new(budget),
                grants,
            },
            tree,
        ))
    }

    /// Scope DOWN into a child region of this authority: the child's kind
    /// must be legal under the parent's kind (region-tree rule), its budget
    /// must not exceed the parent's remaining in any dimension (no silent
    /// widening), and it shares the parent's cancellation state.
    pub fn scope_down(
        &mut self,
        tree: &mut RegionTree,
        child_id: RegionId,
        child_kind: RegionKind,
        child_budget: BudgetVector,
        child_authority_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<AuthorityCx, AuthorityError> {
        self.kind
            .validate_child_kind(child_kind)
            .map_err(|e| AuthorityError::IllegalScope {
                detail: format!("{e}"),
            })?;
        // Budget widening is refused against the canonical vector: the child
        // must fit within the parent's remaining in every dimension.
        let remaining = self.budget.remaining();
        if !child_budget.fits_within(remaining) {
            return Err(AuthorityError::IllegalScope {
                detail: "child budget exceeds parent remaining in at least one dimension"
                    .to_string(),
            });
        }
        // All fallible validation happens BEFORE the reservation debit, so
        // a refused scope-down never strands budget in the parent's ledger:
        // authority construction, grant resolution, narrowing checks, and
        // the tree attach must all succeed first.
        let child_authority = ContextAuthority::new_root(child_authority_spec)?;
        let child_grants = crate::grant::GrantSet::from_authority(&child_authority)
            .map_err(AuthorityError::Grant)?;
        // Capability narrowing: the child's grant set must be a subset of
        // this authority's (resource scopes may narrow, never widen).
        self.grants
            .verify_narrowed_by(&child_grants)
            .map_err(AuthorityError::Grant)?;
        tree.attach_child(
            &self.region,
            child_id.clone(),
            child_kind,
            child_authority,
            now,
        )?;
        // Reservation: the grant debits the parent's ledger only once the
        // child region exists, so sibling scopes cannot jointly overdraw it,
        // the parent's derived pressure reflects outstanding child
        // allocations, and a failed scope-down debits nothing. The
        // reservation is released with `release_scope_reservation` when the
        // child closes.
        self.budget
            .spend_vector(&child_budget)
            .map_err(|e| AuthorityError::IllegalScope {
                detail: format!("reservation failed: {e}"),
            })?;
        Ok(AuthorityCx {
            // Cloned Cx shares underlying cancellation/budget state — a
            // parent cancellation is visible to every derived scope.
            cx: self.cx.clone(),
            region: child_id,
            kind: child_kind,
            budget: BudgetLedger::new(child_budget),
            grants: child_grants,
        })
    }

    /// The pressure derived from this authority's own ledger. Because child
    /// scopes debit the parent at grant time, a parent's pressure reflects
    /// outstanding descendant allocations — degradation propagates up the
    /// scope chain as a typed signal, never a silent drop.
    #[must_use]
    pub fn pressure(&self) -> fss_core::ResourcePressure {
        self.budget.pressure()
    }

    /// Releases a closed child scope's reservation back into this ledger.
    /// Saturating: double-release never invents budget.
    pub fn release_scope_reservation(&mut self, child_budget: &BudgetVector) {
        for dimension in crate::budget::METERED {
            self.budget
                .refund(dimension, crate::budget::read_dim(child_budget, dimension));
        }
    }

    /// The region this authority belongs to.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        &self.region
    }

    /// The region kind.
    #[must_use]
    pub const fn kind(&self) -> RegionKind {
        self.kind
    }

    /// This authority's budget ledger (mutable).
    pub fn budget_mut(&mut self) -> &mut BudgetLedger {
        &mut self.budget
    }

    /// Requires a capability grant; fails closed naming the missing grant.
    pub fn require_grant(
        &self,
        grant: fss_core::RuntimeGrant,
    ) -> Result<(), crate::grant::GrantError> {
        self.grants.require_grant(grant)
    }

    /// Requires a grant for a specific resource; scoped grants refuse
    /// resources outside their scope.
    pub fn require_grant_for(
        &self,
        grant: fss_core::RuntimeGrant,
        resource: &str,
    ) -> Result<(), crate::grant::GrantError> {
        self.grants.require_grant_for(grant, resource)
    }

    /// This authority's typed grant set (read-only).
    #[must_use]
    pub fn grants(&self) -> &crate::grant::GrantSet {
        &self.grants
    }

    /// The budget ledger (read).
    #[must_use]
    pub const fn budget(&self) -> &BudgetLedger {
        &self.budget
    }

    /// Register an obligation on this authority's region — delegated to the
    /// region tree (the tree owns obligation lifecycle; no parallel
    /// registry). Refuses on closed/inactive regions and duplicates.
    pub fn register_obligation(
        &self,
        tree: &mut RegionTree,
        obligation: Obligation,
    ) -> Result<(), AuthorityError> {
        tree.register_obligation(&self.region, obligation)
            .map_err(AuthorityError::Region)
    }

    /// Resolve one of this authority's obligations through the tree
    /// (Indeterminate resolutions carry the durable reconciliation note the
    /// tree enforces).
    pub fn resolve_obligation(
        &self,
        tree: &mut RegionTree,
        obligation_id: &fss_core::ObligationId,
        terminal: crate::obligation::ObligationTerminal,
        proof_digest: Option<fss_core::ContentDigest>,
        reconciliation_note: Option<&str>,
    ) -> Result<(), AuthorityError> {
        tree.resolve_obligation(
            &self.region,
            obligation_id,
            terminal.to_state(),
            proof_digest,
            reconciliation_note,
        )
        .map_err(AuthorityError::Region)
    }

    /// The leak oracle for this authority's region: pending obligations by
    /// name — read from the tree, never a parallel registry.
    #[must_use]
    pub fn leaked_obligations(
        &self,
        tree: &RegionTree,
    ) -> Vec<crate::obligation::LeakedObligation> {
        match tree.get(&self.region) {
            Ok(node) => crate::obligation::leaked_in(node.obligations.values().cloned()),
            Err(_) => Vec::new(),
        }
    }

    /// Request cancellation of this scope and every derived scope (the
    /// shared-state chain carries it).
    pub fn request_cancellation(&self) {
        self.cx.cancel_fast(asupersync::types::CancelKind::User);
    }

    /// Whether cancellation has been requested on this scope's chain.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.cx.is_cancelled()
    }

    /// Finalize this scope: the leak oracle over the tree's state for this
    /// region. A scope with pending obligations is NOT clean; the names come
    /// out, never silence.
    #[must_use]
    pub fn finalize_report(&self, tree: &RegionTree) -> Vec<crate::obligation::LeakedObligation> {
        self.leaked_obligations(tree)
    }
}
