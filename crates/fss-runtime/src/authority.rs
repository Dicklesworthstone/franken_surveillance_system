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
    ContextAuthority, OperationId, RegionError, RegionId, RegionKind, RegionTree,
    RootAuthoritySpec, TimestampNs,
};

use crate::budget::{Budget, BudgetLedger};
use crate::obligation::ObligationRegistry;

/// One explicit authority context: the cancellation substrate, the region it
/// belongs to, its budget ledger, and its obligation registry. There is no
/// ambient accessor by design.
pub struct AuthorityCx {
    cx: asupersync::cx::Cx<asupersync::cx::cap::None>,
    region: RegionId,
    kind: RegionKind,
    budget: BudgetLedger,
    obligations: ObligationRegistry,
}

/// Typed authority errors.
#[derive(Debug)]
pub enum AuthorityError {
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
        budget: Budget,
        now: TimestampNs,
    ) -> Result<(Self, RegionTree), AuthorityError> {
        let authority = ContextAuthority::new_root(spec)?;
        let tree = RegionTree::new(process_region.clone(), authority, now)?;
        Ok((
            Self {
                cx: asupersync::Cx::detached_cancel_context(),
                region: process_region,
                kind: process_kind,
                budget: BudgetLedger::new(budget),
                obligations: ObligationRegistry::new(),
            },
            tree,
        ))
    }

    /// Scope DOWN into a child region of this authority: the child's kind
    /// must be legal under the parent's kind (region-tree rule), its budget
    /// must not exceed the parent's remaining in any dimension (no silent
    /// widening), and it shares the parent's cancellation state.
    pub fn scope_down(
        &self,
        tree: &mut RegionTree,
        child_id: RegionId,
        child_kind: RegionKind,
        child_budget: Budget,
        child_authority_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<AuthorityCx, AuthorityError> {
        self.kind
            .validate_child_kind(child_kind)
            .map_err(|e| AuthorityError::IllegalScope {
                detail: format!("{e}"),
            })?;
        let remaining = self.budget.remaining();
        for (allowed, requested, name) in [
            (remaining.work_units, child_budget.work_units, "work_units"),
            (remaining.bytes, child_budget.bytes, "bytes"),
            (remaining.wall_ns, child_budget.wall_ns, "wall_ns"),
        ] {
            if requested > allowed {
                return Err(AuthorityError::IllegalScope {
                    detail: format!(
                        "child {name} budget ({requested}) exceeds parent remaining ({allowed})"
                    ),
                });
            }
        }
        let child_authority = ContextAuthority::new_root(child_authority_spec)?;
        tree.attach_child(
            &self.region,
            child_id.clone(),
            child_kind,
            child_authority,
            now,
        )?;
        Ok(AuthorityCx {
            // Cloned Cx shares underlying cancellation/budget state — a
            // parent cancellation is visible to every derived scope.
            cx: self.cx.clone(),
            region: child_id,
            kind: child_kind,
            budget: BudgetLedger::new(child_budget),
            obligations: ObligationRegistry::new(),
        })
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

    /// The budget ledger (mutable only by the owner of the Cx).
    #[must_use]
    pub fn budget_mut(&mut self) -> &mut BudgetLedger {
        &mut self.budget
    }

    /// The budget ledger (read).
    #[must_use]
    pub const fn budget(&self) -> &BudgetLedger {
        &self.budget
    }

    /// The obligation registry.
    #[must_use]
    pub fn obligations_mut(&mut self) -> &mut ObligationRegistry {
        &mut self.obligations
    }

    /// The obligation registry (read).
    #[must_use]
    pub const fn obligations(&self) -> &ObligationRegistry {
        &self.obligations
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

    /// Finalize this scope: the leak oracle result. A scope with leaked
    /// obligations is NOT clean; the names come out, never silence.
    #[must_use]
    pub fn finalize_report(&self) -> Vec<crate::obligation::LeakedObligation> {
        self.obligations.leaked()
    }
}
