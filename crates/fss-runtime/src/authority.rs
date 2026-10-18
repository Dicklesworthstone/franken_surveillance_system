//! The explicit authority context: Asupersync `Cx` underneath, the fss-core
//! region hierarchy above, and the FSS charter's rule between them — every
//! authority is constructed explicitly and passed by value. There is no
//! ambient lookup in this module by design.
//!
//! Scoping follows `fss-core`'s region-kind legality (`validate_child_kind`)
//! and multiplicity caps: a child scope that violates the parent's rules is
//! a typed refusal, never a silent widening.

use fss_core::{RegionError, RegionId, RegionKind, RegionState, RegionTree, TaskId};

use crate::budget::{Budget, BudgetLedger};
use crate::obligation::ObligationRegistry;

/// One explicit authority context. Holds:
/// * the Asupersync cancellation substrate for this scope (`cx`),
/// * the region it belongs to in the fss-core region tree,
/// * its budget ledger and obligation registry (value types; moved/borrowed
///   explicitly, never ambient).
pub struct AuthorityCx {
    cx: asupersync::Cx,
    region: RegionId,
    kind: RegionKind,
    budget: BudgetLedger,
    obligations: ObligationRegistry,
}

/// Typed authority errors.
#[derive(Debug)]
pub enum AuthorityError {
    /// The requested scope violates the parent region's rules.
    IllegalScope {
        /// What was attempted (typed detail).
        detail: String,
    },
    /// The region tree rejected the scope.
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
    /// Construct the root authority for a fresh region tree: a named root
    /// region of the given kind, with an initial budget.
    pub fn root(
        tree: &mut RegionTree,
        region_id: RegionId,
        kind: RegionKind,
        budget: Budget,
    ) -> Result<Self, AuthorityError> {
        let mut node = tree
            .add_region(region_id.clone(), None, kind, RegionState::Active)
            .map_err(AuthorityError::Region)?;
        node.register_task(TaskId::new("root"))?;
        Ok(Self {
            cx: asupersync::Cx::new(),
            region: region_id,
            kind,
            budget: BudgetLedger::new(budget),
            obligations: ObligationRegistry::new(),
        })
    }

    /// Scope DOWN into a child region of this authority. The child's kind
    /// must be legal under the parent's kind (region-tree rule), the child
    /// budget must not exceed the parent's remaining budget in any dimension
    /// (no silent widening), and the child shares the parent's cancellation
    /// substrate (cancellation cascades through the scope chain).
    pub fn scope_down(
        &self,
        tree: &mut RegionTree,
        child_id: RegionId,
        child_kind: RegionKind,
        child_budget: Budget,
    ) -> Result<AuthorityCx, AuthorityError> {
        // Kind legality per the region hierarchy.
        self.kind
            .validate_child_kind(child_kind)
            .map_err(|e| AuthorityError::IllegalScope {
                detail: format!("{e}"),
            })?;
        // Budget must not exceed the parent's remaining (any dimension).
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
        tree.add_region(child_id.clone(), Some(self.region.clone()), child_kind, RegionState::Active)?;
        Ok(AuthorityCx {
            // asupersync Cx derives: child contexts inherit the parent's
            // cancellation chain.
            cx: self.cx.derive(),
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

    /// Request cancellation of this scope (cascades through derived
    /// contexts, per asupersync's cancellation chain).
    pub fn request_cancellation(&self) {
        self.cx.cancel();
    }

    /// Whether cancellation has been requested on this scope.
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
