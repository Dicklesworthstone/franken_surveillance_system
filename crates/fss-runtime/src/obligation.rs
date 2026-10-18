//! Obligation construction + leak-oracle reporting for the runtime authority
//! core (FSS-021 slice 1 / FSS-023 groundwork). The obligation RECORDS and
//! lifecycle are owned by `fss-core` (`effect::Obligation`/`ObligationState`,
//! registered and resolved per region via `RegionTree`); this module is the
//! constructor + reporting facade — it invents no parallel vocabulary and
//! stores no parallel state.
//!
//! The four-valued terminal mapping (from IMP-AS-CANCEL-001's outcome
//! vocabulary): Completed→`Verified`, Drained→`Cancelled`, Failed→`Failed`,
//! and non-cooperative/unknown→`Indeterminate` (which REQUIRES a durable
//! reconciliation note — enforced by the tree).

use fss_core::{ObligationId, OperationId};

pub use fss_core::{Obligation, ObligationState};

/// Our four-valued terminal vocabulary for obligations (the runtime lane's
/// honest outcome classes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationTerminal {
    /// Completed normally (maps to `ObligationState::Verified`).
    Completed,
    /// Drained on cancellation (maps to `ObligationState::Cancelled`).
    Drained,
    /// Failed terminally (maps to `ObligationState::Failed`).
    Failed,
    /// Non-cooperative/unknown (maps to `ObligationState::Indeterminate` —
    /// requires a reconciliation note at the tree boundary).
    Indeterminate,
}

impl ObligationTerminal {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Drained => "drained",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// The fss-core obligation state this terminal class maps to.
    #[must_use]
    pub const fn to_state(self) -> ObligationState {
        match self {
            Self::Completed => ObligationState::Verified,
            Self::Drained => ObligationState::Cancelled,
            Self::Failed => ObligationState::Failed,
            Self::Indeterminate => ObligationState::Indeterminate,
        }
    }
}

/// Builds one fss-core obligation record bound to an operation, with the
/// terminal predicate spelled out (a vague predicate is a leak amplifier).
#[must_use]
pub fn new_obligation(
    id: impl Into<String>,
    operation: OperationId,
    terminal_predicate: impl Into<String>,
) -> Result<Obligation, fss_core::ContractError> {
    Ok(Obligation {
        obligation_id: ObligationId::parse(id)?,
        operation_id: operation,
        terminal_predicate: terminal_predicate.into(),
        state: ObligationState::Pending,
        proof_digest: None,
    })
}

/// One leak finding (an obligation not terminal at oracle evaluation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeakedObligation {
    /// The leaked obligation's id.
    pub id: String,
    /// Its terminal predicate (what was never proven).
    pub terminal_predicate: String,
}

/// The leak oracle over one region's obligation map: every obligation whose
/// state is not terminal, in deterministic order. Terminal means
/// Verified/Failed/Cancelled/Indeterminate-with-proof-or-note — Pending is
/// never terminal.
#[must_use]
pub fn leaked_in(
    obligations: impl IntoIterator<Item = Obligation>,
) -> Vec<LeakedObligation> {
    obligations
        .into_iter()
        .filter(|o| matches!(o.state, ObligationState::Pending))
        .map(|o| LeakedObligation {
            id: o.obligation_id.as_str().to_string(),
            terminal_predicate: o.terminal_predicate.clone(),
        })
        .collect()
}
