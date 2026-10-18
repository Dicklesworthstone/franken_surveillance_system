//! Obligation registry and leak oracle: every registered obligation must be
//! terminal at region finalize, and any that are not are named — never
//! silently dropped. (FSS-021 slice 1 / FSS-023 groundwork.)

use std::collections::BTreeMap;

/// One tracked obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Obligation {
    /// Stable obligation identity (caller-chosen).
    pub id: String,
    /// What kind of work it represents (typed, non-secret-bearing).
    pub kind: String,
    /// Terminal status, when reached.
    pub terminal: Option<ObligationTerminal>,
}

/// How an obligation terminated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationTerminal {
    /// Completed normally.
    Completed,
    /// Drained on cancellation.
    Drained,
    /// Failed terminally.
    Failed,
}

impl ObligationTerminal {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Drained => "drained",
            Self::Failed => "failed",
        }
    }
}

/// The registry: ids are unique (duplicate registration is a typed refusal,
/// never a silent overwrite).
#[derive(Default)]
pub struct ObligationRegistry {
    obligations: BTreeMap<String, Obligation>,
}

/// One leak finding (an obligation that never reached terminal at oracle
/// evaluation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeakedObligation {
    /// The leaked obligation's id.
    pub id: String,
    /// Its kind.
    pub kind: String,
}

/// Typed registry errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObligationError {
    /// Registering an id that already exists.
    Duplicate(String),
    /// Completing an id that was never registered.
    Unknown(String),
    /// Completing an obligation that is already terminal.
    AlreadyTerminal(String),
}

impl core::fmt::Display for ObligationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Duplicate(id) => write!(f, "duplicate obligation id: {id}"),
            Self::Unknown(id) => write!(f, "unknown obligation id: {id}"),
            Self::AlreadyTerminal(id) => write!(f, "obligation already terminal: {id}"),
        }
    }
}

impl std::error::Error for ObligationError {}

impl ObligationRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new obligation; duplicate ids are a typed refusal.
    pub fn register(&mut self, id: impl Into<String>, kind: impl Into<String>) -> Result<(), ObligationError> {
        let id = id.into();
        if self.obligations.contains_key(&id) {
            return Err(ObligationError::Duplicate(id));
        }
        self.obligations.insert(
            id.clone(),
            Obligation {
                id,
                kind: kind.into(),
                terminal: None,
            },
        );
        Ok(())
    }

    /// Mark an obligation terminal.
    pub fn terminate(&mut self, id: &str, terminal: ObligationTerminal) -> Result<(), ObligationError> {
        let Some(o) = self.obligations.get_mut(id) else {
            return Err(ObligationError::Unknown(id.to_string()));
        };
        if o.terminal.is_some() {
            return Err(ObligationError::AlreadyTerminal(id.to_string()));
        }
        o.terminal = Some(terminal);
        Ok(())
    }

    /// The leak oracle: every obligation that has not reached terminal, in
    /// deterministic order. An empty result is the only acceptable state at
    /// region finalize; anything else is a named leak.
    #[must_use]
    pub fn leaked(&self) -> Vec<LeakedObligation> {
        self.obligations
            .values()
            .filter(|o| o.terminal.is_none())
            .map(|o| LeakedObligation {
                id: o.id.clone(),
                kind: o.kind.clone(),
            })
            .collect()
    }

    /// Whether every obligation is terminal (the finalize predicate).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.obligations.values().all(|o| o.terminal.is_some())
    }

    /// Snapshot of current obligations (for evidence bundles).
    #[must_use]
    pub fn snapshot(&self) -> Vec<Obligation> {
        self.obligations.values().cloned().collect()
    }
}
