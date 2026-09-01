use std::collections::BTreeMap;
use std::fmt;

use crate::digest::{CanonicalWriter, Digest, DigestError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectState {
    Prepared,
    Dispatching,
    AppliedAwaitingVerification,
    Verified,
    CancelRequested,
    Cancelled,
    Failed,
    Indeterminate,
}

impl EffectState {
    const fn code(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::Dispatching => 1,
            Self::AppliedAwaitingVerification => 2,
            Self::Verified => 3,
            Self::CancelRequested => 4,
            Self::Cancelled => 5,
            Self::Failed => 6,
            Self::Indeterminate => 7,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationState {
    Pending,
    Satisfied,
    Failed,
    Indeterminate,
}

impl ObligationState {
    const fn code(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Satisfied => 1,
            Self::Failed => 2,
            Self::Indeterminate => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOutcome {
    Acknowledged,
    Rejected,
    LostAcknowledgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationObservation {
    AppliedAndVerified,
    ProvenNotApplied,
    StillUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    pub id: String,
    pub operation_id: String,
    pub terminal_predicate: String,
    pub state: ObligationState,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectOperation {
    pub id: String,
    pub idempotency_key: String,
    pub obligation_id: String,
    pub action: String,
    pub state: EffectState,
    pub dispatch_attempts: u32,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectError {
    Digest(DigestError),
    EmptyIdentity(&'static str),
    MissingOperation(String),
    IdempotencyConflict(String),
    ObligationConflict {
        obligation_id: String,
        existing_operation: String,
        proposed_operation: String,
    },
    InvalidTransition {
        operation_id: String,
        from: EffectState,
        attempted: &'static str,
    },
    BlindRetryForbidden(String),
    AttemptOverflow(String),
}

impl fmt::Display for EffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "digest failure: {error}"),
            Self::EmptyIdentity(field) => write!(formatter, "{field} cannot be empty"),
            Self::MissingOperation(key) => write!(formatter, "no effect uses idempotency key {key}"),
            Self::IdempotencyConflict(key) => write!(
                formatter,
                "idempotency key {key} was reused for a different effect"
            ),
            Self::ObligationConflict {
                obligation_id,
                existing_operation,
                proposed_operation,
            } => write!(
                formatter,
                "obligation {obligation_id} belongs to {existing_operation}, not {proposed_operation}"
            ),
            Self::InvalidTransition {
                operation_id,
                from,
                attempted,
            } => write!(
                formatter,
                "effect {operation_id} cannot {attempted} from state {from:?}"
            ),
            Self::BlindRetryForbidden(operation_id) => write!(
                formatter,
                "effect {operation_id} is indeterminate and requires reconciliation before retry"
            ),
            Self::AttemptOverflow(operation_id) => {
                write!(formatter, "effect {operation_id} exhausted its attempt counter")
            }
        }
    }
}

impl std::error::Error for EffectError {}

impl From<DigestError> for EffectError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

#[derive(Debug, Clone)]
pub struct EffectCoordinator {
    operations: BTreeMap<String, EffectOperation>,
    obligation_owners: BTreeMap<String, String>,
    obligations: BTreeMap<String, Obligation>,
    root: Digest,
    transition_count: u64,
}

impl Default for EffectCoordinator {
    fn default() -> Self {
        Self {
            operations: BTreeMap::new(),
            obligation_owners: BTreeMap::new(),
            obligations: BTreeMap::new(),
            root: Digest::ZERO,
            transition_count: 0,
        }
    }
}

impl EffectCoordinator {
    #[must_use]
    pub const fn root(&self) -> Digest {
        self.root
    }

    pub fn prepare(
        &mut self,
        operation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        obligation_id: impl Into<String>,
        action: impl Into<String>,
        terminal_predicate: impl Into<String>,
    ) -> Result<EffectOperation, EffectError> {
        let operation_id = operation_id.into();
        let idempotency_key = idempotency_key.into();
        let obligation_id = obligation_id.into();
        let action = action.into();
        let terminal_predicate = terminal_predicate.into();
        validate_nonempty("operation_id", &operation_id)?;
        validate_nonempty("idempotency_key", &idempotency_key)?;
        validate_nonempty("obligation_id", &obligation_id)?;
        validate_nonempty("action", &action)?;
        validate_nonempty("terminal_predicate", &terminal_predicate)?;

        if let Some(existing) = self.operations.get(&idempotency_key) {
            if existing.id == operation_id
                && existing.obligation_id == obligation_id
                && existing.action == action
            {
                return Ok(existing.clone());
            }
            return Err(EffectError::IdempotencyConflict(idempotency_key));
        }
        if let Some(existing_operation) = self.obligation_owners.get(&obligation_id) {
            if existing_operation != &operation_id {
                return Err(EffectError::ObligationConflict {
                    obligation_id,
                    existing_operation: existing_operation.clone(),
                    proposed_operation: operation_id,
                });
            }
        }

        let obligation_digest = obligation_digest(
            &obligation_id,
            &operation_id,
            &terminal_predicate,
            ObligationState::Pending,
        )?;
        let obligation = Obligation {
            id: obligation_id.clone(),
            operation_id: operation_id.clone(),
            terminal_predicate,
            state: ObligationState::Pending,
            digest: obligation_digest,
        };
        let operation = EffectOperation {
            digest: operation_digest(
                &operation_id,
                &idempotency_key,
                &obligation_id,
                &action,
                EffectState::Prepared,
                0,
                obligation.digest,
            )?,
            id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            obligation_id: obligation_id.clone(),
            action,
            state: EffectState::Prepared,
            dispatch_attempts: 0,
        };
        self.obligation_owners
            .insert(obligation_id.clone(), operation_id);
        self.obligations.insert(obligation_id, obligation);
        self.operations
            .insert(idempotency_key.clone(), operation.clone());
        self.advance_root(&idempotency_key)?;
        Ok(operation)
    }

    pub fn dispatch(
        &mut self,
        idempotency_key: &str,
        outcome: DispatchOutcome,
    ) -> Result<EffectOperation, EffectError> {
        let current = self
            .operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?
            .state;
        if current == EffectState::Indeterminate {
            let id = self
                .operations
                .get(idempotency_key)
                .expect("operation checked above")
                .id
                .clone();
            return Err(EffectError::BlindRetryForbidden(id));
        }
        if current != EffectState::Prepared {
            let operation = self
                .operations
                .get(idempotency_key)
                .expect("operation checked above");
            return Err(EffectError::InvalidTransition {
                operation_id: operation.id.clone(),
                from: current,
                attempted: "dispatch",
            });
        }
        self.transition_effect(idempotency_key, EffectState::Dispatching, None)?;
        let terminal_state = match outcome {
            DispatchOutcome::Acknowledged => EffectState::AppliedAwaitingVerification,
            DispatchOutcome::Rejected => EffectState::Failed,
            DispatchOutcome::LostAcknowledgement => EffectState::Indeterminate,
        };
        self.transition_effect(idempotency_key, terminal_state, Some(true))?;
        self.sync_obligation(idempotency_key)?;
        self.operations
            .get(idempotency_key)
            .cloned()
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))
    }

    pub fn verify(&mut self, idempotency_key: &str) -> Result<EffectOperation, EffectError> {
        let current = self
            .operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?
            .state;
        if current != EffectState::AppliedAwaitingVerification {
            let id = self
                .operations
                .get(idempotency_key)
                .expect("operation checked above")
                .id
                .clone();
            return Err(EffectError::InvalidTransition {
                operation_id: id,
                from: current,
                attempted: "verify",
            });
        }
        self.transition_effect(idempotency_key, EffectState::Verified, None)?;
        self.sync_obligation(idempotency_key)?;
        self.operations
            .get(idempotency_key)
            .cloned()
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))
    }

    pub fn reconcile(
        &mut self,
        idempotency_key: &str,
        observation: ReconciliationObservation,
    ) -> Result<EffectOperation, EffectError> {
        let current = self
            .operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?
            .state;
        if current != EffectState::Indeterminate {
            let id = self
                .operations
                .get(idempotency_key)
                .expect("operation checked above")
                .id
                .clone();
            return Err(EffectError::InvalidTransition {
                operation_id: id,
                from: current,
                attempted: "reconcile",
            });
        }
        match observation {
            ReconciliationObservation::AppliedAndVerified => {
                self.transition_effect(idempotency_key, EffectState::Verified, None)?;
            }
            ReconciliationObservation::ProvenNotApplied => {
                self.transition_effect(idempotency_key, EffectState::Prepared, None)?;
            }
            ReconciliationObservation::StillUnknown => {
                self.advance_root(idempotency_key)?;
            }
        }
        self.sync_obligation(idempotency_key)?;
        self.operations
            .get(idempotency_key)
            .cloned()
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))
    }

    pub fn cancel(&mut self, idempotency_key: &str) -> Result<EffectOperation, EffectError> {
        let current = self
            .operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?
            .state;
        let next = match current {
            EffectState::Prepared => EffectState::Cancelled,
            EffectState::Dispatching | EffectState::AppliedAwaitingVerification => {
                EffectState::CancelRequested
            }
            EffectState::Indeterminate => {
                let id = self
                    .operations
                    .get(idempotency_key)
                    .expect("operation checked above")
                    .id
                    .clone();
                return Err(EffectError::InvalidTransition {
                    operation_id: id,
                    from: current,
                    attempted: "cancel without reconciliation",
                });
            }
            _ => {
                let operation = self
                    .operations
                    .get(idempotency_key)
                    .expect("operation checked above");
                return Ok(operation.clone());
            }
        };
        self.transition_effect(idempotency_key, next, None)?;
        self.sync_obligation(idempotency_key)?;
        self.operations
            .get(idempotency_key)
            .cloned()
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))
    }

    pub fn operation(&self, idempotency_key: &str) -> Result<&EffectOperation, EffectError> {
        self.operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))
    }

    pub fn obligation(&self, obligation_id: &str) -> Option<&Obligation> {
        self.obligations.get(obligation_id)
    }

    fn transition_effect(
        &mut self,
        idempotency_key: &str,
        state: EffectState,
        increment_attempt: Option<bool>,
    ) -> Result<(), EffectError> {
        let obligation_digest = {
            let operation = self
                .operations
                .get(idempotency_key)
                .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?;
            self.obligations
                .get(&operation.obligation_id)
                .map(|obligation| obligation.digest)
                .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?
        };
        let operation = self
            .operations
            .get_mut(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?;
        if increment_attempt == Some(true) {
            operation.dispatch_attempts = operation
                .dispatch_attempts
                .checked_add(1)
                .ok_or_else(|| EffectError::AttemptOverflow(operation.id.clone()))?;
        }
        operation.state = state;
        operation.digest = operation_digest(
            &operation.id,
            &operation.idempotency_key,
            &operation.obligation_id,
            &operation.action,
            operation.state,
            operation.dispatch_attempts,
            obligation_digest,
        )?;
        self.advance_root(idempotency_key)
    }

    fn sync_obligation(&mut self, idempotency_key: &str) -> Result<(), EffectError> {
        let operation = self
            .operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?
            .clone();
        let obligation = self
            .obligations
            .get_mut(&operation.obligation_id)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?;
        obligation.state = match operation.state {
            EffectState::Verified => ObligationState::Satisfied,
            EffectState::Failed | EffectState::Cancelled => ObligationState::Failed,
            EffectState::Indeterminate => ObligationState::Indeterminate,
            _ => ObligationState::Pending,
        };
        obligation.digest = obligation_digest(
            &obligation.id,
            &obligation.operation_id,
            &obligation.terminal_predicate,
            obligation.state,
        )?;
        let operation = self
            .operations
            .get_mut(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?;
        operation.digest = operation_digest(
            &operation.id,
            &operation.idempotency_key,
            &operation.obligation_id,
            &operation.action,
            operation.state,
            operation.dispatch_attempts,
            obligation.digest,
        )?;
        self.advance_root(idempotency_key)
    }

    fn advance_root(&mut self, idempotency_key: &str) -> Result<(), EffectError> {
        let operation = self
            .operations
            .get(idempotency_key)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?;
        let obligation = self
            .obligations
            .get(&operation.obligation_id)
            .ok_or_else(|| EffectError::MissingOperation(idempotency_key.to_owned()))?;
        let next_count = self
            .transition_count
            .checked_add(1)
            .ok_or_else(|| EffectError::AttemptOverflow(operation.id.clone()))?;
        let mut writer = CanonicalWriter::new("fss-effect-root-v1")?;
        writer.push_digest(self.root);
        writer.push_u64(next_count);
        writer.push_digest(operation.digest);
        writer.push_digest(obligation.digest);
        self.root = writer.digest()?;
        self.transition_count = next_count;
        Ok(())
    }
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), EffectError> {
    if value.is_empty() {
        Err(EffectError::EmptyIdentity(field))
    } else {
        Ok(())
    }
}

fn obligation_digest(
    id: &str,
    operation_id: &str,
    terminal_predicate: &str,
    state: ObligationState,
) -> Result<Digest, DigestError> {
    let mut writer = CanonicalWriter::new("fss-obligation-v1")?;
    writer.push_str(id)?;
    writer.push_str(operation_id)?;
    writer.push_str(terminal_predicate)?;
    writer.push_u8(state.code());
    writer.digest()
}

fn operation_digest(
    id: &str,
    idempotency_key: &str,
    obligation_id: &str,
    action: &str,
    state: EffectState,
    dispatch_attempts: u32,
    obligation_digest: Digest,
) -> Result<Digest, DigestError> {
    let mut writer = CanonicalWriter::new("fss-effect-operation-v1")?;
    writer.push_str(id)?;
    writer.push_str(idempotency_key)?;
    writer.push_str(obligation_id)?;
    writer.push_str(action)?;
    writer.push_u8(state.code());
    writer.push_u32(dispatch_attempts);
    writer.push_digest(obligation_digest);
    writer.digest()
}

#[cfg(test)]
mod tests {
    use super::{
        DispatchOutcome, EffectCoordinator, EffectError, EffectState, ObligationState,
        ReconciliationObservation,
    };

    #[test]
    fn exact_idempotent_prepare_returns_the_existing_operation() {
        let mut coordinator = EffectCoordinator::default();
        let first = coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("prepare");
        let second = coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("repeat");
        assert_eq!(first, second);
    }

    #[test]
    fn idempotency_drift_fails() {
        let mut coordinator = EffectCoordinator::default();
        coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("prepare");
        assert!(matches!(
            coordinator.prepare("op-2", "key-1", "obl-2", "different", "different"),
            Err(EffectError::IdempotencyConflict(_))
        ));
    }

    #[test]
    fn obligation_cannot_drift_between_operations() {
        let mut coordinator = EffectCoordinator::default();
        coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("prepare");
        assert!(matches!(
            coordinator.prepare("op-2", "key-2", "obl-1", "log-event", "log visible"),
            Err(EffectError::ObligationConflict { .. })
        ));
    }

    #[test]
    fn lost_ack_is_indeterminate_and_blocks_blind_retry() {
        let mut coordinator = EffectCoordinator::default();
        coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("prepare");
        let operation = coordinator
            .dispatch("key-1", DispatchOutcome::LostAcknowledgement)
            .expect("dispatch");
        assert_eq!(operation.state, EffectState::Indeterminate);
        assert_eq!(
            coordinator.obligation("obl-1").expect("obligation").state,
            ObligationState::Indeterminate
        );
        assert!(matches!(
            coordinator.dispatch("key-1", DispatchOutcome::Acknowledged),
            Err(EffectError::BlindRetryForbidden(_))
        ));
    }

    #[test]
    fn reconciliation_can_prove_completion() {
        let mut coordinator = EffectCoordinator::default();
        coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("prepare");
        coordinator
            .dispatch("key-1", DispatchOutcome::LostAcknowledgement)
            .expect("dispatch");
        let operation = coordinator
            .reconcile("key-1", ReconciliationObservation::AppliedAndVerified)
            .expect("reconcile");
        assert_eq!(operation.state, EffectState::Verified);
        assert_eq!(
            coordinator.obligation("obl-1").expect("obligation").state,
            ObligationState::Satisfied
        );
    }

    #[test]
    fn proven_non_application_allows_same_key_retry() {
        let mut coordinator = EffectCoordinator::default();
        coordinator
            .prepare("op-1", "key-1", "obl-1", "send-alert", "delivery observed")
            .expect("prepare");
        coordinator
            .dispatch("key-1", DispatchOutcome::LostAcknowledgement)
            .expect("dispatch");
        coordinator
            .reconcile("key-1", ReconciliationObservation::ProvenNotApplied)
            .expect("reconcile");
        let operation = coordinator
            .dispatch("key-1", DispatchOutcome::Acknowledged)
            .expect("retry");
        assert_eq!(operation.state, EffectState::AppliedAwaitingVerification);
        assert_eq!(operation.dispatch_attempts, 2);
    }
}
