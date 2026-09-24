#![forbid(unsafe_code)]
//! Case commands and their session-state witnesses share the existing coordination journal.

use super::super::super::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession,
};
use super::super::{COORDINATION_COMMAND_RECORD_KIND, CoordinationState};
use super::*;
use fss_core::CanonicalDecoder;

mod codec;
mod evolution;
pub(super) mod source_citation;

const INIT: &str = "fss.reference_investigation_init.v1";
const RECORD: &str = "fss.reference_investigation_record.v1";

/// Separates expected case refusal from uncertain or invalid persistence.
#[derive(Debug)]
pub enum DurableInvestigationError {
    /// No response is authorized until the session journal's failure/recovery contract permits it.
    Durability(DurableSessionError),
    /// A case refusal; any session/case watermark changes were committed before return.
    Refused(InvestigationError),
}
impl fmt::Display for DurableInvestigationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Durability(_) => "durable investigation persistence failed",
            Self::Refused(_) => "durable investigation request refused",
        })
    }
}
impl std::error::Error for DurableInvestigationError {}
impl From<DurableSessionError> for DurableInvestigationError {
    fn from(error: DurableSessionError) -> Self {
        Self::Durability(error)
    }
}

impl DurableSessionStore {
    /// Initializes case history once in an explicitly enabled coordination journal.
    /// Stored ceilings are immutable and bounded by the absolute investigation envelope.
    /// This administrative owner method is not a transport capability or case-authority grant.
    pub fn enable_investigations(
        &mut self,
        limits: InvestigationLimits,
    ) -> Result<(), DurableInvestigationError> {
        self.preflight()?;
        limits
            .validate()
            .map_err(DurableInvestigationError::Refused)?;
        let current = self
            .coordination
            .as_ref()
            .ok_or(DurableSessionError::InvalidHistory)?;
        if let Some(cases) = &current.cases {
            return if cases.limits == limits {
                Ok(())
            } else {
                Err(DurableSessionError::InvalidHistory.into())
            };
        }
        let mut state = current.fork();
        state.cases = Some(
            ReferenceInvestigationStore::new(limits).map_err(DurableInvestigationError::Refused)?,
        );
        let checkpoint = self
            .memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?;
        let mut e = CanonicalEncoder::new();
        e.text(INIT);
        e.u64(limits.max_cases as u64);
        e.u64(limits.max_revisions as u64);
        e.u64(limits.max_retained_bytes as u64);
        e.digest(checkpoint.digest());
        let payload = e.finish_checked().map_err(DurableSessionError::from)?;
        self.commit_candidate(PendingSession {
            memory: self.memory.clone(),
            checkpoint,
            coordination: Some(state),
            record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
        })?;
        Ok(())
    }

    /// Commits case and refusal-side session changes before delivering any case revision.
    ///
    /// Exact-root reopening, pending-append reconciliation and cold recovery use the existing
    /// coordination methods. All session/work/case APIs remain fenced after an ambiguous write.
    /// Never persist this command by itself while independently checkpointing its session owner.
    pub fn investigate(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        command: InvestigationCommand,
        now: TimestampNs,
    ) -> Result<InvestigationRevision, DurableInvestigationError> {
        self.preflight()?;
        let request = codec::Request {
            principal: principal.clone(),
            session: session.clone(),
            command,
            now,
        };
        // Validate bounded private bytes before copying history or changing any watermark.
        let request_bytes = codec::encode(&request)?;
        let mut state = self
            .coordination
            .as_ref()
            .ok_or(DurableSessionError::InvalidHistory)?
            .fork();
        let cases = state
            .cases
            .as_mut()
            .ok_or(DurableSessionError::InvalidHistory)?;
        let mut memory = self.memory.clone();
        let result = cases.execute(&mut memory, principal, session, &request.command, now);
        let staged = (|| -> Result<PendingSession, DurableSessionError> {
            let checkpoint = memory.checkpoint(self.limits.max_checkpoint_bytes)?;
            let mut e = CanonicalEncoder::new();
            e.text(RECORD);
            e.bytes(&request_bytes);
            e.digest(self.checkpoint_digest);
            e.digest(checkpoint.digest());
            e.digest(outcome(&result));
            let payload = e.finish_checked()?;
            if payload.len() > MAX_INVESTIGATION_BYTES {
                return Err(DurableSessionError::CapacityExceeded);
            }
            Ok(PendingSession {
                memory,
                checkpoint,
                coordination: Some(state),
                record: Some((COORDINATION_COMMAND_RECORD_KIND, payload)),
            })
        })();
        let pending = match staged {
            Ok(pending) => pending,
            Err(error) => {
                self.fenced = true;
                return Err(error.into());
            }
        };
        self.commit_candidate(pending)?;
        result.map_err(DurableInvestigationError::Refused)
    }
}

pub(in crate::agent_session::checkpoint::journal::coordination) fn is_record(
    payload: &[u8],
) -> Result<bool, DurableSessionError> {
    if payload.len() > MAX_INVESTIGATION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(payload);
    Ok(matches!(
        d.text()?,
        INIT | RECORD | evolution::RECORD | source_citation::RECORD
    ))
}

pub(in crate::agent_session::checkpoint::journal::coordination) fn replay_record(
    payload: &[u8],
    sessions: &mut ReferenceSessionStore,
    state: &mut CoordinationState,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    if payload.len() > MAX_INVESTIGATION_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(payload);
    match d.text()? {
        INIT => {
            if state.cases.is_some() {
                return Err(DurableSessionError::InvalidHistory);
            }
            let case_limits = InvestigationLimits {
                max_cases: usize::try_from(d.u64()?)
                    .map_err(|_| DurableSessionError::CapacityExceeded)?,
                max_revisions: usize::try_from(d.u64()?)
                    .map_err(|_| DurableSessionError::CapacityExceeded)?,
                max_retained_bytes: usize::try_from(d.u64()?)
                    .map_err(|_| DurableSessionError::CapacityExceeded)?,
            };
            let witness = d.digest()?;
            d.ensure_finished()?;
            if witness != sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() {
                return Err(DurableSessionError::InvalidHistory);
            }
            state.cases = Some(
                ReferenceInvestigationStore::new(case_limits)
                    .map_err(|_| DurableSessionError::InvalidHistory)?,
            );
        }
        RECORD => {
            let request_bytes = d.bytes()?;
            let before = d.digest()?;
            let after = d.digest()?;
            let expected = d.digest()?;
            d.ensure_finished()?;
            let request = codec::decode(request_bytes)?;
            if before != sessions.checkpoint(limits.max_checkpoint_bytes)?.digest() {
                return Err(DurableSessionError::InvalidHistory);
            }
            let cases = state
                .cases
                .as_mut()
                .ok_or(DurableSessionError::InvalidHistory)?;
            let result = cases.execute(
                sessions,
                &request.principal,
                &request.session,
                &request.command,
                request.now,
            );
            if outcome(&result) != expected
                || after != sessions.checkpoint(limits.max_checkpoint_bytes)?.digest()
            {
                return Err(DurableSessionError::InvalidHistory);
            }
        }
        evolution::RECORD => evolution::replay(payload, sessions, state, limits)?,
        source_citation::RECORD => source_citation::replay(payload, sessions, state, limits)?,
        _ => return Err(DurableSessionError::InvalidHistory),
    }
    Ok(())
}

fn outcome(result: &Result<InvestigationRevision, InvestigationError>) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss-reference:investigation-outcome:v1");
    match result {
        Ok(revision) => {
            e.tag(0);
            e.digest(revision.digest());
        }
        Err(error) => e.tag(match error {
            InvestigationError::Unavailable => 1,
            InvestigationError::Denied => 2,
            InvestigationError::InvalidRecord => 3,
            InvestigationError::Conflict => 4,
            InvestigationError::StaleRevision => 5,
            InvestigationError::StaleBasis => 6,
            InvestigationError::DeadlineElapsed => 7,
            InvestigationError::InvalidTransition => 8,
            InvestigationError::UnresolvedAlternatives => 9,
            InvestigationError::EvidenceRequired => 10,
            InvestigationError::ResidualsRequired => 11,
            InvestigationError::CapacityExceeded => 12,
            InvestigationError::CounterExhausted => 13,
            InvestigationError::ClockRegression => 14,
        }),
    }
    // Only fixed bounded fields are written here; there is no untrusted formatting or text.
    ContentDigest::sha256(&e.finish())
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
