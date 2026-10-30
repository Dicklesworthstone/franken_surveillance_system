#![forbid(unsafe_code)]
//! Cumulative session accounting before an explicitly selected probe view is released.

use super::*;
use crate::agent_session::ReferenceSessionError;

impl DurableSessionStore {
    /// Charge a complete bounded probe projection through the existing checkpoint transaction.
    /// This is an internal composition hook, never a caller-supplied hydration or source grant.
    /// Every explicit delivery is charged; recovery neither redelivers nor refunds it.
    pub(crate) fn charge_supervision_projection(
        &mut self,
        principal: &PrincipalId,
        expected: &SupervisionSubscription,
        view: fss_core::AgentView,
        tokens: u64,
        now: TimestampNs,
    ) -> Result<u64> {
        if !matches!(
            view,
            fss_core::AgentView::Case | fss_core::AgentView::Forensic
        ) || tokens == 0
            || tokens > u64::from(view.maximum_tokens())
        {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        let current = self.inspect_supervision(principal, expected.registration(), now)?;
        if current.digest() != expected.digest() {
            return Err(DurableSupervisionError::Conflict);
        }
        let session = &expected.registration().session_id;
        self.transact(|memory| {
            let entry = memory.live_entry(principal, session, now)?;
            if !entry
                .session
                .capabilities
                .contains("CAP-AGENT-CASE-WRITE-001")
            {
                return Err(ReferenceSessionError::GrantEscalation);
            }
            entry.spent_tokens = entry
                .spent_tokens
                .checked_add(tokens)
                .filter(|spent| *spent <= entry.session.token_budget)
                .ok_or(ReferenceSessionError::BudgetExceeded)?;
            Ok(entry.session.token_budget - entry.spent_tokens)
        })
        .map_err(Into::into)
    }
}
