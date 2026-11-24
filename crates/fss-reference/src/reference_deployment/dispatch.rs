#![forbid(unsafe_code)]
//! Durable alert dispatch, cooperative cancellation drain, situation compilation, and handoff sealing
//! for [`super::ReferenceDeployment`].

use fss_core::{EffectState, HandoffCapsule, HandoffId, OperationReceipt, TimestampNs};
use fss_publication::LocalPublicationError;

use super::ReferenceDeployment;
use super::constants::{STAGE_COMPILE_SITUATION, STAGE_DISPATCH_ALERT, STAGE_SEAL_HANDOFF};
use crate::adapter_replay::ReplayCx;
use crate::alert::{ReferenceAlertPlan, ReferenceProviderBehavior};
use crate::error::ReferenceError;
use crate::situation_guard::{
    ReferenceSituation, ReferenceSituationRequest,
    compile_reference_situation_with_durable_journal, seal_reference_handoff,
};

impl ReferenceDeployment {
    /// Dispatches an alert durably through the deployment-owned simulated provider.
    ///
    /// A cooperative cancellation observed at entry is request → drain → finalize with no orphan
    /// obligation (fss-51xqy): the drain step durably cancels the plan's still-`Prepared`
    /// operation with [`crate::alert_cooperative_cancel_proof`] evidence and the
    /// [`crate::ALERT_COOPERATIVE_CANCEL_REASON`] reason, so its obligation is terminal
    /// (`cancelled`) and the situation guard verifies the cancellation; then the context is
    /// finalized and [`ReferenceError::CancellationRequested`] is returned. The provider is never
    /// called. An operation past `Prepared`, or one whose prepared intent is not exactly the
    /// plan's, is never touched by the drain. If the durable cancel itself fails, the context is
    /// still finalized and that failure is returned instead.
    pub fn dispatch_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        behavior: ReferenceProviderBehavior,
        committed_at: TimestampNs,
        outcome_at: TimestampNs,
        cx: &ReplayCx,
    ) -> Result<OperationReceipt, ReferenceError> {
        // A copied Prepared state does not establish that the source never sent this alert
        // after the snapshot. Even cooperative cancellation cannot retire that obligation.
        if let Err(error) = crate::alert::refuse_restored_effect_authority(&self.ledger) {
            if cx.is_cancelled() {
                cx.drain_and_finalize();
            }
            return Err(error);
        }
        if cx.is_cancelled() {
            cx.drain();
            let drained = self.drain_prepared_alert_on_cancel(plan, committed_at);
            cx.finalize();
            drained?;
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DISPATCH_ALERT,
            });
        }
        let receipt = crate::alert::execute_alert_dispatch(crate::alert::AlertDispatchOptions {
            plan,
            authority: &self.ledger,
            read_payload: |digest| {
                self.publisher
                    .spool()
                    .read(digest)
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))
            },
            behavior,
            commit_at: committed_at,
            outcome_at,
            journal: &mut self.effects,
            provider: &mut self.alert_provider,
        })
        .map_err(|error| match error {
            // The composition layer owns the durable journal, so journal state-machine
            // verdicts surface wrapped in this layer's effect error.
            ReferenceError::Contract(contract_error) => ReferenceError::DurableEffect(Box::new(
                crate::durable_effect::DurableEffectError::Contract(contract_error),
            )),
            ReferenceError::StaleEventAuthority => ReferenceError::DurableEffect(Box::new(
                crate::durable_effect::DurableEffectError::Reference(
                    ReferenceError::StaleEventAuthority,
                ),
            )),
            other => other,
        })?;
        Ok(receipt)
    }

    /// Drain step of a cooperative cancellation at [`STAGE_DISPATCH_ALERT`] (fss-51xqy): durably
    /// cancels the plan's operation when, and only when, it is still `Prepared` under exactly the
    /// plan's intent and obligation. The cancellation time is `requested_at`, or the instant after
    /// the operation's last update when `requested_at` is not later, as dispatch revalidation does.
    fn drain_prepared_alert_on_cancel(
        &mut self,
        plan: &ReferenceAlertPlan,
        requested_at: TimestampNs,
    ) -> Result<(), ReferenceError> {
        let operation_id = &plan.intent.operation_id;
        let Some(operation) = self.effects.operation(operation_id) else {
            return Ok(());
        };
        let owns_obligation = self
            .effects
            .obligation(&plan.obligation_id)
            .is_some_and(|obligation| obligation.operation_id == *operation_id);
        if operation.state != EffectState::Prepared
            || operation.intent != plan.intent
            || !owns_obligation
        {
            return Ok(());
        }
        let updated_at = operation.updated_at;
        let cancel_at = if requested_at > updated_at {
            requested_at
        } else {
            TimestampNs(updated_at.0.saturating_add(1))
        };
        let evidence = crate::alert::alert_cooperative_cancel_proof(
            operation_id,
            &plan.authority_anchor,
            STAGE_DISPATCH_ALERT,
        );
        self.effects
            .cancel(
                operation_id,
                cancel_at,
                evidence,
                Some(crate::alert::ALERT_COOPERATIVE_CANCEL_REASON.to_owned()),
            )
            .map_err(|error| ReferenceError::DurableEffect(Box::new(error)))?;
        Ok(())
    }

    /// Compiles a situation projection bound to this deployment's durable effect journal and ledger.
    pub fn compile_situation(
        &self,
        request: ReferenceSituationRequest<'_>,
        cx: &ReplayCx,
    ) -> Result<ReferenceSituation, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_COMPILE_SITUATION,
            });
        }
        compile_reference_situation_with_durable_journal(request, &self.effects, &self.ledger)
    }

    /// Seals a verified handoff capsule from a compiled reference situation.
    pub fn seal_handoff(
        &self,
        situation: &ReferenceSituation,
        handoff_id: HandoffId,
        created_at: TimestampNs,
        expires_at: TimestampNs,
        cx: &ReplayCx,
    ) -> Result<HandoffCapsule, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_SEAL_HANDOFF,
            });
        }
        seal_reference_handoff(situation, handoff_id, created_at, expires_at)
    }
}
