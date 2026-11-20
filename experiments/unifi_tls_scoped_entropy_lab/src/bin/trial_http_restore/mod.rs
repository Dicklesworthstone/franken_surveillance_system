#![forbid(unsafe_code)]
//! One explicitly opted-in, same-session serializer restoration attempt.
//!
//! This is not a crash-recovery workflow or proof of physical-camera behavior.
//! Both the forward and restore effect remain unresolved after readback.

use std::{cell::RefCell, error::Error, net::Ipv4Addr, time::Duration};

use asupersync::{Cx, io::{AsyncRead, AsyncWrite}};
use fss_core::{BudgetVector, ContentDigest, IdempotencyKey, RuntimeGrant};
use fss_reference::unifi_direct::{
    camera_api::{HandoffResponseObservation, HandoffWrite, SerializerAuthority, VideoSerializers}, camera_http, handoff,
    http_stream::{Plan, Preconditions}, metered::MeteredClock,
};
use fss_runtime::{
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
    execution::TaskCx,
    lease::LeaseRegistry,
};

use super::{trial_http_checkpoint::{self, Prepared}, trial_http_record::{ObservationCheckpoint, stopped}, trial_run_id::TrialRunId};

// Bind only the bounded, payload-free HTTP 200 response shape to the complete
// preparation. This records a local exchange claim, not remote effect success,
// physical identity, or authority to retry. No serializer contents are retained.
fn response_receipt(prepared: ContentDigest, observation: HandoffResponseObservation) -> ContentDigest {
    response_receipt_for("fss.unifi-direct.http-restore-response.v1", prepared, observation)
}

#[cfg(test)]
fn start_response_receipt(prepared: ContentDigest, observation: HandoffResponseObservation) -> ContentDigest {
    response_receipt_for("fss.unifi-direct.http-start-response.v1", prepared, observation)
}

fn response_receipt_for(domain: &str, prepared: ContentDigest, observation: HandoffResponseObservation) -> ContentDigest {
    trial_http_checkpoint::response_receipt(domain, prepared, observation)
}

#[must_use = "retain the restore permit and reconcile both camera effects"]
pub struct Outcome {
    pub plan: Plan,
    pub permit: CommittedEffect,
    pub before: VideoSerializers,
    pub after: VideoSerializers,
}

#[must_use = "retain the anchored observation and reconcile both camera effects"]
pub struct AnchoredOutcome {
    pub plan: Plan,
    pub permit: CommittedEffect,
    pub before: VideoSerializers,
    pub after: Prepared,
}

#[must_use = "retain both observations and reconcile both camera effects"]
pub struct FailureRecovery {
    pub observed: Prepared,
    pub restored: AnchoredOutcome,
}

/// Classify a startup name-probe error without reporting source contents.
/// This is diagnostic only; it neither authenticates a peer nor authorizes a
/// restore or retry.
pub(super) fn name_probe_error_label(error: &fss_reference::unifi_direct::pipeline::NameProbeError) -> &'static str {
    use fss_packet::extended_flv::stream;
    use fss_reference::unifi_direct::{ingress, pipeline};
    match error {
        pipeline::NameProbeError::NotFresh | pipeline::NameProbeError::NotConfigured => "owner_state",
        pipeline::NameProbeError::Ingress(ingress::NameProbeError::Ingress(error)) => match error {
            ingress::Error::CancelledOrUnauthorized => "cancelled_or_unauthorized",
            ingress::Error::Source(_) => "source",
            ingress::Error::Framing(_) => "framing",
            ingress::Error::OffsetOverflow => "offset_overflow",
        },
        pipeline::NameProbeError::Ingress(ingress::NameProbeError::Inspect(error)) => match error {
            stream::NameProbeError::Configuration => "configuration",
            stream::NameProbeError::WorkLimit => "work_limit",
            stream::NameProbeError::Provisional => "provisional",
            stream::NameProbeError::Allocation => "allocation",
            stream::NameProbeError::Framing(stream::Error::TrailerPolicyMismatch) => "trailer_policy",
            stream::NameProbeError::Framing(_) => "framing",
            stream::NameProbeError::Metadata(_) => "metadata",
        },
    }
}

/// Only media-originated refusals are eligible; cancellation, authority,
/// transport and owner-state failures do not trigger an automatic write.
pub fn eligible_media_error(error: &fss_reference::unifi_direct::pipeline::Error) -> bool {
    use fss_reference::unifi_direct::{ingress, pipeline};
    matches!(error, pipeline::Error::Recording(_) | pipeline::Error::Ingress(ingress::Error::Framing(_)))
}

/// A timed-out accept is eligible only after a complete forward write and a
/// matching readback. Authority, admission and other listener failures are not.
pub fn eligible_start_failure(failure: &fss_reference::unifi_direct::http_stream::media::Failure, may_have_written: bool, has_readback: bool) -> bool {
    use fss_reference::unifi_direct::{http_stream::media, listener};
    may_have_written && has_readback && matches!(failure, media::Failure::Accept(listener::Error::Deadline))
}

#[cfg(test)]
mod tests {
    use super::{eligible_media_error, eligible_start_failure, name_probe_error_label, response_receipt, start_response_receipt};
    use fss_reference::unifi_direct::{ingress, listener, pipeline, recording, http_stream::media};
    use fss_packet::extended_flv::stream;

    #[test]
    fn response_receipts_bind_preparation_and_redacted_shape() {
        use fss_core::ContentDigest;
        use fss_reference::unifi_direct::camera_api::HandoffResponseObservation as Shape;
        let first = ContentDigest::sha256(b"first preparation");
        let second = ContentDigest::sha256(b"second preparation");
        let objects = [
            Shape::Empty, Shape::Other,
            Shape::Object { success: None, status_code: None },
            Shape::Object { success: Some(false), status_code: None },
            Shape::Object { success: Some(true), status_code: None },
            Shape::Object { success: Some(true), status_code: Some(-1) },
            Shape::Object { success: Some(true), status_code: Some(0) },
        ];
        let mut unique = std::collections::BTreeSet::new();
        for shape in objects {
            let digest = response_receipt(first, shape);
            assert!(unique.insert(digest.to_text()));
            assert_ne!(digest, response_receipt(second, shape));
            assert_ne!(digest, start_response_receipt(first, shape));
            assert_eq!(digest, response_receipt(first, shape));
        }
    }

    #[test]
    fn media_failure_recovery_does_not_treat_cancellation_or_authority_as_media() {
        let cases = [
            (pipeline::Error::Cancelled, false),
            (pipeline::Error::Stopped, false),
            (pipeline::Error::AudioPending, false),
            (pipeline::Error::Ingress(ingress::Error::CancelledOrUnauthorized), false),
            (pipeline::Error::Ingress(ingress::Error::OffsetOverflow), false),
            (pipeline::Error::Ingress(ingress::Error::Framing(stream::Error::TrailerPolicyMismatch)), true),
            (pipeline::Error::Recording(recording::Refusal { reason: recording::Error::Timeline, unaccepted: None }), true),
        ];
        for (error, expected) in cases {
            assert_eq!(eligible_media_error(&error), expected);
        }
    }

    #[test]
    fn name_probe_classification_keeps_distinct_refusals_payload_free() {
        use fss_reference::unifi_direct::ingress::NameProbeError as SourceError;
        use fss_reference::unifi_direct::pipeline::NameProbeError as OwnerError;
        let classify = |error| name_probe_error_label(&OwnerError::Ingress(error));
        assert_eq!(classify(SourceError::Ingress(ingress::Error::CancelledOrUnauthorized)), "cancelled_or_unauthorized");
        assert_eq!(classify(SourceError::Inspect(stream::NameProbeError::WorkLimit)), "work_limit");
        assert_eq!(classify(SourceError::Inspect(stream::NameProbeError::Provisional)), "provisional");
        assert_eq!(classify(SourceError::Inspect(stream::NameProbeError::Framing(stream::Error::TrailerPolicyMismatch))), "trailer_policy");
        assert_eq!(classify(SourceError::Inspect(stream::NameProbeError::Framing(stream::Error::StreamIdMismatch))), "framing");
        assert_eq!(classify(SourceError::Inspect(stream::NameProbeError::Metadata(fss_packet::extended_flv::metadata::Error::InvalidUtf8))), "metadata");
        assert_eq!(name_probe_error_label(&OwnerError::NotConfigured), "owner_state");
    }

    #[test]
    fn startup_recovery_requires_a_timed_out_accept_and_retained_readback() {
        let deadline = media::Failure::Accept(listener::Error::Deadline);
        assert!(eligible_start_failure(&deadline, true, true));
        assert!(!eligible_start_failure(&deadline, false, true));
        assert!(!eligible_start_failure(&deadline, true, false));
        for reason in [listener::Error::Authority, listener::Error::Denied, listener::Error::Busy, listener::Error::Source] {
            assert!(!eligible_start_failure(&media::Failure::Accept(reason), true, true));
        }
        assert!(!eligible_start_failure(&media::Failure::IndeterminateWrite, true, true));
        assert!(!eligible_start_failure(&media::Failure::Preflight, true, true));
    }
}

/// After a drained media failure or matching-readback accept timeout, anchor a fresh matching forward observation,
/// then independently revalidate, restore once and anchor the final readback.
/// A matching observation is not proof that the forward effect caused it.
pub async fn after_observed_failure<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    checkpoint: &Prepared,
    conditions: Preconditions,
    authority: &dyn SerializerAuthority,
    leases: &RefCell<LeaseRegistry>,
    effects: &mut EffectCoordinator,
    run_id: &TrialRunId,
    resource: &str,
    observation: &ObservationCheckpoint<'_>,
    authorize: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<FailureRecovery, Box<dyn Error>> {
    task.checkpoint_for(RuntimeGrant::ObserveStatus, resource, clock.now()?, &BudgetVector::ZERO)?;
    let (_, readback) = http.settings_serializers(Duration::from_secs(10)).await?;
    let comparison = checkpoint.plan.observe_readback(&checkpoint.baseline, &readback, &authorize)?;
    if comparison.change != fss_reference::unifi_direct::http_stream::ReadbackChange::TargetTrackOnly
        || !comparison.requested_fields_match {
        return Err(stopped("failure restore forward observation changed", readback));
    }
    let candidate = (|| {
        let current = Preconditions { serializers: readback.binding(&authorize).ok()?, ..conditions };
        let candidate = Plan::new(observation.peer, observation.start, current, &readback, handoff::Framing::ContentLength).ok()?;
        (candidate.request_digest() == checkpoint.plan.request_digest()).then_some(candidate)
    })();
    let candidate = match candidate {
        Some(value) => value,
        None => return Err(stopped("failure restore observation scope refused", readback)),
    };
    let observed = trial_http_checkpoint::prepare(task, cx, clock, observation.root.join("observation"), candidate, readback, observation.certificate)
        .await.map_err(|_| "failure restore observation checkpoint requires inspection")?;
    let outcome = match run(cx, task, clock, http, checkpoint, conditions, authority, leases, effects, run_id, resource, &authorize).await {
        Ok(value) => value,
        Err(error) => return Err(stopped("failure restore requires reconciliation", (observed, error))),
    };
    let restored = match anchor(cx, task, clock, checkpoint, conditions, observation, outcome, &authorize).await {
        Ok(value) => value,
        Err(error) => return Err(stopped("failure restore final checkpoint requires inspection", (observed, error))),
    };
    Ok(FailureRecovery { observed, restored })
}

/// Revalidate the full live serializer state and dispatch one separately
/// committed restoration. Any write or response failure retains the permit;
/// no response or readback is treated as independent effect settlement.
pub async fn run<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    checkpoint: &Prepared,
    conditions: Preconditions,
    authority: &dyn SerializerAuthority,
    leases: &RefCell<LeaseRegistry>,
    effects: &mut EffectCoordinator,
    run_id: &TrialRunId,
    resource: &str,
    authorize: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<Outcome, Box<dyn Error>> {
    task.checkpoint_for(RuntimeGrant::ObserveStatus, resource, clock.now()?, &BudgetVector::ZERO)?;
    let (_, before) = http.settings_serializers(Duration::from_secs(10)).await?;
    let current = Preconditions { serializers: before.binding(&authorize)?, ..conditions };
    let plan = checkpoint.plan.prepare_restore(
        &checkpoint.baseline, &before, current, handoff::Framing::ContentLength, &authorize,
    )?;
    let operation = run_id.operation("http-restore")?;
    let prepared = task.prepare_effect(cx, effects, &mut leases.borrow_mut(), PrepareSpec {
        operation: &operation,
        idempotency_key: IdempotencyKey::parse(operation.as_str())?,
        request_digest: plan.request_digest(),
        precondition_digest: plan.precondition_digest(),
        resource,
        fence: current.lease_fence,
        prepare_grant: RuntimeGrant::CameraSettingPrepare,
        commit_grant: RuntimeGrant::CameraSettingCommit,
        terminal_predicate: "independent restore observation or reconciliation",
    }, clock.now()?)?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(), current_precondition_digest: plan.precondition_digest(),
    };
    let permit = task.commit_effect(cx, effects, &mut leases.borrow_mut(), prepared, clock.now()?, approval)
        .map_err(|_| "HTTP restore commit refused; inspect journal")?;
    let mut permit = match http.dispatch_serializer(&plan, current, &before, None, permit, authority, Duration::from_secs(10)).await {
        Ok(HandoffWrite::Written { permit }) => permit,
        Ok(HandoffWrite::Indeterminate { permit }) => return Err(stopped("HTTP restore write indeterminate", (plan, before, permit))),
        Err(refusal) => return Err(stopped("HTTP restore dispatch refused", (plan, before, refusal))),
    };
    let response = match http.read_serializer_response_observed(&permit, Duration::from_secs(10)).await {
        Ok(response) => response,
        Err(error) => return Err(stopped("HTTP restore response unavailable", (plan, before, permit, error))),
    };
    let admitted = (|| {
        cx.checkpoint().map_err(|_| "restore response custody cancelled")?;
        let now = clock.now().map_err(|_| "restore response custody clock unavailable")?;
        let mut cost = BudgetVector::ZERO;
        cost.storage_operations = 1;
        task.checkpoint_for(RuntimeGrant::ObjectStage, resource, now, &cost)
            .map_err(|_| "restore response custody authority refused")?;
        Ok::<_, &'static str>(now)
    })();
    let now = match admitted {
        Ok(now) => now,
        Err(reason) => return Err(stopped(reason, (plan, before, permit, response))),
    };
    let receipt = response_receipt(permit.prepared().digest(), response);
    if let Err(error) = effects.adapter_accepted(&mut permit, Some(receipt), now) {
        return Err(stopped("HTTP restore response journal requires reconciliation", (plan, before, permit, response, error)));
    }
    println!("trial_http_restore_response=journaled response=peer_claim effect=unsettled");
    let after = match http.settings_serializers(Duration::from_secs(10)).await {
        Ok((_, value)) => value,
        Err(error) => return Err(stopped("HTTP restore readback unavailable", (plan, before, permit, error))),
    };
    let consistent = (|| {
        let original = checkpoint.baseline.binding(&authorize).ok()?;
        let final_binding = after.binding(&authorize).ok()?;
        let comparison = plan.observe_readback(&before, &after, &authorize).ok()?;
        Some(original == final_binding && comparison.requested_fields_match)
    })();
    if consistent != Some(true) {
        return Err(stopped("HTTP restore readback did not match baseline", (plan, before, permit, after)));
    }
    Ok(Outcome { plan, permit, before, after })
}

/// Retain the same-session post-restore readback in a separate encrypted
/// checkpoint. This is an observation claim, not effect settlement.
pub async fn anchor<'scope, 'task>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    checkpoint: &Prepared,
    conditions: Preconditions,
    observation: &ObservationCheckpoint<'_>,
    outcome: Outcome,
    authorize: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<AnchoredOutcome, Box<dyn Error>> {
    let Outcome { plan, permit, before, after } = outcome;
    let candidate = (|| {
        let current = Preconditions { serializers: after.binding(&authorize).ok()?, ..conditions };
        let candidate = Plan::new(observation.peer, observation.start, current, &after, handoff::Framing::ContentLength).ok()?;
        (candidate.request_digest() == checkpoint.plan.request_digest()).then_some(candidate)
    })();
    let candidate = match candidate {
        Some(value) => value,
        None => return Err(stopped("HTTP restored observation scope refused", (plan, permit, before, after))),
    };
    let restored = match trial_http_checkpoint::prepare(task, cx, clock, observation.root.join("restored"), candidate, after, observation.certificate).await {
        Ok(value) => value,
        Err(error) => return Err(stopped("HTTP restored observation checkpoint requires inspection", (plan, permit, before, error))),
    };
    Ok(AnchoredOutcome { plan, permit, before, after: restored })
}
