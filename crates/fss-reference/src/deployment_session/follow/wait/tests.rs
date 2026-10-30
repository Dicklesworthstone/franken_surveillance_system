#![forbid(unsafe_code)]
//! Virtual clocks exercise real durable journals, source custody and adjacent replay. Source
//! bytes and effect intents are explicit synthetic fixtures, never physical observations.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    BatchId, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContextAuthority,
    EffectIntent, EvidenceDelta, IdempotencyKey, MeaningfulDeltaClass, ObjectId, ObligationId,
    OperationId, Plane, RootAuthoritySpec, SensorCapsule, SensorId, SensorSourceBytesSpec,
    StreamId,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::*;
use crate::agent_follow::replay::{ReplayBinding, ReplayBoundary};
use crate::agent_follow::wait::{MAX_FOLLOW_WAIT_READS, MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES};
use crate::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::agent_session::workspace::{WorkspaceWrite, WorkspaceWriteMode};
use crate::deployment_session::{OpenSessionRequest, OpenedSession, open_session};
use crate::ingest::source_coverage::{
    SourceCoverageInput, build_source_coverage, retain_source_coverage,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:durable-follow-wait";
const NOW: TimestampNs = TimestampNs(5_000);

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
    opened: OpenedSession,
    source_path: PathBuf,
    children: Vec<ContentDigest>,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-durable-follow-wait-{tag}-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:durable-follow-wait:{tag}"),
            operation_id: OperationId::parse(format!("operation:durable-follow-wait:{tag}"))?,
            principal: "operator:durable-follow-wait-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"durable-follow-wait-fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            root.with_extension("cx"),
        )?);
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        // Retain an explicit metadata-only import before the observed interval. Its stable
        // provenance prevents an empty import inventory from restating a moving ledger root.
        let imported = deployment.stage_payload(b"synthetic metadata-only earlier import")?;
        deployment.append_batch(
            BatchId::parse("batch:durable-wait:prior-import")?,
            vec![EvidenceDelta {
                delta_id: "delta:durable-wait:prior-import".to_owned(),
                family: "file_import_manifest".to_owned(),
                object_id: ObjectId::parse("object:durable-wait:prior-import")?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(-2), TimestampNs(-1))?,
                plane: Plane::Authority,
                payload_digest: imported,
                witness_digest: None,
                operation_id: None,
            }],
            vec![imported],
            &cx,
        )?;
        let source = b"explicit synthetic covered source for durable follow wait";
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse("capsule:durable-follow-wait")?,
            sensor_id: SensorId::parse("sensor:durable-follow-wait")?,
            stream_id: StreamId::parse("stream:durable-follow-wait")?,
            sequence: 0,
            capture: interval()?,
            receive_time: NOW,
            clock_basis: ClockBasis::DeviceMonotonic,
            source,
            frame_count: 1,
            gap_before: false,
        })?;
        let source_digest = deployment.stage_payload(source)?;
        let source_path = deployment.publisher().spool().object_path(source_digest);
        let capsule_digest = deployment.stage_payload(&capsule.canonical_bytes())?;
        let coverage = build_source_coverage(&SourceCoverageInput {
            basis: deployment.current_anchor().clone(),
            interval: interval()?,
            negative_predicate: "no_unknown_person_present",
            authorized_domain: BTreeSet::from(["durable-wait-domain".to_owned()]),
            sources: vec![("durable-wait-domain".to_owned(), &capsule)],
        })?;
        retain_source_coverage(&mut deployment, &coverage, coverage.approval_digest(), &cx)?;
        let mut children = vec![
            source_digest,
            capsule_digest,
            coverage.digest(),
            coverage.witness_object(),
        ];
        children.sort_unstable();
        children.dedup();
        deployment.publish_and_commit(
            &SlotName::parse("quiet")?,
            &ObjectManifest::new("durable-wait-quiet", children.clone(), None)?,
            interval()?,
            &cx,
        )?;
        drop(deployment);
        let opened = open_session(
            &root,
            &OpenSessionRequest {
                mission: "Observe every retained deployment transition".to_owned(),
                objective: "Preserve source custody and exact explicit acknowledgements".to_owned(),
                principal: PrincipalId::parse("principal:durable-follow-wait")?,
                view: AgentView::Brief,
                token_budget: 100_000,
            },
        )?;
        Ok(Self {
            root,
            cx,
            opened,
            source_path,
            children,
        })
    }

    fn request(&self) -> TestResult<FollowSessionRequest> {
        Ok(FollowSessionRequest {
            session_id: self.opened.session.session_id.clone(),
            subscription_id: "retained-watch".to_owned(),
            since: AnchorToken::parse(&self.opened.orientation.anchor_token)
                .ok_or("opening anchor")?,
            view: AgentView::Brief,
            max_entries: 64,
            acknowledge: None,
        })
    }

    fn binding(
        &self,
        request: &FollowSessionRequest,
        wait_ms: u64,
        reads: u32,
    ) -> TestResult<FollowSessionWaitBinding> {
        Ok(FollowSessionWaitBinding::new(
            &self.root,
            self.opened.session.principal_id.clone(),
            request.clone(),
            OrientLimits::default(),
            wait_ms,
            reads,
        )?)
    }

    fn immediate(&self, request: &FollowSessionRequest) -> TestResult<FollowSessionDelivery> {
        let binding = self.binding(request, 1, MAX_FOLLOW_WAIT_READS)?;
        Ok(follow_session(
            &self.root,
            &self.opened.session.principal_id,
            request,
            &OrientLimits::default(),
            &mut Control::new(&binding),
        )?)
    }

    fn inspect(&self) -> TestResult<SessionRecoveryState> {
        Ok(inspect_session_bytes(
            &fs::read(self.root.join("agent/sessions/journal.fssj"))?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?)
    }

    fn harmless(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        deployment.publish_and_commit(
            &SlotName::parse("quiet-second")?,
            &ObjectManifest::new("durable-wait-quiet", self.children.clone(), None)?,
            interval()?,
            &self.cx,
        )?;
        Ok(())
    }

    fn material(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let digest = deployment.stage_payload(b"explicit new unanalysed virtual evidence")?;
        deployment.append_batch(
            BatchId::parse("batch:durable-wait:new-evidence")?,
            vec![EvidenceDelta {
                delta_id: "delta:durable-wait:new-evidence".to_owned(),
                family: "sensor_capsule".to_owned(),
                object_id: ObjectId::parse("object:durable-wait:new-evidence")?,
                prior_generation: None,
                new_generation: 1,
                validity: interval()?,
                plane: Plane::Authority,
                payload_digest: digest,
                witness_digest: None,
                operation_id: None,
            }],
            vec![digest],
            &self.cx,
        )?;
        Ok(())
    }

    fn effect(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        deployment.effects_mut().prepare(
            EffectIntent {
                operation_id: OperationId::parse("operation:durable-wait:prepared-fixture")?,
                idempotency_key: IdempotencyKey::parse(
                    "idempotency:durable-wait:prepared-fixture",
                )?,
                effect_class: "fixture.observe".to_owned(),
                request_digest: ContentDigest::sha256(b"explicit unexecuted fixture intent"),
                precondition_digest: ContentDigest::sha256(b"fixture precondition"),
            },
            ObligationId::parse("obligation:durable-wait:prepared-fixture")?,
            "fixture terminal proof is still required",
            NOW,
        )?;
        Ok(())
    }

    fn mutate_workspace(&self) -> TestResult {
        let mut journal = SessionJournal::open(&self.root)?;
        let mut capsule = self.opened.revision.capsule().clone();
        capsule.revision += 1;
        capsule
            .unknowns
            .push("New unresolved mission obligation".to_owned());
        journal.store.publish_workspace(
            &self.opened.session.principal_id,
            WorkspaceWrite {
                expected_head: Some(self.opened.revision.digest()),
                capsule,
                mode: WorkspaceWriteMode::Advance,
            },
            NOW,
        )?;
        journal.commit_pin()?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(self.root.with_extension("cx"));
    }
}

fn interval() -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(TimestampNs::ZERO, NOW)?)
}

struct Control<'a> {
    binding: FollowSessionWaitBinding,
    now: u64,
    parks: Vec<u64>,
    lock_attempts: u32,
    cancel_after_park: bool,
    short_park: bool,
    action: Option<Box<dyn FnMut() -> TestResult + 'a>>,
    action_error: Option<String>,
}

impl<'a> Control<'a> {
    fn new(binding: &FollowSessionWaitBinding) -> Self {
        Self {
            binding: binding.clone(),
            now: 0,
            parks: Vec::new(),
            lock_attempts: 0,
            cancel_after_park: false,
            short_park: false,
            action: None,
            action_error: None,
        }
    }
}

impl ReplayControl for Control<'_> {
    fn admit(&mut self, binding: &ReplayBinding, _: ReplayBoundary) -> Result<(), ReplayDenial> {
        if !binding
            .objects_root()
            .starts_with(self.binding.read_scope().root())
            || &binding.request().principal != self.binding.read_scope().principal()
            || binding.request().view != self.binding.request().view
            || binding.request().max_entries != self.binding.request().max_entries
            || binding
                .session()
                .is_none_or(|session| session.session_id != self.binding.request().session_id)
        {
            return Err(ReplayDenial::Unauthorized);
        }
        Ok(())
    }
}

impl FollowSessionControl for Control<'_> {
    fn admit_session(
        &mut self,
        binding: &FollowSessionBinding<'_>,
        boundary: FollowSessionBoundary,
    ) -> Result<(), ReplayDenial> {
        if binding.root() != self.binding.read_scope().root()
            || binding.principal() != self.binding.read_scope().principal()
            || binding.request() != self.binding.request()
            || *binding.limits() != self.binding.read_scope().read_limits()
        {
            return Err(ReplayDenial::Unauthorized);
        }
        if boundary == FollowSessionBoundary::OpenJournal {
            self.lock_attempts += 1;
        }
        Ok(())
    }
}

impl FollowWaitControl for Control<'_> {
    fn checkpoint(
        &mut self,
        binding: &FollowWaitBinding,
        _: FollowWaitBoundary,
    ) -> Result<u64, FollowWaitDenial> {
        if binding != self.binding.read_scope() {
            return Err(FollowWaitDenial::Unauthorized);
        }
        if self.cancel_after_park && !self.parks.is_empty() {
            return Err(FollowWaitDenial::Cancelled);
        }
        Ok(self.now)
    }

    fn park(&mut self, binding: &FollowWaitBinding, delay_ms: u64) -> Result<(), FollowWaitDenial> {
        if binding != self.binding.read_scope()
            || delay_ms == 0
            || delay_ms > FOLLOW_WAIT_POLL_MS
            || self.now + delay_ms > binding.wait_ms()
        {
            return Err(FollowWaitDenial::Unauthorized);
        }
        self.parks.push(delay_ms);
        self.now += delay_ms - u64::from(self.short_park);
        if let Some(mut action) = self.action.take()
            && let Err(error) = action()
        {
            self.action_error = Some(error.to_string());
            return Err(FollowWaitDenial::ClockUnavailable);
        }
        Ok(())
    }
}

#[test]
fn quiet_timeout_drops_the_writer_and_retains_no_undelivered_page() -> TestResult {
    let fixture = Fixture::new("quiet-timeout")?;
    let request = fixture.request()?;
    let binding = fixture.binding(&request, 500, MAX_FOLLOW_WAIT_READS)?;
    let immutable = ["ledger/journal.fssj", "effects/journal.fssj"]
        .iter()
        .map(|path| fs::read(fixture.root.join(path)))
        .collect::<Result<Vec<_>, _>>()?;
    let source = fs::read(&fixture.source_path)?;
    let mut control = Control::new(&binding);
    control.action = Some(Box::new(|| {
        // This takes the real exclusive owner. A writer held across the park fails here.
        let mut journal = SessionJournal::open(&fixture.root)?;
        let retained = journal
            .store
            .follow_subscription(
                &fixture.opened.session.principal_id,
                &request.session_id,
                &request.subscription_id,
                NOW,
            )?
            .ok_or("registered quiet subscription")?;
        assert!(retained.pending().is_none());
        assert_eq!(retained.acknowledged_anchor(), request.since.as_str());
        Ok(())
    }));
    let failure = follow_session_wait(&binding, &mut control)
        .err()
        .ok_or("timeout")?;
    assert!(matches!(
        failure.failure.error,
        FollowSessionError::Denied(ReplayDenial::Deadline)
    ));
    assert!(failure.failure.journal_may_have_changed);
    assert!(failure.failure.acknowledged.is_none());
    assert!(bounded::certified_quiet(
        failure.last_follow.as_ref().ok_or("quiet comparison")?
    ));
    assert_eq!(failure.progress.completed_comparisons, 2);
    assert_eq!(failure.progress.admitted_reads, 4);
    assert_eq!(failure.progress.completed_parks, 2);
    assert_eq!(failure.progress.elapsed_ms, 500);
    assert_eq!(control.parks, [250, 250]);
    assert_eq!(control.lock_attempts, 2);
    assert!(control.action_error.is_none(), "{:?}", control.action_error);
    let retained = fixture.inspect()?;
    assert_eq!(retained.follows.len(), 1);
    assert!(retained.follows[0].pending().is_none());
    assert_eq!(retained.follows[0].last_acknowledged(), None);
    for (path, expected) in ["ledger/journal.fssj", "effects/journal.fssj"]
        .iter()
        .zip(immutable)
    {
        assert_eq!(fs::read(fixture.root.join(path))?, expected);
    }
    assert_eq!(fs::read(&fixture.source_path)?, source);
    Ok(())
}

#[test]
fn existing_quiet_delivery_is_replayed_without_waiting_or_changing_its_receipt() -> TestResult {
    let fixture = Fixture::new("pending-retry")?;
    let request = fixture.request()?;
    let pending = fixture.immediate(&request)?;
    assert!(bounded::certified_quiet(&pending.follow));
    let before = fixture.inspect()?;
    let binding = fixture.binding(&request, 10_000, MAX_FOLLOW_WAIT_READS)?;
    let mut control = Control::new(&binding);
    let result = follow_session_wait(&binding, &mut control)?;
    assert!(result.delivery.replayed);
    assert_eq!(result.delivery.delivery_receipt, pending.delivery_receipt);
    assert_eq!(result.delivery.follow, pending.follow);
    assert_eq!(result.delivery.journal_root, pending.journal_root);
    assert_eq!(fixture.inspect()?, before);
    assert!(control.parks.is_empty());
    assert_eq!(result.progress.completed_comparisons, 1);
    assert_eq!(result.progress.source_read_attempts, 0);
    Ok(())
}

#[test]
fn acknowledgement_survives_cancelled_wait_and_cold_retry_without_advancing_a_successor()
-> TestResult {
    let fixture = Fixture::new("ack-cancel-restart")?;
    let mut request = fixture.request()?;
    let pending = fixture.immediate(&request)?;
    request.acknowledge = Some(pending.delivery_receipt);
    let binding = fixture.binding(&request, 500, MAX_FOLLOW_WAIT_READS)?;
    let mut control = Control::new(&binding);
    control.cancel_after_park = true;
    let failure = follow_session_wait(&binding, &mut control)
        .err()
        .ok_or("cancelled")?;
    assert!(matches!(
        failure.failure.error,
        FollowSessionError::Denied(ReplayDenial::Cancelled)
    ));
    assert_eq!(failure.failure.acknowledged, Some(pending.delivery_receipt));
    assert_eq!(
        failure.progress.completed_comparisons, 2,
        "ACK reconstruction is charged too"
    );
    let acknowledged = fixture.inspect()?;
    assert!(acknowledged.follows[0].pending().is_none());
    assert_eq!(
        acknowledged.follows[0].last_acknowledged(),
        Some(pending.delivery_receipt)
    );
    let retry = fixture.binding(&request, 1, MAX_FOLLOW_WAIT_READS)?;
    let failure = follow_session_wait(&retry, &mut Control::new(&retry))
        .err()
        .ok_or("timeout")?;
    assert!(matches!(
        failure.failure.error,
        FollowSessionError::Denied(ReplayDenial::Deadline)
    ));
    assert_eq!(failure.failure.acknowledged, Some(pending.delivery_receipt));
    assert_eq!(failure.progress.completed_comparisons, 1);
    assert_eq!(
        fixture.inspect()?,
        acknowledged,
        "retry neither republishes nor refills session state"
    );
    fixture.material()?;
    let delivered = follow_session_wait(&binding, &mut Control::new(&binding))?;
    assert_eq!(
        delivered.delivery.acknowledged,
        Some(pending.delivery_receipt)
    );
    assert_eq!(delivered.delivery.since_anchor, pending.result_anchor);
    assert_ne!(
        delivered.delivery.delivery_receipt,
        pending.delivery_receipt
    );
    assert_eq!(delivered.progress.completed_parks, 0);
    Ok(())
}

#[test]
fn wake_delivers_every_adjacent_transition_including_a_harmless_first_advance() -> TestResult {
    let fixture = Fixture::new("adjacent-wake")?;
    let mut request = fixture.request()?;
    let binding = fixture.binding(&request, 1_000, MAX_FOLLOW_WAIT_READS)?;
    let mut control = Control::new(&binding);
    control.action = Some(Box::new(|| {
        fixture.harmless()?;
        fixture.material()
    }));
    let first = follow_session_wait(&binding, &mut control)?;
    assert!(control.action_error.is_none(), "{:?}", control.action_error);
    assert_eq!(first.progress.completed_parks, 1);
    assert_eq!(first.delivery.since_anchor, request.since);
    assert_eq!(
        first.delivery.result_anchor.position().commit_sequence,
        request.since.position().commit_sequence + 1
    );
    assert_eq!(
        first.delivery.horizon_anchor.position().commit_sequence,
        request.since.position().commit_sequence + 2
    );
    assert!(
        bounded::certified_quiet(&first.delivery.follow),
        "even a harmless real advance must be delivered"
    );
    assert!(!first.delivery.horizon_reached);
    request.acknowledge = Some(first.delivery.delivery_receipt);
    let next_binding = fixture.binding(&request, 1_000, MAX_FOLLOW_WAIT_READS)?;
    let second = follow_session_wait(&next_binding, &mut Control::new(&next_binding))?;
    assert_eq!(second.delivery.since_anchor, first.delivery.result_anchor);
    assert_eq!(second.delivery.result_anchor, first.delivery.horizon_anchor);
    assert_eq!(second.progress.completed_parks, 0);
    assert!(!bounded::certified_quiet(&second.delivery.follow));
    assert_eq!(
        fixture.inspect()?.follows[0]
            .pending()
            .ok_or("second pending")?
            .receipt(),
        second.delivery.delivery_receipt
    );
    Ok(())
}

#[test]
fn effect_wake_preserves_uncertainty_and_mixed_journals_refuse_unproved_order() -> TestResult {
    for mixed in [false, true] {
        let fixture = Fixture::new(if mixed { "mixed-wake" } else { "effect-wake" })?;
        let request = fixture.request()?;
        let binding = fixture.binding(&request, 1_000, MAX_FOLLOW_WAIT_READS)?;
        let mut control = Control::new(&binding);
        control.action = Some(Box::new(|| {
            fixture.effect()?;
            if mixed {
                fixture.material()?;
            }
            Ok(())
        }));
        let result = follow_session_wait(&binding, &mut control);
        assert!(control.action_error.is_none(), "{:?}", control.action_error);
        if mixed {
            let failure = result.err().ok_or("ambiguous journal order")?;
            assert!(matches!(
                failure.failure.error,
                FollowSessionError::Replay(ReplayError::AmbiguousOrder)
            ));
            assert!(fixture.inspect()?.follows[0].pending().is_none());
            assert_eq!(
                fixture.inspect()?.follows[0].acknowledged_anchor(),
                request.since.as_str()
            );
        } else {
            let delivered = result?;
            assert_eq!(
                delivered.delivery.result_anchor.position().commit_sequence,
                request.since.position().commit_sequence
            );
            assert_ne!(delivered.delivery.result_anchor, request.since);
            assert!(
                delivered
                    .delivery
                    .follow
                    .delta
                    .classes
                    .contains(&MeaningfulDeltaClass::EffectUncertainty)
            );
            assert!(
                delivered
                    .delivery
                    .follow
                    .delta
                    .silence_certificate
                    .is_none()
            );
        }
        assert_eq!(control.parks, [250]);
    }
    Ok(())
}

#[test]
fn parked_semantic_change_or_closed_session_cannot_issue_another_page() -> TestResult {
    for close in [false, true] {
        let fixture = Fixture::new(if close {
            "closed-while-parked"
        } else {
            "semantics-while-parked"
        })?;
        let request = fixture.request()?;
        let binding = fixture.binding(&request, 1_000, MAX_FOLLOW_WAIT_READS)?;
        let mut control = Control::new(&binding);
        control.action = Some(Box::new(|| {
            if close {
                let mut journal = SessionJournal::open(&fixture.root)?;
                journal.store.close(
                    &fixture.opened.session.principal_id,
                    &request.session_id,
                    NOW,
                )?;
                journal.commit_pin()?;
                Ok(())
            } else {
                fixture.mutate_workspace()
            }
        }));
        let failure = follow_session_wait(&binding, &mut control)
            .err()
            .ok_or("changed live scope")?;
        assert!(control.action_error.is_none(), "{:?}", control.action_error);
        if close {
            assert!(matches!(
                failure.failure.error,
                FollowSessionError::Session(_)
            ));
        } else {
            assert!(matches!(
                failure.failure.error,
                FollowSessionError::ChangedDelivery
            ));
        }
        assert_eq!(control.parks, [250]);
        assert_eq!(failure.progress.completed_comparisons, 1);
        assert!(failure.failure.acknowledged.is_none());
        assert!(fixture.inspect()?.follows[0].pending().is_none());
    }
    Ok(())
}

#[test]
fn whole_wait_source_budget_does_not_refill_after_a_quiet_poll() -> TestResult {
    let fixture = Fixture::new("cumulative-custody")?;
    let request = fixture.request()?;
    let baseline = fixture.binding(&request, 1, MAX_FOLLOW_WAIT_READS)?;
    let first = follow_session_wait(&baseline, &mut Control::new(&baseline))
        .err()
        .ok_or("timeout")?;
    assert!(matches!(
        first.failure.error,
        FollowSessionError::Denied(ReplayDenial::Deadline)
    ));
    let attempts = first.progress.source_read_attempts;
    assert!(attempts > 0);
    assert_eq!(first.progress.completed_comparisons, 1);
    let binding = fixture
        .binding(&request, 1_000, MAX_FOLLOW_WAIT_READS)?
        .with_source_limits(attempts, MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES)?;
    let mut control = Control::new(&binding);
    let failed = follow_session_wait(&binding, &mut control)
        .err()
        .ok_or("cumulative source cap")?;
    assert!(matches!(
        failed.failure.error,
        FollowSessionError::Denied(ReplayDenial::Budget)
    ));
    assert_eq!(failed.progress.completed_comparisons, 2);
    assert_eq!(failed.progress.source_read_attempts, attempts);
    assert_eq!(
        failed.progress.source_reserved_bytes,
        first.progress.source_reserved_bytes
    );
    assert_eq!(
        failed.progress.source_payload_bytes,
        first.progress.source_payload_bytes
    );
    assert!(failed.progress.consumed.bytes > first.progress.consumed.bytes);
    assert_eq!(control.parks, [250]);
    assert!(fixture.inspect()?.follows[0].pending().is_none());
    Ok(())
}

#[test]
fn deleted_source_and_early_returning_clock_refuse_before_a_second_park() -> TestResult {
    for short in [false, true] {
        let fixture = Fixture::new(if short {
            "short-clock"
        } else {
            "deleted-source"
        })?;
        let request = fixture.request()?;
        let binding = fixture.binding(&request, 1_000, MAX_FOLLOW_WAIT_READS)?;
        let mut control = Control::new(&binding);
        control.short_park = short;
        if !short {
            control.action = Some(Box::new(|| {
                fs::remove_file(&fixture.source_path)?;
                Ok(())
            }));
        }
        let failure = follow_session_wait(&binding, &mut control)
            .err()
            .ok_or("unsafe quiet retry")?;
        assert!(control.action_error.is_none(), "{:?}", control.action_error);
        if short {
            assert!(matches!(
                failure.failure.error,
                FollowSessionError::Denied(ReplayDenial::Unavailable)
            ));
            assert_eq!(failure.progress.completed_comparisons, 1);
        } else {
            assert!(matches!(
                failure.failure.error,
                FollowSessionError::Replay(_)
            ));
            assert!(failure.progress.source_read_attempts > 0);
        }
        assert_eq!(control.parks, [250]);
        assert!(fixture.inspect()?.follows[0].pending().is_none());
    }
    Ok(())
}

#[test]
fn history_ceiling_also_bounds_revalidation_and_writer_acquisitions() -> TestResult {
    let fixture = Fixture::new("history-limit")?;
    let request = fixture.request()?;
    let binding = fixture.binding(&request, 1_000, 2)?;
    let mut control = Control::new(&binding);
    let failure = follow_session_wait(&binding, &mut control)
        .err()
        .ok_or("read admission cap")?;
    assert!(matches!(
        failure.failure.error,
        FollowSessionError::Denied(ReplayDenial::Budget)
    ));
    assert_eq!(failure.progress.admitted_reads, 2);
    assert_eq!(failure.progress.completed_comparisons, 1);
    assert_eq!(control.lock_attempts, 1);
    assert!(
        control.parks.is_empty(),
        "an exhausted call does not sleep before refusing"
    );
    assert!(fixture.inspect()?.follows[0].pending().is_none());
    Ok(())
}
