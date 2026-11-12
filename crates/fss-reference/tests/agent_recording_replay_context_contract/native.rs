#![forbid(unsafe_code)]

#[path = "authority.rs"]
mod authority;
#[path = "deletion.rs"]
mod deletion;
#[allow(dead_code)]
#[path = "../recording_replay_contract/utc/fixtures.rs"]
mod fixtures;

use super::*;
use fixtures::*;
use fss_core::{
    BudgetVector, CaptureInterval, ContextAuthority, DecisionPath, EventHypothesis, EventId,
    EventKind, EventState, KnowledgeState, OperationId, PrincipalId, ProbabilityInterval,
    RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::SpoolIo;
use fss_reference::agent_recording_context::replay::{
    DeploymentRecordingReplayQuery, RecordingReplayContextError as E, RecordingReplayContextLimits,
    RecordingReplayContextRequest, ReplaySourceReadPermit, query_recordings_replay_in_deployment,
};
use fss_reference::rtsp::recording_replay::time::query_replay_time;
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx,
};
use read_io::ReadOnlyIo;
use std::sync::atomic::AtomicBool;

const SITE: &str = "site:recording-replay-context";
const PRINCIPAL: &str = "principal:recording-replay-context";

struct Fixture {
    native: Sealed,
    deployment: PathBuf,
    request: RecordingReplayContextRequest,
}

impl Fixture {
    fn new(label: &str) -> Result<Self, Error> {
        Self::from_native(seal_avc(label, &stamped_avc()?, 1, 7)?)
    }

    fn from_native(native: Sealed) -> Result<Self, Error> {
        let mut replay = native.query();
        replay.limits.max_results = 32;
        let fixture = Self {
            native,
            deployment: path("deployment"),
            request: RecordingReplayContextRequest {
                replay,
                principal: PrincipalId::parse(PRINCIPAL)?,
                expected_anchor: None,
            },
        };
        drop(ReferenceDeployment::open(
            &fixture.deployment,
            SITE,
            &fixture.cx()?,
        )?);
        Ok(fixture)
    }

    fn cx(&self) -> Result<ReplayCx, Error> {
        // Setup authority is independently held by the fixture owner; it is never passed
        // to the query, which receives only its separately constructed read permit.
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:recording-replay-context-setup".to_owned(),
            operation_id: OperationId::parse("operation:recording-replay-context-setup")?,
            principal: PRINCIPAL.to_owned(),
            capabilities: [
                ADP_REPLAY_ROW_ID,
                "CAP-READ-MEDIA-001",
                "CAP-OBJECT-STAGE-001",
                "CAP-OBJECT-PUBLISH-001",
                "CAP-RETENTION-COMMIT-001",
                "CAP-DELETE-PREPARE-001",
                "CAP-DELETE-COMMIT-001",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder().bytes(512 * 1024 * 1024).build()?,
            privacy_scope: "privacy:fixture".to_owned(),
            retention_scope: "retention:fixture".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority(
            &authority,
            self.deployment.clone(),
        )?)
    }

    fn authority(&self, limits: &RecordingReplayContextLimits) -> Result<ContextAuthority, Error> {
        Ok(ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:recording-replay-read".to_owned(),
            operation_id: OperationId::parse("operation:recording-replay-read")?,
            principal: self.request.principal.as_str().to_owned(),
            capabilities: vec![
                RuntimeGrant::AgentQuery.as_str().to_owned(),
                RuntimeGrant::ReadMedia.as_str().to_owned(),
            ],
            deadline: None,
            priority: 10,
            budgets: limits.allowance()?,
            privacy_scope: "privacy:source-verification".to_owned(),
            retention_scope: "retention:no-new-retention".to_owned(),
            anchor_universe: self.request.replay.scope.recording.anchor,
            generation: self.request.replay.scope.recording.generation,
        })?)
    }

    fn query(
        &self,
        io: &dyn SpoolIo,
        limits: &RecordingReplayContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingReplayQuery, Error> {
        let authority = self.authority(limits)?;
        let now = || TimestampNs(0);
        let permit =
            ReplaySourceReadPermit::authorize(&authority, &self.request, limits.replay, &now)?;
        Ok(query_recordings_replay_in_deployment(
            io,
            &self.deployment,
            &self.native.root,
            &self.request,
            limits,
            Some(&permit),
            cancelled,
        )?)
    }

    fn publish_hypothesis(&self, id: &str) -> TestResult {
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse(id)?,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: None,
            zone_ids: vec!["door".to_owned()],
            track_ids: Vec::new(),
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: Vec::new(),
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"fixture-policy"),
                fingerprint: ContentDigest::sha256(id.as_bytes()),
                abstained: true,
                abstention_reason: Some("synthetic unadjudicated fixture".to_owned()),
            },
        };
        event.verify()?;
        let cx = self.cx()?;
        ReferenceDeployment::open(&self.deployment, SITE, &cx)?.publish_event(
            &ReferencePolicyDecision {
                event,
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(())
    }
}

fn stamped_avc() -> Result<recording_support::Fixture, Error> {
    rebuild_avc(fixture(941, true)?, |index, wire| {
        if index == 0 {
            stamp(wire, NTP_SECONDS, 0x8000_0000, 0x80, 7)?;
        }
        Ok(())
    })
}

#[test]
fn exact_native_report_and_read_accounting_survive_both_held_writer_locks() -> TestResult {
    let f = Fixture::new("context-parity")?;
    let publisher = f.native.open()?;
    let expected = query_replay_time(&publisher, &f.request.replay, &NeverCancel)?;
    let cx = f.cx()?;
    let _deployment = ReferenceDeployment::open(&f.deployment, SITE, &cx)?;
    let io = ReadOnlyIo::default();
    let result = f.query(&io, &RecordingReplayContextLimits::default(), &|| false)?;
    assert_eq!(
        format!("{:?}", result.native.report),
        format!("{expected:?}")
    );
    assert_eq!(result.native.report.matches.len(), 1);
    assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    assert_eq!(
        io.calls.load(Ordering::SeqCst),
        result.native.metadata_usage.io_calls + result.native.original_usage.io_calls
    );
    assert_eq!(
        io.read_bytes.load(Ordering::SeqCst),
        result.native.metadata_usage.read_bytes + result.native.original_usage.read_bytes
    );
    assert!(result.deployment_bytes_read > 0);
    assert!(result.deployment_metadata_reads > 0);
    let epistemic = result.epistemic();
    assert_eq!(epistemic.propositions.len(), 4);
    assert!(
        epistemic.propositions[0]
            .statement
            .contains("Native source bytes were internally read")
    );
    assert_eq!(result.coverage().omitted_count, 0);
    Ok(())
}

#[test]
fn unknown_native_samples_and_source_only_tails_remain_separate() -> TestResult {
    let mut packets = stamped_hevc()?;
    packets[0].bytes[24] |= 1;
    packets[5].bytes[24] |= 1;
    let f = Fixture::from_native(seal_hevc(
        "context-hevc-unknown",
        &packets[..8],
        &hevc_recording_support::timings(2),
        7,
    )?)?;
    let publisher = f.native.open()?;
    let expected = query_replay_time(&publisher, &f.request.replay, &NeverCancel)?;
    let result = f.query(
        &ReadOnlyIo::default(),
        &RecordingReplayContextLimits::default(),
        &|| false,
    )?;
    assert_eq!(
        format!("{:?}", result.native.report),
        format!("{expected:?}")
    );
    assert!(!result.native.report.unknown.is_empty());
    assert_eq!(result.native.report.source_only.len(), 1);
    let epistemic = result.epistemic();
    assert_eq!(
        epistemic.propositions.len(),
        3 + result.native.report.matches.len()
            + result.native.report.unknown.len()
            + result.native.report.source_only.len()
    );
    assert!(
        epistemic
            .propositions
            .iter()
            .any(|p| p.id.contains(":unknown:")
                && p.state == KnowledgeState::NotObservable
                && p.statement.contains("malformed_replay_extension"))
    );
    assert!(
        epistemic
            .propositions
            .iter()
            .any(|p| p.id.contains(":source-only:")
                && p.statement.contains("not a media sample")
                && p.statement.contains("malformed_replay_extension"))
    );
    assert!(
        !epistemic
            .propositions
            .iter()
            .any(|p| p.statement.contains("No source-media bytes were read"))
    );
    Ok(())
}

#[test]
fn empty_receipt_claims_no_original_source_reads_or_physical_absence() -> TestResult {
    let f = Fixture::from_native(seal_avc("context-empty-receipt", &stamped_avc()?, 0, 7)?)?;
    let publisher = f.native.open()?;
    let expected = query_replay_time(&publisher, &f.request.replay, &NeverCancel)?;
    let io = ReadOnlyIo::default();
    let result = f.query(&io, &RecordingReplayContextLimits::default(), &|| false)?;
    assert_eq!(
        format!("{:?}", result.native.report),
        format!("{expected:?}")
    );
    assert_eq!(result.native.report.scanned_windows, 0);
    assert_eq!(result.native.report.source_bytes, 0);
    assert_eq!(result.native.original_usage.read_bytes, 0);
    let epistemic = result.epistemic();
    assert_eq!(epistemic.propositions.len(), 3);
    assert!(
        epistemic.propositions[0]
            .statement
            .contains("no original source bytes were read")
    );
    assert!(
        !epistemic.propositions[0]
            .statement
            .contains("Native source bytes were internally read")
    );
    assert!(
        epistemic.propositions[2]
            .statement
            .contains("physical absence are unknown")
    );
    assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn current_deployment_change_during_original_reads_discards_complete_native_result() -> TestResult {
    let f = Fixture::new("context-racing-deployment")?;
    let publisher = f.native.open()?;
    let source = publisher
        .spool()
        .object_path(f.native.receipt.windows()[0].original_leaf_digests()[0]);
    let io = ReadOnlyIo::default();
    let changed = AtomicBool::new(false);
    let mutation_failed = AtomicBool::new(false);
    let cancelled = || {
        if io.opened_count(&source) > 0 && !changed.swap(true, Ordering::SeqCst) {
            mutation_failed.store(
                f.publish_hypothesis("event:recorder-query-racing-head")
                    .is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let error = f
        .query(&io, &RecordingReplayContextLimits::default(), &cancelled)
        .err()
        .ok_or("changed deployment must refuse")?;
    assert!(matches!(error.downcast_ref::<E>(), Some(E::AnchorChanged)));
    assert!(changed.load(Ordering::SeqCst));
    assert!(!mutation_failed.load(Ordering::SeqCst));
    assert_eq!(io.forbidden.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.query(
            &ReadOnlyIo::default(),
            &RecordingReplayContextLimits::default(),
            &|| false
        )?
        .snapshot
        .events
        .len(),
        1
    );
    Ok(())
}
