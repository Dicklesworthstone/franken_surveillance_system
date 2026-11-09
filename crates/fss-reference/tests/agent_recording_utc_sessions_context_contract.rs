#![forbid(unsafe_code)]
//! Independent session clocks retain current protected context under one shared read budget.

#[path = "recording_clock_contract/support.rs"]
mod clock_support;
mod collector_support;
#[path = "agent_recordings_utc_sessions_contract/support.rs"]
mod fixture;
mod hevc_recording_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fixture::{Fixture as NativeFixture, TestResult};
use fss_core::{
    AgentView, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath,
    EventHypothesis, EventId, EventKind, EventState, KnowledgeState, OperationId, PrincipalId,
    ProbabilityInterval, RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIo, SpoolIoCall};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::{OrientRequest, orient_deployment};
use fss_reference::agent_recording_context::utc_sessions::{
    DeploymentRecordingUtcSessionsQuery, RecordingUtcSessionsContextError as E,
    RecordingUtcSessionsContextLimits, RecordingUtcSessionsContextRequest,
    query_recordings_utc_sessions_in_deployment,
};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx,
};

const SITE: &str = "site:utc-sessions-context";
const PRINCIPAL: &str = "principal:utc-sessions-context";

struct Fixture {
    native: NativeFixture,
    deployment: PathBuf,
    request: RecordingUtcSessionsContextRequest,
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        Self::from_native(NativeFixture::new(
            label,
            &[RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc],
            2,
            1,
            &[0],
        )?)
    }

    fn from_native(native: NativeFixture) -> TestResult<Self> {
        let deployment = native.root.join("deployment");
        let mut recording = native.request.clone();
        recording.max_windows = 32;
        let value = Self {
            native,
            deployment,
            request: RecordingUtcSessionsContextRequest {
                recording,
                principal: PrincipalId::parse(PRINCIPAL)?,
                expected_anchor: None,
            },
        };
        let cx = value.cx()?;
        drop(ReferenceDeployment::open(&value.deployment, SITE, &cx)?);
        Ok(value)
    }

    fn cx(&self) -> TestResult<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:utc-sessions-context".to_owned(),
            operation_id: OperationId::parse("operation:utc-sessions-context")?,
            principal: PRINCIPAL.to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority(
            &authority,
            self.deployment.clone(),
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

    fn query(&self) -> Result<DeploymentRecordingUtcSessionsQuery, E> {
        self.query_with(
            &HostSpoolIo,
            &RecordingUtcSessionsContextLimits::default(),
            &|| false,
        )
    }

    fn query_with(
        &self,
        io: &dyn SpoolIo,
        limits: &RecordingUtcSessionsContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingUtcSessionsQuery, E> {
        query_recordings_utc_sessions_in_deployment(
            io,
            &self.deployment,
            &self.native.root,
            &self.request,
            limits,
            cancelled,
        )
    }
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut found = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            found.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            found.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("special fixture file".into());
        }
    }
    Ok(found)
}

#[test]
fn mixed_sessions_keep_protected_events_independent_clocks_and_unknown_windows() -> TestResult {
    let mut f = Fixture::new("context-provenance")?;
    f.publish_hypothesis("event:protected-utc-sessions")?;
    let envelopes = f
        .native
        .sessions
        .iter()
        .flat_map(|session| session.clock.windows())
        .map(|window| window.utc_interval())
        .collect::<Vec<_>>();
    let first = envelopes
        .iter()
        .map(|interval| interval.earliest_ns)
        .min()
        .ok_or("first envelope")?;
    let last = envelopes
        .iter()
        .map(|interval| interval.latest_ns)
        .max()
        .ok_or("last envelope")?;
    f.request.recording.interval = first..last.checked_add(1).ok_or("envelope end")?;
    let before = tree(&f.native.root)?;
    let result = f.query()?;
    assert_eq!(result.native.sessions.len(), 2);
    assert_eq!(result.native.rows.len(), 4);
    assert_eq!(result.selected_catalog_indexes().len(), 4);
    assert_eq!(result.snapshot.events.len(), 1);
    assert_eq!(
        result.snapshot.events[0].event.event_id.as_str(),
        "event:protected-utc-sessions"
    );
    assert!(!result.snapshot.doctor_inspected);
    for session in &result.native.sessions {
        assert_ne!(
            result.anchor_token,
            session.scope.recording.anchor.to_text()
        );
        assert!(
            result
                .native
                .reference_digests
                .contains(&session.clock_root)
        );
    }
    let orientation = orient_deployment(
        &result.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: f.request.principal.clone(),
            budget_tokens: None,
        },
        &RecordingUtcSessionsContextLimits::default().snapshot,
    )?;
    assert!(
        orientation
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| cell
                .disclosable_statement()
                .contains("event:protected-utc-sessions"))
    );
    let epistemic = result.epistemic(&f.request.recording);
    let physical = epistemic
        .propositions
        .iter()
        .find(|claim| claim.id == "claim:recordings-utc-sessions:physical-observability")
        .ok_or("physical claim")?;
    assert_eq!(physical.state, KnowledgeState::Unknown);
    assert!(physical.statement.contains("clock equivalence"));
    assert_eq!(
        epistemic
            .propositions
            .iter()
            .filter(|claim| claim
                .id
                .starts_with("claim:recordings-utc-sessions:window:")
                && claim.state == KnowledgeState::NotObservable)
            .count(),
        2
    );
    for (index, session) in result.native.sessions.iter().enumerate() {
        let clock = epistemic
            .propositions
            .iter()
            .find(|claim| {
                claim.id == format!("claim:recordings-utc-sessions:session:{index}:clock")
            })
            .ok_or("clock claim")?;
        assert!(
            clock
                .evidence
                .contains(&session.clock_metadata_digest.to_text())
        );
        assert!(clock.statement.contains(&session.clock_root.to_text()));
        assert_eq!(
            epistemic
                .propositions
                .iter()
                .filter(|claim| claim.id.starts_with(&format!(
                    "claim:recordings-utc-sessions:session:{index}:indexed-gap:"
                )))
                .count(),
            session.indexed_gaps.len()
        );
    }
    assert_eq!(
        result.coverage().stop_reason,
        "pinned_sessions_catalogs_and_clocks_exhausted"
    );
    assert_eq!(result.coverage().omitted_count, 0);
    assert_eq!(tree(&f.native.root)?, before);
    Ok(())
}

#[test]
fn input_order_is_canonical_while_principal_changes_only_protected_identity() -> TestResult {
    let mut f = Fixture::new("context-identity")?;
    let first = f.query()?;
    f.request.recording.sessions.reverse();
    for input in &mut f.request.recording.sessions {
        input.catalogs.reverse();
    }
    let reordered = f.query()?;
    assert_eq!(first.request_digest, reordered.request_digest);
    assert_eq!(first.decision_digest, reordered.decision_digest);
    assert_eq!(first.native, reordered.native);
    assert_eq!(
        first.epistemic(&f.request.recording),
        reordered.epistemic(&f.request.recording)
    );
    f.request.principal = PrincipalId::parse("principal:second-utc-sessions-reader")?;
    let second = f.query()?;
    assert_ne!(first.request_digest, second.request_digest);
    assert_ne!(first.decision_digest, second.decision_digest);
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(first.native, second.native);
    assert_eq!(first.anchor_token, second.anchor_token);
    Ok(())
}

#[test]
fn stale_and_racing_deployment_heads_refuse_the_entire_session_union() -> TestResult {
    let mut f = Fixture::new("context-heads")?;
    let initial = f.query()?;
    f.request.expected_anchor = Some(AnchorToken::parse(&initial.anchor_token).ok_or("anchor")?);
    assert_eq!(f.query()?.decision_digest, initial.decision_digest);
    f.publish_hypothesis("event:utc-sessions-new-head")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let limits = RecordingUtcSessionsContextLimits::default();
    let before = tree(&f.native.root)?;
    assert!(matches!(
        f.query_with(&io, &limits, &|| false),
        Err(E::AnchorChanged)
    ));
    assert!(io.calls().is_empty());
    assert_eq!(tree(&f.native.root)?, before);
    f.request.expected_anchor = None;
    let current = f.query()?;
    assert_eq!(current.native, initial.native);
    assert_ne!(current.request_digest, initial.request_digest);
    let changed = AtomicBool::new(false);
    let mutation_failed = AtomicBool::new(false);
    let mutate = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5 && !changed.swap(true, Ordering::SeqCst) {
            if f.publish_hypothesis("event:utc-sessions-racing-head")
                .is_err()
            {
                mutation_failed.store(true, Ordering::SeqCst);
                return true;
            }
        }
        false
    };
    assert!(matches!(
        f.query_with(&io, &limits, &mutate),
        Err(E::AnchorChanged)
    ));
    assert!(changed.load(Ordering::SeqCst));
    assert!(!mutation_failed.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn whole_query_deployment_and_archive_budgets_never_refill_per_session() -> TestResult {
    let f = Fixture::new("context-budgets")?;
    let limits = RecordingUtcSessionsContextLimits::default();
    let baseline = f.query()?;
    let exact = RecordingUtcSessionsContextLimits {
        deployment_bytes: baseline.deployment_bytes_read as usize + 1,
        deployment_reads: baseline.deployment_metadata_reads as usize,
        ..limits
    };
    let admitted = f.query_with(&HostSpoolIo, &exact, &|| false)?;
    assert_eq!(admitted.native, baseline.native);
    assert_ne!(admitted.request_digest, baseline.request_digest);
    assert_eq!(
        admitted.deployment_metadata_reads,
        baseline.deployment_metadata_reads
    );
    let before = tree(&f.native.root)?;
    for (dimension, mut lowered) in [exact; 4].into_iter().enumerate() {
        match dimension {
            0 => lowered.deployment_bytes = baseline.deployment_bytes_read as usize - 1,
            1 => lowered.deployment_reads -= 1,
            2 => lowered.recording.metadata.max_io_calls = baseline.native.read_usage.io_calls - 1,
            _ => lowered.recording.max_scanned_windows = baseline.native.scanned_windows - 1,
        }
        assert!(
            f.query_with(&HostSpoolIo, &lowered, &|| false).is_err(),
            "dimension {dimension}"
        );
    }
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert!(matches!(
        f.query_with(&io, &limits, &|| true),
        Err(E::Cancelled)
    ));
    assert!(io.calls().is_empty());
    let cancelled = || io.call_count(SpoolIoCall::OpenRead) >= 5;
    assert!(f.query_with(&io, &limits, &cancelled).is_err());
    assert!(io.call_count(SpoolIoCall::OpenRead) >= 5);
    assert_eq!(tree(&f.native.root)?, before);
    Ok(())
}

#[test]
fn source_media_and_locked_writers_are_not_opened_or_recovered_by_the_query() -> TestResult {
    let f = Fixture::new("context-no-media")?;
    let before_media = f.query()?;
    let cx = f.cx()?;
    let writer = ReferenceDeployment::open(&f.deployment, SITE, &cx)?;
    let archive_lock = fs::File::create(f.native.root.join("LOCK"))?;
    archive_lock.try_lock()?;
    for leaf in &f.native.leaves {
        assert!(!f.native.object(*leaf).exists());
        fs::write(f.native.object(*leaf), b"corrupt source bytes stay unread")?;
    }
    let before = tree(&f.native.root)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let result = f.query_with(&io, &RecordingUtcSessionsContextLimits::default(), &|| {
        false
    })?;
    assert_eq!(result.native, before_media.native);
    assert_eq!(result.decision_digest, before_media.decision_digest);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(tree(&f.native.root)?, before);
    archive_lock.unlock()?;
    drop(writer);
    Ok(())
}

#[test]
fn invalid_mixed_source_or_oversized_protected_output_refuses_before_archive_reads() -> TestResult {
    let f = Fixture::new("context-invalid")?;
    let limits = RecordingUtcSessionsContextLimits::default();
    for mutation in 0..3 {
        let mut request = f.request.clone();
        match mutation {
            0 => request.recording.max_windows = 33,
            1 => {
                request.recording.sessions[1].scope.recording.sensor =
                    SensorId::parse("another-sensor")?
            }
            _ => request
                .recording
                .sessions
                .push(request.recording.sessions[0].clone()),
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert!(
            query_recordings_utc_sessions_in_deployment(
                &io,
                &f.native.root.join("nonexistent-deployment"),
                &f.native.root,
                &request,
                &limits,
                &|| false
            )
            .is_err()
        );
        assert!(io.calls().is_empty());
        assert!(!f.native.root.join("nonexistent-deployment").exists());
    }
    Ok(())
}

#[test]
fn eight_sessions_sixty_four_catalogs_and_thirty_two_rows_fit_the_protected_plan() -> TestResult {
    let f = Fixture::from_native(NativeFixture::new(
        "context-maximum",
        &[
            RecordingQueryCodec::Avc,
            RecordingQueryCodec::Hevc,
            RecordingQueryCodec::Avc,
            RecordingQueryCodec::Hevc,
            RecordingQueryCodec::Avc,
            RecordingQueryCodec::Hevc,
            RecordingQueryCodec::Avc,
            RecordingQueryCodec::Hevc,
        ],
        8,
        1,
        &[0, 1, 2, 3],
    )?)?;
    let result = f.query()?;
    assert_eq!(result.native.sessions.len(), 8);
    assert_eq!(
        result
            .native
            .sessions
            .iter()
            .map(|session| session.catalogs.len())
            .sum::<usize>(),
        64
    );
    assert_eq!(result.native.scanned_windows, 64);
    assert_eq!(result.native.unique_windows, 64);
    assert_eq!(result.native.rows.len(), 32);
    assert!(
        result
            .native
            .rows
            .iter()
            .all(|row| row.row.utc_interval.is_none())
    );
    assert_eq!(result.selected_catalog_indexes().len(), 32);
    let epistemic = result.epistemic(&f.request.recording);
    assert_eq!(
        epistemic
            .propositions
            .iter()
            .filter(|claim| claim
                .id
                .starts_with("claim:recordings-utc-sessions:window:"))
            .count(),
        32
    );
    assert_eq!(
        epistemic
            .propositions
            .iter()
            .filter(|claim| claim.id.ends_with(":clock"))
            .count(),
        8
    );
    assert!(epistemic.propositions.len() < 4096);
    assert!(
        epistemic
            .propositions
            .iter()
            .all(|claim| claim.statement.len() <= 16_384)
    );
    assert_eq!(result.coverage().omitted_count, 0);
    Ok(())
}
