#![forbid(unsafe_code)]
//! Session handoffs discover durable supervision without replaying its private presentation.
//!
//! The deployment, session journal, reservations and handoff publications are real. Native
//! evaluation is an explicitly synthetic fixture that verifies one local source; these tests
//! establish metadata continuity, not camera acquisition or detector accuracy.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentView, BudgetVector, ContentDigest, ContextAuthority, EventId, LedgerAnchor, OperationId,
    PrincipalId, RootAuthoritySpec,
};
use fss_reference::agent_orient::{DeploymentOrientation, OrientLimits};
use fss_reference::agent_session::checkpoint::journal::supervision::{
    PendingSupervisionDelivery, SupervisionInventoryEntry, SupervisionRegistration,
    SupervisionSourcePin, SupervisionSubscription,
};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::supervision::{
    SupervisionAction, SupervisionAdapterError, SupervisionEvaluation, SupervisionEvaluator,
    SupervisionSessionBinding, SupervisionSessionBoundary, SupervisionSessionControl,
    SupervisionSessionDelivery, SupervisionSessionError, SupervisionSessionFailure,
    SupervisionSessionOutcome, SupervisionSessionRequest, SupervisionValidation, supervise_session,
};
use fss_reference::deployment_session::{
    HandoffRecord, HandoffRequest, OpenSessionRequest, OpenedSession, ResumeRequest, open_session,
    prepare_handoff, resume_session,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
const SITE: &str = "site:supervision-orientation-contract";
const SUBSCRIPTION: &str = "overnight-patrol";
const PRIVATE_CONFIGURATION: &str = "private-native-fixture-configuration";
const PRIVATE_REPORT: &str = "private-native-fixture-report";
const PRIVATE_SOURCE: &[u8] = b"private-native-fixture-source-bytes";
const PRIVATE_EVENT: &str = "event:package:private-native-fixture-source-identity";

struct Fixture {
    root: PathBuf,
    scratch: PathBuf,
    source: PathBuf,
    opened: OpenedSession,
    request: OpenSessionRequest,
    registration: SupervisionRegistration,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fss-supervision-orientation-{tag}-{}-{serial}",
            std::process::id(),
        ));
        fs::create_dir(&root)?;
        let scratch = root.with_extension("cx");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:supervision-orientation:{tag}"),
            operation_id: OperationId::parse(format!("operation:supervision-orientation:{tag}"))?,
            principal: "operator:supervision-orientation-fixture".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit supervision orientation fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority, &scratch,
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        let source = root.join("native-source.fixture");
        fs::write(&source, PRIVATE_SOURCE)?;
        let request = OpenSessionRequest {
            mission: "Keep the retained overnight patrol discoverable across handoffs".to_owned(),
            objective: "Recover pending work without repeating acquisition or losing charges"
                .to_owned(),
            principal: PrincipalId::parse("principal:supervision-orientation")?,
            view: AgentView::Brief,
            token_budget: 100_000,
        };
        let opened = open_session(&root, &request)?;
        let configuration =
            format!("{{\"native_configuration\":\"{PRIVATE_CONFIGURATION}\"}}").into_bytes();
        let registration = SupervisionRegistration {
            session_id: opened.session.session_id.clone(),
            subscription_id: SUBSCRIPTION.to_owned(),
            configuration_digest: ContentDigest::sha256(&configuration),
            configuration,
            max_read_bytes: 4096,
            max_read_attempts: 4,
            maximum_attempts: 16,
            max_report_bytes: 4096,
        };
        Ok(Self {
            root,
            scratch,
            source,
            opened,
            request,
            registration,
        })
    }

    fn handoff_request(&self) -> HandoffRequest {
        HandoffRequest {
            session_id: self.opened.session.session_id.clone(),
            principal: self.opened.session.principal_id.clone(),
            note: Some("Continue the existing bounded patrol".to_owned()),
        }
    }

    fn action(
        &self,
        action: SupervisionAction,
    ) -> Result<SupervisionSessionDelivery, Box<SupervisionSessionFailure>> {
        let request = SupervisionSessionRequest {
            registration: self.registration.clone(),
            expected_authority_root: self.opened.session.current_anchor.state_root,
            action,
        };
        let mut evaluator = SyntheticEvaluator {
            root: &self.root,
            source: &self.source,
            principal: &self.opened.session.principal_id,
            registration: &self.registration,
        };
        supervise_session(
            &self.root,
            &self.opened.session.principal_id,
            &request,
            &OrientLimits::default(),
            &mut evaluator,
        )
    }

    fn retained(&self) -> TestResult<SupervisionSubscription> {
        let recovered = inspect_session_bytes(
            &fs::read(self.root.join("agent/sessions/journal.fssj"))?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        let mut owned = recovered.supervisions.into_iter().filter(|state| {
            state.registration().session_id == self.opened.session.session_id
                && state.registration().subscription_id == SUBSCRIPTION
        });
        let state = owned.next().ok_or("retained subscription")?;
        assert!(owned.next().is_none());
        Ok(state)
    }

    fn authority_and_sources(&self) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
        fn collect(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
            for child in fs::read_dir(path)? {
                let child = child?;
                let path = child.path();
                if path == root.join("agent") {
                    continue;
                }
                if child.file_type()?.is_dir() {
                    collect(root, &path, files)?;
                } else {
                    files.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
                }
            }
            Ok(())
        }
        let mut files = BTreeMap::new();
        collect(&self.root, &self.root, &mut files)?;
        Ok(files)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

/// This test adapter explicitly owns synthetic source checks; orientation has no access to it.
struct SyntheticEvaluator<'a> {
    root: &'a Path,
    source: &'a Path,
    principal: &'a PrincipalId,
    registration: &'a SupervisionRegistration,
}

impl SyntheticEvaluator<'_> {
    fn refused() -> SupervisionAdapterError {
        SupervisionAdapterError {
            identity: "fixture:source-unavailable",
            reason: "synthetic source or authority no longer matches".to_owned(),
        }
    }

    fn verify_source(&self) -> Result<(), SupervisionAdapterError> {
        if fs::read(self.source).map_err(|_| Self::refused())? != PRIVATE_SOURCE {
            return Err(Self::refused());
        }
        Ok(())
    }

    fn sources(&self) -> Result<Vec<SupervisionSourcePin>, SupervisionAdapterError> {
        Ok(vec![SupervisionSourcePin {
            event_id: EventId::parse(PRIVATE_EVENT).map_err(|_| Self::refused())?,
            event_root: ContentDigest::sha256(PRIVATE_SOURCE),
            source_verified: true,
            health_digest: None,
        }])
    }
}

impl SupervisionSessionControl for SyntheticEvaluator<'_> {
    fn admit_session(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        _: SupervisionSessionBoundary,
    ) -> Result<(), SupervisionAdapterError> {
        if binding.root() != self.root
            || binding.principal() != self.principal
            || &binding.request().registration != self.registration
        {
            return Err(Self::refused());
        }
        Ok(())
    }
}

impl SupervisionEvaluator for SyntheticEvaluator<'_> {
    fn evaluate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
    ) -> Result<SupervisionEvaluation, SupervisionAdapterError> {
        self.verify_source()?;
        let window = binding.active_window_count().ok_or_else(Self::refused)?;
        let payload =
            format!("{{\"report\":\"{PRIVATE_REPORT}\",\"window\":{window}}}").into_bytes();
        Ok(SupervisionEvaluation {
            basis: anchor.clone(),
            report_receipt: ContentDigest::sha256(&payload),
            payload,
            sources: self.sources()?,
            detection_sources: Vec::new(),
        })
    }

    fn revalidate(
        &mut self,
        _: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
        pending: &PendingSupervisionDelivery,
    ) -> Result<SupervisionValidation, SupervisionAdapterError> {
        self.verify_source()?;
        if pending.source_inventory() != self.sources()? {
            return Err(Self::refused());
        }
        Ok(SupervisionValidation {
            basis: anchor.clone(),
            receipt: ContentDigest::sha256(b"explicit synthetic source validation"),
            reserved_bytes: PRIVATE_SOURCE.len() as u64,
            read_attempts: 1,
        })
    }
}

fn exact_inventory(entry: &SupervisionInventoryEntry, state: &SupervisionSubscription) {
    let registration = state.registration();
    assert_eq!(entry.subscription_id, registration.subscription_id);
    assert_eq!(entry.state_digest, state.digest());
    assert!(entry.authority_current);
    assert_eq!(
        entry.configuration_digest,
        registration.configuration_digest
    );
    assert_eq!(entry.max_read_bytes, registration.max_read_bytes);
    assert_eq!(entry.max_read_attempts, registration.max_read_attempts);
    assert_eq!(entry.maximum_attempts, registration.maximum_attempts);
    assert_eq!(entry.max_report_bytes, registration.max_report_bytes);
    assert_eq!(entry.attempts_reserved, state.attempts_reserved());
    assert_eq!(entry.reserved_bytes, state.reserved_bytes());
    assert_eq!(entry.reserved_read_attempts, state.reserved_read_attempts());
    assert_eq!(entry.reservation.as_ref(), state.reservation());
    assert_eq!(
        entry.reservation_generations_current,
        state.reservation().map(|_| true)
    );
    assert_eq!(entry.schedule.as_ref(), state.schedule());
    assert_eq!(entry.last_acknowledged, state.last_acknowledged());
    assert_eq!(entry.last_discarded, state.last_discarded());
    assert_eq!(
        entry.pending.is_some(),
        state.pending().is_some(),
        "inventory must preserve the exact pending-report disposition"
    );
    if let (Some(metadata), Some(pending)) = (&entry.pending, state.pending()) {
        assert_eq!(metadata.receipt, pending.receipt());
        assert_eq!(metadata.report_receipt, pending.report_receipt());
        assert_eq!(&metadata.anchor, pending.anchor());
        assert_eq!(metadata.payload_digest, pending.payload_digest());
        assert_eq!(metadata.payload_len, pending.payload_len());
        assert_eq!(metadata.active_window_count, pending.active_window_count());
        assert!(metadata.generations_current);
    }
}

fn no_private_presentation(
    orientation: &DeploymentOrientation,
    handoff: &HandoffRecord,
) -> TestResult {
    // Check every exported orientation field and the canonical handoff, including a Vec<u8>
    // debug representation, so accidentally adding a raw configuration/report also fails.
    let projected = format!("{orientation:?}");
    let handoff_bytes = handoff.to_bytes()?;
    let handoff_text = String::from_utf8_lossy(&handoff_bytes);
    for private in [
        PRIVATE_CONFIGURATION,
        PRIVATE_REPORT,
        PRIVATE_EVENT,
        std::str::from_utf8(PRIVATE_SOURCE)?,
    ] {
        assert!(!projected.contains(private), "orientation leaked {private}");
        assert!(
            !projected.contains(&format!("{:?}", private.as_bytes())),
            "orientation leaked private bytes"
        );
        assert!(!handoff_text.contains(private), "handoff leaked {private}");
    }
    assert!(
        !projected.contains(&ContentDigest::sha256(PRIVATE_SOURCE).to_text()),
        "the source inventory is not a supervision discovery surface"
    );
    Ok(())
}

#[test]
fn pending_report_changes_same_head_handoff_and_is_discoverable_on_resume() -> TestResult {
    let fixture = Fixture::new("pending")?;
    let protected = fixture.authority_and_sources()?;
    let baseline = prepare_handoff(&fixture.root, &fixture.handoff_request())?;
    assert!(baseline.orientation.supervision_inventory_available);
    assert!(baseline.orientation.supervision_inventory.is_empty());
    let baseline = baseline.publish(&[])?;

    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 3 })?;
    let configured = prepare_handoff(&fixture.root, &fixture.handoff_request())?;
    assert_eq!(configured.orientation.supervision_inventory.len(), 1);
    exact_inventory(
        &configured.orientation.supervision_inventory[0],
        &fixture.retained()?,
    );
    assert!(
        configured.orientation.supervision_inventory[0]
            .pending
            .is_none()
    );
    let configured = configured.publish(&[])?;

    let polled = fixture.action(SupervisionAction::Poll)?;
    assert!(matches!(
        polled.outcome,
        SupervisionSessionOutcome::Report {
            replayed: false,
            ..
        }
    ));
    let retained = fixture.retained()?;
    assert_eq!(retained, polled.subscription);
    let journal_before_reopen = fs::read(fixture.root.join("agent/sessions/journal.fssj"))?;
    let reopened = open_session(&fixture.root, &fixture.request)?;
    assert_eq!(
        reopened.session.session_id,
        fixture.opened.session.session_id
    );
    assert_eq!(
        reopened.revision, fixture.opened.revision,
        "an exact open retry does not replace the original workspace"
    );
    assert!(reopened.orientation.supervision_inventory_available);
    assert_eq!(reopened.orientation.supervision_inventory.len(), 1);
    exact_inventory(&reopened.orientation.supervision_inventory[0], &retained);
    assert_eq!(
        fs::read(fixture.root.join("agent/sessions/journal.fssj"))?,
        journal_before_reopen
    );
    let prepared = prepare_handoff(&fixture.root, &fixture.handoff_request())?;
    assert_eq!(prepared.record.anchor_token, configured.record.anchor_token);
    assert_eq!(prepared.workspace, fixture.opened.revision);
    assert_ne!(
        prepared.record.situation_fingerprint, configured.record.situation_fingerprint,
        "a new pending report changes decisions even without an authority commit"
    );
    assert_ne!(
        prepared.record.capsule.handoff_id,
        configured.record.capsule.handoff_id
    );
    assert_eq!(prepared.orientation.supervision_inventory.len(), 1);
    exact_inventory(&prepared.orientation.supervision_inventory[0], &retained);
    no_private_presentation(&prepared.orientation, &prepared.record)?;
    let expected_inventory = prepared.orientation.supervision_inventory.clone();
    let pending = prepared.publish(&[])?;

    // Resume an older handoff with no subscription list from the caller. All state is reopened
    // from disk and the pending work must still be discoverable at the unchanged ledger head.
    let resume_request = ResumeRequest {
        handoff_id: baseline.record.capsule.handoff_id,
        principal: fixture.opened.session.principal_id.clone(),
    };
    let resumed = resume_session(&fixture.root, &resume_request)?;
    assert!(!resumed.anchor_moved);
    assert!(resumed.handoff_situation_changed);
    resumed.delta.validate()?;
    assert!(
        resumed.committed,
        "same-head agent work updates the workspace's situation identity"
    );
    assert_eq!(
        resumed.revision.capsule().revision,
        fixture.opened.revision.capsule().revision + 1
    );
    assert_eq!(
        resumed.revision.parent_digest(),
        Some(fixture.opened.revision.digest())
    );
    assert!(resumed.result.supervision_inventory_available);
    assert_eq!(resumed.result.supervision_inventory, expected_inventory);
    assert_eq!(
        resumed.result.capsule().decision_fingerprint()?,
        pending.record.situation_fingerprint
    );
    assert_eq!(
        resumed.revision.capsule().situation_capsule_digest,
        resumed.result.capsule().decision_fingerprint()?.to_text()
    );
    no_private_presentation(&resumed.result, &resumed.handoff)?;
    assert_eq!(
        fixture.retained()?,
        retained,
        "discovery must not ACK or reserve work"
    );
    let journal_after_resume = fs::read(fixture.root.join("agent/sessions/journal.fssj"))?;
    let again = resume_session(&fixture.root, &resume_request)?;
    assert!(again.handoff_situation_changed);
    again.delta.validate()?;
    assert!(
        !again.committed,
        "replaying the same handoff does not manufacture revisions"
    );
    assert_eq!(again.revision, resumed.revision);
    assert_eq!(again.result.supervision_inventory, expected_inventory);
    assert_eq!(
        fs::read(fixture.root.join("agent/sessions/journal.fssj"))?,
        journal_after_resume
    );
    assert_eq!(fixture.authority_and_sources()?, protected);
    Ok(())
}

#[test]
fn cold_handoff_preserves_schedule_terminal_receipts_and_failed_attempt_charges() -> TestResult {
    let fixture = Fixture::new("continuity")?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 3 })?;
    let first = fixture.action(SupervisionAction::Poll)?;
    let first_receipt = first
        .subscription
        .pending()
        .ok_or("first pending report")?
        .receipt();
    fixture.action(SupervisionAction::Acknowledge(first_receipt))?;
    fixture.action(SupervisionAction::Advance {
        target_count: 2,
        after_receipt: first_receipt,
    })?;
    let second = fixture.action(SupervisionAction::Poll)?;
    let second_receipt = second
        .subscription
        .pending()
        .ok_or("second pending report")?
        .receipt();
    assert_ne!(first_receipt, second_receipt);

    // Native custody can fail after a report was retained. Discovery must preserve that report
    // as historical metadata while an actual release still requires a fresh source check.
    fs::write(
        &fixture.source,
        b"synthetic source changed after the historical report",
    )?;
    let refused = fixture
        .action(SupervisionAction::Poll)
        .err()
        .ok_or("changed source must refuse")?;
    assert!(matches!(
        refused.error,
        SupervisionSessionError::Evaluation(_)
    ));
    assert_eq!(refused.attempts_reserved, 4);
    let retained = fixture.retained()?;
    assert_eq!(retained.attempts_reserved(), 4);
    assert_eq!(
        retained.reserved_bytes(),
        4 * fixture.registration.max_read_bytes
    );
    assert_eq!(
        retained.reserved_read_attempts(),
        4 * fixture.registration.max_read_attempts
    );
    assert!(
        retained.reservation().is_some(),
        "failed validation stays charged and unfinished"
    );
    assert_eq!(retained.last_acknowledged(), Some(first_receipt));
    assert_eq!(retained.last_discarded(), None);
    assert_eq!(
        retained
            .pending()
            .ok_or("historical pending report")?
            .receipt(),
        second_receipt
    );
    let schedule = retained.schedule().ok_or("configured schedule")?;
    assert_eq!(schedule.total_windows(), 3);
    assert_eq!(schedule.active_window_count(), 2);
    assert_eq!(
        schedule
            .last_advance()
            .ok_or("explicit advance")?
            .after_receipt(),
        first_receipt
    );
    let protected = fixture.authority_and_sources()?;

    let prepared = prepare_handoff(&fixture.root, &fixture.handoff_request())?;
    assert_eq!(prepared.orientation.supervision_inventory.len(), 1);
    exact_inventory(&prepared.orientation.supervision_inventory[0], &retained);
    no_private_presentation(&prepared.orientation, &prepared.record)?;
    let expected_inventory = prepared.orientation.supervision_inventory.clone();
    let handoff = prepared.publish(&[])?;
    let resumed = resume_session(
        &fixture.root,
        &ResumeRequest {
            handoff_id: handoff.record.capsule.handoff_id,
            principal: fixture.opened.session.principal_id.clone(),
        },
    )?;
    assert!(!resumed.anchor_moved);
    assert!(
        !resumed.handoff_situation_changed,
        "a freshly sealed handoff already names the current supervision state"
    );
    assert!(
        resumed.committed,
        "the older workspace still advances to the situation sealed by that handoff"
    );
    assert_eq!(
        resumed.revision.capsule().situation_capsule_digest,
        resumed.result.capsule().decision_fingerprint()?.to_text()
    );
    assert_eq!(resumed.result.supervision_inventory, expected_inventory);
    assert_eq!(
        resumed.session.token_budget,
        fixture.opened.session.token_budget
    );
    assert_eq!(fixture.retained()?, retained);
    no_private_presentation(&resumed.result, &resumed.handoff)?;
    assert_eq!(
        fixture.authority_and_sources()?,
        protected,
        "handoff and resume only observe source and effect authority"
    );

    // Discovery did not turn historical metadata into permission to release the payload.
    let refused = fixture
        .action(SupervisionAction::Poll)
        .err()
        .ok_or("discovery grants no release")?;
    assert!(matches!(
        refused.error,
        SupervisionSessionError::Evaluation(_)
    ));
    assert_eq!(refused.attempts_reserved, 5);
    let failed_again = fixture.retained()?;
    assert_eq!(failed_again.attempts_reserved(), 5);
    assert_eq!(failed_again.pending(), retained.pending());
    assert_eq!(
        failed_again.last_acknowledged(),
        retained.last_acknowledged()
    );
    assert_eq!(failed_again.schedule(), retained.schedule());
    assert_eq!(fixture.authority_and_sources()?, protected);
    Ok(())
}

#[test]
fn discarding_pending_work_updates_protected_context_without_rewriting_history() -> TestResult {
    let fixture = Fixture::new("discarded-unknown")?;
    let protected = fixture.authority_and_sources()?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 3 })?;
    let polled = fixture.action(SupervisionAction::Poll)?;
    let receipt = polled
        .subscription
        .pending()
        .ok_or("pending report")?
        .receipt();
    let receipt_text = receipt.to_text();
    let has_pending_risk = |risks: &[String]| {
        risks
            .iter()
            .any(|line| line.contains("pending") && line.contains(&receipt_text))
    };
    let has_volatile_unknown = |unknowns: &[String]| {
        unknowns.iter().any(|line| {
            line.starts_with("Retained supervision pending report: ")
                || line.contains(&receipt_text)
        })
    };

    let pending_handoff =
        prepare_handoff(&fixture.root, &fixture.handoff_request())?.publish(&[])?;
    let pending_resume = resume_session(
        &fixture.root,
        &ResumeRequest {
            handoff_id: pending_handoff.record.capsule.handoff_id,
            principal: fixture.opened.session.principal_id.clone(),
        },
    )?;
    assert!(pending_resume.committed);
    assert!(has_pending_risk(
        &pending_resume.result.capsule().frame.at_risk
    ));
    assert!(!has_volatile_unknown(
        &pending_resume.result.capsule().frame.unknown
    ));
    let pending_workspace = pending_resume.revision;
    assert!(!has_volatile_unknown(&pending_workspace.capsule().unknowns));
    assert!(pending_workspace.capsule().unknowns.iter().any(
        |line| line == "Current validity of retained supervision report sources is unverified."
    ));
    let charged = fixture.retained()?;

    let discarded = fixture.action(SupervisionAction::Discard(receipt))?;
    assert!(
        matches!(discarded.outcome, SupervisionSessionOutcome::Discarded(value) if value == receipt)
    );
    assert!(discarded.subscription.pending().is_none());
    assert_eq!(discarded.subscription.last_discarded(), Some(receipt));
    assert_eq!(discarded.subscription.last_acknowledged(), None);
    assert_eq!(
        discarded.subscription.attempts_reserved(),
        charged.attempts_reserved()
    );
    assert_eq!(
        discarded.subscription.reserved_bytes(),
        charged.reserved_bytes()
    );
    assert_eq!(
        discarded.subscription.reserved_read_attempts(),
        charged.reserved_read_attempts()
    );

    let prepared = prepare_handoff(&fixture.root, &fixture.handoff_request())?;
    assert_eq!(
        prepared.workspace, pending_workspace,
        "sealing the new situation does not rewrite the handed-off workspace"
    );
    assert!(!has_pending_risk(
        &prepared.orientation.capsule().frame.at_risk
    ));
    assert!(!has_volatile_unknown(
        &prepared.orientation.capsule().frame.unknown
    ));
    assert!(!has_volatile_unknown(&prepared.record.unknowns));
    let handoff = prepared.publish(&[])?;
    let request = ResumeRequest {
        handoff_id: handoff.record.capsule.handoff_id,
        principal: fixture.opened.session.principal_id.clone(),
    };
    let resumed = resume_session(&fixture.root, &request)?;
    assert!(!resumed.anchor_moved);
    assert!(resumed.committed);
    assert_eq!(
        resumed.revision.parent_digest(),
        Some(pending_workspace.digest())
    );
    assert_eq!(
        resumed.handed_off, pending_workspace,
        "the pending workspace remains immutable in the recovered journal history"
    );
    assert!(!has_pending_risk(&resumed.result.capsule().frame.at_risk));
    assert!(!has_volatile_unknown(
        &resumed.result.capsule().frame.unknown
    ));
    assert!(
        !has_volatile_unknown(&resumed.revision.capsule().unknowns),
        "volatile receipt and charge facts never accumulate as persistent uncertainty"
    );
    assert_eq!(
        resumed.revision.capsule().unknowns,
        pending_workspace.capsule().unknowns,
        "source uncertainty remains stable when the pending delivery is explicitly discarded"
    );
    assert_eq!(
        fixture.retained()?,
        discarded.subscription,
        "workspace reconciliation neither refunds nor spends native work allowance"
    );
    let mut distinct_unknowns = resumed.revision.capsule().unknowns.clone();
    distinct_unknowns.sort();
    distinct_unknowns.dedup();
    assert_eq!(
        distinct_unknowns.len(),
        resumed.revision.capsule().unknowns.len()
    );

    let journal = fs::read(fixture.root.join("agent/sessions/journal.fssj"))?;
    let again = resume_session(&fixture.root, &request)?;
    assert!(!again.committed);
    assert_eq!(again.revision, resumed.revision);
    assert_eq!(
        again.revision.capsule().unknowns,
        resumed.revision.capsule().unknowns
    );
    assert_eq!(again.handed_off, pending_workspace);
    assert_eq!(
        fs::read(fixture.root.join("agent/sessions/journal.fssj"))?,
        journal
    );
    assert_eq!(fixture.retained()?, discarded.subscription);
    assert_eq!(fixture.authority_and_sources()?, protected);
    Ok(())
}

#[test]
fn same_mission_other_session_does_not_discover_the_owners_subscription() -> TestResult {
    let fixture = Fixture::new("isolation")?;
    fixture.action(SupervisionAction::ConfigureSchedule { total_windows: 3 })?;
    fixture.action(SupervisionAction::Poll)?;
    let retained = fixture.retained()?;
    let owner_before = prepare_handoff(&fixture.root, &fixture.handoff_request())?.publish(&[])?;
    let journal_before = fs::read(fixture.root.join("agent/sessions/journal.fssj"))?;
    let mut other_request = fixture.request.clone();
    other_request.token_budget += 1;
    let other = open_session(&fixture.root, &other_request)?;
    assert_eq!(other.session.mission_id, fixture.opened.session.mission_id);
    assert_eq!(
        other.session.principal_id,
        fixture.opened.session.principal_id
    );
    assert_ne!(other.session.session_id, fixture.opened.session.session_id);
    assert!(other.orientation.supervision_inventory_available);
    assert!(other.orientation.supervision_inventory.is_empty());
    assert_ne!(
        fs::read(fixture.root.join("agent/sessions/journal.fssj"))?,
        journal_before,
        "opening another session changes the enclosing journal"
    );
    let owner_after = prepare_handoff(&fixture.root, &fixture.handoff_request())?;
    assert_eq!(
        owner_after.record.situation_fingerprint, owner_before.record.situation_fingerprint,
        "unrelated journal appends do not change this owner's situation"
    );
    assert_eq!(
        owner_after.record.capsule.handoff_id,
        owner_before.record.capsule.handoff_id
    );
    drop(owner_after);
    let protected = fixture.authority_and_sources()?;

    let prepared = prepare_handoff(
        &fixture.root,
        &HandoffRequest {
            session_id: other.session.session_id,
            principal: other.session.principal_id.clone(),
            note: None,
        },
    )?;
    assert!(prepared.orientation.supervision_inventory.is_empty());
    assert!(!format!("{:?}", prepared.orientation).contains(SUBSCRIPTION));
    let handoff = prepared.publish(&[])?;
    let resumed = resume_session(
        &fixture.root,
        &ResumeRequest {
            handoff_id: handoff.record.capsule.handoff_id,
            principal: other.session.principal_id,
        },
    )?;
    assert!(resumed.result.supervision_inventory.is_empty());
    assert_eq!(fixture.retained()?, retained);
    assert_eq!(fixture.authority_and_sources()?, protected);
    Ok(())
}
