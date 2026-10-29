#![forbid(unsafe_code)]
//! Real deployment/session boundaries with synthetic retained journal content only.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContextAuthority, EvidenceDelta, EventId,
    ObjectId, OperationId, Plane, RootAuthoritySpec, SessionId,
};

use super::*;
use crate::agent_session::SessionRefresh;
use crate::deployment_session::{OpenSessionRequest, open_session};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
const SITE: &str = "site:supervision-inventory-boundary";
const PRIVATE_CONFIG: &[u8] = b"private native inventory configuration";
const PRIVATE_REPORT: &[u8] = b"private native inventory presentation";
const PRIVATE_EVENT: &str = "event:package:private-native-inventory-source";

// Supervision admits 32 MiB journals; the general orientation default allows 64 MiB.
fn inventory_limits() -> OrientLimits {
    OrientLimits {
        max_journal_bytes: 32 * 1024 * 1024,
        ..OrientLimits::default()
    }
}

struct Fixture {
    root: PathBuf,
    scratch: PathBuf,
    cx: ReplayCx,
    session: AgentSession,
    head: SupervisionSessionHead,
    state: SupervisionSubscription,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fss-native-inventory-boundary-{}-{serial}", std::process::id(),
        ));
        let scratch = root.with_extension("cx");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:inventory-boundary".to_owned(),
            operation_id: OperationId::parse("operation:inventory-boundary")?,
            principal: "operator:inventory-boundary".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None, priority: 10, budgets: BudgetVector::ZERO,
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"explicit inventory boundary fixture"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority, &scratch)?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        let opened = open_session(&root, &OpenSessionRequest {
            mission: "Recover retained bounded supervision".to_owned(),
            objective: "Discover unacknowledged work after context loss".to_owned(),
            principal: PrincipalId::parse("principal:inventory-boundary")?,
            view: AgentView::Brief, token_budget: 100_000,
        })?;
        let history = DeploymentHistory::read(&root, &inventory_limits())?;
        let head = observe_head(&history)?;
        let mut journal = SessionJournal::open(&root)?;
        let session = journal.store.session(&opened.session.principal_id,
            &opened.session.session_id, head.observed_at)?;
        let registration = SupervisionRegistration {
            session_id: session.session_id.clone(), subscription_id: "retained-patrol".to_owned(),
            configuration: PRIVATE_CONFIG.to_vec(),
            configuration_digest: ContentDigest::sha256(PRIVATE_CONFIG),
            max_read_bytes: 4096, max_read_attempts: 4, maximum_attempts: 2,
            max_report_bytes: 4096,
        };
        let state = journal.store.configure_supervision_schedule(
            &session.principal_id, &registration, 2, head.observed_at,
        )?;
        let state = journal.store.reserve_supervision(
            &session.principal_id, &state, &head.anchor, head.observed_at,
        )?;
        let reservation = state.reservation().ok_or("charged synthetic work")?.clone();
        let state = journal.store.publish_supervision(&session.principal_id, &state, &reservation,
            PRIVATE_REPORT.to_vec(), vec![SupervisionSourcePin {
                event_id: EventId::parse(PRIVATE_EVENT)?,
                event_root: ContentDigest::sha256(b"synthetic native source root"),
                source_verified: true,
                health_digest: None,
            }], ContentDigest::sha256(b"synthetic native report receipt"), head.observed_at)?;
        // Retain an interrupted revalidation at the exhausted lifetime cap. Listing must still
        // recover its metadata without opening any native source or attempting a new poll.
        let state = journal.store.reserve_supervision(
            &session.principal_id, &state, &head.anchor, head.observed_at,
        )?;
        journal.commit_pin()?;
        drop(journal);
        Ok(Self { root, scratch, cx, session, head, state })
    }

    fn request(&self) -> SupervisionInventoryRequest {
        SupervisionInventoryRequest {
            session_id: self.session.session_id.clone(),
            expected_authority_root: self.head.anchor.state_root,
        }
    }

    fn journal_bytes(&self) -> TestResult<Vec<u8>> {
        Ok(fs::read(self.root.join("agent/sessions/journal.fssj"))?)
    }

    fn advance_authority(&self) -> TestResult {
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(b"new observation during inventory delivery")?;
        deployment.append_batch(BatchId::parse("batch:inventory-boundary:changed")?,
            vec![EvidenceDelta {
                delta_id: "delta:inventory-boundary:changed".to_owned(),
                family: "sensor_capsule".to_owned(),
                object_id: ObjectId::parse("object:inventory-boundary:changed")?,
                prior_generation: None, new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(1_000), TimestampNs(1_500))?,
                plane: Plane::Authority, payload_digest: payload, witness_digest: None,
                operation_id: None,
            }], vec![payload], &self.cx)?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

struct Control<'a> {
    fixture: &'a Fixture,
    deny: Option<(SupervisionInventoryBoundary, usize)>,
    mutate: Option<SupervisionInventoryBoundary>,
    boundaries: Vec<SupervisionInventoryBoundary>,
}

impl<'a> Control<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        Self { fixture, deny: None, mutate: None, boundaries: Vec::new() }
    }
}

impl SupervisionInventoryControl for Control<'_> {
    fn admit_inventory(&mut self, binding: &SupervisionInventoryBinding<'_>,
        boundary: SupervisionInventoryBoundary) -> Result<(), SupervisionAdapterError>
    {
        assert_eq!(binding.root(), self.fixture.root);
        assert_eq!(binding.request().expected_authority_root, self.fixture.head.anchor.state_root);
        assert_eq!(binding.limits(), &inventory_limits());
        self.boundaries.push(boundary);
        let occurrence = self.boundaries.iter().filter(|seen| **seen == boundary).count();
        if self.deny == Some((boundary, occurrence)) {
            return Err(SupervisionAdapterError {
                identity: "fixture:inventory-cancelled", reason: "explicit boundary cancellation".to_owned(),
            });
        }
        if self.mutate == Some(boundary) {
            self.mutate = None;
            self.fixture.advance_authority().map_err(|_| SupervisionAdapterError {
                identity: "fixture:inventory-mutation-failed", reason: "fixture append failed".to_owned(),
            })?;
        }
        Ok(())
    }
}

#[test]
fn list_recovers_complete_metadata_at_exhaustion_without_native_sources_or_acknowledgement() -> TestResult {
    let fixture = Fixture::new()?;
    let before = fixture.journal_bytes()?;
    let request = fixture.request();
    let mut control = Control::new(&fixture);
    let listed = list_supervision(&fixture.root, &fixture.session.principal_id,
        &request, &inventory_limits(), &mut control)?;
    assert_eq!(listed.session, fixture.session);
    assert_eq!(listed.head, fixture.head);
    assert_eq!(listed.subscriptions.len(), 1);
    let metadata = &listed.subscriptions[0];
    assert_eq!(metadata.state_digest, fixture.state.digest());
    assert_eq!(metadata.configuration_digest, ContentDigest::sha256(PRIVATE_CONFIG));
    assert_eq!(metadata.attempts_reserved, metadata.maximum_attempts);
    assert_eq!(metadata.pending.as_ref().ok_or("pending metadata")?.receipt,
        fixture.state.pending().ok_or("retained report")?.receipt());
    assert_eq!(metadata.reservation.as_ref(), fixture.state.reservation());
    assert_eq!(metadata.schedule.as_ref(), fixture.state.schedule());
    assert!(metadata.last_acknowledged.is_none());
    assert!(metadata.last_discarded.is_none());
    for private in [std::str::from_utf8(PRIVATE_CONFIG)?,
        std::str::from_utf8(PRIVATE_REPORT)?, PRIVATE_EVENT] {
        assert!(!format!("{listed:?}").contains(private));
    }
    assert_eq!(control.boundaries, vec![
        SupervisionInventoryBoundary::ReadHistory,
        SupervisionInventoryBoundary::OpenJournal,
        SupervisionInventoryBoundary::ReadInventory,
        SupervisionInventoryBoundary::RevalidateHistory,
        SupervisionInventoryBoundary::Deliver,
        SupervisionInventoryBoundary::RevalidateHistory,
    ]);
    assert_eq!(fixture.journal_bytes()?, before);
    Ok(())
}

#[test]
fn cancellation_at_every_inventory_boundary_withholds_output_and_preserves_work() -> TestResult {
    for denied in [
        (SupervisionInventoryBoundary::ReadHistory, 1),
        (SupervisionInventoryBoundary::OpenJournal, 1),
        (SupervisionInventoryBoundary::ReadInventory, 1),
        (SupervisionInventoryBoundary::RevalidateHistory, 1),
        (SupervisionInventoryBoundary::Deliver, 1),
        (SupervisionInventoryBoundary::RevalidateHistory, 2),
    ] {
        let fixture = Fixture::new()?;
        let before = fixture.journal_bytes()?;
        let mut control = Control::new(&fixture);
        control.deny = Some(denied);
        assert!(matches!(list_supervision(&fixture.root, &fixture.session.principal_id,
            &fixture.request(), &inventory_limits(), &mut control),
            Err(SupervisionSessionError::Denied(error))
                if error.identity == "fixture:inventory-cancelled"));
        assert_eq!(fixture.journal_bytes()?, before);
        let listed = list_supervision(&fixture.root, &fixture.session.principal_id,
            &fixture.request(), &inventory_limits(), &mut Control::new(&fixture))?;
        assert_eq!(listed.subscriptions[0].state_digest, fixture.state.digest());
    }
    Ok(())
}

#[test]
fn authority_changes_during_read_or_final_delivery_withhold_the_inventory() -> TestResult {
    for mutation in [SupervisionInventoryBoundary::RevalidateHistory,
        SupervisionInventoryBoundary::Deliver] {
        let fixture = Fixture::new()?;
        let before = fixture.journal_bytes()?;
        let mut control = Control::new(&fixture);
        control.mutate = Some(mutation);
        assert!(matches!(list_supervision(&fixture.root, &fixture.session.principal_id,
            &fixture.request(), &inventory_limits(), &mut control),
            Err(SupervisionSessionError::ChangedAuthority)));
        assert!(control.mutate.is_none(), "the concrete mutation boundary was reached");
        assert_eq!(fixture.journal_bytes()?, before);
        let changed = observe_head(&DeploymentHistory::read(&fixture.root, &inventory_limits())?)?;
        assert_ne!(changed, fixture.head);
    }
    Ok(())
}

#[test]
fn listing_rejects_foreign_owner_unknown_session_missing_grants_and_wrong_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let before = fixture.journal_bytes()?;
    let wrong_principal = PrincipalId::parse("principal:foreign-inventory-owner")?;
    assert!(matches!(list_supervision(&fixture.root, &wrong_principal,
        &fixture.request(), &inventory_limits(), &mut Control::new(&fixture)),
        Err(SupervisionSessionError::Session(_))));
    let mut unknown = fixture.request();
    unknown.session_id = SessionId::parse("session:missing-inventory-owner")?;
    assert!(matches!(list_supervision(&fixture.root, &fixture.session.principal_id,
        &unknown, &inventory_limits(), &mut Control::new(&fixture)),
        Err(SupervisionSessionError::Session(_))));
    let mut wrong_root = fixture.request();
    wrong_root.expected_authority_root = ContentDigest::sha256(b"wrong current inventory authority");
    // An invalid current root is rejected after the first history read, before the journal.
    struct AdmitOnlyHistory;
    impl SupervisionInventoryControl for AdmitOnlyHistory {
        fn admit_inventory(&mut self, _: &SupervisionInventoryBinding<'_>,
            boundary: SupervisionInventoryBoundary) -> Result<(), SupervisionAdapterError>
        {
            assert_eq!(boundary, SupervisionInventoryBoundary::ReadHistory);
            Ok(())
        }
    }
    assert!(matches!(list_supervision(&fixture.root, &fixture.session.principal_id,
        &wrong_root, &inventory_limits(), &mut AdmitOnlyHistory),
        Err(SupervisionSessionError::ChangedAuthority)));
    assert_eq!(fixture.journal_bytes()?, before);
    let mut journal = SessionJournal::open(&fixture.root)?;
    let mut capabilities = fixture.session.capabilities.clone();
    assert!(capabilities.remove("CAP-AGENT-INVESTIGATE-001"));
    journal.store.refresh(&fixture.session.principal_id, &fixture.session.session_id, SessionRefresh {
        expected_session_digest: fixture.session.session_digest(),
        current_anchor: fixture.session.current_anchor.clone(), capabilities,
        privacy_scope: fixture.session.privacy_scope.clone(),
    }, fixture.head.observed_at)?;
    journal.commit_pin()?;
    drop(journal);
    let before = fixture.journal_bytes()?;
    assert!(matches!(list_supervision(&fixture.root, &fixture.session.principal_id,
        &fixture.request(), &inventory_limits(), &mut Control::new(&fixture)),
        Err(SupervisionSessionError::Store(DurableSupervisionError::StaleScope))));
    assert_eq!(fixture.journal_bytes()?, before);
    Ok(())
}

#[test]
fn inventory_rejects_unadmitted_history_limits_before_any_boundary() -> TestResult {
    let fixture = Fixture::new()?;
    let before = fixture.journal_bytes()?;
    for max_journal_bytes in [
        0,
        32 * 1024 * 1024 + 1,
        OrientLimits::default().max_journal_bytes,
    ] {
        let limits = OrientLimits {
            max_journal_bytes,
            ..inventory_limits()
        };
        let mut control = Control::new(&fixture);
        assert!(matches!(
            list_supervision(
                &fixture.root,
                &fixture.session.principal_id,
                &fixture.request(),
                &limits,
                &mut control,
            ),
            Err(SupervisionSessionError::InvalidRequest)
        ));
        assert!(control.boundaries.is_empty(), "invalid limits reached an I/O boundary");
        assert_eq!(fixture.journal_bytes()?, before);
    }
    Ok(())
}
