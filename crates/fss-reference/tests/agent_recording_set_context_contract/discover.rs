#![forbid(unsafe_code)]
//! Archive namespace discovery composed with current deployment authority and protected context.

use super::*;
use fss_reference::agent_recording_context::discover::{
    DeploymentRecordingDiscoveryQuery, RecordingDiscoveryContextLimits,
    RecordingDiscoveryContextRequest, discover_recordings_in_deployment,
};
use fss_reference::agent_recordings::discover::{
    RecordingDiscoveryError, RecordingDiscoveryLimits, RecordingDiscoveryRequest,
    discover_recordings,
};
use fss_reference::rtsp::recording_archive::{AvcArchiveCodec, CodecArchiveNamespace};

struct DiscoveryFixture {
    base: Fixture,
    request: RecordingDiscoveryContextRequest,
    namespace: CodecArchiveNamespace<AvcArchiveCodec>,
}
impl DiscoveryFixture {
    fn new(label: &str) -> TestResult<Self> {
        let base = Fixture::new(&format!("discovery-{label}"))?;
        let scope = base.request.recording.scope.clone();
        let namespace = CodecArchiveNamespace::<AvcArchiveCodec>::new(scope.clone())?;
        let recordings = [window(1, 3600)?, window(3, 10800)?, window(5, 18000)?];
        let slots = [
            namespace.window_slot(0)?,
            namespace.window_slot(1)?,
            namespace.window_slot(2)?,
        ];
        for (slot, recording) in slots.iter().zip(&recordings) {
            publish(&base.archive, slot, recording.manifest())?;
        }
        for range in [0..2, 2..3] {
            let first = range.start;
            let members = range
                .map(|ordinal| CatalogWindow {
                    slot: &slots[ordinal],
                    recording: &recordings[ordinal],
                })
                .collect::<Vec<_>>();
            let catalog = prepare_catalog(scope.clone(), &members)?;
            put(&base.archive, catalog.index_bytes())?;
            publish(
                &base.archive,
                &namespace.page_slot(first)?,
                catalog.manifest(),
            )?;
        }
        let request = RecordingDiscoveryContextRequest {
            recording: RecordingDiscoveryRequest {
                codec: base.request.recording.codec,
                scope,
                interval: base.request.recording.interval.clone(),
                max_windows: base.request.recording.max_windows,
                max_hydration_bytes: base.request.recording.max_hydration_bytes,
            },
            principal: base.request.principal.clone(),
            expected_anchor: None,
        };
        Ok(Self {
            base,
            request,
            namespace,
        })
    }

    fn query(&self) -> Result<DeploymentRecordingDiscoveryQuery, RecordingContextError> {
        self.query_with(
            &HostSpoolIo,
            &RecordingDiscoveryContextLimits::default(),
            &|| false,
        )
    }

    fn query_with(
        &self,
        io: &dyn SpoolIo,
        limits: &RecordingDiscoveryContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingDiscoveryQuery, RecordingContextError> {
        discover_recordings_in_deployment(
            io,
            &self.base.deployment,
            &self.base.archive,
            &self.request,
            limits,
            cancelled,
        )
    }
}

#[test]
fn discovery_preserves_current_hypotheses_and_complete_source_closure_without_writes() -> TestResult
{
    let fixture = DiscoveryFixture::new("protected")?;
    fixture
        .base
        .publish_hypothesis("event:protected-archive-discovery")?;
    let before = tree(&fixture.base.directory)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let result = fixture.query_with(&io, &RecordingDiscoveryContextLimits::default(), &|| false)?;
    assert_eq!(result.native.scanned_windows, 3);
    assert_eq!(result.native.catalogs.len(), 2);
    assert_eq!(result.native.rows.len(), 3);
    assert_eq!(result.native.scanned_root_entries, 10); // Five canonical and five unrelated roots.
    assert_eq!(result.native.read_usage.pinned_roots, 5);
    assert_eq!(
        result.native.indexed_gaps,
        vec![0..3600, 7200..10800, 14400..18000, 21600..25200]
    );
    assert_eq!(result.snapshot.events.len(), 1);
    assert_eq!(
        result.snapshot.events[0].event.event_id.as_str(),
        "event:protected-archive-discovery"
    );
    assert!(!result.snapshot.doctor_inspected);
    let orientation = orient_deployment(
        &result.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: fixture.request.principal.clone(),
            budget_tokens: None,
        },
        &RecordingDiscoveryContextLimits::default().snapshot,
    )?;
    assert!(
        orientation
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| cell
                .disclosable_statement()
                .contains("event:protected-archive-discovery"))
    );
    let epistemic = result.epistemic(&fixture.request.recording);
    let physical = epistemic
        .propositions
        .iter()
        .find(|claim| claim.id == "claim:recordings-discovery:physical-observability")
        .ok_or("missing physical observation state")?;
    assert_eq!(physical.state, KnowledgeState::Unknown);
    assert!(physical.statement.contains("does not register"));
    assert!(
        epistemic
            .propositions
            .iter()
            .filter(|claim| claim
                .id
                .starts_with("claim:recordings-discovery:indexed-gap:"))
            .all(|claim| claim.state == KnowledgeState::NotObservable)
    );
    assert_eq!(result.coverage().stop_reason, "archive_namespace_exhausted");
    for source in &fixture.base.source_leaves {
        assert!(result.native.reference_digests.contains(source));
        assert!(!object_path(&fixture.base.archive, *source).exists());
    }
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 2);
    assert_eq!(tree(&fixture.base.directory)?, before);
    Ok(())
}

#[test]
fn narrow_discovery_projects_selected_catalogs_and_binds_the_complete_inventory() -> TestResult {
    let mut fixture = DiscoveryFixture::new("selected-pages")?;
    let complete = fixture.query()?;
    fixture.request.recording.interval = 3601..7199;
    let selected = fixture.query()?;
    assert_eq!(selected.native.scanned_windows, 3);
    assert_eq!(selected.native.catalogs.len(), 2);
    assert_eq!(selected.native.rows.len(), 1);
    assert_eq!(
        selected.native.inventory_digest,
        complete.native.inventory_digest
    );
    assert_eq!(
        selected.native.reference_digests,
        complete.native.reference_digests
    );
    assert_eq!(selected.selected_catalog_indexes(), BTreeSet::from([0]));
    let epistemic = selected.epistemic(&fixture.request.recording);
    assert!(
        epistemic
            .propositions
            .iter()
            .any(|claim| claim.id == "claim:recordings-discovery:catalog:0")
    );
    assert!(
        !epistemic
            .propositions
            .iter()
            .any(|claim| claim.id == "claim:recordings-discovery:catalog:1")
    );
    let inventory = epistemic
        .propositions
        .iter()
        .find(|claim| claim.id == "claim:recordings-discovery:inventory")
        .ok_or("missing inventory claim")?;
    assert!(inventory.statement.contains("catalogs=2"));
    assert!(inventory.statement.contains("selected_windows=1"));
    assert!(
        inventory
            .evidence
            .contains(&selected.native.inventory_digest.to_text())
    );
    let before_principal = selected.request_digest;
    fixture.request.principal = PrincipalId::parse("principal:another-discovery-reader")?;
    let relabelled = fixture.query()?;
    assert_ne!(relabelled.request_digest, before_principal);
    assert_eq!(relabelled.native, selected.native);
    Ok(())
}

#[test]
fn obsolete_expected_anchor_refuses_before_archive_enumeration_and_refresh_changes_context_only()
-> TestResult {
    let mut fixture = DiscoveryFixture::new("stale-anchor")?;
    let initial = fixture.query()?;
    fixture.request.expected_anchor =
        Some(AnchorToken::parse(&initial.anchor_token).ok_or("anchor")?);
    assert_eq!(fixture.query()?.decision_digest, initial.decision_digest);
    fixture
        .base
        .publish_hypothesis("event:discovery-new-deployment-head")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let result = fixture.query_with(&io, &RecordingDiscoveryContextLimits::default(), &|| false);
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    assert!(io.calls().is_empty());
    fixture.request.expected_anchor = None;
    let current = fixture.query()?;
    assert_ne!(current.anchor_token, initial.anchor_token);
    assert_ne!(current.request_digest, initial.request_digest);
    assert_eq!(current.native, initial.native);
    assert_eq!(current.snapshot.events.len(), 1);
    Ok(())
}

#[test]
fn changed_deployment_during_discovery_discards_all_native_results() -> TestResult {
    let fixture = DiscoveryFixture::new("racing-context")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let changed = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 8 && !changed.swap(true, Ordering::SeqCst) {
            failed.store(
                fixture
                    .base
                    .publish_hypothesis("event:discovery-racing-head")
                    .is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let result = fixture.query_with(&io, &RecordingDiscoveryContextLimits::default(), &cancelled);
    assert!(changed.load(Ordering::SeqCst) && !failed.load(Ordering::SeqCst));
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    assert!(io.is_read_only());
    assert_eq!(fixture.query()?.snapshot.events.len(), 1);
    Ok(())
}

#[test]
fn discovery_deployment_reads_share_one_nonrefillable_budget() -> TestResult {
    let fixture = DiscoveryFixture::new("context-budget")?;
    let defaults = RecordingDiscoveryContextLimits::default();
    let baseline = fixture.query()?;
    let exact = RecordingDiscoveryContextLimits {
        deployment_bytes: baseline.deployment_bytes_read as usize + 1,
        deployment_reads: baseline.deployment_metadata_reads as usize,
        ..defaults
    };
    let bounded = fixture.query_with(&HostSpoolIo, &exact, &|| false)?;
    assert_eq!(bounded.native, baseline.native);
    assert_eq!(
        bounded.deployment_bytes_read,
        baseline.deployment_bytes_read
    );
    assert_eq!(
        bounded.deployment_metadata_reads,
        baseline.deployment_metadata_reads
    );
    assert_ne!(bounded.request_digest, baseline.request_digest);
    for limits in [
        RecordingDiscoveryContextLimits {
            deployment_bytes: baseline.deployment_bytes_read as usize - 1,
            ..exact
        },
        RecordingDiscoveryContextLimits {
            deployment_reads: exact.deployment_reads - 1,
            ..exact
        },
    ] {
        assert!(
            fixture
                .query_with(&HostSpoolIo, &limits, &|| false)
                .is_err()
        );
    }
    let mut narrowed = defaults;
    narrowed.recording.max_scan_roots = 9;
    assert!(matches!(
        fixture.query_with(&HostSpoolIo, &narrowed, &|| false),
        Err(RecordingContextError::Discovery(_))
    ));
    Ok(())
}

#[test]
fn empty_unknown_namespace_is_explicit_but_an_unindexed_tail_refuses() -> TestResult {
    let mut fixture = DiscoveryFixture::new("empty-tail")?;
    fixture.request.recording.scope.recording.generation += 1;
    let empty = fixture.query()?;
    assert_eq!(empty.native.scanned_windows, 0);
    assert!(empty.native.rows.is_empty() && empty.native.catalogs.is_empty());
    assert_eq!(
        empty.native.indexed_gaps,
        vec![fixture.request.recording.interval.clone()]
    );
    assert!(empty.native.reference_digests.is_empty());
    let epistemic = empty.epistemic(&fixture.request.recording);
    assert!(epistemic.propositions.iter().any(|claim| claim.id
        == "claim:recordings-discovery:physical-observability"
        && claim.state == KnowledgeState::Unknown));
    assert!(epistemic.propositions.iter().any(|claim| claim.id
        == "claim:recordings-discovery:indexed-gap:0"
        && claim.state == KnowledgeState::NotObservable));
    fixture.request.recording.scope.recording.generation -= 1;
    fixture.request.recording.interval = 0..1;
    fs::remove_file(
        fixture
            .base
            .archive
            .join("roots")
            .join(format!("{}.root", fixture.namespace.page_slot(2)?)),
    )?;
    let before = tree(&fixture.base.directory)?;
    assert!(matches!(
        fixture.query(),
        Err(RecordingContextError::Discovery(
            RecordingDiscoveryError::UnindexedWindows
        ))
    ));
    assert_eq!(tree(&fixture.base.directory)?, before);
    Ok(())
}

#[test]
fn invalid_discovery_preconditions_and_cancellation_fail_before_either_owner_read() -> TestResult {
    let fixture = DiscoveryFixture::new("preflight")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let missing = fixture.base.directory.join("missing-deployment");
    let defaults = RecordingDiscoveryContextLimits::default();
    let mut request = fixture.request.clone();
    request.recording.max_windows = 33;
    assert!(matches!(
        discover_recordings_in_deployment(
            &io,
            &missing,
            &fixture.base.archive,
            &request,
            &defaults,
            &|| false,
        ),
        Err(RecordingContextError::InvalidRequest)
    ));
    request = fixture.request.clone();
    request.recording.interval = 1..1;
    assert!(matches!(
        discover_recordings_in_deployment(
            &io,
            &missing,
            &fixture.base.archive,
            &request,
            &defaults,
            &|| false,
        ),
        Err(RecordingContextError::Discovery(
            RecordingDiscoveryError::InvalidRequest
        ))
    ));
    let mut invalid_limits = defaults;
    invalid_limits.recording.max_scan_roots += 1;
    assert!(matches!(
        discover_recordings_in_deployment(
            &io,
            &missing,
            &fixture.base.archive,
            &fixture.request,
            &invalid_limits,
            &|| false,
        ),
        Err(RecordingContextError::Discovery(
            RecordingDiscoveryError::InvalidRequest
        ))
    ));
    assert!(matches!(
        discover_recordings_in_deployment(
            &io,
            &missing,
            &fixture.base.archive,
            &fixture.request,
            &defaults,
            &|| true,
        ),
        Err(RecordingContextError::Cancelled)
    ));
    assert!(io.calls().is_empty());
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn current_deployment_deletion_denies_an_unselected_discovered_source_with_intact_archive()
-> TestResult {
    let mut fixture = DiscoveryFixture::new("deletion")?;
    fixture.request.recording.interval = 0..1;
    let before_delete = fixture.query()?;
    assert!(before_delete.native.rows.is_empty());
    let later_leaf = *fixture
        .base
        .later_leaves
        .first()
        .ok_or("later-only source leaf")?;
    assert!(before_delete.native.reference_digests.contains(&later_leaf));
    commit_later_deletion(&fixture, later_leaf)?;
    // Archive metadata alone remains valid; current deployment deletion authority denies release.
    let native = discover_recordings(
        &HostSpoolIo,
        &fixture.base.archive,
        &fixture.request.recording,
        RecordingDiscoveryLimits::default(),
        &|| false,
    )?;
    assert!(native.rows.is_empty());
    assert_eq!(
        native.reference_digests,
        before_delete.native.reference_digests
    );
    let before = tree(&fixture.base.directory)?;
    let result = fixture.query();
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    assert_eq!(tree(&fixture.base.directory)?, before);
    Ok(())
}

/// Actual fixture setup through authorized import and deletion owners; the discovery query
/// receives no capture, publisher, retention or deletion capability.
fn commit_later_deletion(fixture: &DiscoveryFixture, later_leaf: ContentDigest) -> TestResult {
    let recording = window(5, 18000)?;
    let slot = fixture.namespace.window_slot(2)?;
    let mut source = LocalRootPublisher::open(
        fixture.base.directory.join("discovery-deletion-source"),
        LocalPublicationLimits::new(
            16,
            64,
            16,
            256,
            SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256),
        ),
    )?;
    for (_, digest, bytes) in recording.children() {
        assert_eq!(source.stage_object(bytes)?, digest);
    }
    source.publish(&slot, recording.manifest())?;
    let principal = "principal:recording-discovery-delete";
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recording-discovery-delete".to_owned(),
        operation_id: OperationId::parse("operation:recording-discovery-delete")?,
        principal: principal.to_owned(),
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
        anchor_universe: ContentDigest::sha256(b"independent-set-deployment-universe"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, fixture.base.deployment.clone())?;
    let mut deployment = ReferenceDeployment::open(&fixture.base.deployment, SITE, &cx)?;
    struct Owner(ContentDigest);
    impl RtspImportAuthority for Owner {
        fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
            request.root == self.0 && destination.site_lineage() == SITE
        }
    }
    let imported = import_rtsp(
        &source,
        &mut deployment,
        &RtspImportRequest {
            codec: RtspImportCodec::Avc,
            slot,
            root: recording.manifest().root(),
            source: recording.summary().scope.clone(),
            receive_time: TimestampNs(10_000_000_000),
            capture_origin: None,
            max_frames: 256,
            max_original_bytes: 32 * 1024 * 1024,
            max_media_bytes: 32 * 1024 * 1024,
        },
        &Owner(recording.manifest().root()),
        &cx,
        &mut WorkBudget::new(512 * 1024 * 1024),
    )?;
    let plan = plan_deletion(&deployment, imported.import_identity, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(
        plan.deletable
            .iter()
            .any(|entry| entry.digest == later_leaf)
    );
    let receipt = commit_deletion(
        &mut deployment,
        plan.digest()?,
        plan.approval_digest(principal)?,
        principal,
        &cx,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    Ok(())
}
