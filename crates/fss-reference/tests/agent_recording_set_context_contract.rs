#![forbid(unsafe_code)]
//! Multi-catalog metadata keeps current deployment authority and never acquires media authority.

mod collector_support;

#[path = "agent_recording_set_context_contract/discover.rs"]
mod discover;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CaptureInterval, ContentDigest, ContextAuthority,
    DecisionPath, EventHypothesis, EventId, EventKind, EventState, KnowledgeState, OperationId,
    PrincipalId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::{
    HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIo, SpoolIoCall, SpoolLimits,
    encode_spool_object,
};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, SlotName, root_record_bytes};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::{OrientRequest, orient_deployment};
use fss_reference::agent_recording_context::RecordingContextError;
use fss_reference::agent_recording_context::set::{
    DeploymentRecordingSetQuery, RecordingSetContextLimits, RecordingSetContextRequest,
    query_recording_set_in_deployment,
};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::set::{
    RecordingCatalogPin, RecordingSetQueryLimits, RecordingSetQueryRequest, query_recording_set,
};
use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
use fss_reference::ingest::rtsp_import::{
    RtspImportAuthority, RtspImportCodec, RtspImportRequest, import_rtsp,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:recording-set-context";

struct Fixture {
    directory: PathBuf,
    deployment: PathBuf,
    archive: PathBuf,
    request: RecordingSetContextRequest,
    source_leaves: BTreeSet<ContentDigest>,
    later_leaves: BTreeSet<ContentDigest>,
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let mut directory = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-recording-set-context-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(path);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("temporary directory capacity")?;
        let deployment = directory.join("deployment");
        let archive = directory.join("archive");
        for path in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(archive.join(path))?;
        }

        let first = window(1, 3600)?;
        let shared = window(3, 10800)?;
        let later = window(5, 18000)?;
        let slots = [
            SlotName::parse("first-window")?,
            SlotName::parse("shared-window")?,
            SlotName::parse("later-window")?,
        ];
        let scope = CatalogScope {
            recording: collector_support::scope()?,
            decode_clock: ContentDigest::sha256(b"recording-set-context-decode-clock"),
            time_scale: 90_000,
        };
        let first_catalog = prepare_catalog(
            scope.clone(),
            &[
                CatalogWindow {
                    slot: &slots[0],
                    recording: &first,
                },
                CatalogWindow {
                    slot: &slots[1],
                    recording: &shared,
                },
            ],
        )?;
        let later_catalog = prepare_catalog(
            scope.clone(),
            &[
                CatalogWindow {
                    slot: &slots[1],
                    recording: &shared,
                },
                CatalogWindow {
                    slot: &slots[2],
                    recording: &later,
                },
            ],
        )?;
        for (slot, recording) in slots.iter().zip([&first, &shared, &later]) {
            publish(&archive, slot, recording.manifest())?;
        }
        let mut catalogs = Vec::new();
        for (name, catalog) in [("catalog-a", &first_catalog), ("catalog-b", &later_catalog)] {
            let slot = SlotName::parse(name)?;
            publish(&archive, &slot, catalog.manifest())?;
            put(&archive, catalog.index_bytes())?;
            catalogs.push(RecordingCatalogPin {
                slot,
                root: catalog.manifest().root(),
            });
        }
        let earlier_leaves: BTreeSet<_> = first
            .children()
            .into_iter()
            .chain(shared.children())
            .map(|(_, digest, _)| digest)
            .collect();
        let later_leaves: BTreeSet<_> = later
            .children()
            .into_iter()
            .map(|(_, digest, _)| digest)
            .filter(|digest| !earlier_leaves.contains(digest))
            .collect();
        let source_leaves = earlier_leaves
            .into_iter()
            .chain(later.children().into_iter().map(|(_, digest, _)| digest))
            .collect();
        let fixture = Self {
            directory,
            deployment,
            archive,
            source_leaves,
            later_leaves,
            request: RecordingSetContextRequest {
                recording: RecordingSetQueryRequest {
                    codec: RecordingQueryCodec::Avc,
                    scope,
                    catalogs,
                    interval: 0..25200,
                    max_windows: 32,
                    max_hydration_bytes: 256 * 1024 * 1024,
                },
                principal: PrincipalId::parse("principal:recording-set-context")?,
                expected_anchor: None,
            },
        };
        let cx = fixture.cx()?;
        drop(ReferenceDeployment::open(&fixture.deployment, SITE, &cx)?);
        Ok(fixture)
    }

    fn cx(&self) -> TestResult<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:recording-set-context".to_owned(),
            operation_id: OperationId::parse("operation:recording-set-context")?,
            principal: "operator:recording-set-context".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"independent-set-deployment-universe"),
            generation: 1,
        })?;
        Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            self.directory.join("cx"),
        )?))
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

    fn query(&self) -> Result<DeploymentRecordingSetQuery, RecordingContextError> {
        self.query_with(&HostSpoolIo, &RecordingSetContextLimits::default(), &|| {
            false
        })
    }

    fn query_with(
        &self,
        io: &dyn SpoolIo,
        limits: &RecordingSetContextLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<DeploymentRecordingSetQuery, RecordingContextError> {
        query_recording_set_in_deployment(
            io,
            &self.deployment,
            &self.archive,
            &self.request,
            limits,
            cancelled,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("spool/objects")
        .join(digest.to_text().trim_start_matches("sha256:"))
}

fn put(root: &Path, bytes: &[u8]) -> TestResult {
    let digest = ContentDigest::sha256(bytes);
    fs::write(
        object_path(root, digest),
        encode_spool_object(digest, bytes)?,
    )?;
    Ok(())
}

fn publish(root: &Path, slot: &SlotName, manifest: &ObjectManifest) -> TestResult {
    put(root, &manifest.canonical_bytes())?;
    fs::write(
        root.join("roots").join(format!("{}.root", slot.as_str())),
        root_record_bytes(slot, manifest.root(), manifest.children().len())?,
    )?;
    Ok(())
}

fn window(sequence: u64, decode_time: u64) -> TestResult<PreparedRecording> {
    let mut collector = collector_support::collector(CollectorLimits::default())?;
    let sample = collector_support::sample(sequence, 90_000 + sequence as u32 * 3600, true, false)?;
    sample.source(&mut collector, 1)?;
    collector_support::accepted(collector.push_picture(sample.timed(decode_time), 1))?;
    collector.seal(2)?;
    collector
        .take_ready()
        .ok_or_else(|| "missing AVC window".into())
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut tree = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            tree.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            tree.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("special file in fixture".into());
        }
    }
    Ok(tree)
}

#[test]
fn merged_metadata_retains_protected_deployment_context_and_unknown_observability() -> TestResult {
    let mut fixture = Fixture::new("context")?;
    fixture.publish_hypothesis("event:protected-recording-set")?;
    let before = tree(&fixture.directory)?;
    let result = fixture.query()?;
    assert_eq!(result.native.scanned_windows, 4);
    assert_eq!(result.native.unique_windows, 3);
    assert_eq!(result.native.rows.len(), 3);
    assert_eq!(result.native.rows[1].locations.len(), 2);
    assert_eq!(
        result.native.indexed_gaps,
        vec![0..3600, 7200..10800, 14400..18000, 21600..25200]
    );
    assert_eq!(
        result.native.quoted_hydration_bytes,
        result
            .native
            .rows
            .iter()
            .map(|row| row.entry.byte_len() as u64)
            .sum::<u64>()
    );
    assert_eq!(result.snapshot.events.len(), 1);
    assert_eq!(
        result.snapshot.events[0].event.event_id.as_str(),
        "event:protected-recording-set"
    );
    assert!(!result.snapshot.doctor_inspected);
    assert_ne!(
        result.anchor_token,
        fixture.request.recording.scope.recording.anchor.to_text()
    );
    let orientation = orient_deployment(
        &result.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: fixture.request.principal.clone(),
            budget_tokens: None,
        },
        &RecordingSetContextLimits::default().snapshot,
    )?;
    assert!(
        orientation
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| {
                cell.disclosable_statement()
                    .contains("event:protected-recording-set")
            })
    );
    let epistemic = result.epistemic(&fixture.request.recording);
    let physical = epistemic
        .propositions
        .iter()
        .find(|claim| claim.id == "claim:recordings-set:physical-observability")
        .ok_or("missing physical-observability proposition")?;
    assert_eq!(physical.state, KnowledgeState::Unknown);
    assert!(physical.statement.contains("no search of other catalogs"));
    let gaps: Vec<_> = epistemic
        .propositions
        .iter()
        .filter(|claim| claim.id.starts_with("claim:recordings-set:indexed-gap:"))
        .collect();
    assert_eq!(gaps.len(), 4);
    assert!(
        gaps.iter()
            .all(|claim| claim.state == KnowledgeState::NotObservable)
    );
    assert_eq!(
        result.coverage().stop_reason,
        "pinned_catalog_set_exhausted"
    );
    for leaf in &fixture.source_leaves {
        assert!(!object_path(&fixture.archive, *leaf).exists());
    }
    fixture.request.recording.catalogs.reverse();
    let reordered = fixture.query()?;
    assert_eq!(result.request_digest, reordered.request_digest);
    assert_eq!(result.decision_digest, reordered.decision_digest);
    assert_eq!(result.native, reordered.native);
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn principal_binds_context_identity_without_changing_the_native_selection() -> TestResult {
    let mut fixture = Fixture::new("principal")?;
    let first = fixture.query()?;
    fixture.request.principal = PrincipalId::parse("principal:second-set-reader")?;
    let second = fixture.query()?;
    assert_ne!(first.request_digest, second.request_digest);
    assert_ne!(first.decision_digest, second.decision_digest);
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(first.native, second.native);
    assert_eq!(first.anchor_token, second.anchor_token);
    Ok(())
}

#[test]
fn locked_writers_and_corrupt_media_do_not_trigger_hydration_or_recovery() -> TestResult {
    let fixture = Fixture::new("locked")?;
    let cx = fixture.cx()?;
    let writer = ReferenceDeployment::open(&fixture.deployment, SITE, &cx)?;
    let archive_lock = fs::File::create(fixture.archive.join("LOCK"))?;
    archive_lock.try_lock()?;
    for leaf in &fixture.source_leaves {
        fs::write(
            object_path(&fixture.archive, *leaf),
            b"corrupt unread media/index",
        )?;
    }
    let before = tree(&fixture.directory)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let query = fixture.query_with(&io, &RecordingSetContextLimits::default(), &|| false)?;
    assert_eq!(query.native.rows.len(), 3);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
    assert!(query.deployment_bytes_read > 0 && query.deployment_metadata_reads > 0);
    assert_eq!(tree(&fixture.directory)?, before);
    archive_lock.unlock()?;
    drop(writer);
    Ok(())
}

#[test]
fn stale_anchor_refuses_before_archive_io_and_new_context_rebinds_the_same_recordings() -> TestResult
{
    let mut fixture = Fixture::new("anchor")?;
    let initial = fixture.query()?;
    fixture.request.expected_anchor =
        Some(AnchorToken::parse(&initial.anchor_token).ok_or("anchor token")?);
    assert_eq!(fixture.query()?.decision_digest, initial.decision_digest);
    fixture.publish_hypothesis("event:recording-set-new-head")?;
    let before = tree(&fixture.directory)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let result = fixture.query_with(&io, &RecordingSetContextLimits::default(), &|| false);
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    assert!(io.calls().is_empty());
    fixture.request.expected_anchor = None;
    let current = fixture.query()?;
    assert_ne!(current.anchor_token, initial.anchor_token);
    assert_ne!(current.request_digest, initial.request_digest);
    assert_ne!(current.decision_digest, initial.decision_digest);
    assert_eq!(current.native, initial.native);
    assert_eq!(current.snapshot.events.len(), 1);
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn deployment_change_during_catalog_reads_discards_the_complete_metadata_result() -> TestResult {
    let fixture = Fixture::new("racing-head")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let changed = AtomicBool::new(false);
    let mutation_failed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5 && !changed.swap(true, Ordering::SeqCst) {
            mutation_failed.store(
                fixture
                    .publish_hypothesis("event:recording-set-racing-head")
                    .is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let result = fixture.query_with(&io, &RecordingSetContextLimits::default(), &cancelled);
    assert!(changed.load(Ordering::SeqCst));
    assert!(!mutation_failed.load(Ordering::SeqCst));
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    assert!(io.is_read_only());
    assert_eq!(fixture.query()?.snapshot.events.len(), 1);
    Ok(())
}

#[test]
fn both_deployment_reads_share_one_budget_and_allowances_bind_context_identity() -> TestResult {
    let fixture = Fixture::new("budgets")?;
    let limits = RecordingSetContextLimits::default();
    let baseline = fixture.query_with(&HostSpoolIo, &limits, &|| false)?;
    // An absent optional metadata file requires one unconsumed byte for the bounded probe.
    let exact = RecordingSetContextLimits {
        deployment_bytes: baseline.deployment_bytes_read as usize + 1,
        deployment_reads: baseline.deployment_metadata_reads as usize,
        ..limits
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
    for lowered in [
        RecordingSetContextLimits {
            deployment_bytes: baseline.deployment_bytes_read as usize - 1,
            ..exact
        },
        RecordingSetContextLimits {
            deployment_reads: exact.deployment_reads - 1,
            ..exact
        },
    ] {
        assert!(
            fixture
                .query_with(&HostSpoolIo, &lowered, &|| false)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn unselected_later_catalog_source_deletion_never_becomes_an_empty_success() -> TestResult {
    let mut fixture = Fixture::new("unselected-deleted")?;
    fixture.request.recording.interval = 0..1;
    let baseline = fixture.query()?;
    assert!(baseline.native.rows.is_empty());
    assert_eq!(baseline.native.indexed_gaps, vec![0..1]);
    let later_leaf = *fixture
        .later_leaves
        .first()
        .ok_or("unique later source leaf")?;
    assert!(baseline.native.reference_digests.contains(&later_leaf));
    fs::write(
        fixture.archive.join("tombstones").join(format!(
            "{}.tomb",
            later_leaf.to_text().replacen(':', "-", 1)
        )),
        b"deletion present",
    )?;
    let before = tree(&fixture.directory)?;
    assert!(matches!(
        fixture.query(),
        Err(RecordingContextError::Recording(_))
    ));
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn deployment_deletion_denies_unselected_sources_even_when_archive_publication_is_intact()
-> TestResult {
    let mut fixture = Fixture::new("deployment-deleted")?;
    fixture.request.recording.interval = 0..1;
    let recording = window(5, 18000)?;
    let slot = SlotName::parse("later-window")?;
    let mut source = LocalRootPublisher::open(
        fixture.directory.join("deletion-source"),
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

    // These capabilities belong only to fixture setup. The metadata query receives none.
    let principal = "principal:recording-set-delete";
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recording-set-delete".to_owned(),
        operation_id: OperationId::parse("operation:recording-set-delete")?,
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
    let cx = ReplayCx::from_context_authority(&authority, fixture.deployment.clone())?;
    let mut deployment = ReferenceDeployment::open(&fixture.deployment, SITE, &cx)?;
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
    let before_delete = fixture.query()?;
    assert!(before_delete.native.rows.is_empty());
    let later_leaf = *fixture
        .later_leaves
        .first()
        .ok_or("unique later source leaf")?;
    assert!(before_delete.native.reference_digests.contains(&later_leaf));
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
    drop(deployment);
    drop(source);

    // The separate archive still verifies; only current deployment deletion authority denies it.
    let native = query_recording_set(
        &HostSpoolIo,
        &fixture.archive,
        &fixture.request.recording,
        RecordingSetQueryLimits::default(),
        &|| false,
    )?;
    assert!(native.rows.is_empty());
    assert_eq!(
        native.reference_digests,
        before_delete.native.reference_digests
    );
    let before = tree(&fixture.directory)?;
    let result = fixture.query();
    assert!(
        matches!(result, Err(RecordingContextError::AnchorChanged)),
        "{result:?}"
    );
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn invalid_set_preconditions_and_cancellation_fail_before_either_owner_is_read() -> TestResult {
    let fixture = Fixture::new("preflight")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let missing = fixture.directory.join("not-a-deployment");
    let limits = RecordingSetContextLimits::default();
    let mut invalid = fixture.request.clone();
    invalid
        .recording
        .catalogs
        .push(invalid.recording.catalogs[0].clone());
    assert!(matches!(
        query_recording_set_in_deployment(
            &io,
            &missing,
            &fixture.archive,
            &invalid,
            &limits,
            &|| false
        ),
        Err(RecordingContextError::Recording(_))
    ));
    invalid = fixture.request.clone();
    invalid.recording.max_windows = 33;
    assert!(matches!(
        query_recording_set_in_deployment(
            &io,
            &missing,
            &fixture.archive,
            &invalid,
            &limits,
            &|| false
        ),
        Err(RecordingContextError::InvalidRequest)
    ));
    let mut invalid_limits = limits;
    invalid_limits.recording.metadata.max_io_calls += 1;
    assert!(matches!(
        query_recording_set_in_deployment(
            &io,
            &missing,
            &fixture.archive,
            &fixture.request,
            &invalid_limits,
            &|| false
        ),
        Err(RecordingContextError::Recording(_))
    ));
    assert!(matches!(
        query_recording_set_in_deployment(
            &io,
            &missing,
            &fixture.archive,
            &fixture.request,
            &limits,
            &|| true
        ),
        Err(RecordingContextError::Cancelled)
    ));
    assert!(io.calls().is_empty());
    assert!(!missing.exists());
    Ok(())
}
