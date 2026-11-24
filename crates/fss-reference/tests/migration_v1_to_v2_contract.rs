#![forbid(unsafe_code)]
//! Contract tests for Track A5 (`fss-x4a.31.1.5`): non-destructive v1-to-v2 deployment
//! migration, cryptographic equivalence receipts, dual-read format detection, and fault handling.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CapsuleId, CaptureInterval, ContentDigest, DecisionPath, EventHypothesis,
    EventId, EventKind, EventState, IdempotencyKey, ObligationId, OperationId, ProbabilityInterval,
    SensorId, StreamId, TimestampNs,
};
use fss_ledger::{
    DurableReferenceLedger, EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger,
};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_pack::{DurabilityMode, PackConfig, PackStore};
use fss_projection_store::{
    HistoryChainMode, MvccProjectionStore, ProjectionStore, ProjectionStoreConfig, WalSyncPolicy,
};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::migration::{
    DeploymentFormatVersion, ERR_DEPLOYMENT_FORMAT_V1_001, ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001,
    MIGRATE_INCOMPLETE_FILENAME, MIGRATION_RECEIPT_FILENAME, MigrationError, MigrationRequest,
    detect_deployment_format, migrate_v1_to_v2, migrate_v1_to_v2_with_progress,
    require_v2_deployment,
};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceDeployment, ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model,
    policy_decision_path, run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:migration-v1-v2-contract";
const PRINCIPAL: &str = "principal:migration-operator";

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-migrate-contract-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err("could not allocate temp workspace".into())
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_authority() -> TestResult<ContextAuthority> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:migration-contract".to_owned(),
        operation_id: OperationId::parse("operation:migration-contract")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".to_owned(),
            CAP_HOLD_PREPARE.to_owned(),
            CAP_HOLD_COMMIT.to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(16_384)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(authority)
}

fn ingest_synthetic_mjpeg(
    ws: &Path,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
    name: &str,
    gray: u8,
) -> TestResult<ContentDigest> {
    let path = ws.join(format!("{name}.mjpeg"));
    let bytes = encode_jpeg(
        16,
        16,
        &[gray; 256],
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?;
    fs::write(&path, bytes)?;
    let req = FileIngestRequest::new(
        path,
        SensorId::parse(format!("sensor:{name}"))?,
        StreamId::parse(format!("stream:{name}"))?,
    )
    .with_receive_time(TimestampNs(1_000_000_000))
    .with_format_hint(FileFormatHint::JpegStream);
    Ok(FileIngestAdapter::ingest(req, cx, deployment)?.import_identity)
}

fn make_event(
    event_id: &EventId,
    revision: u64,
    supersedes: Option<ContentDigest>,
    state: EventState,
) -> TestResult<EventHypothesis> {
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: event_id.clone(),
        revision,
        supersedes,
        state,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        uncertainty_reason: if state == EventState::Hypothesized {
            Some("initial motion hypothesis".to_owned())
        } else {
            None
        },
        zone_ids: vec!["zone:front-door".to_owned()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.4, 0.9)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"migration-test-policy"),
            fingerprint: ContentDigest::sha256(format!("migration-fp-{revision}").as_bytes()),
            abstained: state == EventState::Hypothesized,
            abstention_reason: if state == EventState::Hypothesized {
                Some("awaiting corroboration".to_owned())
            } else {
                None
            },
        },
    };
    event.verify()?;
    Ok(event)
}

struct RichV1Fixture {
    v1_root: PathBuf,
    event_id: EventId,
    held_import: ContentDigest,
    deleted_import: ContentDigest,
    mask_sensor: SensorId,
    mask_policy_digest: ContentDigest,
    orphan_digest: ContentDigest,
}

fn build_rich_v1_deployment(ws: &Path) -> TestResult<RichV1Fixture> {
    let v1_root = ws.join("v1-deployment");
    let authority = make_authority()?;
    let cx = ReplayCx::from_context_authority(&authority, v1_root.clone())?;
    let mut dep = ReferenceDeployment::open(&v1_root, SITE, &cx)?;

    // 1. Multi-revision event (rev 1 Hypothesized -> rev 2 Corroborated via 2-domain evidence).
    let event_id = EventId::parse("event:migration:multi-rev")?;
    let rev1_decision = ReferencePolicyDecision {
        event: make_event(&event_id, 1, None, EventState::Hypothesized)?,
        action: ReferencePolicyAction::Hold,
    };
    let rev1_receipt = dep.publish_event(&rev1_decision, &cx)?;

    let mut scratch_objects = InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024));
    let mut scratch_captures = DurableReferenceLedger::open(
        ws.join("scratch-captures.journal"),
        "site:migration-captures",
        IncompleteTailPolicy::Reject,
    )?;
    let mut observations = Vec::new();
    for (lane, seed) in [("a", 101_u64), ("b", 202_u64)] {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:migration:{lane}"))?,
            sensor_id: SensorId::parse(format!("sensor:migration:{lane}"))?,
            seed,
            packet_count: 2,
            packet_bytes: 32,
            start_ns: 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 100,
        };
        let capture = run_reference_capture(
            &spec,
            &DeliveryPlan::identity(spec.packet_count)?,
            &mut scratch_objects,
            &mut scratch_captures,
        )?;
        let model = MockModelSpec::new(
            format!("mock:migration:{lane}:v1"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.98, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut scratch_objects)?;
        observations.push(ReferenceModelObservation::new(
            result,
            format!("power:migration:{lane}"),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        )?);
    }
    let mut rev2_decision = evaluate_unknown_presence(event_id.clone(), observations)?;
    assert_eq!(rev2_decision.action, ReferencePolicyAction::PrepareAlert);
    rev2_decision.event.revision = 2;
    rev2_decision.event.supersedes = Some(rev1_receipt.event_revision_digest);
    rev2_decision.event.decision_path = policy_decision_path(
        &rev2_decision.event.event_id,
        &rev2_decision.event.evidence,
        rev2_decision.event.state,
        rev2_decision.action,
    );
    rev2_decision.event.verify()?;
    for digest in &rev2_decision.event.model_receipts {
        let staged = dep.stage_payload(scratch_objects.read_verified(*digest)?)?;
        assert_eq!(staged, *digest);
    }
    let rev2_receipt = dep.publish_event(&rev2_decision, &cx)?;

    // 2. Durable alert effect written to effects/journal.fssj.
    {
        let (effects_journal, authority_ledger) = dep.effects_and_ledger();
        let _alert_plan = effects_journal.prepare_alert(PrepareAlertParams {
            decision: &rev2_decision,
            event_receipt: &rev2_receipt,
            authority: authority_ledger,
            operation_id: OperationId::parse("op:migration:alert-1")?,
            idempotency_key: IdempotencyKey::parse("idempotency:migration:alert-1")?,
            obligation_id: ObligationId::parse("obligation:migration:alert-1")?,
            channel: "test-channel".to_owned(),
            now: TimestampNs(5_000_000),
        })?;
    }

    // 3. Two file imports: one held indefinitely, one deleted to completion.
    let held_import = ingest_synthetic_mjpeg(ws, &mut dep, &cx, "held_cam", 64)?;
    let deleted_import = ingest_synthetic_mjpeg(ws, &mut dep, &cx, "deleted_cam", 192)?;

    let hold_req = HoldRequest {
        hold_id: "hold-incident-1".to_owned(),
        import_identity: held_import,
        state: HoldState::Held,
        reason: "Preserve incident footage across migration".to_owned(),
    };
    let hold_preview = preview_hold(&dep, &hold_req, &authority, &cx)?;
    let _hold_committed = commit_hold(
        &mut dep,
        &hold_req,
        hold_preview.record.approval(),
        &authority,
        &cx,
    )?;

    // 4. Per-sensor privacy mask policy.
    let mask_sensor = SensorId::parse("sensor:mask-cam")?;
    let mask_policy = PrivacyMaskPolicy::new(mask_sensor.clone(), [640, 480], &[[10, 20, 80, 60]])?;
    let mask_preview = preview_mask(&dep, &mask_policy)?;
    let _mask_committed = declare_mask(&mut dep, &mask_policy, mask_preview.approval, &cx)?;
    let mask_policy_digest = mask_policy.digest();

    // 5. Completed deletion of deleted_import (creates deletion_record, deletion_tombstone,
    //    local_root_retraction, deletion_completion, and objects/tombstones/).
    let del_plan = plan_deletion(&dep, deleted_import, &cx)?;
    assert!(del_plan.blockers.is_empty(), "{:?}", del_plan.blockers);
    let del_plan_digest = del_plan.digest()?;
    let del_approval = fss_reference::deletion::approval_digest(del_plan_digest, SITE, PRINCIPAL)?;
    let del_receipt = commit_deletion(&mut dep, del_plan_digest, del_approval, PRINCIPAL, &cx)?;
    assert_eq!(del_receipt.outcome, CommitOutcome::Completed);

    // 6. Explicit unreferenced v1 spool orphan (staged & verified, never referenced anywhere).
    let orphan_digest = dep.stage_payload(b"explicit-v1-unreferenced-spool-orphan-bytes")?;

    drop(dep);
    cx.drain_and_finalize();

    // 7. Populate an agent/ file to verify byte-for-byte agent/ preservation.
    fs::create_dir_all(v1_root.join("agent/notes"))?;
    fs::write(
        v1_root.join("agent/notes/mission.txt"),
        b"mission-state-snapshot-v1\n",
    )?;

    Ok(RichV1Fixture {
        v1_root,
        event_id,
        held_import,
        deleted_import,
        mask_sensor,
        mask_policy_digest,
        orphan_digest,
    })
}

fn directory_sha256_inventory(root: &Path) -> TestResult<BTreeMap<String, ContentDigest>> {
    let mut map = BTreeMap::new();
    walk_inventory(root, root, &mut map)?;
    Ok(map)
}

fn walk_inventory(
    base: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, ContentDigest>,
) -> TestResult {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            walk_inventory(base, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(base)?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path)?;
            out.insert(rel, ContentDigest::sha256(&bytes));
        }
    }
    Ok(())
}

#[test]
fn migrate_rich_v1_deployment_preserves_source_and_proves_full_equivalence() -> TestResult {
    let ws = TempWorkspace::new("rich")?;
    let fixture = build_rich_v1_deployment(&ws.0)?;
    let dest_v2 = ws.0.join("v2-deployment");

    // Dual-read detection on v1 root emits exact ERR-DEPLOYMENT-FORMAT-V1-001 guidance.
    assert!(matches!(
        detect_deployment_format(&fixture.v1_root)?,
        DeploymentFormatVersion::V1 { .. }
    ));
    let v2_gate = require_v2_deployment(&fixture.v1_root);
    match v2_gate {
        Err(MigrationError::UnsupportedV1Format(guidance)) => {
            assert_eq!(guidance.error_id, ERR_DEPLOYMENT_FORMAT_V1_001);
            assert!(
                guidance.migrate_command.contains("fss migrate --from"),
                "{}",
                guidance.migrate_command
            );
            assert!(guidance.migrate_command.contains("--to"));
        }
        other => return Err(format!("expected UnsupportedV1Format, got {other:?}").into()),
    }

    // Capture full byte-for-byte SHA-256 inventory of v1 source BEFORE migration.
    let source_before = directory_sha256_inventory(&fixture.v1_root)?;

    let request = MigrationRequest::new(&fixture.v1_root, &dest_v2);
    let mut progress_lines = Vec::new();
    let receipt = migrate_v1_to_v2_with_progress(&request, &|| false, &mut |ev| {
        progress_lines.push(ev.to_jsonl());
    })?;

    // 1. Source v1 directory MUST be byte-for-byte untouched!
    let source_after = directory_sha256_inventory(&fixture.v1_root)?;
    assert_eq!(
        source_before, source_after,
        "v1 source deployment was mutated during migration!"
    );

    // 2. Destination v2 format detected cleanly with no `.migrate-incomplete` sentinel.
    assert!(!dest_v2.join(MIGRATE_INCOMPLETE_FILENAME).exists());
    assert!(dest_v2.join(MIGRATION_RECEIPT_FILENAME).is_file());
    assert!(matches!(
        detect_deployment_format(&dest_v2)?,
        DeploymentFormatVersion::V2 { .. }
    ));
    let _v2_layout = require_v2_deployment(&dest_v2)?;

    // 3. Receipt fields, counts, orphan reporting, and independent cryptographic equivalence.
    assert!(receipt.semantic_equivalence_verified);
    assert!(receipt.effects_verified);
    assert!(receipt.batches_migrated >= 6);
    assert!(receipt.objects_migrated >= 5);
    assert!(receipt.roots_migrated >= 1);
    assert_eq!(receipt.events_migrated, 1);
    assert_eq!(receipt.holds_migrated, 1);
    assert_eq!(receipt.masks_migrated, 1);
    assert!(receipt.tombstones_migrated >= 1);
    assert_eq!(receipt.agent_files_verified, 1);
    assert_eq!(
        receipt.source_unreferenced_orphans,
        vec![fixture.orphan_digest],
        "v1 orphan must be explicitly reported, never silently adopted or lost"
    );
    receipt.verify_equivalence(&fixture.v1_root, &dest_v2)?;

    // Structured JSONL progress emitted.
    assert!(
        progress_lines
            .iter()
            .any(|l| l.contains("\"schema\":\"fss.migration_progress.v1\""))
    );

    // 4. Verify v2 PackStore directly: sealed packs exist in objects/packs/, orphan NOT adopted.
    let packs_dir = dest_v2.join("objects/packs");
    assert!(packs_dir.is_dir());
    let has_fssp = fs::read_dir(&packs_dir)?
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().ends_with(".fssp"));
    assert!(
        has_fssp,
        "expected sealed .fssp packfile in dest/objects/packs/"
    );

    let pack_store = PackStore::open(&dest_v2, PackConfig::default())?;
    assert!(
        pack_store.lookup(&fixture.orphan_digest)?.is_none(),
        "orphan must NOT be adopted into v2 pack store"
    );
    assert!(
        pack_store
            .read_verified(&fixture.mask_policy_digest)
            .is_ok(),
        "privacy mask policy must be readable and SHA-256 verified in v2 PackStore"
    );
    drop(pack_store);

    // 5. Verify v2 MVCC ProjectionStore directly: multi-rev event, hold, mask, tombstone!
    let epoch_ledger = MerkleEpochLedger::open(
        dest_v2.join("ledger"),
        SITE,
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let proj_store = MvccProjectionStore::open_or_rebuild_with_config(
        dest_v2.join("projections/mvcc"),
        &epoch_ledger,
        &fss_projection_store::NoopPayloadResolver,
        ProjectionStoreConfig {
            durability: DurabilityMode::Fsync,
            wal_sync: WalSyncPolicy::FlushOnly,
            history_mode: HistoryChainMode::V2MerkleEpoch,
            ..ProjectionStoreConfig::default()
        },
    )?;
    let snap = proj_store.snapshot_latest();
    assert_eq!(snap.state_digest(), receipt.projection_state_digest);

    // Multi-revision event materialized with both rev 1 and rev 2!
    let ev = snap
        .get_event(&fixture.event_id)
        .ok_or("missing migrated event in MVCC projection")?;
    assert_eq!(ev.revision, 2);
    assert_eq!(ev.state, EventState::Corroborated);
    assert!(snap.get_event_revision(&fixture.event_id, 1).is_some());
    assert!(snap.get_event_revision(&fixture.event_id, 2).is_some());

    // Evidence hold materialized!
    let hold = snap
        .get_hold("hold-incident-1")
        .ok_or("missing migrated hold in MVCC projection")?;
    assert!(hold.active);
    assert_eq!(hold.target_digest, fixture.held_import);

    // Privacy mask policy materialized!
    let mask = snap
        .get_privacy_mask(&fixture.mask_sensor)
        .ok_or("missing migrated privacy mask in MVCC projection")?;
    assert_eq!(mask.policy_digest, fixture.mask_policy_digest);

    // Held import remains present while deleted import was tombstoned/retracted!
    assert!(snap.get_footage_import(&fixture.held_import).is_some());
    assert!(
        snap.get_footage_import(&fixture.deleted_import).is_none(),
        "completed deletion must tombstone/retract deleted import from MVCC projection"
    );

    Ok(())
}

#[test]
fn refuses_existing_destination_without_touching_it() -> TestResult {
    let ws = TempWorkspace::new("dest-exists")?;
    let fixture = build_rich_v1_deployment(&ws.0)?;
    let existing_dest = ws.0.join("already-here");
    fs::create_dir(&existing_dest)?;
    let sentinel = existing_dest.join("precious.txt");
    fs::write(&sentinel, b"do-not-touch")?;

    let req = MigrationRequest::new(&fixture.v1_root, &existing_dest);
    let err = migrate_v1_to_v2(&req, &|| false);
    assert!(matches!(err, Err(MigrationError::DestinationExists { .. })));
    assert_eq!(fs::read(&sentinel)?, b"do-not-touch");
    assert!(!existing_dest.join(MIGRATE_INCOMPLETE_FILENAME).exists());
    Ok(())
}

#[test]
fn interrupted_migration_leaves_sentinel_and_is_strictly_refused() -> TestResult {
    let ws = TempWorkspace::new("cancelled")?;
    let fixture = build_rich_v1_deployment(&ws.0)?;
    let dest_v2 = ws.0.join("interrupted-v2");
    let source_before = directory_sha256_inventory(&fixture.v1_root)?;

    let cancel_now = AtomicBool::new(false);
    let ledger_steps = AtomicUsize::new(0);
    let req = MigrationRequest::new(&fixture.v1_root, &dest_v2);
    let result =
        migrate_v1_to_v2_with_progress(&req, &|| cancel_now.load(Ordering::SeqCst), &mut |ev| {
            if ev.stage == "stream_ledger" {
                let n = ledger_steps.fetch_add(1, Ordering::SeqCst) + 1;
                if n >= 2 {
                    cancel_now.store(true, Ordering::SeqCst);
                }
            }
        });

    assert!(matches!(
        result,
        Err(MigrationError::Cancelled {
            stage: "stream_ledger"
        })
    ));
    assert!(dest_v2.join(MIGRATE_INCOMPLETE_FILENAME).is_file());
    assert!(matches!(
        detect_deployment_format(&dest_v2)?,
        DeploymentFormatVersion::MigrateIncomplete { .. }
    ));
    let refused = require_v2_deployment(&dest_v2);
    assert!(matches!(
        refused,
        Err(MigrationError::IncompleteMigration { .. })
    ));
    if let Err(err) = refused {
        assert_eq!(err.stable_id(), ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001);
    }

    // Source v1 still byte-for-byte untouched!
    assert_eq!(source_before, directory_sha256_inventory(&fixture.v1_root)?);
    Ok(())
}

#[test]
fn refuses_unclean_v1_source_with_corrupt_ledger_tail() -> TestResult {
    let ws = TempWorkspace::new("unclean-tail")?;
    let fixture = build_rich_v1_deployment(&ws.0)?;

    // Append an incomplete/garbage tail to v1 ledger/journal.fssj.
    let ledger_path = fixture.v1_root.join("ledger/journal.fssj");
    let mut f = fs::OpenOptions::new().append(true).open(&ledger_path)?;
    f.write_all(b"FSSJRN01truncated")?;
    f.sync_all()?;
    drop(f);

    let dest_v2 = ws.0.join("should-not-exist-v2");
    let req = MigrationRequest::new(&fixture.v1_root, &dest_v2);
    let err = migrate_v1_to_v2(&req, &|| false);
    assert!(
        matches!(err, Err(MigrationError::SourceNotClean { .. })),
        "expected SourceNotClean, got {err:?}"
    );
    assert!(
        !dest_v2.exists(),
        "destination must never be created when v1 source preflight fails"
    );
    Ok(())
}
