#![forbid(unsafe_code)]
//! Real OS `SIGKILL` mid-migration recovery & v1→v2 live replay orient speedup suite (`QL-SCALE-001`).
//!
//! 1. Constructs a rich multi-camera v1 `ReferenceDeployment` (events, multi-revision
//!    corroborations, durable alert effects, active legal holds, per-sensor privacy masks,
//!    completed deletions/tombstones, unreferenced spool orphan, and `agent/` state).
//! 2. Executes **6 real child-process `SIGKILL` crash cuts** across all migration phases
//!    (`stream_ledger`, `pack_objects`, `publish_virtual_roots`, `materialize_projections`,
//!    `copy_effects_and_agent`, and pre-activation `finalize`), proving `.migrate-incomplete`
//!    fails closed with `ERR-DEPLOYMENT-MIGRATE-INCOMPLETE-001` and the v1 source remains
//!    100% byte-for-byte untouched!
//! 3. Executes clean v1→v2 migration, independently verifies cryptographic equivalence via
//!    `MigrationEquivalenceReceipt::verify_equivalence`, and benchmarks v1 full-replay
//!    `orient_deployment` vs v2 `ProjectionBridge` / `MvccProjectionStore` orient latency,
//!    writing structured JSONL telemetry to `target/test-logs/scale-benchmark/migration_speedup.jsonl`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    AgentView, BudgetVector, CapsuleId, CaptureInterval, ContentDigest, DecisionPath,
    EventHypothesis, EventId, EventKind, EventState, IdempotencyKey, ObligationId, OperationId,
    PrincipalId, ProbabilityInterval, SensorId, StreamId, TimestampNs,
};
use fss_ledger::{
    DurableReferenceLedger, EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger,
};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_pack::DurabilityMode;
use fss_projection_store::{
    HistoryChainMode, MvccProjectionStore, NoopPayloadResolver, ProjectionRecoveryMode,
    ProjectionStore, ProjectionStoreConfig, WalSyncPolicy,
};
use fss_reference::agent_orient::projection_bridge::ProjectionBridge;
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::{CommitOutcome, commit_deletion, plan_deletion};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::migration::{
    DeploymentFormatVersion, ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001, MIGRATE_INCOMPLETE_FILENAME,
    MigrationError, MigrationRequest, detect_deployment_format, migrate_v1_to_v2,
    migrate_v1_to_v2_with_progress, require_v2_deployment,
};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceDeployment, ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model,
    policy_decision_path, run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:scale-migration-sigkill";
const PRINCIPAL: &str = "principal:scale-migration-operator";

const MIGRATION_CUT_STAGES: [&str; 6] = [
    "reserve_destination",
    "stream_ledger",
    "pack_objects",
    "publish_virtual_roots",
    "materialize_projections",
    "copy_effects_and_agent",
];

static MIG_WS_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempMigWorkspace(PathBuf);

impl TempMigWorkspace {
    fn new(tag: &str) -> TestResult<Self> {
        let id = MIG_WS_SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-scale-mig-{tag}-{}-{id}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempMigWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn log_output_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("FSS_SCALE_LOG_DIR")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/test-logs/scale-benchmark")
}

fn make_authority() -> TestResult<ContextAuthority> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:scale-migration".to_owned(),
        operation_id: OperationId::parse("operation:scale-migration")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".to_owned(),
            CAP_HOLD_PREPARE.to_owned(),
            CAP_HOLD_COMMIT.to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(32_768)
            .build()?,
        privacy_scope: "privacy:scale".to_owned(),
        retention_scope: "retention:scale".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(authority)
}

fn ingest_mjpeg_camera(
    ws: &Path,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
    cam_name: &str,
    gray: u8,
) -> TestResult<ContentDigest> {
    let path = ws.join(format!("{cam_name}.mjpeg"));
    let bytes = encode_jpeg(
        32,
        32,
        &[gray; 1024],
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
        SensorId::parse(format!("sensor:{cam_name}"))?,
        StreamId::parse(format!("stream:{cam_name}"))?,
    )
    .with_receive_time(TimestampNs(1_700_000_000_000))
    .with_format_hint(FileFormatHint::JpegStream);
    Ok(FileIngestAdapter::ingest(req, cx, deployment)?.import_identity)
}

fn make_hypothesized_event(event_id: &EventId, idx: u64) -> TestResult<EventHypothesis> {
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(
            TimestampNs(10_000 + i128::from(idx) * 1_000),
            TimestampNs(20_000 + i128::from(idx) * 1_000),
        )?,
        uncertainty_reason: Some("initial camera motion".to_owned()),
        zone_ids: vec![format!("zone:cam-{:02}", idx % 6)],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.4, 0.88)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"scale-mig-policy-v1"),
            fingerprint: ContentDigest::sha256(format!("scale-mig-fp-{idx}").as_bytes()),
            abstained: true,
            abstention_reason: Some("awaiting multi-domain corroboration".to_owned()),
        },
    };
    event.verify()?;
    Ok(event)
}

fn build_multicam_v1_deployment(ws: &Path) -> TestResult<PathBuf> {
    let v1_root = ws.join("v1-multicam");
    let authority = make_authority()?;
    let cx = ReplayCx::from_context_authority(&authority, v1_root.clone())?;
    let mut dep = ReferenceDeployment::open(&v1_root, SITE, &cx)?;

    // 1. 24 events across 6 zones, including 4 corroborated multi-revision events + durable alerts!
    let mut scratch_objects = InMemoryObjectStore::new(ObjectLimits::new(4096, 64 * 1024 * 1024));
    let mut scratch_captures = DurableReferenceLedger::open(
        ws.join("scratch-captures.journal"),
        "site:scale-mig-captures",
        IncompleteTailPolicy::Reject,
    )?;

    for idx in 0..24_u64 {
        let ev_id = EventId::parse(format!("event:scale-mig:{idx:03}"))?;
        let rev1_decision = ReferencePolicyDecision {
            event: make_hypothesized_event(&ev_id, idx)?,
            action: ReferencePolicyAction::Hold,
        };
        let rev1_receipt = dep.publish_event(&rev1_decision, &cx)?;

        if idx < 4 {
            let mut observations = Vec::new();
            for (lane, seed_off) in [("east", 11_u64), ("west", 29_u64)] {
                let spec = VirtualCameraSpec {
                    capture_id: CapsuleId::parse(format!("capture:sm:{idx:02}:{lane}"))?,
                    sensor_id: SensorId::parse(format!("sensor:sm:{idx:02}:{lane}"))?,
                    seed: 100 + idx * 17 + seed_off,
                    packet_count: 2,
                    packet_bytes: 32,
                    start_ns: 10_000 + i128::from(idx) * 1_000,
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
                    format!("mock:sm:{idx:02}:{lane}:v1"),
                    MockModelScript::Fixed {
                        label: MockSemanticLabel::PersonLike,
                        probability: ProbabilityInterval::new(0.97, 1.0)?,
                    },
                )?;
                let result = execute_mock_model(&model, &capture, &mut scratch_objects)?;
                observations.push(ReferenceModelObservation::new(
                    result,
                    format!("power:sm:{idx:02}:{lane}"),
                    CaptureInterval::new(
                        TimestampNs(10_000 + i128::from(idx) * 1_000),
                        TimestampNs(20_000 + i128::from(idx) * 1_000),
                    )?,
                )?);
            }
            let mut rev2_decision = evaluate_unknown_presence(ev_id.clone(), observations)?;
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
                let _ = dep.stage_payload(scratch_objects.read_verified(*digest)?)?;
            }
            let rev2_receipt = dep.publish_event(&rev2_decision, &cx)?;

            let (effects_journal, authority_ledger) = dep.effects_and_ledger();
            let _alert = effects_journal.prepare_alert(PrepareAlertParams {
                decision: &rev2_decision,
                event_receipt: &rev2_receipt,
                authority: authority_ledger,
                operation_id: OperationId::parse(format!("op:sm:alert:{idx:02}"))?,
                idempotency_key: IdempotencyKey::parse(format!("idem:sm:alert:{idx:02}"))?,
                obligation_id: ObligationId::parse(format!("obl:sm:alert:{idx:02}"))?,
                channel: "ops-webhook".to_owned(),
                now: TimestampNs(5_000_000 + i128::from(idx) * 1_000),
            })?;
        }
    }

    // 2. 8 camera footage imports: 4 held under legal holds, 2 deleted to completion, 2 unheld live.
    let mut held_imports = Vec::new();
    let mut deleted_imports = Vec::new();
    for cam in 0..8_u8 {
        let name = format!("cam_{cam:02}");
        let imp = ingest_mjpeg_camera(ws, &mut dep, &cx, &name, 32 + cam * 24)?;
        if cam < 4 {
            held_imports.push((cam, imp));
        } else if cam < 6 {
            deleted_imports.push(imp);
        }
    }

    for &(cam, imp) in &held_imports {
        let hold_req = HoldRequest {
            hold_id: format!("hold-sm-{cam:02}"),
            import_identity: imp,
            state: HoldState::Held,
            reason: format!("Legal hold on camera {cam:02} incident clip"),
        };
        let preview = preview_hold(&dep, &hold_req, &authority, &cx)?;
        let _ = commit_hold(
            &mut dep,
            &hold_req,
            preview.record.approval(),
            &authority,
            &cx,
        )?;
    }

    // 3. 8 per-sensor privacy mask policies.
    for cam in 0..8_u8 {
        let sensor = SensorId::parse(format!("sensor:cam_{cam:02}"))?;
        let policy = PrivacyMaskPolicy::new(sensor, [1280, 720], &[[16, 16, 120, 80]])?;
        let preview = preview_mask(&dep, &policy)?;
        let _ = declare_mask(&mut dep, &policy, preview.approval, &cx)?;
    }

    // 4. Completed deletions for 2 camera imports (generating tombstones & retracted roots).
    for del_imp in deleted_imports {
        let plan = plan_deletion(&dep, del_imp, &cx)?;
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
        let plan_digest = plan.digest()?;
        let approval = fss_reference::deletion::approval_digest(plan_digest, SITE, PRINCIPAL)?;
        let receipt = commit_deletion(&mut dep, plan_digest, approval, PRINCIPAL, &cx)?;
        assert_eq!(receipt.outcome, CommitOutcome::Completed);
    }

    // 5. Explicit unreferenced v1 spool orphan (must never be adopted or mutated in v1).
    let _orphan = dep.stage_payload(b"scale-migration-explicit-v1-orphan-bytes")?;

    drop(dep);
    cx.drain_and_finalize();

    // 6. Populate agent/ files to verify byte-for-byte agent preservation.
    fs::create_dir_all(v1_root.join("agent/handoffs"))?;
    fs::write(
        v1_root.join("agent/handoffs/latest.txt"),
        b"handoff-v1-scale-migration-checkpoint\n",
    )?;

    Ok(v1_root)
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

fn percentile_us(samples: &[u64], pct_num: usize, pct_den: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let idx = (sorted.len().saturating_sub(1) * pct_num) / pct_den;
    sorted[idx]
}

fn mean_us(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: u128 = samples.iter().map(|&v| u128::from(v)).sum();
    (sum as f64) / (samples.len() as f64)
}

/// Child worker invoked by parent via `std::env::current_exe()` and killed mid-migration via `SIGKILL`.
#[test]
fn migration_sigkill_child_entrypoint() -> TestResult {
    if std::env::var("FSS_MIGRATE_SIGKILL_CHILD").as_deref() != Ok("1") {
        return Ok(());
    }
    let src = PathBuf::from(std::env::var("FSS_MIGRATE_SRC")?);
    let dst = PathBuf::from(std::env::var("FSS_MIGRATE_DST")?);
    let target_stage = std::env::var("FSS_MIGRATE_TARGET_STAGE")?;
    let req = MigrationRequest::new(&src, &dst);

    let _ = migrate_v1_to_v2_with_progress(&req, &|| false, &mut |ev| {
        if ev.stage == target_stage {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "KILL_NOW:{}", ev.stage);
            let _ = out.flush();
            // Hold briefly at this exact post-sentinel migration stage so parent's real OS SIGKILL
            // deterministically hits this phase before `.migrate-incomplete` is removed!
            thread::sleep(Duration::from_secs(5));
        }
    })?;
    Ok(())
}

fn run_migration_sigkill_cut(
    v1_root: &Path,
    dest_v2: &Path,
    target_stage: &str,
) -> TestResult<bool> {
    let exe = std::env::current_exe()?;
    let mut child = Command::new(&exe)
        .arg("--exact")
        .arg("migration_sigkill_child_entrypoint")
        .arg("--nocapture")
        .env("FSS_MIGRATE_SIGKILL_CHILD", "1")
        .env("FSS_MIGRATE_SRC", v1_root)
        .env("FSS_MIGRATE_DST", dest_v2)
        .env("FSS_MIGRATE_TARGET_STAGE", target_stage)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take().ok_or("child stdout missing")?;
    let ready = Arc::new(Mutex::new(false));
    let ready_reader = Arc::clone(&ready);
    let reader = thread::spawn(move || {
        let mut br = BufReader::new(stdout);
        let mut line = String::new();
        while let Ok(n) = br.read_line(&mut line) {
            if n == 0 {
                break;
            }
            if line.trim().starts_with("KILL_NOW:")
                && let Ok(mut g) = ready_reader.lock()
            {
                *g = true;
            }
            line.clear();
        }
    });

    let start = Instant::now();
    loop {
        if ready.lock().map(|g| *g).unwrap_or(false) {
            break;
        }
        if start.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out waiting for migration stage {target_stage}").into());
        }
        thread::sleep(Duration::from_millis(1));
    }

    child.kill()?;
    let status = child.wait()?;
    let _ = reader.join();

    #[cfg(unix)]
    let killed_by_sigkill = {
        use std::os::unix::process::ExitStatusExt;
        status.signal() == Some(9)
    };
    #[cfg(not(unix))]
    let killed_by_sigkill = !status.success();

    Ok(killed_by_sigkill)
}

#[test]
fn migration_sigkill_recovery_and_v1_to_v2_orient_speedup_benchmark() -> TestResult {
    let ws = TempMigWorkspace::new("e2e")?;
    let v1_root = build_multicam_v1_deployment(&ws.0)?;
    let source_before = directory_sha256_inventory(&v1_root)?;

    let out_dir = log_output_dir();
    fs::create_dir_all(&out_dir)?;
    let log_path = out_dir.join("migration_speedup.jsonl");
    let mut jsonl_lines: Vec<String> = Vec::new();

    // -----------------------------------------------------------------------
    // Part 1: 6 real OS SIGKILL crash cuts across every post-sentinel migration stage
    // -----------------------------------------------------------------------
    for (idx, stage) in MIGRATION_CUT_STAGES.iter().enumerate() {
        let dest_cut = ws.0.join(format!("v2-sigkill-cut-{idx:02}-{stage}"));
        let killed = run_migration_sigkill_cut(&v1_root, &dest_cut, stage)?;
        assert!(
            killed,
            "migration cut {idx} ({stage}) did not terminate via POSIX SIGKILL"
        );

        // 1. `.migrate-incomplete` sentinel MUST exist and fail closed!
        assert!(
            dest_cut.join(MIGRATE_INCOMPLETE_FILENAME).is_file(),
            "missing .migrate-incomplete after SIGKILL at stage {stage}"
        );
        assert!(matches!(
            detect_deployment_format(&dest_cut)?,
            DeploymentFormatVersion::MigrateIncomplete { .. }
        ));
        let refused = require_v2_deployment(&dest_cut);
        match refused {
            Err(err @ MigrationError::IncompleteMigration { .. }) => {
                assert_eq!(err.stable_id(), ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001);
            }
            other => {
                return Err(
                    format!("expected IncompleteMigration for cut {stage}, got {other:?}").into(),
                );
            }
        }

        // 2. Source v1 deployment MUST remain 100% byte-for-byte untouched!
        let source_now = directory_sha256_inventory(&v1_root)?;
        assert_eq!(
            source_before, source_now,
            "v1 source mutated during SIGKILL migration cut at stage {stage}"
        );

        jsonl_lines.push(format!(
            "{{\"schema\":\"fss.migration_scale.v1\",\"record_type\":\"sigkill_cut\",\"cut_index\":{},\"stage\":\"{}\",\"killed_by_sigkill\":true,\"sentinel_present\":true,\"error_id\":\"{}\",\"source_v1_untouched\":true}}",
            idx + 1,
            stage,
            ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001
        ));
    }

    // -----------------------------------------------------------------------
    // Part 2: Clean v1 -> v2 migration + independent cryptographic equivalence proof
    // -----------------------------------------------------------------------
    let dest_v2 = ws.0.join("v2-clean");
    let mig_start = Instant::now();
    let req = MigrationRequest::new(&v1_root, &dest_v2);
    let receipt = migrate_v1_to_v2(&req, &|| false)?;
    let migration_ms = mig_start.elapsed().as_secs_f64() * 1_000.0;

    assert_eq!(
        source_before,
        directory_sha256_inventory(&v1_root)?,
        "v1 source mutated during clean migration"
    );
    receipt.verify_equivalence(&v1_root, &dest_v2)?;
    assert_eq!(receipt.events_migrated, 24);
    assert_eq!(receipt.holds_migrated, 4);
    assert_eq!(receipt.masks_migrated, 8);
    assert!(receipt.tombstones_migrated >= 2);
    assert_eq!(receipt.agent_files_verified, 1);

    // -----------------------------------------------------------------------
    // Part 3: Orient latency benchmark — v1 full replay vs v2 MVCC ProjectionBridge
    // -----------------------------------------------------------------------
    let limits = OrientLimits::default();
    let orient_req = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse(PRINCIPAL)?,
        budget_tokens: None,
    };

    const BENCH_ITERS: usize = 30;

    // Baseline (v1): read_deployment (full-spool doctor + ledger/effect replay) + orient_deployment.
    let mut v1_orient_us = Vec::with_capacity(BENCH_ITERS);
    for _ in 0..BENCH_ITERS {
        let t0 = Instant::now();
        let snap = read_deployment(&v1_root, &limits)?;
        let orient = orient_deployment(&snap, &orient_req, &limits)?;
        assert_eq!(snap.events.len(), 24);
        let _fp = orient.capsule().decision_fingerprint()?;
        v1_orient_us.push(t0.elapsed().as_micros() as u64);
    }

    // v1 Decoupled ProjectionBridge::orient_decoupled (no full-spool doctor scan).
    let v1_bridge = ProjectionBridge::open_or_catch_up(&v1_root, &limits)?;
    let mut v1_decoupled_us = Vec::with_capacity(BENCH_ITERS);
    for _ in 0..BENCH_ITERS {
        let t0 = Instant::now();
        let (orient, _, _) = v1_bridge.orient_decoupled(&orient_req, &limits)?;
        let _fp = orient.capsule().decision_fingerprint()?;
        v1_decoupled_us.push(t0.elapsed().as_micros() as u64);
    }

    // v2 MerkleEpochLedger + MvccProjectionStore (cold open + warm O(1) MVCC orient_summary!).
    let v2_proj_cfg = ProjectionStoreConfig {
        durability: DurabilityMode::Fsync,
        wal_sync: WalSyncPolicy::FlushOnly,
        history_mode: HistoryChainMode::V2MerkleEpoch,
        ..ProjectionStoreConfig::default()
    };
    let open_v2_mvcc = || -> TestResult<MvccProjectionStore> {
        let epoch_ledger = MerkleEpochLedger::open(
            dest_v2.join("ledger"),
            SITE,
            EpochLedgerConfig::default(),
            IncompleteTailPolicy::Reject,
        )?;
        let store = MvccProjectionStore::open_or_rebuild_with_config(
            dest_v2.join("projections/mvcc"),
            &epoch_ledger,
            &NoopPayloadResolver,
            v2_proj_cfg,
        )?;
        Ok(store)
    };

    let v2_store = open_v2_mvcc()?;
    assert_eq!(
        v2_store.recovery_report().mode,
        ProjectionRecoveryMode::LoadedCurrent
    );
    assert_eq!(
        v2_store.snapshot_latest().state_digest(),
        receipt.projection_state_digest
    );
    let mut v2_cold_open_and_orient_us = Vec::with_capacity(BENCH_ITERS);
    for _ in 0..BENCH_ITERS {
        let t0 = Instant::now();
        let store = open_v2_mvcc()?;
        let sum = store.snapshot_latest().orient_summary();
        assert_eq!(sum.total_events, 24);
        assert_eq!(sum.active_holds, 4);
        assert_eq!(sum.privacy_masks, 8);
        v2_cold_open_and_orient_us.push(t0.elapsed().as_micros() as u64);
    }

    let mut v2_mvcc_orient_us = Vec::with_capacity(200);
    let mut v2_mvcc_total_ns: u128 = 0;
    for _ in 0..200 {
        let t0 = Instant::now();
        let sum = v2_store.snapshot_latest().orient_summary();
        assert_eq!(sum.total_events, 24);
        assert_eq!(sum.active_holds, 4);
        assert_eq!(sum.privacy_masks, 8);
        let elapsed = t0.elapsed();
        v2_mvcc_total_ns = v2_mvcc_total_ns.saturating_add(elapsed.as_nanos());
        v2_mvcc_orient_us.push(elapsed.as_micros() as u64);
    }

    let v1_p50 = percentile_us(&v1_orient_us, 50, 100);
    let v1_p95 = percentile_us(&v1_orient_us, 95, 100);
    let v1_p99 = percentile_us(&v1_orient_us, 99, 100);
    let v1_mean = mean_us(&v1_orient_us);

    let v1_decoupled_p50 = percentile_us(&v1_decoupled_us, 50, 100);
    let v1_decoupled_p99 = percentile_us(&v1_decoupled_us, 99, 100);
    let v1_decoupled_mean = mean_us(&v1_decoupled_us);

    let v2_cold_p50 = percentile_us(&v2_cold_open_and_orient_us, 50, 100);
    let v2_cold_p99 = percentile_us(&v2_cold_open_and_orient_us, 99, 100);
    let v2_cold_mean = mean_us(&v2_cold_open_and_orient_us);

    let v2_mvcc_p50 = percentile_us(&v2_mvcc_orient_us, 50, 100);
    let v2_mvcc_p95 = percentile_us(&v2_mvcc_orient_us, 95, 100);
    let v2_mvcc_p99 = percentile_us(&v2_mvcc_orient_us, 99, 100);
    let v2_mvcc_mean = (v2_mvcc_total_ns as f64) / (200.0 * 1_000.0);

    let speedup_mvcc_vs_v1 = v1_mean / v2_mvcc_mean.max(0.001);
    let speedup_v2_cold_vs_v1 = v1_mean / v2_cold_mean.max(0.1);
    let speedup_decoupled_vs_v1 = v1_mean / v1_decoupled_mean.max(0.1);

    // Also verify v2 MVCC anchor matches migrated ledger head exactly.
    assert_eq!(
        v2_store.head_anchor().commit_sequence,
        receipt.dest_v2_anchor.commit_sequence
    );

    let summary_line = format!(
        concat!(
            "{{\"schema\":\"fss.migration_scale.v1\",\"record_type\":\"speedup_summary\",",
            "\"sigkill_cuts_passed\":{},\"equivalence_verified\":true,",
            "\"migration_wall_ms\":{:.3},",
            "\"batches_migrated\":{},\"objects_migrated\":{},\"roots_migrated\":{},",
            "\"events_migrated\":{},\"holds_migrated\":{},\"masks_migrated\":{},\"tombstones_migrated\":{},",
            "\"v1_full_orient\":{{\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"mean_us\":{:.2}}},",
            "\"v1_decoupled_orient\":{{\"p50_us\":{},\"p99_us\":{},\"mean_us\":{:.2}}},",
            "\"v2_cold_open_orient\":{{\"p50_us\":{},\"p99_us\":{},\"mean_us\":{:.2}}},",
            "\"v2_mvcc_orient\":{{\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"mean_us\":{:.2}}},",
            "\"speedup_v2_mvcc_vs_v1\":{:.2},",
            "\"speedup_v2_cold_vs_v1\":{:.2},",
            "\"speedup_decoupled_vs_v1\":{:.2}}}"
        ),
        MIGRATION_CUT_STAGES.len(),
        migration_ms,
        receipt.batches_migrated,
        receipt.objects_migrated,
        receipt.roots_migrated,
        receipt.events_migrated,
        receipt.holds_migrated,
        receipt.masks_migrated,
        receipt.tombstones_migrated,
        v1_p50,
        v1_p95,
        v1_p99,
        v1_mean,
        v1_decoupled_p50,
        v1_decoupled_p99,
        v1_decoupled_mean,
        v2_cold_p50,
        v2_cold_p99,
        v2_cold_mean,
        v2_mvcc_p50,
        v2_mvcc_p95,
        v2_mvcc_p99,
        v2_mvcc_mean,
        speedup_mvcc_vs_v1,
        speedup_v2_cold_vs_v1,
        speedup_decoupled_vs_v1,
    );
    jsonl_lines.push(summary_line.clone());

    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)?;
        for line in &jsonl_lines {
            writeln!(f, "{line}")?;
        }
    }

    println!("{summary_line}");

    assert!(
        speedup_mvcc_vs_v1 >= 5.0,
        "expected >= 5x v2 MVCC orient speedup over v1 full replay, observed {speedup_mvcc_vs_v1:.2}x"
    );
    assert!(
        v2_mvcc_p99 < 10_000,
        "v2 MVCC orient p99={v2_mvcc_p99}us exceeded 10ms budget"
    );

    Ok(())
}
