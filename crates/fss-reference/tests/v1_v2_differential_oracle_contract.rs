#![forbid(unsafe_code)]
//! 500-Seed v1 vs v2 Differential Oracle Equivalence Suite (bead `fss-x4a.31.1.7` / `A7`):
//! - Executes 500 seeded deterministic random operation streams (imports, events, multi-rev updates,
//!   2-domain corroborations, legal holds + releases, per-sensor privacy masks, deletions/tombstones,
//!   source coverage witnesses, durable + indeterminate alert effects, and refusal error paths)
//!   against `v1 ReferenceDeployment`;
//! - Migrates every stream non-destructively into `v2` (`MerkleEpochLedger` + `PackStore` +
//!   `MvccProjectionStore`) via `migrate_v1_to_v2` and projects via `ProjectionBridge`;
//! - Asserts on EVERY SINGLE SEED (500/500):
//!   1. Exact equality of all query answers (events, holds, privacy masks, tombstones, footage,
//!      coverage, and durable/indeterminate effects);
//!   2. Bit-exact `SituationCapsule` fields, `publication_digest`, and `decisionFingerprint`
//!      parity between `orient_v1` (`read_deployment` + `orient_deployment`) and
//!      `ProjectionBridge::orient_decoupled`;
//!   3. Full custody audit equivalence (live roots, object closures, deletion index, local
//!      tombstones, Merkle object map, effects journal) and exact registered refusal error IDs;
//! - Emits per-seed and summary pure-Rust JSONL telemetry (including latency percentiles) to
//!   `target/test-logs/scale-storage/v1_v2_differential_oracle.jsonl`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis,
    ContentDigest, DecisionPath, EffectState, EventHypothesis, EventId, EventKind, EventState,
    IdempotencyKey, ObligationId, OperationId, PrincipalId, ProbabilityInterval, SensorCapsule,
    SensorId, StreamId, TimestampNs,
};
use fss_ledger::{
    DurableReferenceLedger, EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger,
    inspect_durable,
};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_pack::{DurabilityMode, PackConfig, PackStore};
use fss_projection_store::{
    EventQueryFilter, FootageQueryFilter, HistoryChainMode, MvccProjectionStore,
    NoopPayloadResolver, ProjectionRecoveryMode, ProjectionStore, ProjectionStoreConfig,
    WalSyncPolicy,
};
use fss_reference::DurableEffectJournal;
use fss_reference::agent_orient::projection_bridge::ProjectionBridge;
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, list_holds,
    preview_hold,
};
use fss_reference::deletion::{
    CommitOutcome, DeletionError, DeletionIndex, approval_digest, commit_deletion, plan_deletion,
};
use fss_reference::ingest::privacy_mask::{
    PrivacyMaskPolicy, current_mask, declare_mask, preview_mask,
};
use fss_reference::ingest::source_coverage::{
    SourceCoverageError, SourceCoverageInput, build_source_coverage, retain_source_coverage,
};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::migration::{
    DeploymentFormatVersion, ERR_DEPLOYMENT_FORMAT_V1_001, ERR_MIGRATION_DESTINATION_EXISTS_001,
    ERR_MIGRATION_SOURCE_ALREADY_V2_001, MigrationError, MigrationRequest,
    detect_deployment_format, migrate_v1_to_v2, require_v2_deployment,
};
use fss_reference::reference_deployment::DeploymentLimits;
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceDeployment, ReferenceModelObservation, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model,
    policy_decision_path, run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SUITE_NAME: &str = "v1_v2_differential_oracle";
const PRINCIPAL: &str = "principal:diff-oracle-a7";
const TOTAL_SEEDS: u64 = 500;
const WORKER_THREADS: usize = 4;

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static LOG_LOCK: Mutex<()> = Mutex::new(());

struct TempSeedWorkspace(PathBuf);

impl TempSeedWorkspace {
    fn new(seed: u64) -> Result<Self, String> {
        let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-a7-diff-s{seed:03}-{}-{seq}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).map_err(|e| format!("cleanup temp dir: {e}"))?;
        }
        fs::create_dir_all(&path).map_err(|e| format!("create temp dir: {e}"))?;
        Ok(Self(path))
    }
}

impl Drop for TempSeedWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Deterministic zero-dependency SplitMix64 PRNG.
struct SeededRng(u64);

impl SeededRng {
    const fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next_u64() as usize) % upper
    }

    fn chance(&mut self, denom: usize) -> bool {
        self.range(denom) == 0
    }
}

struct SeedOutcome {
    seed: u64,
    op_count: u64,
    stage_latency_us: u64,
    pack_count: u64,
    live_bytes: u64,
    assertion_digest: ContentDigest,
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn log_targets() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        dirs.push(workspace_root.join("target/test-logs/scale-storage"));
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target_dir).join("test-logs/scale-storage");
        if !dirs.contains(&candidate) {
            dirs.push(candidate);
        }
    }
    if dirs.is_empty() {
        dirs.push(std::env::temp_dir().join("fss-test-logs/scale-storage"));
    }
    dirs
}

fn write_jsonl_lines(lines: &[String]) {
    let _guard = LOG_LOCK.lock();
    let mut wrote_any = false;
    for dir in log_targets() {
        if fs::create_dir_all(&dir).is_ok() {
            let file_path = dir.join(format!("{SUITE_NAME}.jsonl"));
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
            {
                let mut ok = true;
                for line in lines {
                    if f.write_all(line.as_bytes()).is_err() {
                        ok = false;
                        break;
                    }
                }
                if ok && f.flush().is_ok() {
                    wrote_any = true;
                }
            }
        }
    }
    if !wrote_any {
        let fallback_dir = std::env::temp_dir().join("fss-test-logs/scale-storage");
        if fs::create_dir_all(&fallback_dir).is_ok()
            && let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(fallback_dir.join(format!("{SUITE_NAME}.jsonl")))
        {
            for line in lines {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn format_jsonl_line(
    test_name: &str,
    seed: u64,
    op_count: u64,
    stage_latency_us: u64,
    pack_count: u64,
    live_bytes: u64,
    assertion_digest: ContentDigest,
    verdict: &str,
) -> String {
    format!(
        "{{\"suite\":\"{}\",\"test_name\":\"{}\",\"seed\":{},\"op_count\":{},\"stage_latency_us\":{},\"pack_count\":{},\"live_bytes\":{},\"assertion_digest\":\"{}\",\"verdict\":\"{}\"}}\n",
        escape_json(SUITE_NAME),
        escape_json(test_name),
        seed,
        op_count,
        stage_latency_us,
        pack_count,
        live_bytes,
        escape_json(&assertion_digest.to_text()),
        escape_json(verdict),
    )
}

fn preencode_jpegs() -> TestResult<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(8);
    for idx in 0..8_u8 {
        let mut pixels = [32_u8.wrapping_add(idx.wrapping_mul(28)); 256];
        pixels[0] = idx.wrapping_mul(17);
        pixels[255] = 255_u8.wrapping_sub(idx.wrapping_mul(19));
        let bytes = encode_jpeg(
            16,
            16,
            &pixels,
            &JpegConfig {
                quality: 85,
                subsampling: Subsampling::Grayscale,
                restart_interval: 0,
                custom_markers: Vec::new(),
            },
        )?;
        out.push(bytes);
    }
    Ok(out)
}

fn make_authority(site: &str) -> Result<ContextAuthority, String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:{site}"),
        operation_id: OperationId::parse(format!("operation:{site}")).map_err(|e| e.to_string())?,
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
            .build()
            .map_err(|e| e.to_string())?,
        privacy_scope: "privacy:diff-oracle".to_owned(),
        retention_scope: "retention:diff-oracle".to_owned(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })
    .map_err(|e| e.to_string())?;
    authority.validate().map_err(|e| e.to_string())?;
    Ok(authority)
}

fn make_hypothesized_event(
    event_id: &EventId,
    revision: u64,
    supersedes: Option<ContentDigest>,
    zone_idx: usize,
    seed: u64,
) -> Result<EventHypothesis, String> {
    let start = 10_000 + i128::from(revision) * 5_000 + i128::from(seed) * 10;
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: event_id.clone(),
        revision,
        supersedes,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 2_000))
            .map_err(|e| e.to_string())?,
        uncertainty_reason: Some(format!("motion hypothesis rev {revision}")),
        zone_ids: vec![format!("zone:z{zone_idx}")],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.25, 0.85).map_err(|e| e.to_string())?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"diff-oracle-policy-v1"),
            fingerprint: ContentDigest::sha256(
                format!("diff-fp-{seed}-{}-{revision}", event_id.as_str()).as_bytes(),
            ),
            abstained: true,
            abstention_reason: Some("awaiting multi-domain corroboration".to_owned()),
        },
    };
    event.verify().map_err(|e| e.to_string())?;
    Ok(event)
}

fn build_corroborated_revision(
    ws: &Path,
    dep: &mut ReferenceDeployment,
    event_id: &EventId,
    revision: u64,
    supersedes: ContentDigest,
    seed: u64,
) -> Result<ReferencePolicyDecision, String> {
    let mut scratch_objects = InMemoryObjectStore::new(ObjectLimits::new(2048, 8 * 1024 * 1024));
    let mut scratch_captures = DurableReferenceLedger::open(
        ws.join(format!("scratch-cap-{seed}-{revision}.fssj")),
        format!("site:scratch-{seed}"),
        IncompleteTailPolicy::Reject,
    )
    .map_err(|e| e.to_string())?;

    let mut observations = Vec::with_capacity(2);
    for (lane, offset) in [("a", 11_u64), ("b", 29_u64)] {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:s{seed}:{lane}:{revision}"))
                .map_err(|e| e.to_string())?,
            sensor_id: SensorId::parse(format!("sensor:s{seed}:{lane}"))
                .map_err(|e| e.to_string())?,
            seed: seed.wrapping_mul(31).wrapping_add(offset),
            packet_count: 1,
            packet_bytes: 16,
            start_ns: 20_000,
            period_ns: 1_000_000,
            uncertainty_ns: 50,
        };
        let delivery = DeliveryPlan::identity(spec.packet_count).map_err(|e| e.to_string())?;
        let capture = run_reference_capture(
            &spec,
            &delivery,
            &mut scratch_objects,
            &mut scratch_captures,
        )
        .map_err(|e| e.to_string())?;
        let model = MockModelSpec::new(
            format!("mock:s{seed}:{lane}:v1"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.96, 1.0).map_err(|e| e.to_string())?,
            },
        )
        .map_err(|e| e.to_string())?;
        let result = execute_mock_model(&model, &capture, &mut scratch_objects)
            .map_err(|e| e.to_string())?;
        observations.push(
            ReferenceModelObservation::new(
                result,
                format!("power:s{seed}:{lane}"),
                CaptureInterval::new(TimestampNs(20_000), TimestampNs(30_000))
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
        );
    }

    let mut decision =
        evaluate_unknown_presence(event_id.clone(), observations).map_err(|e| e.to_string())?;
    if decision.action != ReferencePolicyAction::PrepareAlert {
        return Err(format!(
            "seed {seed}: expected PrepareAlert for 2-domain corroboration, got {:?}",
            decision.action
        ));
    }
    decision.event.revision = revision;
    decision.event.supersedes = Some(supersedes);
    decision.event.decision_path = policy_decision_path(
        &decision.event.event_id,
        &decision.event.evidence,
        decision.event.state,
        decision.action,
    );
    decision.event.verify().map_err(|e| e.to_string())?;
    for digest in &decision.event.model_receipts {
        let bytes = scratch_objects
            .read_verified(*digest)
            .map_err(|e| e.to_string())?;
        let staged = dep.stage_payload(bytes).map_err(|e| e.to_string())?;
        if staged != *digest {
            return Err(format!("seed {seed}: staged receipt digest mismatch"));
        }
    }
    Ok(decision)
}

fn run_single_differential_seed(seed: u64, jpegs: &[Vec<u8>]) -> Result<SeedOutcome, String> {
    let started = Instant::now();
    let ws = TempSeedWorkspace::new(seed)?;
    let v1_root = ws.0.join("v1");
    let v2_root = ws.0.join("v2");
    let site = format!("site:diff-oracle-s{seed:03}");
    let mut rng = SeededRng::new(0x0500_D1FF_0000_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));

    let authority = make_authority(&site)?;
    let cx = ReplayCx::from_context_authority(&authority, v1_root.clone())
        .map_err(|e| format!("seed {seed} ReplayCx: {e}"))?;
    let mut dep = ReferenceDeployment::open(&v1_root, &site, &cx)
        .map_err(|e| format!("seed {seed} open v1: {e}"))?;

    let mut op_count: u64 = 0;

    // Ground-truth semantic expectations tracked across the seed's randomized operation stream.
    let mut expected_events: BTreeMap<EventId, (u64, EventState, bool)> = BTreeMap::new();
    let mut event_last_digest: BTreeMap<EventId, ContentDigest> = BTreeMap::new();
    let mut retained_imports: Vec<ContentDigest> = Vec::new();
    let mut deleted_imports: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut expected_holds: BTreeMap<String, (ContentDigest, bool)> = BTreeMap::new();
    let mut expected_masks: BTreeMap<SensorId, ContentDigest> = BTreeMap::new();
    let mut expected_coverage_count: usize = 0;
    let mut expected_indeterminate_ops: usize = 0;

    // 1. Ingest 2..=3 distinct synthetic MJPEG file imports.
    let num_imports = 2 + rng.range(2); // 2 or 3
    for imp_idx in 0..num_imports {
        let jpeg_idx = ((seed as usize) + imp_idx) % jpegs.len();
        let file_path = ws.0.join(format!("clip-{seed}-{imp_idx}.mjpeg"));
        fs::write(&file_path, &jpegs[jpeg_idx]).map_err(|e| e.to_string())?;
        let req = FileIngestRequest::new(
            file_path,
            SensorId::parse(format!("sensor:cam-{imp_idx}")).map_err(|e| e.to_string())?,
            StreamId::parse(format!("stream:cam-{imp_idx}")).map_err(|e| e.to_string())?,
        )
        .with_receive_time(TimestampNs(
            1_000_000_000 + i128::from(imp_idx as u64) * 100_000,
        ))
        .with_format_hint(FileFormatHint::JpegStream);
        let receipt = FileIngestAdapter::ingest(req, &cx, &mut dep)
            .map_err(|e| format!("seed {seed} ingest {imp_idx}: {e}"))?;
        retained_imports.push(receipt.import_identity);
        op_count += 1;
    }

    // 2. Publish 1..=2 initial events, multi-rev updates, optional 2-domain corroboration + durable/indeterminate alert effect!
    let num_events = 1 + rng.range(2); // 1 or 2
    for ev_idx in 0..num_events {
        let ev_id =
            EventId::parse(format!("event:s{seed:03}:e{ev_idx}")).map_err(|e| e.to_string())?;
        let rev1 = make_hypothesized_event(&ev_id, 1, None, rng.range(4), seed)?;
        let r1 = dep
            .publish_event(
                &ReferencePolicyDecision {
                    event: rev1,
                    action: ReferencePolicyAction::Hold,
                },
                &cx,
            )
            .map_err(|e| format!("seed {seed} publish rev1: {e}"))?;
        expected_events.insert(ev_id.clone(), (1, EventState::Hypothesized, false));
        event_last_digest.insert(ev_id.clone(), r1.event_revision_digest);
        op_count += 1;

        // Multi-rev update: either 2-domain corroboration + alert effect, or a rev-2 hypothesis update.
        if ev_idx == 0 && (seed.is_multiple_of(2) || rng.chance(2)) {
            let rev2_dec = build_corroborated_revision(
                &ws.0,
                &mut dep,
                &ev_id,
                2,
                r1.event_revision_digest,
                seed,
            )?;
            let r2 = dep
                .publish_event(&rev2_dec, &cx)
                .map_err(|e| format!("seed {seed} publish rev2 corroborated: {e}"))?;
            expected_events.insert(ev_id.clone(), (2, EventState::Corroborated, true));
            event_last_digest.insert(ev_id.clone(), r2.event_revision_digest);
            op_count += 1;

            // Durable alert effect in effects/journal.fssj (+ indeterminate transition on ~60% of corroborated seeds!).
            let op_id = OperationId::parse(format!("op:s{seed:03}:alert-{ev_idx}"))
                .map_err(|e| e.to_string())?;
            let idem = IdempotencyKey::parse(format!("idem:s{seed:03}:alert-{ev_idx}"))
                .map_err(|e| e.to_string())?;
            let obl_id = ObligationId::parse(format!("obl:s{seed:03}:alert-{ev_idx}"))
                .map_err(|e| e.to_string())?;
            let make_indeterminate = seed.is_multiple_of(3) || rng.chance(2);
            {
                let (effects_journal, authority_ledger) = dep.effects_and_ledger();
                let _plan = effects_journal
                    .prepare_alert(PrepareAlertParams {
                        decision: &rev2_dec,
                        event_receipt: &r2,
                        authority: authority_ledger,
                        operation_id: op_id.clone(),
                        idempotency_key: idem,
                        obligation_id: obl_id,
                        channel: "webhook-primary".to_owned(),
                        now: TimestampNs(5_000_000),
                    })
                    .map_err(|e| format!("seed {seed} prepare_alert: {e}"))?;
                if make_indeterminate {
                    effects_journal
                        .transition(
                            &op_id,
                            EffectState::Committed,
                            TimestampNs(5_000_100),
                            None,
                            None,
                        )
                        .map_err(|e| format!("seed {seed} transition committed: {e}"))?;
                    effects_journal
                        .mark_indeterminate(
                            &op_id,
                            TimestampNs(5_000_200),
                            "provider_ack_timeout_indeterminate",
                        )
                        .map_err(|e| format!("seed {seed} mark_indeterminate: {e}"))?;
                    expected_indeterminate_ops += 1;
                }
            }
            op_count += 1;
        } else if rng.chance(2) {
            let rev2 = make_hypothesized_event(
                &ev_id,
                2,
                Some(r1.event_revision_digest),
                rng.range(4),
                seed,
            )?;
            let r2 = dep
                .publish_event(
                    &ReferencePolicyDecision {
                        event: rev2,
                        action: ReferencePolicyAction::Hold,
                    },
                    &cx,
                )
                .map_err(|e| format!("seed {seed} publish rev2 hyp: {e}"))?;
            expected_events.insert(ev_id.clone(), (2, EventState::Hypothesized, false));
            event_last_digest.insert(ev_id.clone(), r2.event_revision_digest);
            op_count += 1;
        }
    }

    // 3. Place an indefinite legal hold on import #0 (+ refusal test: held deletion blocked!).
    let held_import = retained_imports[0];
    let hold_id = format!("hold-s{seed:03}-primary");
    let hold_req = HoldRequest {
        hold_id: hold_id.clone(),
        import_identity: held_import,
        state: HoldState::Held,
        reason: format!("Incident preservation for seed {seed}"),
    };
    let hold_prev = preview_hold(&dep, &hold_req, &authority, &cx)
        .map_err(|e| format!("seed {seed} preview_hold: {e}"))?;
    let _ = commit_hold(
        &mut dep,
        &hold_req,
        hold_prev.record.approval(),
        &authority,
        &cx,
    )
    .map_err(|e| format!("seed {seed} commit_hold: {e}"))?;
    expected_holds.insert(hold_id.clone(), (held_import, true));
    op_count += 1;

    // Refusal error path 1: deleting a held import MUST fail closed with ERR-DELETION-BLOCKED-001!
    let blocked_plan = plan_deletion(&dep, held_import, &cx)
        .map_err(|e| format!("seed {seed} blocked plan: {e}"))?;
    if blocked_plan.blockers.is_empty() {
        return Err(format!(
            "seed {seed}: held import deletion plan had no blockers!"
        ));
    }
    let blocked_plan_digest = blocked_plan.digest().map_err(|e| e.to_string())?;
    let blocked_approval =
        approval_digest(blocked_plan_digest, &site, PRINCIPAL).map_err(|e| e.to_string())?;
    match commit_deletion(
        &mut dep,
        blocked_plan_digest,
        blocked_approval,
        PRINCIPAL,
        &cx,
    ) {
        Err(err) if matches!(err, DeletionError::Blocked(_)) => {
            if err.stable_id() != "ERR-DELETION-BLOCKED-001" {
                return Err(format!(
                    "seed {seed}: unexpected blocked error id {}",
                    err.stable_id()
                ));
            }
        }
        other => {
            return Err(format!(
                "seed {seed}: expected DeletionError::Blocked on held import, got {other:?}"
            ));
        }
    }
    op_count += 1;

    // Optionally test a second hold that gets released (exercises active->inactive transition!).
    if retained_imports.len() >= 3 && rng.chance(3) {
        let rel_imp = retained_imports[2];
        let rel_hold_id = format!("hold-s{seed:03}-temp");
        let h_on = HoldRequest {
            hold_id: rel_hold_id.clone(),
            import_identity: rel_imp,
            state: HoldState::Held,
            reason: "Temporary review hold".to_owned(),
        };
        let p_on = preview_hold(&dep, &h_on, &authority, &cx).map_err(|e| e.to_string())?;
        let _ = commit_hold(&mut dep, &h_on, p_on.record.approval(), &authority, &cx)
            .map_err(|e| e.to_string())?;

        let h_off = HoldRequest {
            hold_id: rel_hold_id.clone(),
            import_identity: rel_imp,
            state: HoldState::Released,
            reason: "Review completed".to_owned(),
        };
        let p_off = preview_hold(&dep, &h_off, &authority, &cx).map_err(|e| e.to_string())?;
        let _ = commit_hold(&mut dep, &h_off, p_off.record.approval(), &authority, &cx)
            .map_err(|e| e.to_string())?;
        expected_holds.insert(rel_hold_id, (rel_imp, false));
        op_count += 2;
    }

    // 4. Declare 1..=2 per-sensor privacy mask policies (occasionally superseding a sensor's mask!).
    let mask_sensor_0 =
        SensorId::parse(format!("sensor:mask-s{seed:03}-0")).map_err(|e| e.to_string())?;
    let rx = 10 + (rng.range(40) as u32);
    let ry = 10 + (rng.range(40) as u32);
    let mask_pol_0 = PrivacyMaskPolicy::new(mask_sensor_0.clone(), [640, 480], &[[rx, ry, 80, 60]])
        .map_err(|e| e.to_string())?;
    let mprev_0 = preview_mask(&dep, &mask_pol_0).map_err(|e| e.to_string())?;
    let _ =
        declare_mask(&mut dep, &mask_pol_0, mprev_0.approval, &cx).map_err(|e| e.to_string())?;
    expected_masks.insert(mask_sensor_0.clone(), mask_pol_0.digest());
    op_count += 1;

    if rng.chance(3) {
        let mask_pol_0_v2 = PrivacyMaskPolicy::new(
            mask_sensor_0.clone(),
            [640, 480],
            &[[rx + 5, ry + 5, 100, 70]],
        )
        .map_err(|e| e.to_string())?;
        let mprev_v2 = preview_mask(&dep, &mask_pol_0_v2).map_err(|e| e.to_string())?;
        let _ = declare_mask(&mut dep, &mask_pol_0_v2, mprev_v2.approval, &cx)
            .map_err(|e| e.to_string())?;
        expected_masks.insert(mask_sensor_0, mask_pol_0_v2.digest());
        op_count += 1;
    }

    // 5. Retain a verified SourceCoverageRecord witness (on ~half of seeds) + refusal test on stale approval!
    if seed.is_multiple_of(2) || rng.chance(2) {
        let cov_sensor =
            SensorId::parse(format!("sensor:cov-s{seed:03}")).map_err(|e| e.to_string())?;
        let cov_stream =
            StreamId::parse(format!("stream:cov-s{seed:03}")).map_err(|e| e.to_string())?;
        let raw_frame = format!("coverage-frame-seed-{seed}").into_bytes();
        let src_digest = dep
            .stage_payload(&raw_frame)
            .map_err(|e| format!("seed {seed} stage cov src: {e}"))?;
        let interval = CaptureInterval::new(TimestampNs(100_000), TimestampNs(200_000))
            .map_err(|e| e.to_string())?;
        let capsule = SensorCapsule {
            capsule_id: CapsuleId::parse(format!("cap:cov:s{seed:03}"))
                .map_err(|e| e.to_string())?,
            sensor_id: cov_sensor,
            stream_id: cov_stream,
            sequence: 1,
            capture: interval,
            receive_time: TimestampNs(200_100),
            clock_basis: ClockBasis::DeviceMonotonic,
            source_digest: src_digest,
            source_bytes: raw_frame.len() as u64,
            frame_count: 1,
            gap_before: false,
        };
        let _cap_digest = dep
            .stage_payload(&capsule.canonical_bytes())
            .map_err(|e| format!("seed {seed} stage cov cap: {e}"))?;
        let domain_name = format!("domain:s{seed:03}");
        let mut authorized_domain = BTreeSet::new();
        authorized_domain.insert(domain_name.clone());
        let cov_record = build_source_coverage(&SourceCoverageInput {
            basis: dep.current_anchor().clone(),
            interval,
            negative_predicate: "no_unknown_person_present",
            authorized_domain,
            sources: vec![(domain_name, &capsule)],
        })
        .map_err(|e| format!("seed {seed} build_source_coverage: {e}"))?;

        // Refusal error path 2: stale/wrong coverage approval returns ERR-COVERAGE-APPROVAL-STALE-001!
        let bad_cov_approval = ContentDigest::sha256(b"wrong-coverage-approval");
        match retain_source_coverage(&mut dep, &cov_record, bad_cov_approval, &cx) {
            Err(err) if matches!(err, SourceCoverageError::StaleApproval(_)) => {
                if err.stable_id() != "ERR-COVERAGE-APPROVAL-STALE-001" {
                    return Err(format!(
                        "seed {seed}: unexpected coverage err id {}",
                        err.stable_id()
                    ));
                }
            }
            other => {
                return Err(format!(
                    "seed {seed}: expected StaleApproval, got {other:?}"
                ));
            }
        }
        let _ = retain_source_coverage(&mut dep, &cov_record, cov_record.approval_digest(), &cx)
            .map_err(|e| format!("seed {seed} retain_source_coverage: {e}"))?;
        expected_coverage_count += 1;
        op_count += 2;
    }

    // 6. Complete deletion + tombstone of unheld import #1 (testing wrong approval + post-delete refusal!).
    let del_target = retained_imports[1];
    let del_plan = plan_deletion(&dep, del_target, &cx)
        .map_err(|e| format!("seed {seed} plan_deletion: {e}"))?;
    if !del_plan.blockers.is_empty() {
        return Err(format!(
            "seed {seed}: unheld deletion unexpectedly blocked: {:?}",
            del_plan.blockers
        ));
    }
    let del_plan_digest = del_plan.digest().map_err(|e| e.to_string())?;
    let del_approval =
        approval_digest(del_plan_digest, &site, PRINCIPAL).map_err(|e| e.to_string())?;

    // Refusal error path 3: wrong deletion approval -> ERR-DELETION-APPROVAL-001!
    let wrong_del_approval = ContentDigest::sha256(b"wrong-deletion-approval");
    match commit_deletion(
        &mut dep,
        del_plan_digest,
        wrong_del_approval,
        PRINCIPAL,
        &cx,
    ) {
        Err(err) if matches!(err, DeletionError::ApprovalMismatch(_)) => {
            if err.stable_id() != "ERR-DELETION-APPROVAL-001" {
                return Err(format!(
                    "seed {seed}: unexpected approval err id {}",
                    err.stable_id()
                ));
            }
        }
        other => {
            return Err(format!(
                "seed {seed}: expected ApprovalMismatch, got {other:?}"
            ));
        }
    }

    let del_rcpt = commit_deletion(&mut dep, del_plan_digest, del_approval, PRINCIPAL, &cx)
        .map_err(|e| format!("seed {seed} commit_deletion: {e}"))?;
    if del_rcpt.outcome != CommitOutcome::Completed {
        return Err(format!(
            "seed {seed}: deletion did not complete: {:?}",
            del_rcpt.outcome
        ));
    }
    deleted_imports.insert(del_target);
    op_count += 2;

    // Refusal error path 4: re-planning an already-deleted import -> ERR-EVIDENCE-DELETED-001!
    match plan_deletion(&dep, del_target, &cx) {
        Err(err) if matches!(err, DeletionError::EvidenceDeleted { .. }) => {
            if err.stable_id() != "ERR-EVIDENCE-DELETED-001" {
                return Err(format!(
                    "seed {seed}: unexpected deleted err id {}",
                    err.stable_id()
                ));
            }
        }
        other => {
            return Err(format!(
                "seed {seed}: expected EvidenceDeleted, got {other:?}"
            ));
        }
    }
    op_count += 1;

    // Optionally stage an unreferenced v1 spool orphan on 1/5 of seeds to verify explicit reporting!
    let maybe_orphan = if seed.is_multiple_of(5) {
        let od = dep
            .stage_payload(format!("v1-orphan-seed-{seed}").as_bytes())
            .map_err(|e| e.to_string())?;
        op_count += 1;
        Some(od)
    } else {
        None
    };

    // Snapshot v1 hold and mask query answers BEFORE dropping ReferenceDeployment.
    let v1_holds =
        list_holds(&dep, &authority, &cx).map_err(|e| format!("seed {seed} list_holds: {e}"))?;
    let mut v1_masks = BTreeMap::new();
    for sensor in expected_masks.keys() {
        let m = current_mask(&dep, sensor).map_err(|e| format!("seed {seed} current_mask: {e}"))?;
        v1_masks.insert(sensor.clone(), m.policy_digest());
    }

    drop(dep);
    cx.drain_and_finalize();

    // Refusal error path 5: v1 root offered to require_v2_deployment -> ERR-DEPLOYMENT-FORMAT-V1-001!
    match require_v2_deployment(&v1_root) {
        Err(MigrationError::UnsupportedV1Format(g)) => {
            if g.error_id != ERR_DEPLOYMENT_FORMAT_V1_001 {
                return Err(format!(
                    "seed {seed}: wrong v1 format err id {}",
                    g.error_id
                ));
            }
        }
        other => {
            return Err(format!(
                "seed {seed}: expected UnsupportedV1Format, got {other:?}"
            ));
        }
    }

    // 7. Migrate v1 -> v2 with tight epoch cap so multi-epoch segmentation is exercised!
    let mut mig_req = MigrationRequest::new(&v1_root, &v2_root);
    mig_req.epoch_config = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024,
        max_batches_per_epoch: 4,
        checkpoint_stride: 4,
        max_objects: None,
    };
    mig_req.pack_config = PackConfig {
        target_pack_bytes: 32 * 1024,
        durability: DurabilityMode::Fsync,
        max_open_packs: 16,
        ..PackConfig::default()
    };

    let receipt = migrate_v1_to_v2(&mig_req, &|| false)
        .map_err(|e| format!("seed {seed} migrate_v1_to_v2: {e}"))?;
    receipt
        .verify_self_digest()
        .map_err(|e| format!("seed {seed} verify_self_digest: {e}"))?;
    receipt
        .verify_equivalence(&v1_root, &v2_root)
        .map_err(|e| format!("seed {seed} verify_equivalence: {e}"))?;

    if !matches!(
        detect_deployment_format(&v2_root).map_err(|e| e.to_string())?,
        DeploymentFormatVersion::V2 { .. }
    ) {
        return Err(format!("seed {seed}: migrated root not detected as V2"));
    }

    // Check explicit orphan reporting.
    if let Some(od) = maybe_orphan
        && receipt.source_unreferenced_orphans != vec![od]
    {
        return Err(format!(
            "seed {seed}: orphan mismatch: {:?}",
            receipt.source_unreferenced_orphans
        ));
    }

    // Refusal error path 6 & 7: existing destination & already-v2 source (checked periodically to stay fast).
    if seed.is_multiple_of(10) {
        match migrate_v1_to_v2(&mig_req, &|| false) {
            Err(err) if matches!(err, MigrationError::DestinationExists { .. }) => {
                if err.stable_id() != ERR_MIGRATION_DESTINATION_EXISTS_001 {
                    return Err(format!(
                        "seed {seed}: wrong dest exists id {}",
                        err.stable_id()
                    ));
                }
            }
            other => {
                return Err(format!(
                    "seed {seed}: expected DestinationExists, got {other:?}"
                ));
            }
        }
        let v2_as_src = MigrationRequest::new(&v2_root, ws.0.join("v2-again"));
        match migrate_v1_to_v2(&v2_as_src, &|| false) {
            Err(err) if matches!(err, MigrationError::SourceAlreadyV2 { .. }) => {
                if err.stable_id() != ERR_MIGRATION_SOURCE_ALREADY_V2_001 {
                    return Err(format!(
                        "seed {seed}: wrong already v2 id {}",
                        err.stable_id()
                    ));
                }
            }
            other => {
                return Err(format!(
                    "seed {seed}: expected SourceAlreadyV2, got {other:?}"
                ));
            }
        }
    }

    // 8. Exhaustive v1 vs v2 query & custody audit equivalence!
    let v1_ledger = inspect_durable(v1_root.join("ledger/journal.fssj"), &site, 16 * 1024 * 1024)
        .map_err(|e| format!("seed {seed} inspect v1 ledger: {e}"))?;
    let v2_ledger = MerkleEpochLedger::open(
        v2_root.join("ledger"),
        &site,
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )
    .map_err(|e| format!("seed {seed} open v2 ledger: {e}"))?;
    if v2_ledger.snapshot_objects() != v1_ledger.snapshot.objects {
        return Err(format!(
            "seed {seed}: v2 Merkle object map != v1 ledger snapshot"
        ));
    }

    let v2_packs = PackStore::open(&v2_root, PackConfig::default())
        .map_err(|e| format!("seed {seed} open v2 packs: {e}"))?;
    let v2_pack_count = v2_packs.sealed_pack_ids().map_err(|e| e.to_string())?.len() as u64;
    let v2_live_bytes = v2_packs.on_disk_pack_bytes().map_err(|e| e.to_string())?;

    // Custody audit: live roots in v1 publication match v2 PackStore VirtualRootCatalog!
    let v1_pub = fss_publication::inspect(
        v1_root.join("objects"),
        DeploymentLimits::standard().to_publication_limits(),
    )
    .map_err(|e| format!("seed {seed} v1 pub inspect: {e}"))?;
    if v2_packs.live_root_count().map_err(|e| e.to_string())? != v1_pub.report.roots.len() as u64 {
        return Err(format!("seed {seed}: v1/v2 live root count mismatch"));
    }
    for root in &v1_pub.report.roots {
        let entry = v2_packs
            .get_root(root.slot.as_str())
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                format!(
                    "seed {seed}: missing root {} in v2 catalog",
                    root.slot.as_str()
                )
            })?;
        if entry.record.root_digest != root.root {
            return Err(format!(
                "seed {seed}: root digest mismatch for {}",
                root.slot.as_str()
            ));
        }
    }

    // Custody audit: v1 vs v2 batch-level delta/children equivalence + DeletionIndex + tombstones!
    let max_obj =
        usize::try_from(DeploymentLimits::standard().spool_object_max_bytes).unwrap_or(usize::MAX);
    let v1_del_idx = DeletionIndex::from_batches::<MigrationError>(&v1_ledger.batches, |digest| {
        fss_publication::read_verified(v1_root.join("objects"), digest, max_obj).map_err(|e| {
            MigrationError::VerificationFailed {
                detail: format!("v1 deletion read: {e}"),
            }
        })
    })
    .map_err(|e| format!("seed {seed} v1 DeletionIndex: {e}"))?;
    let v2_batches = fss_projection_store::CanonicalBatchSource::read_batches_range(
        &v2_ledger,
        1,
        v2_ledger.commit_sequence(),
    )
    .map_err(|e| format!("seed {seed} read v2 batches: {e}"))?;
    if v2_batches.len() != v1_ledger.batches.len() {
        return Err(format!("seed {seed}: v1 vs v2 batch count mismatch"));
    }
    for (b1, b2) in v1_ledger.batches.iter().zip(v2_batches.iter()) {
        if b1.batch_id != b2.batch_id
            || b1.deltas != b2.deltas
            || b1.children != b2.children
            || b1.new_anchor.commit_sequence != b2.new_anchor.commit_sequence
        {
            return Err(format!(
                "seed {seed}: batch {} deltas or children diverged between v1 and v2",
                b1.batch_id
            ));
        }
    }
    for entry in v1_del_idx.entries() {
        let v1_plan_bytes =
            fss_publication::read_verified(v1_root.join("objects"), entry.plan_digest, max_obj)
                .map_err(|e| format!("seed {seed} read v1 del plan: {e}"))?;
        let v2_plan_bytes = v2_packs
            .read_verified(&entry.plan_digest)
            .map_err(|e| format!("seed {seed} read v2 del plan: {e}"))?;
        if v1_plan_bytes != v2_plan_bytes {
            return Err(format!(
                "seed {seed}: deletion plan bytes diverged between v1 and v2"
            ));
        }
        if let Some(comp_digest) = entry.completion_digest {
            let v1_comp_bytes =
                fss_publication::read_verified(v1_root.join("objects"), comp_digest, max_obj)
                    .map_err(|e| format!("seed {seed} read v1 del completion: {e}"))?;
            let v2_comp_bytes = v2_packs
                .read_verified(&comp_digest)
                .map_err(|e| format!("seed {seed} read v2 del completion: {e}"))?;
            if v1_comp_bytes != v2_comp_bytes {
                return Err(format!(
                    "seed {seed}: deletion completion bytes diverged between v1 and v2"
                ));
            }
        }
    }
    for deleted_obj in v1_del_idx.deleted_objects() {
        if v2_packs
            .lookup(&deleted_obj)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err(format!(
                "seed {seed}: deleted object {deleted_obj} was unexpectedly packed in v2"
            ));
        }
    }
    for del_imp in &deleted_imports {
        if v1_del_idx.import(*del_imp).is_none() {
            return Err(format!(
                "seed {seed}: deleted import {del_imp} missing in DeletionIndex"
            ));
        }
    }
    // Verify local tombstone directory files match byte-for-byte between v1 and v2.
    let v1_tomb_dir = v1_root.join("objects/tombstones");
    let v2_tomb_dir = v2_root.join("objects/tombstones");
    if v1_tomb_dir.is_dir() {
        let mut v1_tombs = BTreeMap::new();
        for e in fs::read_dir(&v1_tomb_dir).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            if e.file_type().map_err(|e| e.to_string())?.is_file() {
                let bytes = fs::read(e.path()).map_err(|e| e.to_string())?;
                v1_tombs.insert(e.file_name().to_string_lossy().into_owned(), bytes);
            }
        }
        let mut v2_tombs = BTreeMap::new();
        if v2_tomb_dir.is_dir() {
            for e in fs::read_dir(&v2_tomb_dir).map_err(|e| e.to_string())? {
                let e = e.map_err(|e| e.to_string())?;
                if e.file_type().map_err(|e| e.to_string())?.is_file() {
                    let bytes = fs::read(e.path()).map_err(|e| e.to_string())?;
                    v2_tombs.insert(e.file_name().to_string_lossy().into_owned(), bytes);
                }
            }
        }
        if v1_tombs != v2_tombs {
            return Err(format!(
                "seed {seed}: local objects/tombstones/ diverged between v1 and v2"
            ));
        }
    }

    // Custody audit: v1 vs v2 DurableEffectJournal (including indeterminate operations!).
    let v1_eff =
        DurableEffectJournal::inspect(v1_root.join("effects/journal.fssj"), 16 * 1024 * 1024)
            .map_err(|e| format!("seed {seed} v1 effects inspect: {e}"))?;
    let v2_eff =
        DurableEffectJournal::inspect(v2_root.join("effects/journal.fssj"), 16 * 1024 * 1024)
            .map_err(|e| format!("seed {seed} v2 effects inspect: {e}"))?;
    if !v1_eff.is_clean()
        || !v2_eff.is_clean()
        || v1_eff.status != v2_eff.status
        || v1_eff.obligation_counts != v2_eff.obligation_counts
        || v1_eff.indeterminate_operations != v2_eff.indeterminate_operations
        || v2_eff.indeterminate_operations.len() != expected_indeterminate_ops
    {
        return Err(format!(
            "seed {seed}: v1 vs v2 DurableEffectJournal state diverged"
        ));
    }

    // Open v2 MvccProjectionStore and verify EVERY query answer!
    let v2_proj = MvccProjectionStore::open_or_rebuild_with_config(
        v2_root.join("projections/mvcc"),
        &v2_ledger,
        &NoopPayloadResolver,
        ProjectionStoreConfig {
            durability: DurabilityMode::Fsync,
            wal_sync: WalSyncPolicy::FlushOnly,
            history_mode: HistoryChainMode::V2MerkleEpoch,
            ..ProjectionStoreConfig::default()
        },
    )
    .map_err(|e| format!("seed {seed} open v2 mvcc: {e}"))?;
    if v2_proj.recovery_report().mode != ProjectionRecoveryMode::LoadedCurrent {
        return Err(format!(
            "seed {seed}: expected LoadedCurrent for migrated v2 projection, got {:?}",
            v2_proj.recovery_report().mode
        ));
    }
    let v2_snap = v2_proj.snapshot_latest();
    if v2_snap.state_digest() != receipt.projection_state_digest {
        return Err(format!(
            "seed {seed}: v2 projection state_digest mismatch vs receipt"
        ));
    }

    // Query parity: Events
    let v2_ev_page = v2_proj.query_events(&v2_snap, &EventQueryFilter::default(), 64);
    if v2_ev_page.entries.len() != expected_events.len() {
        return Err(format!(
            "seed {seed}: event count mismatch: v2={} expected={}",
            v2_ev_page.entries.len(),
            expected_events.len()
        ));
    }
    for (ev_id, &(exp_rev, exp_state, exp_corrob)) in &expected_events {
        let got = v2_snap
            .get_event(ev_id)
            .ok_or_else(|| format!("seed {seed}: missing event {ev_id} in v2 MVCC"))?;
        if got.revision != exp_rev || got.state != exp_state || got.corroborated != exp_corrob {
            return Err(format!(
                "seed {seed}: event {ev_id} mismatch: got rev={} state={:?} corrob={}, expected rev={exp_rev} state={exp_state:?} corrob={exp_corrob}",
                got.revision, got.state, got.corroborated
            ));
        }
        for r in 1..=exp_rev {
            if v2_snap.get_event_revision(ev_id, r).is_none() {
                return Err(format!(
                    "seed {seed}: missing revision {r} of event {ev_id}"
                ));
            }
        }
    }

    // Query parity: Holds (v1 list_holds == v2 MVCC get_hold)
    for hold_rec in &v1_holds {
        let req = hold_rec.request();
        let v2_hold = v2_snap
            .get_hold(&req.hold_id)
            .ok_or_else(|| format!("seed {seed}: missing hold {} in v2 MVCC", req.hold_id))?;
        if v2_hold.active != req.state.is_active() || v2_hold.target_digest != req.import_identity {
            return Err(format!("seed {seed}: hold {} parity mismatch", req.hold_id));
        }
    }
    for (hid, &(tgt, active)) in &expected_holds {
        let h = v2_snap
            .get_hold(hid)
            .ok_or_else(|| format!("seed {seed}: expected hold {hid} missing in v2"))?;
        if h.active != active || h.target_digest != tgt {
            return Err(format!("seed {seed}: expected hold {hid} state mismatch"));
        }
    }

    // Query parity: Privacy Masks (v1 current_mask == v2 MVCC get_privacy_mask)
    for (sensor, exp_digest) in &expected_masks {
        if v1_masks.get(sensor).copied().flatten() != Some(*exp_digest) {
            return Err(format!(
                "seed {seed}: v1 current_mask mismatch for {sensor}"
            ));
        }
        let v2_mask = v2_snap
            .get_privacy_mask(sensor)
            .ok_or_else(|| format!("seed {seed}: missing privacy mask for {sensor} in v2"))?;
        if v2_mask.policy_digest != *exp_digest {
            return Err(format!("seed {seed}: v2 mask digest mismatch for {sensor}"));
        }
    }

    // Query parity: Footage & Tombstones
    let v2_foot_page = v2_proj.query_footage(&v2_snap, &FootageQueryFilter::default(), 64);
    let expected_live_imports = retained_imports.len() - deleted_imports.len();
    if v2_foot_page.entries.len() != expected_live_imports {
        return Err(format!(
            "seed {seed}: footage count mismatch: v2={} expected={expected_live_imports}",
            v2_foot_page.entries.len()
        ));
    }
    for &imp in &retained_imports {
        let present = v2_snap.get_footage_import(&imp).is_some();
        let should_exist = !deleted_imports.contains(&imp);
        if present != should_exist {
            return Err(format!(
                "seed {seed}: import {imp} presence={present} expected={should_exist}"
            ));
        }
    }

    // Query parity: Coverage witnesses
    let v2_cov = v2_proj.query_coverage(&v2_snap, None, None);
    if v2_cov.len() != expected_coverage_count {
        return Err(format!(
            "seed {seed}: coverage count mismatch: v2={} expected={expected_coverage_count}",
            v2_cov.len()
        ));
    }

    drop(v2_proj);
    drop(v2_packs);
    drop(v2_ledger);

    // 9. Bit-exact SituationCapsule & decisionFingerprint parity between orient_v1 and orient_decoupled!
    let orient_limits = OrientLimits::default();
    let orient_req = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse(PRINCIPAL).map_err(|e| e.to_string())?,
        budget_tokens: None,
    };
    let bridge = ProjectionBridge::open_or_catch_up(&v1_root, &orient_limits)
        .map_err(|e| format!("seed {seed} ProjectionBridge open: {e}"))?;
    let _scrub = bridge
        .scrub_and_record_receipt(TimestampNs(999_000_000 + i128::from(seed)))
        .map_err(|e| format!("seed {seed} scrub_and_record_receipt: {e}"))?;

    let v1_snapshot = read_deployment(&v1_root, &orient_limits)
        .map_err(|e| format!("seed {seed} read_deployment: {e}"))?;
    let orient_v1 = orient_deployment(&v1_snapshot, &orient_req, &orient_limits)
        .map_err(|e| format!("seed {seed} orient_v1: {e}"))?;
    let (orient_decoupled, health, _trace) =
        bridge
            .orient_decoupled(&orient_req, &orient_limits)
            .map_err(|e| format!("seed {seed} orient_decoupled: {e}"))?;

    if !health.projection_caught_up {
        return Err(format!("seed {seed}: ProjectionBridge not caught up"));
    }
    let fp_v1 = orient_v1
        .capsule()
        .decision_fingerprint()
        .map_err(|e| format!("seed {seed} v1 decision_fingerprint: {e}"))?;
    let fp_v2 = orient_decoupled
        .capsule()
        .decision_fingerprint()
        .map_err(|e| format!("seed {seed} decoupled decision_fingerprint: {e}"))?;
    if fp_v1 != fp_v2 {
        return Err(format!(
            "seed {seed}: decisionFingerprint DIVERGED: orient_v1={fp_v1} vs orient_decoupled={fp_v2}"
        ));
    }
    if orient_v1.publication.publication_digest != orient_decoupled.publication.publication_digest {
        return Err(format!(
            "seed {seed}: publication_digest diverged between orient_v1 and orient_decoupled"
        ));
    }
    if orient_v1.capsule() != orient_decoupled.capsule() {
        return Err(format!(
            "seed {seed}: SituationCapsule fields diverged between orient_v1 and orient_decoupled"
        ));
    }
    if v1_snapshot.events.len() != expected_events.len()
        || bridge
            .store()
            .snapshot_latest()
            .orient_summary()
            .total_events
            != expected_events.len()
    {
        return Err(format!(
            "seed {seed}: orient event count mismatch: v1_snap={} bridge={} expected={}",
            v1_snapshot.events.len(),
            bridge
                .store()
                .snapshot_latest()
                .orient_summary()
                .total_events,
            expected_events.len()
        ));
    }

    if seed == 1 {
        // Verify the migrated deletion on the v2 root itself. A later orphaned deletion
        // must still fail the full proof even though an earlier plan carries a v1 basis.
        let migrated = ProjectionBridge::open_or_catch_up(&v2_root, &orient_limits)
            .map_err(|e| format!("migrated deletion proof: {e}"))?;
        assert_eq!(
            migrated.store().snapshot_latest().state_digest(),
            v2_snap.state_digest()
        );
        drop(migrated);
        let receipt_path = v2_root.join(fss_reference::migration::MIGRATION_RECEIPT_FILENAME);
        let saved_receipt = fs::read(&receipt_path).map_err(|e| e.to_string())?;
        fs::write(&receipt_path, b"{}").map_err(|e| e.to_string())?;
        assert!(matches!(
            ProjectionBridge::open_or_catch_up(&v2_root, &orient_limits),
            Err(fss_reference::agent_orient::DeploymentReadError::Corrupt { .. })
        ));
        fs::write(receipt_path, saved_receipt).map_err(|e| e.to_string())?;
        let mut ledger = MerkleEpochLedger::open(
            v2_root.join("ledger"),
            &site,
            EpochLedgerConfig::default(),
            IncompleteTailPolicy::Reject,
        )
        .map_err(|e| e.to_string())?;
        let orphan = ledger
            .prepare_batch(
                fss_core::BatchId::parse("batch:deletion:orphan").map_err(|e| e.to_string())?,
                Vec::new(),
                [],
            )
            .map_err(|e| e.to_string())?;
        ledger.append_batch(orphan).map_err(|e| e.to_string())?;
        drop(ledger);
        assert!(matches!(
            ProjectionBridge::open_or_catch_up(&v2_root, &orient_limits),
            Err(fss_reference::agent_orient::DeploymentReadError::Corrupt { reason })
                if reason.contains("deletion custody replay failed")
        ));
    }

    let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    Ok(SeedOutcome {
        seed,
        op_count,
        stage_latency_us: elapsed_us,
        pack_count: v2_pack_count,
        live_bytes: v2_live_bytes,
        assertion_digest: fp_v1,
    })
}

#[test]
fn differential_500_seeds_v1_vs_v2_projection_migration_custody_and_orient_parity() -> TestResult {
    let suite_start = Instant::now();
    let jpegs = Arc::new(preencode_jpegs()?);

    // Partition seeds 1..=500 deterministically across 4 worker threads for fast macOS execution.
    let per_worker = (TOTAL_SEEDS as usize) / WORKER_THREADS;
    let mut handles = Vec::with_capacity(WORKER_THREADS);
    for worker_idx in 0..WORKER_THREADS {
        let start_seed = (worker_idx * per_worker) as u64 + 1;
        let end_seed = if worker_idx + 1 == WORKER_THREADS {
            TOTAL_SEEDS
        } else {
            ((worker_idx + 1) * per_worker) as u64
        };
        let shared_jpegs = Arc::clone(&jpegs);
        handles.push(thread::spawn(
            move || -> Result<Vec<SeedOutcome>, String> {
                let mut local = Vec::with_capacity((end_seed - start_seed + 1) as usize);
                for seed in start_seed..=end_seed {
                    local.push(run_single_differential_seed(seed, &shared_jpegs)?);
                }
                Ok(local)
            },
        ));
    }

    let mut outcomes = Vec::with_capacity(TOTAL_SEEDS as usize);
    for h in handles {
        let batch = h
            .join()
            .map_err(|_| "differential oracle worker thread panicked")?
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        outcomes.extend(batch);
    }
    outcomes.sort_by_key(|o| o.seed);
    assert_eq!(outcomes.len(), TOTAL_SEEDS as usize);

    let mut latencies: Vec<u64> = outcomes.iter().map(|o| o.stage_latency_us).collect();
    latencies.sort_unstable();
    let p50_us = latencies[latencies.len() / 2];
    let p95_us = latencies[(latencies.len() * 95) / 100];
    let p99_us = latencies[(latencies.len() * 99) / 100];

    let total_ops: u64 = outcomes.iter().map(|o| o.op_count).sum();
    let total_packs: u64 = outcomes.iter().map(|o| o.pack_count).sum();
    let total_live_bytes: u64 = outcomes.iter().map(|o| o.live_bytes).sum();
    let mut agg_bytes = Vec::with_capacity((TOTAL_SEEDS as usize) * 32);
    let mut jsonl_lines = Vec::with_capacity((TOTAL_SEEDS as usize) + 1);
    for o in &outcomes {
        agg_bytes.extend_from_slice(&o.assertion_digest.bytes());
        jsonl_lines.push(format_jsonl_line(
            "differential_500_seeds_v1_vs_v2_seed",
            o.seed,
            o.op_count,
            o.stage_latency_us,
            o.pack_count,
            o.live_bytes,
            o.assertion_digest,
            "pass",
        ));
    }
    let agg_digest = ContentDigest::sha256(&agg_bytes);
    let wall_us = suite_start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    jsonl_lines.push(format!(
        "{{\"suite\":\"{}\",\"test_name\":\"differential_500_seeds_summary\",\"seed\":0,\"seeds_passed\":{},\"op_count\":{},\"stage_latency_us\":{},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"pack_count\":{},\"live_bytes\":{},\"assertion_digest\":\"{}\",\"verdict\":\"pass\"}}\n",
        escape_json(SUITE_NAME),
        TOTAL_SEEDS,
        total_ops,
        wall_us,
        p50_us,
        p95_us,
        p99_us,
        total_packs,
        total_live_bytes,
        escape_json(&agg_digest.to_text()),
    ));
    write_jsonl_lines(&jsonl_lines);

    println!(
        "v1_v2_differential_oracle: 500/500 seeds passed in {:.2}s (ops={}, p50={}us, p95={}us, p99={}us)",
        suite_start.elapsed().as_secs_f64(),
        total_ops,
        p50_us,
        p95_us,
        p99_us
    );
    Ok(())
}
