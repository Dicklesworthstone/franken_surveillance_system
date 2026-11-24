#![forbid(unsafe_code)]
//! Typed data model for the 6-pane live operator cockpit frame (`fss.dashboard_live_frame.v1`).
//!
//! Semantic plane: `"projection"`.

use std::path::Path;

/// Schema identifier for live operator cockpit frames.
pub const LIVE_FRAME_SCHEMA: &str = "fss.dashboard_live_frame.v1";

/// Non-secret live daemon metadata when connected over `fss-ipc`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveDaemonInfo {
    /// Stable daemon instance identifier.
    pub daemon_instance_id: String,
    /// OS process identifier of the running supervisor.
    pub pid: u32,
    /// Daemon uptime in milliseconds.
    pub uptime_ms: u64,
    /// Active authenticated IPC connections.
    pub active_connections: u32,
    /// Canonical digest of the active site manifest.
    pub manifest_digest: String,
    /// Canonical digest of the pinned `ContractBasis`.
    pub contract_basis_digest: String,
}

/// Pane 1 row: per-camera mesh health, throughput, reconnects, and coverage status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveCameraHealth {
    /// Stable camera sensor identifier.
    pub camera_id: String,
    /// Current runtime state (`streaming`, `degraded`, `offline`, `unknown`).
    pub state: String,
    /// True when the live daemon reports the camera worker running.
    pub running: bool,
    /// Observed ingest FPS in milli-FPS (`30_000` = `30.000 FPS`).
    pub fps_in_milli: u32,
    /// Estimated decode FPS in milli-FPS (bounded by ingest rate).
    pub fps_decode_milli: u32,
    /// Cumulative reconnect count since daemon start.
    pub reconnect_count: u64,
    /// Current ring queue depth in frames.
    pub queue_depth: u32,
    /// Dropped/shed frame count observed via delta stream (`0` if none observed).
    pub dropped_frames: u64,
    /// Cumulative frames ingested.
    pub frames_ingested: u64,
    /// Epistemic coverage status (`covered`, `stale`, `not_observable`, `unknown`).
    pub coverage_status: String,
    /// Number of active coverage gaps across zones for this camera.
    pub active_gaps: u32,
    /// Associated zone identifiers.
    pub zones: Vec<String>,
}

/// One prioritized attention item in Pane 2 (`Active Situation & Attention Frontier`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveAttentionItem {
    /// Priority class (`critical`, `high`, `normal`).
    pub priority: String,
    /// Machine-stable attention category.
    pub category: String,
    /// Human-legible non-secret explanation.
    pub summary: String,
}

/// One dynamic operator/agent affordance in Pane 2 (never grants effect authority).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveAffordanceItem {
    /// Canonical affordance identifier (e.g. `affordance:orient:plan`).
    pub affordance_id: String,
    /// Classification against `WorldEnvelope` (`robust`, `conditional`, `information_gathering`, `wait_watch`).
    pub classification: String,
    /// Whether executing the affordance requires preview -> `approval_digest` -> approve.
    pub requires_approval: bool,
    /// Exact read-only guidance or CLI command template.
    pub summary: String,
}

/// Pane 2: active situation anchor, epistemic state, coverage rollup, and attention frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveSituationFrontier {
    /// Authoritative commit sequence pinned by this projection.
    pub anchor_commit_sequence: u64,
    /// Canonical authority/state root digest text.
    pub authority_root: String,
    /// Canonical history/ledger root digest text.
    pub history_root: String,
    /// Materialized MVCC state digest (or `"v1_reference_readonly"` for v1 fallback).
    pub state_digest: String,
    /// Explicit epistemic classification (`corroborated`, `indeterminate`, `observed`, `unknown`).
    pub epistemic_state: String,
    /// Count of zones with `CoverageStatus::Covered`.
    pub covered_zones: usize,
    /// Count of zones with `CoverageStatus::Stale`.
    pub stale_zones: usize,
    /// Count of zones with `CoverageStatus::NotObservable`.
    pub not_observable_zones: usize,
    /// Absence is never silently certified without explicit negative witnesses.
    pub absence_certified: bool,
    /// Prioritized attention frontier items.
    pub attention_frontier: Vec<LiveAttentionItem>,
    /// Typed nondominated next affordances (zero implicit effect authority).
    pub affordances: Vec<LiveAffordanceItem>,
}

/// Privacy-masked H0 inspection handle for a rolling event (never exposes raw unrestricted media).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyMaskedEventHandle {
    /// Stable inspection handle string.
    pub handle_id: String,
    /// Event publication root digest.
    pub event_root: String,
    /// Exact event revision payload digest.
    pub revision_digest: String,
    /// Hydration tier (`H0` metadata handle).
    pub hydration_level: String,
    /// Count of active privacy mask policies on contributing sensors/site.
    pub privacy_masks_active: usize,
    /// Always `false` in the live cockpit; raw media requires explicit gated hydration.
    pub raw_media_exposed: bool,
    /// Read-only inspection command template.
    pub inspect_command: String,
}

/// Pane 3 row: rolling event with epistemic state, failure-domain clusters, and fusion summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveEventRow {
    /// Stable event lineage identifier.
    pub event_id: String,
    /// Latest committed 1-based revision number.
    pub revision: u64,
    /// Coarse event kind label.
    pub kind: String,
    /// Committed lifecycle state label.
    pub state: String,
    /// Epistemic corroboration class (`Corroborated`, `SharedFailureDomainHeld`, `Indeterminate`, `Observed`).
    pub epistemic_classification: String,
    /// Independent failure-domain cluster count (`0` when unknown).
    pub failure_domain_clusters: u32,
    /// Milliban fusion / probability summary (honestly labeled when uncalibrated).
    pub fusion_summary: String,
    /// Spatial zones associated with this event.
    pub zones: Vec<String>,
    /// Contributing sensor identifiers.
    pub sensors: Vec<String>,
    /// True when an open sensor-tamper report affects this lineage.
    pub tamper_open: bool,
    /// Commit sequence at which this revision was published.
    pub committed_sequence: u64,
    /// Privacy-masked inspection handle.
    pub privacy_masked_handle: PrivacyMaskedEventHandle,
}

/// Pane 4: active obligations, unresolved indeterminate effects, and legal/operator holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveObligationsHolds {
    /// Number of non-terminal obligations (`Pending` or `Indeterminate`).
    pub open_obligations: usize,
    /// Number of unresolved indeterminate external effects.
    pub indeterminate_effects: usize,
    /// Number of active evidence retention holds blocking deletion/eviction.
    pub active_holds: usize,
    /// Number of active per-sensor privacy mask policy generations.
    pub privacy_masks: usize,
    /// Read-only summaries of open obligations or indeterminate operations.
    pub notes: Vec<String>,
}

/// Pane 5: storage ring capacity, sealed packfile counts, resource pressure, and scrubber status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveStorageRingTelemetry {
    /// Total `.fssp` packfiles discovered under `objects/packs/`.
    pub pack_count: u64,
    /// Number of immutable sealed packfiles ending with `FSSE`.
    pub sealed_pack_count: u64,
    /// Total on-disk bytes across all packfiles.
    pub on_disk_pack_bytes: u64,
    /// On-disk packfile size formatted in decimal MiB (`"0.00"`).
    pub on_disk_mb: String,
    /// Bytes currently accounted in the retention ring.
    pub ring_used_bytes: u64,
    /// Configured retention ring capacity in bytes (`0` when offline/unknown).
    pub ring_cap_bytes: u64,
    /// Ring occupancy percentage clamped to `0..=100`.
    pub watermark_percent: u8,
    /// Explicit resource pressure (`Nominal`, `Elevated`, `Critical`).
    pub resource_pressure: String,
    /// Explicit scrubber status (`Clean`, `Stale`, `NeverScrubbed`, `Running`, `Degraded`, `Failed`).
    pub scrubber_status: String,
    /// Verified object count from latest scrub pass.
    pub scrub_verified_objects: u64,
    /// Verified pack count from latest scrub pass.
    pub scrub_verified_packs: u64,
    /// Verified corpus fraction in ppm (`0..=1_000_000`).
    pub scrub_verified_fraction_ppm: u32,
    /// Commits since latest scrub anchor (`0` when current or never scrubbed).
    pub scrub_behind_commits: u64,
    /// Total unified footage imports indexed.
    pub total_footage_imports: usize,
}

/// One live delta record received from `fss-daemon` `SubscribeDeltas` or read-only commit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveDeltaEntry {
    /// Committed authority sequence.
    pub commit_sequence: u64,
    /// Digest of the committed delta batch or decision.
    pub delta_digest: String,
    /// Meaningful delta class label.
    pub delta_class: String,
    /// Priority class label.
    pub priority: String,
    /// Non-secret summary text.
    pub summary: String,
    /// Measured client delivery latency in milliseconds (when received live via IPC).
    pub latency_ms: Option<u64>,
}

/// One explicit preview -> `approval_digest` -> approve workflow hint for Pane 6.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorWorkflowHint {
    /// Action category (`acknowledge`, `hold`, `alert`).
    pub action: String,
    /// Always `true`: cockpit never executes direct mutations.
    pub requires_approval_digest: bool,
    /// Step 1 preview command template.
    pub preview_command: String,
    /// Step 2 exact approval command template.
    pub approve_command: String,
}

/// Pane 6: rolling delta stream activity log and read-only preview->approve workflow hints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveAgentActivityLog {
    /// Always `true` in default live mode.
    pub read_only: bool,
    /// Recent deltas in chronological order.
    pub recent_deltas: Vec<LiveDeltaEntry>,
    /// Explicit preview -> `approval_digest` -> approve operator workflow hints.
    pub operator_workflows: Vec<OperatorWorkflowHint>,
}

/// Complete 6-pane live operator cockpit frame (`fss.dashboard_live_frame.v1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveCockpitFrame {
    /// Fixed schema identifier (`fss.dashboard_live_frame.v1`).
    pub schema: &'static str,
    /// Site lineage identifier.
    pub site: String,
    /// Strictly `true` (read-only by default; zero deployment mutations).
    pub read_only: bool,
    /// `true` when connected to a running `fss-daemon` over `fss-ipc`; `false` on offline fallback.
    pub daemon_live: bool,
    /// Transport mode (`live_daemon_ipc`, `offline_mvcc_readonly`, `offline_v1_readonly`).
    pub connection_mode: String,
    /// Optional non-secret daemon metadata when live.
    pub daemon_info: Option<LiveDaemonInfo>,
    /// Non-secret reason when running in offline read-only fallback mode.
    pub fallback_reason: Option<String>,
    /// Total live `SubscribeDeltas` events received during this session.
    pub deltas_received: u64,
    /// Maximum measured delta delivery latency in milliseconds.
    pub max_delta_latency_ms: u64,
    /// Most recent measured delta delivery latency in milliseconds.
    pub last_delta_latency_ms: Option<u64>,
    /// Pane 1: Camera Mesh Health.
    pub cameras: Vec<LiveCameraHealth>,
    /// Pane 2: Active Situation & Attention Frontier.
    pub situation: LiveSituationFrontier,
    /// Pane 3: Corroborated Events & Milliban Fusion Scores.
    pub events: Vec<LiveEventRow>,
    /// Pane 4: Active Obligations, Effects & Legal Holds.
    pub obligations_and_holds: LiveObligationsHolds,
    /// Pane 5: Storage Ring Capacity & Compaction Telemetry.
    pub storage_ring: LiveStorageRingTelemetry,
    /// Pane 6: Agent Activity Log & Preview->Approve Workflows.
    pub agent_log: LiveAgentActivityLog,
}

/// Formats `bytes` as decimal MiB with two fractional digits.
#[must_use]
pub fn format_mb(bytes: u64) -> String {
    let hundredths = (u128::from(bytes) * 100) / (1024 * 1024);
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// Builds explicit preview -> `approval_digest` -> approve operator workflow hints.
#[must_use]
pub fn build_operator_workflows(root: &Path, site: &str) -> Vec<OperatorWorkflowHint> {
    let root_str = root.to_string_lossy();
    vec![
        OperatorWorkflowHint {
            action: "acknowledge".to_owned(),
            requires_approval_digest: true,
            preview_command: format!(
                "fss-review prepare --root {root_str} --site {site} --event-id <EVENT_ID> --disposition acknowledged"
            ),
            approve_command: format!(
                "fss-review commit --root {root_str} --site {site} --event-id <EVENT_ID> --approve <APPROVAL_DIGEST>"
            ),
        },
        OperatorWorkflowHint {
            action: "hold".to_owned(),
            requires_approval_digest: true,
            preview_command: format!(
                "fss-hold place --root {root_str} --site {site} --scope <SCOPE> --target <TARGET_DIGEST>"
            ),
            approve_command: format!(
                "fss-hold place --root {root_str} --site {site} --scope <SCOPE> --target <TARGET_DIGEST> --approve <APPROVAL_DIGEST>"
            ),
        },
        OperatorWorkflowHint {
            action: "alert".to_owned(),
            requires_approval_digest: true,
            preview_command: format!(
                "fss plan --json --root {root_str} --session <SESSION_ID> --intent alert --event-id <EVENT_ID> --relay <HOST:PORT> --path /fss/alert --plaintext-approval <SHA256> --deadline-ms 5000"
            ),
            approve_command: format!(
                "fss commit --json --root {root_str} --plan <PLAN_ID> --approve <APPROVAL_DIGEST>"
            ),
        },
    ]
}

/// Extracts `key=value` tokens from structured daemon delta summaries.
#[must_use]
pub fn parse_delta_kv<'a>(summary: &'a str, key: &str) -> Option<&'a str> {
    for token in summary.split_whitespace() {
        if let Some(rest) = token.strip_prefix(key)
            && let Some(val) = rest.strip_prefix('=')
        {
            return Some(val);
        }
    }
    None
}
