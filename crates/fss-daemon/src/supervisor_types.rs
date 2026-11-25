#![forbid(unsafe_code)]
//! Configuration, tick report, shutdown receipt, and camera slot types for [`crate::supervisor::DaemonSupervisor`].
//!
//! Semantic plane: `"authority"`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{CanonicalEncoder, ContentDigest, ResourcePressure, SensorId};
use fss_ipc::{CameraLiveStatus, RingWatermarkStatus};
use fss_pack::CapacityPressure;
use fss_reference::ingest::live_corroborate::LiveCorroborationDecision;

use crate::control::ControlStatusSnapshot;
use crate::manifest::{CameraManifestEntry, SiteManifest};
use crate::perception::PerceptionConfig;
use crate::regions::RegionShutdownProof;
use crate::ring::{BoundedFrameRing, RingConsumerCursor, RingStats};
use crate::sensor::{BackoffSchedule, CameraFrame, SensorDriver, SensorState};
use crate::storage::{StorageHeadSnapshot, StorageShutdownSummary};
use crate::telemetry::{DaemonTelemetrySnapshot, escape_json};

/// Canonical digest domain for [`DaemonShutdownReport::receipt_digest`].
pub const DAEMON_SHUTDOWN_RECEIPT_DOMAIN: &str = "fss.daemon.shutdown_receipt.v1";

/// Configuration bundle for launching a [`crate::supervisor::DaemonSupervisor`].
pub struct DaemonStartConfig {
    /// Validated secret-free site manifest (`fss.site_manifest.v1`).
    pub manifest: SiteManifest,
    /// Optional on-disk path of `site.json` enabling live `BoundedControlOp::ReloadManifest`.
    pub manifest_path: Option<PathBuf>,
    /// Optional deployment root override (takes precedence over `manifest.deployment_root`).
    pub root_override: Option<PathBuf>,
    /// Owner/operator principal recorded on the root `AuthorityCx`.
    pub principal: String,
    /// Live perception (`C3` + `C5` + `C8`) configuration.
    pub perception_config: PerceptionConfig,
    /// Optional custom camera drivers keyed by `SensorId` (e.g., synthetic fault-injection drivers).
    pub custom_drivers: BTreeMap<SensorId, Box<dyn SensorDriver>>,
    /// Deterministic start timestamp in nanoseconds.
    pub started_at_ns: i128,
    /// Whether to bind the local UDS `fss-ipc` server (`ControlPlaneRegion`).
    pub enable_ipc: bool,
    /// Optional explicit daemon instance identifier.
    pub daemon_instance_id: Option<String>,
    /// Optional `fss-vault` directory for scoped camera credential resolution at startup.
    pub vault_dir: Option<PathBuf>,
    /// Optional owner-only (`0600`) passphrase file unlocking `vault_dir` once during startup.
    pub vault_passphrase_file: Option<PathBuf>,
}

impl DaemonStartConfig {
    /// Creates a default [`DaemonStartConfig`] for `manifest` with IPC enabled.
    #[must_use]
    pub fn new(manifest: SiteManifest) -> Self {
        Self {
            manifest,
            manifest_path: None,
            root_override: None,
            principal: "principal:local-daemon".to_owned(),
            perception_config: PerceptionConfig::default(),
            custom_drivers: BTreeMap::new(),
            started_at_ns: monotonic_wall_ns(),
            enable_ipc: true,
            daemon_instance_id: None,
            vault_dir: None,
            vault_passphrase_file: None,
        }
    }
}

/// Complete output of one supervision tick.
#[derive(Clone, Debug)]
pub struct TickReport {
    /// Monotonic tick ordinal (`1`-based).
    pub tick: u64,
    /// Total upstream frames received across all cameras during this tick.
    pub frames_received: u64,
    /// Total frames deterministically shed by bounded per-camera rings during this tick.
    pub frames_shed: u64,
    /// Total frames committed into `FSMC` media chunks during this tick.
    pub frames_committed: u64,
    /// Explicit coverage gaps emitted during this tick.
    pub coverage_gaps_emitted: u64,
    /// Camera reconnects completed with fresh stream generations during this tick.
    pub reconnects_completed: u64,
    /// Corroborated multi-camera events emitted during this tick.
    pub corroborated_events: u64,
    /// Shared-failure-domain events honestly withheld during this tick.
    pub shared_domain_held_events: u64,
    /// True if storage capacity is 100%-pinned (`ERR-STORAGE-QUOTA-PINNED-001`).
    pub quota_pinned: bool,
    /// Current capacity pressure classification.
    pub pressure: CapacityPressure,
    /// All live corroboration decisions produced during this tick.
    pub decisions: Vec<LiveCorroborationDecision>,
    /// Structured telemetry snapshot for this tick.
    pub telemetry: DaemonTelemetrySnapshot,
}

/// Complete verified shutdown receipt produced by [`crate::supervisor::DaemonSupervisor::shutdown_graceful`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonShutdownReport {
    /// Supervised site identifier.
    pub site_id: String,
    /// Terminated daemon instance identifier.
    pub daemon_instance_id: String,
    /// Total supervision ticks executed before graceful shutdown.
    pub ticks_executed: u64,
    /// Measured wall-clock drain duration in milliseconds.
    pub drain_duration_ms: u64,
    /// Remaining active tasks across `ProcessRegion` (MUST be `0`).
    pub active_tasks: usize,
    /// Remaining leaked obligations across `ProcessRegion` (MUST be `0`).
    pub leaked_obligations: usize,
    /// Total regions finalized bottom-up.
    pub closed_regions: usize,
    /// Final verified ledger head commit sequence.
    pub head_commit_sequence: u64,
    /// Final verified history-chain root digest.
    pub history_root: ContentDigest,
    /// Final verified Merkle state root digest.
    pub state_root: ContentDigest,
    /// Total epochs verified by `verify_full_chain()`.
    pub verified_epochs: u64,
    /// Total batches verified by `verify_full_chain()`.
    pub verified_batches: u64,
    /// Cumulative corroborated events emitted across daemon lifetime.
    pub corroborated_events: u64,
    /// Cumulative shared-failure-domain events held across daemon lifetime.
    pub shared_domain_held_events: u64,
    /// Cumulative explicit coverage gaps emitted across daemon lifetime.
    pub coverage_gaps: u64,
    /// Verified root `QuiescenceProof` summary and storage flush summary.
    pub region_proof: RegionShutdownProof,
    /// Verified storage flush and chain verification summary.
    pub storage_summary: StorageShutdownSummary,
    /// Domain-separated canonical SHA-256 digest under [`DAEMON_SHUTDOWN_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl DaemonShutdownReport {
    /// Renders a deterministic non-secret JSON shutdown summary.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"schema\":\"fss.daemon_shutdown.v1\",\"site_id\":\"{}\",",
                "\"daemon_instance_id\":\"{}\",\"ticks_executed\":{},\"drain_duration_ms\":{},",
                "\"active_tasks\":{},\"leaked_obligations\":{},\"closed_regions\":{},",
                "\"head_commit_sequence\":{},\"history_root\":\"{}\",\"state_root\":\"{}\",",
                "\"verified_epochs\":{},\"verified_batches\":{},\"corroborated_events\":{},",
                "\"shared_domain_held_events\":{},\"coverage_gaps\":{},",
                "\"receipt_digest\":\"{}\"}}"
            ),
            escape_json(&self.site_id),
            escape_json(&self.daemon_instance_id),
            self.ticks_executed,
            self.drain_duration_ms,
            self.active_tasks,
            self.leaked_obligations,
            self.closed_regions,
            self.head_commit_sequence,
            self.history_root.to_text(),
            self.state_root.to_text(),
            self.verified_epochs,
            self.verified_batches,
            self.corroborated_events,
            self.shared_domain_held_events,
            self.coverage_gaps,
            self.receipt_digest.to_text(),
        )
    }
}

/// Read-only inspection view of one supervised camera's state and ring telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraRuntimeView {
    /// Camera sensor identifier.
    pub sensor_id: SensorId,
    /// Current lifecycle state.
    pub state: SensorState,
    /// Active stream generation (`1`-based).
    pub stream_generation: u64,
    /// Active upstream sessions right now (`0` or `1`).
    pub active_sessions: u32,
    /// Peak concurrent upstream sessions observed (MUST be `<= 1`).
    pub peak_concurrent_sessions: u32,
    /// Cumulative upstream connections opened.
    pub total_connections: u64,
    /// Cumulative reconnect attempts.
    pub reconnects: u64,
    /// Cumulative frames committed to storage.
    pub frames_ingested: u64,
    /// Cumulative frames forwarded to perception.
    pub frames_decoded: u64,
    /// Current ring accounting stats.
    pub ring: RingStats,
}

pub(crate) struct CameraSlot {
    pub(crate) entry: CameraManifestEntry,
    pub(crate) driver: Box<dyn SensorDriver>,
    pub(crate) ring: BoundedFrameRing<CameraFrame>,
    pub(crate) ingest_cursor: RingConsumerCursor,
    pub(crate) perception_cursor: RingConsumerCursor,
    pub(crate) preview_cursor: RingConsumerCursor,
    pub(crate) backoff: BackoffSchedule,
    pub(crate) state: SensorState,
    pub(crate) stream_generation: u64,
    // Source identity, sequence, and receive high-water for this generation, including
    // valid frames shed locally. Retention loss must never permit source identity replay.
    pub(crate) previous_frame: Option<(fss_core::StreamId, u64, i128)>,
    // Contiguous admitted samples since the latest source or retention gap, capped at two.
    pub(crate) continuity_frames: u8,
    pub(crate) last_frame_ns: i128,
    pub(crate) next_reconnect_ns: i128,
    pub(crate) reconnects: u64,
    pub(crate) frames_ingested: u64,
    pub(crate) frames_decoded: u64,
    pub(crate) last_ingest_lag_ms: u64,
    pub(crate) active_gaps: u32,
    pub(crate) ingest_paused: bool,
    pub(crate) peak_concurrent_sessions: u32,
}

pub(crate) fn build_control_status(
    head: &StorageHeadSnapshot,
    sensors: &BTreeMap<SensorId, CameraSlot>,
) -> ControlStatusSnapshot {
    let cameras = sensors
        .values()
        .map(|slot| {
            let stats = slot.ring.stats();
            CameraLiveStatus {
                camera_id: slot.entry.sensor_id.as_str().to_owned(),
                running: slot.state == SensorState::Streaming,
                fps_milli: u32::try_from(stats.total_enqueued.saturating_mul(1_000))
                    .unwrap_or(u32::MAX),
                reconnect_count: slot.reconnects,
                queue_depth: u32::try_from(stats.current_frames).unwrap_or(u32::MAX),
                frames_ingested: slot.frames_ingested,
            }
        })
        .collect();
    let pct = if head.ring_cap_bytes == 0 {
        0
    } else {
        let raw = (u128::from(head.ring_used_bytes) * 100) / u128::from(head.ring_cap_bytes);
        u8::try_from(raw.min(100)).unwrap_or(100)
    };
    ControlStatusSnapshot {
        head_commit_sequence: head.commit_sequence,
        history_root: head.history_root,
        state_root: head.state_root,
        cameras,
        ring: RingWatermarkStatus {
            used_bytes: head.ring_used_bytes,
            capacity_bytes: head.ring_cap_bytes,
            watermark_percent: pct,
        },
        scrub: head.scrub_status.clone(),
    }
}

pub(crate) const fn combined_pressure_label(
    cap: CapacityPressure,
    ring: ResourcePressure,
) -> &'static str {
    if matches!(cap, CapacityPressure::Critical) || matches!(ring, ResourcePressure::Critical) {
        "critical"
    } else if matches!(cap, CapacityPressure::Constrained)
        || matches!(ring, ResourcePressure::Constrained)
    {
        "constrained"
    } else if matches!(cap, CapacityPressure::Elevated)
        || matches!(ring, ResourcePressure::Elevated)
    {
        "elevated"
    } else {
        "nominal"
    }
}

pub(crate) fn compute_shutdown_digest(
    site_id: &str,
    instance_id: &str,
    ticks_executed: u64,
    storage: &StorageShutdownSummary,
    region: &RegionShutdownProof,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(DAEMON_SHUTDOWN_RECEIPT_DOMAIN);
    enc.text(site_id);
    enc.text(instance_id);
    enc.u64(ticks_executed);
    enc.u64(storage.head_commit_sequence);
    enc.digest(storage.history_root);
    enc.digest(storage.state_root);
    enc.u64(storage.verified_batches);
    enc.u64(region.active_tasks as u64);
    enc.u64(region.leaked_obligations as u64);
    ContentDigest::sha256(&enc.finish())
}

pub(crate) fn monotonic_wall_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000_000_000_000, |d| {
            i128::try_from(d.as_nanos()).unwrap_or(1_700_000_000_000_000_000)
        })
}
