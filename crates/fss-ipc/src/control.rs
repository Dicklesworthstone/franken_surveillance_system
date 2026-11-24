#![forbid(unsafe_code)]
//! Bounded control operations, stream end reasons, and canonical delta summaries.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DeltaPriority, MeaningfulDeltaClass,
};

use crate::handshake::MAX_REASON_BYTES;

/// Canonical digest domain for [`DeltaEventSummary`].
pub const IPC_DELTA_SUMMARY_DIGEST_DOMAIN: &str = "fss.ipc.delta_summary.v1";

/// Strictly closed set of supervisor control operations (zero arbitrary shell escapes).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BoundedControlOp {
    /// Start ingest for a configured camera.
    StartCamera,
    /// Stop ingest for a configured camera.
    StopCamera,
    /// Capture one bounded on-demand snapshot from a configured camera.
    SnapshotCamera,
    /// Reload the immutable site manifest generation.
    ReloadManifest,
    /// Run a bounded camera/probe detection pass.
    ProbeDetect,
    /// Trigger an integrity scrub over retained local storage.
    TriggerScrub,
}

impl BoundedControlOp {
    /// Returns the canonical lower-snake-case operation label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartCamera => "start_camera",
            Self::StopCamera => "stop_camera",
            Self::SnapshotCamera => "snapshot_camera",
            Self::ReloadManifest => "reload_manifest",
            Self::ProbeDetect => "probe_detect",
            Self::TriggerScrub => "trigger_scrub",
        }
    }

    /// Returns true if this control op requires a specific `target_camera_id`.
    #[must_use]
    pub const fn requires_camera_id(self) -> bool {
        matches!(
            self,
            Self::StartCamera | Self::StopCamera | Self::SnapshotCamera
        )
    }
}

impl CanonicalEncode for BoundedControlOp {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(match self {
            Self::StartCamera => 1,
            Self::StopCamera => 2,
            Self::SnapshotCamera => 3,
            Self::ReloadManifest => 4,
            Self::ProbeDetect => 5,
            Self::TriggerScrub => 6,
        });
    }
}

impl CanonicalDecode for BoundedControlOp {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => Ok(Self::StartCamera),
            2 => Ok(Self::StopCamera),
            3 => Ok(Self::SnapshotCamera),
            4 => Ok(Self::ReloadManifest),
            5 => Ok(Self::ProbeDetect),
            6 => Ok(Self::TriggerScrub),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Lifecycle state returned when a bounded control operation is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlOperationState {
    /// Admitted and queued in the supervisor's bounded control queue.
    Queued,
    /// Accepted by the target subsystem.
    Accepted,
    /// Actively executing.
    Executing,
    /// Synchronously completed before response emission.
    Completed,
}

impl CanonicalEncode for ControlOperationState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(match self {
            Self::Queued => 1,
            Self::Accepted => 2,
            Self::Executing => 3,
            Self::Completed => 4,
        });
    }
}

impl CanonicalDecode for ControlOperationState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => Ok(Self::Queued),
            2 => Ok(Self::Accepted),
            3 => Ok(Self::Executing),
            4 => Ok(Self::Completed),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Terminal reason closing a `SubscribeDeltas` response stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamEndReason {
    /// All currently available deltas up to the current head were delivered.
    Completed,
    /// The caller's `max_batch` bound was reached cleanly.
    BatchLimitReached,
    /// The subscription was cooperatively cancelled by the client or peer disconnect.
    Cancelled,
    /// The daemon is draining for shutdown.
    DaemonShuttingDown,
    /// The requested `since_commit_seq` cursor is ahead of or inconsistent with ledger history.
    CursorStale,
}

impl StreamEndReason {
    /// Returns the canonical snake-case string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::BatchLimitReached => "batch_limit_reached",
            Self::Cancelled => "cancelled",
            Self::DaemonShuttingDown => "daemon_shutting_down",
            Self::CursorStale => "cursor_stale",
        }
    }
}

impl CanonicalEncode for StreamEndReason {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(match self {
            Self::Completed => 1,
            Self::BatchLimitReached => 2,
            Self::Cancelled => 3,
            Self::DaemonShuttingDown => 4,
            Self::CursorStale => 5,
        });
    }
}

impl CanonicalDecode for StreamEndReason {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => Ok(Self::Completed),
            2 => Ok(Self::BatchLimitReached),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::DaemonShuttingDown),
            5 => Ok(Self::CursorStale),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Helper structured summary that encodes into `IpcResponse::DeltaEvent::summary_canonical`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaEventSummary {
    /// Semantic delta class from `fss-core`.
    pub delta_class: MeaningfulDeltaClass,
    /// Delivery priority from `fss-core`.
    pub priority: DeltaPriority,
    /// Bounded human/machine summary note (non-secret).
    pub summary: String,
}

impl DeltaEventSummary {
    /// Computes the canonical digest of this delta summary.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(IPC_DELTA_SUMMARY_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for DeltaEventSummary {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.delta_class.encode_canonical(encoder);
        self.priority.encode_canonical(encoder);
        encoder.text(&self.summary);
    }
}

impl CanonicalDecode for DeltaEventSummary {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let delta_class = decode_delta_class(decoder.text()?)?;
        let priority = decode_delta_priority(decoder.text()?)?;
        let summary = decoder.text()?.to_owned();
        if summary.len() > MAX_REASON_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            delta_class,
            priority,
            summary,
        })
    }
}

fn decode_delta_class(text: &str) -> Result<MeaningfulDeltaClass, ContractError> {
    match text {
        "material_state" => Ok(MeaningfulDeltaClass::MaterialState),
        "hypothesis" => Ok(MeaningfulDeltaClass::Hypothesis),
        "contradiction" => Ok(MeaningfulDeltaClass::Contradiction),
        "coverage_loss" => Ok(MeaningfulDeltaClass::CoverageLoss),
        "coverage_recovery" => Ok(MeaningfulDeltaClass::CoverageRecovery),
        "sensor_health" => Ok(MeaningfulDeltaClass::SensorHealth),
        "plan_invalidation" => Ok(MeaningfulDeltaClass::PlanInvalidation),
        "obligation" => Ok(MeaningfulDeltaClass::Obligation),
        "effect_uncertainty" => Ok(MeaningfulDeltaClass::EffectUncertainty),
        "policy_or_authority" => Ok(MeaningfulDeltaClass::PolicyOrAuthority),
        "budget_pressure" => Ok(MeaningfulDeltaClass::BudgetPressure),
        "terminal_transition" => Ok(MeaningfulDeltaClass::TerminalTransition),
        "no_meaningful_change" => Ok(MeaningfulDeltaClass::NoMeaningfulChange),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

fn decode_delta_priority(text: &str) -> Result<DeltaPriority, ContractError> {
    match text {
        "constitutional" => Ok(DeltaPriority::Constitutional),
        "critical" => Ok(DeltaPriority::Critical),
        "high" => Ok(DeltaPriority::High),
        "normal" => Ok(DeltaPriority::Normal),
        "low" => Ok(DeltaPriority::Low),
        _ => Err(ContractError::InvalidIdentifier),
    }
}
