#![forbid(unsafe_code)]
//! Always-on Asupersync-owned multi-camera supervisor (`fss-daemon` / `fss site run`).
//!
//! Semantic plane: `"authority"`.

pub mod control;
mod control_client;
pub mod error;
pub mod health;
pub mod manifest;
mod manifest_parse;
pub mod perception;
pub mod regions;
pub mod ring;
pub mod sensor;
mod sensor_network;
mod sensor_synthetic;
pub mod storage;
mod storage_types;
pub mod supervisor;
mod supervisor_tick;
mod supervisor_types;
pub mod telemetry;

pub use control::{
    ControlPlaneServer, ControlPlaneShared, ControlStatusSnapshot,
    DAEMON_RUNTIME_DESCRIPTOR_DOMAIN, DAEMON_RUNTIME_DESCRIPTOR_SCHEMA,
    DAEMON_RUNTIME_META_FILENAME, DAEMON_SHUTDOWN_APPROVAL_DOMAIN, DAEMON_STOP_TARGET,
    DaemonRuntimeDescriptor, ForwardBatchReceipt, ForwardBatchWriter, PendingControlCommand,
    control_op_approval_digest, daemon_stop_approval_digest, query_live_daemon_status,
    request_live_daemon_stop,
};
pub use error::{
    DaemonError, ERR_DAEMON_CONTROL_APPROVAL_001, ERR_DAEMON_IO_001, ERR_DAEMON_IPC_001,
    ERR_DAEMON_MANIFEST_INVALID_001, ERR_DAEMON_PERCEPTION_001, ERR_DAEMON_REGION_ERROR_001,
    ERR_DAEMON_SECRET_IN_MANIFEST_001, ERR_DAEMON_SHUTDOWN_001, ERR_DAEMON_STORAGE_001,
    ERR_DAEMON_UNKNOWN_CAMERA_001, ERR_DAEMON_VAULT_001,
};
pub use health::{
    CameraHealthStatus, SENSOR_HEALTH_CLEAR_FRAMES, SensorHealthPolicy, SensorHealthState,
};
pub use manifest::{
    CameraAdapterKind, CameraManifestEntry, DAEMON_SITE_MANIFEST_DOMAIN, DEFAULT_CAMERA_DIMENSIONS,
    DEFAULT_GOP_FRAMES, DEFAULT_RECONNECT_MAX_MS, DEFAULT_RECONNECT_MIN_MS, DEFAULT_RETAIN_HOT_NS,
    DEFAULT_RING_MAX_BYTES, DEFAULT_RING_MAX_FRAMES, DEFAULT_SCRUB_BUDGET_BYTES_PER_TICK,
    DEFAULT_SITE_RING_CAP_BYTES, DEFAULT_STALL_TIMEOUT_MS, ManifestHomography,
    SITE_MANIFEST_SCHEMA, SiteManifest, SiteTopologyManifest,
};
pub use perception::{PerceptionConfig, PerceptionEngine, PerceptionTickOutcome};
pub use regions::{DaemonRegionTree, RegionShutdownProof, SensorRegionDrainReceipt};
pub use ring::{
    BoundedFrameRing, ConsumerLagGap, RingConsumerCursor, RingMetered, RingPushOutcome, RingStats,
};
pub use sensor::{
    BackoffSchedule, CameraFrame, DAEMON_BACKOFF_JITTER_DOMAIN, NetworkAdapterDriver,
    SensorDisconnectReason, SensorDriver, SensorDriverEvent, SensorState, SyntheticCameraControl,
    SyntheticCameraDriver, SyntheticDetectionHint, SyntheticFrameSpec, default_driver_for_camera,
    draw_rect_luma,
};
pub use storage::{
    MaintenanceTickReport, StorageCommitReceipt, StorageEngine, StorageHeadSnapshot,
    StorageShutdownSummary,
};
pub use supervisor::{
    CameraRuntimeView, DAEMON_CONTROL_DISPOSITION_DOMAIN, DAEMON_SHUTDOWN_RECEIPT_DOMAIN,
    DaemonControlDisposition, DaemonShutdownReport, DaemonStartConfig, DaemonSupervisor, TickReport,
};
pub use telemetry::{
    DaemonTelemetrySnapshot, SensorTelemetryRecord, escape_json, render_live_status_json,
    render_stop_accepted_json,
};
