#![forbid(unsafe_code)]
//! Zero-Serde structured JSONL telemetry for `fss-daemon` (strictly non-secret).
//!
//! Semantic plane: `"support"`.

use std::fmt::Write as _;

/// Structured per-camera telemetry line emitted on every supervision tick.
#[derive(Clone, Debug, PartialEq)]
pub struct SensorTelemetryRecord {
    /// Stable camera sensor identifier.
    pub sensor_id: String,
    /// Current lifecycle state (`streaming`, `gap_backoff`, `stopped`, `connecting`, `draining`).
    pub state: String,
    /// Current stream generation ordinal (`1`-based, increments on reconnect).
    pub stream_generation: u64,
    /// Observed ingest frame rate in frames per second.
    pub fps_in: f64,
    /// Observed decode/perception frame rate in frames per second.
    pub fps_decode: f64,
    /// Measured ingest lag in milliseconds.
    pub ingest_lag_ms: u64,
    /// Current bounded per-camera ring queue depth in frames.
    pub queue_depth: usize,
    /// Cumulative frames shed due to bounded ring backpressure.
    pub dropped_frames: u64,
    /// Cumulative reconnect attempts since daemon start.
    pub reconnects: u64,
    /// Total on-disk sealed + active pack bytes expressed in MiB.
    pub pack_mb: f64,
    /// Combined capacity and queue resource pressure label.
    pub pressure: String,
    /// Cumulative corroborated multi-camera events emitted by this daemon.
    pub corroborated_events: u64,
    /// Total currently active region-owned tasks across the daemon tree.
    pub active_tasks: usize,
}

impl SensorTelemetryRecord {
    /// Renders a deterministic single-line JSONL record containing zero secrets.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(288);
        let _ = write!(
            out,
            concat!(
                "{{\"schema\":\"fss.daemon_telemetry.v1\",",
                "\"sensor_id\":\"{}\",\"state\":\"{}\",\"stream_generation\":{},",
                "\"fps_in\":{:.2},\"fps_decode\":{:.2},\"ingest_lag_ms\":{},",
                "\"queue_depth\":{},\"dropped_frames\":{},\"reconnects\":{},",
                "\"pack_mb\":{:.3},\"pressure\":\"{}\",\"corroborated_events\":{},",
                "\"active_tasks\":{}}}"
            ),
            escape_json(&self.sensor_id),
            escape_json(&self.state),
            self.stream_generation,
            self.fps_in,
            self.fps_decode,
            self.ingest_lag_ms,
            self.queue_depth,
            self.dropped_frames,
            self.reconnects,
            self.pack_mb,
            escape_json(&self.pressure),
            self.corroborated_events,
            self.active_tasks,
        );
        out
    }
}

/// Site-wide structured daemon telemetry summary emitted per tick or on status queries.
#[derive(Clone, Debug, PartialEq)]
pub struct DaemonTelemetrySnapshot {
    /// Stable site identifier.
    pub site_id: String,
    /// Stable daemon instance identifier.
    pub daemon_instance_id: String,
    /// Monotonic supervision tick ordinal.
    pub tick: u64,
    /// Daemon process uptime in milliseconds.
    pub uptime_ms: u64,
    /// Current authoritative ledger head commit sequence.
    pub head_commit_sequence: u64,
    /// Total on-disk pack bytes expressed in MiB.
    pub pack_mb: f64,
    /// Tracked retention ring bytes used.
    pub ring_used_bytes: u64,
    /// Configured retention ring byte cap.
    pub ring_cap_bytes: u64,
    /// Overall pressure label (`nominal`, `elevated`, `constrained`, `critical`).
    pub pressure: String,
    /// True when critical capacity is 100% pinned by active holds/obligations/events.
    pub quota_pinned: bool,
    /// Cumulative corroborated events emitted.
    pub corroborated_events: u64,
    /// Cumulative shared-failure-domain events honestly withheld (`Indeterminate`/`Hold`).
    pub shared_domain_held_events: u64,
    /// Cumulative explicit coverage gaps emitted.
    pub coverage_gaps: u64,
    /// Active region-owned tasks across `ProcessRegion`.
    pub active_tasks: usize,
    /// Non-terminal leaked obligations across `ProcessRegion`.
    pub leaked_obligations: usize,
    /// Per-camera telemetry records in canonical `sensor_id` order.
    pub sensors: Vec<SensorTelemetryRecord>,
}

impl DaemonTelemetrySnapshot {
    /// Renders a deterministic single-line JSONL summary for this supervision tick.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(512);
        let _ = write!(
            out,
            concat!(
                "{{\"schema\":\"fss.daemon_tick_summary.v1\",",
                "\"site_id\":\"{}\",\"daemon_instance_id\":\"{}\",\"tick\":{},\"uptime_ms\":{},",
                "\"head_commit_sequence\":{},\"pack_mb\":{:.3},\"ring_used_bytes\":{},",
                "\"ring_cap_bytes\":{},\"pressure\":\"{}\",\"quota_pinned\":{},",
                "\"corroborated_events\":{},\"shared_domain_held_events\":{},",
                "\"coverage_gaps\":{},\"active_tasks\":{},\"leaked_obligations\":{},",
                "\"sensor_count\":{}}}"
            ),
            escape_json(&self.site_id),
            escape_json(&self.daemon_instance_id),
            self.tick,
            self.uptime_ms,
            self.head_commit_sequence,
            self.pack_mb,
            self.ring_used_bytes,
            self.ring_cap_bytes,
            escape_json(&self.pressure),
            self.quota_pinned,
            self.corroborated_events,
            self.shared_domain_held_events,
            self.coverage_gaps,
            self.active_tasks,
            self.leaked_obligations,
            self.sensors.len(),
        );
        out
    }
}

/// Renders deterministic non-secret `fss.daemon_status.v1` JSON from a live IPC query result.
#[must_use]
pub fn render_live_status_json(
    desc: &crate::control::DaemonRuntimeDescriptor,
    status: &fss_ipc::LiveDaemonStatus,
) -> String {
    let cameras: Vec<String> = status
        .cameras
        .iter()
        .map(|c| {
            format!(
                "{{\"camera_id\":\"{}\",\"running\":{},\"fps_milli\":{},\"reconnect_count\":{},\"queue_depth\":{},\"frames_ingested\":{}}}",
                escape_json(&c.camera_id),
                c.running,
                c.fps_milli,
                c.reconnect_count,
                c.queue_depth,
                c.frames_ingested
            )
        })
        .collect();
    let ring = status.ring.as_ref().map_or_else(
        || "null".to_owned(),
        |r| {
            format!(
                "{{\"used_bytes\":{},\"capacity_bytes\":{},\"watermark_percent\":{}}}",
                r.used_bytes, r.capacity_bytes, r.watermark_percent
            )
        },
    );
    format!(
        "{{\"schema\":\"fss.daemon_status.v1\",\"site_id\":\"{}\",\"daemon_instance_id\":\"{}\",\"pid\":{},\"uptime_ms\":{},\"head_commit_sequence\":{},\"history_root\":\"{}\",\"state_root\":\"{}\",\"cameras\":[{}],\"ring\":{}}}",
        escape_json(&desc.site_id),
        escape_json(&desc.daemon_instance_id),
        desc.pid,
        status.daemon_uptime_ms,
        status.head_commit_sequence,
        status.history_root.to_text(),
        status.state_root.to_text(),
        cameras.join(","),
        ring,
    )
}

/// Renders deterministic non-secret `fss.daemon_stop.v1` JSON from a graceful stop response.
#[must_use]
pub fn render_stop_accepted_json(
    desc: &crate::control::DaemonRuntimeDescriptor,
    op_id: &fss_core::OperationId,
    state: fss_ipc::ControlOperationState,
) -> String {
    format!(
        "{{\"schema\":\"fss.daemon_stop.v1\",\"site_id\":\"{}\",\"daemon_instance_id\":\"{}\",\"operation_id\":\"{}\",\"state\":\"{state:?}\"}}",
        escape_json(&desc.site_id),
        escape_json(&desc.daemon_instance_id),
        escape_json(op_id.as_str()),
    )
}

/// Escapes a UTF-8 string safely for deterministic JSON string literals.
#[must_use]
pub fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
