#![forbid(unsafe_code)]
//! Deterministic serde-free JSONL tracing for local IPC operations and offline fallbacks.

use core::fmt::Write as _;

/// One structured JSONL trace record emitted per IPC operation or offline refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcTraceEvent {
    /// Client request identifier (`0` for handshake or connection-level events).
    pub req_id: u64,
    /// Stable operation label (e.g. `handshake`, `query_live_status`, `submit_delta_batch`).
    pub op: String,
    /// Total wire frame bytes sent plus received (`0` when offline fallback triggered).
    pub frame_bytes: usize,
    /// End-to-end round-trip time in microseconds.
    pub rtt_us: u64,
    /// Stable outcome string (`ok`, `cancelled`, `stream_end`, or `ERR-...-NNN`).
    pub outcome: String,
    /// Whether the offline direct read-only fallback path was used.
    pub fallback_used: bool,
}

impl IpcTraceEvent {
    /// Renders this trace record as one compact, strictly escaped JSONL line (without trailing newline).
    #[must_use]
    pub fn to_jsonl_line(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push_str("{\"req_id\":");
        let _ = write!(out, "{}", self.req_id);
        out.push_str(",\"op\":");
        push_json_string(&mut out, &self.op);
        out.push_str(",\"frame_bytes\":");
        let _ = write!(out, "{}", self.frame_bytes);
        out.push_str(",\"rtt_us\":");
        let _ = write!(out, "{}", self.rtt_us);
        out.push_str(",\"outcome\":");
        push_json_string(&mut out, &self.outcome);
        out.push_str(",\"fallback_used\":");
        out.push_str(if self.fallback_used { "true" } else { "false" });
        out.push('}');
        out
    }
}

/// Formats a slice of trace events into newline-delimited JSONL text.
#[must_use]
pub fn format_trace_jsonl(events: &[IpcTraceEvent]) -> String {
    let mut out = String::new();
    for event in events {
        out.push_str(&event.to_jsonl_line());
        out.push('\n');
    }
    out
}

fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
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
    out.push('"');
}
