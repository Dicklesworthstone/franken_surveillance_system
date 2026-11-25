#![forbid(unsafe_code)]
//! Live `fss-daemon` IPC subscription client (`query_live_daemon_status` + `SubscribeDeltas`)
//! and structured-concurrency [`LiveCockpitHub`] powering `fss-dashboard --live` and HTTP SSE.
//!
//! Semantic plane: `"projection"`.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{CanonicalDecode, PrincipalId};
use fss_daemon::query_live_daemon_status;
use fss_ipc::{
    DeltaEventSummary, DeltaSubscriptionItem, DeploymentChannel, DeploymentClient, IpcClient,
    IpcResponse, LiveDaemonStatus, StreamEndReason,
};

pub use super::live_model::{LiveCockpitFrame, LiveDeltaEntry};
pub use super::live_projection::assemble_live_frame;
use super::live_render::render_live_frame_json;
use super::{Lease, Options};

const MAX_RECENT_DELTAS: usize = 64;

fn live_principal() -> io::Result<PrincipalId> {
    PrincipalId::parse("principal:local-operator")
        .map_err(|err| io::Error::other(format!("invalid operator principal: {err}")))
}

fn query_status_on_client(client: &mut IpcClient) -> Option<LiveDaemonStatus> {
    let req_id = client.next_request_id();
    match client.query_live_status(req_id, true, true) {
        Ok(IpcResponse::LiveStatus(status)) => Some(status),
        _ => None,
    }
}

fn decode_delta_summary(
    commit_sequence: u64,
    summary_canonical: &[u8],
) -> (String, String, String) {
    match DeltaEventSummary::from_canonical_bytes(summary_canonical) {
        Ok(s) => (
            format!("{:?}", s.delta_class),
            format!("{:?}", s.priority),
            s.summary,
        ),
        Err(_) => (
            "MaterialState".to_owned(),
            "Normal".to_owned(),
            format!("commit_seq={commit_sequence}"),
        ),
    }
}

/// Connects to `fss-daemon` (or falls back read-only), optionally awaits `once_events` live
/// `SubscribeDeltas` notifications, and returns the assembled [`LiveCockpitFrame`].
pub fn collect_live_frame(options: &Options, lease: &Lease) -> io::Result<LiveCockpitFrame> {
    lease.check()?;
    let root = options
        .root
        .as_ref()
        .ok_or_else(|| io::Error::other("live mode requires --root"))?;
    let site = options
        .site
        .as_deref()
        .ok_or_else(|| io::Error::other("live mode requires --site"))?;
    let principal = live_principal()?;
    let basis = reference_contract_basis();

    let live_probe = query_live_daemon_status(root, Some(site), principal.clone());
    let channel = DeploymentClient::connect_or_direct_with_capabilities(
        root,
        site,
        &basis,
        principal,
        vec!["CAP-OBSERVE-STATUS-001".to_owned()],
    );

    let (descriptor, mut status, mut client) = match (live_probe, channel) {
        (Ok((desc, st)), Ok(DeploymentChannel::LiveDaemon(ipc))) => (desc, st, ipc),
        (Err(err), _) => {
            return assemble_live_frame(
                root,
                site,
                None,
                Some(format!("daemon offline ({err})")),
                &[],
                0,
                0,
                None,
            );
        }
        (
            _,
            Ok(DeploymentChannel::OfflineDirect {
                fallback_reason, ..
            }),
        ) => {
            return assemble_live_frame(root, site, None, Some(fallback_reason), &[], 0, 0, None);
        }
        (_, Err(err)) => {
            return Err(io::Error::other(format!(
                "live IPC security/handshake error: {err}"
            )));
        }
    };

    let target_events = options.once_events.unwrap_or(0);
    let mut cursor = status.head_commit_sequence;
    let mut recent: VecDeque<LiveDeltaEntry> = VecDeque::new();
    let mut deltas_received = 0u64;
    let mut max_latency_ms = 0u64;
    let mut last_latency_ms = None;

    while deltas_received < target_events && lease.check().is_ok() {
        let remaining_target = target_events.saturating_sub(deltas_received);
        let batch_cap = u32::try_from(remaining_target.min(64)).unwrap_or(64);
        let req_id = client.next_request_id();
        let wait_started = Instant::now();
        let mut end_reason = None;
        match client.subscribe_deltas(req_id, cursor, batch_cap) {
            Ok(sub) => {
                for item in sub {
                    let received_at = Instant::now();
                    match item {
                        Ok(DeltaSubscriptionItem::Event {
                            commit_sequence,
                            delta_digest,
                            summary_canonical,
                            ..
                        }) => {
                            let elapsed_ms = u64::try_from(
                                received_at
                                    .saturating_duration_since(wait_started)
                                    .as_millis(),
                            )
                            .unwrap_or(u64::MAX);
                            let (delta_class, priority, summary) =
                                decode_delta_summary(commit_sequence, &summary_canonical);
                            cursor = cursor.max(commit_sequence);
                            deltas_received = deltas_received.saturating_add(1);
                            max_latency_ms = max_latency_ms.max(elapsed_ms);
                            last_latency_ms = Some(elapsed_ms);
                            if recent.len() >= MAX_RECENT_DELTAS {
                                recent.pop_front();
                            }
                            recent.push_back(LiveDeltaEntry {
                                commit_sequence,
                                delta_digest: delta_digest.to_text(),
                                delta_class,
                                priority,
                                summary,
                                latency_ms: Some(elapsed_ms),
                            });
                            // Consume StreamEnd even when the event target is met. It carries
                            // continuation validity and must not leak into the next RPC.
                        }
                        Ok(DeltaSubscriptionItem::End { reason, .. }) => {
                            end_reason = Some(reason);
                            break;
                        }
                        Err(_) => {
                            end_reason = Some(StreamEndReason::Cancelled);
                            break;
                        }
                    }
                }
            }
            Err(_) => break,
        }
        if end_reason == Some(StreamEndReason::CursorStale) {
            return Err(io::Error::other(
                "live delta history is incomplete; resnapshot before requesting more events",
            ));
        }
        if matches!(
            end_reason,
            Some(StreamEndReason::DaemonShuttingDown | StreamEndReason::Cancelled)
        ) {
            break;
        }
        if let Some(refreshed) = query_status_on_client(&mut client) {
            status = refreshed;
        }
    }

    if let Some(refreshed) = query_status_on_client(&mut client) {
        status = refreshed;
    }

    let recent_vec: Vec<LiveDeltaEntry> = recent.into_iter().collect();
    assemble_live_frame(
        root,
        site,
        Some((&descriptor, &status)),
        None,
        &recent_vec,
        deltas_received,
        max_latency_ms,
        last_latency_ms,
    )
}

/// Shared lock-free broadcast hub feeding `/api/live` and `/api/live/stream` (SSE) inside a
/// structured `std::thread::scope` without detached threads or polling storms.
pub struct LiveCockpitHub {
    state: Mutex<LiveHubState>,
    notify: Condvar,
    shutdown: AtomicBool,
}

struct LiveHubState {
    generation: u64,
    latest_json: String,
}

impl LiveCockpitHub {
    /// Creates a new [`LiveCockpitHub`] initialized with `initial_json`.
    #[must_use]
    pub fn new(initial_json: String) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LiveHubState {
                generation: 1,
                latest_json: initial_json,
            }),
            notify: Condvar::new(),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Publishes an updated JSON frame and wakes all waiting SSE subscribers immediately.
    pub fn publish(&self, next_json: String) {
        if let Ok(mut guard) = self.state.lock()
            && guard.latest_json != next_json
        {
            guard.generation = guard.generation.saturating_add(1);
            guard.latest_json = next_json;
            self.notify.notify_all();
        }
    }

    /// Returns `(generation, latest_json)` for immediate `/api/live` or initial SSE delivery.
    #[must_use]
    pub fn snapshot(&self) -> (u64, String) {
        match self.state.lock() {
            Ok(guard) => (guard.generation, guard.latest_json.clone()),
            Err(_) => (0, "{}".to_owned()),
        }
    }

    /// Blocks cooperatively up to `timeout` until `generation > last_seen` or shutdown triggers.
    #[must_use]
    pub fn wait_next(&self, last_seen: u64, timeout: Duration) -> Option<(u64, String)> {
        let Ok(mut guard) = self.state.lock() else {
            return None;
        };
        if guard.generation > last_seen {
            return Some((guard.generation, guard.latest_json.clone()));
        }
        if self.shutdown.load(Ordering::Acquire) {
            return None;
        }
        let Ok((updated, _)) = self.notify.wait_timeout(guard, timeout) else {
            return None;
        };
        guard = updated;
        if guard.generation > last_seen {
            Some((guard.generation, guard.latest_json.clone()))
        } else {
            None
        }
    }

    /// Signals cooperative shutdown and wakes all SSE/subscriber waiters immediately.
    pub fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.notify.notify_all();
    }

    /// Returns `true` once shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

/// Runs the cooperative `SubscribeDeltas` watcher loop inside a scoped worker thread until
/// `hub.is_shutdown()` or `lease.check()` expires.
pub fn run_delta_watcher_loop(options: &Options, lease: &Lease, hub: &LiveCockpitHub) {
    let Some(root) = options.root.as_deref() else {
        return;
    };
    let Some(site) = options.site.as_deref() else {
        return;
    };
    let Ok(principal) = live_principal() else {
        return;
    };
    let basis = reference_contract_basis();
    let mut recent: VecDeque<LiveDeltaEntry> = VecDeque::new();
    let (mut deltas_received, mut max_latency_ms, mut last_latency_ms) = (0u64, 0u64, None);

    while !hub.is_shutdown() && lease.check().is_ok() {
        let live_probe = query_live_daemon_status(root, Some(site), principal.clone());
        let channel = DeploymentClient::connect_or_direct_with_capabilities(
            root,
            site,
            &basis,
            principal.clone(),
            vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        );
        let (descriptor, mut status, mut client) = match (live_probe, channel) {
            (Ok((desc, st)), Ok(DeploymentChannel::LiveDaemon(ipc))) => (desc, st, ipc),
            (Err(err), _) => {
                let rows: Vec<_> = recent.iter().cloned().collect();
                if let Ok(frame) = assemble_live_frame(
                    root,
                    site,
                    None,
                    Some(format!("daemon offline ({err})")),
                    &rows,
                    deltas_received,
                    max_latency_ms,
                    last_latency_ms,
                ) {
                    hub.publish(render_live_frame_json(&frame));
                }
                if hub.is_shutdown() || lease.check().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            (
                _,
                Ok(DeploymentChannel::OfflineDirect {
                    fallback_reason, ..
                }),
            ) => {
                let rows: Vec<_> = recent.iter().cloned().collect();
                if let Ok(frame) = assemble_live_frame(
                    root,
                    site,
                    None,
                    Some(fallback_reason),
                    &rows,
                    deltas_received,
                    max_latency_ms,
                    last_latency_ms,
                ) {
                    hub.publish(render_live_frame_json(&frame));
                }
                if hub.is_shutdown() || lease.check().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            (_, Err(_)) => {
                if hub.is_shutdown() || lease.check().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        };

        let mut cursor = status.head_commit_sequence;
        let init_rows: Vec<_> = recent.iter().cloned().collect();
        if let Ok(frame) = assemble_live_frame(
            root,
            site,
            Some((&descriptor, &status)),
            None,
            &init_rows,
            deltas_received,
            max_latency_ms,
            last_latency_ms,
        ) {
            hub.publish(render_live_frame_json(&frame));
        }

        while !hub.is_shutdown() && lease.check().is_ok() {
            let req_id = client.next_request_id();
            let wait_started = Instant::now();
            let mut reconnect = false;
            let mut saw_event = false;
            match client.subscribe_deltas(req_id, cursor, 64) {
                Ok(sub) => {
                    for item in sub {
                        match item {
                            Ok(DeltaSubscriptionItem::Event {
                                commit_sequence,
                                delta_digest,
                                summary_canonical,
                                ..
                            }) => {
                                saw_event = true;
                                let elapsed_ms = u64::try_from(wait_started.elapsed().as_millis())
                                    .unwrap_or(u64::MAX);
                                let (delta_class, priority, summary) =
                                    decode_delta_summary(commit_sequence, &summary_canonical);
                                cursor = cursor.max(commit_sequence);
                                deltas_received = deltas_received.saturating_add(1);
                                max_latency_ms = max_latency_ms.max(elapsed_ms);
                                last_latency_ms = Some(elapsed_ms);
                                if recent.len() >= MAX_RECENT_DELTAS {
                                    recent.pop_front();
                                }
                                recent.push_back(LiveDeltaEntry {
                                    commit_sequence,
                                    delta_digest: delta_digest.to_text(),
                                    delta_class,
                                    priority,
                                    summary,
                                    latency_ms: Some(elapsed_ms),
                                });
                                // Render each arrival promptly while the bounded stream stays
                                // attached. Refresh status on this client only after StreamEnd.
                                let rows: Vec<_> = recent.iter().cloned().collect();
                                if let Ok(frame) = assemble_live_frame(
                                    root,
                                    site,
                                    Some((&descriptor, &status)),
                                    None,
                                    &rows,
                                    deltas_received,
                                    max_latency_ms,
                                    last_latency_ms,
                                ) {
                                    hub.publish(render_live_frame_json(&frame));
                                }
                            }
                            Ok(DeltaSubscriptionItem::End { reason, .. }) => {
                                if matches!(
                                    reason,
                                    StreamEndReason::DaemonShuttingDown
                                        | StreamEndReason::Cancelled
                                        | StreamEndReason::CursorStale
                                ) {
                                    reconnect = true;
                                }
                                break;
                            }
                            Err(_) => {
                                reconnect = true;
                                break;
                            }
                        }
                    }
                }
                Err(_) => reconnect = true,
            }
            if reconnect {
                break;
            }
            if let Some(refreshed) = query_status_on_client(&mut client) {
                // Status can be ahead of unconsumed summaries. Only received events advance
                // the exclusive follow cursor.
                status = refreshed;
            }
            if saw_event {
                let rows: Vec<_> = recent.iter().cloned().collect();
                if let Ok(frame) = assemble_live_frame(
                    root,
                    site,
                    Some((&descriptor, &status)),
                    None,
                    &rows,
                    deltas_received,
                    max_latency_ms,
                    last_latency_ms,
                ) {
                    hub.publish(render_live_frame_json(&frame));
                }
            }
        }
    }
}
