#![forbid(unsafe_code)]
//! Loss boundaries for the daemon's bounded live delta history.

use super::{BufferedDeltaLog, DeltaBusCursor, MAX_DELTA_BUS_EVENTS};
use fss_core::ContentDigest;
use fss_ipc::StreamEndReason;

fn push(log: &mut BufferedDeltaLog, commit_sequence: u64) {
    let bytes = commit_sequence.to_le_bytes().to_vec();
    log.push(commit_sequence, ContentDigest::sha256(&bytes), bytes);
}

fn sequences(log: &BufferedDeltaLog, cursor: DeltaBusCursor, maximum: u32) -> Vec<u64> {
    log.read_after(cursor, maximum)
        .expect("retained cursor")
        .events
        .iter()
        .map(|event| event.commit_sequence)
        .collect()
}

#[test]
fn restart_requires_resnapshot_for_pre_startup_history() {
    let log = BufferedDeltaLog::new(40);
    assert_eq!(log.start(39, 40), Err(StreamEndReason::CursorStale));
    assert_eq!(log.start(41, 40), Err(StreamEndReason::CursorStale));
    let current = log.start(40, 40).expect("current startup anchor");
    let pending = log.read_after(current, 8).expect("no omitted history");
    assert!(pending.events.is_empty());
    assert_eq!(pending.end_reason, None);
    assert!(!log.has_pending(current).expect("valid current position"));
}

#[test]
fn fresh_replay_honors_the_exclusive_commit_cursor() {
    let mut log = BufferedDeltaLog::new(0);
    for commit in 1..=3 {
        push(&mut log, commit);
    }
    let cursor = log.start(1, 3).expect("retained lower bound");
    let batch = log.read_after(cursor, 8).expect("retained history");
    assert_eq!(
        batch
            .events
            .iter()
            .map(|event| event.commit_sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(batch.end_reason, None);
    for event in batch.events {
        assert_eq!(
            event.delta_digest,
            ContentDigest::sha256(&event.summary_canonical)
        );
    }
}

#[test]
fn eviction_rejects_old_cursors_but_allows_the_exact_exclusive_floor() {
    let mut log = BufferedDeltaLog::new(0);
    let head = MAX_DELTA_BUS_EVENTS as u64 + 1;
    for commit in 1..=head {
        push(&mut log, commit);
    }
    assert_eq!(log.events.len(), MAX_DELTA_BUS_EVENTS);
    assert_eq!(log.start(0, head), Err(StreamEndReason::CursorStale));
    let floor = log
        .start(1, head)
        .expect("evicted row is already acknowledged");
    assert_eq!(sequences(&log, floor, 2), vec![2, 3]);
    let batch = log
        .read_after(floor, u32::MAX)
        .expect("complete retained suffix");
    assert_eq!(batch.events.len(), MAX_DELTA_BUS_EVENTS);
    assert_eq!(batch.events.last().expect("tail").commit_sequence, head);
    assert_eq!(batch.end_reason, None);
}

#[test]
fn replay_floor_does_not_regress_when_publications_arrive_out_of_commit_order() {
    let mut log = BufferedDeltaLog::new(0);
    push(&mut log, 10);
    for _ in 0..MAX_DELTA_BUS_EVENTS + 1 {
        push(&mut log, 4);
    }
    assert_eq!(log.start(9, 10), Err(StreamEndReason::CursorStale));
    let floor = log.start(10, 10).expect("all earlier commits acknowledged");
    assert!(sequences(&log, floor, 8).is_empty());
}

#[test]
fn attached_subscriber_detects_eviction_before_delivering_a_truncated_suffix() {
    let mut log = BufferedDeltaLog::new(0);
    let cursor = log.start(0, 0).expect("attach before publication");
    for commit in 1..=MAX_DELTA_BUS_EVENTS as u64 + 1 {
        push(&mut log, commit);
    }
    assert_eq!(
        log.read_after(cursor, 8).err(),
        Some(StreamEndReason::CursorStale)
    );
    assert_eq!(log.has_pending(cursor), Err(StreamEndReason::CursorStale));
}

#[test]
fn attached_subscriber_at_the_bus_floor_loses_no_event() {
    let mut log = BufferedDeltaLog::new(0);
    let mut cursor = log.start(0, 0).expect("attach");
    push(&mut log, 1);
    let first = log
        .read_after(cursor, 1)
        .expect("first event")
        .events
        .remove(0);
    cursor.advance(first.bus_seq, first.commit_sequence);
    for commit in 2..=MAX_DELTA_BUS_EVENTS as u64 + 1 {
        push(&mut log, commit);
    }
    assert_eq!(sequences(&log, cursor, 2), vec![2, 3]);
}

#[test]
fn eviction_during_a_previously_copied_batch_is_detected_on_the_next_read() {
    let mut log = BufferedDeltaLog::new(0);
    let mut cursor = log.start(0, 0).expect("attach");
    push(&mut log, 1);
    let first = log
        .read_after(cursor, 1)
        .expect("copy first")
        .events
        .remove(0);
    // Simulate publication overtaking a subscriber while its first socket write is blocked.
    for commit in 2..=MAX_DELTA_BUS_EVENTS as u64 + 2 {
        push(&mut log, commit);
    }
    cursor.advance(first.bus_seq, first.commit_sequence);
    assert_eq!(
        log.read_after(cursor, 1).err(),
        Some(StreamEndReason::CursorStale)
    );
    assert_eq!(
        log.finish(cursor, StreamEndReason::BatchLimitReached),
        StreamEndReason::CursorStale
    );
    assert_eq!(
        log.finish(cursor, StreamEndReason::Completed),
        StreamEndReason::CursorStale
    );
}

#[test]
fn terminal_boundary_rechecks_publications_during_the_last_socket_write() {
    let mut log = BufferedDeltaLog::new(0);
    let mut cursor = log.start(0, 0).expect("attach");
    push(&mut log, 1);
    let batch = log.read_after(cursor, 1).expect("copy first");
    assert_eq!(batch.end_reason, Some(StreamEndReason::BatchLimitReached));
    for event in batch.events {
        cursor.advance(event.bus_seq, event.commit_sequence);
    }
    push(&mut log, 2);
    assert_eq!(
        log.finish(cursor, StreamEndReason::BatchLimitReached),
        StreamEndReason::BatchLimitReached
    );
    push(&mut log, 1);
    assert_eq!(
        log.finish(cursor, StreamEndReason::BatchLimitReached),
        StreamEndReason::CursorStale
    );
    assert_eq!(
        log.finish(cursor, StreamEndReason::Completed),
        StreamEndReason::CursorStale
    );
}

#[test]
fn splitting_a_same_commit_group_requires_resnapshot_instead_of_clean_continuation() {
    let mut log = BufferedDeltaLog::new(6);
    for commit in [7, 7, 8] {
        push(&mut log, commit);
    }
    let cursor = log.start(6, 8).expect("start");
    let split = log.read_after(cursor, 1).expect("bounded first event");
    assert_eq!(split.events.len(), 1);
    assert_eq!(split.end_reason, Some(StreamEndReason::CursorStale));

    let complete_group = log.read_after(cursor, 2).expect("complete commit group");
    assert_eq!(
        complete_group.end_reason,
        Some(StreamEndReason::BatchLimitReached)
    );
    assert_eq!(
        sequences(&log, log.start(7, 8).expect("safe next commit"), 2),
        vec![8]
    );
}

#[test]
fn truncation_checks_all_unreturned_rows_for_late_same_or_earlier_commits() {
    for last_commit in [7, 8] {
        let mut log = BufferedDeltaLog::new(6);
        for commit in [8, 9, 10, last_commit] {
            push(&mut log, commit);
        }
        let batch = log
            .read_after(log.start(6, 10).expect("start"), 1)
            .expect("first");
        assert_eq!(batch.end_reason, Some(StreamEndReason::CursorStale));
    }
}

#[test]
fn live_same_commit_notifications_are_preserved_after_attachment() {
    let mut log = BufferedDeltaLog::new(5);
    let mut cursor = log.start(5, 5).expect("current anchor");
    push(&mut log, 5);
    let event = log
        .read_after(cursor, 8)
        .expect("new live notification")
        .events
        .remove(0);
    assert_eq!(event.commit_sequence, 5);
    cursor.advance(event.bus_seq, event.commit_sequence);
    assert!(!log.has_pending(cursor).expect("no duplicate"));
}

#[test]
fn attached_cursor_preserves_the_greatest_delivered_commit() {
    let mut log = BufferedDeltaLog::new(8);
    for commit in [10, 9, 11] {
        push(&mut log, commit);
    }
    let mut cursor = log.start(8, 11).expect("start");
    let batch = log.read_after(cursor, 2).expect("two events");
    assert_eq!(batch.end_reason, Some(StreamEndReason::BatchLimitReached));
    for event in batch.events {
        cursor.advance(event.bus_seq, event.commit_sequence);
    }
    assert_eq!(cursor.commit_sequence, 10);
    assert_eq!(sequences(&log, cursor, 1), vec![11]);
}

#[test]
fn bus_sequence_exhaustion_never_wraps_into_an_accepted_cursor() {
    let mut log = BufferedDeltaLog::new(0);
    log.tail_bus_seq = u64::MAX;
    let cursor = log.start(0, 0).expect("tail still representable");
    push(&mut log, 1);
    assert_eq!(log.tail_bus_seq, u64::MAX);
    assert_eq!(log.start(1, 1), Err(StreamEndReason::CursorStale));
    assert_eq!(log.has_pending(cursor), Err(StreamEndReason::CursorStale));
}

#[test]
fn ipc_reports_restart_loss_and_ambiguous_batch_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use crate::control::{
        ControlPlaneServer, ControlPlaneShared, ControlStatusSnapshot, ForwardBatchWriter,
    };
    use crate::error::DaemonError;
    use fss_core::{DeltaPriority, MeaningfulDeltaClass, PrincipalId, reference_contract_basis};
    use fss_ipc::{
        ActiveScrubStatus, DeltaSubscriptionItem, IpcClient, IpcClientConfig, RingWatermarkStatus,
    };

    struct NeverWrite;
    impl ForwardBatchWriter for NeverWrite {
        fn forward_delta_batch(
            &self,
            _bytes: &[u8],
        ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
            Err(DaemonError::InvalidConfig {
                detail: "read-only fixture".to_owned(),
            })
        }
    }
    struct OwnedTempRoot(PathBuf);
    impl Drop for OwnedTempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let path = PathBuf::from("/tmp").join(format!(
        "fss-delta-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path)?;
    let root = OwnedTempRoot(path);
    let status = ControlStatusSnapshot {
        head_commit_sequence: 40,
        history_root: ContentDigest::sha256(b"delta-test-history"),
        state_root: ContentDigest::sha256(b"delta-test-state"),
        cameras: Vec::new(),
        ring: RingWatermarkStatus {
            used_bytes: 0,
            capacity_bytes: 1_024,
            watermark_percent: 0,
        },
        scrub: ActiveScrubStatus::Idle,
    };
    let stale_status = status.clone();
    let shared = ControlPlaneShared::new(
        "site:delta-history",
        fss_ipc::deployment_root_digest(&root.0),
        Vec::new(),
        status,
        Arc::new(NeverWrite),
    );
    let server = ControlPlaneServer::start(
        root.0.clone(),
        "site:delta-history".to_owned(),
        "daemon:delta-history".to_owned(),
        ContentDigest::sha256(b"delta-test-manifest"),
        0,
        Arc::clone(&shared),
    )?;
    let mut client = IpcClient::connect(IpcClientConfig {
        deployment_root: root.0.clone(),
        deployment_id: "site:delta-history".to_owned(),
        contract_basis_digest: reference_contract_basis().basis_digest(),
        principal: PrincipalId::parse("principal:delta-reader")?,
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(3),
    })?;

    fn read(
        client: &mut IpcClient,
        since: u64,
        limit: u32,
    ) -> Result<(Vec<u64>, StreamEndReason), Box<dyn std::error::Error>> {
        let request_id = client.next_request_id();
        let mut events = Vec::new();
        for item in client.subscribe_deltas(request_id, since, limit)? {
            match item? {
                DeltaSubscriptionItem::Event {
                    commit_sequence, ..
                } => events.push(commit_sequence),
                DeltaSubscriptionItem::End { reason, .. } => return Ok((events, reason)),
            }
        }
        Err("subscription omitted its terminal reason".into())
    }

    assert_eq!(
        read(&mut client, 39, 8)?,
        (Vec::new(), StreamEndReason::CursorStale)
    );
    for (commit, class) in [
        (41_u64, MeaningfulDeltaClass::CoverageLoss),
        (41, MeaningfulDeltaClass::EffectUncertainty),
        (42, MeaningfulDeltaClass::TerminalTransition),
    ] {
        shared.publish_delta_summary(
            commit,
            ContentDigest::sha256(&commit.to_le_bytes()),
            class,
            DeltaPriority::High,
            "protected delta fixture",
        );
    }
    // A supervisor snapshot taken before a concurrent forward must not regress the head.
    shared.publish_status(stale_status);
    assert_eq!(shared.head_commit_sequence.load(Ordering::Acquire), 42);
    assert_eq!(
        read(&mut client, 40, 1)?,
        (vec![41], StreamEndReason::CursorStale)
    );
    assert_eq!(
        read(&mut client, 40, 2)?,
        (vec![41, 41], StreamEndReason::BatchLimitReached)
    );
    assert_eq!(
        read(&mut client, 41, 1)?,
        (vec![42], StreamEndReason::BatchLimitReached)
    );
    assert_eq!(
        read(&mut client, 40, 8)?,
        (vec![41, 41, 42], StreamEndReason::Completed)
    );
    assert_eq!(
        read(&mut client, 42, 1)?,
        (Vec::new(), StreamEndReason::Completed)
    );
    drop(client);
    server.shutdown()?;
    Ok(())
}
