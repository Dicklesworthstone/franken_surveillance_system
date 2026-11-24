#![forbid(unsafe_code)]
//! Scale, cold-open latency, crash-cut mid-epoch rollover, and checkpoint-free rebuild contracts
//! for [`fss_projection_store::agent_index`].

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fss_core::{ContentDigest, EffectState, ObligationState, TimestampNs};
use fss_ledger::IncompleteTailPolicy;
use fss_pack::DurabilityMode;
use fss_projection_store::ProjectionError;
use fss_projection_store::agent_index::{
    AGENT_EPOCH_RECORD_MAGIC, AgentStoreIndex, AgentStoreIndexConfig, CaseLifecycle,
    EffectJournalEvent, EpochJournalConfig, IndexedCase, IndexedEffect, IndexedLearningProposal,
    IndexedObligation, IndexedSession, LearningProposalStatus, SessionJournalEvent,
    SessionLifecycle, epoch_path,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    root: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fss-agent-scale-{label}-{}-{id}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn make_session(id: u64, lifecycle: SessionLifecycle, ts: i128) -> IndexedSession {
    IndexedSession {
        session_id: format!("session:{id:06}"),
        mission_id: format!("mission:{:04}", id % 20),
        principal_id: "principal:operator-scale".to_owned(),
        lifecycle,
        lease_expires_at_ns: TimestampNs(ts + 3_600_000_000_000),
        workspace_revision: 1,
        opened_at_ns: TimestampNs(ts),
        updated_at_ns: TimestampNs(ts),
        last_seq: 0,
    }
}

fn make_effect(id: &str, state: EffectState, ts: i128) -> IndexedEffect {
    IndexedEffect {
        operation_id: id.to_owned(),
        effect_class: "alert.webhook".to_owned(),
        state,
        receipt_digest: ContentDigest::sha256(id.as_bytes()),
        updated_at_ns: TimestampNs(ts),
        last_seq: 0,
    }
}

fn make_obligation(id: &str, op_id: &str, state: ObligationState, ts: i128) -> IndexedObligation {
    IndexedObligation {
        obligation_id: id.to_owned(),
        operation_id: op_id.to_owned(),
        state,
        proof_digest: matches!(
            state,
            ObligationState::Verified | ObligationState::Failed | ObligationState::Cancelled
        )
        .then(|| ContentDigest::sha256(id.as_bytes())),
        updated_at_ns: TimestampNs(ts),
        last_seq: 0,
    }
}

fn make_learning(id: u64, ts: i128) -> IndexedLearningProposal {
    let proposal_id = format!("learning:{id:06}");
    IndexedLearningProposal {
        proposal_id: proposal_id.clone(),
        root_id: format!("learning-root-{id:06}"),
        experience_id: format!("experience:{id:06}"),
        source_episode_id: format!("episode:{id:06}"),
        session_id: format!("session:{:06}", id % 50),
        mission_id: format!("mission:{:04}", id % 10),
        class_label: "procedure_candidate".to_owned(),
        publication_root: ContentDigest::sha256(format!("pub-{id}").as_bytes()),
        experience_digest: ContentDigest::sha256(format!("exp-{id}").as_bytes()),
        proposal_digest: ContentDigest::sha256(format!("prop-{id}").as_bytes()),
        payload_bytes: 2_048,
        status: LearningProposalStatus::PendingReview,
        transition_receipt_digest: None,
        created_at_ns: TimestampNs(ts),
        review_after_ns: TimestampNs(ts + 86_400_000_000_000),
        expires_at_ns: TimestampNs(ts + 2_592_000_000_000_000),
        last_seq: 0,
    }
}

#[test]
fn scale_10k_sessions_10k_effects_50_open_500_learning_cold_open_and_orient() -> TestResult {
    let dir = TempDir::new("main")?;
    let cfg = AgentStoreIndexConfig::uniform(EpochJournalConfig {
        max_epoch_bytes: 256 * 1024,
        checkpoint_stride: 4_096,
        durability: DurabilityMode::Fsync,
        tail_policy: IncompleteTailPolicy::Reject,
    });

    let (mut store, _) = AgentStoreIndex::open(&dir.root, cfg)?;

    // 1. 10,000 historical sessions: 9,950 terminal closed (archived out of hot set) + 50 active
    //    sessions with active leases and 50 open investigation cases.
    let mut session_events = Vec::with_capacity(20_050);
    for i in 0..10_000_u64 {
        let ts = 1_000_000 + i128::from(i) * 1_000;
        session_events.push(SessionJournalEvent::OpenSession(make_session(
            i,
            SessionLifecycle::Active,
            ts,
        )));
        if i < 9_950 {
            let terminal = match i % 3 {
                0 => SessionLifecycle::Closed,
                1 => SessionLifecycle::Revoked,
                _ => SessionLifecycle::Expired,
            };
            session_events.push(SessionJournalEvent::TransitionSession {
                session_id: format!("session:{i:06}"),
                lifecycle: terminal,
                updated_at_ns: TimestampNs(ts + 500),
            });
        } else {
            session_events.push(SessionJournalEvent::UpsertCase(IndexedCase {
                case_id: format!("case:{i:06}"),
                session_id: format!("session:{i:06}"),
                mission_id: format!("mission:{:04}", i % 20),
                lifecycle: CaseLifecycle::Open,
                hypothesis_count: 3,
                updated_at_ns: TimestampNs(ts + 250),
                last_seq: 0,
            }));
        }
    }
    store.append_session_events_batch(&session_events)?;

    // 2. 10,000 completed effects + 50 active open/indeterminate effects & 50 open obligations.
    let mut effect_events = Vec::with_capacity(20_100);
    for i in 0..10_000_u64 {
        let ts = 2_000_000 + i128::from(i) * 1_000;
        let op = format!("op:hist:{i:06}");
        let ob = format!("ob:hist:{i:06}");
        let st = match i % 3 {
            0 => EffectState::Verified,
            1 => EffectState::Failed,
            _ => EffectState::Cancelled,
        };
        let ob_st = match i % 3 {
            0 => ObligationState::Verified,
            1 => ObligationState::Failed,
            _ => ObligationState::Cancelled,
        };
        effect_events.push(EffectJournalEvent::UpsertEffect(make_effect(&op, st, ts)));
        effect_events.push(EffectJournalEvent::UpsertObligation(make_obligation(
            &ob, &op, ob_st, ts,
        )));
    }
    for i in 0..50_u64 {
        let ts = 90_000_000 + i128::from(i) * 1_000;
        let op = format!("op:live:{i:03}");
        let ob = format!("ob:live:{i:03}");
        let eff_state = if i < 25 {
            EffectState::Indeterminate
        } else {
            EffectState::Committed
        };
        let ob_state = if i < 25 {
            ObligationState::Indeterminate
        } else {
            ObligationState::Pending
        };
        effect_events.push(EffectJournalEvent::UpsertEffect(make_effect(
            &op, eff_state, ts,
        )));
        effect_events.push(EffectJournalEvent::UpsertObligation(make_obligation(
            &ob, &op, ob_state, ts,
        )));
    }
    store.append_effect_events_batch(&effect_events)?;

    // 3. 500 captured learning proposals backed by VirtualRootCatalog (exceeds 16 & 128 walls).
    let learning_batch: Vec<_> = (0..500_u64)
        .map(|i| make_learning(i, 50_000_000 + i128::from(i) * 10_000))
        .collect();
    store.record_learning_proposals_batch(&learning_batch)?;
    for i in 0..5_u64 {
        store.transition_learning_status(
            &format!("learning:{i:06}"),
            LearningProposalStatus::Promoted,
            ContentDigest::sha256(format!("promote-{i}").as_bytes()),
        )?;
    }
    for i in 5..10_u64 {
        store.transition_learning_status(
            &format!("learning:{i:06}"),
            LearningProposalStatus::Rejected,
            ContentDigest::sha256(format!("reject-{i}").as_bytes()),
        )?;
    }

    // Write verified checkpoints, then append a small post-checkpoint tail to exercise O(tail).
    store.checkpoint_all()?;
    store.append_session_event(SessionJournalEvent::RenewLease {
        session_id: "session:009999".to_owned(),
        lease_expires_at_ns: TimestampNs(999_000_000_000_000),
        workspace_revision: 2,
        updated_at_ns: TimestampNs(99_000_000),
    })?;
    let expected_digest = store.state_digest();
    drop(store);

    // Cold-open from checkpoint + tail and measure latency (< 10 ms target).
    let t_open = Instant::now();
    let (reopened, report) = AgentStoreIndex::open(&dir.root, cfg)?;
    let cold_open_ms = t_open.elapsed().as_secs_f64() * 1_000.0;

    let now = TimestampNs(100_000_000);
    let t_orient = Instant::now();
    let summary = reopened.orient_summary(now, 16);
    let orient_query_ms = t_orient.elapsed().as_secs_f64() * 1_000.0;

    println!(
        "{{\"event\":\"agent_scale_contract\",\"sessions_total\":{},\"learning_total\":{},\"effects_total\":{},\"open_obligations\":{},\"indeterminate_effects\":{},\"cold_open_ms\":{:.3},\"orient_query_ms\":{:.3},\"session_epochs\":{},\"effect_epochs\":{}}}",
        summary.sessions.total_sessions_ever,
        summary.learning.total_captured,
        summary.effects.total_effects_ever,
        summary.effects.open_obligations,
        summary.effects.indeterminate_effects,
        cold_open_ms,
        orient_query_ms,
        report.sessions.epoch_count,
        report.effects.epoch_count,
    );

    assert_eq!(reopened.state_digest(), expected_digest);
    assert!(report.sessions.loaded_checkpoint_seq.is_some());
    assert!(report.effects.loaded_checkpoint_seq.is_some());
    assert!(report.learning.loaded_checkpoint_seq.is_some());
    assert!(
        cold_open_ms < 10.0,
        "cold_open_ms={cold_open_ms:.3} exceeded 10 ms budget"
    );
    assert!(
        orient_query_ms < 5.0,
        "orient_query_ms={orient_query_ms:.3} exceeded 5 ms budget"
    );

    // Verify exact session/case/lease invariants.
    assert_eq!(summary.sessions.total_sessions_ever, 10_000);
    assert_eq!(summary.sessions.active_sessions, 50);
    assert_eq!(summary.sessions.active_leases, 50);
    assert_eq!(summary.sessions.archived_terminal_sessions, 9_950);
    assert_eq!(summary.sessions.active_cases, 50);
    assert!(
        reopened
            .sessions()
            .get_active_session("session:000000")
            .is_none()
    );
    assert!(reopened.sessions().is_lease_active("session:009999", now));

    // Verify 100% of all 50 open obligations and all 25 indeterminate + 25 committed effects survive.
    assert_eq!(summary.effects.total_effects_ever, 10_050);
    assert_eq!(summary.effects.completed_effects_count, 10_000);
    assert_eq!(summary.effects.non_terminal_effects, 50);
    assert_eq!(summary.effects.indeterminate_effects, 25);
    assert_eq!(summary.effects.open_obligations, 50);
    for i in 0..50_u64 {
        let op = format!("op:live:{i:03}");
        let ob = format!("ob:live:{i:03}");
        assert!(
            reopened.effects().get_non_terminal_effect(&op).is_some(),
            "missing live effect {op}"
        );
        assert!(
            reopened.effects().get_open_obligation(&ob).is_some(),
            "missing open obligation {ob}"
        );
        if i < 25 {
            assert!(
                reopened.effects().get_indeterminate_effect(&op).is_some(),
                "missing indeterminate effect {op}"
            );
        }
    }

    // Verify 500 learning proposals + VirtualRootCatalog + deterministic full pagination.
    assert_eq!(summary.learning.total_captured, 500);
    assert_eq!(summary.learning.pending_review, 490);
    assert_eq!(summary.learning.promoted, 5);
    assert_eq!(summary.learning.rejected, 5);
    assert_eq!(summary.learning.top_recent.len(), 16);
    assert_eq!(summary.learning.omitted_count, 484);
    assert!(summary.learning.next_cursor.is_some());
    assert_eq!(summary.learning.catalog_live_roots, 500);
    assert!(
        reopened
            .learning()
            .catalog_root("learning-root-000499")
            .is_some()
    );

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = reopened.list_learning_page(cursor.as_deref(), 37);
        assert_eq!(page.total_captured, 500);
        for item in &page.entries {
            seen.push(item.proposal_id.clone());
        }
        if !page.has_more {
            assert!(page.next_cursor.is_none());
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen.len(), 500);
    assert_eq!(seen.first().map(String::as_str), Some("learning:000000"));
    assert_eq!(seen.last().map(String::as_str), Some("learning:000499"));
    assert!(seen.windows(2).all(|w| w[0] < w[1]));

    Ok(())
}

#[test]
fn crash_cut_mid_epoch_rollover_reject_and_recover() -> TestResult {
    let dir = TempDir::new("crash-rollover")?;
    let strict_cfg = AgentStoreIndexConfig::uniform(EpochJournalConfig {
        max_epoch_bytes: 4 * 1024,
        checkpoint_stride: 0,
        durability: DurabilityMode::Fsync,
        tail_policy: IncompleteTailPolicy::Reject,
    });
    let recover_cfg = AgentStoreIndexConfig::uniform(EpochJournalConfig {
        max_epoch_bytes: 4 * 1024,
        checkpoint_stride: 0,
        durability: DurabilityMode::Fsync,
        tail_policy: IncompleteTailPolicy::Truncate,
    });

    let (mut store, _) = AgentStoreIndex::open(&dir.root, strict_cfg)?;
    let events: Vec<_> = (0..120_u64)
        .map(|i| {
            SessionJournalEvent::OpenSession(make_session(
                i,
                SessionLifecycle::Active,
                10_000 + i128::from(i) * 100,
            ))
        })
        .collect();
    store.append_session_events_batch(&events)?;
    let committed_digest = store.state_digest();
    drop(store);

    // Confirm multiple epochs were sealed at the 4 KiB boundary.
    let sessions_epochs = dir.root.join("agent/sessions/epochs");
    let (_, pre_report) = AgentStoreIndex::open(&dir.root, strict_cfg)?;
    assert!(
        pre_report.sessions.epoch_count >= 3,
        "expected >= 3 epochs at 4 KiB rollover, got {}",
        pre_report.sessions.epoch_count
    );
    let last_epoch_id = pre_report.sessions.epoch_count - 1;
    let active_epoch_file = epoch_path(&sessions_epochs, last_epoch_id);

    // Fault A: append a truncated partial record header + corrupt tail garbage bytes.
    {
        let mut f = OpenOptions::new().append(true).open(&active_epoch_file)?;
        f.write_all(&AGENT_EPOCH_RECORD_MAGIC)?;
        f.write_all(&[0x01, 0x01, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x42])?;
        f.sync_all()?;
    }

    // Strict IncompleteTailPolicy::Reject MUST refuse.
    let strict_err = AgentStoreIndex::open(&dir.root, strict_cfg);
    assert!(
        matches!(strict_err, Err(ProjectionError::CorruptDerivedStore { .. })),
        "strict Reject must refuse torn tail"
    );

    // Explicit IncompleteTailPolicy::Truncate recovers cleanly with 0 committed records lost.
    let (mut recovered, rec_report) = AgentStoreIndex::open(&dir.root, recover_cfg)?;
    assert_eq!(rec_report.sessions.truncated_tail_bytes, 13);
    assert_eq!(recovered.state_digest(), committed_digest);
    assert_eq!(recovered.sessions().total_sessions_ever(), 120);

    // Append post-recovery record and confirm strict Reject reopens cleanly.
    recovered.append_session_event(SessionJournalEvent::OpenSession(make_session(
        120,
        SessionLifecycle::Active,
        99_999,
    )))?;
    let post_recovery_digest = recovered.state_digest();
    drop(recovered);

    let (reopened_strict, strict_report) = AgentStoreIndex::open(&dir.root, strict_cfg)?;
    assert_eq!(reopened_strict.state_digest(), post_recovery_digest);
    drop(reopened_strict);

    // Fault B: simulate crash mid-rollover creating a torn next epoch file (partial 20-byte header).
    let next_epoch_id = strict_report.sessions.epoch_count;
    let torn_next = epoch_path(&sessions_epochs, next_epoch_id);
    fs::write(&torn_next, b"FSSA\x00\x01corrupt_mid_rollover")?;

    assert!(matches!(
        AgentStoreIndex::open(&dir.root, strict_cfg),
        Err(ProjectionError::CorruptDerivedStore { .. })
    ));
    let (recovered_b, report_b) = AgentStoreIndex::open(&dir.root, recover_cfg)?;
    assert!(report_b.sessions.truncated_tail_bytes > 0);
    assert_eq!(recovered_b.state_digest(), post_recovery_digest);
    drop(recovered_b);

    // Fault C: corrupting an earlier sealed epoch (epoch 0) MUST fail closed even under Truncate.
    let epoch0 = epoch_path(&sessions_epochs, 0);
    {
        let mut f = OpenOptions::new().read(true).write(true).open(&epoch0)?;
        f.seek(SeekFrom::Start(70))?;
        f.write_all(&[0xFF, 0xFF, 0xFF, 0xFF])?;
        f.sync_all()?;
    }
    assert!(matches!(
        AgentStoreIndex::rebuild_from_epochs(&dir.root, recover_cfg),
        Err(ProjectionError::CorruptDerivedStore { .. })
    ));

    Ok(())
}

#[test]
fn delete_checkpoints_and_rebuild_from_epochs_bit_identical() -> TestResult {
    let dir = TempDir::new("rebuild-exact")?;
    let cfg = AgentStoreIndexConfig::uniform(EpochJournalConfig {
        max_epoch_bytes: 4 * 1024,
        checkpoint_stride: 128,
        durability: DurabilityMode::Fsync,
        tail_policy: IncompleteTailPolicy::Reject,
    });

    let (mut store, _) = AgentStoreIndex::open(&dir.root, cfg)?;
    for i in 0..300_u64 {
        let ts = 1_000 + i128::from(i) * 50;
        store.append_session_event(SessionJournalEvent::OpenSession(make_session(
            i,
            SessionLifecycle::Active,
            ts,
        )))?;
        if i < 270 {
            store.append_session_event(SessionJournalEvent::TransitionSession {
                session_id: format!("session:{i:06}"),
                lifecycle: SessionLifecycle::Closed,
                updated_at_ns: TimestampNs(ts + 10),
            })?;
        }
    }
    for i in 0..300_u64 {
        let ts = 50_000 + i128::from(i) * 50;
        let op = format!("op:rb:{i:04}");
        let ob = format!("ob:rb:{i:04}");
        let eff_st = if i < 280 {
            EffectState::Verified
        } else {
            EffectState::Indeterminate
        };
        let ob_st = if i < 280 {
            ObligationState::Verified
        } else {
            ObligationState::Indeterminate
        };
        store.append_effect_event(EffectJournalEvent::UpsertEffect(make_effect(
            &op, eff_st, ts,
        )))?;
        store.append_effect_event(EffectJournalEvent::UpsertObligation(make_obligation(
            &ob, &op, ob_st, ts,
        )))?;
    }
    let proposals: Vec<_> = (0..150_u64)
        .map(|i| make_learning(i, 100_000 + i128::from(i) * 100))
        .collect();
    store.record_learning_proposals_batch(&proposals)?;
    store.checkpoint_all()?;
    // Add post-checkpoint tail before closing.
    store.transition_learning_status(
        "learning:000010",
        LearningProposalStatus::Promoted,
        ContentDigest::sha256(b"auth-promote-10"),
    )?;

    let expected_digest = store.state_digest();
    let expected_summary = store.orient_summary(TimestampNs(200_000), 16);
    drop(store);

    // 1. Rebuild from epochs while checkpoints still exist.
    let (rebuilt_inline, _) = AgentStoreIndex::rebuild_from_epochs(&dir.root, cfg)?;
    assert_eq!(rebuilt_inline.state_digest(), expected_digest);
    drop(rebuilt_inline);

    // 2. Physically delete ALL checkpoint directories on disk and reopen cold from epochs only.
    for ckpt_dir in [
        dir.root.join("agent/sessions/checkpoints"),
        dir.root.join("effects/checkpoints"),
        dir.root.join("agent/publications/journal/checkpoints"),
    ] {
        fs::remove_dir_all(&ckpt_dir)?;
    }
    let (rebuilt_cold, cold_report) = AgentStoreIndex::open(&dir.root, cfg)?;
    assert!(cold_report.sessions.loaded_checkpoint_seq.is_none());
    assert!(cold_report.effects.loaded_checkpoint_seq.is_none());
    assert!(cold_report.learning.loaded_checkpoint_seq.is_none());
    assert_eq!(rebuilt_cold.state_digest(), expected_digest);
    assert_eq!(
        rebuilt_cold.orient_summary(TimestampNs(200_000), 16),
        expected_summary
    );
    Ok(())
}

#[test]
fn effects_open_obligations_never_truncated_across_100k_completed_effects() -> TestResult {
    let dir = TempDir::new("effects-100k")?;
    let cfg = AgentStoreIndexConfig::uniform(EpochJournalConfig {
        max_epoch_bytes: 2 * 1024 * 1024,
        checkpoint_stride: 20_000,
        durability: DurabilityMode::Fsync,
        tail_policy: IncompleteTailPolicy::Reject,
    });

    let (mut store, _) = AgentStoreIndex::open(&dir.root, cfg)?;
    // Insert 25 Indeterminate effects and 25 Pending obligations FIRST (oldest records!).
    let mut initial_live = Vec::with_capacity(50);
    for i in 0..25_u64 {
        let op = format!("op:oldest-indet:{i:02}");
        let ob = format!("ob:oldest-open:{i:02}");
        initial_live.push(EffectJournalEvent::UpsertEffect(make_effect(
            &op,
            EffectState::Indeterminate,
            1_000 + i128::from(i),
        )));
        initial_live.push(EffectJournalEvent::UpsertObligation(make_obligation(
            &ob,
            &op,
            ObligationState::Pending,
            1_000 + i128::from(i),
        )));
    }
    store.append_effect_events_batch(&initial_live)?;

    // Follow with 100,000 terminal completed effects in 10k chunks.
    for chunk in 0..10_u64 {
        let mut batch = Vec::with_capacity(10_000);
        for j in 0..10_000_u64 {
            let idx = chunk * 10_000 + j;
            let op = format!("op:done:{idx:06}");
            batch.push(EffectJournalEvent::UpsertEffect(make_effect(
                &op,
                EffectState::Verified,
                100_000 + i128::from(idx),
            )));
        }
        store.append_effect_events_batch(&batch)?;
    }
    store.checkpoint_all()?;
    let expected_digest = store.state_digest();
    drop(store);

    let t0 = Instant::now();
    let (reopened, _) = AgentStoreIndex::open(&dir.root, cfg)?;
    let cold_open_ms = t0.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(reopened.state_digest(), expected_digest);
    assert!(
        cold_open_ms < 10.0,
        "100k effects cold_open_ms={cold_open_ms:.3} exceeded 10 ms budget"
    );

    let sum = reopened.effects().summary();
    assert_eq!(sum.total_effects_ever, 100_025);
    assert_eq!(sum.completed_effects_count, 100_000);
    assert_eq!(sum.indeterminate_effects, 25);
    assert_eq!(sum.open_obligations, 25);
    for i in 0..25_u64 {
        assert!(
            reopened
                .effects()
                .get_indeterminate_effect(&format!("op:oldest-indet:{i:02}"))
                .is_some()
        );
        assert!(
            reopened
                .effects()
                .get_open_obligation(&format!("ob:oldest-open:{i:02}"))
                .is_some()
        );
    }
    Ok(())
}
