#![forbid(unsafe_code)]
//! Native pin custody in the real session journal. The fixtures are explicitly synthetic;
//! native detector/source/health reproduction belongs to the deployment integration tests.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::AgentSession;
use fss_ledger::{AppendPhase, IncompleteTailPolicy};

use super::*;
use crate::agent_session::checkpoint::journal::{SessionAppendRecovery, inspect_session_bytes};
use crate::agent_session::checkpoint::tests::{basis, params};
use crate::agent_session::work_claims::WorkClaimLimits;

type Test<T = ()> = std::result::Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
const PAYLOAD: &[u8] = br#"{"private":"synthetic detector source custody fixture"}"#;

fn opened() -> Test<(DurableSessionStore, AgentSession)> {
    let mut path = None;
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let candidate = std::env::temp_dir().join(format!(
            "fss-supervision-detection-pins-{}-{serial}.journal",
            std::process::id(),
        ));
        if !candidate.exists() {
            path = Some(candidate);
            break;
        }
    }
    let mut store = DurableSessionStore::create(
        path.ok_or("bounded native pin fixture inventory exhausted")?,
        DurableSessionLimits::default(),
    )?;
    let mut input = params()?;
    input.capabilities.extend([
        "CAP-AGENT-SESSION-READ-001".into(),
        "CAP-AGENT-SESSION-WRITE-001".into(),
        "CAP-AGENT-SITUATION-READ-001".into(),
        "CAP-AGENT-INVESTIGATE-001".into(),
    ]);
    let session = store.open(input, basis(), TimestampNs(10))?;
    Ok((store, session))
}

fn registration(session: &AgentSession) -> SupervisionRegistration {
    let configuration = br#"{"fixture":"native detector custody"}"#.to_vec();
    SupervisionRegistration {
        session_id: session.session_id.clone(),
        subscription_id: "native-source-pins".into(),
        configuration_digest: ContentDigest::sha256(&configuration),
        configuration,
        max_read_bytes: 10_000,
        max_read_attempts: 100,
        maximum_attempts: 16,
        max_report_bytes: 4096,
    }
}

fn anchor(session: &AgentSession) -> LedgerAnchor {
    let mut anchor = session.current_anchor.clone();
    anchor.state_root = ContentDigest::sha256(b"synthetic detector authority");
    anchor
}

fn pins() -> Vec<SupervisionDetectionSourcePin> {
    let mut pins = vec![
        SupervisionDetectionSourcePin {
            report_digest: ContentDigest::sha256(b"synthetic native report"),
            record_digest: ContentDigest::sha256(b"synthetic native record"),
            detection_root: ContentDigest::sha256(b"synthetic native source-closed root"),
            source_verified: true,
            health_digest: Some(ContentDigest::sha256(b"synthetic source-bound health view")),
        },
        SupervisionDetectionSourcePin {
            report_digest: ContentDigest::sha256(b"synthetic excluded report"),
            record_digest: ContentDigest::sha256(b"synthetic excluded record"),
            detection_root: ContentDigest::sha256(b"synthetic excluded root"),
            source_verified: false,
            health_digest: None,
        },
    ];
    pins.sort_by_key(|pin| pin.report_digest);
    pins
}

fn reserve(
    store: &mut DurableSessionStore,
    session: &AgentSession,
    state: &SupervisionSubscription,
) -> Test<(SupervisionSubscription, SupervisionReservation)> {
    let state = store.reserve_supervision(
        &session.principal_id,
        state,
        &anchor(session),
        TimestampNs(10),
    )?;
    let reservation = state
        .reservation()
        .ok_or("native work reservation")?
        .clone();
    Ok((state, reservation))
}

fn publish(
    store: &mut DurableSessionStore,
    session: &AgentSession,
    state: &SupervisionSubscription,
    reservation: &SupervisionReservation,
) -> Test<SupervisionSubscription> {
    let mut reversed = pins();
    reversed.reverse();
    Ok(store.publish_supervision_with_detections(
        &session.principal_id,
        state,
        reservation,
        PAYLOAD.to_vec(),
        Vec::new(),
        reversed,
        ContentDigest::sha256(b"synthetic native supervision report"),
        TimestampNs(10),
    )?)
}

fn restart(store: DurableSessionStore) -> Test<DurableSessionStore> {
    let path: PathBuf = store.path().to_owned();
    let root = store.committed_root();
    drop(store);
    Ok(DurableSessionStore::open_existing(
        path,
        root,
        DurableSessionLimits::default(),
    )?)
}

#[test]
fn native_publication_crash_cuts_reopen_exact_pins_and_require_exact_release_and_ack() -> Test {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.register_supervision(
            &session.principal_id,
            registration.clone(),
            TimestampNs(10),
        )?;
        let (state, reservation) = reserve(&mut store, &session, &state)?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(publish(&mut store, &session, &state, &reservation).is_err());
        assert!(store.needs_reconciliation());
        if !committed {
            let bytes = fs::read(store.path())?;
            assert!(
                store
                    .reconcile_pending(IncompleteTailPolicy::Reject)
                    .is_err()
            );
            assert_eq!(fs::read(store.path())?, bytes);
        }
        assert_eq!(
            store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let mut state =
            store.inspect_supervision(&session.principal_id, &registration, TimestampNs(10))?;
        assert_eq!(state.pending().is_some(), committed);
        assert_eq!(state.attempts_reserved(), 1);
        if !committed {
            let (reserved, retry) = reserve(&mut store, &session, &state)?;
            state = publish(&mut store, &session, &reserved, &retry)?;
        }
        let pending = state.pending().ok_or("native pending")?;
        assert!(pending.source_inventory().is_empty());
        assert_eq!(pending.detection_source_inventory(), pins());
        assert_eq!(pending.payload_digest(), ContentDigest::sha256(PAYLOAD));
        assert!(!format!("{pending:?}").contains("synthetic detector source custody fixture"));
        let receipt = pending.receipt();
        // Read-only orientation replays the same additive record without changing private
        // delivery state or consuming another native source-validation attempt.
        let before_inventory = store.committed_root();
        let inventory = store.supervision_inventory(&session, TimestampNs(10))?;
        assert_eq!(inventory.len(), 1);
        let entry = inventory.first().ok_or("native supervision inventory")?;
        assert_eq!(entry.state_digest, state.digest());
        assert_eq!(entry.attempts_reserved, state.attempts_reserved());
        let descriptor = entry.pending.as_ref().ok_or("native pending descriptor")?;
        assert_eq!(descriptor.receipt, receipt);
        assert_eq!(descriptor.payload_digest, ContentDigest::sha256(PAYLOAD));
        assert_eq!(descriptor.payload_len, PAYLOAD.len());
        assert_eq!(store.committed_root(), before_inventory);
        let (state, validation) = reserve(&mut store, &session, &state)?;
        let before = store.committed_root();
        assert!(
            store
                .release_supervision_payload(
                    &session.principal_id,
                    &state,
                    &validation,
                    ContentDigest::sha256(b"wrong receipt"),
                    TimestampNs(10),
                )
                .is_err()
        );
        assert_eq!(store.committed_root(), before);
        let (state, payload) = store.release_supervision_payload(
            &session.principal_id,
            &state,
            &validation,
            receipt,
            TimestampNs(10),
        )?;
        assert_eq!(payload, PAYLOAD);
        assert_eq!(
            state
                .pending()
                .ok_or("retained after release")?
                .detection_source_inventory(),
            pins()
        );
        let (state, validation) = reserve(&mut store, &session, &state)?;
        let before = store.committed_root();
        assert!(
            store
                .acknowledge_supervision(
                    &session.principal_id,
                    &state,
                    Some(&validation),
                    ContentDigest::sha256(b"wrong ACK"),
                    &anchor(&session),
                    TimestampNs(10),
                )
                .is_err()
        );
        assert_eq!(store.committed_root(), before);
        let state = store.acknowledge_supervision(
            &session.principal_id,
            &state,
            Some(&validation),
            receipt,
            &anchor(&session),
            TimestampNs(10),
        )?;
        assert!(state.pending().is_none());
        assert_eq!(state.last_acknowledged(), Some(receipt));
        let mut store = restart(store)?;
        assert_eq!(
            store.inspect_supervision(&session.principal_id, &registration, TimestampNs(10))?,
            state
        );
    }
    Ok(())
}

#[test]
fn native_duplicates_mixed_inventories_unverified_health_and_invalid_digests_never_publish() -> Test
{
    let (mut store, session) = opened()?;
    let state = store.register_supervision(
        &session.principal_id,
        registration(&session),
        TimestampNs(10),
    )?;
    let (state, reservation) = reserve(&mut store, &session, &state)?;
    let valid = pins()
        .into_iter()
        .find(|pin| pin.source_verified)
        .ok_or("verified pin")?;
    let zero = ContentDigest::parse(format!("sha256:{}", "00".repeat(32)))?;
    let mut invalid = Vec::new();
    let mut pin = valid.clone();
    pin.source_verified = false;
    invalid.push(vec![pin]);
    let mut pin = valid.clone();
    pin.report_digest = zero;
    invalid.push(vec![pin]);
    let mut pin = valid.clone();
    pin.record_digest = zero;
    invalid.push(vec![pin]);
    let mut pin = valid.clone();
    pin.detection_root = zero;
    invalid.push(vec![pin]);
    let mut pin = valid.clone();
    pin.health_digest = Some(zero);
    invalid.push(vec![pin]);
    let mut duplicate = valid.clone();
    duplicate.record_digest = ContentDigest::sha256(b"other record");
    invalid.push(vec![valid.clone(), duplicate]);
    invalid.push(vec![valid.clone(); MAX_SUPERVISION_SOURCES + 1]);
    let before = store.committed_root();
    for native in invalid {
        assert!(
            store
                .publish_supervision_with_detections(
                    &session.principal_id,
                    &state,
                    &reservation,
                    PAYLOAD.to_vec(),
                    Vec::new(),
                    native,
                    ContentDigest::sha256(b"report"),
                    TimestampNs(10),
                )
                .is_err()
        );
        assert_eq!(store.committed_root(), before);
    }
    let events = vec![SupervisionSourcePin {
        event_id: EventId::parse("event:package:mixed")?,
        event_root: ContentDigest::sha256(b"event root"),
        source_verified: true,
        health_digest: None,
    }];
    assert!(
        store
            .publish_supervision_with_detections(
                &session.principal_id,
                &state,
                &reservation,
                PAYLOAD.to_vec(),
                events,
                vec![valid],
                ContentDigest::sha256(b"report"),
                TimestampNs(10),
            )
            .is_err()
    );
    assert_eq!(store.committed_root(), before);
    let restored = inspect_session_bytes(
        &fs::read(store.path())?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(restored.supervisions, vec![state]);
    Ok(())
}

fn command_record(
    session: &AgentSession,
    before: &SupervisionSubscription,
    reservation: &SupervisionReservation,
    native: Vec<SupervisionDetectionSourcePin>,
) -> Record {
    Record {
        principal: session.principal_id.clone(),
        session: session.session_id.clone(),
        now: TimestampNs(10),
        session_digest: ContentDigest::sha256(b"test checkpoint"),
        before_state: ContentDigest::sha256(b"test before"),
        after_state: ContentDigest::sha256(b"test after"),
        command: Command::Publish {
            subscription: before.registration().subscription_id.clone(),
            expected: before.digest(),
            reservation: reservation.receipt(),
            payload: PAYLOAD.to_vec(),
            sources: Vec::new(),
            detection_sources: native,
            report_receipt: ContentDigest::sha256(b"synthetic native supervision report"),
        },
    }
}

#[test]
fn every_native_source_and_health_pin_is_bound_into_replay_and_delivery_identity() -> Test {
    let (mut store, session) = opened()?;
    let registered = store.register_supervision(
        &session.principal_id,
        registration(&session),
        TimestampNs(10),
    )?;
    let (before, reservation) = reserve(&mut store, &session, &registered)?;
    let after = publish(&mut store, &session, &before, &reservation)?;
    let key = (
        session.session_id.clone(),
        before.registration().subscription_id.clone(),
    );
    let original = SupervisionState {
        subscriptions: BTreeMap::from([(key.clone(), before.clone())]),
    };
    let updated = SupervisionState {
        subscriptions: BTreeMap::from([(key, after.clone())]),
    };
    let limits = DurableSessionLimits::default();
    let mut record = command_record(&session, &before, &reservation, pins());
    record.session_digest = store
        .memory
        .checkpoint(limits.max_checkpoint_bytes)?
        .digest();
    record.before_state = original.digest();
    record.after_state = updated.digest();
    let mut memory = store.memory.clone();
    let mut state = original.clone();
    replay_command(
        &codec::encode_record(&record)?,
        &mut memory,
        &mut state,
        limits,
    )?;
    assert_eq!(state.retained(), vec![after.clone()]);

    for coordinate in 0..6 {
        let mut native = pins();
        let pin = native
            .iter_mut()
            .find(|pin| pin.source_verified)
            .ok_or("verified pin")?;
        match coordinate {
            0 => pin.report_digest = ContentDigest::sha256(b"altered native report"),
            1 => pin.record_digest = ContentDigest::sha256(b"altered native record"),
            2 => pin.detection_root = ContentDigest::sha256(b"altered source root"),
            3 => pin.health_digest = Some(ContentDigest::sha256(b"altered historical health view")),
            4 => pin.health_digest = None,
            _ => {
                pin.source_verified = false;
                pin.health_digest = None;
            }
        }
        native.sort_by_key(|pin| pin.report_digest);
        let Command::Publish {
            detection_sources, ..
        } = &mut record.command
        else {
            return Err("publish".into());
        };
        *detection_sources = native;
        let mut memory = store.memory.clone();
        let mut state = original.clone();
        assert!(matches!(
            replay_command(
                &codec::encode_record(&record)?,
                &mut memory,
                &mut state,
                limits
            ),
            Err(DurableSessionError::InvalidHistory)
        ));
        let changed = state.retained();
        assert_ne!(
            changed[0].pending().ok_or("tampered pending")?.receipt(),
            after.pending().ok_or("original pending")?.receipt()
        );
    }
    Ok(())
}

#[test]
fn native_command_codec_rejects_empty_extension_counts_truncation_order_and_invalid_flags() -> Test
{
    let (mut store, session) = opened()?;
    let state = store.register_supervision(
        &session.principal_id,
        registration(&session),
        TimestampNs(10),
    )?;
    let (state, reservation) = reserve(&mut store, &session, &state)?;
    let record = command_record(&session, &state, &reservation, pins());
    let bytes = codec::encode_record(&record)?;
    assert_eq!(codec::encode_record(&codec::decode_record(&bytes)?)?, bytes);
    for end in 0..bytes.len() {
        assert!(
            codec::decode_record(&bytes[..end]).is_err(),
            "incomplete native command at {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(codec::decode_record(&trailing).is_err());
    let tag_at = 8
        + "fss.reference_supervision_command.v1".len()
        + 8
        + session.principal_id.as_str().len()
        + 8
        + session.session_id.as_str().len()
        + 16
        + 3 * 33;
    assert_eq!(bytes[tag_at], 8);

    let legacy = codec::encode_record(&command_record(&session, &state, &reservation, Vec::new()))?;
    assert_eq!(legacy[tag_at], 2);
    assert_eq!(
        codec::encode_record(&codec::decode_record(&legacy)?)?,
        legacy
    );
    for count in [0_u64, MAX_SUPERVISION_SOURCES as u64 + 1] {
        let mut invalid = legacy.clone();
        invalid[tag_at] = 8;
        invalid.extend_from_slice(&count.to_be_bytes());
        assert!(codec::decode_record(&invalid).is_err());
    }
    let mut unordered = pins();
    unordered.reverse();
    let malformed =
        codec::encode_record(&command_record(&session, &state, &reservation, unordered))?;
    assert!(codec::decode_record(&malformed).is_err());
    let pin = pins()
        .into_iter()
        .find(|pin| !pin.source_verified)
        .ok_or("excluded pin")?;
    let mut invalid_bool =
        codec::encode_record(&command_record(&session, &state, &reservation, vec![pin]))?;
    *invalid_bool.last_mut().ok_or("optional digest flag")? = 2;
    assert!(codec::decode_record(&invalid_bool).is_err());
    Ok(())
}
