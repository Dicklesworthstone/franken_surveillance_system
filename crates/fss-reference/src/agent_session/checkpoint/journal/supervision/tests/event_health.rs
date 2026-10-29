#![forbid(unsafe_code)]
//! Additive event health pins survive journal failure and cannot be removed from old advice.
//! Native health reproduction is exercised separately by the real event-supervision CLI fixture.

use super::*;

fn health_sources() -> TestResult<Vec<SupervisionSourcePin>> {
    let mut inventory = sources()?;
    let native = inventory
        .iter_mut()
        .find(|source| source.source_verified)
        .ok_or("native event pin")?;
    native.health_digest = Some(ContentDigest::sha256(
        b"synthetic selected event health view",
    ));
    Ok(inventory)
}

fn publish_health(
    store: &mut DurableSessionStore,
    session: &AgentSession,
    state: &SupervisionSubscription,
    reservation: &SupervisionReservation,
) -> TestResult<SupervisionSubscription> {
    Ok(store.publish_supervision(
        &session.principal_id,
        state,
        reservation,
        PRIVATE_REPORT.to_vec(),
        health_sources()?,
        ContentDigest::sha256(b"synthetic native report receipt"),
        TimestampNs(10),
    )?)
}

#[test]
fn event_health_publication_crash_cuts_recover_exact_pins_and_receipts() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.register_supervision(
            &session.principal_id,
            registration.clone(),
            TimestampNs(10),
        )?;
        let (state, reservation) = reserve(&mut store, &session, &state)?;
        store.journal.fail_after_phase(phase);
        assert!(publish_health(&mut store, &session, &state, &reservation).is_err());
        reconcile(&mut store, committed)?;
        let mut store = restart(store)?;
        let mut state =
            store.inspect_supervision(&session.principal_id, &registration, TimestampNs(10))?;
        assert_eq!(state.pending().is_some(), committed);
        assert_eq!(state.attempts_reserved(), 1);
        if !committed {
            let (reserved, retry) = reserve(&mut store, &session, &state)?;
            state = publish_health(&mut store, &session, &reserved, &retry)?;
        }
        let pending = state.pending().ok_or("health-bound pending report")?;
        assert_eq!(pending.source_inventory(), health_sources()?);
        assert!(pending.detection_source_inventory().is_empty());
        assert_eq!(
            pending.payload_digest(),
            ContentDigest::sha256(PRIVATE_REPORT)
        );
        let receipt = pending.receipt();
        assert_eq!(retained(&store)?, vec![state.clone()]);
        let (state, validation) = reserve(&mut store, &session, &state)?;
        let (state, payload) = store.release_supervision_payload(
            &session.principal_id,
            &state,
            &validation,
            receipt,
            TimestampNs(10),
        )?;
        assert_eq!(payload, PRIVATE_REPORT);
        assert_eq!(
            state.pending().ok_or("released report")?.source_inventory(),
            health_sources()?
        );
        let mut store = restart(store)?;
        let (state, validation) = reserve(&mut store, &session, &state)?;
        let acknowledged = store.acknowledge_supervision(
            &session.principal_id,
            &state,
            Some(&validation),
            receipt,
            &anchor(&session),
            TimestampNs(10),
        )?;
        assert_eq!(acknowledged.last_acknowledged(), Some(receipt));
        assert!(acknowledged.pending().is_none());
        let store = restart(store)?;
        assert_eq!(retained(&store)?, vec![acknowledged]);
    }
    Ok(())
}

#[test]
fn event_health_pin_changes_and_legacy_downgrade_invalidate_replay_identity() -> TestResult {
    let (mut store, session) = opened()?;
    let state = store.register_supervision(
        &session.principal_id,
        registration(&session),
        TimestampNs(10),
    )?;
    let (before, reservation) = reserve(&mut store, &session, &state)?;
    let after = publish_health(&mut store, &session, &before, &reservation)?;
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
    let mut record = Record {
        principal: session.principal_id.clone(),
        session: session.session_id.clone(),
        now: TimestampNs(10),
        session_digest: store
            .memory
            .checkpoint(limits.max_checkpoint_bytes)?
            .digest(),
        before_state: original.digest(),
        after_state: updated.digest(),
        command: Command::Publish {
            subscription: before.registration().subscription_id.clone(),
            expected: before.digest(),
            reservation: reservation.receipt(),
            payload: PRIVATE_REPORT.to_vec(),
            sources: health_sources()?,
            detection_sources: Vec::new(),
            report_receipt: ContentDigest::sha256(b"synthetic native report receipt"),
        },
    };
    let encoded = codec::encode_record(&record)?;
    let tag_at = 8
        + "fss.reference_supervision_command.v1".len()
        + 8
        + session.principal_id.as_str().len()
        + 8
        + session.session_id.as_str().len()
        + 16
        + 3 * 33;
    assert_eq!(
        encoded[tag_at], 9,
        "health-bound events require their additive record tag"
    );
    assert_eq!(
        codec::encode_record(&codec::decode_record(&encoded)?)?,
        encoded
    );
    let mut memory = store.memory.clone();
    let mut replayed = original.clone();
    replay_command(&encoded, &mut memory, &mut replayed, limits)?;
    assert_eq!(replayed.retained(), vec![after.clone()]);

    for changed in [
        Some(ContentDigest::sha256(b"changed selected-row health")),
        None,
    ] {
        let Command::Publish { sources, .. } = &mut record.command else {
            return Err("event publication command".into());
        };
        sources
            .iter_mut()
            .find(|source| source.source_verified)
            .ok_or("health-bound event")?
            .health_digest = changed;
        let encoded = codec::encode_record(&record)?;
        assert_eq!(encoded[tag_at], if changed.is_some() { 9 } else { 2 });
        let mut memory = store.memory.clone();
        let mut replayed = original.clone();
        assert!(matches!(
            replay_command(&encoded, &mut memory, &mut replayed, limits),
            Err(DurableSessionError::InvalidHistory)
        ));
        assert_ne!(
            replayed.retained()[0]
                .pending()
                .ok_or("changed pending")?
                .receipt(),
            after.pending().ok_or("original pending")?.receipt(),
        );
    }
    Ok(())
}

#[test]
fn unverified_or_invalid_event_health_pins_are_refused_before_journal_append() -> TestResult {
    let (mut store, session) = opened()?;
    let state = store.register_supervision(
        &session.principal_id,
        registration(&session),
        TimestampNs(10),
    )?;
    let (state, reservation) = reserve(&mut store, &session, &state)?;
    let before = store.committed_root();
    let zero = ContentDigest::parse(format!("sha256:{}", "00".repeat(32)))?;
    for metadata_only in [false, true] {
        let mut inventory = health_sources()?;
        let pin = inventory
            .iter_mut()
            .find(|source| source.source_verified)
            .ok_or("event pin")?;
        if metadata_only {
            pin.source_verified = false;
        } else {
            pin.health_digest = Some(zero);
        }
        assert!(
            store
                .publish_supervision(
                    &session.principal_id,
                    &state,
                    &reservation,
                    PRIVATE_REPORT.to_vec(),
                    inventory,
                    ContentDigest::sha256(b"synthetic native report receipt"),
                    TimestampNs(10),
                )
                .is_err()
        );
        assert_eq!(store.committed_root(), before);
        assert_eq!(retained(&store)?, vec![state.clone()]);
    }
    Ok(())
}
