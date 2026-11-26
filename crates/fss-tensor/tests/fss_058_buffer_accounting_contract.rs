#![forbid(unsafe_code)]
//! Contract, property, fault, pressure, generation-revocation, canonical round-trip, tamper
//! refusal, and cooperative cancellation tests for `FSS-058` (`fss-x4a.12.7`: decoded-frame and
//! tensor buffer accounting).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::buffer_accounting::{
    BufferAccountant, BufferAccountingError, BufferAccountingPolicy, BufferAccountingSnapshot,
    BufferClass, BufferPressureTier, BufferReservationRequest, checked_align_up,
};

type TestResult = Result<(), Box<dyn Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn small_policy() -> BufferAccountingPolicy {
    BufferAccountingPolicy {
        max_total_bytes: 1024,
        max_decoded_frame_bytes: 768,
        max_tensor_workspace_bytes: 512,
        max_staging_scratch_bytes: 256,
        max_live_buffers: 8,
        alignment_bytes: 64,
        elevated_threshold_bps: 5_000,
        critical_threshold_bps: 8_000,
    }
}

#[test]
fn fss_058_aligned_accounting_watermarks_pressure_and_canonical_snapshot() -> TestResult {
    assert_eq!(checked_align_up(1, 64)?, 64);
    assert_eq!(checked_align_up(64, 64)?, 64);
    assert_eq!(checked_align_up(65, 64)?, 128);
    assert_eq!(
        checked_align_up(usize::MAX, 64),
        Err(BufferAccountingError::ArithmeticOverflow)
    );

    let mut acct = BufferAccountant::new(small_policy())?;
    assert_eq!(acct.pressure_tier(), BufferPressureTier::Normal);

    // Reserve 200 bytes decoded frame -> charged 256 aligned (25% -> Normal).
    let r1 = acct.reserve(
        &BufferReservationRequest {
            owner_id: "cam:front".to_owned(),
            class: BufferClass::DecodedFrame,
            generation: Generation(1),
            requested_bytes: 200,
            source_digest: Some(ContentDigest::sha256(b"frame-1")),
        },
        TimestampNs(1_000),
        || false,
    )?;
    assert_eq!(r1.charged_bytes, 256);
    assert_eq!(r1.pressure_after, BufferPressureTier::Normal);
    assert_eq!(acct.live_bytes(), 256);
    assert_eq!(acct.class_live_bytes(BufferClass::DecodedFrame), 256);
    assert_eq!(acct.generation_live_bytes(Generation(1)), 256);
    assert_eq!(acct.owner_live_bytes("cam:front"), 256);

    // Reserve 300 bytes tensor workspace -> charged 320 aligned -> total 576 (56.25% -> Elevated).
    let r2 = acct.reserve(
        &BufferReservationRequest {
            owner_id: "model:yolox".to_owned(),
            class: BufferClass::TensorWorkspace,
            generation: Generation(2),
            requested_bytes: 300,
            source_digest: None,
        },
        TimestampNs(2_000),
        || false,
    )?;
    assert_eq!(r2.charged_bytes, 320);
    assert_eq!(r2.pressure_after, BufferPressureTier::Elevated);

    // Reserve 256 bytes staging -> total 832 (81.25% -> Critical).
    let r3 = acct.reserve(
        &BufferReservationRequest {
            owner_id: "stage:resize".to_owned(),
            class: BufferClass::StagingScratch,
            generation: Generation(2),
            requested_bytes: 256,
            source_digest: None,
        },
        TimestampNs(3_000),
        || false,
    )?;
    assert_eq!(r3.pressure_after, BufferPressureTier::Critical);

    // Reserve remaining 192 bytes decoded frame -> total 1024 (100% -> Exhausted).
    let r4 = acct.reserve(
        &BufferReservationRequest {
            owner_id: "cam:front".to_owned(),
            class: BufferClass::DecodedFrame,
            generation: Generation(1),
            requested_bytes: 192,
            source_digest: Some(ContentDigest::sha256(b"frame-2")),
        },
        TimestampNs(4_000),
        || false,
    )?;
    assert_eq!(r4.pressure_after, BufferPressureTier::Exhausted);
    assert_eq!(acct.live_bytes(), 1024);
    assert_eq!(acct.peak_live_bytes(), 1024);
    assert_eq!(acct.live_buffers(), 4);

    // Deterministic canonical snapshot round-trip + tamper refusal.
    let snap = acct.snapshot(TimestampNs(5_000));
    assert!(snap.verify_digest());
    assert_eq!(snap.live_bytes, 1024);
    assert_eq!(
        snap.live_by_generation,
        vec![(Generation(1), 448), (Generation(2), 576)]
    );
    let mut enc = CanonicalEncoder::new();
    snap.encode_canonical(&mut enc);
    let raw = enc.finish();
    let decoded = BufferAccountingSnapshot::decode_canonical(&mut CanonicalDecoder::new(&raw))?;
    assert_eq!(decoded, snap);

    // Tampered snapshot fails verify_digest AND decode_canonical.
    let mut tampered = snap.clone();
    tampered.live_bytes = 512;
    assert!(!tampered.verify_digest());
    let mut bad_enc = CanonicalEncoder::new();
    tampered.encode_canonical(&mut bad_enc);
    assert!(
        BufferAccountingSnapshot::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    // Even a recomputed-digest forged snapshot violating balance invariants fails decode_canonical!
    let mut forged = snap.clone();
    forged.live_bytes = 999;
    forged.snapshot_digest = forged.computed_digest();
    let mut forged_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut forged_enc);
    assert!(
        BufferAccountingSnapshot::decode_canonical(&mut CanonicalDecoder::new(
            &forged_enc.finish()
        ))
        .is_err()
    );

    // Release all reservations cleanly and confirm zero residual live bytes while preserving peaks.
    for (receipt, ts) in [(r1, 6_000), (r2, 7_000), (r3, 8_000), (r4, 9_000)] {
        let rel = acct.release(receipt.reservation_id, &receipt.owner_id, TimestampNs(ts))?;
        assert_eq!(rel.released_bytes, receipt.charged_bytes);
    }
    assert_eq!(acct.live_bytes(), 0);
    assert_eq!(acct.live_buffers(), 0);
    assert_eq!(acct.peak_live_bytes(), 1024);
    assert_eq!(acct.peak_live_buffers(), 4);
    assert_eq!(acct.pressure_tier(), BufferPressureTier::Normal);

    emit_caplog(
        "fss_058_aligned_accounting_and_canonical_snapshot",
        "exact_aligned_charges_pressure_peaks_and_tamper_evident_snapshot",
        "exact_aligned_charges_pressure_peaks_and_tamper_evident_snapshot",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_058_bounds_revocation_ownership_double_release_and_cancellation_fail_closed() -> TestResult {
    // 1. Invalid policies fail closed.
    assert_eq!(
        BufferAccountant::new(BufferAccountingPolicy {
            alignment_bytes: 48,
            ..small_policy()
        })
        .unwrap_err(),
        BufferAccountingError::InvalidPolicy
    );
    assert_eq!(
        BufferAccountant::new(BufferAccountingPolicy {
            elevated_threshold_bps: 9_000,
            critical_threshold_bps: 8_000,
            ..small_policy()
        })
        .unwrap_err(),
        BufferAccountingError::InvalidPolicy
    );

    let mut acct = BufferAccountant::new(small_policy())?;

    // 2. Class budget refusal does not corrupt balances.
    let err = acct
        .reserve(
            &BufferReservationRequest {
                owner_id: "stage:1".to_owned(),
                class: BufferClass::StagingScratch,
                generation: Generation(1),
                requested_bytes: 300, // > 256 staging cap
                source_digest: None,
            },
            TimestampNs(100),
            || false,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BufferAccountingError::ClassBudgetExceeded {
            class: BufferClass::StagingScratch,
            ..
        }
    ));
    assert!(!err.recovery_guidance().is_empty());
    assert_eq!(acct.live_bytes(), 0);
    assert_eq!(acct.total_refused(), 1);

    // 3. Admit one buffer, revoke its generation, verify live balance stays intact until released
    //    and future reservations for that generation fail closed.
    let live_rec = acct.reserve(
        &BufferReservationRequest {
            owner_id: "cam:a".to_owned(),
            class: BufferClass::DecodedFrame,
            generation: Generation(7),
            requested_bytes: 128,
            source_digest: None,
        },
        TimestampNs(200),
        || false,
    )?;
    acct.revoke_generation(Generation(7));
    assert!(acct.is_generation_revoked(Generation(7)));
    assert_eq!(acct.generation_live_bytes(Generation(7)), 128);
    assert_eq!(
        acct.reserve(
            &BufferReservationRequest {
                owner_id: "cam:a".to_owned(),
                class: BufferClass::DecodedFrame,
                generation: Generation(7),
                requested_bytes: 64,
                source_digest: None,
            },
            TimestampNs(300),
            || false,
        ),
        Err(BufferAccountingError::StaleOrRevokedGeneration {
            generation: Generation(7),
        })
    );

    // 4. Foreign owner release fails closed without dropping the reservation.
    assert_eq!(
        acct.release(live_rec.reservation_id, "cam:foreign", TimestampNs(350)),
        Err(BufferAccountingError::OwnerMismatch {
            reservation_id: live_rec.reservation_id,
        })
    );
    assert_eq!(acct.live_bytes(), 128);

    // 5. Legitimate release succeeds; double release fails closed.
    acct.release(live_rec.reservation_id, "cam:a", TimestampNs(400))?;
    assert_eq!(acct.live_bytes(), 0);
    assert_eq!(
        acct.release(live_rec.reservation_id, "cam:a", TimestampNs(401)),
        Err(BufferAccountingError::UnknownOrAlreadyReleased(
            live_rec.reservation_id
        ))
    );

    // 6. Cooperative cancellation at both preflight and pre-commit checkpoints leaves zero charge.
    for cancel_at in [0_usize, 1] {
        let checks = AtomicUsize::new(0);
        let res = acct.reserve(
            &BufferReservationRequest {
                owner_id: "cam:cancel".to_owned(),
                class: BufferClass::DecodedFrame,
                generation: Generation(8),
                requested_bytes: 64,
                source_digest: None,
            },
            TimestampNs(500),
            || checks.fetch_add(1, Ordering::Relaxed) >= cancel_at,
        );
        assert_eq!(res, Err(BufferAccountingError::Cancelled));
        assert_eq!(acct.live_bytes(), 0);
        assert_eq!(acct.live_buffers(), 0);
    }

    // 7. Slot limit exhaustion refuses cleanly.
    let mut slot_ids = Vec::new();
    for i in 0..8_u64 {
        let r = acct.reserve(
            &BufferReservationRequest {
                owner_id: format!("slot:{i}"),
                class: BufferClass::DecodedFrame,
                generation: Generation(9),
                requested_bytes: 64,
                source_digest: None,
            },
            TimestampNs(600 + i128::from(i)),
            || false,
        )?;
        slot_ids.push(r);
    }
    assert_eq!(acct.pressure_tier(), BufferPressureTier::Exhausted);
    assert_eq!(
        acct.reserve(
            &BufferReservationRequest {
                owner_id: "slot:overflow".to_owned(),
                class: BufferClass::DecodedFrame,
                generation: Generation(9),
                requested_bytes: 64,
                source_digest: None,
            },
            TimestampNs(700),
            || false,
        ),
        Err(BufferAccountingError::SlotLimitExceeded { live: 8, max: 8 })
    );

    emit_caplog(
        "fss_058_fail_closed_faults_and_cancellation",
        "bounds_revocation_owner_fence_double_release_and_cancel_fail_closed",
        "bounds_revocation_owner_fence_double_release_and_cancel_fail_closed",
        "pass",
    );
    Ok(())
}
