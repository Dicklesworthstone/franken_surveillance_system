#![forbid(unsafe_code)]
//! Contract, generation-fencing, zero-copy lease fan-out, deterministic reclamation, retirement
//! drain, canonical receipt round-trip, tamper refusal, and cooperative cancellation tests for
//! `FSS-119` (`fss-x4a.12.18`: generation-leased immutable frame pools).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::buffer_accounting::BufferPressureTier;
use fss_tensor::dtype::DType;
use fss_tensor::frame_pool::{
    FrameDescriptor, FramePool, FramePoolError, FramePoolPolicy, FramePoolReceipt,
};

type TestResult = Result<(), Box<dyn Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn desc(gen_num: u64, seq: u64) -> FrameDescriptor {
    FrameDescriptor {
        width: 16,
        height: 16,
        channels: 1,
        dtype: DType::U8,
        generation: Generation(gen_num),
        frame_seq: seq,
        source_evidence_digest: ContentDigest::sha256(format!("src:{gen_num}:{seq}").as_bytes()),
    }
}

fn tiny_pool_policy() -> FramePoolPolicy {
    FramePoolPolicy {
        pool_id: "pool:cam-front".to_owned(),
        max_slots: 3,
        max_bytes: 768, // exact fit for 3 x 256-byte frames
        max_leases_per_frame: 2,
        alignment_bytes: 64,
        elevated_threshold_bps: 6_000,
        critical_threshold_bps: 9_000,
    }
}

#[test]
fn fss_119_immutable_zero_copy_leases_eviction_and_canonical_receipt() -> TestResult {
    let mut pool = FramePool::new(tiny_pool_policy())?;

    let bytes_1 = vec![0x11_u8; 256];
    let l1_a = pool.admit_frame(desc(1, 1), bytes_1.clone(), TimestampNs(1_000), || false)?;
    assert!(l1_a.is_derived_evidence());
    assert_eq!(l1_a.bytes(), bytes_1.as_slice());
    assert_eq!(l1_a.frame_digest(), ContentDigest::sha256(&bytes_1));
    assert_eq!(l1_a.storage().generation(), Generation(1));
    assert_eq!(pool.retained_slots(), 1);
    assert_eq!(pool.active_leases(), 1);

    // Second immutable lease shares the exact backing TensorStorage (same StorageId, zero copy).
    let l1_b = pool.acquire_lease(l1_a.slot_id(), Generation(1), || false)?;
    assert_eq!(l1_a.storage().id(), l1_b.storage().id());
    assert_eq!(l1_a.bytes(), l1_b.bytes());
    assert_eq!(pool.slot_active_leases(l1_a.slot_id()), Some(2));

    // Third lease on the same slot exceeds max_leases_per_frame (2) and fails closed.
    assert_eq!(
        pool.acquire_lease(l1_a.slot_id(), Generation(1), || false)
            .unwrap_err(),
        FramePoolError::LeaseCapExceeded {
            slot_id: l1_a.slot_id(),
            max_leases: 2,
        }
    );

    // Fill slots 2 and 3; pool reaches Exhausted.
    let l2 = pool.admit_frame(desc(1, 2), vec![0x22; 256], TimestampNs(2_000), || false)?;
    let l3 = pool.admit_frame(desc(1, 3), vec![0x33; 256], TimestampNs(3_000), || false)?;
    assert_eq!(pool.retained_slots(), 3);
    assert_eq!(
        pool.accountant().pressure_tier(),
        BufferPressureTier::Exhausted
    );

    // With ALL 3 slots actively leased, admitting slot 4 MUST fail closed (never evict leased!).
    assert_eq!(
        pool.admit_frame(desc(1, 4), vec![0x44; 256], TimestampNs(4_000), || false)
            .unwrap_err(),
        FramePoolError::PoolCapacityExhausted
    );
    assert_eq!(pool.retained_slots(), 3);

    // Release BOTH leases on slot 1 -> slot 1 remains cached (unleased) until needed or reclaimed.
    let slot1 = l1_a.slot_id();
    pool.release_lease(l1_a, TimestampNs(4_100))?;
    pool.release_lease(l1_b, TimestampNs(4_200))?;
    assert_eq!(pool.slot_active_leases(slot1), Some(0));

    // Now admitting slot 4 deterministically reclaims unleased slot 1 and succeeds!
    let l4 = pool.admit_frame(desc(1, 4), vec![0x44; 256], TimestampNs(4_300), || false)?;
    assert_eq!(pool.slot_active_leases(slot1), None);
    assert_eq!(pool.retained_slots(), 3);
    assert_eq!(pool.active_leases(), 3);

    // Canonical FramePoolReceipt round-trip and tamper detection.
    let rcpt = pool.receipt(TimestampNs(5_000));
    assert!(rcpt.verify_digest());
    assert_eq!(rcpt.total_admitted_frames, 4);
    assert_eq!(rcpt.total_reclaimed_slots, 1);
    assert_eq!(rcpt.retained_slots, 3);
    let mut enc = CanonicalEncoder::new();
    rcpt.encode_canonical(&mut enc);
    let bytes = enc.finish();
    let decoded = FramePoolReceipt::decode_canonical(&mut CanonicalDecoder::new(&bytes))?;
    assert_eq!(decoded, rcpt);

    let mut tampered = rcpt.clone();
    tampered.retained_slots = 0;
    assert!(!tampered.verify_digest());
    let mut bad_enc = CanonicalEncoder::new();
    tampered.encode_canonical(&mut bad_enc);
    assert!(
        FramePoolReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish())).is_err()
    );

    // Release remaining leases and reclaim cleanly to 0 bytes.
    pool.release_lease(l2, TimestampNs(5_100))?;
    pool.release_lease(l3, TimestampNs(5_200))?;
    pool.release_lease(l4, TimestampNs(5_300))?;
    assert_eq!(pool.reclaim_unleased(TimestampNs(5_400))?, 3);
    assert_eq!(pool.retained_slots(), 0);
    assert_eq!(pool.accountant().live_bytes(), 0);

    emit_caplog(
        "fss_119_immutable_zero_copy_leases_and_receipt",
        "zero_copy_fanout_leased_protection_fifo_eviction_and_tamper_evident_receipt",
        "zero_copy_fanout_leased_protection_fifo_eviction_and_tamper_evident_receipt",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_119_generation_fencing_retirement_drain_cross_pool_and_cancellation() -> TestResult {
    let mut pool = FramePool::new(tiny_pool_policy())?;
    let other_policy = FramePoolPolicy {
        pool_id: "pool:cam-rear".to_owned(),
        ..tiny_pool_policy()
    };
    let mut other_pool = FramePool::new(other_policy)?;

    // Admit two frames in generation 10 (one stays leased, one becomes unleased).
    let leased_g10 = pool.admit_frame(desc(10, 1), vec![0xAA; 256], TimestampNs(100), || false)?;
    let unleased_g10 =
        pool.admit_frame(desc(10, 2), vec![0xBB; 256], TimestampNs(200), || false)?;
    let unleased_slot = unleased_g10.slot_id();
    let leased_slot = leased_g10.slot_id();
    pool.release_lease(unleased_g10, TimestampNs(250))?;

    // Wrong generation fence fails closed on acquire_lease.
    assert_eq!(
        pool.acquire_lease(leased_slot, Generation(11), || false)
            .unwrap_err(),
        FramePoolError::StaleOrRetiredGeneration {
            generation: Generation(10),
        }
    );

    // Retiring generation 10 immediately reclaims the unleased slot, leaves the leased slot
    // draining safely without corrupting the live lease, and fences new admissions/leases!
    let reclaimed_now = pool.retire_generation(Generation(10), TimestampNs(300))?;
    assert_eq!(reclaimed_now, 1);
    assert_eq!(pool.slot_active_leases(unleased_slot), None);
    assert_eq!(pool.draining_retired_slots(), 1);
    assert_eq!(leased_g10.bytes(), &[0xAA; 256]);

    assert_eq!(
        pool.admit_frame(desc(10, 3), vec![0xCC; 256], TimestampNs(310), || false)
            .unwrap_err(),
        FramePoolError::StaleOrRetiredGeneration {
            generation: Generation(10),
        }
    );
    assert_eq!(
        pool.acquire_lease(leased_slot, Generation(10), || false)
            .unwrap_err(),
        FramePoolError::StaleOrRetiredGeneration {
            generation: Generation(10),
        }
    );

    // Cross-pool release fails closed without touching the target pool.
    let foreign_lease =
        other_pool.admit_frame(desc(20, 1), vec![0x99; 256], TimestampNs(315), || false)?;
    assert_eq!(
        pool.release_lease(foreign_lease, TimestampNs(320)),
        Err(FramePoolError::PoolMismatch)
    );
    assert_eq!(pool.draining_retired_slots(), 1);
    assert_eq!(other_pool.retained_slots(), 1);

    // Releasing the final lease on the draining retired slot auto-reclaims it immediately!
    pool.release_lease(leased_g10, TimestampNs(330))?;
    assert_eq!(pool.draining_retired_slots(), 0);
    assert_eq!(pool.retained_slots(), 0);
    assert_eq!(pool.accountant().live_bytes(), 0);

    // Byte length mismatch and cooperative cancellation fail closed with zero leak.
    assert_eq!(
        pool.admit_frame(desc(11, 1), vec![0x00; 100], TimestampNs(400), || false)
            .unwrap_err(),
        FramePoolError::ByteLengthMismatch {
            expected: 256,
            actual: 100,
        }
    );
    for cancel_at in [0_usize, 1] {
        let seen = AtomicUsize::new(0);
        let res = pool.admit_frame(desc(11, 2), vec![0x55; 256], TimestampNs(500), || {
            seen.fetch_add(1, Ordering::Relaxed) >= cancel_at
        });
        assert_eq!(res.unwrap_err(), FramePoolError::Cancelled);
        assert_eq!(pool.retained_slots(), 0);
        assert_eq!(pool.accountant().live_bytes(), 0);
    }

    emit_caplog(
        "fss_119_generation_fencing_retirement_and_cancellation",
        "retired_generation_drains_safely_blocks_reuse_and_cancels_cleanly",
        "retired_generation_drains_safely_blocks_reuse_and_cancels_cleanly",
        "pass",
    );
    Ok(())
}
