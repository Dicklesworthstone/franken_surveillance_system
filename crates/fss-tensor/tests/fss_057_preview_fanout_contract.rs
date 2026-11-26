#![forbid(unsafe_code)]
//! Contract & fault suite for `FSS-057` (`fss-x4a.12.6`): live preview bounded fan-out.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::{
    DType, FrameDescriptor, FramePool, FramePoolPolicy, MediaDegradationRung, PreviewFanoutError,
    PreviewFanoutHub, PreviewFanoutPolicy, PreviewFanoutReceipt, PreviewFrameOffer,
    PreviewSubscriberSpec,
};

type TestResult = Result<(), Box<dyn Error>>;

fn digest(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn make_pool(max_slots: usize, max_leases_per_frame: usize) -> Result<FramePool, Box<dyn Error>> {
    Ok(FramePool::new(FramePoolPolicy {
        pool_id: "pool:preview-01".to_owned(),
        max_slots,
        max_bytes: 2 * 1024 * 1024,
        max_leases_per_frame,
        alignment_bytes: 64,
        elevated_threshold_bps: 7_500,
        critical_threshold_bps: 9_000,
    })?)
}

fn make_desc(generation: u64, seq: u64) -> FrameDescriptor {
    FrameDescriptor {
        width: 16,
        height: 8,
        channels: 3,
        dtype: DType::U8,
        generation: Generation(generation),
        frame_seq: seq,
        source_evidence_digest: digest(&format!("src:{generation}:{seq}")),
    }
}

fn make_sub(id: &str, priority_tier: u8, requires_privacy_masked: bool) -> PreviewSubscriberSpec {
    PreviewSubscriberSpec {
        subscriber_id: id.to_owned(),
        priority_tier,
        requires_privacy_masked,
        authority_grant_digest: digest(&format!("grant:{id}")),
    }
}

#[test]
fn fss_057_zero_copy_fanout_and_bounded_drop_oldest_never_leaks_pool_leases() -> TestResult {
    let mut pool = make_pool(16, 8)?;
    let mut hub = PreviewFanoutHub::new(PreviewFanoutPolicy {
        stream_id: "cam:driveway:main".to_owned(),
        max_subscribers: 4,
        max_queue_depth: 2,
        active_generation: Generation(1),
    })?;

    hub.subscribe(make_sub("op:primary", 0, false))?;
    hub.subscribe(make_sub("op:slow-wall", 1, false))?;

    // Publish 5 frames: primary drains immediately, slow-wall stalls and drops oldest unviewed.
    for seq in 1..=5_u64 {
        let now = TimestampNs(seq as i128 * 1_000_000);
        let payload = vec![(seq * 17) as u8; 16 * 8 * 3];
        let producer_lease = pool.admit_frame(make_desc(1, seq), payload, now, || false)?;
        let slot_id = producer_lease.slot_id();
        let producer_storage_id = producer_lease.storage().id();

        let outcome = hub.publish_frame(
            &mut pool,
            PreviewFrameOffer {
                slot_id,
                generation: Generation(1),
                frame_is_privacy_masked: true,
                rung: MediaDegradationRung::Rung0Nominal,
                now_ns: now,
            },
            || false,
        )?;

        assert_eq!(outcome.delivered_count, 2);
        assert_eq!(outcome.evicted_oldest_count, usize::from(seq > 2));
        assert_eq!(outcome.privacy_filtered_count, 0);
        assert_eq!(outcome.pressure_shed_count, 0);

        // Primary reads immediately and proves zero-copy StorageId identity with producer lease.
        let Some(primary_lease) = hub.recv_next("op:primary")? else {
            return Err("primary lease missing".into());
        };
        assert_eq!(primary_lease.storage().id(), producer_storage_id);
        assert_eq!(primary_lease.descriptor().frame_seq, seq);
        pool.release_lease(primary_lease, now)?;
        pool.release_lease(producer_lease, now)?;
    }

    // Slow subscriber queue is strictly capped at max_queue_depth == 2 holding frames 4 and 5!
    assert_eq!(hub.subscriber_queue_len("op:primary"), Some(0));
    assert_eq!(hub.subscriber_queue_len("op:slow-wall"), Some(2));
    assert_eq!(pool.active_leases(), 2);

    let Some(l4) = hub.recv_next("op:slow-wall")? else {
        return Err("missing frame 4".into());
    };
    let Some(l5) = hub.recv_next("op:slow-wall")? else {
        return Err("missing frame 5".into());
    };
    assert_eq!(l4.descriptor().frame_seq, 4);
    assert_eq!(l5.descriptor().frame_seq, 5);
    assert!(hub.recv_next("op:slow-wall")?.is_none());

    pool.release_lease(l4, TimestampNs(6_000_000))?;
    pool.release_lease(l5, TimestampNs(6_000_000))?;
    assert_eq!(pool.active_leases(), 0);
    pool.reclaim_unleased(TimestampNs(7_000_000))?;
    assert_eq!(pool.accountant().live_bytes(), 0);

    let receipt = hub.receipt(TimestampNs(7_000_000));
    assert_eq!(receipt.total_frames_offered, 5);
    assert_eq!(receipt.total_deliveries, 10);
    assert_eq!(receipt.total_dropped_oldest, 3);
    assert_eq!(receipt.queued_leases, 0);
    assert!(receipt.verify_digest());

    println!(
        "CAPLOG {{\"step\":\"fss_057_fanout\",\"deliveries\":{},\"dropped_oldest\":{},\"live_bytes\":{},\"verdict\":\"ok\"}}",
        receipt.total_deliveries,
        receipt.total_dropped_oldest,
        pool.accountant().live_bytes()
    );
    Ok(())
}

#[test]
fn fss_057_privacy_mask_gate_pressure_ladder_and_priority_lease_cap() -> TestResult {
    // Tight max_leases_per_frame = 2: producer holds 1 lease, leaving 1 lease for highest-priority viewer!
    let mut pool = make_pool(8, 2)?;
    let mut hub = PreviewFanoutHub::new(PreviewFanoutPolicy::bounded_default(
        "cam:lobby",
        Generation(3),
    ))?;

    hub.subscribe(make_sub("viewer:masked-guest", 0, true))?;
    hub.subscribe(make_sub("op:high", 0, false))?;
    hub.subscribe(make_sub("op:low", 2, false))?;

    // 1. Unmasked frame: masked-guest MUST be privacy-filtered, op:high wins the 1 free lease,
    //    op:low hits lease_cap_skipped cleanly (zero crash/leak).
    let f1 = pool.admit_frame(
        make_desc(3, 1),
        vec![11; 16 * 8 * 3],
        TimestampNs(100),
        || false,
    )?;
    let out1 = hub.publish_frame(
        &mut pool,
        PreviewFrameOffer {
            slot_id: f1.slot_id(),
            generation: Generation(3),
            frame_is_privacy_masked: false,
            rung: MediaDegradationRung::Rung0Nominal,
            now_ns: TimestampNs(100),
        },
        || false,
    )?;
    assert_eq!(out1.privacy_filtered_count, 1);
    assert_eq!(out1.delivered_count, 1);
    assert_eq!(out1.lease_cap_skipped_count, 1);
    assert_eq!(hub.subscriber_queue_len("viewer:masked-guest"), Some(0));
    assert_eq!(hub.subscriber_queue_len("op:high"), Some(1));
    assert_eq!(hub.subscriber_queue_len("op:low"), Some(0));
    pool.release_lease(f1, TimestampNs(110))?;

    // 2. Under Rung2ThrottleLivePreview (stride == 2): frame_ordinal=1 is odd, so all viewers shed.
    let f2 = pool.admit_frame(
        make_desc(3, 2),
        vec![22; 16 * 8 * 3],
        TimestampNs(200),
        || false,
    )?;
    let out2 = hub.publish_frame(
        &mut pool,
        PreviewFrameOffer {
            slot_id: f2.slot_id(),
            generation: Generation(3),
            frame_is_privacy_masked: true,
            rung: MediaDegradationRung::Rung2ThrottleLivePreview,
            now_ns: TimestampNs(200),
        },
        || false,
    )?;
    assert_eq!(out2.delivered_count, 0);
    assert_eq!(out2.pressure_shed_count, 3);
    pool.release_lease(f2, TimestampNs(210))?;

    // 3. Under Rung2ThrottleLivePreview at even frame_ordinal=0: priority_tier==0 viewers pass
    //    (op:high), priority_tier>0 (op:low) is shed first.
    let mut pool_wide = make_pool(8, 8)?;
    let mut hub2 = PreviewFanoutHub::new(PreviewFanoutPolicy::bounded_default(
        "cam:lobby-wide",
        Generation(3),
    ))?;
    hub2.subscribe(make_sub("op:high", 0, false))?;
    hub2.subscribe(make_sub("op:low", 2, false))?;
    let fw = pool_wide.admit_frame(
        make_desc(3, 1),
        vec![33; 16 * 8 * 3],
        TimestampNs(300),
        || false,
    )?;
    let out_even = hub2.publish_frame(
        &mut pool_wide,
        PreviewFrameOffer {
            slot_id: fw.slot_id(),
            generation: Generation(3),
            frame_is_privacy_masked: true,
            rung: MediaDegradationRung::Rung2ThrottleLivePreview,
            now_ns: TimestampNs(300),
        },
        || false,
    )?;
    assert_eq!(out_even.delivered_count, 1);
    assert_eq!(out_even.pressure_shed_count, 1);
    assert_eq!(hub2.subscriber_queue_len("op:high"), Some(1));
    assert_eq!(hub2.subscriber_queue_len("op:low"), Some(0));

    // 4. Under Rung4PauseDerivedCognition (stride == 0): preview pauses completely.
    let out_pause = hub2.publish_frame(
        &mut pool_wide,
        PreviewFrameOffer {
            slot_id: fw.slot_id(),
            generation: Generation(3),
            frame_is_privacy_masked: true,
            rung: MediaDegradationRung::Rung4PauseDerivedCognition,
            now_ns: TimestampNs(400),
        },
        || false,
    )?;
    assert_eq!(out_pause.delivered_count, 0);
    assert_eq!(out_pause.pressure_shed_count, 2);

    // Unsubscribe and advance_generation cleanly drain all queued leases back to pool.
    let drained_unsub = hub.unsubscribe("op:high", &mut pool, TimestampNs(500))?;
    assert_eq!(drained_unsub, 1);
    assert_eq!(pool.active_leases(), 0);

    let drained_gen = hub2.advance_generation(Generation(4), &mut pool_wide, TimestampNs(500))?;
    assert_eq!(drained_gen, 1);
    pool_wide.release_lease(fw, TimestampNs(510))?;
    assert_eq!(pool_wide.active_leases(), 0);
    Ok(())
}

#[test]
fn fss_057_refuses_stale_generation_cancellation_invalid_policy_and_tampered_receipt() -> TestResult
{
    let mut pool = make_pool(4, 4)?;
    assert_eq!(
        PreviewFanoutHub::new(PreviewFanoutPolicy {
            stream_id: String::new(),
            max_subscribers: 2,
            max_queue_depth: 2,
            active_generation: Generation(1),
        })
        .err(),
        Some(PreviewFanoutError::InvalidPolicy)
    );
    assert_eq!(
        PreviewFanoutHub::new(PreviewFanoutPolicy {
            stream_id: "cam:x".to_owned(),
            max_subscribers: 1,
            max_queue_depth: 1,
            active_generation: Generation(0),
        })
        .err(),
        Some(PreviewFanoutError::InvalidPolicy)
    );

    let mut hub = PreviewFanoutHub::new(PreviewFanoutPolicy {
        stream_id: "cam:gate".to_owned(),
        max_subscribers: 1,
        max_queue_depth: 2,
        active_generation: Generation(2),
    })?;
    hub.subscribe(make_sub("op:1", 0, false))?;
    assert!(matches!(
        hub.subscribe(make_sub("op:1", 0, false)),
        Err(PreviewFanoutError::DuplicateSubscriber(_))
    ));
    assert!(matches!(
        hub.subscribe(make_sub("op:2", 0, false)),
        Err(PreviewFanoutError::SubscriberCapExceeded { active: 1, max: 1 })
    ));

    let f = pool.admit_frame(
        make_desc(2, 1),
        vec![7; 16 * 8 * 3],
        TimestampNs(10),
        || false,
    )?;

    // Cancelled publish mutates nothing.
    assert_eq!(
        hub.publish_frame(
            &mut pool,
            PreviewFrameOffer {
                slot_id: f.slot_id(),
                generation: Generation(2),
                frame_is_privacy_masked: true,
                rung: MediaDegradationRung::Rung0Nominal,
                now_ns: TimestampNs(20),
            },
            || true,
        ),
        Err(PreviewFanoutError::Cancelled)
    );
    assert_eq!(hub.total_queued_leases(), 0);

    // Stale generation publish refused.
    assert_eq!(
        hub.publish_frame(
            &mut pool,
            PreviewFrameOffer {
                slot_id: f.slot_id(),
                generation: Generation(1),
                frame_is_privacy_masked: true,
                rung: MediaDegradationRung::Rung0Nominal,
                now_ns: TimestampNs(20),
            },
            || false,
        ),
        Err(PreviewFanoutError::StaleGeneration {
            expected: Generation(2),
            actual: Generation(1),
        })
    );

    // Non-monotonic generation advance refused.
    assert_eq!(
        hub.advance_generation(Generation(2), &mut pool, TimestampNs(30)),
        Err(PreviewFanoutError::StaleGeneration {
            expected: Generation(2),
            actual: Generation(2),
        })
    );

    // Canonical receipt round-trip + tamper refusal (both digest mismatch and impossible counters).
    let receipt = hub.receipt(TimestampNs(40));
    let mut enc = CanonicalEncoder::new();
    receipt.encode_canonical(&mut enc);
    let encoded = enc.finish();
    let decoded = PreviewFanoutReceipt::decode_canonical(&mut CanonicalDecoder::new(&encoded))?;
    assert_eq!(decoded, receipt);

    let mut forged = receipt.clone();
    forged.queued_leases = 1; // impossible since total_deliveries == 0!
    forged.receipt_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    let bad_bytes = bad_enc.finish();
    assert!(
        PreviewFanoutReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_bytes)).is_err()
    );

    pool.release_lease(f, TimestampNs(50))?;
    Ok(())
}
