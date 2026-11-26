#![forbid(unsafe_code)]
//! Contract & fault suite for `DOC-054` (`fss-x4a.5.54`): shared frame pyramids, cache tiling,
//! and optional accelerator isolation behind deterministic scalar truth.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::{
    AcceleratorCandidate, AcceleratorGateDecision, DType, FrameDescriptor, FramePool,
    FramePoolPolicy, FramePyramid, FramePyramidError, FramePyramidReceipt, TilePlan,
    adjudicate_accelerator_against_scalar, downsample_2x_box_u8,
};

type TestResult = Result<(), Box<dyn Error>>;

fn digest(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn make_pool(max_slots: usize, max_bytes: usize) -> Result<FramePool, Box<dyn Error>> {
    Ok(FramePool::new(FramePoolPolicy {
        pool_id: "pool:pyramid-01".to_owned(),
        max_slots,
        max_bytes,
        max_leases_per_frame: 8,
        alignment_bytes: 64,
        elevated_threshold_bps: 7_500,
        critical_threshold_bps: 9_000,
    })?)
}

#[test]
fn doc_054_scalar_downsample_shared_pyramid_pool_and_zero_leak_release() -> TestResult {
    // Hand-verify exact 2x box filter including odd dimension edge replication (5x3 luma).
    #[rustfmt::skip]
    let odd_plane: Vec<u8> = vec![
        10, 20,  30, 40,  50,
        30, 40,  50, 60,  70,
        90, 100, 110, 120, 130,
    ];
    let (w1, h1, l1) = downsample_2x_box_u8(&odd_plane, 5, 3, 1)?;
    assert_eq!((w1, h1), (3, 2));
    // Row 0: (10+20+30+40+2)>>2=25, (30+40+50+60+2)>>2=45, (50+50+70+70+2)>>2=60
    // Row 1 (y=2 replicated): (90+100+90+100+2)>>2=95, (110+120+110+120+2)>>2=115, (130*4+2)>>2=130
    assert_eq!(l1, vec![25, 45, 60, 95, 115, 130]);

    // Build a 3-level shared RGB pyramid (32x16 -> 16x8 -> 8x4) directly inside FramePool.
    let mut pool = make_pool(16, 1024 * 1024)?;
    let base_bytes: Vec<u8> = (0..(32 * 16 * 3)).map(|i| (i % 251) as u8).collect();
    let desc = FrameDescriptor {
        width: 32,
        height: 16,
        channels: 3,
        dtype: DType::U8,
        generation: Generation(7),
        frame_seq: 42,
        source_evidence_digest: digest("src:frame:42"),
    };
    let pyramid = FramePyramid::build_in_pool(
        &mut pool,
        desc,
        base_bytes.clone(),
        3,
        TimestampNs(1_000),
        || false,
    )?;

    assert_eq!(pyramid.level_count(), 3);
    let e0 = pyramid.level_entry(0).ok_or("missing level 0")?;
    let e1 = pyramid.level_entry(1).ok_or("missing level 1")?;
    let e2 = pyramid.level_entry(2).ok_or("missing level 2")?;
    assert_eq!((e0.width, e0.height), (32, 16));
    assert_eq!((e1.width, e1.height), (16, 8));
    assert_eq!((e2.width, e2.height), (8, 4));
    assert_eq!(pyramid.level_bytes(0), Some(base_bytes.as_slice()));

    // Two independent consumers share level 1 zero-copy via the exact same StorageId.
    let detector_lease = pyramid.share_level(&mut pool, 1, || false)?;
    let tracker_lease = pyramid.share_level(&mut pool, 1, || false)?;
    assert_eq!(detector_lease.storage().id(), tracker_lease.storage().id());
    assert_eq!(Some(detector_lease.bytes()), pyramid.level_bytes(1));
    assert_eq!(pool.active_leases(), 5); // 3 internal pyramid leases + 2 shared leases

    // Build cache-friendly tile plan for level 0 and seal canonical receipt.
    let tile_plan = TilePlan::build(32, 16, 12, 10, 2)?;
    assert!(tile_plan.verify_exact_coverage());
    assert_eq!(tile_plan.tiles.len(), 6); // ceil(32/12)=3 cols x ceil(16/10)=2 rows

    let receipt = pyramid.receipt(
        &tile_plan,
        AcceleratorGateDecision::FallbackScalarUnavailable,
    )?;
    assert!(receipt.verify_digest());
    let mut enc = CanonicalEncoder::new();
    receipt.encode_canonical(&mut enc);
    let encoded = enc.finish();
    let decoded = FramePyramidReceipt::decode_canonical(&mut CanonicalDecoder::new(&encoded))?;
    assert_eq!(decoded, receipt);

    // Release all consumer leases + pyramid leases -> 0 live leases, 0 live bytes after reclaim.
    pool.release_lease(detector_lease, TimestampNs(2_000))?;
    pool.release_lease(tracker_lease, TimestampNs(2_000))?;
    pyramid.release_all(&mut pool, TimestampNs(2_000))?;
    assert_eq!(pool.active_leases(), 0);
    pool.reclaim_unleased(TimestampNs(3_000))?;
    assert_eq!(pool.accountant().live_bytes(), 0);

    println!(
        "CAPLOG {{\"step\":\"doc_054_pyramid\",\"levels\":{},\"tiles\":{},\"live_bytes\":{},\"verdict\":\"ok\"}}",
        receipt.level_digests.len(),
        receipt.tile_count,
        pool.accountant().live_bytes()
    );
    Ok(())
}

#[test]
fn doc_054_tile_plan_clamping_pool_rollback_and_accelerator_isolation_gate() -> TestResult {
    // 1. Odd image tile plan clamps halos cleanly to [0..W] x [0..H] and detects tampering.
    let mut plan = TilePlan::build(19, 13, 8, 6, 3)?;
    assert!(plan.verify_exact_coverage());
    let first = plan.tiles[0];
    assert_eq!((first.core_x, first.core_y), (0, 0));
    assert_eq!((first.halo_x, first.halo_y), (0, 0));
    assert_eq!((first.halo_width, first.halo_height), (11, 9));
    let last = *plan.tiles.last().ok_or("empty tile plan")?;
    assert_eq!(last.core_x + last.core_width, 19);
    assert_eq!(last.core_y + last.core_height, 13);
    assert_eq!(last.halo_x + last.halo_width, 19);
    assert_eq!(last.halo_y + last.halo_height, 13);

    // Tampered tile halo failing to enclose core MUST fail verify_exact_coverage.
    plan.tiles[0].halo_width = 4;
    assert!(!plan.verify_exact_coverage());

    // Tile count explosion refused cleanly.
    assert!(matches!(
        TilePlan::build(1000, 1000, 1, 1, 0),
        Err(FramePyramidError::TileLimitExceeded { .. })
    ));

    // 2. Atomic rollback on mid-pyramid pool slot exhaustion: max_slots == 2 cannot hold 3 levels,
    //    so zero leases remain leaked in pool after error!
    let mut tiny_pool = make_pool(2, 1024 * 1024)?;
    let desc = FrameDescriptor {
        width: 16,
        height: 16,
        channels: 1,
        dtype: DType::U8,
        generation: Generation(2),
        frame_seq: 1,
        source_evidence_digest: digest("src:tiny"),
    };
    let err = FramePyramid::build_in_pool(
        &mut tiny_pool,
        desc,
        vec![5; 256],
        3,
        TimestampNs(100),
        || false,
    )
    .err();
    assert!(matches!(err, Some(FramePyramidError::Pool(_))));
    assert_eq!(tiny_pool.active_leases(), 0);
    tiny_pool.reclaim_unleased(TimestampNs(200))?;
    assert_eq!(tiny_pool.accountant().live_bytes(), 0);

    // Cancellation refused cleanly without touching pool.
    assert_eq!(
        FramePyramid::build_in_pool(
            &mut tiny_pool,
            desc,
            vec![5; 256],
            2,
            TimestampNs(210),
            || true,
        )
        .err(),
        Some(FramePyramidError::Cancelled)
    );
    assert_eq!(tiny_pool.retained_slots(), 0);

    // 3. Optional accelerator isolation gate behind scalar reference truth.
    let scalar = vec![10_u8, 20, 30, 40, 50];
    let within_tol = vec![10_u8, 21, 29, 40, 51]; // max delta == 1
    let divergent = vec![10_u8, 25, 30, 40, 50]; // max delta == 5 > 1

    let (d_unavail, delta_unavail, out_unavail) = adjudicate_accelerator_against_scalar(
        Generation(4),
        &scalar,
        AcceleratorCandidate::Unavailable,
        1,
    );
    assert_eq!(
        d_unavail,
        AcceleratorGateDecision::FallbackScalarUnavailable
    );
    assert_eq!(delta_unavail, 0);
    assert_eq!(out_unavail, scalar.as_slice());

    let (d_fault, delta_fault, out_fault) = adjudicate_accelerator_against_scalar(
        Generation(4),
        &scalar,
        AcceleratorCandidate::FaultedOrTimedOut,
        1,
    );
    assert_eq!(d_fault, AcceleratorGateDecision::FallbackScalarFaulted);
    assert_eq!(delta_fault, 0);
    assert_eq!(out_fault, scalar.as_slice());

    let (d_ok, delta_ok, out_ok) = adjudicate_accelerator_against_scalar(
        Generation(4),
        &scalar,
        AcceleratorCandidate::Candidate {
            generation: Generation(4),
            bytes: &within_tol,
        },
        1,
    );
    assert_eq!(d_ok, AcceleratorGateDecision::AdmittedWithinTolerance);
    assert_eq!(delta_ok, 1);
    assert_eq!(out_ok, within_tol.as_slice());

    // Divergent bytes quarantined back to scalar truth!
    let (d_div, delta_div, out_div) = adjudicate_accelerator_against_scalar(
        Generation(4),
        &scalar,
        AcceleratorCandidate::Candidate {
            generation: Generation(4),
            bytes: &divergent,
        },
        1,
    );
    assert_eq!(
        d_div,
        AcceleratorGateDecision::QuarantinedDivergenceFallbackScalar
    );
    assert_eq!(delta_div, 5);
    assert_eq!(out_div, scalar.as_slice());

    // Stale accelerator generation quarantined back to scalar truth even if bytes match!
    let (d_stale, delta_stale, out_stale) = adjudicate_accelerator_against_scalar(
        Generation(4),
        &scalar,
        AcceleratorCandidate::Candidate {
            generation: Generation(3),
            bytes: &scalar,
        },
        1,
    );
    assert_eq!(
        d_stale,
        AcceleratorGateDecision::QuarantinedDivergenceFallbackScalar
    );
    assert_eq!(delta_stale, u8::MAX);
    assert_eq!(out_stale, scalar.as_slice());

    // Wrong byte length quarantined back to scalar truth!
    let (d_len, delta_len, out_len) = adjudicate_accelerator_against_scalar(
        Generation(4),
        &scalar,
        AcceleratorCandidate::Candidate {
            generation: Generation(4),
            bytes: &scalar[..3],
        },
        1,
    );
    assert_eq!(
        d_len,
        AcceleratorGateDecision::QuarantinedDivergenceFallbackScalar
    );
    assert_eq!(delta_len, u8::MAX);
    assert_eq!(out_len, scalar.as_slice());
    Ok(())
}
