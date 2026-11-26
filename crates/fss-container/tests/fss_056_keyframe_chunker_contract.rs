#![forbid(unsafe_code)]
//! Contract, pre-sync discard, GOP boundary sealing, open-GOP cap refusal, gap interruption,
//! canonical round-trip, tamper refusal, and cooperative cancellation tests for `FSS-056`
//! (`fss-x4a.12.5`: keyframe-aware chunker).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_container::chunker::{
    ChunkSampleInput, ChunkSealReason, ChunkerError, KeyframeChunk, KeyframeChunker,
    KeyframeChunkerPolicy,
};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
};

type TestResult = Result<(), Box<dyn Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample(
    seq: u64,
    dts_ns: i128,
    pts_ns: i128,
    duration_ns: u64,
    is_keyframe: bool,
    offset: u64,
    len: u64,
) -> ChunkSampleInput {
    ChunkSampleInput {
        sample_seq: seq,
        pts_ns,
        dts_ns,
        duration_ns,
        is_keyframe,
        source_byte_offset: offset,
        source_byte_len: len,
        payload_digest: ContentDigest::sha256(format!("sample:{seq}:{dts_ns}").as_bytes()),
        generation: Generation(3),
    }
}

#[test]
fn fss_056_presync_discard_keyframe_sealing_gap_reset_and_canonical_receipt() -> TestResult {
    let policy = KeyframeChunkerPolicy {
        stream_id: "cam:driveway:h264".to_owned(),
        stream_generation: Generation(3),
        target_duration_ns: 1_000,
        max_duration_ns: 3_000,
        max_chunk_bytes: 4_096,
        max_samples_per_chunk: 16,
        max_pre_sync_discard_bytes: 1_024,
    };
    let mut chunker = KeyframeChunker::new(policy)?;

    // 1. Leading non-keyframe P/B samples are discarded cleanly (never emitted as broken chunks).
    assert_eq!(
        chunker.push_sample(sample(1, 100, 100, 500, false, 0, 200), || false)?,
        None
    );
    assert_eq!(
        chunker.push_sample(sample(2, 600, 600, 500, false, 200, 200), || false)?,
        None
    );
    assert_eq!(chunker.pre_sync_discarded_samples(), 2);
    assert!(!chunker.has_open_chunk());

    // 2. First keyframe opens chunk 1; second non-keyframe reaches target_duration_ns (1000ns).
    assert_eq!(
        chunker.push_sample(sample(3, 1_100, 1_200, 500, true, 400, 800), || false)?,
        None
    );
    assert!(chunker.has_open_chunk());
    assert_eq!(
        chunker.push_sample(sample(4, 1_600, 1_100, 500, false, 1_200, 400), || false)?,
        None
    );

    // 3. Next keyframe seals chunk 1 cleanly at TargetDurationKeyframeBoundary and opens chunk 2!
    let sealed = chunker
        .push_sample(sample(5, 2_100, 2_100, 500, true, 1_600, 700), || false)?
        .ok_or("expected chunk 1 to seal on keyframe boundary")?;
    assert_eq!(sealed.chunk_index, 1);
    assert!(sealed.starts_with_keyframe);
    assert!(sealed.is_complete_gop);
    assert_eq!(
        sealed.seal_reason,
        ChunkSealReason::TargetDurationKeyframeBoundary
    );
    assert_eq!(sealed.first_sample_seq, 3);
    assert_eq!(sealed.last_sample_seq, 4);
    assert_eq!(sealed.sample_count, 2);
    assert_eq!(sealed.keyframe_count, 1);
    assert_eq!(sealed.min_pts_ns, 1_100);
    assert_eq!(sealed.max_pts_ns, 1_200);
    assert_eq!(sealed.total_duration_ns, 1_000);
    assert_eq!(sealed.total_bytes, 1_200);
    assert_eq!(sealed.first_source_offset, 400);
    assert_eq!(sealed.last_source_end_offset, 1_600);
    assert_eq!(sealed.pre_sync_discarded_samples, 2);
    assert!(sealed.verify_digest());

    // Canonical binary round-trip + forged-contradiction refusal.
    let mut enc = CanonicalEncoder::new();
    sealed.encode_canonical(&mut enc);
    let raw = enc.finish();
    let decoded = KeyframeChunk::decode_canonical(&mut CanonicalDecoder::new(&raw))?;
    assert_eq!(decoded, sealed);

    // Forged chunk claiming GapInterrupt AND is_complete_gop=true MUST fail decode even with matching digest.
    let mut forged = sealed.clone();
    forged.seal_reason = ChunkSealReason::GapInterrupt;
    forged.is_complete_gop = true;
    forged.chunk_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        KeyframeChunk::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish())).is_err()
    );

    // 4. Upstream gap seals chunk 2 with GapInterrupt (is_complete_gop = false) and resets sync!
    let gap_chunk = chunker
        .record_gap()?
        .ok_or("expected gap to seal open chunk 2")?;
    assert_eq!(gap_chunk.chunk_index, 2);
    assert_eq!(gap_chunk.seal_reason, ChunkSealReason::GapInterrupt);
    assert!(!gap_chunk.is_complete_gop);
    assert_eq!(
        gap_chunk.pre_sync_discarded_samples, 0,
        "chunk 2 opened immediately on a keyframe boundary and must not double-count chunk 1 discards"
    );
    assert!(!chunker.has_open_chunk());

    // Non-keyframe after gap is discarded until fresh keyframe arrives.
    assert_eq!(
        chunker.push_sample(sample(6, 2_600, 2_600, 500, false, 2_300, 300), || false)?,
        None
    );
    assert!(!chunker.has_open_chunk());
    assert_eq!(
        chunker.push_sample(sample(7, 3_100, 3_100, 500, true, 2_600, 500), || false)?,
        None
    );
    let flushed = chunker
        .flush()?
        .ok_or("expected flush to seal open chunk 3")?;
    assert_eq!(flushed.chunk_index, 3);
    assert_eq!(flushed.seal_reason, ChunkSealReason::ExplicitFlush);
    assert!(!flushed.is_complete_gop);
    assert_eq!(flushed.pre_sync_discarded_samples, 1);
    assert_eq!(chunker.pre_sync_discarded_samples(), 3);

    emit_caplog(
        "fss_056_presync_sealing_gap_and_canonical_receipt",
        "keyframe_aligned_chunks_presync_accounting_gap_reset_and_tamper_refusal",
        "keyframe_aligned_chunks_presync_accounting_gap_reset_and_tamper_refusal",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_056_open_gop_bounds_presync_cap_dts_regression_and_cancellation_fail_closed() -> TestResult {
    let policy = KeyframeChunkerPolicy {
        stream_id: "cam:gate:hevc".to_owned(),
        stream_generation: Generation(3),
        target_duration_ns: 1_000,
        max_duration_ns: 1_500,
        max_chunk_bytes: 2_000,
        max_samples_per_chunk: 4,
        max_pre_sync_discard_bytes: 500,
    };

    // 1. Pre-sync discard budget exceeded without keyframe fails closed.
    let mut pre = KeyframeChunker::new(policy.clone())?;
    pre.push_sample(sample(1, 0, 0, 500, false, 0, 400), || false)?;
    assert!(matches!(
        pre.push_sample(sample(2, 500, 500, 500, false, 400, 200), || false),
        Err(ChunkerError::PreSyncBudgetExceeded { .. })
    ));

    // 2. Open GOP exceeding max_duration_ns without keyframe fails closed (never splits mid-GOP!).
    let mut gop = KeyframeChunker::new(policy.clone())?;
    gop.push_sample(sample(1, 0, 0, 1_000, true, 0, 400), || false)?;
    assert_eq!(
        gop.push_sample(sample(2, 1_000, 1_000, 600, false, 400, 400), || false),
        Err(ChunkerError::OpenGopExceededBounds("max_duration_ns"))
    );

    // 3. DTS regression, duplicate sequence, and generation mismatch fail closed.
    assert!(matches!(
        gop.push_sample(sample(1, 1_000, 1_000, 500, false, 400, 200), || false),
        Err(ChunkerError::NonMonotonicSequence { .. })
    ));
    assert!(matches!(
        gop.push_sample(sample(2, -1, 0, 500, false, 400, 200), || false),
        Err(ChunkerError::DtsRegression { .. })
    ));
    let mut wrong_gen = sample(2, 1_000, 1_000, 500, true, 400, 200);
    wrong_gen.generation = Generation(99);
    assert!(matches!(
        gop.push_sample(wrong_gen, || false),
        Err(ChunkerError::GenerationMismatch { .. })
    ));

    // 4. Cooperative cancellation at both checkpoints leaves state unmutated.
    for cancel_at in [0_usize, 1] {
        let mut c = KeyframeChunker::new(policy.clone())?;
        let seen = AtomicUsize::new(0);
        let res = c.push_sample(sample(1, 0, 0, 500, true, 0, 400), || {
            seen.fetch_add(1, Ordering::Relaxed) >= cancel_at
        });
        assert_eq!(res, Err(ChunkerError::Cancelled));
        assert!(!c.has_open_chunk());
    }

    emit_caplog(
        "fss_056_faults_and_cancellation",
        "presync_cap_open_gop_bounds_dts_regression_and_cancellation_fail_closed",
        "presync_cap_open_gop_bounds_dts_regression_and_cancellation_fail_closed",
        "pass",
    );
    Ok(())
}
