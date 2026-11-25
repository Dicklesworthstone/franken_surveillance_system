#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-107` (`fss-x4a.9.14`):
//! Derived high-water protocol for graph, search, model, and projection caches.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DerivedCacheKind, DerivedGenerationPin, DerivedHighWaterState,
    DurableAppendReconciliation, DurableReferenceLedger, HIGH_WATER_VERSION, HighWaterError,
    HighWaterPlan, HighWaterProtocol, IncompleteTailPolicy, LedgerOracle,
    MAX_HIGH_WATER_WIRE_BYTES, MAX_REPLAY_PAGE_BYTES, OracleLimits, RebuildReason,
    ReplayPageBudget,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..32 {
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("fss-107-highwater-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp dir namespace exhausted",
        ))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn base_pin(kind: DerivedCacheKind, id: &str) -> DerivedGenerationPin {
    DerivedGenerationPin {
        cache_kind: kind,
        cache_id: id.to_owned(),
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        adapter_registry_epoch: 0,
        package_generation: 1,
        preprocess_generation: 1,
        numeric_generation: 1,
        kernel_generation: 1,
        memory_generation: 1,
        calibration_generation: 1,
        model_digest: Some(d("model-weights-gen-1")),
    }
}

fn append_n(
    oracle: &mut LedgerOracle,
    durable: &mut DurableReferenceLedger,
    start: u64,
    end: u64,
) -> TestResult {
    for seq in start..=end {
        let batch = oracle.prepare_batch(
            BatchId::parse(format!("batch:hw-{seq:03}"))?,
            vec![EvidenceDelta {
                delta_id: format!("dhw-{seq}"),
                family: "source_evidence".to_owned(),
                object_id: ObjectId::parse(format!("obj:hw-{seq}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
                plane: Plane::Authority,
                payload_digest: d(&format!("payload-hw-{seq}")),
                witness_digest: None,
                operation_id: None,
            }],
            vec![],
        )?;
        oracle.append(batch.clone())?;
        durable.append(batch)?;
    }
    Ok(())
}

#[test]
fn incremental_catchup_converges_to_up_to_date_across_cache_kinds_and_wire_persistence()
-> TestResult {
    let dir = TempDir::new()?;
    let journal = dir.0.join("hw.journal");
    let mut oracle = LedgerOracle::new("site-fss-107", OracleLimits::CEILING)?;
    let mut durable =
        DurableReferenceLedger::open(&journal, "site-fss-107", IncompleteTailPolicy::Reject)?;
    append_n(&mut oracle, &mut durable, 1, 6)?;

    let budget = ReplayPageBudget::new(2, MAX_REPLAY_PAGE_BYTES)?;
    for (kind, id) in [
        (DerivedCacheKind::Graph, "graph:g_assoc"),
        (DerivedCacheKind::Search, "search:lexical-v1"),
        (DerivedCacheKind::Model, "model:person-det-v1"),
        (DerivedCacheKind::Projection, "proj:mvcc-main"),
    ] {
        let pin = base_pin(kind, id);
        let mut wm = DerivedHighWaterState::new(
            pin.clone(),
            durable.replay_cursor_genesis()?,
            d("empty-derived-state"),
        )?;

        let mut applied_batches = 0usize;
        loop {
            // Round-trip watermark binary wire bytes before each evaluation.
            let wire = wm.to_canonical_bytes()?;
            wm = DerivedHighWaterState::from_canonical_bytes(&wire)?;

            let plan = if applied_batches.is_multiple_of(2) {
                HighWaterProtocol::evaluate_durable(&durable, &wm, &pin, budget, false)?
            } else {
                HighWaterProtocol::evaluate_oracle(&oracle, &wm, &pin, budget, false)?
            };
            match plan {
                HighWaterPlan::IncrementalCatchUp { page, .. } => {
                    applied_batches += page.batches.len();
                    let next_digest = d(&format!("{id}:state:{applied_batches}"));
                    wm = wm.commit_advance(&page, next_digest, &pin)?;
                }
                HighWaterPlan::UpToDate {
                    cursor,
                    head_anchor,
                } => {
                    assert_eq!(cursor.sequence(), 6);
                    assert_eq!(head_anchor.commit_sequence, 6);
                    break;
                }
                other => return Err(format!("unexpected plan for {id}: {other:?}").into()),
            }
        }
        assert_eq!(applied_batches, 6);
    }

    emit_caplog(
        "fss107_incremental_catchup_all_cache_kinds",
        "graph_search_model_projection_converged_to_head",
        "graph_search_model_projection_converged_to_head",
        "pass",
    );
    Ok(())
}

#[test]
fn generation_drift_corruption_fork_pending_cancel_and_wire_hostility_fail_closed() -> TestResult {
    let dir = TempDir::new()?;
    let journal = dir.0.join("hw-faults.journal");
    let mut oracle = LedgerOracle::new("site-fss-107-faults", OracleLimits::CEILING)?;
    let mut durable = DurableReferenceLedger::open(
        &journal,
        "site-fss-107-faults",
        IncompleteTailPolicy::Reject,
    )?;
    append_n(&mut oracle, &mut durable, 1, 3)?;

    let pin = base_pin(DerivedCacheKind::Model, "model:detector-v1");
    let budget = ReplayPageBudget::new(4, MAX_REPLAY_PAGE_BYTES)?;
    let wm2 =
        DerivedHighWaterState::new(pin.clone(), oracle.replay_cursor_at(2)?, d("state-at-2"))?;

    // 1. Any generation drift (kernel, calibration, model_digest, schema_epoch, cache_id) -> RebuildRequired.
    let mut drifted_kernel = pin.clone();
    drifted_kernel.kernel_generation = 2;
    assert!(matches!(
        HighWaterProtocol::evaluate_oracle(&oracle, &wm2, &drifted_kernel, budget, false)?,
        HighWaterPlan::RebuildRequired {
            reason: RebuildReason::DerivedGenerationDrift,
            ..
        }
    ));

    let mut drifted_cal = pin.clone();
    drifted_cal.calibration_generation = 9;
    assert!(matches!(
        HighWaterProtocol::evaluate_oracle(&oracle, &wm2, &drifted_cal, budget, false)?,
        HighWaterPlan::RebuildRequired {
            reason: RebuildReason::DerivedGenerationDrift,
            ..
        }
    ));

    let mut drifted_model = pin.clone();
    drifted_model.model_digest = Some(d("model-weights-gen-2"));
    assert!(matches!(
        HighWaterProtocol::evaluate_oracle(&oracle, &wm2, &drifted_model, budget, false)?,
        HighWaterPlan::RebuildRequired {
            reason: RebuildReason::DerivedGenerationDrift,
            ..
        }
    ));

    let mut drifted_schema = pin.clone();
    drifted_schema.schema_epoch = 2;
    assert!(matches!(
        HighWaterProtocol::evaluate_oracle(&oracle, &wm2, &drifted_schema, budget, false)?,
        HighWaterPlan::RebuildRequired {
            reason: RebuildReason::LedgerEpochChanged,
            ..
        }
    ));

    // 2. Corrupted watermark forces RebuildRequired and refuses commit_advance.
    let corrupt_wm = wm2.mark_corrupted()?;
    assert!(corrupt_wm.is_corrupted());
    assert!(matches!(
        HighWaterProtocol::evaluate_oracle(&oracle, &corrupt_wm, &pin, budget, false)?,
        HighWaterPlan::RebuildRequired {
            reason: RebuildReason::CacheCorrupted,
            ..
        }
    ));
    if let HighWaterPlan::IncrementalCatchUp { page, .. } =
        HighWaterProtocol::evaluate_oracle(&oracle, &wm2, &pin, budget, false)?
    {
        assert_eq!(
            corrupt_wm.commit_advance(&page, d("x"), &pin),
            Err(HighWaterError::CorruptedWatermarkCannotAdvance)
        );
        // Forged non-monotonic page (next_cursor rewinds to start_cursor while claiming batches)
        // must fail closed with CursorContinuityViolation.
        let mut forged_page = *page;
        forged_page.next_cursor = forged_page.start_cursor.clone();
        assert!(matches!(
            wm2.commit_advance(&forged_page, d("x"), &pin),
            Err(HighWaterError::CursorContinuityViolation { .. })
        ));
    }

    // 3. Cooperative cancellation returns Cancelled with unchanged sequence (even when corrupted).
    assert_eq!(
        HighWaterProtocol::evaluate_oracle(&oracle, &wm2, &pin, budget, true)?,
        HighWaterPlan::Cancelled { cursor_sequence: 2 }
    );
    assert_eq!(
        HighWaterProtocol::evaluate_oracle(&oracle, &corrupt_wm, &pin, budget, true)?,
        HighWaterPlan::Cancelled { cursor_sequence: 2 }
    );

    // 4. Forked lineage/history -> RebuildRequired.
    let other_oracle = LedgerOracle::new("site-other-107", OracleLimits::CEILING)?;
    let other_wm = DerivedHighWaterState::new(
        pin.clone(),
        other_oracle.replay_cursor_genesis()?,
        d("other"),
    )?;
    assert!(matches!(
        HighWaterProtocol::evaluate_oracle(&oracle, &other_wm, &pin, budget, false)?,
        HighWaterPlan::RebuildRequired {
            reason: RebuildReason::LineageOrEpochDiverged,
            ..
        }
    ));

    // 5. Pending indeterminate durable append blocks derived catch-up until reconciled.
    let b4 = durable.prepare_batch(
        BatchId::parse("batch:hw-004")?,
        vec![EvidenceDelta {
            delta_id: "dhw-4".to_owned(),
            family: "source_evidence".to_owned(),
            object_id: ObjectId::parse("obj:hw-4")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
            plane: Plane::Authority,
            payload_digest: d("payload-hw-4"),
            witness_digest: None,
            operation_id: None,
        }],
        vec![],
    )?;
    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(durable.append(b4).is_err());
    assert_eq!(
        HighWaterProtocol::evaluate_durable(&durable, &wm2, &pin, budget, false)?,
        HighWaterPlan::BlockedPendingReconciliation {
            pending_sequence: 4
        }
    );
    assert!(matches!(
        durable.reconcile_pending(IncompleteTailPolicy::Reject)?,
        DurableAppendReconciliation::Committed { sequence: 4, .. }
    ));
    assert!(matches!(
        HighWaterProtocol::evaluate_durable(&durable, &wm2, &pin, budget, false)?,
        HighWaterPlan::IncrementalCatchUp { .. }
    ));

    // 6. Hostile wire bytes fail closed.
    let wire = wm2.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        DerivedHighWaterState::from_canonical_bytes(&bad_magic),
        Err(HighWaterError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&(HIGH_WATER_VERSION + 1).to_be_bytes());
    assert_eq!(
        DerivedHighWaterState::from_canonical_bytes(&bad_ver),
        Err(HighWaterError::UnsupportedVersion {
            version: HIGH_WATER_VERSION + 1
        })
    );
    assert!(matches!(
        DerivedHighWaterState::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(HighWaterError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let end = flipped.len() - 1;
    flipped[end] ^= 0x02;
    assert_eq!(
        DerivedHighWaterState::from_canonical_bytes(&flipped),
        Err(HighWaterError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x01);
    assert!(matches!(
        DerivedHighWaterState::from_canonical_bytes(&trailing),
        Err(HighWaterError::MalformedWire(_))
    ));
    let huge = vec![0u8; MAX_HIGH_WATER_WIRE_BYTES + 1];
    assert!(matches!(
        DerivedHighWaterState::from_canonical_bytes(&huge),
        Err(HighWaterError::BoundsExceeded { .. })
    ));

    emit_caplog(
        "fss107_faults_drift_corrupt_pending_cancel_wire",
        "all_high_water_faults_fail_closed_or_mandate_rebuild",
        "all_high_water_faults_fail_closed_or_mandate_rebuild",
        "pass",
    );
    Ok(())
}
