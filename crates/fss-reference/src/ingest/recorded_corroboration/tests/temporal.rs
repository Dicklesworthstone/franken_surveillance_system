#![forbid(unsafe_code)]
//! The actual corroboration entry adapter, not a second association implementation.
use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use std::fs;
use std::path::PathBuf;

struct Context {
    root: PathBuf,
    cx: ReplayCx,
}
impl Context {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let root = std::env::temp_dir().join(format!("fss-interval-{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let authority = ContextAuthority::new_root(RootAuthoritySpec {
                        trace_id: "trace:intervals".into(), operation_id: OperationId::parse("operation:intervals")?,
                        principal: "principal:test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
                        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(1_000_000).build()?,
                        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
                        anchor_universe: ContentDigest::sha256(b"site:intervals"), generation: 1,
                    })?;
                    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
                    return Ok(Self { root, cx });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn entry(camera: usize, track_id: u64, a: i128, b: i128, x: f64) -> TestResult<GroundEntry> {
    let record = format!("entry:{camera}:{track_id}:{a}:{b}:{x}").into_bytes();
    Ok(GroundEntry {
        camera, zone_id: "door".into(), track_id, segment: 0, capture: interval(a, b)?,
        capsule_digest: ContentDigest::sha256(format!("capsule:{camera}:{track_id}").as_bytes()),
        track_box: [60, 16, 16, 16], ground: (x, 24.0),
        record_digest: ContentDigest::sha256(&record),
        disposition: EntryDisposition::NoCounterpartEntry, class_evidence: Vec::new(), record,
    })
}
fn tiny_plan() -> CorroborationPlan {
    let mut plan = plan();
    plan.gates.time_gate_ns = 10;
    plan.gates.distance_gate = 10.0;
    plan
}

#[test]
fn discarded_midpoint_favorite_no_longer_hides_a_valid_proposal_pair() -> TestResult {
    let context = Context::new("alternative")?;
    let mut entries = vec![entry(0, 0, 0, 0, 60.0)?, entry(1, 0, -20, 20, 60.0)?, entry(1, 1, 0, 0, 61.0)?];
    let before: Vec<_> = entries.iter().map(|e| (e.record.clone(), e.record_digest, e.capture)).collect();
    let pairs = associate_entries(&tiny_plan(), &mut entries, &context.cx)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].pair, [0, 2]);
    assert_eq!(pairs[0].separation, 0);
    assert_eq!(entries[1].disposition, EntryDisposition::TimeGateUncertain);
    assert_eq!(entries[0].disposition, EntryDisposition::Corroborated);
    assert_eq!(entries[2].disposition, EntryDisposition::Corroborated);
    assert_eq!(before, entries.iter().map(|e| (e.record.clone(), e.record_digest, e.capture)).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn full_width_capture_coordinates_reach_the_real_adapter_without_narrowing() -> TestResult {
    let context = Context::new("wide-time")?;
    for shift in [i128::MIN + 10, i128::from(i64::MAX) + 1000, i128::MAX - 10] {
        let mut entries = vec![entry(0, 0, shift - 2, shift + 2, 60.0)?, entry(1, 0, shift, shift + 4, 61.0)?];
        let pairs = associate_entries(&tiny_plan(), &mut entries, &context.cx)?;
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].separation, 6);
        assert_eq!(entries[0].capture.earliest.0, shift - 2);
    }
    Ok(())
}

#[test]
fn source_gap_unreliable_entries_remain_excluded_even_when_their_rank_is_best() -> TestResult {
    let context = Context::new("source-gap")?;
    let mut entries = vec![entry(0, 0, 0, 0, 60.0)?, entry(1, 0, 0, 0, 60.0)?, entry(1, 1, 0, 0, 61.0)?];
    entries[1].disposition = EntryDisposition::CaptureTimeUnreliableAfterGap;
    let pairs = associate_entries(&tiny_plan(), &mut entries, &context.cx)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].pair, [0, 2]);
    assert_eq!(entries[1].disposition, EntryDisposition::CaptureTimeUnreliableAfterGap);
    Ok(())
}

#[test]
fn unresolved_valid_competition_does_not_produce_a_proposal() -> TestResult {
    let context = Context::new("tie")?;
    let mut entries = vec![entry(0, 0, 0, 0, 60.0)?, entry(1, 0, -20, 20, 60.0)?,
        entry(1, 1, 0, 0, 61.0)?, entry(1, 2, 0, 0, 61.0)?];
    assert!(associate_entries(&tiny_plan(), &mut entries, &context.cx)?.is_empty());
    assert_eq!(entries[0].disposition, EntryDisposition::Ambiguous);
    assert_eq!(entries[1].disposition, EntryDisposition::TimeGateUncertain);
    assert_eq!(entries[2].disposition, EntryDisposition::Ambiguous);
    assert_eq!(entries[3].disposition, EntryDisposition::Ambiguous);
    Ok(())
}

#[test]
fn candidate_indices_and_zone_order_survive_canonical_track_sorting() -> TestResult {
    let context = Context::new("zones")?;
    let mut plan = tiny_plan();
    let mut yard = plan.zones[0].clone(); yard.zone_id = "yard".into(); plan.zones.push(yard);
    let mut entries = vec![entry(1, 0, 0, 0, 60.0)?, entry(0, 0, 0, 0, 60.0)?,
        entry(0, 0, 0, 0, 60.0)?, entry(1, 0, 0, 0, 60.0)?];
    entries[0].zone_id = "yard".into(); entries[2].zone_id = "yard".into();
    let pairs = associate_entries(&plan, &mut entries, &context.cx)?;
    assert_eq!(pairs.len(), 2);
    assert_eq!((pairs[0].zone_id.as_str(), pairs[0].pair), ("door", [1, 3]));
    assert_eq!((pairs[1].zone_id.as_str(), pairs[1].pair), ("yard", [2, 0]));
    Ok(())
}

#[test]
fn only_uncertain_pairs_keep_both_observations_and_produce_no_proposal() -> TestResult {
    let context = Context::new("uncertain")?;
    let mut entries = vec![entry(0, 0, -6, 6, 60.0)?, entry(1, 0, -6, 6, 60.0)?];
    assert!(associate_entries(&tiny_plan(), &mut entries, &context.cx)?.is_empty());
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.disposition == EntryDisposition::TimeGateUncertain));
    Ok(())
}

#[test]
fn cancellation_before_assignment_returns_no_partial_pair_set() -> TestResult {
    let context = Context::new("cancel")?;
    context.cx.set_cancel_at_checkpoint("recorded_corroboration:associate");
    let mut entries = vec![entry(0, 0, 0, 0, 60.0)?, entry(1, 0, 0, 0, 60.0)?];
    assert!(associate_entries(&tiny_plan(), &mut entries, &context.cx).is_err());
    assert!(context.cx.is_drain_completed());
    assert!(entries.iter().all(|e| e.disposition == EntryDisposition::NoCounterpartEntry));
    Ok(())
}
