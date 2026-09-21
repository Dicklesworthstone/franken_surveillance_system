#![forbid(unsafe_code)]
//! Actual original JPEG/graph/weights survive disk closure and native replay.
mod rgb_evidence_support;
use rgb_evidence_support::{capture, context, replay, Test, WORK};
use std::cell::Cell;
use std::path::PathBuf;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_reference::ingest::rgb_archive::{PreparedRgbArchive, RgbArchiveAuthority, RgbArchiveError,
    RgbArchiveLimits, RgbArchiveOperation, restore_rgb_evidence};
use fss_reference::ingest::rgb_evidence::RgbEvidenceBudget;
use fss_publication::RootLedgerOutcome;
use fss_twin::image_tracking::TrackingAvailability;
const STORAGE_WORK: u64 = 4_000_000_000;

struct Temp(PathBuf);
impl Temp {
    fn new(name: &str) -> Test<Self> {
        let path = std::env::temp_dir().join(format!("fss-rgb-archive-{}-{name}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
struct Access { reads: Cell<bool>, writes: Cell<bool>, calls: Cell<usize>, deny_at: Cell<usize> }
impl Access {
    fn new() -> Self { Self { reads: Cell::new(true), writes: Cell::new(true), calls: Cell::new(0), deny_at: Cell::new(usize::MAX) } }
}
fn retention() -> ContentDigest { ContentDigest::sha256(b"explicit original-byte retention test grant") }
impl RgbArchiveAuthority for Access {
    fn permits(&self, op: RgbArchiveOperation, r: ContentDigest, _: ContentDigest) -> bool {
        let n = self.calls.get() + 1; self.calls.set(n);
        r == retention() && n < self.deny_at.get() && match op {
            RgbArchiveOperation::RetainOriginals => self.writes.get(),
            RgbArchiveOperation::ReadOriginals => self.reads.get(),
        }
    }
}
fn plan(exposure: u8, availability: TrackingAvailability, cx: &ReplayCx) -> Test<PreparedRgbArchive> {
    let e = capture(exposure, availability, cx)?;
    let r = replay(&e, cx)?;
    Ok(PreparedRgbArchive::new(&e, &r, retention(), RgbArchiveLimits::default(),
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), cx)?)
}
#[test]
fn cold_originals_recompute_the_same_native_inference_without_source_files() -> Test {
    let temp = Temp::new("cold")?; let root = temp.0.join("deployment"); let cx = context(&temp.0)?;
    let access = Access::new(); let prepared = plan(1, TrackingAvailability::Available, &cx)?; let pin = prepared.pin();
    let mut d = ReferenceDeployment::open(&root, "site:rgb-custody", &cx)?;
    let receipt = prepared.publish(&mut d, &access, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    assert_eq!(receipt.root, pin.root); assert_eq!(receipt.outcome, RootLedgerOutcome::Committed);
    drop(prepared); drop(d); // No source envelope, imported model, tensors or deployment left.
    let mut d = ReferenceDeployment::reopen(&root, "site:rgb-custody", &cx)?;
    let e = restore_rgb_evidence(&mut d, pin, RgbArchiveLimits::default(), &access,
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    assert_eq!(e.jpeg(), rgb_evidence_support::jpeg(1));
    assert_eq!(e.graph(), rgb_evidence_support::graph()?); assert_eq!(e.weights(), rgb_evidence_support::weights());
    let actual = replay(&e, &cx)?;
    let original = capture(1, TrackingAvailability::Available, &cx)?; let expected = replay(&original, &cx)?;
    assert_eq!(actual.evidence_identity(), pin.evidence);
    assert_eq!(actual.run().report().digest(), expected.run().report().digest());
    assert_eq!(actual.run().inference().output_digest(), expected.run().inference().output_digest());
    assert_eq!(actual.admission().source().capture, pin.capture);
    Ok(())
}
#[test]
fn lost_ack_retry_has_exactly_one_canonical_reachability_batch() -> Test {
    let t = Temp::new("retry")?; let cx = context(&t.0)?; let a = Access::new();
    let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    let first = p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    let anchor = d.current_anchor().clone();
    let again = p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    assert_eq!(again.outcome, RootLedgerOutcome::AlreadyLedgered); assert_eq!(again.root, first.root);
    assert_eq!(again.anchor, first.anchor); assert_eq!(d.current_anchor(), &anchor);
    assert_eq!(d.ledger().batches().len(), 1); Ok(())
}
#[test]
fn byte_retention_denial_precedes_all_object_and_ledger_writes() -> Test {
    let t = Temp::new("denied")?; let cx = context(&t.0)?; let a = Access::new(); a.writes.set(false);
    let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    assert!(matches!(p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx), Err(RgbArchiveError::Denied)));
    assert!(d.ledger().batches().is_empty()); assert!(d.publisher().root(&p.pin().slot()?).is_none());
    a.writes.set(true);
    assert_eq!(p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?.outcome, RootLedgerOutcome::Committed);
    Ok(())
}
#[test]
fn revoke_read_permission_does_not_return_originals_or_change_authority() -> Test {
    let t = Temp::new("read-denied")?; let cx = context(&t.0)?; let a = Access::new();
    let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?; let anchor = d.current_anchor().clone();
    a.reads.set(false);
    assert!(matches!(restore_rgb_evidence(&mut d, p.pin(), RgbArchiveLimits::default(), &a,
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx), Err(RgbArchiveError::Denied)));
    assert_eq!(d.current_anchor(), &anchor); Ok(())
}
#[test]
fn unledgered_durable_root_is_not_reinterpreted_as_a_completed_publication() -> Test {
    let t = Temp::new("root-before-ledger")?; let root = t.0.join("deployment"); let cx = context(&t.0)?; let a = Access::new();
    let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&root, "site:rgb-custody", &cx)?;
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?; drop(d);
    // Plant the root-durable/ledger-absent crash state in this exclusively owned test tree.
    std::fs::write(root.join("ledger/journal.fssj"), [])?;
    let mut d = ReferenceDeployment::reopen(&root, "site:rgb-custody", &cx)?;
    assert!(matches!(restore_rgb_evidence(&mut d, p.pin(), RgbArchiveLimits::default(), &a,
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx), Err(RgbArchiveError::NotCommitted)));
    assert!(d.ledger().batches().is_empty());
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    assert_eq!(d.ledger().batches().len(), 1); Ok(())
}
#[test]
fn changed_capture_or_retention_pin_is_never_silently_rebound() -> Test {
    let t = Temp::new("pins")?; let cx = context(&t.0)?; let a = Access::new(); let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    for field in 0..4 {
        let mut pin = p.pin();
        match field { 0 => pin.capture[1] += 1, 1 => pin.evidence = ContentDigest::sha256(b"other"),
            2 => pin.retention = ContentDigest::sha256(b"other"), _ => pin.root = ContentDigest::sha256(b"other") }
        assert!(restore_rgb_evidence(&mut d, pin, RgbArchiveLimits::default(), &a,
            &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx).is_err());
    }
    assert_eq!(d.ledger().batches().len(), 1); Ok(())
}
#[test]
fn independent_bound_and_budget_failures_preserve_retryability() -> Test {
    let t = Temp::new("limits")?; let cx = context(&t.0)?; let a = Access::new(); let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    assert!(p.publish(&mut d, &a, &mut WorkBudget::new(0), &cx).is_err());
    assert!(d.ledger().batches().is_empty());
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    let limits = RgbArchiveLimits { maximum_spool_object_bytes: 1024, ..RgbArchiveLimits::default() };
    assert!(matches!(restore_rgb_evidence(&mut d, p.pin(), limits, &a,
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx), Err(RgbArchiveError::Limit)));
    assert!(restore_rgb_evidence(&mut d, p.pin(), RgbArchiveLimits::default(), &a,
        &mut RgbEvidenceBudget::new(0), &mut WorkBudget::new(STORAGE_WORK), &cx).is_err());
    let e = restore_rgb_evidence(&mut d, p.pin(), RgbArchiveLimits::default(), &a,
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    assert_eq!(e.identity(), p.pin().evidence); Ok(())
}
#[test]
fn late_precommit_revocation_leaves_no_success_and_exact_retry_completes() -> Test {
    let t = Temp::new("revocation")?; let cx = context(&t.0)?; let a = Access::new(); let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    // Initial admission + five source writes + metadata = seven. Refuse the first root cut point.
    a.deny_at.set(8);
    assert!(p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx).is_err());
    assert!(d.ledger().batches().is_empty()); a.deny_at.set(usize::MAX);
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    assert_eq!(d.ledger().batches().len(), 1); Ok(())
}
#[test]
fn interrupted_and_unobservable_exposures_replay_without_availability_upgrade() -> Test {
    let t = Temp::new("availability")?; let cx = context(&t.0)?; let a = Access::new();
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    for (i, status) in [TrackingAvailability::Unobservable, TrackingAvailability::Disturbed].into_iter().enumerate() {
        let p = plan(i as u8 + 1, status, &cx)?; p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
        let e = restore_rgb_evidence(&mut d, p.pin(), RgbArchiveLimits::default(), &a,
            &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx)?;
        assert_eq!(replay(&e, &cx)?.admission().availability(), status);
    }
    Ok(())
}
#[test]
fn repeated_models_are_shared_objects_not_per_frame_envelopes() -> Test {
    let t = Temp::new("model-sharing")?; let cx = context(&t.0)?; let a = Access::new();
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    let graph = ContentDigest::sha256(&rgb_evidence_support::graph()?);
    let weights = ContentDigest::sha256(&rgb_evidence_support::weights());
    let mut roots = Vec::new();
    for exposure in [1, 2] {
        let p = plan(exposure, TrackingAvailability::Available, &cx)?;
        let r = p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
        let manifest = fss_object::ObjectManifest::from_canonical_bytes(&d.publisher().spool().read(r.root)?)?;
        assert!(manifest.children().contains(&graph)); assert!(manifest.children().contains(&weights));
        roots.push(r.root);
    }
    assert_ne!(roots[0], roots[1]);
    assert_eq!(d.publisher().spool().read(weights)?, rgb_evidence_support::weights()); Ok(())
}
fn damage_exact_payload(path: &std::path::Path, payload: &[u8]) -> Test<bool> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?; let p = entry.path();
        if entry.file_type()?.is_dir() {
            if damage_exact_payload(&p, payload)? { return Ok(true); }
        } else if entry.file_type()?.is_file() {
            let mut bytes = std::fs::read(&p)?;
            if let Some(at) = bytes.windows(payload.len()).position(|w| w == payload) {
                bytes[at + payload.len() - 1] ^= 1; std::fs::write(&p, bytes)?; return Ok(true);
            }
        }
    }
    Ok(false)
}
#[test]
fn late_original_corruption_refuses_restore_without_rewriting_canonical_history() -> Test {
    let t = Temp::new("corruption")?; let cx = context(&t.0)?; let a = Access::new();
    let p = plan(1, TrackingAvailability::Available, &cx)?;
    let mut d = ReferenceDeployment::open(&t.0.join("deployment"), "site:rgb-custody", &cx)?;
    p.publish(&mut d, &a, &mut WorkBudget::new(STORAGE_WORK), &cx)?;
    let anchor = d.current_anchor().clone();
    assert!(damage_exact_payload(&d.root().join("objects/spool"), &rgb_evidence_support::jpeg(1))?);
    assert!(restore_rgb_evidence(&mut d, p.pin(), RgbArchiveLimits::default(), &a,
        &mut RgbEvidenceBudget::new(WORK), &mut WorkBudget::new(STORAGE_WORK), &cx).is_err());
    assert_eq!(d.current_anchor(), &anchor); Ok(())
}
