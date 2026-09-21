#![forbid(unsafe_code)]
//! Actual filesystem publication and cold read-back, without a replacement store.
use super::*;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, NeverCancel, PublishOutcome};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fss-http-wire-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
    fn open(&self) -> Result<LocalRootPublisher, Box<dyn std::error::Error>> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(128, 16, 128, 1024,
            SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024)))?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn scope() -> HttpWireScope {
    HttpWireScope { stream: StreamBasis { source: [1; 32], generation: 2 }, receive_clock: [3; 32], retention_evidence: [4; 32] }
}
fn limits() -> HttpArchiveLimits {
    HttpArchiveLimits { maximum_reads: 16, maximum_bytes: 1024 * 1024,
        maximum_scan_roots: 256, maximum_spool_object_bytes: 65536 }
}
fn work() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }
fn raw(at: u64, bytes: &[u8], time: u64) -> HttpWireReceipt {
    HttpWireReceipt { basis: scope().stream, range: [at, at + bytes.len() as u64],
        sha256: ContentDigest::sha256(bytes).bytes(), admitted_ns: time }
}
fn add(a: &mut HttpWireArchive, p: &mut LocalRootPublisher, bytes: &[u8], time: u64)
    -> Result<HttpWirePublication, HttpArchiveError> {
    let plan = a.prepare_bytes(raw(a.pin().bytes, bytes, time), bytes, &mut work())?;
    a.publish(&plan, p, &NeverCancel, &mut work())
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}

#[test]
fn original_read_bytes_survive_cold_restart_and_cross_read_ranges() -> Test {
    let d = Directory::new();
    let pin = {
        let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
        add(&mut a, &mut p, b"HTTP/1.1 200 OK\r\n", 10)?;
        add(&mut a, &mut p, b"Content-Type: multipart/x-mixed-replace\r\n\r\n", 11)?;
        add(&mut a, &mut p, b"original bytes not decoded pixels", 11)?.pin
    }; // Lose every source buffer, index and storage owner; retain only the explicit pin.
    let p = d.open()?;
    let a = HttpWireArchive::load(&p, scope(), pin, limits(), &NeverCancel, &mut work())?;
    let expected = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace\r\n\r\noriginal bytes not decoded pixels";
    assert_eq!(a.read_range(&p, [0, pin.bytes], &NeverCancel, &mut work())?, expected);
    for start in 0..expected.len() {
        let end = (start + 9).min(expected.len());
        assert_eq!(a.read_range(&p, [start as u64, end as u64], &NeverCancel, &mut work())?, expected[start..end]);
    }
    Ok(())
}
#[test]
fn exact_retry_is_idempotent_but_changed_read_or_clock_is_not() -> Test {
    let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
    let wire = raw(0, b"abc", 10);
    let first = a.prepare_bytes(wire, b"abc", &mut work())?;
    assert_eq!(a.publish(&first, &mut p, &NeverCancel, &mut work())?.local.outcome, PublishOutcome::Published);
    let again = a.prepare_bytes(wire, b"abc", &mut work())?;
    assert_eq!(a.publish(&again, &mut p, &NeverCancel, &mut work())?.local.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(a.pin(), first.pin());
    assert!(a.prepare_bytes(wire, b"abd", &mut work()).is_err());
    assert!(a.prepare_bytes(raw(0, b"abc", 11), b"abc", &mut work()).is_err());
    assert!(a.prepare_bytes(raw(3, b"x", 9), b"x", &mut work()).is_err());
    assert_eq!(p.visible_roots().count(), 1); Ok(())
}
#[test]
fn lost_acknowledgement_resolves_original_prepared_pin_and_root() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut first = HttpWireArchive::new(scope(), limits())?;
    let mut old = HttpWireArchive::new(scope(), limits())?;
    let plan = first.prepare_bytes(raw(0, b"original", 10), b"original", &mut work())?;
    let expected = plan.pin(); let expected_slot = plan.slot().clone();
    first.publish(&plan, &mut p, &NeverCancel, &mut work())?;
    // Simulate a lost return to another stale in-process owner: same slot, not another read.
    let result = old.publish(&plan, &mut p, &NeverCancel, &mut work())?;
    assert_eq!(result.local.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(result.local.slot, expected_slot); assert_eq!(old.pin(), expected);
    drop(first); drop(old); drop(plan); drop(p);
    let p = d.open()?;
    assert_eq!(HttpWireArchive::load(&p, scope(), expected, limits(), &NeverCancel, &mut work())?.pin(), expected);
    Ok(())
}
#[test]
fn all_root_crash_cuts_never_advance_acknowledged_index_on_error() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename] {
        let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
        let before = a.pin(); let plan = a.prepare_bytes(raw(0, b"read", 10), b"read", &mut work())?;
        let expected = plan.pin(); p.inject_crash_at(cut);
        assert!(a.publish(&plan, &mut p, &NeverCancel, &mut work()).is_err());
        assert_eq!(a.pin(), before); assert!(p.is_poisoned()); drop(p);
        let p = d.open()?;
        let result = HttpWireArchive::load(&p, scope(), expected, limits(), &NeverCancel, &mut work());
        if cut == PublishCutPoint::AfterRootRename { assert_eq!(result?.pin(), expected); }
        else { assert!(result.is_err()); }
    }
    Ok(())
}
#[test]
fn cancellation_and_budget_refusal_leave_source_and_index_unchanged() -> Test {
    let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
    let before = a.pin(); let source = b"unconsumed";
    let plan = a.prepare_bytes(raw(0, source, 10), source, &mut work())?;
    assert!(matches!(a.publish(&plan, &mut p, &Stop, &mut work()), Err(HttpArchiveError::Cancelled)));
    for cut in [0, 1, 100, 4095] {
        assert!(a.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(cut)).is_err());
        assert_eq!(a.pin(), before); assert_eq!(p.visible_roots().count(), 0);
    }
    assert_eq!(plan.bytes, source);
    a.publish(&plan, &mut p, &NeverCancel, &mut work())?; Ok(())
}
#[test]
fn rollback_missing_root_and_unaccounted_later_roots_are_refused() -> Test {
    let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
    let old = add(&mut a, &mut p, b"one", 10)?.pin;
    let pin = add(&mut a, &mut p, b"two", 20)?.pin;
    assert!(HttpWireArchive::load(&p, scope(), old, limits(), &NeverCancel, &mut work()).is_err());
    let missing = HttpWirePin { reads: 3, ..pin };
    assert!(HttpWireArchive::load(&p, scope(), missing, limits(), &NeverCancel, &mut work()).is_err());
    let path = p.root_dir().join("roots").join(format!("{}.root", a.slot(1)?));
    drop(p); std::fs::remove_file(path)?;
    let p = d.open()?;
    assert!(HttpWireArchive::load(&p, scope(), pin, limits(), &NeverCancel, &mut work()).is_err()); Ok(())
}
#[test]
fn corruption_after_publication_refuses_warm_reads_and_cold_recovery() -> Test {
    let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
    let published = add(&mut a, &mut p, b"original", 10)?;
    let hex: String = published.wire.sha256.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(p.root_dir().join("spool/objects").join(hex), b"corrupt envelope")?;
    assert!(a.read_range(&p, [0, 8], &NeverCancel, &mut work()).is_err());
    drop(p); let p = d.open()?;
    assert!(HttpWireArchive::load(&p, scope(), published.pin, limits(), &NeverCancel, &mut work()).is_err()); Ok(())
}
#[test]
fn source_generation_retention_and_clock_cannot_rebind_existing_slots() -> Test {
    let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
    let pin = add(&mut a, &mut p, b"source", 10)?.pin;
    for changed in [HttpWireScope { receive_clock: [9; 32], ..scope() },
        HttpWireScope { retention_evidence: [9; 32], ..scope() }] {
        assert!(HttpWireArchive::load(&p, changed, pin, limits(), &NeverCancel, &mut work()).is_err());
        let mut other = HttpWireArchive::new(changed, limits())?;
        let plan = other.prepare_bytes(raw(0, b"source", 10), b"source", &mut work())?;
        assert!(other.publish(&plan, &mut p, &NeverCancel, &mut work()).is_err());
    }
    let changed = HttpWireScope { stream: StreamBasis { generation: 3, ..scope().stream }, ..scope() };
    assert!(HttpWireArchive::load(&p, changed, pin, limits(), &NeverCancel, &mut work()).is_err()); Ok(())
}
#[test]
fn limits_are_external_complete_prefix_bounds_not_serialized_authority() -> Test {
    let d = Directory::new(); let mut p = d.open()?; let mut a = HttpWireArchive::new(scope(), limits())?;
    add(&mut a, &mut p, b"abc", 10)?; let pin = add(&mut a, &mut p, b"def", 10)?.pin;
    for bounds in [HttpArchiveLimits { maximum_reads: 1, ..limits() },
        HttpArchiveLimits { maximum_bytes: 5, ..limits() },
        HttpArchiveLimits { maximum_scan_roots: 1, ..limits() },
        HttpArchiveLimits { maximum_spool_object_bytes: 1024, ..limits() }] {
        assert!(HttpWireArchive::load(&p, scope(), pin, bounds, &NeverCancel, &mut work()).is_err());
    }
    assert!(a.read_range(&p, [0, 7], &NeverCancel, &mut work()).is_err());
    assert!(a.read_range(&p, [2, 1], &NeverCancel, &mut work()).is_err());
    Ok(())
}
#[test]
fn incorrect_root_family_and_extra_children_cannot_supply_source_custody() -> Test {
    for extra in [false, true] {
        let d = Directory::new(); let mut p = d.open()?; let a = HttpWireArchive::new(scope(), limits())?;
        let plan = a.prepare_bytes(raw(0, b"data", 10), b"data", &mut work())?;
        let raw = p.stage_object(b"data")?;
        let metadata = p.stage_object(&plan.entry.metadata()?)?;
        let children = if extra { vec![raw, p.stage_object(b"unaccounted child")?] } else { vec![raw] };
        let manifest = ObjectManifest::new(if extra { HTTP_WIRE_KIND } else { "unrelated_family" }, children, Some(metadata))?;
        p.publish(&a.slot(1)?, &manifest)?;
        let pin = HttpWirePin { head: manifest.root(), reads: 1, bytes: 4, ..a.pin() };
        assert!(HttpWireArchive::load(&p, scope(), pin, limits(), &NeverCancel, &mut work()).is_err());
    }
    Ok(())
}
