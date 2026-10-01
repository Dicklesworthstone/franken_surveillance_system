#![forbid(unsafe_code)]
use super::*;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationError, LocalPublicationLimits, NeverCancel};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const FIRST: &[u8] = b"first original response fragment";
const SECOND: &[u8] = b"second original response fragment";
const WORK: u64 = 100_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, std::io::Error> {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-http-cold-recovery-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("test directory collision bound"))
    }
    fn open(&self) -> Result<LocalRootPublisher, LocalPublicationError> {
        LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(
            64, 8, 64, 256, SpoolLimits::new(512, 8 * 1024 * 1024, 65536, 1024),
        ))
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn scope() -> HttpWireScope {
    HttpWireScope {
        stream: StreamBasis { source: [41; 32], generation: 7 },
        receive_clock: [42; 32], retention_evidence: [43; 32],
    }
}
fn limits() -> HttpArchiveLimits {
    HttpArchiveLimits {
        maximum_reads: 16, maximum_bytes: 65536,
        maximum_scan_roots: 256, maximum_spool_object_bytes: 65536,
    }
}
fn wire(bytes: &[u8], offset: u64, admitted_ns: u64) -> HttpWireReceipt {
    HttpWireReceipt {
        basis: scope().stream, range: [offset, offset + bytes.len() as u64],
        sha256: ContentDigest::sha256(bytes).bytes(), admitted_ns,
    }
}
fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, std::io::Error> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { pending.push(entry.path()); }
            else { result.insert(entry.path(), std::fs::read(entry.path())?); }
        }
    }
    Ok(result)
}
fn start(p: &mut LocalRootPublisher) -> Result<HttpWireArchive, HttpArchiveError> {
    let mut archive = HttpWireArchive::new(scope(), limits())?;
    let plan = archive.prepare_bytes(wire(FIRST, 0, 10), FIRST, &mut WorkBudget::new(WORK))?;
    archive.publish(&plan, p, &NeverCancel, &mut WorkBudget::new(WORK))?;
    Ok(archive)
}
fn prepare(archive: &HttpWireArchive) -> Result<(HttpWireRecoveryKey, PreparedHttpWire<'static>), HttpArchiveError> {
    let plan = archive.prepare_bytes(wire(SECOND, archive.pin().bytes, 20), SECOND, &mut WorkBudget::new(WORK))?;
    let key = HttpWireRecoveryKey::new(scope(), archive.pin(), plan.entry.wire, plan.pin())?;
    Ok((key, plan))
}
fn stage_only(p: &mut LocalRootPublisher, plan: &PreparedHttpWire<'_>) -> Test {
    p.stage_object(plan.bytes)?;
    p.stage_object(&plan.entry.metadata()?)?;
    Ok(())
}

#[test]
fn all_native_crash_cuts_recover_from_only_the_serialized_key_and_disk() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename]
    {
        let dir = Directory::new()?;
        let mut p = dir.open()?;
        let mut archive = start(&mut p)?;
        let (key, plan) = prepare(&archive)?;
        let saved = key.to_text()?;
        let wanted = key.expected_pin();
        p.inject_crash_at(cut);
        assert!(archive.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(WORK)).is_err());
        assert_eq!(archive.pin(), key.prior_pin());
        // No live camera, archive index, prepared borrowed buffer or recovery object survives.
        drop(plan); drop(key); drop(archive); drop(p);
        let mut p = dir.open()?;
        let key = HttpWireRecoveryKey::from_text(&saved)?;
        let before = snapshot(&dir.0)?;
        let state = key.inspect(&p, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?;
        assert_eq!(state, if cut == PublishCutPoint::AfterRootRename {
            HttpWireRecoveryState::Durable
        } else { HttpWireRecoveryState::Staged });
        assert_eq!(snapshot(&dir.0)?, before, "inspection must not repair a temp");
        let receipt = key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?;
        assert_eq!(receipt.pin, wanted);
        assert_eq!(receipt.local.root, wanted.head);
        assert_eq!(receipt.local.claims.local, LocalPublicationState::Durable);
        assert_eq!(p.visible_roots().count(), 2);
        let loaded = HttpWireArchive::load(&p, scope(), wanted, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?;
        assert_eq!(loaded.read_range(&p, [0, wanted.bytes], &NeverCancel, &mut WorkBudget::new(WORK))?,
            [FIRST, SECOND].concat());
        assert_eq!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?.pin, wanted);
        assert_eq!(p.visible_roots().count(), 2, "retry cannot append another read");
        drop(loaded); drop(p);
        let mut p = dir.open()?;
        assert_eq!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?.pin, wanted);
    }
    Ok(())
}

#[test]
fn the_first_read_is_recoverable_without_inventing_a_predecessor() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = HttpWireArchive::new(scope(), limits())?;
    let plan = archive.prepare_bytes(wire(FIRST, 0, 0), FIRST, &mut WorkBudget::new(WORK))?;
    let key = HttpWireRecoveryKey::new(scope(), archive.pin(), plan.entry.wire, plan.pin())?;
    stage_only(&mut p, &plan)?;
    drop(plan); drop(archive); drop(p);
    let mut p = dir.open()?;
    assert_eq!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?.pin.reads, 1);
    Ok(())
}

#[test]
fn missing_read_metadata_is_not_manufactured_from_the_key() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    p.stage_object(plan.bytes)?;
    let before = snapshot(&dir.0)?;
    assert_eq!(key.inspect(&p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Storage));
    assert!(matches!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Storage)));
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn missing_original_bytes_cannot_be_recreated_or_reacquired() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    p.stage_object(&plan.entry.metadata()?)?;
    let before = snapshot(&dir.0)?;
    assert!(matches!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Storage)));
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn another_root_in_the_pending_slot_is_never_overwritten() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let mut archive = start(&mut p)?;
    let (key, intended) = prepare(&archive)?;
    stage_only(&mut p, &intended)?;
    let other = b"different original second read";
    let plan = archive.prepare_bytes(wire(other, archive.pin().bytes, 21), other, &mut WorkBudget::new(WORK))?;
    archive.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(WORK))?;
    let before = snapshot(&dir.0)?;
    assert!(matches!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Sequence)));
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn later_source_history_is_not_silently_followed_or_discarded() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let mut archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    archive.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(WORK))?;
    let plan = archive.prepare_bytes(wire(FIRST, archive.pin().bytes, 30), FIRST, &mut WorkBudget::new(WORK))?;
    archive.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(WORK))?;
    let before = snapshot(&dir.0)?;
    assert!(matches!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Sequence)));
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn missing_predecessor_fails_even_when_the_pending_bytes_are_present() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    stage_only(&mut p, &plan)?;
    let slot = archive.slot(1)?;
    drop(p);
    std::fs::remove_file(dir.0.join("roots").join(format!("{slot}.root")))?;
    let mut p = dir.open()?;
    let before = snapshot(&dir.0)?;
    assert!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)).is_err());
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn corrupt_predecessor_source_is_not_trusted_from_a_cached_root() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    stage_only(&mut p, &plan)?;
    let digest = ContentDigest::sha256(FIRST);
    let name: String = digest.bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    let path = p.root_dir().join("spool/objects").join(name);
    std::fs::write(path, b"corrupt")?;
    let before = snapshot(&dir.0)?;
    assert!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)).is_err());
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}
#[test]
fn cancellation_work_exhaustion_and_limits_refuse_before_writing() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    stage_only(&mut p, &plan)?;
    let before = snapshot(&dir.0)?;
    assert!(matches!(key.recover(&mut p, limits(), &Cancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Cancelled)));
    assert!(matches!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(0)), Err(HttpArchiveError::Work(_))));
    let low = HttpArchiveLimits { maximum_reads: 1, ..limits() };
    assert!(matches!(key.recover(&mut p, low, &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Limit)));
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn changed_or_foreign_temp_is_preserved_on_refusal() -> Test {
    for foreign in [false, true] {
        let dir = Directory::new()?;
        let mut p = dir.open()?;
        let mut archive = start(&mut p)?;
        let (key, plan) = prepare(&archive)?;
        p.inject_crash_at(PublishCutPoint::AfterRootTempWrite);
        assert!(archive.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(WORK)).is_err());
        let own = dir.0.join(LocalRootPublisher::root_temp_path(plan.slot()));
        drop(plan); drop(archive); drop(p);
        if foreign {
            let parent = own.parent().ok_or("temp parent")?;
            let name = own.file_name().and_then(|s| s.to_str()).ok_or("temp name")?;
            std::fs::rename(&own, parent.join(name.replace("00000002", "00000003")))?;
        } else { std::fs::write(&own, b"foreign partial publication")?; }
        let mut p = dir.open()?;
        let before = snapshot(&dir.0)?;
        assert!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)).is_err());
        assert_eq!(snapshot(&dir.0)?, before);
    }
    Ok(())
}

#[test]
fn keys_round_trip_and_reject_unbound_or_noncanonical_changes() -> Test {
    let archive = HttpWireArchive::new(scope(), limits())?;
    let (key, _) = prepare(&archive)?;
    assert_eq!(HttpWireRecoveryKey::from_bytes(&key.to_bytes()?)?, key);
    assert_eq!(HttpWireRecoveryKey::from_text(&key.to_text()?)?, key);
    let mut changed = key.wire(); changed.admitted_ns += 1;
    assert!(HttpWireRecoveryKey::new(scope(), key.prior_pin(), changed, key.expected_pin()).is_err());
    let mut other = scope(); other.receive_clock[0] ^= 1;
    assert!(HttpWireRecoveryKey::new(other, key.prior_pin(), key.wire(), key.expected_pin()).is_err());
    let mut bytes = key.to_bytes()?; bytes.push(0);
    assert!(HttpWireRecoveryKey::from_bytes(&bytes).is_err());
    for text in ["hex:", "hex:0", "hex:GG", "HEX:00", "hex:00 "] {
        assert!(HttpWireRecoveryKey::from_text(text).is_err());
    }
    assert!(HttpWireRecoveryKey::from_text(&key.to_text()?.to_uppercase()).is_err());
    assert!(HttpWireRecoveryKey::from_text(&format!("hex:{}", "0".repeat(MAX_HTTP_WIRE_RECOVERY_KEY_BYTES * 2 + 2))).is_err());
    Ok(())
}

#[test]
fn hostile_maximum_ordinal_is_a_refusal_not_integer_overflow() -> Test {
    let archive = HttpWireArchive::new(scope(), limits())?;
    let (mut key, _) = prepare(&archive)?;
    key.entry.prior.reads = u64::MAX;
    let bytes = key.to_bytes()?;
    assert!(HttpWireRecoveryKey::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn exact_staged_manifest_and_recovery_work_boundary_are_supported() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    stage_only(&mut p, &plan)?;
    p.stage_manifest(plan.slot(), &plan.manifest)?;
    let mut budget = WorkBudget::new(WORK);
    assert_eq!(key.inspect(&p, limits(), &NeverCancel, &mut budget)?, HttpWireRecoveryState::Staged);
    let cost = budget.used();
    let before = snapshot(&dir.0)?;
    assert!(key.inspect(&p, limits(), &NeverCancel, &mut WorkBudget::new(cost - 1)).is_err());
    let mut exact = WorkBudget::new(cost);
    key.inspect(&p, limits(), &NeverCancel, &mut exact)?;
    assert_eq!(exact.remaining(), 0);
    assert_eq!(snapshot(&dir.0)?, before);
    assert_eq!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK))?.pin, key.expected_pin());
    Ok(())
}

#[test]
fn a_broken_pending_root_is_not_an_empty_namespace() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let (key, plan) = prepare(&archive)?;
    stage_only(&mut p, &plan)?;
    let target = dir.0.join("roots").join(format!("{}.root", plan.slot()));
    drop(p);
    std::fs::write(&target, b"unresolved original publication")?;
    let mut p = dir.open()?;
    let before = snapshot(&dir.0)?;
    assert!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)).is_err());
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}

#[test]
fn a_saved_key_cannot_lower_receive_admission_below_its_verified_predecessor() -> Test {
    let dir = Directory::new()?;
    let mut p = dir.open()?;
    let archive = start(&mut p)?;
    let mut entry = Entry {
        prior: archive.pin(), wire: wire(SECOND, archive.pin().bytes, 9), root: archive.pin().head,
    };
    entry.root = entry.manifest()?.root();
    let key = HttpWireRecoveryKey::new(scope(), entry.prior, entry.wire, entry.pin())?;
    p.stage_object(SECOND)?;
    p.stage_object(&entry.metadata()?)?;
    let before = snapshot(&dir.0)?;
    assert!(matches!(key.recover(&mut p, limits(), &NeverCancel, &mut WorkBudget::new(WORK)), Err(HttpArchiveError::Sequence)));
    assert_eq!(snapshot(&dir.0)?, before);
    Ok(())
}
