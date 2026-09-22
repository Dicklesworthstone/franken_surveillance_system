#![forbid(unsafe_code)]
//! Real filesystem custody; historical selection never becomes a writable short history.
use super::*;
use fss_object::SpoolLimits;
use fss_packet::StreamKey;
use fss_publication::{LocalPublicationLimits, NeverCancel};
use crate::rtsp::tcp::TcpSecurityPolicy;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type Test = std::result::Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fss-datagram-prefix-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
    fn open(&self) -> std::result::Result<LocalRootPublisher, Box<dyn std::error::Error>> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(128, 16, 128, 1024,
            SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024)))?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn scope() -> std::result::Result<DatagramScope, Box<dyn std::error::Error>> {
    Ok(DatagramScope {
        binding: TcpBinding::new(StreamKey { ingress: 410, generation: 1, ssrc: 7 },
            "127.0.0.1:554".parse()?, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?,
        channels: (0, 1), receive_clock: ContentDigest::sha256(b"prefix clock"),
        retention_evidence: ContentDigest::sha256(b"prefix owner retention"),
    })
}
fn limits() -> DatagramArchiveLimits {
    DatagramArchiveLimits { max_datagrams: 32, max_payload_bytes: 1_048_576,
        max_scan_roots: 1024, max_spool_object_bytes: 65536 }
}
fn work() -> WorkBudget<'static> { WorkBudget::new(1_000_000_000) }
fn append(a: &mut DatagramArchive, p: &mut LocalRootPublisher, bytes: &[u8]) -> Result<DatagramPin> {
    let plan = a.prepare_bytes(0, a.pin().datagrams + 10, bytes, &mut work())?;
    Ok(a.publish(&plan, p, &NeverCancel, &mut work())?.record.pin)
}
fn load(p: &LocalRootPublisher, selected: DatagramPin) -> std::result::Result<DatagramPrefix, Box<dyn std::error::Error>> {
    Ok(DatagramPrefix::recover(p, scope()?, limits(), selected, &NeverCancel, &mut work())?)
}

#[test]
fn cold_selection_preserves_old_input_and_reports_the_distinct_verified_head() -> Test {
    let d = Directory::new();
    let (selected, head) = {
        let mut p = d.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
        let selected = append(&mut a, &mut p, b"first original")?;
        let head = append(&mut a, &mut p, b"later original")?;
        (selected, head)
    };
    let p = d.open()?; let prefix = load(&p, selected)?;
    assert_eq!(prefix.pin(), selected); assert_eq!(prefix.observed_head(), head);
    assert_eq!(prefix.archive().records().len(), 1);
    assert_eq!(prefix.read(1, &p, &NeverCancel, &mut work())?.payload(), b"first original");
    assert!(prefix.read(2, &p, &NeverCancel, &mut work()).is_err());
    assert_eq!(prefix.revalidate(&p, &NeverCancel, &mut work())?, head);
    assert_eq!(p.visible_roots().count(), 2);
    Ok(())
}

#[test]
fn selecting_empty_prefix_does_not_claim_the_source_namespace_is_empty() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?; let empty = a.pin();
    let head = append(&mut a, &mut p, b"retained outside selection")?;
    let prefix = load(&p, empty)?;
    assert_eq!(prefix.pin(), empty); assert_eq!(prefix.observed_head(), head);
    assert!(prefix.archive().records().is_empty());
    let mut replay = DatagramReplay::new(prefix.archive(), &p, 0, 0, 100)?;
    assert!(matches!(replay.step(1, &NeverCancel, &mut work())?,
        DatagramReplayStep::PrefixExhausted(pin) if pin == empty));
    assert!(prefix.read(1, &p, &NeverCancel, &mut work()).is_err());
    Ok(())
}

#[test]
fn separate_capture_owner_keeps_appending_without_moving_historical_selection() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    let selected = append(&mut a, &mut p, b"one")?;
    let observed = append(&mut a, &mut p, b"two")?;
    let prefix = load(&p, selected)?;
    let next = append(&mut a, &mut p, b"three")?;
    assert_eq!(a.pin(), next); assert_eq!(prefix.pin(), selected);
    assert_eq!(prefix.observed_head(), observed);
    assert_eq!(prefix.revalidate(&p, &NeverCancel, &mut work())?, next);
    assert_eq!(prefix.pin(), selected); assert_eq!(prefix.observed_head(), observed);
    assert_eq!(DatagramArchive::recover(&p, scope()?, limits(), Some(next), &NeverCancel, &mut work())?.pin(), next);
    Ok(())
}

#[test]
fn every_prefix_pin_field_must_match_an_actual_position() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    let selected = append(&mut a, &mut p, b"one")?; append(&mut a, &mut p, b"two")?;
    for wrong in [DatagramPin { head: ContentDigest::sha256(b"forged"), ..selected },
        DatagramPin { scope: ContentDigest::sha256(b"other scope"), ..selected },
        DatagramPin { datagrams: 2, ..selected }, DatagramPin { payload_bytes: 4, ..selected },
        DatagramPin { datagrams: 0, ..selected }, DatagramPin { datagrams: u64::MAX, ..selected }] {
        assert!(load(&p, wrong).is_err());
        assert_eq!(p.visible_roots().count(), 2);
    }
    Ok(())
}

#[test]
fn an_unselected_corrupt_descendant_is_not_silently_skipped_during_recovery() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    let selected = append(&mut a, &mut p, b"one")?;
    append(&mut a, &mut p, b"corruption target")?;
    let digest = ContentDigest::sha256(b"corruption target").to_text();
    let hex = digest.strip_prefix("sha256:").ok_or("digest algorithm")?;
    std::fs::write(p.root_dir().join("spool/objects").join(hex), b"broken envelope")?;
    assert!(load(&p, selected).is_err());
    Ok(())
}

#[test]
fn missing_selected_root_and_missing_intermediate_descendant_both_refuse() -> Test {
    for ordinal in [1, 2] {
        let d = Directory::new(); let mut p = d.open()?;
        let mut a = DatagramArchive::new(scope()?, limits())?;
        let selected = append(&mut a, &mut p, b"one")?;
        append(&mut a, &mut p, b"two")?; append(&mut a, &mut p, b"three")?;
        let root_file = p.root_dir().join("roots").join(format!("{}.root", a.slot(ordinal)?));
        drop(p); std::fs::remove_file(root_file)?;
        let p = d.open()?;
        assert!(load(&p, selected).is_err());
    }
    Ok(())
}

#[test]
fn same_attempt_revalidation_rejects_rollback_above_the_selected_prefix() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    let selected = append(&mut a, &mut p, b"one")?;
    append(&mut a, &mut p, b"two")?; let prefix = load(&p, selected)?;
    let root_file = p.root_dir().join("roots").join(format!("{}.root", a.slot(2)?));
    drop(p); std::fs::remove_file(root_file)?;
    let p = d.open()?;
    assert!(prefix.revalidate(&p, &NeverCancel, &mut work()).is_err());
    // The old independent pin alone cannot prove that a now absent later record existed.
    assert_eq!(load(&p, selected)?.observed_head(), selected);
    Ok(())
}

#[test]
fn all_uncertain_descendant_write_cuts_keep_ordinary_recovery_semantics() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename] {
        let d = Directory::new(); let mut p = d.open()?;
        let mut a = DatagramArchive::new(scope()?, limits())?;
        let selected = append(&mut a, &mut p, b"one")?;
        let plan = a.prepare_bytes(0, 20, b"next", &mut work())?; let candidate = plan.pin();
        p.inject_crash_at(cut);
        assert!(a.publish(&plan, &mut p, &NeverCancel, &mut work()).is_err());
        assert!(load(&p, selected).is_err()); drop(p);
        let p = d.open()?;
        let recovered = load(&p, selected);
        if cut == PublishCutPoint::AfterRootTempWrite {
            assert!(recovered.is_err());
        } else {
            let prefix = recovered?;
            assert_eq!(prefix.pin(), selected);
            assert_eq!(prefix.observed_head(), if cut == PublishCutPoint::AfterRootRename { candidate } else { selected });
        }
    }
    Ok(())
}

#[test]
fn independent_limits_cover_full_current_chain_not_just_selected_records() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    let selected = append(&mut a, &mut p, b"one")?; append(&mut a, &mut p, b"two")?;
    for ceiling in [DatagramArchiveLimits { max_datagrams: 1, ..limits() },
        DatagramArchiveLimits { max_payload_bytes: 3, ..limits() },
        DatagramArchiveLimits { max_scan_roots: 1, ..limits() },
        DatagramArchiveLimits { max_spool_object_bytes: 1024, ..limits() }] {
        assert!(DatagramPrefix::recover(&p, scope()?, ceiling, selected, &NeverCancel, &mut work()).is_err());
    }
    assert_eq!(a.pin().datagrams, 2);
    Ok(())
}

struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}
#[test]
fn cancellation_and_work_refusal_do_not_mutate_the_source_owner_or_storage() -> Test {
    let d = Directory::new(); let mut p = d.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    let selected = append(&mut a, &mut p, b"one")?; let head = append(&mut a, &mut p, b"two")?;
    assert!(DatagramPrefix::recover(&p, scope()?, limits(), selected, &Stop, &mut work()).is_err());
    assert!(DatagramPrefix::recover(&p, scope()?, limits(), selected, &NeverCancel, &mut WorkBudget::new(0)).is_err());
    let prefix = load(&p, selected)?;
    assert!(prefix.revalidate(&p, &Stop, &mut work()).is_err());
    assert_eq!(prefix.observed_head(), head); assert_eq!(a.pin(), head);
    assert_eq!(p.visible_roots().count(), 2);
    Ok(())
}
