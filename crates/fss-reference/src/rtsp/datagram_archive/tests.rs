#![forbid(unsafe_code)]
//! Actual source objects/root-last publication; failures never become synthetic EOF.
use super::*;
use fss_object::SpoolLimits;
use fss_packet::StreamKey;
use fss_publication::{LocalPublicationLimits, NeverCancel, PublishOutcome};
use crate::rtsp::tcp::TcpSecurityPolicy;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let path = std::env::temp_dir().join(format!("fss-datagrams-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory bound".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(128, 8, 128, 512,
            SpoolLimits::new(512, 8 * 1024 * 1024, 65_536, 512)))?)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn scope() -> Test<DatagramScope> {
    Ok(DatagramScope {
        binding: TcpBinding::new(StreamKey { ingress: 51, generation: 3, ssrc: 7 },
            "127.0.0.1:554".parse()?, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?,
        channels: (0, 1), receive_clock: ContentDigest::sha256(b"receive epoch"),
        retention_evidence: ContentDigest::sha256(b"authorized media and RTCP custody"),
    })
}
fn limits() -> DatagramArchiveLimits {
    DatagramArchiveLimits { max_datagrams: 16, max_payload_bytes: 1024 * 1024,
        max_scan_roots: 512, max_spool_object_bytes: 65_536 }
}
fn work() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }
fn add(a: &mut DatagramArchive, p: &mut LocalRootPublisher, channel: u8, time: u64, bytes: &[u8]) -> Test<DatagramPublication> {
    let plan = a.prepare_bytes(channel, time, bytes, &mut work())?;
    Ok(a.publish(&plan, p, &NeverCancel, &mut work())?)
}
struct Cancel;
impl PublishCancellation for Cancel { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }

#[test]
fn cold_recovery_replays_order_channel_time_and_original_bytes_not_codec_eof() -> Test {
    let dir = Directory::new()?;
    let original: &[(u8, u64, &[u8])] = &[(0, 10, b"original RTP padding\0"), (1, 10, b"RTCP"), (0, 11, b"incomplete FU-A")];
    let pin = {
        let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
        for &(channel, time, bytes) in original { add(&mut a, &mut p, channel, time, bytes)?; }
        a.pin()
    };
    let p = dir.open()?;
    let a = DatagramArchive::recover(&p, scope()?, limits(), Some(pin), &NeverCancel, &mut work())?;
    let mut replay = DatagramReplay::new(&a, &p, pin.payload_bytes, 0, 100)?;
    for &(channel, time, bytes) in original {
        let DatagramReplayStep::Datagram(d) = replay.step(1, &NeverCancel, &mut work())? else { return Err("premature exhaustion".into()); };
        assert_eq!(d.payload(), bytes); assert_eq!((d.record().channel, d.record().received_ns), (channel, time));
    }
    assert!(matches!(replay.step(2, &NeverCancel, &mut work())?, DatagramReplayStep::PrefixExhausted(p) if p == pin));
    assert!(matches!(replay.step(3, &NeverCancel, &mut work())?, DatagramReplayStep::Ended));
    Ok(())
}
#[test]
fn equal_retransmissions_are_distinct_but_same_prepared_publication_is_idempotent() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    let first = a.prepare_bytes(0, 10, b"same packet", &mut work())?;
    let one = a.publish(&first, &mut p, &NeverCancel, &mut work())?;
    assert_eq!(a.publish(&first, &mut p, &NeverCancel, &mut work())?.local.outcome, PublishOutcome::AlreadyPublished);
    let two = add(&mut a, &mut p, 0, 10, b"same packet")?;
    assert_eq!(one.record.payload_digest, two.record.payload_digest);
    assert_ne!(one.record.pin.head, two.record.pin.head);
    assert_eq!(two.record.pin.datagrams, 2); assert_eq!(two.record.pin.payload_bytes, 22);
    assert!(a.publish(&first, &mut p, &NeverCancel, &mut work()).is_err());
    assert_eq!(p.visible_roots().count(), 2); Ok(())
}
#[test]
fn zero_length_and_malformed_datagrams_remain_bounded_evidence() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    add(&mut a, &mut p, 0, 0, b"")?; add(&mut a, &mut p, 1, 0, b"\xffnot RTCP")?;
    assert_eq!(a.read(1, &p, &NeverCancel, &mut work())?.payload(), b"");
    let recovered = DatagramArchive::recover(&p, scope()?, limits(), Some(a.pin()), &NeverCancel, &mut work())?;
    assert_eq!(recovered.records().len(), 2); Ok(())
}
#[test]
fn all_root_failure_cuts_preserve_original_plan_and_never_advance_on_error() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename] {
        let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
        let before = a.pin(); let plan = a.prepare_bytes(0, 10, b"unsealed picture source", &mut work())?;
        p.inject_crash_at(cut);
        assert!(matches!(a.publish(&plan, &mut p, &NeverCancel, &mut work()), Err(DatagramArchiveError::Publication(_))));
        assert_eq!(a.pin(), before); assert_eq!(plan.bytes, b"unsealed picture source");
        assert!(p.is_poisoned()); drop(p);
        let p = dir.open()?;
        let result = DatagramArchive::recover(&p, scope()?, limits(), Some(plan.pin()), &NeverCancel, &mut work());
        if cut == PublishCutPoint::AfterRootRename { assert_eq!(result?.pin(), plan.pin()); }
        else { assert!(result.is_err()); }
    }
    Ok(())
}
#[test]
fn stale_owner_can_reconcile_only_its_exact_last_publication() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?;
    let mut a = DatagramArchive::new(scope()?, limits())?; let mut stale = DatagramArchive::new(scope()?, limits())?;
    let plan = a.prepare_bytes(0, 1, b"source", &mut work())?;
    a.publish(&plan, &mut p, &NeverCancel, &mut work())?;
    assert_eq!(stale.publish(&plan, &mut p, &NeverCancel, &mut work())?.local.outcome, PublishOutcome::AlreadyPublished);
    let different = DatagramArchive::new(scope()?, limits())?.prepare_bytes(0, 1, b"other", &mut work())?;
    assert!(stale.publish(&different, &mut p, &NeverCancel, &mut work()).is_err());
    assert_eq!(p.visible_roots().count(), 1); Ok(())
}
#[test]
fn minimum_prefix_allows_verified_descendants_but_rejects_rollback_or_forks() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    let first = add(&mut a, &mut p, 0, 1, b"one")?.record.pin;
    let last = add(&mut a, &mut p, 0, 2, b"two")?.record.pin;
    assert_eq!(DatagramArchive::recover(&p, scope()?, limits(), Some(first), &NeverCancel, &mut work())?.pin(), last);
    for pin in [DatagramPin { head: ContentDigest::sha256(b"fork"), ..first },
        DatagramPin { datagrams: 3, ..last }, DatagramPin { payload_bytes: 99, ..first }] {
        assert!(DatagramArchive::recover(&p, scope()?, limits(), Some(pin), &NeverCancel, &mut work()).is_err());
    }
    let last_path = p.root_dir().join("roots").join(format!("{}.root", a.slot(2)?));
    drop(p); std::fs::remove_file(last_path)?;
    let p = dir.open()?;
    assert!(DatagramArchive::recover(&p, scope()?, limits(), Some(last), &NeverCancel, &mut work()).is_err());
    Ok(())
}
#[test]
fn missing_intermediate_root_never_becomes_a_shorter_valid_prefix() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    add(&mut a, &mut p, 0, 1, b"one")?; add(&mut a, &mut p, 0, 2, b"two")?;
    let path = p.root_dir().join("roots").join(format!("{}.root", a.slot(1)?));
    drop(p); std::fs::remove_file(path)?;
    let p = dir.open()?;
    assert!(DatagramArchive::recover(&p, scope()?, limits(), None, &NeverCancel, &mut work()).is_err()); Ok(())
}
#[test]
fn scope_changes_cannot_escape_an_occupied_connection_namespace() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    add(&mut a, &mut p, 0, 1, b"source")?;
    let mut route = scope()?;
    route.binding = TcpBinding::new(route.binding.key(), "127.0.0.1:8554".parse()?, "other.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
    for changed in [DatagramScope { receive_clock: ContentDigest::sha256(b"other clock"), ..scope()? },
        DatagramScope { retention_evidence: ContentDigest::sha256(b"other policy"), ..scope()? },
        DatagramScope { channels: (2, 3), ..scope()? }, route] {
        assert!(DatagramArchive::recover(&p, changed.clone(), limits(), None, &NeverCancel, &mut work()).is_err());
        let mut other = DatagramArchive::new(changed, limits())?;
        let plan = other.prepare_bytes(other.scope.channels.0, 1, b"source", &mut work())?;
        assert!(other.publish(&plan, &mut p, &NeverCancel, &mut work()).is_err());
    }
    Ok(())
}
#[test]
fn cancellation_work_and_input_refusals_do_not_publish_or_mutate_source() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    let before = a.pin(); let bytes = b"source";
    let plan = a.prepare_bytes(0, 10, bytes, &mut work())?;
    assert!(matches!(a.publish(&plan, &mut p, &Cancel, &mut work()), Err(DatagramArchiveError::Cancelled)));
    for budget in [0, 1, 1024, 4095] {
        assert!(a.publish(&plan, &mut p, &NeverCancel, &mut WorkBudget::new(budget)).is_err());
        assert_eq!(a.pin(), before); assert_eq!(p.visible_roots().count(), 0);
    }
    assert!(a.prepare_bytes(2, 10, bytes, &mut work()).is_err());
    a.publish(&plan, &mut p, &NeverCancel, &mut work())?;
    assert!(a.prepare_bytes(0, 9, bytes, &mut work()).is_err());
    assert_eq!(plan.bytes, bytes); Ok(())
}
#[test]
fn all_external_prefix_and_preallocation_limits_are_enforced() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    add(&mut a, &mut p, 0, 1, b"one")?; add(&mut a, &mut p, 1, 2, b"two")?;
    for bound in [DatagramArchiveLimits { max_datagrams: 1, ..limits() },
        DatagramArchiveLimits { max_payload_bytes: 5, ..limits() },
        DatagramArchiveLimits { max_scan_roots: 1, ..limits() },
        DatagramArchiveLimits { max_spool_object_bytes: 1024, ..limits() }] {
        assert!(DatagramArchive::recover(&p, scope()?, bound, None, &NeverCancel, &mut work()).is_err());
    }
    assert!(DatagramReplay::new(&a, &p, 5, 0, 10).is_err());
    assert!(a.read(0, &p, &NeverCancel, &mut work()).is_err());
    assert!(a.read(3, &p, &NeverCancel, &mut work()).is_err()); Ok(())
}
#[test]
fn source_corruption_stops_warm_replay_and_cold_recovery() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    let record = add(&mut a, &mut p, 0, 1, b"original")?.record;
    let text = record.payload_digest.to_text();
    std::fs::write(p.root_dir().join("spool/objects").join(text.strip_prefix("sha256:").ok_or("digest")?), b"corrupt!")?;
    let mut replay = DatagramReplay::new(&a, &p, 8, 0, 100)?;
    assert!(replay.step(1, &NeverCancel, &mut work()).is_err());
    assert!(replay.step(2, &NeverCancel, &mut work()).is_err());
    drop(replay); drop(p);
    let p = dir.open()?;
    assert!(DatagramArchive::recover(&p, scope()?, limits(), None, &NeverCancel, &mut work()).is_err()); Ok(())
}
#[test]
fn foreign_families_extra_children_and_noncanonical_source_metadata_are_refused() -> Test {
    for extra in [false, true] {
        let dir = Directory::new()?; let mut p = dir.open()?; let a = DatagramArchive::new(scope()?, limits())?;
        let plan = a.prepare_bytes(0, 1, b"source", &mut work())?;
        let payload = p.stage_object(plan.bytes)?; let metadata = p.stage_object(&plan.metadata)?;
        let children = if extra { vec![payload, p.stage_object(b"extra")?] } else { vec![payload] };
        let manifest = ObjectManifest::new(if extra { RTSP_DATAGRAM_KIND } else { "not_datagram" }, children, Some(metadata))?;
        p.publish(plan.slot(), &manifest)?;
        assert!(DatagramArchive::recover(&p, scope()?, limits(), None, &NeverCancel, &mut work()).is_err());
        for end in 0..plan.metadata.len() { assert!(DatagramRecord::decode(&plan.metadata[..end], plan.pin().head).is_err()); }
        let mut suffix = plan.metadata.clone(); suffix.push(0);
        assert!(DatagramRecord::decode(&suffix, plan.pin().head).is_err());
    }
    Ok(())
}
