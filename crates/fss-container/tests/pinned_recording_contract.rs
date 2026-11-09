#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Actual storage/custody and AVC/HEVC recording modules under their native component closure.
//!
//! These source inclusions execute the production contracts, filesystem spool, root-last
//! publisher, exact-pin reader and source replay without compiling unrelated object uploaders.
//! No storage, custody, codec or authority implementation is substituted. This is component
//! evidence; ReferenceDeployment, asynchronous runtime and CLI integration are not exercised.

extern crate self as fss_object;
extern crate self as fss_publication;

#[path = "../../fss-object/src/contracts.rs"]
mod object_contracts;
#[path = "../../fss-object/src/error.rs"]
mod object_error;
#[path = "../../fss-object/src/manifest.rs"]
mod object_manifest;
#[path = "../../fss-object/src/spool/mod.rs"]
mod spool;
pub use object_contracts::*;
pub use object_error::ObjectError;
pub use object_manifest::ObjectManifest;
pub use spool::*;

#[path = "../../fss-publication/src/custody_audit.rs"]
pub mod custody_audit;
#[path = "../../fss-publication/src/ledger.rs"]
mod ledger;
#[path = "../../fss-publication/src/local/mod.rs"]
mod local;
#[path = "../../fss-publication/src/error.rs"]
mod publication_error;
#[path = "../../fss-publication/src/publisher.rs"]
mod publisher;
pub use ledger::*;
pub use local::{
    BlockReason, BrokenRoot, BrokenRootReason, CapacityResource, ClaimStatus, HostLockTableSource,
    InjectedIoFault, IoFaultPoint, LOCAL_LOCK_FILE, LOCAL_PUBLICATION_ERROR_CODES,
    LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR,
    LOCAL_TOMBSTONE_RECORD_DOMAIN, LOCAL_TOMBSTONES_DIR, LocalInspection, LocalIoOperation,
    LocalLimitViolation, LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits,
    LocalPublicationReceipt, LocalPublicationState, LocalRecoveryReport, LocalRootPublisher,
    LockTableSource, MAX_LOCAL_ROOTS, MAX_LOCAL_TOMBSTONES, MAX_LOCK_TABLE_BYTES,
    MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES, MAX_TOMBSTONE_RECORD_BYTES, NeverCancel,
    PublicationClaims, PublicationTransition, PublishCancellation, PublishCutPoint, PublishOutcome,
    ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ReferenceRole,
    ScopedPublicationIo, SlotName, SlotViolation, StringLockTableSource, TOMBSTONE_RECORD_SUFFIX,
    TombstoneOutcome, UnknownLockReason, VisibleRoot, WriterDetectionOptions, WriterLockBasis,
    WriterState, read_verified, read_verified_with_io, root_record_bytes, tombstone_record_bytes,
};
pub use publication_error::PublicationError;
pub use publisher::AuthorityPublisher;

#[path = "../../fss-reference/src/rtsp/recording.rs"]
mod recording;
mod rtsp_movie_support;

#[path = "../../fss-publication/tests/pinned_closure_contract.rs"]
mod closure_contract;
#[path = "../../fss-publication/tests/pinned_metadata_contract.rs"]
mod metadata_regression;
#[path = "../../fss-publication/tests/pinned_namespace_contract.rs"]
mod namespace_regression;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use custody_audit::CustodyAuditLimits;
use custody_audit::pinned_closure::PinnedClosureReader;
use fss_core::{ContentDigest, SensorId, StreamId};
use recording::hevc::local::load_pinned_hevc_recording;
use recording::hevc::{HevcRecordingTiming, PreparedHevcRecording, prepare_hevc_recording};
use recording::local::{RecordingIoError, RecordingProgress, RecordingPublication};
use recording::pinned::load_pinned_recording;
use recording::{PreparedRecording, RecordingPacket, RecordingScope, prepare_recording};
use rtsp_movie_support::{KEY, SCALE, Test};

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn running() -> bool {
    false
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        let path = std::env::temp_dir().join(format!(
            "fss-native-pinned-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn scope() -> Test<RecordingScope> {
    Ok(RecordingScope {
        sensor: SensorId::parse("sensor:pinned-native")?,
        stream: StreamId::parse("stream:pinned-native")?,
        generation: KEY.generation,
        anchor: ContentDigest::sha256(b"explicit fixture authority"),
        receive_clock: ContentDigest::sha256(b"independent monotonic clock"),
    })
}
fn avc(ordinal: usize) -> Test<PreparedRecording> {
    let source = rtsp_movie_support::avc_window(ordinal)?;
    let packets: Vec<_> = source
        .packets
        .iter()
        .map(|p| RecordingPacket {
            sequence: p.sequence,
            received_ns: p.received_ns,
            bytes: &p.bytes,
        })
        .collect();
    Ok(prepare_recording(
        scope()?,
        SCALE,
        &rtsp_movie_support::avc_timing(&source.pictures),
        &packets,
    )?)
}
fn hevc() -> Test<PreparedHevcRecording> {
    let source = rtsp_movie_support::hevc()?;
    let packets: Vec<_> = source
        .packets
        .iter()
        .map(|p| RecordingPacket {
            sequence: p.sequence,
            received_ns: p.received_ns,
            bytes: &p.bytes,
        })
        .collect();
    let timings: Vec<_> = rtsp_movie_support::hevc_timing(&source.pictures)
        .iter()
        .map(|p| HevcRecordingTiming {
            decode_time: p.decode_time,
            duration: p.duration,
            composition_offset: p.composition_offset,
        })
        .collect();
    Ok(prepare_hevc_recording(
        scope()?,
        &source.configuration,
        SCALE,
        &timings,
        &packets,
    )?)
}
fn publisher(directory: &Directory) -> Test<LocalRootPublisher> {
    Ok(LocalRootPublisher::open(
        &directory.0,
        LocalPublicationLimits::new(
            16,
            16,
            16,
            128,
            SpoolLimits::new(128, 64 * 1024 * 1024, recording::MAX_RECORDING_BYTES, 128),
        ),
    )?)
}
fn publish(
    publisher: &mut LocalRootPublisher,
    plan: &PreparedRecording,
    name: &str,
) -> Test<SlotName> {
    let slot = SlotName::parse(name)?;
    let mut cursor =
        RecordingPublication::new(plan, publisher, slot.clone(), plan.byte_len(), 1_000_000)?;
    loop {
        match cursor.step(1, &NeverCancel)? {
            RecordingProgress::Published(receipt) => {
                assert_eq!(receipt.root, plan.manifest().root());
                assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
                break;
            }
            RecordingProgress::ChildStaged { .. } => {}
            RecordingProgress::Complete => {
                return Err("publication completed without receipt".into());
            }
        }
    }
    Ok(slot)
}
fn read_limits(windows: usize) -> CustodyAuditLimits {
    CustodyAuditLimits {
        max_catalogue_entries: windows,
        max_objects: windows * 5,
        max_edges: windows * 4,
        max_object_bytes: recording::MAX_RECORDING_BYTES,
        max_read_bytes: 128 * 1024 * 1024,
        max_io_calls: 1024 * windows as u64 + 16,
    }
}
fn same(a: &PreparedRecording, b: &PreparedRecording) {
    assert_eq!(a.manifest(), b.manifest());
    assert_eq!(a.summary(), b.summary());
    for (left, right) in a.children().iter().zip(b.children()) {
        assert_eq!(left, &right);
    }
}

#[test]
fn native_avc_and_hevc_replay_match_writer_loader_while_archive_writer_lock_is_held() -> Test {
    let dir = Directory::new()?;
    let a = avc(0)?;
    let h = hevc()?;
    let mut owner = publisher(&dir)?;
    let a_slot = publish(&mut owner, &a, "avc")?;
    let h_slot = publish(&mut owner, h.publication_plan(), "hevc")?;
    let oracle_a = recording::local::load_recording(
        &owner,
        &a_slot,
        a.manifest().root(),
        &scope()?,
        &NeverCancel,
    )?;
    let oracle_h = recording::hevc::local::load_hevc_recording(
        &owner,
        &h_slot,
        h.manifest().root(),
        &scope()?,
        &NeverCancel,
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &dir.0, read_limits(2), &running)?;
    let actual_a = load_pinned_recording(
        &mut reader,
        &a_slot,
        a.manifest().root(),
        &scope()?,
        &NeverCancel,
    )?;
    let actual_h = load_pinned_hevc_recording(
        &mut reader,
        &h_slot,
        h.manifest().root(),
        &scope()?,
        &NeverCancel,
    )?;
    same(&oracle_a, &actual_a);
    same(oracle_h.publication_plan(), actual_h.publication_plan());
    assert_eq!(oracle_h.source_only_nals(), actual_h.source_only_nals());
    assert_eq!(oracle_h.mappings(), actual_h.mappings());
    assert_eq!(oracle_h.samples(), actual_h.samples());
    let usage = reader.finish()?;
    assert_eq!(
        (usage.completed_roots, usage.objects, usage.edges),
        (2, 10, 8)
    );
    assert_eq!(usage.io_calls, io.calls().len() as u64);
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert!(io.is_read_only());
    drop(owner);
    Ok(())
}

#[test]
fn unrelated_corrupt_source_and_inflight_root_do_not_block_selected_native_retrieval() -> Test {
    let dir = Directory::new()?;
    let selected = avc(0)?;
    let unrelated = avc(1)?;
    let mut owner = publisher(&dir)?;
    let slot = publish(&mut owner, &selected, "selected")?;
    publish(&mut owner, &unrelated, "unrelated")?;
    drop(owner);
    let foreign_source = unrelated.children()[0].1;
    fs::write(
        dir.0
            .join("spool/objects")
            .join(foreign_source.to_text().trim_start_matches("sha256:")),
        b"corrupt unselected original",
    )?;
    fs::write(
        dir.0.join("roots/unrelated.root.tmp"),
        b"unrelated pending writer",
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &dir.0, read_limits(1), &running)?;
    let actual = load_pinned_recording(
        &mut reader,
        &slot,
        selected.manifest().root(),
        &scope()?,
        &NeverCancel,
    )?;
    same(&selected, &actual);
    reader.finish()?;
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    Ok(())
}

#[test]
fn wrong_codec_scope_and_selected_source_corruption_are_refused_before_returning_bytes() -> Test {
    let dir = Directory::new()?;
    let a = avc(0)?;
    let mut owner = publisher(&dir)?;
    let slot = publish(&mut owner, &a, "selected")?;
    drop(owner);
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &dir.0, read_limits(1), &running)?;
    assert!(
        load_pinned_hevc_recording(
            &mut reader,
            &slot,
            a.manifest().root(),
            &scope()?,
            &NeverCancel
        )
        .is_err()
    );
    let mut wrong_scope = scope()?;
    wrong_scope.generation += 1;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &dir.0, read_limits(1), &running)?;
    assert!(matches!(
        load_pinned_recording(
            &mut reader,
            &slot,
            a.manifest().root(),
            &wrong_scope,
            &NeverCancel
        ),
        Err(RecordingIoError::Content(recording::RecordingError::Scope))
    ));
    let source = a.children()[0].1;
    fs::write(
        dir.0
            .join("spool/objects")
            .join(source.to_text().trim_start_matches("sha256:")),
        b"bad selected source",
    )?;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &dir.0, read_limits(1), &running)?;
    assert!(matches!(
        load_pinned_recording(
            &mut reader,
            &slot,
            a.manifest().root(),
            &scope()?,
            &NeverCancel
        ),
        Err(RecordingIoError::Pinned(_))
    ));
    Ok(())
}

#[test]
fn current_native_authority_refusal_prevents_all_selected_payload_io() -> Test {
    struct Denied;
    impl PublishCancellation for Denied {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            true
        }
    }
    let dir = Directory::new()?;
    let a = avc(0)?;
    let mut owner = publisher(&dir)?;
    let slot = publish(&mut owner, &a, "selected")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &dir.0, read_limits(1), &running)?;
    assert!(matches!(
        load_pinned_recording(&mut reader, &slot, a.manifest().root(), &scope()?, &Denied),
        Err(RecordingIoError::Cancelled)
    ));
    assert_eq!(io.call_count(SpoolIoCall::OpenRead), 0);
    Ok(())
}

#[test]
fn native_cancellation_after_replay_never_releases_a_verified_recording() -> Test {
    struct CancelAfter(AtomicUsize);
    impl PublishCancellation for CancelAfter {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst) >= 10
        }
    }
    let dir = Directory::new()?;
    let a = avc(0)?;
    let mut owner = publisher(&dir)?;
    let slot = publish(&mut owner, &a, "selected")?;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &dir.0, read_limits(1), &running)?;
    assert!(matches!(
        load_pinned_recording(
            &mut reader,
            &slot,
            a.manifest().root(),
            &scope()?,
            &CancelAfter(AtomicUsize::new(0))
        ),
        Err(RecordingIoError::Cancelled)
    ));
    assert_eq!(reader.usage().completed_roots, 0);
    Ok(())
}

#[test]
fn checksummed_source_and_index_forgery_still_fails_real_native_packet_replay() -> Test {
    let dir = Directory::new()?;
    let original = avc(0)?;
    let objects = original.objects();
    let old_source = ContentDigest::sha256(objects.source);
    let mut altered_source = objects.source.to_vec();
    *altered_source.last_mut().ok_or("source packet bytes")? ^= 0x80;
    let new_source = ContentDigest::sha256(&altered_source);
    let mut index = objects.index.to_vec();
    let offsets: Vec<_> = index
        .windows(32)
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == old_source.bytes()).then_some(offset))
        .collect();
    assert_eq!(offsets.len(), 1);
    index[offsets[0]..offsets[0] + 32].copy_from_slice(&new_source.bytes());
    let mut owner = publisher(&dir)?;
    let source = owner.stage_object(&altered_source)?;
    let initialization = owner.stage_object(objects.initialization)?;
    let media = owner.stage_object(objects.media)?;
    let metadata = owner.stage_object(&index)?;
    let forged = ObjectManifest::new(
        recording::RECORDING_KIND,
        [source, initialization, media],
        Some(metadata),
    )?;
    let slot = SlotName::parse("forged-source")?;
    owner.publish(&slot, &forged)?;
    // Every envelope, root binding and reference digest verifies; media no longer matches
    // the original RTP bytes named by the index. The actual codec replay must detect that.
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &dir.0, read_limits(1), &running)?;
    assert!(matches!(
        load_pinned_recording(&mut reader, &slot, forged.root(), &scope()?, &NeverCancel),
        Err(RecordingIoError::Content(_))
    ));
    assert_eq!(reader.usage().completed_roots, 0);
    Ok(())
}

#[test]
fn dynamic_native_permission_revoked_during_final_rehash_stops_before_next_object_read() -> Test {
    struct RevokedDuringFinal<'a>(&'a RecordingSpoolIo);
    impl PublishCancellation for RevokedDuringFinal<'_> {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            // First pass: one exact root record + five object payloads. The first
            // final-pass payload opens the seventh file and revokes permission.
            self.0.call_count(SpoolIoCall::OpenRead) >= 7
        }
    }
    let dir = Directory::new()?;
    let original = avc(0)?;
    let mut owner = publisher(&dir)?;
    let slot = publish(&mut owner, &original, "selected")?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &dir.0, read_limits(1), &running)?;
    assert!(
        load_pinned_recording(
            &mut reader,
            &slot,
            original.manifest().root(),
            &scope()?,
            &RevokedDuringFinal(&io)
        )
        .is_err()
    );
    assert_eq!(io.call_count(SpoolIoCall::OpenRead), 7);
    assert_eq!(reader.usage().completed_roots, 0);
    Ok(())
}
