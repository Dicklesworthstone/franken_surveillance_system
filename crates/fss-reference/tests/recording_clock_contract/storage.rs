#![forbid(unsafe_code)]
//! The clock companion obeys original custody, root-last publication and cold replay.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::fixture::*;
use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    LOCAL_TOMBSTONES_DIR, LocalPublicationLimits, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, PublishOutcome, SlotName,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{
    RecordingIoError, RecordingProgress, RecordingPublication, load_recording,
};
use fss_reference::rtsp::recording_clock::{
    CLOCK_INDEX_KIND, RecordingClockCodec as Codec, RecordingClockError as E, RecordingClockIndex,
    clock_slot, load_clock_index, publish_clock_index,
};

static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

fn path(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("recording_clock_contract")
        .join(format!(
            "{}-{}-{name}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        128,
        SpoolLimits::new(128, 32 * 1024 * 1024, 8 * 1024 * 1024, 256),
    )
}

fn publish_window(
    publisher: &mut LocalRootPublisher,
    slot: &SlotName,
    recording: &PreparedRecording,
) -> TestResult {
    let mut job = RecordingPublication::new(
        recording,
        publisher,
        slot.clone(),
        recording.byte_len(),
        100,
    )?;
    for now in 0..4 {
        assert!(matches!(
            job.step(now, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        job.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}

fn setup(name: &str) -> Result<(PathBuf, LocalRootPublisher, RecordingClockIndex), Error> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let a = window(1, 0, &[60_000_000, 30_000_000])?;
    let b = window(3, 7200, &[80_000_000])?;
    let first = SlotName::parse("first")?;
    let second = SlotName::parse("second")?;
    publish_window(&mut publisher, &first, &a)?;
    publish_window(&mut publisher, &second, &b)?;
    let index = prepare(
        &[
            descriptor(first.as_str(), &a)?,
            descriptor(second.as_str(), &b)?,
        ],
        &[
            bracket(30_000_000),
            bracket(60_000_000),
            bracket(80_000_000),
        ],
    )?;
    Ok((root, publisher, index))
}

struct StopAt(PublishCutPoint);
impl PublishCancellation for StopAt {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        point == self.0
    }
}

#[test]
fn durable_clock_closure_survives_reopen_and_exact_repeat_is_idempotent() -> TestResult {
    let (root, mut publisher, index) = setup("reopen")?;
    let mut closure = BTreeSet::new();
    closure.insert(index.manifest().metadata_digest().ok_or("metadata")?);
    for window in index.windows() {
        closure.insert(window.root());
        closure.extend(window.original_leaf_digests());
    }
    assert_eq!(
        index.manifest().children(),
        closure.into_iter().collect::<Vec<_>>()
    );
    let receipt = publish_clock_index(&index, &mut publisher, &NeverCancel)?;
    assert_eq!(receipt.root, index.root());
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    drop(publisher);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let loaded = load_clock_index(
        &publisher,
        index.root(),
        index.scope(),
        Codec::Avc,
        &NeverCancel,
    )?;
    assert_eq!(loaded.index_bytes(), index.index_bytes());
    assert_eq!(loaded.windows(), index.windows());
    assert_eq!(loaded.brackets(), index.brackets());
    for original in index.windows() {
        let recording = load_recording(
            &publisher,
            original.slot(),
            original.root(),
            &index.scope().recording,
            &NeverCancel,
        )?;
        assert_eq!(recording.byte_len(), original.byte_len());
        assert_eq!(
            recording.children().map(|(_, digest, _)| digest),
            original.original_leaf_digests()
        );
    }
    assert_eq!(
        publish_clock_index(&index, &mut publisher, &NeverCancel)?.outcome,
        PublishOutcome::AlreadyPublished
    );
    Ok(())
}

#[test]
fn unpublished_original_or_current_slot_substitution_cannot_publish_a_clock_root() -> TestResult {
    for conflict in [false, true] {
        let mut publisher = LocalRootPublisher::open(path("missing-or-substituted"), limits())?;
        let recording = window(1, 0, &[30_000_000])?;
        let descriptor = descriptor("original", &recording)?;
        let index = prepare(&[descriptor], &[bracket(30_000_000)])?;
        if conflict {
            publish_window(
                &mut publisher,
                &SlotName::parse("original")?,
                &window(3, 0, &[40_000_000])?,
            )?;
        }
        let result = publish_clock_index(&index, &mut publisher, &NeverCancel);
        assert!(matches!(
            result,
            Err(E::Storage(
                RecordingIoError::NotDurable | RecordingIoError::RootConflict
            ))
        ));
        assert!(
            publisher
                .root(&clock_slot(Codec::Avc, index.scope())?)
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn cancellation_at_each_precommit_cut_leaves_originals_and_no_clock_visibility() -> TestResult {
    for cut in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
    ] {
        let (_, mut publisher, index) = setup("cancel")?;
        assert!(publish_clock_index(&index, &mut publisher, &StopAt(cut)).is_err());
        assert!(
            publisher
                .root(&clock_slot(Codec::Avc, index.scope())?)
                .is_none()
        );
        for original in index.windows() {
            assert_eq!(
                publisher
                    .root(original.slot())
                    .ok_or("original must remain")?
                    .root,
                original.root()
            );
        }
        assert_eq!(
            publish_clock_index(&index, &mut publisher, &NeverCancel)?.outcome,
            PublishOutcome::Published
        );
    }
    Ok(())
}

#[test]
fn every_root_last_crash_cut_recovers_without_false_clock_visibility() -> TestResult {
    for cut in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ] {
        let (root, mut publisher, index) = setup("crash")?;
        publisher.inject_crash_at(cut);
        assert!(publish_clock_index(&index, &mut publisher, &NeverCancel).is_err());
        drop(publisher);
        let mut reopened = LocalRootPublisher::open(root, limits())?;
        for original in index.windows() {
            assert_eq!(
                load_recording(
                    &reopened,
                    original.slot(),
                    original.root(),
                    &index.scope().recording,
                    &NeverCancel
                )?
                .manifest()
                .root(),
                original.root()
            );
        }
        if cut == PublishCutPoint::AfterRootRename {
            assert_eq!(
                load_clock_index(
                    &reopened,
                    index.root(),
                    index.scope(),
                    Codec::Avc,
                    &NeverCancel
                )?
                .root(),
                index.root()
            );
            assert_eq!(
                publish_clock_index(&index, &mut reopened, &NeverCancel)?.outcome,
                PublishOutcome::AlreadyPublished
            );
        } else {
            assert!(
                reopened
                    .root(&clock_slot(Codec::Avc, index.scope())?)
                    .is_none()
            );
            assert!(
                load_clock_index(
                    &reopened,
                    index.root(),
                    index.scope(),
                    Codec::Avc,
                    &NeverCancel
                )
                .is_err()
            );
            // A precommit orphan is preserved for the existing recovery owner;
            // this immutable slot does not silently overwrite that evidence.
        }
    }
    Ok(())
}

#[test]
fn cold_loading_requires_the_pinned_root_exact_session_scope_and_explicit_codec() -> TestResult {
    let (_, mut publisher, index) = setup("pins")?;
    publish_clock_index(&index, &mut publisher, &NeverCancel)?;
    assert!(matches!(
        load_clock_index(
            &publisher,
            ContentDigest::sha256(b"unrelated companion"),
            index.scope(),
            Codec::Avc,
            &NeverCancel
        ),
        Err(E::Storage(RecordingIoError::RootConflict))
    ));
    assert!(
        load_clock_index(
            &publisher,
            index.root(),
            index.scope(),
            Codec::Hevc,
            &NeverCancel
        )
        .is_err()
    );
    for field in 0..4 {
        let mut scope = index.scope().clone();
        match field {
            0 => scope.recording.generation += 1,
            1 => scope.recording.receive_clock = ContentDigest::sha256(b"different receive clock"),
            2 => scope.decode_clock = ContentDigest::sha256(b"different DTS clock"),
            _ => scope.recording.anchor = ContentDigest::sha256(b"different capture owner"),
        }
        assert!(
            load_clock_index(&publisher, index.root(), &scope, Codec::Avc, &NeverCancel).is_err()
        );
    }
    assert!(matches!(
        load_clock_index(
            &publisher,
            index.root(),
            index.scope(),
            Codec::Avc,
            &StopAt(PublishCutPoint::AfterChildrenVerified)
        ),
        Err(E::Storage(RecordingIoError::Cancelled))
    ));
    Ok(())
}

#[test]
fn later_originals_never_inherit_an_older_companions_clock_evidence() -> TestResult {
    let (_, mut publisher, index) = setup("later-original")?;
    publish_clock_index(&index, &mut publisher, &NeverCancel)?;
    let additional = window(5, 14400, &[90_000_000])?;
    let slot = SlotName::parse("later-unannotated")?;
    publish_window(&mut publisher, &slot, &additional)?;
    let loaded = load_clock_index(
        &publisher,
        index.root(),
        index.scope(),
        Codec::Avc,
        &NeverCancel,
    )?;
    assert_eq!(loaded.windows(), index.windows());
    assert!(
        loaded
            .windows()
            .iter()
            .all(|entry| entry.root() != additional.manifest().root())
    );
    assert_eq!(
        publisher.root(&slot).ok_or("additional original")?.root,
        additional.manifest().root()
    );
    Ok(())
}

fn replace_digest(bytes: &mut [u8], old: ContentDigest, new: ContentDigest) -> TestResult {
    if old == new {
        return Ok(());
    }
    let matches: Vec<_> = bytes
        .windows(32)
        .enumerate()
        .filter_map(|(i, candidate)| (candidate == old.bytes()).then_some(i))
        .collect();
    if matches.len() != 1 {
        return Err("fixture expected one digest role".into());
    }
    bytes[matches[0]..matches[0] + 32].copy_from_slice(&new.bytes());
    Ok(())
}

#[test]
fn coherently_rehashed_clock_claims_still_require_actual_original_packet_coordinates() -> TestResult
{
    let mut publisher = LocalRootPublisher::open(path("forged-source-coordinates"), limits())?;
    let actual = window(1, 0, &[30_000_000, 60_000_000])?;
    let invented = window(1, 0, &[31_000_000, 61_000_000])?;
    let slot = SlotName::parse("original")?;
    publish_window(&mut publisher, &slot, &actual)?;
    let wrong = prepare(
        &[descriptor(slot.as_str(), &invented)?],
        &[bracket(31_000_000), bracket(61_000_000)],
    )?;
    assert_eq!(actual.byte_len(), invented.byte_len());
    let mut metadata = wrong.index_bytes().to_vec();
    let body_len = metadata.len().checked_sub(33).ok_or("checksum length")?;
    let body = &mut metadata[..body_len];
    replace_digest(body, invented.manifest().root(), actual.manifest().root())?;
    for ((_, old, _), (_, new, _)) in invented.children().into_iter().zip(actual.children()) {
        replace_digest(body, old, new)?;
    }
    let checksum = ContentDigest::sha256(body);
    metadata[body_len] = 1;
    metadata[body_len + 1..].copy_from_slice(&checksum.bytes());
    let metadata_digest = publisher.stage_object(&metadata)?;
    let mut leaves = BTreeSet::from([actual.manifest().root()]);
    leaves.extend(actual.children().map(|(_, digest, _)| digest));
    let manifest = ObjectManifest::new(CLOCK_INDEX_KIND, leaves, Some(metadata_digest))?;
    publisher.publish(&clock_slot(Codec::Avc, wrong.scope())?, &manifest)?;
    // All hashes, original closure, independently derived UTC bounds, slot,
    // counts and byte sizes now agree. Only native original replay exposes the
    // invented receive coordinates, which must never become a UTC candidate.
    assert!(matches!(
        load_clock_index(
            &publisher,
            manifest.root(),
            wrong.scope(),
            Codec::Avc,
            &NeverCancel
        ),
        Err(E::WindowMismatch)
    ));
    Ok(())
}

#[test]
fn a_durable_original_tombstone_blocks_recovered_clock_discovery() -> TestResult {
    for leaf in [false, true] {
        let (root, mut publisher, index) = setup("tombstone")?;
        publish_clock_index(&index, &mut publisher, &NeverCancel)?;
        let witness_bytes = b"authorized deletion fixture witness";
        let witness = publisher.stage_object(witness_bytes)?;
        let deleted = if leaf {
            index.windows()[0].original_leaf_digests()[0]
        } else {
            index.windows()[0].root()
        };
        drop(publisher);

        // Construct a valid durable tombstone through its owner in a separate
        // fixture, then model its arrival while the original owner is closed.
        // No live-owner API silently unpublishes a reachable original.
        let donor_root = path("tombstone-donor");
        let mut donor = LocalRootPublisher::open(&donor_root, limits())?;
        assert_eq!(donor.stage_object(witness_bytes)?, witness);
        donor.record_tombstone(TombstoneRecord::new(
            ObjectId::parse("object:recording-clock-fixture")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(witness),
            deleted,
        )?)?;
        drop(donor);
        for entry in std::fs::read_dir(donor_root.join(LOCAL_TOMBSTONES_DIR))? {
            let entry = entry?;
            std::fs::copy(
                entry.path(),
                root.join(LOCAL_TOMBSTONES_DIR).join(entry.file_name()),
            )?;
        }
        let reopened = LocalRootPublisher::open(root, limits())?;
        assert!(reopened.tombstones().any(|digest| *digest == deleted));
        assert!(
            load_clock_index(
                &reopened,
                index.root(),
                index.scope(),
                Codec::Avc,
                &NeverCancel
            )
            .is_err()
        );
        assert!(
            reopened
                .root(&clock_slot(Codec::Avc, index.scope())?)
                .is_none()
        );
    }
    Ok(())
}
