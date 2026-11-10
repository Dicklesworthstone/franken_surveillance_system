#![forbid(unsafe_code)]
//! Recorder replay receipts retain native AVC/HEVC custody without inventing UTC coverage.

mod recording_support;
mod hevc_recording_support;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    ContentDigest, Generation, ObjectId, SensorId, StreamId, TombstoneReason, TombstoneRecord,
};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    LOCAL_TOMBSTONES_DIR, LocalPublicationLimits, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, PublishOutcome, SlotName,
};
use fss_reference::rtsp::client::replay::{ReplayAcceptance, ReplayWindow};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use fss_reference::rtsp::recording::local::{
    RecordingIoError, RecordingProgress, RecordingPublication, load_recording,
};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{
    MAX_REPLAY_WINDOWS, REPLAY_RECEIPT_KIND, HEVC_REPLAY_RECEIPT_KIND, ReplayCodec, ReplayReceipt, ReplayReceiptError as E,
    ReplayRequest, ReplayTermination, ReplayWindowProof, load_replay_receipt,
    publish_replay_receipt, replay_slot, hevc_replay_slot, load_hevc_replay_receipt,
};
use recording_support::{Error, fixture, scope};

type TestResult = Result<(), Error>;
static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

fn path(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("recording_replay_contract")
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

fn request() -> Result<ReplayRequest, Error> {
    Ok(ReplayRequest::new(
        scope()?,
        ContentDigest::sha256(b"approved credential-free route"),
        ReplayWindow::from_timestamps("20261105T010000Z", "20261105T010500Z")?,
        ContentDigest::sha256(b"original decode clock"),
    )?)
}

fn catalog_scope(request: &ReplayRequest) -> CatalogScope {
    CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    }
}

fn accepted(request: &ReplayRequest) -> Result<ReplayAcceptance, Error> {
    Ok(ReplayAcceptance::new(
        7,
        request.window(),
        ReplayWindow::from_timestamps("20261105T010100Z", "20261105T010400Z")?,
    )?)
}

fn prepare(
    request: ReplayRequest,
    windows: Vec<ReplayWindowProof>,
    termination: ReplayTermination,
    publication_complete: bool,
) -> Result<ReplayReceipt, Error> {
    let scope = catalog_scope(&request);
    let acceptance = accepted(&request)?;
    Ok(ReplayReceipt::prepare(
        request,
        scope,
        ContentDigest::sha256(b"complete approved capture plan"),
        acceptance,
        windows,
        termination,
        publication_complete,
    )?)
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

fn setup(
    name: &str,
    count: usize,
) -> Result<(PathBuf, LocalRootPublisher, ReplayReceipt), Error> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let request = request()?;
    let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
    let source = fixture(73, true)?;
    let mut windows = Vec::new();
    for ordinal in 0..count {
        let recording = source.prepare_at(ordinal as u64 * 3600)?;
        let slot = namespace.window_slot(ordinal)?;
        publish_window(&mut publisher, &slot, &recording)?;
        windows.push(ReplayWindowProof::from_avc(slot, &recording)?);
    }
    let receipt = prepare(request, windows, ReplayTermination::RequestedStop, true)?;
    Ok((root, publisher, receipt))
}

struct StopAt(PublishCutPoint);
impl PublishCancellation for StopAt {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        point == self.0
    }
}

fn rechecksum(metadata: &mut [u8]) -> TestResult {
    let body_end = metadata.len().checked_sub(33).ok_or("checksum length")?;
    let checksum = ContentDigest::sha256(&metadata[..body_end]);
    metadata[body_end] = 1;
    metadata[body_end + 1..].copy_from_slice(&checksum.bytes());
    Ok(())
}

fn replace_digest(bytes: &mut [u8], old: ContentDigest, new: ContentDigest) -> TestResult {
    let matches: Vec<_> = bytes
        .windows(32)
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == old.bytes()).then_some(index))
        .collect();
    if matches.len() != 1 {
        return Err("fixture expected exactly one digest role".into());
    }
    bytes[matches[0]..matches[0] + 32].copy_from_slice(&new.bytes());
    Ok(())
}

fn publish_metadata(
    publisher: &mut LocalRootPublisher,
    receipt: &ReplayReceipt,
    scope: &CatalogScope,
    metadata: &[u8],
) -> Result<ObjectManifest, Error> {
    let old = receipt.manifest().metadata_digest().ok_or("metadata")?;
    let current = publisher.stage_object(metadata)?;
    let children = receipt.manifest().children().iter().copied().filter(|value| *value != old);
    let manifest = ObjectManifest::new(receipt.manifest().kind(), children, Some(current))?;
    let slot = match receipt.request().codec() {
        ReplayCodec::Avc => replay_slot(scope, receipt.request().digest())?,
        ReplayCodec::Hevc => hevc_replay_slot(scope, receipt.request().digest())?,
    };
    publisher.publish(&slot, &manifest)?;
    Ok(manifest)
}

#[test]
fn request_identity_binds_route_range_authority_receive_clock_and_base_decode_clock() -> TestResult {
    let original = request()?;
    let normalized = ReplayRequest::new(
        original.scope().clone(),
        original.route(),
        ReplayWindow::from_timestamps(
            "20261105T010000.000000000Z",
            "20261105T010500.000Z",
        )?,
        original.base_decode_clock(),
    )?;
    assert_eq!(normalized, original);
    assert_ne!(original.decode_clock(), original.base_decode_clock());
    assert_eq!(original.scope().anchor, scope()?.anchor);
    assert_eq!(original.scope().receive_clock, scope()?.receive_clock);
    for field in 0..8 {
        let mut recording = original.scope().clone();
        let mut route = original.route();
        let mut window = original.window();
        let mut base = original.base_decode_clock();
        match field {
            0 => recording.sensor = SensorId::parse("different-sensor")?,
            1 => recording.stream = StreamId::parse("different-stream")?,
            2 => recording.generation += 1,
            3 => recording.anchor = ContentDigest::sha256(b"different authority"),
            4 => recording.receive_clock = ContentDigest::sha256(b"different receive clock"),
            5 => route = ContentDigest::sha256(b"different approved route"),
            6 => {
                window = ReplayWindow::from_timestamps(
                    "20261105T010001Z",
                    "20261105T010500Z",
                )?;
            }
            _ => base = ContentDigest::sha256(b"different base decode clock"),
        }
        let changed = ReplayRequest::new(recording, route, window, base)?;
        assert_ne!(changed.digest(), original.digest());
        assert_ne!(changed.decode_clock(), original.decode_clock());
    }
    let mut retired = original.scope().clone();
    retired.generation = 0;
    assert!(matches!(
        ReplayRequest::new(
            retired,
            original.route(),
            original.window(),
            original.base_decode_clock()
        ),
        Err(E::Scope)
    ));
    Ok(())
}

#[test]
fn preparation_refuses_live_clock_foreign_scope_rate_and_other_request_acceptance() -> TestResult {
    let request = request()?;
    let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
    let recording = fixture(73, true)?.prepare()?;
    let proof = ReplayWindowProof::from_avc(namespace.window_slot(0)?, &recording)?;
    for field in 0..4 {
        let mut scope = catalog_scope(&request);
        match field {
            0 => scope.decode_clock = request.base_decode_clock(),
            1 => scope.recording.generation += 1,
            2 => scope.recording.anchor = ContentDigest::sha256(b"foreign authority"),
            _ => scope.time_scale += 1,
        }
        assert!(matches!(
            ReplayReceipt::prepare(
                request.clone(),
                scope,
                ContentDigest::sha256(b"approval"),
                accepted(&request)?,
                vec![proof.clone()],
                ReplayTermination::RequestedStop,
                true
            ),
            Err(E::Scope)
        ));
    }
    let other = ReplayWindow::from_timestamps("20261105T010100Z", "20261105T010200Z")?;
    assert!(matches!(
        ReplayReceipt::prepare(
            request.clone(),
            catalog_scope(&request),
            ContentDigest::sha256(b"approval"),
            ReplayAcceptance::new(7, other, other)?,
            vec![proof],
            ReplayTermination::RequestedStop,
            true
        ),
        Err(E::Scope)
    ));
    Ok(())
}

#[test]
fn a_live_archive_slot_cannot_be_relabelled_as_a_replay_original() -> TestResult {
    let request = request()?;
    let mut live_scope = catalog_scope(&request);
    live_scope.decode_clock = request.base_decode_clock();
    let live = ArchiveNamespace::new(live_scope)?;
    let replay = ArchiveNamespace::new(catalog_scope(&request))?;
    let recording = fixture(73, true)?.prepare()?;
    assert_ne!(live.window_slot(0)?, replay.window_slot(0)?);
    let mut publisher = LocalRootPublisher::open(path("live-namespace"), limits())?;
    publish_window(&mut publisher, &live.window_slot(0)?, &recording)?;
    assert!(matches!(
        ReplayReceipt::prepare(
            request.clone(),
            catalog_scope(&request),
            ContentDigest::sha256(b"approval"),
            accepted(&request)?,
            vec![ReplayWindowProof::from_avc(live.window_slot(0)?, &recording)?],
            ReplayTermination::RequestedStop,
            true
        ),
        Err(E::Scope)
    ));
    assert_eq!(
        load_recording(
            &publisher,
            &live.window_slot(0)?,
            recording.manifest().root(),
            request.scope(),
            &NeverCancel
        )?.manifest().root(),
        recording.manifest().root()
    );
    Ok(())
}

#[test]
fn bounded_contiguous_original_prefix_rejects_duplicates_overlap_and_missing_ordinals() -> TestResult {
    let request = request()?;
    let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
    let source = fixture(73, true)?;
    let first = source.prepare_at(0)?;
    let overlap = source.prepare_at(1800)?;
    let next = source.prepare_at(3600)?;
    let first_proof = ReplayWindowProof::from_avc(namespace.window_slot(0)?, &first)?;
    for second in [
        ReplayWindowProof::from_avc(namespace.window_slot(1)?, &first)?,
        ReplayWindowProof::from_avc(namespace.window_slot(1)?, &overlap)?,
        ReplayWindowProof::from_avc(namespace.window_slot(0)?, &next)?,
        ReplayWindowProof::from_avc(namespace.window_slot(2)?, &next)?,
    ] {
        assert!(prepare(
            request.clone(),
            vec![first_proof.clone(), second],
            ReplayTermination::RequestedStop,
            true
        ).is_err());
    }
    let mut maximum = Vec::new();
    for ordinal in 0..MAX_REPLAY_WINDOWS {
        maximum.push(ReplayWindowProof::from_avc(
            namespace.window_slot(ordinal)?,
            &source.prepare_at(ordinal as u64 * 3600)?,
        )?);
    }
    assert_eq!(
        prepare(
            request.clone(),
            maximum.clone(),
            ReplayTermination::Budget,
            true
        )?.windows().len(),
        MAX_REPLAY_WINDOWS
    );
    maximum.push(first_proof);
    assert!(matches!(
        ReplayReceipt::prepare(
            request.clone(),
            catalog_scope(&request),
            ContentDigest::sha256(b"approval"),
            accepted(&request)?,
            maximum,
            ReplayTermination::Budget,
            true
        ),
        Err(E::Limit)
    ));
    Ok(())
}

#[test]
fn durable_replay_closure_survives_reopen_with_exact_original_native_verification() -> TestResult {
    let (root, mut publisher, receipt) = setup("reopen", 2)?;
    let mut closure = BTreeSet::from([
        receipt.manifest().metadata_digest().ok_or("metadata")?,
    ]);
    for original in receipt.windows() {
        closure.insert(original.root());
        closure.extend(original.original_leaf_digests());
    }
    assert_eq!(receipt.manifest().children(), closure.into_iter().collect::<Vec<_>>());
    assert_eq!(
        publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?.outcome,
        PublishOutcome::Published
    );
    drop(publisher);
    let mut reopened = LocalRootPublisher::open(root, limits())?;
    let loaded = load_replay_receipt(
        &reopened,
        receipt.root(),
        receipt.scope(),
        receipt.request().digest(),
        &NeverCancel,
    )?;
    assert_eq!(loaded.metadata_bytes(), receipt.metadata_bytes());
    assert_eq!(loaded.windows(), receipt.windows());
    assert_eq!(loaded.request(), receipt.request());
    assert_eq!(loaded.acceptance(), receipt.acceptance());
    assert_eq!(loaded.approval(), receipt.approval());
    assert_eq!(loaded.rate_control(), "no");
    assert_ne!(loaded.acceptance().requested(), loaded.acceptance().acknowledged());
    for original in loaded.windows() {
        let recording = load_recording(
            &reopened,
            original.slot(),
            original.root(),
            loaded.request().scope(),
            &NeverCancel,
        )?;
        assert_eq!(recording.summary().decode_interval, original.decode_interval());
        assert_eq!(recording.byte_len(), original.byte_len());
        assert_eq!(
            recording.children().map(|(_, digest, _)| digest),
            original.original_leaf_digests()
        );
        assert_eq!(recording.summary().scope.anchor, scope()?.anchor);
    }
    assert_eq!(
        publish_replay_receipt(&receipt, &mut reopened, &NeverCancel)?.outcome,
        PublishOutcome::AlreadyPublished
    );
    Ok(())
}

#[test]
fn absent_or_substituted_original_prevents_companion_publication() -> TestResult {
    for substituted in [false, true] {
        let mut publisher = LocalRootPublisher::open(path("missing-original"), limits())?;
        let request = request()?;
        let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
        let source = fixture(73, true)?;
        let original = source.prepare_at(0)?;
        let slot = namespace.window_slot(0)?;
        let receipt = prepare(
            request,
            vec![ReplayWindowProof::from_avc(slot.clone(), &original)?],
            ReplayTermination::RequestedStop,
            true,
        )?;
        if substituted {
            publish_window(&mut publisher, &slot, &source.prepare_at(3600)?)?;
        }
        assert!(matches!(
            publish_replay_receipt(&receipt, &mut publisher, &NeverCancel),
            Err(E::Storage(RecordingIoError::NotDurable | RecordingIoError::RootConflict))
        ));
        assert!(publisher.root(&replay_slot(receipt.scope(), receipt.request().digest())?).is_none());
    }
    Ok(())
}

#[test]
fn cancellation_before_each_commit_cut_preserves_originals_and_allows_exact_retry() -> TestResult {
    for cut in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
    ] {
        let (_, mut publisher, receipt) = setup("cancel", 2)?;
        assert!(publish_replay_receipt(&receipt, &mut publisher, &StopAt(cut)).is_err());
        assert!(publisher.root(&replay_slot(receipt.scope(), receipt.request().digest())?).is_none());
        for original in receipt.windows() {
            assert_eq!(publisher.root(original.slot()).ok_or("original")?.root, original.root());
        }
        assert_eq!(
            publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?.outcome,
            PublishOutcome::Published
        );
    }
    Ok(())
}

#[test]
fn every_root_last_crash_cut_keeps_originals_and_recovers_only_visible_receipts() -> TestResult {
    for cut in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ] {
        let (root, mut publisher, receipt) = setup("crash", 2)?;
        publisher.inject_crash_at(cut);
        assert!(publish_replay_receipt(&receipt, &mut publisher, &NeverCancel).is_err());
        drop(publisher);
        let mut reopened = LocalRootPublisher::open(root, limits())?;
        for original in receipt.windows() {
            assert_eq!(
                load_recording(
                    &reopened,
                    original.slot(),
                    original.root(),
                    receipt.request().scope(),
                    &NeverCancel
                )?.manifest().root(),
                original.root()
            );
        }
        if cut == PublishCutPoint::AfterRootRename {
            assert_eq!(
                load_replay_receipt(
                    &reopened,
                    receipt.root(),
                    receipt.scope(),
                    receipt.request().digest(),
                    &NeverCancel
                )?.root(),
                receipt.root()
            );
            assert_eq!(
                publish_replay_receipt(&receipt, &mut reopened, &NeverCancel)?.outcome,
                PublishOutcome::AlreadyPublished
            );
        } else {
            assert!(reopened.root(
                &replay_slot(receipt.scope(), receipt.request().digest())?
            ).is_none());
            assert!(load_replay_receipt(
                &reopened,
                receipt.root(),
                receipt.scope(),
                receipt.request().digest(),
                &NeverCancel
            ).is_err());
        }
    }
    Ok(())
}

#[test]
fn cold_loading_requires_exact_root_request_scope_and_uncancelled_owner() -> TestResult {
    let (_, mut publisher, receipt) = setup("pins", 1)?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    assert!(matches!(
        load_replay_receipt(
            &publisher,
            ContentDigest::sha256(b"unrelated root"),
            receipt.scope(),
            receipt.request().digest(),
            &NeverCancel
        ),
        Err(E::Storage(RecordingIoError::RootConflict))
    ));
    assert!(load_replay_receipt(
        &publisher,
        receipt.root(),
        receipt.scope(),
        ContentDigest::sha256(b"unrelated request"),
        &NeverCancel
    ).is_err());
    for field in 0..7 {
        let mut scope = receipt.scope().clone();
        match field {
            0 => scope.recording.sensor = SensorId::parse("other-sensor")?,
            1 => scope.recording.stream = StreamId::parse("other-stream")?,
            2 => scope.recording.generation += 1,
            3 => scope.recording.anchor = ContentDigest::sha256(b"other authority"),
            4 => scope.recording.receive_clock = ContentDigest::sha256(b"other receive clock"),
            5 => scope.decode_clock = ContentDigest::sha256(b"other decode clock"),
            _ => scope.time_scale += 1,
        }
        assert!(load_replay_receipt(
            &publisher,
            receipt.root(),
            &scope,
            receipt.request().digest(),
            &NeverCancel
        ).is_err());
    }
    assert!(matches!(
        load_replay_receipt(
            &publisher,
            receipt.root(),
            receipt.scope(),
            receipt.request().digest(),
            &StopAt(PublishCutPoint::AfterChildrenVerified)
        ),
        Err(E::Storage(RecordingIoError::Cancelled))
    ));
    Ok(())
}

#[test]
fn coherent_rehash_of_false_original_accounting_still_requires_native_source_verification() -> TestResult {
    let (_, mut publisher, receipt) = setup("forged-accounting", 1)?;
    let mut metadata = receipt.metadata_bytes().to_vec();
    let body_end = metadata.len().checked_sub(33).ok_or("checksum")?;
    // The final descriptor ends with byte count followed by four role-ordered digests.
    let offset = body_end.checked_sub(4 * 33 + 8).ok_or("descriptor")?;
    let invented = receipt.windows()[0].byte_len() as u64 + 1;
    metadata[offset..offset + 8].copy_from_slice(&invented.to_be_bytes());
    rechecksum(&mut metadata)?;
    let forged = publish_metadata(&mut publisher, &receipt, receipt.scope(), &metadata)?;
    assert!(matches!(
        load_replay_receipt(
            &publisher,
            forged.root(),
            receipt.scope(),
            receipt.request().digest(),
            &NeverCancel
        ),
        Err(E::WindowMismatch)
    ));
    Ok(())
}

#[test]
fn coherent_rehash_cannot_replace_the_replay_clock_with_a_live_decode_clock() -> TestResult {
    let (_, mut publisher, receipt) = setup("forged-clock", 1)?;
    let mut live = receipt.scope().clone();
    live.decode_clock = receipt.request().base_decode_clock();
    let mut metadata = receipt.metadata_bytes().to_vec();
    let body_end = metadata.len().checked_sub(33).ok_or("checksum")?;
    replace_digest(&mut metadata[..body_end], receipt.scope().decode_clock, live.decode_clock)?;
    rechecksum(&mut metadata)?;
    let forged = publish_metadata(&mut publisher, &receipt, &live, &metadata)?;
    assert!(matches!(
        load_replay_receipt(
            &publisher,
            forged.root(),
            &live,
            receipt.request().digest(),
            &NeverCancel
        ),
        Err(E::Scope)
    ));
    Ok(())
}

#[test]
fn hostile_counts_unknown_tags_noncanonical_trailing_bytes_and_bad_checksums_are_refused() -> TestResult {
    for mutation in 0..6 {
        let (_, mut publisher, receipt) = setup("malformed", 1)?;
        let mut metadata = receipt.metadata_bytes().to_vec();
        let body_end = metadata.len().checked_sub(33).ok_or("checksum")?;
        let record_len = 8 + receipt.windows()[0].slot().as_str().len() + 33 + 6 * 8 + 4 * 33;
        let count_at = body_end.checked_sub(record_len + 8).ok_or("descriptor")?;
        match mutation {
            0 => {
                let last = metadata.len() - 1;
                metadata[last] ^= 1;
            }
            1 => metadata[count_at..count_at + 8].copy_from_slice(&u64::MAX.to_be_bytes()),
            2 => metadata[count_at - 1] = 2, // Publication completeness must be a canonical bool.
            3 => metadata[count_at - 2] = 255, // Unknown termination.
            4 => metadata[count_at - 3] = 1, // Rate-Control yes is not this profile.
            _ => metadata.insert(body_end, 0), // Unconsumed body bytes are never aliases.
        }
        if mutation != 0 {
            rechecksum(&mut metadata)?;
        }
        let forged = publish_metadata(&mut publisher, &receipt, receipt.scope(), &metadata)?;
        let result = load_replay_receipt(
            &publisher,
            forged.root(),
            receipt.scope(),
            receipt.request().digest(),
            &NeverCancel,
        );
        if mutation == 1 {
            assert!(matches!(result, Err(E::Limit)));
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}

#[test]
fn dropping_an_original_leaf_from_the_rehashed_companion_closure_is_refused() -> TestResult {
    let (_, mut publisher, receipt) = setup("missing-closure", 1)?;
    let metadata = publisher.stage_object(receipt.metadata_bytes())?;
    let removed = receipt.windows()[0].original_leaf_digests()[0];
    let children = receipt.manifest().children().iter().copied()
        .filter(|value| *value != removed && *value != metadata);
    let forged = ObjectManifest::new(REPLAY_RECEIPT_KIND, children, Some(metadata))?;
    publisher.publish(&replay_slot(receipt.scope(), receipt.request().digest())?, &forged)?;
    assert!(matches!(
        load_replay_receipt(
            &publisher,
            forged.root(),
            receipt.scope(),
            receipt.request().digest(),
            &NeverCancel
        ),
        Err(E::Digest)
    ));
    Ok(())
}

#[test]
fn durable_tombstones_of_originals_or_companion_evidence_block_cold_loading() -> TestResult {
    for role in 0..4 {
        let (root, mut publisher, receipt) = setup("tombstone", 1)?;
        publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
        let witness_bytes = b"authorized deletion fixture witness";
        let witness = publisher.stage_object(witness_bytes)?;
        let deleted = match role {
            0 => receipt.windows()[0].root(),
            1 => receipt.windows()[0].original_leaf_digests()[0],
            2 => receipt.root(),
            _ => receipt.manifest().metadata_digest().ok_or("metadata")?,
        };
        drop(publisher);
        let donor_root = path("tombstone-donor");
        let mut donor = LocalRootPublisher::open(&donor_root, limits())?;
        assert_eq!(donor.stage_object(witness_bytes)?, witness);
        donor.record_tombstone(TombstoneRecord::new(
            ObjectId::parse("object:recording-replay-fixture")?,
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
        assert!(load_replay_receipt(
            &reopened,
            receipt.root(),
            receipt.scope(),
            receipt.request().digest(),
            &NeverCancel
        ).is_err());
    }
    Ok(())
}

#[test]
fn accepted_empty_attempts_keep_termination_separate_from_publication_and_cannot_be_overwritten() -> TestResult {
    let request = request()?;
    let failed = prepare(request.clone(), Vec::new(), ReplayTermination::ProtocolFailure, false)?;
    let settled = prepare(request.clone(), Vec::new(), ReplayTermination::ProtocolFailure, true)?;
    let stopped = prepare(request, Vec::new(), ReplayTermination::RequestedStop, true)?;
    assert_ne!(failed.root(), settled.root());
    assert_ne!(settled.root(), stopped.root());
    assert_eq!(failed.request(), stopped.request());
    assert_eq!(
        replay_slot(failed.scope(), failed.request().digest())?,
        replay_slot(stopped.scope(), stopped.request().digest())?
    );
    let mut publisher = LocalRootPublisher::open(path("accepted-empty"), limits())?;
    publish_replay_receipt(&failed, &mut publisher, &NeverCancel)?;
    let loaded = load_replay_receipt(
        &publisher,
        failed.root(),
        failed.scope(),
        failed.request().digest(),
        &NeverCancel,
    )?;
    assert!(loaded.windows().is_empty());
    assert!(!loaded.publication_complete());
    assert_eq!(loaded.termination(), ReplayTermination::ProtocolFailure);
    assert!(matches!(
        publish_replay_receipt(&settled, &mut publisher, &NeverCancel),
        Err(E::Storage(RecordingIoError::RootConflict))
    ));
    Ok(())
}

fn hevc_request() -> Result<ReplayRequest, Error> {
    let avc = request()?;
    Ok(ReplayRequest::new_hevc(hevc_recording_support::scope()?, avc.route(),
        avc.window(), avc.base_decode_clock())?)
}

fn hevc_setup(name: &str) -> Result<(PathBuf, LocalRootPublisher, ReplayReceipt), Error> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let request = hevc_request()?;
    let namespace = HevcArchiveNamespace::new(catalog_scope(&request))?;
    // Three real parameter NALs close the second picture and remain source-only.
    let packets = hevc_recording_support::packets()?;
    let original = hevc_recording_support::prepare(&packets[..8], &hevc_recording_support::timings(2))?;
    assert_eq!(original.source_only_nals(), 3);
    let slot = namespace.window_slot(0)?;
    publish_window(&mut publisher, &slot, original.publication_plan())?;
    let proof = ReplayWindowProof::from_hevc(slot, &original)?;
    let receipt = prepare(request, vec![proof], ReplayTermination::RequestedStop, true)?;
    Ok((root, publisher, receipt))
}

#[test]
fn hevc_replay_reopens_native_originals_with_exact_source_only_boundary_witnesses() -> TestResult {
    let (root, mut publisher, receipt) = hevc_setup("hevc-reopen")?;
    assert_eq!(receipt.request().codec(), ReplayCodec::Hevc);
    assert_eq!(receipt.manifest().kind(), HEVC_REPLAY_RECEIPT_KIND);
    assert_eq!(receipt.slot()?, hevc_replay_slot(receipt.scope(), receipt.request().digest())?);
    assert!(receipt.slot()?.as_str().starts_with("fssrr1-hevc-"));
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    drop(publisher);
    let mut reopened = LocalRootPublisher::open(root, limits())?;
    let loaded = load_hevc_replay_receipt(&reopened, receipt.root(), receipt.scope(),
        receipt.request().digest(), &NeverCancel)?;
    assert_eq!(loaded.metadata_bytes(), receipt.metadata_bytes());
    assert_eq!(loaded.windows(), receipt.windows());
    assert_eq!(loaded.request(), receipt.request());
    assert_eq!(loaded.acceptance(), receipt.acceptance());
    let proof = &loaded.windows()[0];
    assert_eq!(proof.codec(), ReplayCodec::Hevc);
    let original = load_hevc_recording(&reopened, proof.slot(), proof.root(),
        loaded.request().scope(), &NeverCancel)?;
    assert_eq!(original.source_only_nals(), 3);
    assert_eq!(original.summary().samples, 2);
    assert_eq!(original.summary().nals, 5);
    assert_eq!(original.summary().decode_interval, proof.decode_interval());
    assert_eq!(original.byte_len(), proof.byte_len());
    let packets = hevc_recording_support::packets()?;
    for (actual, expected) in original.packets()?.iter().zip(&packets[..8]) {
        assert_eq!(actual.bytes, expected.bytes);
        assert_eq!(actual.received_ns, expected.received_ns);
        assert_eq!(actual.sequence, expected.sequence);
    }
    assert_eq!(publish_replay_receipt(&receipt, &mut reopened, &NeverCancel)?.outcome,
        PublishOutcome::AlreadyPublished);
    assert!(load_replay_receipt(&reopened, receipt.root(), receipt.scope(),
        receipt.request().digest(), &NeverCancel).is_err());
    assert!(matches!(load_hevc_replay_receipt(&reopened, receipt.root(), receipt.scope(),
        receipt.request().digest(), &StopAt(PublishCutPoint::AfterChildrenVerified)),
        Err(E::Storage(RecordingIoError::Cancelled))));
    Ok(())
}

#[test]
fn codec_choice_changes_replay_identity_and_cannot_cross_original_or_receipt_families() -> TestResult {
    let hevc = hevc_request()?;
    let avc = ReplayRequest::new(hevc.scope().clone(), hevc.route(), hevc.window(), hevc.base_decode_clock())?;
    assert_ne!(avc.digest(), hevc.digest());
    assert_ne!(avc.decode_clock(), hevc.decode_clock());
    let original = hevc_recording_support::fixture()?;
    let namespace = HevcArchiveNamespace::new(catalog_scope(&hevc))?;
    assert!(ReplayWindowProof::from_avc(namespace.window_slot(0)?, original.publication_plan()).is_err());
    let proof = ReplayWindowProof::from_hevc(namespace.window_slot(0)?, &original)?;
    assert!(prepare(avc.clone(), vec![proof], ReplayTermination::RequestedStop, true).is_err());
    let avc_receipt = prepare(avc, Vec::new(), ReplayTermination::ProtocolFailure, false)?;
    let hevc_receipt = prepare(hevc, Vec::new(), ReplayTermination::ProtocolFailure, false)?;
    assert_ne!(avc_receipt.root(), hevc_receipt.root());
    assert_ne!(avc_receipt.slot()?, hevc_receipt.slot()?);
    let mut publisher = LocalRootPublisher::open(path("codec-pinned"), limits())?;
    publish_replay_receipt(&avc_receipt, &mut publisher, &NeverCancel)?;
    publish_replay_receipt(&hevc_receipt, &mut publisher, &NeverCancel)?;
    // Even a coherently installed AVC root in the HEVC routing slot cannot make
    // the explicitly chosen HEVC loader select AVC from the stored manifest.
    let slot = hevc_replay_slot(avc_receipt.scope(), avc_receipt.request().digest())?;
    publisher.publish(&slot, avc_receipt.manifest())?;
    assert!(matches!(load_hevc_replay_receipt(&publisher, avc_receipt.root(), avc_receipt.scope(),
        avc_receipt.request().digest(), &NeverCancel), Err(E::Digest)));
    Ok(())
}

#[test]
fn hevc_replay_cannot_publish_absent_originals_or_trust_rehashed_accounting() -> TestResult {
    let (_, mut publisher, receipt) = hevc_setup("hevc-forged")?;
    let mut empty = LocalRootPublisher::open(path("hevc-missing"), limits())?;
    assert!(publish_replay_receipt(&receipt, &mut empty, &NeverCancel).is_err());
    assert!(empty.root(&receipt.slot()?).is_none());
    let mut metadata = receipt.metadata_bytes().to_vec();
    let body_end = metadata.len().checked_sub(33).ok_or("checksum")?;
    let offset = body_end.checked_sub(4 * 33 + 8).ok_or("descriptor")?;
    let invented = receipt.windows()[0].byte_len() as u64 + 1;
    metadata[offset..offset + 8].copy_from_slice(&invented.to_be_bytes());
    rechecksum(&mut metadata)?;
    let forged = publish_metadata(&mut publisher, &receipt, receipt.scope(), &metadata)?;
    assert!(matches!(load_hevc_replay_receipt(&publisher, forged.root(), receipt.scope(),
        receipt.request().digest(), &NeverCancel), Err(E::WindowMismatch)));
    Ok(())
}

#[test]
fn hevc_replay_source_tombstone_prevents_a_cold_verified_receipt() -> TestResult {
    let (root, mut publisher, receipt) = hevc_setup("hevc-tombstone")?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    let deleted = receipt.windows()[0].original_leaf_digests()[0];
    let witness_bytes = b"authorized HEVC original deletion witness";
    publisher.stage_object(witness_bytes)?;
    drop(publisher);
    let donor_root = path("hevc-tombstone-donor");
    let mut donor = LocalRootPublisher::open(&donor_root, limits())?;
    let witness = donor.stage_object(witness_bytes)?;
    donor.record_tombstone(TombstoneRecord::new(ObjectId::parse("object:hevc-replay-fixture")?,
        Generation(2), Generation(1), TombstoneReason::Deleted, Some(witness), deleted)?)?;
    drop(donor);
    for entry in std::fs::read_dir(donor_root.join(LOCAL_TOMBSTONES_DIR))? {
        let entry = entry?;
        std::fs::copy(entry.path(), root.join(LOCAL_TOMBSTONES_DIR).join(entry.file_name()))?;
    }
    let reopened = LocalRootPublisher::open(root, limits())?;
    assert!(load_hevc_replay_receipt(&reopened, receipt.root(), receipt.scope(),
        receipt.request().digest(), &NeverCancel).is_err());
    Ok(())
}
