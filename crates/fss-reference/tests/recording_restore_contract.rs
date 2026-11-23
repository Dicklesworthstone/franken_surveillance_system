#![forbid(unsafe_code)]
//! Copied originals must pass native verification before they can enter a new archive.
mod archive_support;
mod hevc_catalog_support;
mod hevc_recording_support;

use archive_support::{Error, TestResult, namespace, owner, owner_limits, window};
use fss_core::{CanonicalEncode, ContentDigest, SensorId, StreamId};
use fss_object::ObjectManifest;
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::recording::local::RecordingIoError;
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, PreparedRecording, RecordingError};
use fss_reference::rtsp::recording_archive::*;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use std::ops::Range;

fn copied_objects(plan: &PreparedRecording) -> [Vec<u8>; 4] {
    let bytes = plan.objects();
    [
        bytes.source.to_vec(),
        bytes.initialization.to_vec(),
        bytes.media.to_vec(),
        bytes.index.to_vec(),
    ]
}

fn restore<C: ArchiveCodec>(
    plan: &PreparedRecording,
    scope: &CatalogScope,
) -> Result<C::Recording, Error> {
    Ok(C::restore_recording(
        plan.manifest().root(),
        &plan.manifest().canonical_bytes(),
        copied_objects(plan),
        scope,
    )?)
}

fn exact_original(actual: &PreparedRecording, original: &PreparedRecording) {
    assert_eq!(actual.manifest(), original.manifest());
    assert_eq!(
        actual.manifest().canonical_bytes(),
        original.manifest().canonical_bytes()
    );
    assert_eq!(actual.summary(), original.summary());
    assert_eq!(actual.byte_len(), original.byte_len());
    let actual = actual.objects();
    let original = original.objects();
    assert_eq!(actual.source, original.source);
    assert_eq!(actual.initialization, original.initialization);
    assert_eq!(actual.media, original.media);
    assert_eq!(actual.index, original.index);
}

fn drive<C: ArchiveCodec>(
    writer: &mut CodecRecordingArchiveWriter<'_, C>,
    now: &mut u64,
    finished: bool,
) -> TestResult {
    for _ in 0..128 {
        let progress = writer.step(*now, &NeverCancel)?;
        *now += 1;
        if matches!(progress, ArchiveWriteProgress::Finished { .. }) && finished
            || matches!(progress, ArchiveWriteProgress::Ready { .. }) && !finished
        {
            return Ok(());
        }
    }
    Err("restored archive failed to settle within bounded steps".into())
}

fn publish_and_reopen<C: ArchiveCodec>(
    label: &str,
    originals: Vec<C::Recording>,
    scope: CatalogScope,
    query: Range<u64>,
    gaps: Vec<Range<u64>>,
) -> TestResult {
    let (path, mut publisher) = owner(label)?;
    let limits = ArchiveLimits {
        windows_per_page: 2,
        ..ArchiveLimits::default()
    };
    let mut now = 0;
    let mut writer = CodecRecordingArchiveWriter::<C>::open(
        &mut publisher,
        CodecArchiveNamespace::new(scope.clone())?,
        limits,
        now,
        1000,
        &NeverCancel,
    )?;
    for (ordinal, original) in originals.iter().enumerate() {
        let plan = C::plan(original);
        let restored = restore::<C>(plan, &scope)?;
        exact_original(C::plan(&restored), plan);
        let admitted = writer
            .offer(restored, plan.byte_len(), now)
            .map_err(|refusal| *refusal.reason)?;
        assert_eq!(admitted.ordinal, ordinal);
        assert_eq!(admitted.root, plan.manifest().root());
        drive(&mut writer, &mut now, false)?;
    }
    writer.finish();
    drive(&mut writer, &mut now, true)?;
    let retired = writer.retire();
    assert!(retired.pending.is_none());
    assert!(retired.prepared_page.is_none());
    assert_eq!(retired.snapshot.indexed_windows(), originals.len());
    assert_eq!(retired.snapshot.pages().len(), 2);
    let expected_snapshot = retired.snapshot.digest()?;
    drop(publisher);

    // Recovery reads the newly published native roots, never the original preparation objects.
    let publisher = LocalRootPublisher::open(path, owner_limits())?;
    let snapshot = CodecArchiveSnapshot::<C>::load(
        &publisher,
        CodecArchiveNamespace::new(scope)?,
        limits,
        &NeverCancel,
    )?;
    assert_eq!(snapshot.digest()?, expected_snapshot);
    let mut read = CodecArchiveRead::<C>::new(
        &publisher,
        &snapshot,
        query,
        ArchiveQueryLimits::default(),
        1000,
    )?;
    for (ordinal, original) in originals.iter().enumerate() {
        let ArchiveReadProgress::Window {
            ordinal: actual,
            recording,
            ..
        } = read.step(ordinal as u64, &NeverCancel)?
        else {
            return Err("restored native window missing from cold query".into());
        };
        assert_eq!(actual, ordinal);
        exact_original(C::plan(&recording), C::plan(original));
    }
    let ArchiveReadProgress::Complete(receipt) = read.step(originals.len() as u64, &NeverCancel)?
    else {
        return Err("restored native query did not complete".into());
    };
    assert_eq!(receipt.windows, originals.len());
    assert_eq!(receipt.unindexed, gaps);
    Ok(())
}

#[test]
fn copied_avc_originals_publish_and_reopen_with_exact_roots_and_sparse_intervals() -> TestResult {
    publish_and_reopen::<AvcArchiveCodec>(
        "restore_avc",
        vec![window(1, 0)?, window(4, 7200)?, window(7, 14_400)?],
        namespace()?.scope().clone(),
        0..18_000,
        vec![3600..7200, 10_800..14_400],
    )
}

#[test]
fn copied_hevc_originals_keep_source_only_nals_and_survive_native_reopen() -> TestResult {
    let packets = hevc_recording_support::packets()?;
    let originals = vec![
        hevc_recording_support::prepare(&packets[..8], &hevc_recording_support::timings(2))?,
        hevc_catalog_support::window(90_000)?,
        hevc_catalog_support::window(180_000)?,
    ];
    let scope = hevc_catalog_support::scope()?;
    let first = originals.first().ok_or("missing HEVC fixture")?;
    let restored = restore::<HevcArchiveCodec>(first.publication_plan(), &scope)?;
    assert_eq!(first.source_only_nals(), 3);
    assert_eq!(restored.source_only_nals(), first.source_only_nals());
    assert_eq!(restored.samples(), first.samples());
    assert_eq!(restored.mappings(), first.mappings());
    publish_and_reopen::<HevcArchiveCodec>(
        "restore_hevc",
        originals,
        scope,
        0..252_000,
        vec![36_000..90_000, 162_000..180_000],
    )
}

fn refuses_copied_mutations<C: ArchiveCodec>(
    original: &C::Recording,
    scope: &CatalogScope,
) -> TestResult {
    let plan = C::plan(original);
    let root = plan.manifest().root();
    let manifest = plan.manifest().canonical_bytes();
    assert!(matches!(
        C::restore_recording(
            ContentDigest::sha256(b"different-independent-pin"),
            &manifest,
            copied_objects(plan),
            scope,
        ),
        Err(ArchiveError::Metadata)
    ));
    let mut trailing = manifest.clone();
    trailing.push(0);
    assert!(matches!(
        C::restore_recording(
            ContentDigest::sha256(&trailing),
            &trailing,
            copied_objects(plan),
            scope,
        ),
        Err(ArchiveError::Metadata)
    ));
    for role in 0..4 {
        let mut copied = copied_objects(plan);
        *copied[role].last_mut().ok_or("empty fixture object")? ^= 1;
        assert!(
            matches!(
                C::restore_recording(root, &manifest, copied, scope),
                Err(ArchiveError::Storage(RecordingIoError::Content(_)))
            ),
            "altered object role {role} was not refused by native verification"
        );
    }
    let mut extra_children = plan.manifest().children().to_vec();
    extra_children.retain(|child| Some(*child) != plan.manifest().metadata_digest());
    extra_children.push(ContentDigest::sha256(b"unrequested-opaque-leaf"));
    let expanded = ObjectManifest::new(
        C::RECORDING_KIND,
        extra_children,
        plan.manifest().metadata_digest(),
    )?;
    assert!(matches!(
        C::restore_recording(
            expanded.root(),
            &expanded.canonical_bytes(),
            copied_objects(plan),
            scope,
        ),
        Err(ArchiveError::Storage(RecordingIoError::Content(
            RecordingError::Digest
        )))
    ));
    Ok(())
}

#[test]
fn wrong_pins_noncanonical_manifests_mutated_children_and_extra_leaves_are_refused() -> TestResult {
    refuses_copied_mutations::<AvcArchiveCodec>(&window(1, 0)?, namespace()?.scope())?;
    refuses_copied_mutations::<HevcArchiveCodec>(
        &hevc_catalog_support::window(0)?,
        &hevc_catalog_support::scope()?,
    )
}

fn refuses_scope_substitution<C: ArchiveCodec>(
    original: &C::Recording,
    scope: &CatalogScope,
) -> TestResult {
    let plan = C::plan(original);
    for field in 0..8 {
        let mut substituted = scope.clone();
        match field {
            0 => substituted.recording.sensor = SensorId::parse("another-sensor")?,
            1 => substituted.recording.stream = StreamId::parse("another-stream")?,
            2 => substituted.recording.generation += 1,
            3 => substituted.recording.anchor = ContentDigest::sha256(b"another-anchor"),
            4 => substituted.recording.receive_clock = ContentDigest::sha256(b"another-clock"),
            5 => substituted.time_scale += 1,
            6 => substituted.recording.generation = 0,
            _ => substituted.time_scale = 0,
        }
        assert!(
            matches!(
                C::restore_recording(
                    plan.manifest().root(),
                    &plan.manifest().canonical_bytes(),
                    copied_objects(plan),
                    &substituted,
                ),
                Err(ArchiveError::Scope)
                    | Err(ArchiveError::Storage(RecordingIoError::Content(
                        RecordingError::Scope
                    )))
            ),
            "scope field {field} was not pinned"
        );
    }
    Ok(())
}

#[test]
fn every_recorded_scope_coordinate_and_the_declared_tick_rate_are_pinned() -> TestResult {
    refuses_scope_substitution::<AvcArchiveCodec>(&window(1, 0)?, namespace()?.scope())?;
    refuses_scope_substitution::<HevcArchiveCodec>(
        &hevc_catalog_support::window(0)?,
        &hevc_catalog_support::scope()?,
    )
}

#[test]
fn codec_selection_is_typed_and_cannot_fall_back_to_a_manifest_tag() -> TestResult {
    let avc = window(1, 0)?;
    let hevc = hevc_catalog_support::window(0)?;
    assert!(restore::<HevcArchiveCodec>(&avc, namespace()?.scope()).is_err());
    assert!(
        restore::<AvcArchiveCodec>(hevc.publication_plan(), &hevc_catalog_support::scope()?)
            .is_err()
    );
    Ok(())
}

fn refuses_rehashed_media<C: ArchiveCodec>(
    original: &C::Recording,
    scope: &CatalogScope,
) -> TestResult {
    let plan = C::plan(original);
    let mut copied = copied_objects(plan);
    let old = ContentDigest::sha256(&copied[2]).bytes();
    *copied[2].last_mut().ok_or("empty media")? ^= 1;
    let changed = ContentDigest::sha256(&copied[2]).bytes();
    let positions: Vec<_> = copied[3]
        .windows(old.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == old.as_ref()).then_some(at))
        .collect();
    assert_eq!(positions.len(), 1, "fixture media digest is not unique");
    let at = positions[0];
    copied[3][at..at + changed.len()].copy_from_slice(&changed);
    let manifest = ObjectManifest::new(
        C::RECORDING_KIND,
        copied[..3].iter().map(|bytes| ContentDigest::sha256(bytes)),
        Some(ContentDigest::sha256(&copied[3])),
    )?;
    // Every object hash, index child reference and independently supplied root now agrees.
    // Only native source replay can establish that the media is not the original rendition.
    assert!(matches!(
        C::restore_recording(manifest.root(), &manifest.canonical_bytes(), copied, scope),
        Err(ArchiveError::Storage(RecordingIoError::Content(
            RecordingError::Source | RecordingError::Malformed | RecordingError::Media(_)
        )))
    ));
    Ok(())
}

#[test]
fn rehashing_every_reference_cannot_replace_native_source_verification() -> TestResult {
    refuses_rehashed_media::<AvcArchiveCodec>(&window(1, 0)?, namespace()?.scope())?;
    refuses_rehashed_media::<HevcArchiveCodec>(
        &hevc_catalog_support::window(0)?,
        &hevc_catalog_support::scope()?,
    )
}

#[test]
fn aggregate_object_and_manifest_budget_is_checked_before_parsing_or_hashing() -> TestResult {
    let copied = std::array::from_fn(|_| vec![0; MAX_RECORDING_BYTES / 4]);
    assert!(matches!(
        AvcArchiveCodec::restore_recording(
            ContentDigest::sha256(b"independent-pin"),
            b"x",
            copied,
            namespace()?.scope(),
        ),
        Err(ArchiveError::Limit)
    ));
    Ok(())
}

#[test]
fn decode_clock_is_a_fresh_explicit_catalog_assertion_not_invented_recording_metadata() -> TestResult
{
    let original = window(1, 0)?;
    let ns = namespace()?;
    let mut destination_scope = ns.scope().clone();
    destination_scope.decode_clock = ContentDigest::sha256(b"explicit-destination-decode-basis");
    let restored = restore::<AvcArchiveCodec>(&original, &destination_scope)?;
    exact_original(&restored, &original);
    assert_ne!(
        CodecArchiveNamespace::<AvcArchiveCodec>::new(destination_scope)?.digest(),
        ns.digest()
    );
    Ok(())
}
