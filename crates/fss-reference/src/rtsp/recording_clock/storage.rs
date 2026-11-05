#![forbid(unsafe_code)]
//! Root-last companion custody and actual native source replay on every cold load.

use super::*;
use crate::rtsp::recording::hevc::local::load_hevc_recording;
use crate::rtsp::recording::local::load_recording;
use fss_publication::{
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint,
};

const MAX_CLOCK_ROOT_BYTES: usize = 16 * 1024;

/// Publish clock metadata only after every referenced original slot is durable
/// and its native source packets have been reverified. The existing publisher
/// owns staging, closure verification, tombstones, cancellation and durability.
/// Refusal never deletes originals or changes their four-child recording roots.
/// Preserve this exact immutable index across an indeterminate publication.
pub fn publish_clock_index(
    index: &RecordingClockIndex,
    publisher: &mut LocalRootPublisher,
    cancel: &dyn PublishCancellation,
) -> Result<LocalPublicationReceipt> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    let slot = clock_slot(index.codec, &index.scope)?;
    if publisher
        .root(&slot)
        .is_some_and(|known| known.root != index.root())
    {
        return Err(RecordingIoError::RootConflict.into());
    }
    if index.index.len() > publisher.limits().spool.max_object_bytes
        || index.manifest.canonical_bytes().len() > publisher.limits().spool.max_object_bytes
        || index.manifest.children().len() > publisher.limits().max_children
    {
        return Err(RecordingIoError::Budget.into());
    }
    verify_originals(publisher, index, cancel)?;
    live_originals(publisher, index, cancel)?;
    let observed = publisher
        .stage_object(&index.index)
        .map_err(RecordingIoError::from)?;
    if Some(observed) != index.manifest.metadata_digest() {
        return Err(RecordingClockError::Digest);
    }
    cancelled(cancel)?;
    live_originals(publisher, index, cancel)?;
    publisher
        .publish_cancellable(&slot, &index.manifest, cancel)
        .map_err(RecordingIoError::from)
        .map_err(RecordingClockError::from)
}

/// Load one independently pinned clock companion through an existing owner.
///
/// The selected codec/scope fixes the native verifier. Metadata must reconstruct
/// exactly, every original slot/root/leaf remains current and untombstoned, and
/// every saved packet coordinate must equal the actual source replay. No media
/// bytes are returned. Original source reads are bounded independently by the
/// existing recording and publisher limits; this is not a metadata-only I/O claim.
pub fn load_clock_index(
    publisher: &LocalRootPublisher,
    expected_root: ContentDigest,
    expected_scope: &CatalogScope,
    expected_codec: RecordingClockCodec,
    cancel: &dyn PublishCancellation,
) -> Result<RecordingClockIndex> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    if !valid_digest(expected_root) {
        return Err(RecordingClockError::Digest);
    }
    let slot = clock_slot(expected_codec, expected_scope)?;
    durable_root(publisher, &slot, expected_root)?;
    let root_bytes = read_object(publisher, expected_root, cancel)?;
    if root_bytes.len() > MAX_CLOCK_ROOT_BYTES {
        return Err(RecordingClockError::Limit);
    }
    let manifest = ObjectManifest::from_canonical_bytes(&root_bytes)
        .map_err(|_| RecordingClockError::Malformed)?;
    if manifest.root() != expected_root
        || manifest.kind() != CLOCK_INDEX_KIND
        || manifest.children().len() > MAX_CLOCK_WINDOWS * 5 + 1
    {
        return Err(RecordingClockError::Digest);
    }
    let metadata_digest = manifest
        .metadata_digest()
        .ok_or(RecordingClockError::Malformed)?;
    let metadata = read_object(publisher, metadata_digest, cancel)?;
    if metadata
        .len()
        .checked_add(root_bytes.len())
        .is_none_or(|bytes| bytes > MAX_CLOCK_INDEX_BYTES)
    {
        return Err(RecordingClockError::Limit);
    }
    let index = wire::decode(&metadata, expected_scope, expected_codec)?;
    if index.manifest != manifest {
        return Err(RecordingClockError::Digest);
    }
    live_originals(publisher, &index, cancel)?;
    verify_originals(publisher, &index, cancel)?;
    // Recheck the selected companion and all current root/tombstone bindings
    // after the source work, before releasing a complete result.
    durable_root(publisher, &slot, expected_root)?;
    live_originals(publisher, &index, cancel)?;
    if read_object(publisher, expected_root, cancel)? != root_bytes
        || read_object(publisher, metadata_digest, cancel)? != metadata
    {
        return Err(RecordingClockError::Digest);
    }
    cancelled(cancel)?;
    Ok(index)
}

fn verify_originals(
    publisher: &LocalRootPublisher,
    index: &RecordingClockIndex,
    cancel: &dyn PublishCancellation,
) -> Result<()> {
    for entry in &index.windows {
        cancelled(cancel)?;
        durable_root(publisher, entry.slot(), entry.root())?;
        // Load and drop one bounded original at a time, never all media in a page.
        let actual = match index.codec {
            RecordingClockCodec::Avc => {
                let recording = load_recording(
                    publisher,
                    entry.slot(),
                    entry.root(),
                    &index.scope.recording,
                    cancel,
                )?;
                ClockWindow::from_avc(entry.slot().clone(), &recording)?
            }
            RecordingClockCodec::Hevc => {
                let recording = load_hevc_recording(
                    publisher,
                    entry.slot(),
                    entry.root(),
                    &index.scope.recording,
                    cancel,
                )?;
                ClockWindow::from_hevc(entry.slot().clone(), &recording)?
            }
        };
        if actual != entry.window {
            return Err(RecordingClockError::WindowMismatch);
        }
    }
    Ok(())
}

fn live_originals(
    publisher: &LocalRootPublisher,
    index: &RecordingClockIndex,
    cancel: &dyn PublishCancellation,
) -> Result<()> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    for entry in &index.windows {
        durable_root(publisher, entry.slot(), entry.root())?;
    }
    for tombstone in publisher.tombstones() {
        if *tombstone == index.root() || index.manifest.children().binary_search(tombstone).is_ok()
        {
            return Err(RecordingIoError::Tombstoned.into());
        }
    }
    Ok(())
}

fn durable_root(
    publisher: &LocalRootPublisher,
    slot: &SlotName,
    root: ContentDigest,
) -> Result<()> {
    let known = publisher.root(slot).ok_or(RecordingIoError::NotDurable)?;
    if known.root != root {
        return Err(RecordingIoError::RootConflict.into());
    }
    if known.state != LocalPublicationState::Durable {
        return Err(RecordingIoError::NotDurable.into());
    }
    if publisher.tombstones().any(|value| *value == root) {
        return Err(RecordingIoError::Tombstoned.into());
    }
    Ok(())
}

fn read_object(
    publisher: &LocalRootPublisher,
    value: ContentDigest,
    cancel: &dyn PublishCancellation,
) -> Result<Vec<u8>> {
    cancelled(cancel)?;
    if publisher.tombstones().any(|tombstone| *tombstone == value) {
        return Err(RecordingIoError::Tombstoned.into());
    }
    publisher
        .spool()
        .read(value)
        .map_err(RecordingIoError::Spool)
        .map_err(RecordingClockError::from)
}

fn owner_ready(publisher: &LocalRootPublisher) -> Result<()> {
    if publisher.is_poisoned() {
        return Err(RecordingIoError::ReopenRequired.into());
    }
    if publisher.limits().spool.max_object_bytes > MAX_RECORDING_BYTES {
        return Err(RecordingIoError::Budget.into());
    }
    Ok(())
}

fn cancelled(cancel: &dyn PublishCancellation) -> Result<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        return Err(RecordingIoError::Cancelled.into());
    }
    Ok(())
}
