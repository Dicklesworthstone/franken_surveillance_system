#![forbid(unsafe_code)]
//! Native source-closed retrieval through a read-only exact-slot capability.
//!
//! The existing writer-backed loader and its recovery semantics remain unchanged. This path
//! verifies only the explicitly selected immutable flat closure and invokes the same complete
//! codec replay verifier before returning it. Publication, local deletion and payload integrity
//! are observed twice. No atomic snapshot, future retrievability or remote authority is claimed.

use super::local::{RecordingIoError, WindowFormat, avc_references};
use super::*;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;
use fss_publication::{PublishCancellation, PublishCutPoint, SlotName};

type IoResult<T> = std::result::Result<T, RecordingIoError>;

/// Rehash exactly one AVC closure and replay its original RTP through the native codec owners.
/// The reader's whole-request allowances are shared with any preceding/following windows.
/// Explicit current authority/cancellation is checked around each selected object boundary.
pub fn load_pinned_recording(
    reader: &mut PinnedClosureReader<'_>,
    slot: &SlotName,
    expected_root: ContentDigest,
    scope: &RecordingScope,
    cancel: &dyn PublishCancellation,
) -> IoResult<PreparedRecording> {
    load_window(
        reader,
        slot,
        expected_root,
        scope,
        cancel,
        WindowFormat {
            kind: RECORDING_KIND,
            references: avc_references,
            verify: verify_recording,
        },
    )
}

fn guard(cancel: &dyn PublishCancellation) -> IoResult<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        Err(RecordingIoError::Cancelled)
    } else {
        Ok(())
    }
}

pub(super) fn load_window(
    reader: &mut PinnedClosureReader<'_>,
    slot: &SlotName,
    expected_root: ContentDigest,
    scope: &RecordingScope,
    cancel: &dyn PublishCancellation,
    format: WindowFormat,
) -> IoResult<PreparedRecording> {
    guard(cancel)?;
    if reader.limits().max_object_bytes > MAX_RECORDING_BYTES {
        return Err(RecordingIoError::Budget);
    }
    let manifest = reader
        .manifest(slot, expected_root)
        .map_err(RecordingIoError::Pinned)?;
    guard(cancel)?;
    if manifest.root() != expected_root
        || manifest.kind() != format.kind
        || manifest.children().len() != 4
    {
        return Err(RecordingIoError::Content(RecordingError::Digest));
    }
    let mut total = manifest.canonical_bytes().len();
    let mut read = |digest| -> IoResult<Vec<u8>> {
        guard(cancel)?;
        let remaining = MAX_RECORDING_BYTES
            .checked_sub(total)
            .ok_or(RecordingIoError::Budget)?;
        let bytes = reader
            .child(
                &manifest,
                digest,
                remaining.min(reader.limits().max_object_bytes),
            )
            .map_err(RecordingIoError::Pinned)?;
        guard(cancel)?;
        total = total
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_RECORDING_BYTES)
            .ok_or(RecordingIoError::Budget)?;
        Ok(bytes)
    };
    let index_digest = manifest
        .metadata_digest()
        .ok_or(RecordingIoError::Content(RecordingError::Malformed))?;
    let index = read(index_digest)?;
    let (indexed_scope, [source_digest, initialization_digest, media_digest]) =
        (format.references)(&index).map_err(RecordingIoError::Content)?;
    if &indexed_scope != scope {
        return Err(RecordingIoError::Content(RecordingError::Scope));
    }
    let expected = ObjectManifest::new(
        format.kind,
        [source_digest, initialization_digest, media_digest],
        Some(index_digest),
    )
    .map_err(|_| RecordingIoError::Content(RecordingError::Digest))?;
    if expected != manifest {
        return Err(RecordingIoError::Content(RecordingError::Digest));
    }
    let source = read(source_digest)?;
    let initialization = read(initialization_digest)?;
    let media = read(media_digest)?;
    let summary = (format.verify)(
        &manifest,
        RecordingObjects {
            source: &source,
            initialization: &initialization,
            media: &media,
            index: &index,
        },
        scope,
    )
    .map_err(RecordingIoError::Content)?;
    guard(cancel)?;
    reader
        .finish_root_with(&|| cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified))
        .map_err(RecordingIoError::Pinned)?;
    guard(cancel)?;
    Ok(PreparedRecording {
        manifest,
        source,
        initialization,
        media,
        index,
        summary,
    })
}
