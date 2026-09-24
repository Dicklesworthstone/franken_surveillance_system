#![forbid(unsafe_code)]
//! HEVC readback using the existing root-last publisher and shared custody checks.

use super::super::local::{RecordingIoError, WindowFormat, load_window};
use super::*;
use fss_publication::{LocalRootPublisher, PublishCancellation, SlotName};

/// Reopen an exact durable HEVC root, rehash every child, and replay source
/// packets through the real HEVC assembly/remux owners before returning bytes.
///
/// The caller supplies the already-open I/O owner, slot, expected root and exact
/// scope. No filesystem discovery, codec fallback or implicit disclosure grant
/// occurs. Tombstones, conflicting roots, ambiguous owner state, quota and
/// cancellation use the same checks as AVC. A point-in-time verified read is
/// not a future retrievability, encryption, decode or physical-coverage claim.
///
/// Publish with RecordingPublication::new(recording.publication_plan(), ...).
/// The existing source-first/root-last write state machine is unchanged.
pub fn load_hevc_recording(
    publisher: &LocalRootPublisher,
    slot: &SlotName,
    expected_root: ContentDigest,
    scope: &RecordingScope,
    cancel: &dyn PublishCancellation,
) -> std::result::Result<PreparedHevcRecording, RecordingIoError> {
    let plan = load_window(
        publisher,
        slot,
        expected_root,
        scope,
        cancel,
        WindowFormat {
            kind: HEVC_RECORDING_KIND,
            references,
            verify: verify_summary,
        },
    )?;
    // The shared loader already replayed and compared the whole representation.
    // Decode only bounded immutable metadata for the typed HEVC getters.
    let index = wire::decode(plan.objects().index).map_err(RecordingIoError::Content)?;
    Ok(PreparedHevcRecording { plan, index })
}

fn references(bytes: &[u8]) -> Result<(RecordingScope, [ContentDigest; 3])> {
    let index = wire::decode(bytes)?;
    Ok((
        index.scope,
        [index.source, index.initialization, index.media],
    ))
}
fn verify_summary(
    manifest: &ObjectManifest,
    objects: RecordingObjects<'_>,
    scope: &RecordingScope,
) -> Result<RecordingSummary> {
    Ok(verify_hevc_recording(manifest, objects, scope)?.recording)
}
