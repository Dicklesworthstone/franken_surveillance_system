#![forbid(unsafe_code)]
//! Root-last replay companions through the existing explicit local I/O owner.

use super::*;
use crate::rtsp::recording::hevc::local::load_hevc_recording;
use crate::rtsp::recording::local::load_recording;
use fss_publication::{
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint,
};

const MAX_REPLAY_ROOT_BYTES: usize = 16 * 1024;

/// Publish only after every named original is durable and natively reverified.
/// Existing roots and source objects are never rewritten or deleted. Preserve
/// this exact immutable receipt across an indeterminate publication and reopen
/// the existing owner before retrying when its storage error requires that.
pub fn publish_replay_receipt(
    receipt: &ReplayReceipt,
    publisher: &mut LocalRootPublisher,
    cancel: &dyn PublishCancellation,
) -> Result<LocalPublicationReceipt> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    let slot = receipt.slot()?;
    if publisher
        .root(&slot)
        .is_some_and(|known| known.root != receipt.root())
    {
        return Err(RecordingIoError::RootConflict.into());
    }
    if receipt.metadata.len() > publisher.limits().spool.max_object_bytes
        || receipt.manifest.canonical_bytes().len() > publisher.limits().spool.max_object_bytes
        || receipt.manifest.children().len() > publisher.limits().max_children
    {
        return Err(RecordingIoError::Budget.into());
    }
    verify_originals(publisher, receipt, cancel, &mut NoopVisitor)?;
    live_originals(publisher, receipt, cancel)?;
    let observed = publisher
        .stage_object(receipt.metadata_bytes())
        .map_err(RecordingIoError::from)?;
    if Some(observed) != receipt.manifest.metadata_digest() {
        return Err(ReplayReceiptError::Digest);
    }
    cancelled(cancel)?;
    live_originals(publisher, receipt, cancel)?;
    publisher
        .publish_cancellable(&slot, receipt.manifest(), cancel)
        .map_err(RecordingIoError::from)
        .map_err(ReplayReceiptError::from)
}

/// Cold-load one pinned receipt and repeat original native source verification.
/// The expected request and complete scope are independent pins. No URI lookup,
/// directory scan, latest-pointer fallback, or historical-frame UTC inference occurs.
pub fn load_replay_receipt(
    publisher: &LocalRootPublisher,
    expected_root: ContentDigest,
    expected_scope: &CatalogScope,
    expected_request: ContentDigest,
    cancel: &dyn PublishCancellation,
) -> Result<ReplayReceipt> {
    load_codec_receipt(
        publisher,
        ReplayCodec::Avc,
        expected_root,
        expected_scope,
        expected_request,
        cancel,
    )
}

/// Cold-load an explicitly selected HEVC receipt using the native HEVC source
/// verifier. No stored tag, manifest, or AVC fallback may select another codec.
pub fn load_hevc_replay_receipt(
    publisher: &LocalRootPublisher,
    expected_root: ContentDigest,
    expected_scope: &CatalogScope,
    expected_request: ContentDigest,
    cancel: &dyn PublishCancellation,
) -> Result<ReplayReceipt> {
    load_codec_receipt(
        publisher,
        ReplayCodec::Hevc,
        expected_root,
        expected_scope,
        expected_request,
        cancel,
    )
}

fn load_codec_receipt(
    publisher: &LocalRootPublisher,
    expected_codec: ReplayCodec,
    expected_root: ContentDigest,
    expected_scope: &CatalogScope,
    expected_request: ContentDigest,
    cancel: &dyn PublishCancellation,
) -> Result<ReplayReceipt> {
    load_codec_receipt_visit(
        publisher,
        expected_codec,
        expected_root,
        expected_scope,
        expected_request,
        cancel,
        &mut NoopVisitor,
    )
}

/// Only sealed native windows reach this internal callback, after exact proof equality.
pub(crate) enum VerifiedOriginal<'a> {
    Avc(&'a PreparedRecording),
    Hevc(&'a PreparedHevcRecording),
}

/// Internal bounded projections may preflight metadata before original I/O. They cannot
/// replace native source verification or the final root/tombstone revalidation.
pub(crate) trait ReceiptVisitor {
    fn admit_receipt(&mut self, receipt: &ReplayReceipt) -> Result<()>;
    fn original(
        &mut self,
        ordinal: usize,
        proof: &ReplayWindowProof,
        original: VerifiedOriginal<'_>,
    ) -> Result<()>;
}
struct NoopVisitor;
impl ReceiptVisitor for NoopVisitor {
    fn admit_receipt(&mut self, _: &ReplayReceipt) -> Result<()> {
        Ok(())
    }
    fn original(&mut self, _: usize, _: &ReplayWindowProof, _: VerifiedOriginal<'_>) -> Result<()> {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_codec_receipt_visit(
    publisher: &LocalRootPublisher,
    expected_codec: ReplayCodec,
    expected_root: ContentDigest,
    expected_scope: &CatalogScope,
    expected_request: ContentDigest,
    cancel: &dyn PublishCancellation,
    visitor: &mut dyn ReceiptVisitor,
) -> Result<ReplayReceipt> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    if !valid_digest(expected_root) || !valid_digest(expected_request) {
        return Err(ReplayReceiptError::Digest);
    }
    let slot = codec_replay_slot(expected_codec, expected_scope, expected_request)?;
    durable_root(publisher, &slot, expected_root)?;
    let root_bytes = read_object(publisher, expected_root, MAX_REPLAY_ROOT_BYTES, cancel)?;
    if root_bytes.len() > MAX_REPLAY_ROOT_BYTES {
        return Err(ReplayReceiptError::Limit);
    }
    let manifest = ObjectManifest::from_canonical_bytes(&root_bytes)
        .map_err(|_| ReplayReceiptError::Malformed)?;
    if manifest.root() != expected_root
        || manifest.kind() != expected_codec.receipt_kind()
        || manifest.children().len() > MAX_REPLAY_WINDOWS * 5 + 1
    {
        return Err(ReplayReceiptError::Digest);
    }
    let metadata_digest = manifest
        .metadata_digest()
        .ok_or(ReplayReceiptError::Malformed)?;
    let metadata_maximum = MAX_REPLAY_RECEIPT_BYTES
        .checked_sub(root_bytes.len())
        .ok_or(ReplayReceiptError::Limit)?;
    let metadata = read_object(publisher, metadata_digest, metadata_maximum, cancel)?;
    if metadata
        .len()
        .checked_add(root_bytes.len())
        .is_none_or(|bytes| bytes > MAX_REPLAY_RECEIPT_BYTES)
    {
        return Err(ReplayReceiptError::Limit);
    }
    let receipt = wire::decode(&metadata, expected_codec, expected_scope, expected_request)?;
    if receipt.manifest != manifest {
        return Err(ReplayReceiptError::Digest);
    }
    visitor.admit_receipt(&receipt)?;
    live_originals(publisher, &receipt, cancel)?;
    verify_originals(publisher, &receipt, cancel, visitor)?;
    // Revalidate visible and tombstone bindings after native source work, before
    // releasing a complete receipt. No returned descriptor is trusted by hash alone.
    durable_root(publisher, &slot, expected_root)?;
    live_originals(publisher, &receipt, cancel)?;
    if read_object(publisher, expected_root, MAX_REPLAY_ROOT_BYTES, cancel)? != root_bytes
        || read_object(publisher, metadata_digest, metadata_maximum, cancel)? != metadata
    {
        return Err(ReplayReceiptError::Digest);
    }
    cancelled(cancel)?;
    Ok(receipt)
}

fn verify_originals(
    publisher: &LocalRootPublisher,
    receipt: &ReplayReceipt,
    cancel: &dyn PublishCancellation,
    visitor: &mut dyn ReceiptVisitor,
) -> Result<()> {
    for (ordinal, window) in receipt.windows().iter().enumerate() {
        cancelled(cancel)?;
        durable_root(publisher, window.slot(), window.root())?;
        // Bound original media residence to one window at a time. Native verification
        // and descriptor equality always precede the read-only projection callback.
        match receipt.request.codec() {
            ReplayCodec::Avc => {
                let recording = load_recording(
                    publisher,
                    window.slot(),
                    window.root(),
                    &receipt.scope.recording,
                    cancel,
                )?;
                let actual = ReplayWindowProof::from_avc(window.slot().clone(), &recording)?;
                if &actual != window {
                    return Err(ReplayReceiptError::WindowMismatch);
                }
                visitor.original(ordinal, window, VerifiedOriginal::Avc(&recording))?;
            }
            ReplayCodec::Hevc => {
                let recording = load_hevc_recording(
                    publisher,
                    window.slot(),
                    window.root(),
                    &receipt.scope.recording,
                    cancel,
                )?;
                let actual = ReplayWindowProof::from_hevc(window.slot().clone(), &recording)?;
                if &actual != window {
                    return Err(ReplayReceiptError::WindowMismatch);
                }
                visitor.original(ordinal, window, VerifiedOriginal::Hevc(&recording))?;
            }
        }
    }
    Ok(())
}

/// Revalidate the same source owner's receipt, window slots and deletion state at an import
/// publication boundary. This does not replace native verification of the retained bytes.
pub(crate) fn revalidate_receipt(
    publisher: &LocalRootPublisher,
    receipt: &ReplayReceipt,
    cancel: &dyn PublishCancellation,
) -> Result<()> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    durable_root(publisher, &receipt.slot()?, receipt.root())?;
    live_originals(publisher, receipt, cancel)
}

fn live_originals(
    publisher: &LocalRootPublisher,
    receipt: &ReplayReceipt,
    cancel: &dyn PublishCancellation,
) -> Result<()> {
    cancelled(cancel)?;
    owner_ready(publisher)?;
    for window in receipt.windows() {
        durable_root(publisher, window.slot(), window.root())?;
    }
    for tombstone in publisher.tombstones() {
        if *tombstone == receipt.root()
            || receipt.manifest.children().binary_search(tombstone).is_ok()
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
    maximum: usize,
    cancel: &dyn PublishCancellation,
) -> Result<Vec<u8>> {
    cancelled(cancel)?;
    if publisher.tombstones().any(|tombstone| *tombstone == value) {
        return Err(RecordingIoError::Tombstoned.into());
    }
    publisher
        .spool()
        .read_bounded(value, maximum)
        .map_err(|error| match error {
            fss_object::SpoolError::Corrupt {
                kind: fss_object::CorruptionKind::DeclaredLengthExceedsLimit { .. },
                ..
            } => ReplayReceiptError::Limit,
            error => RecordingIoError::Spool(error).into(),
        })
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

pub(super) fn cancelled(cancel: &dyn PublishCancellation) -> Result<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        return Err(RecordingIoError::Cancelled.into());
    }
    Ok(())
}
