#![forbid(unsafe_code)]
//! Canonical retained clock interpretation without promoting it to source replay.

use super::*;
use crate::site::clock::{ClockCorrelationPolicy, ClockOffsetInterval};

/// Internally consistent retained clock assertions, without packet/source verification.
///
/// This sealed type deliberately cannot be passed to [`publish_clock_index`]. Its raw
/// exchange, sample brackets, lifetime/drift policy and derived intervals reconstruct
/// canonically, but it does not establish that the claimed admissions occurred or that
/// they describe the original packet bytes. Use [`load_clock_index`] when those original
/// source coordinates must be replayed. Neither API authenticates the local time server,
/// establishes camera exposure time, or proves continuous physical coverage.
#[derive(Debug)]
pub struct RecordingClockMetadata {
    index: RecordingClockIndex,
    offset: ClockOffsetInterval,
}

impl RecordingClockMetadata {
    /// Canonical retained companion, whose publication must be verified by the I/O owner.
    #[must_use]
    pub const fn manifest(&self) -> &ObjectManifest {
        self.index.manifest()
    }

    /// Exact immutable companion identity.
    #[must_use]
    pub fn root(&self) -> ContentDigest {
        self.index.root()
    }

    /// Caller-pinned recording generation and both clock identities.
    #[must_use]
    pub const fn scope(&self) -> &CatalogScope {
        self.index.scope()
    }

    /// Codec supplied independently by the caller, not inferred from stored bytes.
    #[must_use]
    pub const fn codec(&self) -> RecordingClockCodec {
        self.index.codec()
    }

    /// Declared capture approval identity; not a current effect authorization.
    #[must_use]
    pub const fn approval_digest(&self) -> ContentDigest {
        self.index.approval_digest()
    }

    /// Retained drift, sample-width and lifetime assumptions, not measured clock accuracy.
    #[must_use]
    pub const fn policy(&self) -> ClockCorrelationPolicy {
        self.index.exchange.policy
    }

    /// Conservative signed correction reconstructed from the unauthenticated exchange.
    #[must_use]
    pub const fn offset_interval(&self) -> ClockOffsetInterval {
        self.offset
    }

    /// Number of retained completed read/admission brackets that were reconstructed.
    #[must_use]
    pub fn bracket_count(&self) -> usize {
        self.index.brackets.len()
    }

    /// Retained window assertions in decode order, without original source replay.
    ///
    /// Every interval includes the declared drift and the read-completion extrema. A
    /// caller must bind every row to its independently pinned catalog before filtering;
    /// catalog members with no row cannot be excluded by a UTC request.
    #[must_use]
    pub fn windows(&self) -> &[ClockIndexEntry] {
        &self.index.windows
    }
}

/// Reconstruct one exact clock companion's canonical metadata without reading source bytes.
///
/// Checksum, selected codec/scope, original manifest closure, raw exchange, sampled
/// continuity, drift, synchronization age and every projected interval are checked using
/// the existing native clock owner. The result intentionally retains a weaker type than
/// a source-replayed [`RecordingClockIndex`]. The caller still owns current slot binding,
/// cancellation, aggregate read limits, tombstone checks and final revalidation.
pub fn verify_clock_metadata(
    manifest: &ObjectManifest,
    metadata: &[u8],
    expected_scope: &CatalogScope,
    expected_codec: RecordingClockCodec,
) -> Result<RecordingClockMetadata> {
    let manifest_bytes = manifest.canonical_bytes();
    if manifest_bytes.len() > 16 * 1024
        || manifest.children().len() > MAX_CLOCK_WINDOWS * 5 + 1
        || metadata
            .len()
            .checked_add(manifest_bytes.len())
            .is_none_or(|bytes| bytes > MAX_CLOCK_INDEX_BYTES)
    {
        return Err(RecordingClockError::Limit);
    }
    if manifest.kind() != CLOCK_INDEX_KIND || manifest.metadata_digest() != Some(digest(metadata)?)
    {
        return Err(RecordingClockError::Digest);
    }
    let index = wire::decode(metadata, expected_scope, expected_codec)?;
    if index.manifest() != manifest {
        return Err(RecordingClockError::Digest);
    }
    let offset = index.exchange.correlation()?.offset_interval();
    Ok(RecordingClockMetadata { index, offset })
}
