#![forbid(unsafe_code)]
//! Exact source closure without an original publisher namespace or payload cache.
//!
//! The independently supplied pin selects the complete chain from its original first
//! observation. A successful verification proves those bytes at that read boundary,
//! not original publication durability, current access forever, a later archive head,
//! transport EOF, physical sensor identity or calibrated capture time.

use super::*;
use fss_core::CanonicalEncode;

/// Explicit current custody boundary for bounded canonical source objects.
///
/// Implementations carry their actual I/O authority (for example, the retained
/// deployment and its `ReplayCx`), apply current disclosure/tombstone policy, and
/// enforce `maximum` BEFORE allocation or reading an oversized stored object.
/// Cancellation and the shared work budget reach every read; neither a digest nor
/// this trait grants access. An implementation may also copy these exact bytes into
/// a separately authorized destination, but that publication is its own operation.
///
/// The verifier independently checks the returned length and SHA-256. Returning
/// bytes does not let a reader construct an unchecked `RetainedDatagram`.
pub trait DatagramObjectReader {
    /// Read at most `maximum` bytes under the caller's current authority.
    fn read_object(
        &mut self,
        digest: ContentDigest,
        maximum: usize,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<u8>>;
}

/// Sealed complete source metadata reconstructed from copied original objects.
///
/// No original filesystem path, publisher slot, decoded frame or payload cache is
/// retained. The exact pinned predecessor chain is verified in full; callers cannot
/// provide unchecked records, omit probation/RTCP/duplicates, or begin at a later
/// image and lose cached-quantizer ancestry. Later reads reverify the root, metadata
/// and payload through the current object reader.
#[derive(Debug)]
pub struct DetachedDatagramPrefix {
    archive: DatagramArchive,
}

impl DetachedDatagramPrefix {
    /// Verify every selected original, starting at the independently pinned head.
    ///
    /// The selected pin is not a count hint: all four fields must match the chain.
    /// Unlike live namespace recovery, this deliberately makes no claim about later
    /// observations or publisher slots that were not copied into the retained closure.
    /// Independent count/payload/object limits and precharged shared work bound the
    /// complete operation, including root/metadata reads, allocation and failed reads.
    pub fn recover(
        scope: DatagramScope,
        limits: DatagramArchiveLimits,
        selected: DatagramPin,
        reader: &mut dyn DatagramObjectReader,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        probe(cancel)?;
        work.charge(1)?;
        let mut archive = DatagramArchive::new(scope, limits)?;
        if selected.scope != archive.empty.scope
            || selected.head.algorithm() != DigestAlgorithm::Sha256
        {
            return Err(DatagramArchiveError::Sequence);
        }
        if selected.datagrams > limits.max_datagrams as u64
            || selected.datagrams > limits.max_scan_roots as u64
            || selected.payload_bytes > limits.max_payload_bytes
        {
            return Err(DatagramArchiveError::Limit);
        }
        let count = usize::try_from(selected.datagrams).map_err(|_| DatagramArchiveError::Limit)?;
        let allocation = count
            .checked_mul(std::mem::size_of::<DatagramRecord>())
            .and_then(|bytes| bytes.checked_add(count))
            .ok_or(DatagramArchiveError::Limit)?;
        work.charge(u64::try_from(allocation).map_err(|_| DatagramArchiveError::Limit)?)?;
        archive
            .records
            .try_reserve_exact(count)
            .map_err(|_| DatagramArchiveError::Limit)?;
        let mut expected = selected;
        let mut later_receive = None;
        for _ in 0..count {
            let original = archive.read_detached_root(expected.head, reader, cancel, work)?;
            let record = original.record;
            if record.pin != expected {
                return Err(DatagramArchiveError::Sequence);
            }
            if later_receive.is_some_and(|later| record.received_ns > later) {
                return Err(DatagramArchiveError::Source);
            }
            later_receive = Some(record.received_ns);
            expected = record.prior;
            archive.records.push(record);
        }
        if expected != archive.empty {
            return Err(DatagramArchiveError::Sequence);
        }
        archive.records.reverse();
        if archive.pin() != selected {
            return Err(DatagramArchiveError::Sequence);
        }
        probe(cancel)?;
        work.charge(0)?;
        Ok(Self { archive })
    }

    /// Complete independently selected original interpretation, not physical identity.
    pub fn scope(&self) -> &DatagramScope {
        self.archive.scope()
    }

    /// Exact original prefix, never a later publisher head or reconstructed-image digest.
    pub fn pin(&self) -> DatagramPin {
        self.archive.pin()
    }

    /// Verified original metadata in arrival order, including unusable observations.
    pub fn records(&self) -> &[DatagramRecord] {
        self.archive.records()
    }

    /// Re-read one original through CURRENT custody; stored metadata never bypasses I/O.
    /// Out-of-range is refusal, not end-of-stream or physical absence.
    pub fn read(
        &self,
        ordinal: u64,
        reader: &mut dyn DatagramObjectReader,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<RetainedDatagram> {
        self.archive.read_detached(ordinal, reader, cancel, work)
    }

    /// Reverify the same complete selected closure without changing its identity.
    pub fn revalidate(
        &self,
        reader: &mut dyn DatagramObjectReader,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<()> {
        probe(cancel)?;
        work.charge(1)?;
        for record in self.records() {
            self.read(record.pin.datagrams, reader, cancel, work)?;
        }
        probe(cancel)?;
        work.charge(0)?;
        Ok(())
    }

    /// Private read-only inventory for the existing native replay scheduler.
    pub(crate) fn archive(&self) -> &DatagramArchive {
        &self.archive
    }
}

impl DatagramArchive {
    /// Shared exact-object read used by detached replay, never an unchecked record adapter.
    pub(crate) fn read_detached(
        &self,
        ordinal: u64,
        reader: &mut dyn DatagramObjectReader,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<RetainedDatagram> {
        probe(cancel)?;
        work.charge(1)?;
        let index = ordinal
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(DatagramArchiveError::Sequence)?;
        let expected = self
            .records
            .get(index)
            .ok_or(DatagramArchiveError::Sequence)?;
        let original = self.read_detached_root(expected.pin.head, reader, cancel, work)?;
        if original.record != *expected {
            return Err(DatagramArchiveError::Metadata);
        }
        probe(cancel)?;
        work.charge(0)?;
        Ok(original)
    }

    fn read_detached_root(
        &self,
        root: ContentDigest,
        reader: &mut dyn DatagramObjectReader,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<RetainedDatagram> {
        let raw = self.detached_object(root, 1024, reader, cancel, work)?;
        let manifest = ObjectManifest::from_canonical_bytes(&raw)
            .map_err(|_| DatagramArchiveError::Metadata)?;
        if manifest.root() != root
            || manifest.kind() != RTSP_DATAGRAM_KIND
            || manifest.canonical_bytes() != raw
        {
            return Err(DatagramArchiveError::Metadata);
        }
        let metadata = self.detached_object(
            manifest
                .metadata_digest()
                .ok_or(DatagramArchiveError::Metadata)?,
            MAX_METADATA,
            reader,
            cancel,
            work,
        )?;
        // decode() also requires byte-identical metadata reencoding and SHA-256 pins.
        let record = DatagramRecord::decode(&metadata, root)?;
        if record.manifest()? != manifest || record.prior.scope != self.empty.scope {
            return Err(DatagramArchiveError::Metadata);
        }
        if ![self.scope.channels.0, self.scope.channels.1].contains(&record.channel) {
            return Err(DatagramArchiveError::Source);
        }
        if record.payload_bytes > MAX_DATAGRAM_BYTES
            || record.pin.datagrams > self.limits.max_datagrams as u64
            || record.pin.payload_bytes > self.limits.max_payload_bytes
        {
            return Err(DatagramArchiveError::Limit);
        }
        let bytes = self.detached_object(
            record.payload_digest,
            record.payload_bytes,
            reader,
            cancel,
            work,
        )?;
        if bytes.len() != record.payload_bytes {
            return Err(DatagramArchiveError::Source);
        }
        Ok(RetainedDatagram { record, bytes })
    }

    fn detached_object(
        &self,
        digest: ContentDigest,
        maximum: usize,
        reader: &mut dyn DatagramObjectReader,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<u8>> {
        probe(cancel)?;
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(DatagramArchiveError::Metadata);
        }
        let maximum = maximum.min(self.limits.max_spool_object_bytes);
        // Reserve traversal, copying, hashing and canonical verification BEFORE the
        // authority boundary. Repeated/missing/corrupt/oversized reads cost work too.
        work.charge(1024 + maximum as u64 * 8)?;
        let bytes = reader.read_object(digest, maximum, cancel, work)?;
        probe(cancel)?;
        if bytes.len() > maximum {
            return Err(DatagramArchiveError::Limit);
        }
        if ContentDigest::sha256(&bytes) != digest {
            return Err(DatagramArchiveError::Metadata);
        }
        work.charge(0)?;
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "detached/tests.rs"]
mod tests;
