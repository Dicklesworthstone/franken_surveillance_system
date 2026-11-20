#![forbid(unsafe_code)]
//! Lossless, bounded source-tail batch preparation.
//!
//! A batch retains the exact original bytes and each original framing and
//! disposition claim. Preparing one performs no I/O and does not consume the
//! retirement plan, establish capture time, or authenticate a camera.

use std::{collections::BTreeSet, fmt};

use fss_container::flv_avc::SourceKey;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;
use fss_packet::extended_flv::stream::{RecordKind, SearchMode, UnframedOrigin};

use super::{evidence, recording::SourceDisposition, retirement_source, source_evidence};

pub(super) const DOMAIN: &str = "fss.unifi-direct.flv-source-batch.v1";
pub(super) const KIND: &str = "unifi-direct-flv-source-batch-v1";
/// Maximum source records in one batch.
pub const MAX_RECORDS: usize = 2048;
/// Maximum original bytes in one batch.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;

/// A batch could not be prepared without consuming its source plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Identity, bounds, record disposition, or source order is invalid.
    Configuration,
    /// The first original record is larger than the chosen byte bound.
    FirstRecordTooLarge,
    /// Bounded allocation failed.
    Allocation,
    /// Canonical metadata or manifest creation failed.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi source batch refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One candidate graph over a prefix of the retained source plan.
/// The original plan remains unchanged until the caller explicitly transfers it.
pub struct Prepared {
    payload: Vec<u8>,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
    retention: ContentDigest,
    records: usize,
    start: u64,
    end: u64,
}

impl Prepared {
    /// Prepare a nonempty contiguous prefix under explicit item and byte caps.
    /// The camera, source key, and framing are claims, not identity evidence.
    pub fn new(
        plan: &retirement_source::Plan,
        key: SourceKey,
        camera: ContentDigest,
        retention: ContentDigest,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        Self::new_items(
            plan.items_in_order(),
            key,
            camera,
            retention,
            max_records,
            max_bytes,
        )
    }

    pub(super) fn from_items(
        items: &[retirement_source::Item],
        key: SourceKey,
        camera: ContentDigest,
        retention: ContentDigest,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        Self::new_items(items.iter(), key, camera, retention, items.len(), max_bytes)
    }

    fn new_items<'a, I>(
        items: I,
        key: SourceKey,
        camera: ContentDigest,
        retention: ContentDigest,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Self, Error>
    where
        I: Iterator<Item = &'a retirement_source::Item> + Clone,
    {
        let valid_digest = |d: ContentDigest| {
            d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
        };
        if key.connection == 0
            || key.generation == 0
            || !valid_digest(camera)
            || !valid_digest(retention)
            || !(1..=MAX_RECORDS).contains(&max_records)
            || !(1..=MAX_BYTES).contains(&max_bytes)
        {
            return Err(Error::Configuration);
        }
        let mut count = 0usize;
        let mut total = 0usize;
        let mut start = None;
        let mut end = None;
        for item in items.clone().take(max_records) {
            source_evidence::validate_input(
                &item.record,
                key,
                item.disposition,
                camera,
                retention,
                MAX_BYTES,
            )
            .map_err(|_| Error::Configuration)?;
            if end.is_some_and(|expected| expected != item.record.offset()) {
                return Err(Error::Configuration);
            }
            let next = total
                .checked_add(item.record.bytes().len())
                .ok_or(Error::Configuration)?;
            if next > max_bytes {
                if count == 0 {
                    return Err(Error::FirstRecordTooLarge);
                }
                break;
            }
            start.get_or_insert(item.record.offset());
            end = Some(
                item.record
                    .offset()
                    .checked_add(item.record.bytes().len() as u64)
                    .ok_or(Error::Configuration)?,
            );
            total = next;
            count += 1;
        }
        let (Some(start), Some(end)) = (start, end) else {
            return Err(Error::Configuration);
        };
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(total)
            .map_err(|_| Error::Allocation)?;
        for item in items.clone().take(count) {
            payload.extend_from_slice(item.record.bytes());
        }
        let digest = ContentDigest::sha256(&payload);
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DOMAIN);
        encoder.digest(retention);
        encoder.bool(false);
        encoder.u64(key.connection);
        encoder.u64(key.generation);
        encoder.digest(camera);
        encoder.u64(count as u64);
        encoder.u64(total as u64);
        encoder.digest(digest);
        for item in items.take(count) {
            encoder.u8(match item.disposition {
                SourceDisposition::Header => 0,
                SourceDisposition::Configuration => 1,
                SourceDisposition::PreRoll => 2,
                SourceDisposition::Unclosed => 3,
                SourceDisposition::Unframed => 4,
                SourceDisposition::BootstrapCopy => 5,
            });
            evidence::encode_record(&mut encoder, &item.record);
        }
        let metadata = encoder.finish_checked().map_err(|_| Error::Encoding)?;
        let metadata_digest = ContentDigest::sha256(&metadata);
        if digest == metadata_digest {
            return Err(Error::Encoding);
        }
        let mut children = BTreeSet::new();
        children.insert(digest);
        let manifest = ObjectManifest::new(KIND, children, Some(metadata_digest))
            .map_err(|_| Error::Encoding)?;
        Ok(Self {
            payload,
            metadata,
            manifest,
            retention,
            records: count,
            start,
            end,
        })
    }

    /// Exact number of source records represented by this prefix.
    pub fn records(&self) -> usize {
        self.records
    }
    /// First connection-relative byte offset.
    pub fn start(&self) -> u64 {
        self.start
    }
    /// Exclusive connection-relative byte offset.
    pub fn end(&self) -> u64 {
        self.end
    }
    /// Candidate manifest, not a publication receipt.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    /// Reconstruct the same candidate from a validated staged or ledgered batch.
    /// The original payload is revalidated because callers can inspect and edit it.
    pub fn from_recovered(recovered: Recovered) -> Result<Self, Error> {
        let Recovered {
            payload,
            metadata,
            retention,
            ..
        } = recovered;
        let checked = recover(&metadata, payload, retention)?;
        let records = checked.records.len();
        let start = checked.records.first().ok_or(Error::Configuration)?.offset;
        let last = checked.records.last().ok_or(Error::Configuration)?;
        let end = last
            .offset
            .checked_add((last.range.end - last.range.start) as u64)
            .ok_or(Error::Configuration)?;
        let payload_digest = ContentDigest::sha256(&checked.payload);
        let metadata_digest = ContentDigest::sha256(&metadata);
        if payload_digest == metadata_digest {
            return Err(Error::Encoding);
        }
        let mut children = BTreeSet::new();
        children.insert(payload_digest);
        let manifest = ObjectManifest::new(KIND, children, Some(metadata_digest))
            .map_err(|_| Error::Encoding)?;
        Ok(Self {
            payload: checked.payload,
            metadata,
            manifest,
            retention,
            records,
            start,
            end,
        })
    }
    pub(super) fn retention(&self) -> ContentDigest {
        self.retention
    }
    pub(super) fn payloads(&self) -> impl Iterator<Item = &[u8]> {
        [self.payload.as_slice(), self.metadata.as_slice()].into_iter()
    }
}

/// One recovered record's original claims and range inside the batch payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// Connection-relative original byte offset.
    pub offset: u64,
    /// Explicit disposition at retirement.
    pub disposition: SourceDisposition,
    /// Original local framing claim.
    pub kind: RecordKind,
    /// Range of original bytes within [`Recovered::payload`].
    pub range: std::ops::Range<usize>,
}

/// Validated source batch; claims are not camera authentication or capture time.
pub struct Recovered {
    /// Caller-supplied source connection and generation.
    pub key: SourceKey,
    /// Caller-supplied camera claim.
    pub camera_claim: ContentDigest,
    /// Exact original bytes in connection order.
    pub payload: Vec<u8>,
    /// Original per-record boundaries and framing claims.
    pub records: Vec<Record>,
    metadata: Vec<u8>,
    retention: ContentDigest,
}

pub(super) fn recover(
    metadata: &[u8],
    payload: Vec<u8>,
    retention: ContentDigest,
) -> Result<Recovered, Error> {
    if payload.is_empty() || payload.len() > MAX_BYTES {
        return Err(Error::Configuration);
    }
    let mut d = CanonicalDecoder::new(metadata);
    if d.text().map_err(|_| Error::Encoding)? != DOMAIN
        || d.digest().map_err(|_| Error::Encoding)? != retention
        || d.bool().map_err(|_| Error::Encoding)?
    {
        return Err(Error::Configuration);
    }
    let key = SourceKey {
        connection: d.u64().map_err(|_| Error::Encoding)?,
        generation: d.u64().map_err(|_| Error::Encoding)?,
    };
    let camera_claim = d.digest().map_err(|_| Error::Encoding)?;
    let count =
        usize::try_from(d.u64().map_err(|_| Error::Encoding)?).map_err(|_| Error::Configuration)?;
    let length =
        usize::try_from(d.u64().map_err(|_| Error::Encoding)?).map_err(|_| Error::Configuration)?;
    let digest = d.digest().map_err(|_| Error::Encoding)?;
    if key.connection == 0
        || key.generation == 0
        || camera_claim.algorithm() != DigestAlgorithm::Sha256
        || camera_claim.is_laboratory()
        || camera_claim.bytes() == [0; 32]
        || !(1..=MAX_RECORDS).contains(&count)
        || length != payload.len()
        || digest != ContentDigest::sha256(&payload)
    {
        return Err(Error::Configuration);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    let mut next_offset = None;
    let mut position = 0usize;
    for _ in 0..count {
        let disposition = match d.u8().map_err(|_| Error::Encoding)? {
            0 => SourceDisposition::Header,
            1 => SourceDisposition::Configuration,
            2 => SourceDisposition::PreRoll,
            3 => SourceDisposition::Unclosed,
            4 => SourceDisposition::Unframed,
            5 => SourceDisposition::BootstrapCopy,
            _ => return Err(Error::Configuration),
        };
        let offset = d.u64().map_err(|_| Error::Encoding)?;
        let len = usize::try_from(d.u64().map_err(|_| Error::Encoding)?)
            .map_err(|_| Error::Configuration)?;
        let expected = d.digest().map_err(|_| Error::Encoding)?;
        let kind = match d.u8().map_err(|_| Error::Encoding)? {
            0 => RecordKind::Header,
            1 => RecordKind::FirstTag {
                tag_kind: d.u8().map_err(|_| Error::Encoding)?,
                timestamp_ms: d.u32().map_err(|_| Error::Encoding)?,
            },
            2 => {
                let trailer_bytes = usize::try_from(d.u64().map_err(|_| Error::Encoding)?)
                    .map_err(|_| Error::Configuration)?;
                if trailer_bytes >= len {
                    return Err(Error::Configuration);
                }
                RecordKind::Candidate {
                    trailer_bytes,
                    tag_kind: d.u8().map_err(|_| Error::Encoding)?,
                    timestamp_ms: d.u32().map_err(|_| Error::Encoding)?,
                    earlier_incomplete: d.bool().map_err(|_| Error::Encoding)?,
                    provisional: d.bool().map_err(|_| Error::Encoding)?,
                    policy: SearchMode::from_evidence_id(d.u8().map_err(|_| Error::Encoding)?)
                        .ok_or(Error::Configuration)?,
                }
            }
            3 => RecordKind::Unframed {
                origin: UnframedOrigin::from_evidence_id(d.u8().map_err(|_| Error::Encoding)?)
                    .ok_or(Error::Configuration)?,
            },
            _ => return Err(Error::Configuration),
        };
        let stop = position.checked_add(len).ok_or(Error::Configuration)?;
        let source = payload.get(position..stop).ok_or(Error::Configuration)?;
        if len == 0
            || next_offset.is_some_and(|n| n != offset)
            || matches!(kind, RecordKind::Header)
                != matches!(disposition, SourceDisposition::Header)
            || matches!(kind, RecordKind::Unframed { .. })
                != matches!(disposition, SourceDisposition::Unframed)
            || (matches!(kind, RecordKind::Header) && offset != 0)
            || ContentDigest::sha256(source) != expected
        {
            return Err(Error::Configuration);
        }
        next_offset = Some(offset.checked_add(len as u64).ok_or(Error::Configuration)?);
        records.push(Record {
            offset,
            disposition,
            kind,
            range: position..stop,
        });
        position = stop;
    }
    d.ensure_finished().map_err(|_| Error::Encoding)?;
    if position != payload.len() {
        return Err(Error::Configuration);
    }
    let mut metadata_copy = Vec::new();
    metadata_copy
        .try_reserve_exact(metadata.len())
        .map_err(|_| Error::Allocation)?;
    metadata_copy.extend_from_slice(metadata);
    Ok(Recovered {
        key,
        camera_claim,
        payload,
        records,
        metadata: metadata_copy,
        retention,
    })
}
