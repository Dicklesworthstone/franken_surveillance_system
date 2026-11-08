#![forbid(unsafe_code)]
//! Standalone source-record graph for records returned outside a segment.
//!
//! Preparation is in-memory only. Connection, camera and framing values are
//! caller or parser claims, not authentication, physical capture time, or
//! proof of coverage. The borrowed source remains owned by its caller.

use std::{collections::BTreeSet, fmt};

use fss_container::flv_avc::SourceKey;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;
use fss_packet::extended_flv::stream::{RecordKind, SourceRecord};

use super::{evidence, recording::SourceDisposition};

pub(super) const DOMAIN: &str = "fss.unifi-direct.flv-source-evidence.v1";
pub(super) const KIND: &str = "unifi-direct-flv-source-v1";

/// A bounded source graph could not be prepared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The record, identifiers, bounds or disposition were invalid.
    Configuration,
    /// Canonical metadata or its manifest could not be encoded.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi standalone source preparation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A candidate retaining a borrow of the exact original record.
pub struct Prepared<'a> {
    source: &'a [u8],
    retention: ContentDigest,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
}

impl<'a> Prepared<'a> {
    /// Describe one source record with an explicit unknown capture time.
    /// `camera_claim`, `key`, and `disposition` are caller claims, not proof
    /// of peer identity or that the pipeline emitted the claimed disposition.
    pub fn new(
        record: &'a SourceRecord,
        key: SourceKey,
        disposition: SourceDisposition,
        camera_claim: ContentDigest,
        retention: ContentDigest,
        max_source_bytes: usize,
    ) -> Result<Self, Error> {
        validate_input(
            record,
            key,
            disposition,
            camera_claim,
            retention,
            max_source_bytes,
        )?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DOMAIN);
        encoder.digest(retention);
        encoder.bool(false);
        encoder.u64(key.connection);
        encoder.u64(key.generation);
        encoder.digest(camera_claim);
        encoder.u8(match disposition {
            SourceDisposition::Header => 0,
            SourceDisposition::Configuration => 1,
            SourceDisposition::PreRoll => 2,
        });
        evidence::encode_record(&mut encoder, record);
        let metadata = encoder.finish_checked().map_err(|_| Error::Encoding)?;
        let metadata_digest = ContentDigest::sha256(&metadata);
        let source_digest = ContentDigest::sha256(record.bytes());
        if source_digest == metadata_digest {
            return Err(Error::Encoding);
        }
        let mut children = BTreeSet::new();
        children.insert(source_digest);
        let manifest = ObjectManifest::new(KIND, children, Some(metadata_digest))
            .map_err(|_| Error::Encoding)?;
        Ok(Self {
            source: record.bytes(),
            retention,
            metadata,
            manifest,
        })
    }

    /// Candidate manifest; this is not a publication receipt.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }

    /// Digest of the exact original source bytes.
    pub fn source_digest(&self) -> ContentDigest {
        ContentDigest::sha256(self.source)
    }

    /// Recreate the exact candidate from a verified, authorized archive read.
    /// This permits journal replay after the original in-memory record is gone.
    pub fn from_recovered(source: &'a super::archive::RecoveredSource) -> Self {
        Self {
            source: source.bytes.as_slice(),
            retention: source.retention,
            metadata: source.metadata.clone(),
            manifest: source.manifest.clone(),
        }
    }

    pub(super) fn retention(&self) -> ContentDigest {
        self.retention
    }
    pub(super) fn payloads(&self) -> impl Iterator<Item = &[u8]> {
        [self.source, self.metadata.as_slice()].into_iter()
    }
}

pub(super) fn validate_input(
    record: &SourceRecord,
    key: SourceKey,
    disposition: SourceDisposition,
    camera_claim: ContentDigest,
    retention: ContentDigest,
    max_source_bytes: usize,
) -> Result<(), Error> {
    let valid_digest = |d: ContentDigest| {
        d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
    };
    if key.connection == 0
        || key.generation == 0
        || !valid_digest(camera_claim)
        || !valid_digest(retention)
        || !(1..=64 * 1024 * 1024).contains(&max_source_bytes)
        || record.bytes().is_empty()
        || record.bytes().len() > max_source_bytes
        || record
            .offset()
            .checked_add(record.bytes().len() as u64)
            .is_none()
        || matches!(record.kind(), RecordKind::Header)
            != matches!(disposition, SourceDisposition::Header)
        || (matches!(record.kind(), RecordKind::Header) && record.offset() != 0)
    {
        return Err(Error::Configuration);
    }
    Ok(())
}
