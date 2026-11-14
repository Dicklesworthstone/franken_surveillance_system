#![forbid(unsafe_code)]
//! Source-preserving evidence preparation for one UniFi event claim.
//!
//! This candidate neither stores nor discloses its source. Camera and
//! connection bindings are caller claims; the physical capture time and
//! device identity remain unknown. Storage requires separate authority.

use std::{collections::BTreeSet, fmt};

use fss_container::flv_avc::SourceKey;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;

use super::events::{Frame, Kind};

pub(super) const DOMAIN: &str = "fss.unifi-direct.event-source-evidence.v1";
pub(super) const KIND: &str = "unifi-direct-event-source-v1";

/// A bounded event source could not be prepared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied source, connection, retention or camera claim is invalid.
    Configuration,
    /// Canonical encoding or manifest construction failed.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi event evidence preparation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(super) fn kind_code(kind: Kind) -> Option<u8> {
    match kind {
        Kind::SmartDetect => Some(0),
        Kind::SmartDetectZone => Some(1),
        Kind::SmartMotion => Some(2),
        Kind::SmartAudio => Some(3),
        Kind::Analytics => Some(4),
        Kind::Other => Some(5),
        Kind::StartupRequest => None,
    }
}

pub(super) fn kind_from_code(code: u8) -> Option<Kind> {
    match code {
        0 => Some(Kind::SmartDetect),
        1 => Some(Kind::SmartDetectZone),
        2 => Some(Kind::SmartMotion),
        3 => Some(Kind::SmartAudio),
        4 => Some(Kind::Analytics),
        5 => Some(Kind::Other),
        _ => None,
    }
}

pub(super) fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && !digest.is_laboratory()
        && digest.bytes() != [0; 32]
}

pub(super) fn classify(source: &[u8]) -> Option<(Kind, u64, bool)> {
    let identity =
        super::Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0").ok()?;
    let mut controller = super::Controller::new(identity, 1).ok()?;
    match controller.observe_event_claims(source).ok()? {
        super::Observation::CameraEvent {
            kind,
            message_id,
            response_expected,
        } => Some((kind, message_id, response_expected)),
        _ => None,
    }
}

/// A candidate borrowing the exact original message; not a storage receipt.
pub struct Prepared<'a> {
    source: &'a [u8],
    retention: ContentDigest,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
}

impl fmt::Debug for Prepared<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedEvent")
            .field("root", &self.manifest.root())
            .finish_non_exhaustive()
    }
}

impl<'a> Prepared<'a> {
    /// Bind one captured event to caller-provided connection and camera claims.
    /// The original frame stays with the caller on success and refusal.
    pub fn new(
        frame: &'a Frame,
        key: SourceKey,
        camera_claim: ContentDigest,
        retention: ContentDigest,
    ) -> Result<Self, Error> {
        let kind = kind_code(frame.kind()).ok_or(Error::Configuration)?;
        let source = frame.source();
        if key.connection == 0
            || key.generation == 0
            || !valid_digest(camera_claim)
            || !valid_digest(retention)
            || source.is_empty()
            || source.len() > super::MAX_MESSAGE_BYTES
            || ContentDigest::sha256(source) != frame.digest()
            || classify(source)
                != Some((frame.kind(), frame.message_id(), frame.response_expected()))
        {
            return Err(Error::Configuration);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DOMAIN);
        encoder.digest(retention);
        encoder.bool(false);
        encoder.u64(key.connection);
        encoder.u64(key.generation);
        encoder.digest(camera_claim);
        encoder.u8(kind);
        encoder.u64(frame.message_id());
        encoder.bool(frame.response_expected());
        encoder.u64(u64::try_from(source.len()).map_err(|_| Error::Configuration)?);
        encoder.digest(frame.digest());
        let metadata = encoder.finish_checked().map_err(|_| Error::Encoding)?;
        let metadata_digest = ContentDigest::sha256(&metadata);
        if frame.digest() == metadata_digest {
            return Err(Error::Encoding);
        }
        let manifest = ObjectManifest::new(
            KIND,
            BTreeSet::from([frame.digest()]),
            Some(metadata_digest),
        )
        .map_err(|_| Error::Encoding)?;
        Ok(Self {
            source,
            retention,
            metadata,
            manifest,
        })
    }

    /// Candidate root and children; not publication or authority.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    /// Digest of the retained event source.
    pub fn source_digest(&self) -> ContentDigest {
        ContentDigest::sha256(self.source)
    }
    /// Recreate the exact candidate from a verified, authorized archive read.
    pub fn from_recovered(event: &'a super::archive::RecoveredEvent) -> Self {
        Self {
            source: event.frame.source(),
            retention: event.retention,
            metadata: event.metadata.clone(),
            manifest: event.manifest.clone(),
        }
    }
    pub(super) fn retention(&self) -> ContentDigest {
        self.retention
    }
    pub(super) fn payloads(&self) -> impl Iterator<Item = &[u8]> {
        [self.source, self.metadata.as_slice()].into_iter()
    }
}
