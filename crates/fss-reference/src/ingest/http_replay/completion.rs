#![forbid(unsafe_code)]
//! Root-last records of actual native HTTP/MIME termination, not guessed archive EOF.
//! The independently retained completion pin selects a trusted archive-writer statement.
//! It is not a signature, sensor-authentication proof, or permission to disclose originals.

use super::{HttpReplayAccess, HttpReplayError, HttpReplayStep, HttpWireReplay};
use crate::ingest::http_archive::{HttpArchiveError, HttpWireArchive, HttpWirePin, MAX_HTTP_WIRE_READS};
use crate::ingest::http_camera::HttpCamera;
use fss_codec_mjpeg::http::{BodyFraming, HttpEnd, HttpHeadIdentity, HttpTermination};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectManifest};
use fss_publication::{LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher,
    PublishCancellation, PublishCutPoint, SlotName};

const DOMAIN: &str = "fss.http_camera_completion.v1";
const KIND: &str = "http_camera_completion_v1";
const METADATA_BYTES: usize = 1024;

/// Exact independently retained completion root and original wire prefix.
/// Neither public fields nor possession of this key are a successful verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpCompletionPin {
    /// Root containing termination metadata and EVERY original-read root.
    pub root: ContentDigest,
    /// Exact source prefix; later reads cannot silently extend it.
    pub wire: HttpWirePin,
}
impl HttpCompletionPin {
    /// One terminal slot per exact retention/clock scope; rival endings conflict.
    pub fn slot(self) -> Result<SlotName, HttpCompletionError> {
        if !valid(self.root) || !valid(self.wire.scope) || !valid(self.wire.head) {
            return Err(HttpCompletionError::Mismatch);
        }
        SlotName::parse(&format!("fsshe1-{}", hex(self.wire.scope)))
            .map_err(|_| HttpCompletionError::Metadata)
    }
}

/// No error is interpreted as a clean capture or permission to reacquire source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCompletionError {
    /// The camera or replay has not reached the required drained boundary.
    NotReady,
    /// Original prefix, frame accounting, framing or independently pinned root differs.
    Mismatch,
    /// Stored canonical metadata, family or direct child closure is invalid.
    Metadata,
    /// Native or original-media input exceeds independently selected bounds.
    Limit,
    /// Current storage/cancellation/authorization probe refused.
    Cancelled,
    /// Completion root is missing, broken, poisoned or not durable.
    NotDurable,
    /// A completion object was tombstoned; it cannot be recreated here.
    Tombstoned,
    /// Existing storage owner refused an operation; partial publication may remain.
    Storage,
    /// Existing original-wire archive refused current source verification.
    Archive(HttpArchiveError),
    /// Caller-owned deterministic work refused before completion.
    Work(GeometryError),
    /// Existing replay or native parser refused, preserving its accepted prefix.
    Replay(HttpReplayError),
}
impl From<HttpArchiveError> for HttpCompletionError {
    fn from(e: HttpArchiveError) -> Self { Self::Archive(e) }
}
impl From<GeometryError> for HttpCompletionError {
    fn from(e: GeometryError) -> Self { Self::Work(e) }
}
impl std::fmt::Display for HttpCompletionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP completion refused: {self:?}")
    }
}
impl std::error::Error for HttpCompletionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record { wire: HttpWirePin, end: HttpEnd, frames: u64, peer_eof: bool }
impl Record {
    fn validate(self) -> Result<(), HttpCompletionError> {
        let e = self.end;
        if ![self.wire.scope, self.wire.head, sha(e.head.wire.source),
            sha(e.head.entity.source), sha(e.head.header_sha256)].into_iter().all(valid)
            || self.wire.reads == 0 || self.wire.reads > MAX_HTTP_WIRE_READS as u64 || self.wire.bytes == 0
            || self.wire.bytes > 256 * 1024 * 1024 || e.wire_bytes != self.wire.bytes
            || e.entity_bytes > e.wire_bytes || e.head.wire.generation == 0
            || e.head.entity.generation == 0 || self.frames > 1_000_000 || e.chunks > 1_000_000 {
            return Err(HttpCompletionError::Metadata);
        }
        let framing_valid = match (e.head.framing, e.termination) {
            (BodyFraming::Length(n), HttpTermination::ExplicitFraming) => n == e.entity_bytes && e.chunks == 0,
            (BodyFraming::Chunked, HttpTermination::ExplicitFraming) => true,
            (BodyFraming::UntilEof, HttpTermination::CloseDelimitedEof) => self.peer_eof && e.chunks == 0,
            _ => false,
        };
        if !framing_valid { return Err(HttpCompletionError::Metadata); }
        Ok(())
    }
    fn encode(self) -> Result<Vec<u8>, HttpCompletionError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new(); e.text(DOMAIN);
        e.digest(self.wire.scope); e.digest(self.wire.head);
        e.u64(self.wire.reads); e.u64(self.wire.bytes);
        for basis in [self.end.head.wire, self.end.head.entity] {
            e.digest(sha(basis.source)); e.u64(basis.generation);
        }
        e.digest(sha(self.end.head.header_sha256));
        let (tag, length) = match self.end.head.framing {
            BodyFraming::Length(n) => (0, n), BodyFraming::Chunked => (1, 0), BodyFraming::UntilEof => (2, 0),
        };
        e.u64(tag); e.u64(length); e.u64(self.end.wire_bytes); e.u64(self.end.entity_bytes);
        e.u64(self.end.chunks); e.u64(match self.end.termination {
            HttpTermination::ExplicitFraming => 0, HttpTermination::CloseDelimitedEof => 1,
        });
        e.u64(self.frames); e.u64(u64::from(self.peer_eof));
        let bytes = e.finish_checked().map_err(|_| HttpCompletionError::Metadata)?;
        if bytes.len() > METADATA_BYTES { return Err(HttpCompletionError::Limit); }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, HttpCompletionError> {
        let parse = || -> Result<Self, fss_core::ContractError> {
            let mut d = CanonicalDecoder::new(bytes);
            if d.text()? != DOMAIN { return Err(fss_core::ContractError::InvalidIdentifier); }
            let wire = HttpWirePin { scope: d.digest()?, head: d.digest()?, reads: d.u64()?, bytes: d.u64()? };
            let mut basis = || -> Result<StreamBasis, fss_core::ContractError> {
                let digest = d.digest()?;
                if digest.algorithm() != DigestAlgorithm::Sha256 { return Err(fss_core::ContractError::InvalidIdentifier); }
                Ok(StreamBasis { source: digest.bytes(), generation: d.u64()? })
            };
            let source = basis()?; let entity = basis()?; let header = d.digest()?;
            if header.algorithm() != DigestAlgorithm::Sha256 { return Err(fss_core::ContractError::InvalidIdentifier); }
            let framing = match (d.u64()?, d.u64()?) {
                (0, n) => BodyFraming::Length(n), (1, 0) => BodyFraming::Chunked, (2, 0) => BodyFraming::UntilEof,
                _ => return Err(fss_core::ContractError::InvalidIdentifier),
            };
            let head = HttpHeadIdentity { wire: source, entity, header_sha256: header.bytes(), framing };
            let end = HttpEnd { head, wire_bytes: d.u64()?, entity_bytes: d.u64()?, chunks: d.u64()?,
                termination: match d.u64()? {
                    0 => HttpTermination::ExplicitFraming, 1 => HttpTermination::CloseDelimitedEof,
                    _ => return Err(fss_core::ContractError::InvalidIdentifier),
                } };
            let frames = d.u64()?;
            let peer_eof = match d.u64()? { 0 => false, 1 => true, _ => return Err(fss_core::ContractError::InvalidIdentifier) };
            d.ensure_finished()?; Ok(Self { wire, end, frames, peer_eof })
        };
        let record = parse().map_err(|_| HttpCompletionError::Metadata)?;
        if record.encode()? != bytes { return Err(HttpCompletionError::Metadata); }
        Ok(record)
    }
    fn manifest(self, archive: &HttpWireArchive, work: &mut WorkBudget<'_>) -> Result<ObjectManifest, HttpCompletionError> {
        if archive.pin() != self.wire || archive.scope().stream != self.end.head.wire {
            return Err(HttpCompletionError::Mismatch);
        }
        if self.wire.reads as usize >= MAX_MANIFEST_CHILDREN { return Err(HttpCompletionError::Limit); }
        work.charge(4096 + self.wire.reads * 512)?;
        ObjectManifest::new(KIND, archive.reads().map(|(pin, _)| pin.head),
            Some(ContentDigest::sha256(&self.encode()?))).map_err(|_| HttpCompletionError::Metadata)
    }
}

/// Immutable terminal publication prepared ONLY from an opaque native camera owner.
/// No constructor accepts a caller-authored EOF flag, HTTP end, or frame count.
#[derive(Debug)]
pub struct PreparedHttpCompletion { record: Record, manifest: ObjectManifest, pin: HttpCompletionPin }
impl PreparedHttpCompletion {
    /// The native HTTP AND MIME parsers must have completed and every held frame
    /// must already be transferred. Preparation does no I/O or source acknowledgement.
    pub fn from_camera(camera: &HttpCamera, archive: &HttpWireArchive, work: &mut WorkBudget<'_>)
        -> Result<Self, HttpCompletionError> {
        work.charge(1024)?;
        if camera.failure().is_some() || camera.pending_frame().is_some() || camera.pending_wire().is_some() {
            return Err(HttpCompletionError::NotReady);
        }
        let complete = camera.completion().ok_or(HttpCompletionError::NotReady)?;
        let totals = camera.totals();
        if complete.final_frame.is_some() || totals.received_bytes != archive.pin().bytes
            || complete.http.head.wire != camera.route().basis()
            || complete.multipart.basis != complete.http.head.entity
            || complete.multipart.bytes != complete.http.entity_bytes
            || complete.multipart.frames != totals.frames {
            return Err(HttpCompletionError::Mismatch);
        }
        let record = Record { wire: archive.pin(), end: complete.http, frames: totals.frames, peer_eof: totals.peer_eof };
        let manifest = record.manifest(archive, work)?;
        let pin = HttpCompletionPin { root: manifest.root(), wire: record.wire };
        pin.slot()?; work.charge(0)?; Ok(Self { record, manifest, pin })
    }
    /// Retain before publishing so a lost acknowledgement resolves the SAME root.
    pub fn pin(&self) -> HttpCompletionPin { self.pin }
    /// Reverify all originals, then publish terminal metadata and its closure root last.
    /// Existing cancellation, crash, conflicting-slot and tombstone rules apply.
    pub fn publish(&self, archive: &HttpWireArchive, publisher: &mut LocalRootPublisher,
        cancel: &dyn PublishCancellation, work: &mut WorkBudget<'_>) -> Result<LocalPublicationReceipt, HttpCompletionError> {
        probe(cancel)?;
        HttpWireArchive::load(publisher, archive.scope(), self.pin.wire, archive.limits(), cancel, work)?;
        if self.record.manifest(archive, work)? != self.manifest { return Err(HttpCompletionError::Mismatch); }
        let metadata = self.record.encode()?;
        work.charge(4096 + metadata.len() as u64 * 8 + publisher.limits().max_tombstones as u64)?;
        let metadata_digest = ContentDigest::sha256(&metadata);
        if publisher.tombstones().any(|d| *d == self.pin.root || *d == metadata_digest) {
            return Err(HttpCompletionError::Tombstoned);
        }
        probe(cancel)?;
        if publisher.stage_object(&metadata).map_err(|_| HttpCompletionError::Storage)? != metadata_digest {
            return Err(HttpCompletionError::Storage);
        }
        probe(cancel)?; work.charge(0)?;
        let receipt = publisher.publish_cancellable(&self.pin.slot()?, &self.manifest, cancel)
            .map_err(|_| HttpCompletionError::Storage)?;
        // Do not turn successful publication into an error from a late optional check.
        if receipt.root != self.pin.root || receipt.claims.local != LocalPublicationState::Durable {
            return Err(HttpCompletionError::NotDurable);
        }
        Ok(receipt)
    }
}

/// Verified record from a selected trusted archive-writer root, NOT timeless authority.
/// Replay finalization revalidates this token against current storage and disclosure.
#[derive(Debug)]
pub struct VerifiedHttpCompletion { pin: HttpCompletionPin, record: Record }
impl VerifiedHttpCompletion {
    /// Verify exact root family, canonical metadata, all direct children and originals.
    pub fn load(publisher: &LocalRootPublisher, archive: &HttpWireArchive, expected: HttpCompletionPin,
        cancel: &dyn PublishCancellation, work: &mut WorkBudget<'_>) -> Result<Self, HttpCompletionError> {
        probe(cancel)?;
        if expected.wire != archive.pin() { return Err(HttpCompletionError::Mismatch); }
        HttpWireArchive::load(publisher, archive.scope(), expected.wire, archive.limits(), cancel, work)?;
        let slot = expected.slot()?;
        if publisher.is_poisoned() || publisher.is_broken_slot(&slot)
            || publisher.root(&slot).is_none_or(|r| r.root != expected.root || r.state != LocalPublicationState::Durable) {
            return Err(HttpCompletionError::NotDurable);
        }
        let read = |digest: ContentDigest, maximum: usize, work: &mut WorkBudget<'_>| {
            probe(cancel)?;
            work.charge(publisher.limits().spool.max_object_bytes as u64 * 3 + publisher.limits().max_tombstones as u64 + 1)?;
            if publisher.tombstones().any(|d| *d == digest) { return Err(HttpCompletionError::Tombstoned); }
            let bytes = publisher.spool().read(digest).map_err(|_| HttpCompletionError::Storage)?;
            if bytes.len() > maximum { return Err(HttpCompletionError::Limit); }
            probe(cancel)?; work.charge(0)?; Ok(bytes)
        };
        let raw = read(expected.root, publisher.limits().spool.max_object_bytes, work)?;
        let manifest = ObjectManifest::from_canonical_bytes(&raw).map_err(|_| HttpCompletionError::Metadata)?;
        if manifest.root() != expected.root || manifest.kind() != KIND { return Err(HttpCompletionError::Mismatch); }
        let metadata = read(manifest.metadata_digest().ok_or(HttpCompletionError::Metadata)?, METADATA_BYTES, work)?;
        let record = Record::decode(&metadata)?;
        if record.wire != expected.wire || record.manifest(archive, work)? != manifest {
            return Err(HttpCompletionError::Mismatch);
        }
        probe(cancel)?; work.charge(0)?; Ok(Self { pin: expected, record })
    }
    /// Exact independently selected root.
    pub fn pin(&self) -> HttpCompletionPin { self.pin }
    /// Native terminal HTTP accounting; no camera timestamp or coverage claim.
    pub fn http_end(&self) -> HttpEnd { self.record.end }
    /// Delimited MIME frames, not successful model invocations.
    pub fn frames(&self) -> u64 { self.record.frames }
    /// Actual source-owner zero-byte read, separate from explicit HTTP framing.
    pub fn peer_eof(&self) -> bool { self.record.peer_eof }
}

impl HttpWireReplay<'_> {
    /// Finalize a drained prefix using an independently pinned, currently verified
    /// native completion record. Plain step() STILL never invents socket EOF.
    /// If EOF closes a final MIME delimiter, FrameReady is returned BEFORE Complete.
    pub fn finish_completed(&mut self, witness: &VerifiedHttpCompletion, access: HttpReplayAccess<'_, '_>)
        -> Result<HttpReplayStep, HttpCompletionError> {
        probe(access.cancellation)?;
        if self.pin != witness.pin.wire { return Err(HttpCompletionError::Mismatch); }
        if let Some(error) = self.failure { return Err(HttpCompletionError::Replay(error)); }
        if self.frame.is_some() { return Err(HttpCompletionError::NotReady); }
        let verified = VerifiedHttpCompletion::load(access.publisher, self.archive, witness.pin,
            access.cancellation, access.work)?;
        let record = verified.record;
        if record.frames > self.limits.frames { return Err(HttpCompletionError::Limit); }
        if let Some(complete) = &self.complete {
            if complete.http != record.end || complete.multipart.frames != record.frames || self.frames != record.frames {
                return Err(HttpCompletionError::Mismatch);
            }
            return Ok(HttpReplayStep::Complete);
        }
        if !self.exhausted || self.loaded != self.pin.bytes || self.http.next_offset() != self.pin.bytes
            || self.wire.is_some() || self.entity.is_some() {
            return Err(HttpCompletionError::NotReady);
        }
        if record.end.termination != HttpTermination::CloseDelimitedEof || !record.peer_eof
            || self.head.as_ref().is_none_or(|h| h.identity() != record.end.head) {
            return Err(HttpCompletionError::Mismatch);
        }
        let result = (|| -> Result<HttpReplayStep, HttpReplayError> {
            let end = self.http.finish(access.framing).map_err(HttpReplayError::Http)?;
            self.end = Some(end);
            if end != record.end { return Err(HttpReplayError::State); }
            let mut complete = self.multipart.as_mut().ok_or(HttpReplayError::State)?
                .finish(end, access.framing).map_err(HttpReplayError::Multipart)?;
            self.frame = complete.final_frame.take();
            if self.frame.is_some() { self.frames += 1; }
            if self.frames != record.frames || complete.multipart.frames != record.frames
                || complete.multipart.bytes != end.entity_bytes || complete.multipart.basis != end.head.entity {
                return Err(HttpReplayError::State);
            }
            self.complete = Some(complete); self.exhausted = false;
            Ok(if self.frame.is_some() { HttpReplayStep::FrameReady } else { HttpReplayStep::Complete })
        })();
        if let Err(error) = result { self.failure = Some(error); }
        // Preserve final_frame/end/complete BEFORE a late authorization refusal.
        probe(access.cancellation)?; access.work.charge(0)?;
        result.map_err(HttpCompletionError::Replay)
    }
}
fn sha(bytes: [u8; 32]) -> ContentDigest { ContentDigest::new(DigestAlgorithm::Sha256, bytes) }
fn valid(digest: ContentDigest) -> bool { digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32] }
fn hex(digest: ContentDigest) -> String { digest.bytes().iter().map(|b| format!("{b:02x}")).collect() }
fn probe(cancel: &dyn PublishCancellation) -> Result<(), HttpCompletionError> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { Err(HttpCompletionError::Cancelled) } else { Ok(()) }
}
