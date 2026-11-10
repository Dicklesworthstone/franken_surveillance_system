#![forbid(unsafe_code)]
//! Closed canonical custody record. Media and render receipts are separate immutable children.

use super::grant::{MAX_REVIEW_GRANT_BYTES, ReviewGrant};
use super::render::RenderedReviewMovie;
use super::{REVIEW_OBJECT_PREFIX, REVIEW_PROFILE, ReviewMediaError, ReviewMediaRequest};
use crate::ingest::RetainedReadLimits;
use fss_core::region::ContextAuthority;
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, LedgerAnchor, ObjectId,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

/// Complete canonical metadata ceiling; media bytes never fit inside this record.
pub const MAX_REVIEW_RECORD_BYTES: usize = 64 * 1024;
const DOMAIN: &str = "fss.retained_review_media.v1";

/// Verified source, rendering and access pins of one retained screened derivative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewMediaRecord {
    identity: ContentDigest,
    request_digest: ContentDigest,
    grant: ReviewGrant,
    basis: LedgerAnchor,
    authority: ContentDigest,
    source_manifest: ContentDigest,
    source_input: ContentDigest,
    source_read_limits: RetainedReadLimits,
    privacy_generation: Option<u64>,
    lineage: ContentDigest,
    media_digest: ContentDigest,
    media_bytes: u64,
    receipt_digest: ContentDigest,
    receipt_bytes: u64,
    frames: u64,
    width: u32,
    height: u32,
    duration_ns: u64,
    wire: Vec<u8>,
    root: ContentDigest,
}

pub(super) fn valid_digest(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32]
}
pub(super) fn hex(d: ContentDigest) -> String {
    d.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn request_identity(
    request: ContentDigest,
    a: &ContextAuthority,
    site: &str,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.review_media_identity.v1");
    e.digest(request);
    e.digest(super::authority_binding(a));
    e.text(site);
    ContentDigest::sha256(&e.finish())
}

impl ReviewMediaRecord {
    pub(super) fn new(
        identity: ContentDigest,
        request: &ReviewMediaRequest,
        grant: ReviewGrant,
        rendered: &RenderedReviewMovie,
        authority: ContentDigest,
    ) -> Result<Self, ReviewMediaError> {
        let [width, height] = rendered.dimensions();
        let mut value = Self {
            identity,
            request_digest: request.digest()?,
            grant,
            basis: rendered.anchor().clone(),
            authority,
            source_manifest: rendered.selection().manifest_digest,
            source_input: rendered.selection().input_sha256,
            source_read_limits: request.movie.limits.read,
            privacy_generation: rendered.privacy().generation(),
            lineage: rendered.lineage_digest(),
            media_digest: rendered.media_digest(),
            media_bytes: rendered.bytes().len() as u64,
            receipt_digest: rendered.receipt_digest(),
            receipt_bytes: rendered.receipt_bytes().len() as u64,
            frames: rendered.frames() as u64,
            width,
            height,
            duration_ns: rendered.duration_ns(),
            wire: Vec::new(),
            root: ContentDigest::sha256(b"unpublished-review-root"),
        };
        value.validate()?;
        value.wire = value.encode()?;
        if value.wire.len() > MAX_REVIEW_RECORD_BYTES {
            return Err(ReviewMediaError::Limit);
        }
        value.root = value.manifest()?.root();
        Ok(value)
    }
    fn validate(&self) -> Result<(), ReviewMediaError> {
        self.grant.request().validate()?;
        if ![
            self.identity,
            self.request_digest,
            self.authority,
            self.source_manifest,
            self.source_input,
            self.lineage,
            self.media_digest,
            self.receipt_digest,
        ]
        .into_iter()
        .all(valid_digest)
            || self.grant.render_receipt() != self.receipt_digest
            || self.media_bytes == 0
            || self.media_bytes > self.grant.request().maximum_media_bytes
            || self.receipt_bytes == 0
            || self.receipt_bytes > 8 * 1024 * 1024
            || self.frames == 0
            || self.frames > 1024
            || self.width == 0
            || self.height == 0
            || self.width > 4096
            || self.height > 4096
            || u64::from(self.width) * u64::from(self.height) > 4_194_304
            || self.duration_ns == 0
            || self.source_read_limits.max_source_bytes == 0
            || self.source_read_limits.max_source_bytes
                > fss_container::demux::MAX_MP4_INPUT_BYTES as u64
            || self.source_read_limits.max_chunk_bytes == 0
            || self.source_read_limits.max_chunk_bytes
                > crate::ingest::retained::MAX_RETAINED_PAYLOAD_BYTES
            || self.source_read_limits.max_segment_bytes == 0
            || self.source_read_limits.max_segment_bytes
                > crate::ingest::retained::MAX_RETAINED_PAYLOAD_BYTES
            || self.privacy_generation == Some(0)
        {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, ReviewMediaError> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.u32(1);
        e.text(REVIEW_PROFILE);
        e.digest(self.identity);
        e.digest(self.request_digest);
        e.bytes(&self.grant.to_bytes()?);
        self.basis.encode_canonical(&mut e);
        e.digest(self.authority);
        e.digest(self.source_manifest);
        e.digest(self.source_input);
        e.u64(self.source_read_limits.max_source_bytes);
        e.u64(self.source_read_limits.max_chunk_bytes);
        e.u64(self.source_read_limits.max_segment_bytes);
        e.bool(self.privacy_generation.is_some());
        if let Some(generation) = self.privacy_generation {
            e.u64(generation);
        }
        e.digest(self.lineage);
        e.digest(self.media_digest);
        e.u64(self.media_bytes);
        e.digest(self.receipt_digest);
        e.u64(self.receipt_bytes);
        e.u64(self.frames);
        e.u32(self.width);
        e.u32(self.height);
        e.u64(self.duration_ns);
        Ok(e.finish_checked()?)
    }
    /// Strict decoder with independent digest verification and canonical re-encoding.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, ReviewMediaError> {
        if bytes.len() > MAX_REVIEW_RECORD_BYTES
            || !valid_digest(expected)
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN || d.u32()? != 1 || d.text()? != REVIEW_PROFILE {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        let identity = d.digest()?;
        let request_digest = d.digest()?;
        let grant_bytes = d.bytes()?;
        if grant_bytes.len() > MAX_REVIEW_GRANT_BYTES {
            return Err(ReviewMediaError::Limit);
        }
        let grant = ReviewGrant::from_bytes(grant_bytes, ContentDigest::sha256(grant_bytes))?;
        let mut value = Self {
            identity,
            request_digest,
            grant,
            basis: LedgerAnchor::decode_canonical(&mut d)?,
            authority: d.digest()?,
            source_manifest: d.digest()?,
            source_input: d.digest()?,
            source_read_limits: RetainedReadLimits {
                max_source_bytes: d.u64()?,
                max_chunk_bytes: d.u64()?,
                max_segment_bytes: d.u64()?,
            },
            privacy_generation: if d.bool()? { Some(d.u64()?) } else { None },
            lineage: d.digest()?,
            media_digest: d.digest()?,
            media_bytes: d.u64()?,
            receipt_digest: d.digest()?,
            receipt_bytes: d.u64()?,
            frames: d.u64()?,
            width: d.u32()?,
            height: d.u32()?,
            duration_ns: d.u64()?,
            wire: bytes.to_vec(),
            root: ContentDigest::sha256(b"unpublished-review-root"),
        };
        d.ensure_finished()?;
        value.validate()?;
        if value.encode()? != bytes {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        value.root = value.manifest()?.root();
        Ok(value)
    }
    /// Exact canonical custody bytes; no media is embedded.
    pub fn to_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Immutable record identity.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.wire)
    }
    /// Exact reviewer scope; serialized grants alone never authorize reads.
    pub fn grant(&self) -> &ReviewGrant {
        &self.grant
    }
    /// Exact source manifest retained at render time.
    pub fn source_manifest(&self) -> ContentDigest {
        self.source_manifest
    }
    /// Ledger generation of the mask, preserving invalidation across identical re-declarations.
    pub fn privacy_generation(&self) -> Option<u64> {
        self.privacy_generation
    }
    /// Complete rendered media identity.
    pub fn media_digest(&self) -> ContentDigest {
        self.media_digest
    }
    /// Complete rendered byte length.
    pub fn media_bytes(&self) -> u64 {
        self.media_bytes
    }
    /// Render receipt identity.
    pub fn render_receipt_digest(&self) -> ContentDigest {
        self.receipt_digest
    }
    /// Render receipt byte bound.
    pub fn render_receipt_bytes(&self) -> u64 {
        self.receipt_bytes
    }
    /// Exact pre-render authority head.
    pub fn basis(&self) -> &LedgerAnchor {
        &self.basis
    }
    /// Number of selected presentation occurrences.
    pub fn frames(&self) -> u64 {
        self.frames
    }
    /// Display dimensions of the screened gray video.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
    /// Requested movie duration, preserving leading, interior and trailing holes.
    pub fn duration_ns(&self) -> u64 {
        self.duration_ns
    }
    pub(crate) fn identity(&self) -> ContentDigest {
        self.identity
    }
    pub(super) fn request_digest(&self) -> ContentDigest {
        self.request_digest
    }
    pub(super) fn authority(&self) -> ContentDigest {
        self.authority
    }
    pub(super) fn read_limits(&self) -> RetainedReadLimits {
        self.source_read_limits
    }
    /// A pending graph has no guarded issuance witness. Recompute every independent custody
    /// claim from the native renderer before adopting its candidate grant after an interrupted
    /// publication. The original preparation head is checked against root publication separately.
    pub(super) fn verify_rendered(
        &self,
        request: &ReviewMediaRequest,
        rendered: &RenderedReviewMovie,
    ) -> Result<(), ReviewMediaError> {
        if self.request_digest != request.digest()?
            || self.grant.request() != &request.access
            || self.source_read_limits != request.movie.limits.read
            || self.source_manifest != rendered.selection().manifest_digest
            || self.source_input != rendered.selection().input_sha256
            || self.lineage != rendered.lineage_digest()
            || self.media_digest != rendered.media_digest()
            || self.media_bytes != rendered.bytes().len() as u64
            || self.receipt_digest != rendered.receipt_digest()
            || self.receipt_bytes != rendered.receipt_bytes().len() as u64
            || self.frames != rendered.frames() as u64
            || [self.width, self.height] != rendered.dimensions()
            || self.duration_ns != rendered.duration_ns()
            || self.grant.request().import_identity != rendered.selection().import_identity
            || self.grant.request().import_root != rendered.source_import_root()
            || &self.grant.request().sensor != rendered.sensor()
            || self.privacy_generation != rendered.privacy().generation()
            || self.grant.request().expected_privacy != rendered.privacy().digest()
            || rendered.source_anchor().commit_sequence > self.basis.commit_sequence
        {
            return Err(ReviewMediaError::CustodyMismatch);
        }
        Ok(())
    }
    pub(super) fn manifest(&self) -> Result<ObjectManifest, ReviewMediaError> {
        Ok(ObjectManifest::new(
            REVIEW_PROFILE,
            [self.media_digest, self.receipt_digest],
            Some(self.digest()),
        )?)
    }
    /// Immutable three-child review root.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Exact owner approval, including the rendering anchor and resulting bytes.
    pub fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.review_media_approval.v1");
        e.digest(self.digest());
        e.digest(self.root());
        ContentDigest::sha256(&e.finish())
    }
    pub(super) fn slot(&self) -> Result<SlotName, ReviewMediaError> {
        slot(self.identity)
    }
    pub(super) fn object_id(&self) -> Result<ObjectId, ReviewMediaError> {
        Ok(ObjectId::parse(format!(
            "{REVIEW_OBJECT_PREFIX}{}",
            hex(self.identity)
        ))?)
    }
    /// Bounded machine projection. Purpose remains an owner assertion, never evidence of intent.
    pub fn to_json(&self) -> String {
        let access = self.grant.request();
        format!(
            concat!(
                "{{\"format\":\"fss.retained_review_media.v1\",\"profile\":\"{}\",",
                "\"review_root\":\"{}\",\"record_digest\":\"{}\",\"import_identity\":\"{}\",",
                "\"import_root\":\"{}\",\"sensor\":{},\"movie_start_tick\":{},\"movie_end_tick\":{},",
                "\"privacy_binding\":\"{}\",\"recipient\":{},\"owner\":{},\"purpose\":{},",
                "\"issued_at_ns\":\"{}\",\"expires_at_ns\":\"{}\",\"media_digest\":\"{}\",",
                "\"media_bytes\":{},\"render_receipt_digest\":\"{}\",\"frames\":{},",
                "\"width\":{},\"height\":{},\"duration_ns\":{},\"source_capture_time_certified\":false,",
                "\"payment_mask_attested\":false,\"external_reviewer_authenticated\":false}}"
            ),
            REVIEW_PROFILE,
            self.root(),
            self.digest(),
            access.import_identity,
            access.import_root,
            json(access.sensor.as_str()),
            access.movie_start_tick,
            access.movie_end_tick,
            access.expected_privacy,
            json(access.recipient.as_str()),
            json(self.grant.owner().as_str()),
            json(&access.purpose),
            access.issued_at.0,
            access.expires_at.0,
            self.media_digest,
            self.media_bytes,
            self.receipt_digest,
            self.frames,
            self.width,
            self.height,
            self.duration_ns
        )
    }
}
pub(super) fn slot(identity: ContentDigest) -> Result<SlotName, ReviewMediaError> {
    SlotName::parse(&format!("review-{}", hex(identity)))
        .map_err(|_| ReviewMediaError::InvalidRequest)
}
fn json(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
